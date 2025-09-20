# Issue Tracking Application
# A comprehensive issue tracking system with GUI, authentication, and data management

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkcalendar import DateEntry
import pandas as pd
from datetime import datetime
import os
import json
import subprocess
import platform
import hashlib

class IssueTracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Issue Tracking System")
        self.root.geometry("1400x900")
        self.root.configure(bg='#f5f5f5')
        
        # Configure modern styling
        self.setup_styles()
        
        # Data storage
        self.issues_file = "issues_data.xlsx"
        self.masters_file = "masters_data.json"
        self.users_file = "users_data.json"
        
        # Load or initialize data
        self.load_data()
        
        # Show login screen
        if self.authenticate_user():
            # Create GUI after successful login
            self.create_widgets()
            self.load_issues()
        else:
            self.root.destroy()
    
    def setup_styles(self):
        """Setup modern UI styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles for modern look
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), 
                       background='#f5f5f5', foreground='#2c3e50')
        style.configure('Heading.TLabel', font=('Segoe UI', 12, 'bold'),
                       background='#f5f5f5', foreground='#34495e')
        style.configure('Modern.TButton', font=('Segoe UI', 10),
                       padding=(10, 5))
        style.configure('Success.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Danger.TButton', font=('Segoe UI', 10))
        
        # Treeview styling
        style.configure('Modern.Treeview', font=('Segoe UI', 9),
                       rowheight=25, fieldbackground='white')
        style.configure('Modern.Treeview.Heading', font=('Segoe UI', 10, 'bold'),
                       background='#3498db', foreground='white')
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def load_data(self):
        """Load existing data or create default data"""
        # Load users data
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            # Create default users
            self.users = {
                'ROGITPS': {
                    'role': 'Admin',
                    'name': 'Rogith',
                    'password': self.hash_password('Admin@123')
                },
                'SATSHIV': {
                    'role': 'User',
                    'name': 'Sathya',
                    'password': self.hash_password('User@123')
                },
                'KARKART': {
                    'role': 'User',
                    'name': 'Kartheek',
                    'password': self.hash_password('User@123')
                }
            }
            self.save_users()
        
        # Load masters data
        if os.path.exists(self.masters_file):
            with open(self.masters_file, 'r') as f:
                self.masters = json.load(f)
        else:
            # Get action_taken_by from users
            action_taken_by = [user_data['name'] for user_data in self.users.values()]
            self.masters = {
                'applications': ['App1', 'App2', 'App3'],
                'statuses': ['Open', 'Closed', 'Reopened'],
                'issue_types': ['Bug', 'CR', 'Service Ticket', 'User Access Management'],
                'action_taken_by': action_taken_by
            }
            self.save_masters()
        
        # Load issues data
        if os.path.exists(self.issues_file):
            try:
                self.issues_df = pd.read_excel(self.issues_file, engine='openpyxl')
            except ImportError:
                messagebox.showerror("Error", "openpyxl module not found. Please install it using: pip install openpyxl")
                self.issues_df = self.create_empty_dataframe()
            except Exception as e:
                messagebox.showerror("Error", f"Error reading Excel file: {str(e)}")
                self.issues_df = self.create_empty_dataframe()
        else:
            self.issues_df = self.create_empty_dataframe()
    
    def save_users(self):
        """Save users data to JSON file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def authenticate_user(self):
        """Show login dialog and authenticate user"""
        login_window = tk.Toplevel(self.root)
        login_window.title("Login - Issue Tracking System")
        login_window.geometry("400x300")
        login_window.configure(bg='#ecf0f1')
        login_window.transient(self.root)
        login_window.grab_set()
        login_window.resizable(False, False)
        
        # Center the login window
        login_window.geometry("+{}+{}".format(
            int(login_window.winfo_screenwidth()/2 - 200),
            int(login_window.winfo_screenheight()/2 - 150)
        ))
        
        # Main frame with padding
        main_frame = ttk.Frame(login_window, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Issue Tracking System", 
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        # Login form
        ttk.Label(main_frame, text="User ID:", style='Heading.TLabel').grid(
            row=1, column=0, sticky=tk.W, pady=10)
        user_id_var = tk.StringVar()
        user_id_entry = ttk.Entry(main_frame, textvariable=user_id_var, font=('Segoe UI', 11), width=20)
        user_id_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=10, padx=(10, 0))
        
        ttk.Label(main_frame, text="Password:", style='Heading.TLabel').grid(
            row=2, column=0, sticky=tk.W, pady=10)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=password_var, show="*", 
                                  font=('Segoe UI', 11), width=20)
        password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=10, padx=(10, 0))
        
        # Result variable
        login_result = {'success': False}
        
        def attempt_login():
            user_id = user_id_var.get().strip().upper()
            password = password_var.get().strip()
            
            if not user_id or not password:
                messagebox.showwarning("Warning", "Please enter both User ID and Password!")
                return
            
            if user_id in self.users:
                hashed_password = self.hash_password(password)
                if self.users[user_id]['password'] == hashed_password:
                    self.current_user_id = user_id
                    self.current_user = self.users[user_id]
                    login_result['success'] = True
                    login_window.destroy()
                else:
                    messagebox.showerror("Error", "Invalid password!")
            else:
                messagebox.showerror("Error", "Invalid User ID!")
        
        def on_enter(event):
            attempt_login()
        
        # Bind Enter key
        user_id_entry.bind('<Return>', on_enter)
        password_entry.bind('<Return>', on_enter)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=30)
        
        login_btn = ttk.Button(button_frame, text="Login", command=attempt_login,
                              style='Success.TButton')
        login_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(button_frame, text="Cancel", 
                               command=lambda: login_window.destroy(),
                               style='Danger.TButton')
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        
        # Focus on user ID entry
        user_id_entry.focus()
        
        # Wait for login window to close
        self.root.wait_window(login_window)
        
        return login_result['success']
    
    def create_empty_dataframe(self):
        """Create empty DataFrame with required columns"""
        columns = [
            'Sl No', 'Issue Reported Date', 'App Name', 'Issue Type',
            'Reported By', 'Reported By Short ID', 'Department',
            'Issue Description', 'Action Taken', 'Action Taken By',
            'Status', 'Closure Date', 'RCA'
        ]
        return pd.DataFrame(columns=columns)
    
    def save_masters(self):
        """Save masters data to JSON file"""
        with open(self.masters_file, 'w') as f:
            json.dump(self.masters, f, indent=2)
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Main frame with modern styling
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Header with user info
        header_frame = ttk.Frame(main_frame, style='Card.TFrame')
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        header_frame.columnconfigure(1, weight=1)
        
        # Title and user info
        ttk.Label(header_frame, text="Issue Tracking System", 
                 style='Title.TLabel').grid(row=0, column=0, sticky=tk.W)
        
        user_info = f"Welcome, {self.current_user['name']} ({self.current_user['role']})"
        ttk.Label(header_frame, text=user_info, font=('Segoe UI', 10),
                 foreground='#7f8c8d').grid(row=0, column=1, sticky=tk.E)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.rowconfigure(1, weight=1)
        
        # Create tabs based on user role
        self.create_new_issue_tab()
        self.create_view_issues_tab()
        
        # Admin-only tabs
        if self.current_user['role'] == 'Admin':
            self.create_masters_tab()
            self.create_user_management_tab()
    
    def create_new_issue_tab(self):
        """Create the new issue entry tab with modern design"""
        # New Issue Tab
        new_issue_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(new_issue_frame, text="📝 New Issue")
        
        # Create a canvas and scrollbar for scrolling
        canvas = tk.Canvas(new_issue_frame, bg='#f5f5f5')
        scrollbar = ttk.Scrollbar(new_issue_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Form fields in a modern card-like container
        form_frame = ttk.LabelFrame(scrollable_frame, text="Issue Details", padding="20")
        form_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)
        
        row = 0
        
        # Issue Reported Date
        ttk.Label(form_frame, text="Issue Reported Date *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.reported_date = DateEntry(form_frame, width=12, background='#3498db',
                                     foreground='white', borderwidth=2, date_pattern='dd/mm/yyyy',
                                     font=('Segoe UI', 10))
        self.reported_date.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # App Name
        ttk.Label(form_frame, text="App Name *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.app_name_var = tk.StringVar()
        app_combo = ttk.Combobox(form_frame, textvariable=self.app_name_var,
                               values=self.masters['applications'], state="normal",
                               font=('Segoe UI', 10), width=80)
        app_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Issue Type
        ttk.Label(form_frame, text="Issue Type *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.issue_type_var = tk.StringVar()
        issue_combo = ttk.Combobox(form_frame, textvariable=self.issue_type_var,
                                 values=self.masters['issue_types'], state="readonly",
                                 font=('Segoe UI', 10), width=80)
        issue_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Reported By
        ttk.Label(form_frame, text="Reported By *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.reported_by_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.reported_by_var, 
                 font=('Segoe UI', 10), width=80).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Reported By Short ID
        ttk.Label(form_frame, text="Reported By Short ID *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.reported_by_id_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.reported_by_id_var,
                 font=('Segoe UI', 10), width=80).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Department
        ttk.Label(form_frame, text="Department *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.department_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.department_var,
                 font=('Segoe UI', 10), width=80).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Issue Description
        ttk.Label(form_frame, text="Issue Description *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=(tk.W, tk.N), pady=8)
        issue_desc_frame = ttk.Frame(form_frame)
        issue_desc_frame.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        issue_desc_frame.columnconfigure(0, weight=1)
        issue_desc_frame.rowconfigure(0, weight=1)
        self.issue_desc_text = tk.Text(issue_desc_frame, height=4, font=('Segoe UI', 10),
                                      wrap=tk.WORD, bg='white', relief='solid', borderwidth=1)
        self.issue_desc_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        row += 1
        
        # Action Taken
        ttk.Label(form_frame, text="Action Taken *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=(tk.W, tk.N), pady=8)
        action_taken_frame = ttk.Frame(form_frame)
        action_taken_frame.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        action_taken_frame.columnconfigure(0, weight=1)
        action_taken_frame.rowconfigure(0, weight=1)
        self.action_taken_text = tk.Text(action_taken_frame, height=4, font=('Segoe UI', 10),
                                        wrap=tk.WORD, bg='white', relief='solid', borderwidth=1)
        self.action_taken_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        row += 1
        
        # Action Taken By (Auto-populated with current user, non-editable)
        ttk.Label(form_frame, text="Action Taken By *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.action_taken_by_var = tk.StringVar(value=self.current_user['name'])
        ttk.Entry(form_frame, textvariable=self.action_taken_by_var, state='disabled',
                  font=('Segoe UI', 10), width=80).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Status
        ttk.Label(form_frame, text="Status *", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.status_var = tk.StringVar(value="Open")
        status_combo = ttk.Combobox(form_frame, textvariable=self.status_var,
                                  values=self.masters['statuses'], state="readonly",
                                  font=('Segoe UI', 10), width=80)
        status_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # Closure Date
        ttk.Label(form_frame, text="Closure Date", style='Heading.TLabel').grid(
            row=row, column=0, sticky=tk.W, pady=8)
        self.closure_date = DateEntry(form_frame, width=12, background='#3498db',
                                    foreground='white', borderwidth=2, date_pattern='dd/mm/yyyy',
                                    font=('Segoe UI', 10))
        self.closure_date.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        row += 1
        
        # RCA (Not mandatory)
        ttk.Label(form_frame, text="RCA", style='Heading.TLabel').grid(
            row=row, column=0, sticky=(tk.W, tk.N), pady=8)
        rca_frame = ttk.Frame(form_frame)
        rca_frame.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        rca_frame.columnconfigure(0, weight=1)
        rca_frame.rowconfigure(0, weight=1)
        self.rca_text = tk.Text(rca_frame, height=4, font=('Segoe UI', 10),
                               wrap=tk.WORD, bg='white', relief='solid', borderwidth=1)
        self.rca_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        row += 1
        
        # Note about mandatory fields
        note_frame = ttk.Frame(form_frame)
        note_frame.grid(row=row, column=0, columnspan=2, pady=15)
        
        ttk.Label(note_frame, text="* Mandatory fields", 
                 font=('Segoe UI', 9, 'italic'), foreground='#e74c3c').pack()
        
        # Buttons with modern styling
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=row+1, column=0, columnspan=2, pady=20)
        
        add_btn = ttk.Button(button_frame, text="✅ Add Issue", command=self.add_issue,
                            style='Success.TButton')
        add_btn.pack(side=tk.LEFT, padx=10)
        
        clear_btn = ttk.Button(button_frame, text="🗑️ Clear Form", command=self.clear_form,
                              style='Modern.TButton')
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        # Configure column weight
        form_frame.columnconfigure(1, weight=1)
        scrollable_frame.columnconfigure(0, weight=1)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", on_mousewheel)
    
    def create_view_issues_tab(self):
        """Create the view issues tab with enhanced search"""
        # View Issues Tab
        view_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(view_frame, text="📋 View Issues")
        
        # Search and filter frame with modern styling
        search_frame = ttk.LabelFrame(view_frame, text="Search & Filter", padding="15")
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        view_frame.columnconfigure(0, weight=1)
        
        # Search controls
        search_controls = ttk.Frame(search_frame)
        search_controls.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_controls, text="Search:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_controls, textvariable=self.search_var, width=30,
                                font=('Segoe UI', 10))
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Bind search on key release
        search_entry.bind('<KeyRelease>', lambda e: self.search_issues())
        
        ttk.Button(search_controls, text="🔍 Search", command=self.search_issues,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        # Filter controls
        filter_controls = ttk.Frame(search_frame)
        filter_controls.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_controls, text="Status:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        self.filter_status_var = tk.StringVar(value="All")
        status_values = ["All"] + self.masters['statuses']
        ttk.Combobox(filter_controls, textvariable=self.filter_status_var, values=status_values,
                    state="readonly", width=12, font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_controls, text="Type:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        self.filter_type_var = tk.StringVar(value="All")
        type_values = ["All"] + self.masters['issue_types']
        ttk.Combobox(filter_controls, textvariable=self.filter_type_var, values=type_values,
                    state="readonly", width=15, font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(filter_controls, text="🔽 Filter", command=self.filter_issues,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_controls, text="🔄 Show All", command=self.show_all_issues,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        # Treeview for displaying issues with modern styling
        tree_frame = ttk.Frame(view_frame)
        tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        view_frame.rowconfigure(1, weight=1)
        
        # Create treeview with modern styling
        columns = ('Sl No', 'Date', 'App', 'Type', 'Reported By', 'Status', 'Action By')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', 
                                height=20, style='Modern.Treeview')
        
        # Define headings with icons
        self.tree.heading('Sl No', text='🔢 Sl No')
        self.tree.heading('Date', text='📅 Date')
        self.tree.heading('App', text='💻 App Name')
        self.tree.heading('Type', text='🏷️ Type')
        self.tree.heading('Reported By', text='👤 Reported By')
        self.tree.heading('Status', text='📊 Status')
        self.tree.heading('Action By', text='🔧 Action By')
        
        # Define column widths
        self.tree.column('Sl No', width=80, anchor='center')
        self.tree.column('Date', width=120, anchor='center')
        self.tree.column('App', width=200)
        self.tree.column('Type', width=200)
        self.tree.column('Reported By', width=200)
        self.tree.column('Status', width=100, anchor='center')
        self.tree.column('Action By', width=200)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Action buttons with modern styling
        button_frame = ttk.Frame(view_frame)
        button_frame.grid(row=2, column=0, pady=15)
        
        ttk.Button(button_frame, text="👁️ View Details", command=self.view_details,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="✏️ Edit Issue", command=self.edit_issue,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        # Only admin can delete
        if self.current_user['role'] == 'Admin':
            ttk.Button(button_frame, text="🗑️ Delete Issue", command=self.delete_issue,
                      style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="📊 Export to Excel", command=self.export_to_excel,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔄 Refresh", command=self.load_issues,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
    
    def create_masters_tab(self):
        """Create the masters management tab (Admin only)"""
        # Masters Tab
        masters_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(masters_frame, text="⚙️ Masters")
        
        # Create frames for each master with modern styling
        app_frame = ttk.LabelFrame(masters_frame, text="📱 Application Names", padding="15")
        app_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        status_frame = ttk.LabelFrame(masters_frame, text="📊 Status Types", padding="15")
        status_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        issue_frame = ttk.LabelFrame(masters_frame, text="🏷️ Issue Types", padding="15")
        issue_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        # Configure grid weights
        masters_frame.columnconfigure(0, weight=1)
        masters_frame.columnconfigure(1, weight=1)
        masters_frame.rowconfigure(0, weight=1)
        masters_frame.rowconfigure(1, weight=1)
        
        # Create master management widgets
        self.create_master_widgets(app_frame, "applications", "Application")
        self.create_master_widgets(status_frame, "statuses", "Status")
        self.create_master_widgets(issue_frame, "issue_types", "Issue Type")
    
    def create_user_management_tab(self):
        """Create user management tab (Admin only)"""
        user_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(user_frame, text="👤 User Management")
        
        # User list frame
        list_frame = ttk.LabelFrame(user_frame, text="Current Users", padding="15")
        list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        user_frame.columnconfigure(0, weight=1)
        user_frame.rowconfigure(0, weight=1)
        
        # Create user treeview
        user_columns = ('Role', 'Name', 'User ID')
        self.user_tree = ttk.Treeview(list_frame, columns=user_columns, show='headings', 
                                     height=15, style='Modern.Treeview')
        
        # Define headings
        self.user_tree.heading('Role', text='👑 Role')
        self.user_tree.heading('Name', text='👤 Name')
        self.user_tree.heading('User ID', text='🆔 User ID')
        
        # Define column widths
        self.user_tree.column('Role', width=100, anchor='center')
        self.user_tree.column('Name', width=200)
        self.user_tree.column('User ID', width=150, anchor='center')
        
        # Scrollbars for user tree
        user_v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=user_v_scrollbar.set)
        
        # Grid user treeview
        self.user_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        user_v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Load users into treeview
        self.load_users()
        
        # User management buttons
        user_button_frame = ttk.Frame(user_frame)
        user_button_frame.grid(row=1, column=0, pady=10)
        
        ttk.Button(user_button_frame, text="➕ Add User", command=self.add_user,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(user_button_frame, text="✏️ Edit User", command=self.edit_user,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(user_button_frame, text="🔑 Reset Password", command=self.reset_password,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(user_button_frame, text="🗑️ Delete User", command=self.delete_user,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=5)
    
    def load_users(self):
        """Load users into treeview"""
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        # Add users to treeview
        for user_id, user_data in self.users.items():
            self.user_tree.insert('', tk.END, values=(
                user_data['role'],
                user_data['name'],
                user_id
            ))
    
    def add_user(self):
        """Add new user"""
        self.user_dialog("Add New User")
    
    def edit_user(self):
        """Edit selected user"""
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to edit!")
            return
        
        item = self.user_tree.item(selection[0])
        user_id = item['values'][2]
        self.user_dialog("Edit User", user_id)
    
    def user_dialog(self, title, edit_user_id=None):
        """User add/edit dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x350")
        dialog.configure(bg='#ecf0f1')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center dialog
        dialog.geometry("+{}+{}".format(
            int(dialog.winfo_screenwidth()/2 - 200),
            int(dialog.winfo_screenheight()/2 - 175)
        ))
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Form fields
        ttk.Label(main_frame, text="Role:", style='Heading.TLabel').grid(row=0, column=0, sticky=tk.W, pady=8)
        role_var = tk.StringVar(value="User" if not edit_user_id else self.users[edit_user_id]['role'])
        role_combo = ttk.Combobox(main_frame, textvariable=role_var, values=['Admin', 'User'],
                                 state="readonly", font=('Segoe UI', 10))
        role_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        ttk.Label(main_frame, text="Name:", style='Heading.TLabel').grid(row=1, column=0, sticky=tk.W, pady=8)
        name_var = tk.StringVar(value="" if not edit_user_id else self.users[edit_user_id]['name'])
        ttk.Entry(main_frame, textvariable=name_var, font=('Segoe UI', 10)).grid(
            row=1, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        ttk.Label(main_frame, text="User ID:", style='Heading.TLabel').grid(row=2, column=0, sticky=tk.W, pady=8)
        user_id_var = tk.StringVar(value="" if not edit_user_id else edit_user_id)
        user_id_entry = ttk.Entry(main_frame, textvariable=user_id_var, font=('Segoe UI', 10))
        user_id_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        if edit_user_id:
            user_id_entry.configure(state='readonly')
        
        ttk.Label(main_frame, text="Password:", style='Heading.TLabel').grid(row=3, column=0, sticky=tk.W, pady=8)
        password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=password_var, show="*", font=('Segoe UI', 10)).grid(
            row=3, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        ttk.Label(main_frame, text="Confirm Password:", style='Heading.TLabel').grid(row=4, column=0, sticky=tk.W, pady=8)
        confirm_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=confirm_password_var, show="*", font=('Segoe UI', 10)).grid(
            row=4, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        if edit_user_id:
            ttk.Label(main_frame, text="(Leave password blank to keep current)", 
                     font=('Segoe UI', 8), foreground='#7f8c8d').grid(
                row=5, column=0, columnspan=2, pady=5)
        
        def save_user():
            role = role_var.get().strip()
            name = name_var.get().strip()
            user_id = user_id_var.get().strip().upper()
            password = password_var.get().strip()
            confirm_password = confirm_password_var.get().strip()
            
            if not all([role, name, user_id]):
                messagebox.showerror("Error", "Please fill in all required fields!")
                return
            
            if not edit_user_id and not password:
                messagebox.showerror("Error", "Password is required for new users!")
                return
            
            if password and password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            
            if not edit_user_id and user_id in self.users:
                messagebox.showerror("Error", "User ID already exists!")
                return
            
            # Save user
            if edit_user_id:
                # Update existing user
                self.users[user_id]['role'] = role
                self.users[user_id]['name'] = name
                if password:  # Only update password if provided
                    self.users[user_id]['password'] = self.hash_password(password)
            else:
                # Add new user
                self.users[user_id] = {
                    'role': role,
                    'name': name,
                    'password': self.hash_password(password)
                }
            
            # Update action_taken_by in masters
            self.masters['action_taken_by'] = [user_data['name'] for user_data in self.users.values()]
            
            self.save_users()
            self.save_masters()
            self.load_users()
            dialog.destroy()
            messagebox.showinfo("Success", f"User {'updated' if edit_user_id else 'created'} successfully!")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="💾 Save", command=save_user,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=dialog.destroy,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        
        main_frame.columnconfigure(1, weight=1)
    
    def reset_password(self):
        """Reset user password"""
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to reset password!")
            return
        
        item = self.user_tree.item(selection[0])
        user_id = item['values'][2]
        user_name = item['values'][1]
        
        # Password reset dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Reset Password - {user_name}")
        dialog.geometry("350x200")
        dialog.configure(bg='#ecf0f1')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="New Password:", style='Heading.TLabel').grid(row=0, column=0, sticky=tk.W, pady=8)
        password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=password_var, show="*", font=('Segoe UI', 10)).grid(
            row=0, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        ttk.Label(main_frame, text="Confirm Password:", style='Heading.TLabel').grid(row=1, column=0, sticky=tk.W, pady=8)
        confirm_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=confirm_password_var, show="*", font=('Segoe UI', 10)).grid(
            row=1, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
        
        def reset_pwd():
            password = password_var.get().strip()
            confirm_password = confirm_password_var.get().strip()
            
            if not password:
                messagebox.showerror("Error", "Please enter a new password!")
                return
            
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            
            self.users[user_id]['password'] = self.hash_password(password)
            self.save_users()
            dialog.destroy()
            messagebox.showinfo("Success", f"Password reset successfully for {user_name}!")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="🔑 Reset", command=reset_pwd,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=dialog.destroy,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        
        main_frame.columnconfigure(1, weight=1)
    
    def delete_user(self):
        """Delete selected user"""
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to delete!")
            return
        
        item = self.user_tree.item(selection[0])
        user_id = item['values'][2]
        user_name = item['values'][1]
        
        if user_id == self.current_user_id:
            messagebox.showerror("Error", "You cannot delete your own account!")
            return
        
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete user '{user_name}'?"):
            del self.users[user_id]
            # Update action_taken_by in masters
            self.masters['action_taken_by'] = [user_data['name'] for user_data in self.users.values()]
            self.save_users()
            self.save_masters()
            self.load_users()
            messagebox.showinfo("Success", f"User '{user_name}' deleted successfully!")
    
    def create_master_widgets(self, parent, key, label):
        """Create widgets for managing master data"""
        # Listbox to show current items
        listbox = tk.Listbox(parent, height=10, font=('Segoe UI', 10),
                            bg='white', relief='solid', borderwidth=1)
        listbox.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        # Update listbox with current data
        for item in self.masters[key]:
            listbox.insert(tk.END, item)
        
        # Entry for new item
        entry_var = tk.StringVar()
        entry = ttk.Entry(parent, textvariable=entry_var, font=('Segoe UI', 10))
        entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=8)
        
        # Add button
        add_btn = ttk.Button(parent, text=f"➕ Add {label}",
                           command=lambda: self.add_master_item(key, entry_var, listbox),
                           style='Success.TButton')
        add_btn.grid(row=1, column=1, padx=(10, 0), pady=8)
        
        # Delete button
        delete_btn = ttk.Button(parent, text=f"🗑️ Delete {label}",
                              command=lambda: self.delete_master_item(key, listbox),
                              style='Danger.TButton')
        delete_btn.grid(row=2, column=0, columnspan=2, pady=8)
    
    def add_master_item(self, key, entry_var, listbox):
        """Add item to master data"""
        item = entry_var.get().strip()
        if item and item not in self.masters[key]:
            self.masters[key].append(item)
            listbox.insert(tk.END, item)
            entry_var.set("")
            self.save_masters()
            messagebox.showinfo("Success", f"{item} added successfully!")
        elif item in self.masters[key]:
            messagebox.showwarning("Warning", f"{item} already exists!")
        else:
            messagebox.showwarning("Warning", "Please enter a valid item!")
    
    def delete_master_item(self, key, listbox):
        """Delete item from master data"""
        selection = listbox.curselection()
        if selection:
            index = selection[0]
            item = listbox.get(index)
            self.masters[key].remove(item)
            listbox.delete(index)
            self.save_masters()
            messagebox.showinfo("Success", f"{item} deleted successfully!")
        else:
            messagebox.showwarning("Warning", "Please select an item to delete!")
    
    def add_issue(self):
        """Add new issue to the database"""
        try:
            # Validate mandatory fields
            mandatory_fields = {
                'App Name': self.app_name_var.get().strip(),
                'Issue Type': self.issue_type_var.get().strip(),
                'Reported By': self.reported_by_var.get().strip(),
                'Reported By Short ID': self.reported_by_id_var.get().strip(),
                'Department': self.department_var.get().strip(),
                'Issue Description': self.issue_desc_text.get(1.0, tk.END).strip(),
                'Action Taken': self.action_taken_text.get(1.0, tk.END).strip(),
                'Action Taken By': self.action_taken_by_var.get().strip(),
                'Status': self.status_var.get().strip()
            }
            
            # Check for empty mandatory fields
            empty_fields = [field for field, value in mandatory_fields.items() if not value]
            
            if empty_fields:
                messagebox.showerror("Validation Error", 
                                   f"Please fill in the following mandatory fields:\n• " + 
                                   "\n• ".join(empty_fields))
                return
            
            # Get next serial number
            if len(self.issues_df) == 0:
                sl_no = 1
            else:
                sl_no = self.issues_df['Sl No'].max() + 1
            
            # Create new issue record
            new_issue = {
                'Sl No': sl_no,
                'Issue Reported Date': self.reported_date.get_date().strftime('%d/%m/%Y'),
                'App Name': self.app_name_var.get().strip(),
                'Issue Type': self.issue_type_var.get().strip(),
                'Reported By': self.reported_by_var.get().strip(),
                'Reported By Short ID': self.reported_by_id_var.get().strip(),
                'Department': self.department_var.get().strip(),
                'Issue Description': self.issue_desc_text.get(1.0, tk.END).strip(),
                'Action Taken': self.action_taken_text.get(1.0, tk.END).strip(),
                'Action Taken By': self.action_taken_by_var.get().strip(),
                'Status': self.status_var.get().strip(),
                'Closure Date': self.closure_date.get_date().strftime('%d/%m/%Y') if self.status_var.get() == 'Closed' else '',
                'RCA': self.rca_text.get(1.0, tk.END).strip()
            }
            
            # Add to DataFrame
            self.issues_df = pd.concat([self.issues_df, pd.DataFrame([new_issue])], ignore_index=True)
            
            # Save to file
            self.save_issues()
            
            # Clear form
            self.clear_form()
            
            # Refresh view
            self.load_issues()
            
            messagebox.showinfo("Success", f"✅ Issue #{sl_no} added successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error adding issue: {str(e)}")
    
    def clear_form(self):
        """Clear all form fields"""
        self.reported_date.set_date(datetime.now().date())
        self.app_name_var.set("")
        self.issue_type_var.set("")
        self.reported_by_var.set("")
        self.reported_by_id_var.set("")
        self.department_var.set("")
        self.issue_desc_text.delete(1.0, tk.END)
        self.action_taken_text.delete(1.0, tk.END)
        # Keep current user selected
        self.action_taken_by_var.set(self.current_user['name'])
        self.status_var.set("Open")
        self.closure_date.set_date(datetime.now().date())
        self.rca_text.delete(1.0, tk.END)
    
    def save_issues(self):
        """Save issues DataFrame to Excel file"""
        try:
            with pd.ExcelWriter(self.issues_file, engine='openpyxl') as writer:
                self.issues_df.to_excel(writer, index=False, sheet_name='Issues')
                
                # Auto-adjust column widths
                worksheet = writer.sheets['Issues']
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
        except Exception as e:
            messagebox.showerror("Error", f"Error saving data: {str(e)}")
    
    def load_issues(self):
        """Load issues into the treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add issues to treeview with row coloring
        for index, row in self.issues_df.iterrows():
            # Add status-based tags for coloring
            tags = []
            if row['Status'] == 'Open':
                tags = ['open']
            elif row['Status'] == 'Closed':
                tags = ['closed']
            elif row['Status'] == 'Reopened':
                tags = ['reopened']
            
            self.tree.insert('', tk.END, values=(
                row['Sl No'],
                row['Issue Reported Date'],
                row['App Name'],
                row['Issue Type'],
                row['Reported By'],
                row['Status'],
                row['Action Taken By']
            ), tags=tags)
        
        # Configure row colors
        self.tree.tag_configure('open', background='#ffebcd')  # Light orange
        self.tree.tag_configure('closed', background='#d4edda')  # Light green
        self.tree.tag_configure('reopened', background='#f8d7da')  # Light red
    
    def search_issues(self):
        """Enhanced search across all columns"""
        search_term = self.search_var.get().strip().lower()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not search_term:
            self.load_issues()
            return
        
        # Search across all visible columns
        search_columns = ['Sl No', 'Issue Reported Date', 'App Name', 'Issue Type',
                         'Reported By', 'Reported By Short ID', 'Department', 
                         'Issue Description', 'Action Taken', 'Action Taken By', 'Status', 'RCA']
        
        # Filter DataFrame based on search term
        filtered_df = self.issues_df[
            self.issues_df[search_columns].astype(str).apply(
                lambda x: x.str.lower().str.contains(search_term, na=False)
            ).any(axis=1)
        ]
        
        # Add filtered results to treeview
        for index, row in filtered_df.iterrows():
            tags = []
            if row['Status'] == 'Open':
                tags = ['open']
            elif row['Status'] == 'Closed':
                tags = ['closed']
            elif row['Status'] == 'Reopened':
                tags = ['reopened']
            
            self.tree.insert('', tk.END, values=(
                row['Sl No'],
                row['Issue Reported Date'],
                row['App Name'],
                row['Issue Type'],
                row['Reported By'],
                row['Status'],
                row['Action Taken By']
            ), tags=tags)
    
    def filter_issues(self):
        """Filter issues by status and type"""
        filter_status = self.filter_status_var.get()
        filter_type = self.filter_type_var.get()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Start with all issues
        filtered_df = self.issues_df.copy()
        
        # Apply status filter
        if filter_status != "All":
            filtered_df = filtered_df[filtered_df['Status'] == filter_status]
        
        # Apply type filter
        if filter_type != "All":
            filtered_df = filtered_df[filtered_df['Issue Type'] == filter_type]
        
        # Add filtered results to treeview
        for index, row in filtered_df.iterrows():
            tags = []
            if row['Status'] == 'Open':
                tags = ['open']
            elif row['Status'] == 'Closed':
                tags = ['closed']
            elif row['Status'] == 'Reopened':
                tags = ['reopened']
            
            self.tree.insert('', tk.END, values=(
                row['Sl No'],
                row['Issue Reported Date'],
                row['App Name'],
                row['Issue Type'],
                row['Reported By'],
                row['Status'],
                row['Action Taken By']
            ), tags=tags)
    
    def show_all_issues(self):
        """Show all issues"""
        self.search_var.set("")
        self.filter_status_var.set("All")
        self.filter_type_var.set("All")
        self.load_issues()
    
    def view_details(self):
        """View detailed information of selected issue"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an issue to view details!")
            return
        
        # Get selected issue data
        item = self.tree.item(selection[0])
        sl_no = item['values'][0]
        issue_data = self.issues_df[self.issues_df['Sl No'] == sl_no].iloc[0]
        
        # Create detail window with modern styling
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Issue Details - #{sl_no}")
        detail_window.geometry("700x800")
        detail_window.configure(bg='#f5f5f5')
        
        # Create scrollable frame
        canvas = tk.Canvas(detail_window, bg='#f5f5f5')
        scrollbar = ttk.Scrollbar(detail_window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Title
        title_frame = ttk.Frame(scrollable_frame, padding="20")
        title_frame.pack(fill=tk.X)
        ttk.Label(title_frame, text=f"Issue #{sl_no} - Details", 
                 style='Title.TLabel').pack()
        
        # Details in a card
        details_frame = ttk.LabelFrame(scrollable_frame, text="Issue Information", padding="20")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        row = 0
        for column in self.issues_df.columns:
            # Create field frame
            field_frame = ttk.Frame(details_frame)
            field_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=8, padx=10)
            field_frame.columnconfigure(1, weight=1)
            
            # Field label
            ttk.Label(field_frame, text=f"{column}:", 
                     font=('Segoe UI', 10, 'bold'), width=20).grid(
                row=0, column=0, sticky=(tk.W, tk.N), padx=(0, 15))
            
            value = str(issue_data[column]) if pd.notna(issue_data[column]) else ""
            
            if column in ['Issue Description', 'Action Taken', 'RCA']:
                # Text widget for long text
                text_frame = ttk.Frame(field_frame)
                text_frame.grid(row=0, column=1, sticky=(tk.W, tk.E))
                text_frame.columnconfigure(0, weight=1)
                text_frame.rowconfigure(0, weight=1)
                text_widget = tk.Text(text_frame, height=4, wrap=tk.WORD,
                                    font=('Segoe UI', 10), bg='white', relief='solid', borderwidth=1)
                text_widget.insert(1.0, value)
                text_widget.configure(state='disabled')
                text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            else:
                # Label for short text
                ttk.Label(field_frame, text=value, wraplength=400,
                         font=('Segoe UI', 10)).grid(row=0, column=1, sticky=(tk.W, tk.E))
            
            row += 1
        
        details_frame.columnconfigure(0, weight=1)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def edit_issue(self):
        """Edit selected issue"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an issue to edit!")
            return
        
        # Get selected issue data
        item = self.tree.item(selection[0])
        sl_no = item['values'][0]
        issue_index = self.issues_df[self.issues_df['Sl No'] == sl_no].index[0]
        issue_data = self.issues_df.iloc[issue_index]
        
        # Create edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Edit Issue - #{sl_no}")
        edit_window.geometry("600x800")
        edit_window.configure(bg='#f5f5f5')
        
        # Create scrollable frame
        canvas = tk.Canvas(edit_window, bg='#f5f5f5')
        scrollbar = ttk.Scrollbar(edit_window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Form frame
        form_frame = ttk.LabelFrame(scrollable_frame, text=f"Edit Issue #{sl_no}", padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Store variables for editing
        edit_vars = {}
        
        row = 0
        for column in self.issues_df.columns:
            if column == 'Sl No':
                continue
                
            ttk.Label(form_frame, text=f"{column}:", style='Heading.TLabel').grid(
                row=row, column=0, sticky=tk.W, pady=8)
            
            current_value = str(issue_data[column]) if pd.notna(issue_data[column]) else ""
            
            if column in ['Issue Reported Date', 'Closure Date']:
                # Date fields
                edit_vars[column] = DateEntry(form_frame, width=12, background='#3498db',
                                            foreground='white', borderwidth=2, date_pattern='dd/mm/yyyy',
                                            font=('Segoe UI', 10))
                if current_value:
                    try:
                        date_obj = datetime.strptime(current_value, '%d/%m/%Y').date()
                        edit_vars[column].set_date(date_obj)
                    except:
                        pass
                edit_vars[column].grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
            
            elif column == 'App Name':
                # App name combobox
                edit_vars[column] = tk.StringVar(value=current_value)
                combo = ttk.Combobox(form_frame, textvariable=edit_vars[column],
                                   values=self.masters['applications'], state="normal",
                                   font=('Segoe UI', 10), width=80)
                combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
            
            elif column == 'Action Taken By':
                # Action taken by combobox
                edit_vars[column] = tk.StringVar(value=current_value)
                combo = ttk.Combobox(form_frame, textvariable=edit_vars[column],
                                   values=self.masters['action_taken_by'], state="readonly",
                                   font=('Segoe UI', 10), width=80)
                combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
            
            elif column in ['Issue Type', 'Status']:
                # Readonly combobox fields
                edit_vars[column] = tk.StringVar(value=current_value)
                master_key = 'issue_types' if column == 'Issue Type' else 'statuses'
                combo = ttk.Combobox(form_frame, textvariable=edit_vars[column],
                                   values=self.masters[master_key], state="readonly",
                                   font=('Segoe UI', 10), width=80)
                combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
            
            elif column in ['Issue Description', 'Action Taken', 'RCA']:
                # Text fields
                text_frame = ttk.Frame(form_frame)
                text_frame.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=8, padx=(10, 0))
                text_frame.columnconfigure(0, weight=1)
                text_frame.rowconfigure(0, weight=1)
                edit_vars[column] = tk.Text(text_frame, height=4, font=('Segoe UI', 10),
                                          wrap=tk.WORD, bg='white', relief='solid', borderwidth=1)
                edit_vars[column].insert(1.0, current_value)
                edit_vars[column].grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            else:
                # Entry fields
                edit_vars[column] = tk.StringVar(value=current_value)
                ttk.Entry(form_frame, textvariable=edit_vars[column], 
                         font=('Segoe UI', 10), width=80).grid(row=row, column=1, sticky=(tk.W, tk.E), 
                                                    pady=8, padx=(10, 0))
            
            row += 1
        
        # Configure column weight
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=20)
        
        def save_changes():
            try:
                # Update the DataFrame
                for column in edit_vars:
                    if column in ['Issue Reported Date', 'Closure Date']:
                        self.issues_df.at[issue_index, column] = edit_vars[column].get_date().strftime('%d/%m/%Y')
                    elif column in ['Issue Description', 'Action Taken', 'RCA']:
                        self.issues_df.at[issue_index, column] = edit_vars[column].get(1.0, tk.END).strip()
                    else:
                        self.issues_df.at[issue_index, column] = edit_vars[column].get()
                
                # Save to file
                self.save_issues()
                
                # Refresh view
                self.load_issues()
                
                # Close edit window
                edit_window.destroy()
                
                messagebox.showinfo("Success", f"✅ Issue #{sl_no} updated successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error updating issue: {str(e)}")
        
        ttk.Button(button_frame, text="💾 Save Changes", command=save_changes,
                  style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=edit_window.destroy,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def delete_issue(self):
        """Delete selected issue (Admin only)"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an issue to delete!")
            return
        
        # Get selected issue data
        item = self.tree.item(selection[0])
        sl_no = item['values'][0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete Issue #{sl_no}?"):
            try:
                # Remove from DataFrame
                self.issues_df = self.issues_df[self.issues_df['Sl No'] != sl_no]
                
                # Save to file
                self.save_issues()
                
                # Refresh view
                self.load_issues()
                
                messagebox.showinfo("Success", f"✅ Issue #{sl_no} deleted successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting issue: {str(e)}")
    
    def export_to_excel(self):
        """Export current view to Excel file and open it automatically"""
        try:
            # Ask user for file location
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_filename = f"Issues_Export_{timestamp}.xlsx"
            filename = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
                title="Export Issues to Excel",
                initialfile=default_filename
            )
            
            if filename:
                # Get current filtered data
                current_items = []
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    sl_no = values[0]
                    issue_data = self.issues_df[self.issues_df['Sl No'] == sl_no].iloc[0]
                    current_items.append(issue_data)
                
                if current_items:
                    export_df = pd.DataFrame(current_items)
                    
                    # Save with formatting
                    with pd.ExcelWriter(filename, engine='openpyxl', mode='w') as writer:
                        export_df.to_excel(writer, index=False, sheet_name='Issues Export')
                        
                        # Auto-adjust column widths
                        worksheet = writer.sheets['Issues Export']
                        for column in worksheet.columns:
                            max_length = 0
                            column_letter = column[0].column_letter
                            for cell in column:
                                try:
                                    if len(str(cell.value)) > max_length:
                                        max_length = len(str(cell.value))
                                except:
                                    pass
                            adjusted_width = min(max_length + 2, 50)
                            worksheet.column_dimensions[column_letter].width = adjusted_width
                    
                    messagebox.showinfo("Success", f"✅ Data exported successfully to {filename}")
                    
                    # Automatically open the Excel file
                    try:
                        if platform.system() == 'Darwin':  # macOS
                            subprocess.call(('open', filename))
                        elif platform.system() == 'Windows':  # Windows
                            os.startfile(filename)
                        else:  # Linux
                            subprocess.call(('xdg-open', filename))
                    except Exception as e:
                        messagebox.showinfo("Info", f"File exported successfully but couldn't open automatically: {str(e)}")
                else:
                    messagebox.showwarning("Warning", "No data to export!")
            
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Please ensure you have write access to the selected location and close any open Excel files.")
        except ImportError:
            messagebox.showerror("Error", "The 'openpyxl' module is missing. Please install it using: pip install openpyxl")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting data: {str(e)}. Please try a different location or contact support.")

def main():
    """Main function to run the application"""
    root = tk.Tk()
    try:
        app = IssueTracker(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application failed to start: {str(e)}")
        root.destroy()

if __name__ == "__main__":
    main()