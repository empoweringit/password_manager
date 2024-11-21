# login_screen.py

import tkinter as tk
from tkinter import messagebox
import bcrypt
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from crud import get_user_by_username, update_user_password
from create_user import CreateUser
import json
import time
from ttkbootstrap.tooltip import ToolTip
from ttkbootstrap.dialogs import Messagebox, Dialog
import re
import webbrowser
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.style import Style
import os

class AboutDialog(Dialog):
    def __init__(self, parent):
        super().__init__(
            parent=parent,
            title="About Ultimate Password Manager"
        )

    def create_body(self, parent):
        frame = ttk.Frame(parent, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(
            frame,
            text="Ultimate Password Manager",
            font=("Helvetica", 20, "bold"),
            bootstyle="primary"
        )
        title_label.pack(pady=(0, 10))

        # Description
        desc_frame = ttk.LabelFrame(frame, text="About Us", padding=10)
        desc_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(
            desc_frame,
            text="Your secure digital vault for all your passwords and sensitive information.",
            wraplength=400,
            justify=tk.LEFT,
            bootstyle="primary"
        ).pack(pady=5)

        # Features frame
        features_frame = ttk.LabelFrame(frame, text="Key Features", padding=10)
        features_frame.pack(fill=tk.X, pady=10)

        features = [
            "🔒 Military-grade encryption (AES-256)",
            "🔄 Automatic cloud backup",
            "👥 Secure password sharing",
            "🔍 Password health checker",
            "📱 Cross-platform support"
        ]

        for feature in features:
            ttk.Label(
                features_frame,
                text=feature,
                wraplength=400,
                justify=tk.LEFT,
                bootstyle="primary"
            ).pack(anchor='w', pady=2)

        # Pricing frame
        pricing_frame = ttk.LabelFrame(frame, text="Pricing Plans", padding=10)
        pricing_frame.pack(fill=tk.X, pady=10)

        # Free plan
        free_frame = ttk.Frame(pricing_frame)
        free_frame.pack(side=tk.LEFT, padx=10, expand=True)
        ttk.Label(
            free_frame,
            text="Free",
            font=("Helvetica", 12, "bold"),
            bootstyle="primary"
        ).pack()
        ttk.Label(
            free_frame,
            text="$0/month",
            bootstyle="primary"
        ).pack()
        ttk.Label(
            free_frame,
            text="Basic features",
            bootstyle="primary"
        ).pack()

        # Premium plan
        premium_frame = ttk.Frame(pricing_frame)
        premium_frame.pack(side=tk.LEFT, padx=10, expand=True)
        ttk.Label(
            premium_frame,
            text="Premium",
            font=("Helvetica", 12, "bold"),
            bootstyle="primary"
        ).pack()
        ttk.Label(
            premium_frame,
            text="$4.99/month",
            bootstyle="primary"
        ).pack()
        ttk.Label(
            premium_frame,
            text="All features",
            bootstyle="primary"
        ).pack()

        return frame

class PrivacyPolicyDialog(Dialog):
    def __init__(self, parent):
        super().__init__(
            parent=parent,
            title="Privacy Policy"
        )

    def create_body(self, parent):
        frame = ttk.Frame(parent, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Create a canvas with scrollbar
        canvas = tk.Canvas(frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Title
        ttk.Label(
            scrollable_frame,
            text="Privacy Policy",
            font=("Helvetica", 20, "bold"),
            bootstyle="primary"
        ).pack(pady=(0, 10))

        sections = [
            ("Information We Collect", [
                "• Account credentials (encrypted)",
                "• Usage statistics",
                "• Device information",
                "• Email address"
            ]),
            ("How We Use Your Data", [
                "• Provide password management",
                "• Improve our services",
                "• Send important updates",
                "• Maintain security"
            ]),
            ("Your Rights", [
                "• Access your data",
                "• Delete your account",
                "• Export your data",
                "• Update preferences"
            ]),
            ("Security Measures", [
                "• End-to-end encryption",
                "• Regular security audits",
                "• Zero-knowledge architecture",
                "• Secure data centers"
            ])
        ]

        for title, items in sections:
            section_frame = ttk.LabelFrame(scrollable_frame, text=title, padding=10)
            section_frame.pack(fill=tk.X, pady=5)
            
            for item in items:
                ttk.Label(
                    section_frame,
                    text=item,
                    wraplength=400,
                    justify=tk.LEFT,
                    bootstyle="primary"
                ).pack(anchor='w', pady=2)

        # Pack the canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return frame

class LoginScreen:
    def __init__(self, master):
        self.master = master
        self.user = None
        self.login_attempts = 0
        self.last_attempt_time = 0

        # Initialize theme
        self.style = Style()
        self.current_theme = tk.StringVar(value=self.style.theme.name)

        # Create a Toplevel window for the login screen
        self.top_level = ttk.Toplevel(master)
        self.top_level.title("Ultimate Password Manager")
        self.top_level.geometry("600x800")
        self.top_level.resizable(True, True)
        self.top_level.protocol("WM_DELETE_WINDOW", self.on_close)

        # Center the window
        self.center_window()

        # Variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.remember_me_var = tk.BooleanVar(value=False)

        # Main container with scrolling
        self.main_container = ScrolledFrame(self.top_level, autohide=True)
        self.main_container.pack(expand=True, fill=tk.BOTH)

        self.content_frame = ttk.Frame(self.main_container, padding=20)
        self.content_frame.pack(expand=True, fill=tk.BOTH)

        # Create sections
        self.create_header()
        self.create_welcome_section()
        self.create_login_form()
        self.create_additional_options()
        self.create_footer()

        # Bind events
        self.bind_events()

        # Configure responsive behavior
        self.configure_responsive_layout()

        # Set focus
        self.username_entry.focus()

    def configure_responsive_layout(self):
        """Configure responsive layout behavior"""
        self.top_level.bind('<Configure>', self.on_window_resize)
        
        # Make sure content adjusts to window size
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Minimum window size
        self.top_level.minsize(400, 600)

    def on_window_resize(self, event):
        """Handle window resize events"""
        width = event.width
        
        # Adjust font sizes based on window width
        if width < 500:
            title_size = 20
            subtitle_size = 12
            body_size = 9
        else:
            title_size = 24
            subtitle_size = 14
            body_size = 10

        # Update font sizes
        for widget in self.content_frame.winfo_children():
            if isinstance(widget, ttk.Label):
                current_font = widget.cget("font")
                if "bold" in str(current_font).lower():
                    widget.configure(font=("Helvetica", title_size, "bold"))
                else:
                    widget.configure(font=("Helvetica", body_size))

    def create_header(self):
        """Create header with theme selector and info buttons"""
        header_frame = ttk.Frame(self.content_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Theme selector
        theme_frame = ttk.Frame(header_frame)
        theme_frame.pack(side=tk.LEFT)

        ttk.Label(
            theme_frame,
            text="Theme:",
            bootstyle="primary"
        ).pack(side=tk.LEFT, padx=(0, 5))

        themes = ttk.Combobox(
            theme_frame,
            textvariable=self.current_theme,
            values=self.style.theme_names(),
            state="readonly",
            width=15
        )
        themes.pack(side=tk.LEFT)
        themes.bind('<<ComboboxSelected>>', self.change_theme)

        # Info buttons
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.RIGHT)

        ttk.Button(
            info_frame,
            text="About",
            command=self.show_about,
            bootstyle="info-link"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            info_frame,
            text="Privacy Policy",
            command=self.show_privacy_policy,
            bootstyle="info-link"
        ).pack(side=tk.LEFT, padx=5)

    def create_welcome_section(self):
        """Create the welcome section with logo and greeting"""
        welcome_frame = ttk.Frame(self.content_frame)
        welcome_frame.pack(fill=tk.X, pady=(0, 20))

        # App title
        ttk.Label(
            welcome_frame,
            text="Ultimate Password Manager",
            font=("Helvetica", 24, "bold"),
            bootstyle="primary"
        ).pack()

        # Welcome message
        self.welcome_label = ttk.Label(
            welcome_frame,
            text="Welcome to Password Manager",
            font=("Helvetica", 14, "bold"),
            bootstyle="primary"
        )
        self.welcome_label.pack(pady=5)

        # Feature highlights with better contrast
        features_frame = ttk.Frame(welcome_frame)
        features_frame.pack(pady=10)

        features = [
            "🔒 Military-grade encryption",
            "🔄 Cross-platform sync",
            "👥 Secure sharing",
            "📱 Mobile access"
        ]

        for feature in features:
            ttk.Label(
                features_frame,
                text=feature,
                font=("Helvetica", 10),
                bootstyle="primary",
                padding=5
            ).pack(pady=2)

    def create_login_form(self):
        """Create the main login form"""
        form_frame = ttk.Frame(self.content_frame)
        form_frame.pack(fill=tk.BOTH, expand=True, pady=20)

        # Username field with better contrast
        username_container = ttk.Frame(form_frame)
        username_container.pack(fill=tk.X, pady=5)
        
        ttk.Label(
            username_container,
            text="Username",
            font=("Helvetica", 10, "bold"),
            bootstyle="primary"
        ).pack(anchor='w')
        
        self.username_entry = ttk.Entry(
            username_container,
            textvariable=self.username_var,
            width=40,
            bootstyle="primary"
        )
        self.username_entry.pack(fill=tk.X, pady=(5, 0))

        # Password field with better contrast
        password_container = ttk.Frame(form_frame)
        password_container.pack(fill=tk.X, pady=15)
        
        ttk.Label(
            password_container,
            text="Password",
            font=("Helvetica", 10, "bold"),
            bootstyle="primary"
        ).pack(anchor='w')
        
        password_entry_container = ttk.Frame(password_container)
        password_entry_container.pack(fill=tk.X, pady=(5, 0))
        
        self.password_entry = ttk.Entry(
            password_entry_container,
            textvariable=self.password_var,
            show='•',
            width=40,
            bootstyle="primary"
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Show/Hide password button
        self.show_password_check = ttk.Checkbutton(
            password_entry_container,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_show_password,
            bootstyle="round-toggle-primary"
        )
        self.show_password_check.pack(side=tk.LEFT, padx=(5, 0))

        # Options row
        options_frame = ttk.Frame(form_frame)
        options_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(
            options_frame,
            text="Remember me",
            variable=self.remember_me_var,
            bootstyle="round-toggle-primary"
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            options_frame,
            text="Forgot Password?",
            command=self.open_forgot_password,
            bootstyle="link-primary"
        ).pack(side=tk.RIGHT)

        # Login button
        self.login_button = ttk.Button(
            form_frame,
            text="Login",
            command=self.login_user,
            bootstyle="primary",
            width=20
        )
        self.login_button.pack(pady=20)

        # Trial info with better contrast
        trial_frame = ttk.Frame(form_frame)
        trial_frame.pack(fill=tk.X, pady=10)

        ttk.Label(
            trial_frame,
            text="Start with a 30-day free trial, no credit card required",
            font=("Helvetica", 9),
            bootstyle="primary",
            padding=5
        ).pack()

    def open_social(self, platform):
        """Handle social media button clicks with local message"""
        Messagebox.show_info(
            f"Social media integration coming soon!\nFollow us on {platform} for updates.",
            "Coming Soon",
            parent=self.top_level
        )

    def change_theme(self, event):
        """Change the application theme"""
        selected_theme = self.current_theme.get()
        self.style.theme_use(selected_theme)

    def show_about(self):
        """Show the about dialog"""
        AboutDialog(self.top_level)

    def show_privacy_policy(self):
        """Show the privacy policy dialog"""
        PrivacyPolicyDialog(self.top_level)

    def center_window(self):
        """Center the window on the screen"""
        self.top_level.update_idletasks()
        width = self.top_level.winfo_width()
        height = self.top_level.winfo_height()
        x = (self.top_level.winfo_screenwidth() // 2) - (width // 2)
        y = (self.top_level.winfo_screenheight() // 2) - (height // 2)
        self.top_level.geometry(f'{width}x{height}+{x}+{y}')

    def bind_events(self):
        """Bind various events to the window"""
        self.top_level.bind('<Return>', lambda event: self.login_user())
        self.username_entry.bind('<Tab>', lambda event: self.password_entry.focus())
        self.password_entry.bind('<Shift-Tab>', lambda event: self.username_entry.focus())

    def toggle_show_password(self):
        """Toggle password visibility"""
        self.password_entry.configure(show='' if self.show_password_var.get() else '•')

    def validate_login_attempt(self):
        """Validate login attempt timing"""
        current_time = time.time()
        
        # Check if we need to reset attempts
        if current_time - self.last_attempt_time > 300:  # 5 minutes
            self.login_attempts = 0
            
        # Check if too many attempts
        if self.login_attempts >= 5:
            time_remaining = int(300 - (current_time - self.last_attempt_time))
            if time_remaining > 0:
                Messagebox.show_error(
                    f"Too many failed attempts. Please try again in {time_remaining} seconds.",
                    "Login Blocked",
                    parent=self.top_level
                )
                return False
            else:
                self.login_attempts = 0
                
        return True

    def login_user(self):
        """Handle user login"""
        if not self.validate_login_attempt():
            return

        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        print(f"Attempting login with username: {username}")  # Debug log

        # Input validation
        if not username or not password:
            self.welcome_label.config(
                text="Please enter both username and password.",
                foreground="red"
            )
            return

        try:
            from crud import get_user_by_username
            
            # Get user from database
            user = get_user_by_username(username)
            print(f"User found: {user is not None}")  # Debug log
            
            if user:
                print(f"User ID: {user['id']}")  # Debug log
                print(f"Stored hash: {user['password_hash']}")  # Debug log
                
                # Convert password to bytes if it isn't already
                password_bytes = password.encode('utf-8')
                hash_bytes = user['password_hash'].encode('utf-8')
                
                is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
                print(f"Password verification result: {is_valid}")  # Debug log
                
                if is_valid:
                    # Store user info
                    self.user = {'id': user['id'], 'username': user['username']}
                    
                    # Show welcome message in status label
                    self.welcome_label.config(
                        text=f"Welcome back, {user['username']}!",
                        foreground="green"
                    )
                    self.top_level.update()
                    
                    # Wait briefly to show the welcome message
                    self.top_level.after(800, self.top_level.destroy)
                else:
                    print("Password verification failed")  # Debug log
                    self.handle_failed_login()
            else:
                print(f"No user found with username: {username}")  # Debug log
                self.handle_failed_login()
                
        except Exception as e:
            print(f"Login error: {str(e)}")  # Debug log
            self.welcome_label.config(
                text="Invalid username or password. Please try again.",
                foreground="red"
            )

    def handle_failed_login(self):
        """Handle failed login attempt"""
        self.login_attempts += 1
        self.last_attempt_time = time.time()
        
        remaining_attempts = 5 - self.login_attempts
        message = "Invalid username or password."
        if remaining_attempts > 0:
            message += f"\nRemaining attempts: {remaining_attempts}"
        
        self.welcome_label.config(
            text=message,
            foreground="red"
        )

    def open_create_account(self):
        """Open the create account window"""
        create_account_window = ttk.Toplevel(self.top_level)
        app = CreateUser(create_account_window)
        self.top_level.wait_window(create_account_window)

    def open_forgot_password(self):
        """Open the forgot password window"""
        forgot_password_window = ttk.Toplevel(self.top_level)
        app = ForgotPassword(forgot_password_window)
        self.top_level.wait_window(forgot_password_window)

    def on_close(self):
        """Handle window close event"""
        self.top_level.destroy()

    def create_additional_options(self):
        """Create additional options section"""
        options_frame = ttk.Frame(self.content_frame)
        options_frame.pack(fill=tk.X, pady=10)

        # New account section
        account_frame = ttk.Frame(options_frame)
        account_frame.pack(pady=5)

        ttk.Label(
            account_frame,
            text="Don't have an account?",
            bootstyle="primary"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            account_frame,
            text="Create Account",
            command=self.open_create_account,
            bootstyle="link-primary"
        ).pack(side=tk.LEFT)

    def create_footer(self):
        """Create footer section"""
        footer_frame = ttk.Frame(self.content_frame)
        footer_frame.pack(fill=tk.X, pady=20)

        # Social links
        social_frame = ttk.Frame(footer_frame)
        social_frame.pack(pady=5)

        for platform in ["Twitter", "Facebook", "LinkedIn"]:
            ttk.Button(
                social_frame,
                text=platform,
                command=lambda p=platform: self.open_social(p),
                bootstyle="link-primary"
            ).pack(side=tk.LEFT, padx=5)

        # Copyright
        ttk.Label(
            footer_frame,
            text=" 2024 Ultimate Password Manager. All rights reserved.",
            bootstyle="primary",
            font=("Helvetica", 8)
        ).pack(pady=5)

class ForgotPassword:
    def __init__(self, master):
        self.master = master
        master.title("Forgot Password")
        master.geometry("500x500")
        master.resizable(False, False)

        self.username_var = tk.StringVar()
        self.new_password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)

        self.frame = ttk.Frame(master, padding=20)
        self.frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(self.frame, text="Forgot Password", font=("Helvetica", 20, "bold")).pack(pady=10)

        # Initial Form Frame
        self.initial_form_frame = ttk.Frame(self.frame)
        self.initial_form_frame.pack(fill=tk.BOTH, expand=True)

        # Username Label and Entry
        ttk.Label(self.initial_form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.initial_form_frame, textvariable=self.username_var)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.focus()

        # Next Button
        next_button = ttk.Button(self.initial_form_frame, text="Next", command=self.load_security_questions, bootstyle='primary')
        next_button.grid(row=1, column=0, columnspan=2, pady=10)

    def load_security_questions(self):
        username = self.username_var.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter your username.", parent=self.master)
            return

        try:
            user = get_user_by_username(username)
            if user:
                security_questions_json = user.get('security_questions')
                if not security_questions_json:
                    messagebox.showerror("Error", "No security questions found for this user.", parent=self.master)
                    return

                self.user = user  # Store the user data for later use
                security_questions = json.loads(security_questions_json)

                # Destroy the initial form frame
                self.initial_form_frame.destroy()

                # Create a new frame for security questions and password reset
                self.reset_form_frame = ttk.Frame(self.frame)
                self.reset_form_frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(self.reset_form_frame, text="Answer the following security questions:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=5)

                self.security_questions_vars = []
                row_index = 1
                for idx, qa in enumerate(security_questions):
                    question = qa['question']
                    answer_var = tk.StringVar()

                    ttk.Label(self.reset_form_frame, text=f"Question {idx + 1}: {question}").grid(row=row_index, column=0, sticky=tk.W, padx=5, pady=5)
                    answer_entry = ttk.Entry(self.reset_form_frame, textvariable=answer_var, show='*', width=40)
                    answer_entry.grid(row=row_index, column=1, padx=5, pady=5)
                    row_index += 1

                    self.security_questions_vars.append({
                        'question': question,
                        'answer_var': answer_var,
                        'answer_hash': qa['answer_hash'],
                        'answer_entry': answer_entry  # Store the entry widget
                    })

                # New Password Fields
                ttk.Label(self.reset_form_frame, text="New Password:").grid(row=row_index, column=0, sticky=tk.W, padx=5, pady=5)
                self.new_password_entry = ttk.Entry(self.reset_form_frame, textvariable=self.new_password_var, show='*', width=40)
                self.new_password_entry.grid(row=row_index, column=1, padx=5, pady=5)
                row_index +=1

                ttk.Label(self.reset_form_frame, text="Confirm New Password:").grid(row=row_index, column=0, sticky=tk.W, padx=5, pady=5)
                self.confirm_password_entry = ttk.Entry(self.reset_form_frame, textvariable=self.confirm_password_var, show='*', width=40)
                self.confirm_password_entry.grid(row=row_index, column=1, padx=5, pady=5)
                row_index +=1

                # Show Password Checkbox
                self.show_password_check = ttk.Checkbutton(
                    self.reset_form_frame,
                    text="Show Password",
                    variable=self.show_password_var,
                    command=self.toggle_show_password
                )
                self.show_password_check.grid(row=row_index, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
                row_index +=1

                # Reset Password Button
                reset_button = ttk.Button(self.reset_form_frame, text="Reset Password", command=self.reset_password, bootstyle='success')
                reset_button.grid(row=row_index, column=0, columnspan=2, pady=10)
            else:
                messagebox.showerror("Error", "Username not found.", parent=self.master)
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}", parent=self.master)

    def toggle_show_password(self):
        if self.show_password_var.get():
            self.new_password_entry.configure(show='')
            self.confirm_password_entry.configure(show='')
            # Also, show/hide the security answers
            for qa in self.security_questions_vars:
                answer_entry = qa.get('answer_entry')
                if answer_entry:
                    answer_entry.configure(show='')
        else:
            self.new_password_entry.configure(show='*')
            self.confirm_password_entry.configure(show='*')
            for qa in self.security_questions_vars:
                answer_entry = qa.get('answer_entry')
                if answer_entry:
                    answer_entry.configure(show='*')

    def reset_password(self):
        # Verify the security answers
        for idx, qa in enumerate(self.security_questions_vars):
            user_answer = qa['answer_var'].get().strip()
            if not user_answer:
                messagebox.showerror("Error", f"Please answer security question {idx + 1}.", parent=self.master)
                return

            stored_answer_hash = qa['answer_hash']
            if not bcrypt.checkpw(user_answer.encode('utf-8'), stored_answer_hash.encode('utf-8')):
                messagebox.showerror("Error", f"Incorrect answer for security question {idx + 1}.", parent=self.master)
                return

        # Verify new password fields
        new_password = self.new_password_var.get().strip()
        confirm_password = self.confirm_password_var.get().strip()

        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Please enter the new password and confirm it.", parent=self.master)
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.", parent=self.master)
            return

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update the password in the database
        try:
            update_user_password(self.user['id'], hashed_password)
            messagebox.showinfo("Success", "Password reset successfully. You can now log in.", parent=self.master)
            self.master.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}", parent=self.master)
