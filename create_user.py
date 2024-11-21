# create_user.py

import tkinter as tk
from tkinter import messagebox
import bcrypt
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from database import get_connection, return_connection
import json
import re
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.tooltip import ToolTip

class CreateUser:
    def __init__(self, master):
        self.master = master
        master.title("Create Account - Ultimate Password Manager")
        master.geometry("600x800")
        master.resizable(True, True)

        # Create main scrolled frame
        self.main_frame = ScrolledFrame(master, autohide=True)
        self.main_frame.pack(expand=True, fill=tk.BOTH)

        self.frame = ttk.Frame(self.main_frame, padding=20)
        self.frame.pack(expand=True, fill=tk.BOTH)

        # Variables
        self.username_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        
        # Password validation variables
        self.password_var.trace_add('write', self.validate_password_strength)
        self.password_requirements = {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'number': False,
            'special': False
        }

        # Title
        title_frame = ttk.Frame(self.frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(
            title_frame,
            text="Create Your Account",
            font=("Helvetica", 24, "bold"),
            bootstyle="primary"
        ).pack()
        ttk.Label(
            title_frame,
            text="Please fill in all fields to create your secure account",
            font=("Helvetica", 10),
            bootstyle="secondary"
        ).pack()

        # Form
        form_frame = ttk.Frame(self.frame)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # Username
        self.create_labeled_entry(form_frame, "Username:", self.username_var, 0)
        ToolTip(self.username_entry, "Choose a unique username")

        # Email
        self.create_labeled_entry(form_frame, "Email:", self.email_var, 1)
        ToolTip(self.email_entry, "Enter a valid email address")

        # Password section
        password_frame = ttk.LabelFrame(form_frame, text="Password", padding=10)
        password_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=10, padx=5)

        # Password entry
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show='*')
        self.password_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

        # Show password toggle
        self.show_password_check = ttk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_show_password,
            bootstyle="round-toggle"
        )
        self.show_password_check.grid(row=0, column=2, padx=5, pady=5)

        # Password requirements frame
        self.requirements_frame = ttk.Frame(password_frame)
        self.requirements_frame.grid(row=1, column=0, columnspan=3, sticky='ew', pady=(5, 0))
        self.create_password_requirements()

        # Confirm Password
        ttk.Label(password_frame, text="Confirm:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.confirm_password_entry = ttk.Entry(password_frame, textvariable=self.confirm_password_var, show='*')
        self.confirm_password_entry.grid(row=2, column=1, sticky='ew', padx=5, pady=5)

        # Security Questions
        security_frame = ttk.LabelFrame(form_frame, text="Security Questions", padding=10)
        security_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=10, padx=5)
        
        ttk.Label(
            security_frame,
            text="Please select and answer three security questions for account recovery",
            wraplength=400
        ).pack(pady=(0, 10))

        self.security_questions = []
        self.populate_security_questions(security_frame)

        # Create Account Button
        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill=tk.X, pady=20)
        create_account_button = ttk.Button(
            button_frame,
            text="Create Account",
            command=self.create_account,
            bootstyle='success-outline',
            width=20
        )
        create_account_button.pack()

        # Bind Enter key
        self.master.bind('<Return>', lambda event: self.create_account())

    def create_labeled_entry(self, parent, label_text, variable, row):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky='ew', padx=5, pady=5)
        setattr(self, f"{label_text.lower().replace(':', '')}_entry", entry)
        return entry

    def create_password_requirements(self):
        requirements = [
            ("Length (min 8 characters)", 'length'),
            ("Uppercase letter", 'uppercase'),
            ("Lowercase letter", 'lowercase'),
            ("Number", 'number'),
            ("Special character", 'special')
        ]
        
        for i, (text, key) in enumerate(requirements):
            frame = ttk.Frame(self.requirements_frame)
            frame.grid(row=i // 2, column=i % 2, padx=5, pady=2, sticky='w')
            
            self.password_requirements[f"{key}_label"] = ttk.Label(
                frame,
                text="✗",
                bootstyle="danger",
                font=("Helvetica", 8)
            )
            self.password_requirements[f"{key}_label"].pack(side=tk.LEFT, padx=(0, 5))
            
            ttk.Label(frame, text=text, font=("Helvetica", 8)).pack(side=tk.LEFT)

    def validate_password_strength(self, *args):
        password = self.password_var.get()
        
        # Update requirements
        self.password_requirements['length'] = len(password) >= 8
        self.password_requirements['uppercase'] = bool(re.search(r'[A-Z]', password))
        self.password_requirements['lowercase'] = bool(re.search(r'[a-z]', password))
        self.password_requirements['number'] = bool(re.search(r'\d', password))
        self.password_requirements['special'] = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        # Update labels
        for key in ['length', 'uppercase', 'lowercase', 'number', 'special']:
            label = self.password_requirements[f"{key}_label"]
            if self.password_requirements[key]:
                label.configure(text="✓", bootstyle="success")
            else:
                label.configure(text="✗", bootstyle="danger")

    def toggle_show_password(self):
        show_char = '' if self.show_password_var.get() else '*'
        self.password_entry.configure(show=show_char)
        self.confirm_password_entry.configure(show=show_char)

    def populate_security_questions(self, parent_frame):
        questions = [
            "What is your mother's maiden name?",
            "What was the name of your first pet?",
            "What is your favorite book?",
            "What city were you born in?",
            "What is your favorite food?",
            "What was the name of your elementary school?",
            "What is your father's middle name?",
            "What was your childhood nickname?",
            "What is your favorite color?",
            "What is your favorite movie?"
        ]

        self.selected_questions = []
        for i in range(3):
            question_frame = ttk.Frame(parent_frame)
            question_frame.pack(fill=tk.X, pady=5)

            question_var = tk.StringVar()
            answer_var = tk.StringVar()
            show_answer_var = tk.BooleanVar(value=False)

            ttk.Label(question_frame, text=f"Question {i+1}:").pack(anchor='w')
            question_combobox = ttk.Combobox(
                question_frame,
                textvariable=question_var,
                values=questions,
                state='readonly',
                width=50
            )
            question_combobox.pack(fill=tk.X, pady=(0, 5))
            question_combobox.current(i)

            answer_frame = ttk.Frame(question_frame)
            answer_frame.pack(fill=tk.X)

            ttk.Label(answer_frame, text=f"Answer:").pack(side=tk.LEFT)
            answer_entry = ttk.Entry(answer_frame, textvariable=answer_var, show='*')
            answer_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))

            show_answer_check = ttk.Checkbutton(
                answer_frame,
                text="Show",
                variable=show_answer_var,
                command=lambda e=answer_entry, v=show_answer_var: self.toggle_answer_visibility(e, v),
                bootstyle="round-toggle"
            )
            show_answer_check.pack(side=tk.LEFT)

            self.security_questions.append({
                'question_var': question_var,
                'answer_var': answer_var,
                'show_var': show_answer_var
            })

    def toggle_answer_visibility(self, entry, var):
        entry.configure(show='' if var.get() else '*')

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password_requirements(self):
        return all(self.password_requirements[key] for key in ['length', 'uppercase', 'lowercase', 'number', 'special'])

    def create_account(self):
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        confirm_password = self.confirm_password_var.get().strip()

        # Validation
        if not username or not email or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if not self.validate_email(email):
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        if not self.validate_password_requirements():
            messagebox.showerror("Error", "Password does not meet all requirements.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Validate security questions
        security_questions_data = []
        used_questions = set()
        for idx, qa in enumerate(self.security_questions):
            question = qa['question_var'].get().strip()
            answer = qa['answer_var'].get().strip()
            
            if not question or not answer:
                messagebox.showerror("Error", f"Please answer security question {idx + 1}.")
                return
                
            if question in used_questions:
                messagebox.showerror("Error", "Please select different security questions.")
                return
                
            used_questions.add(question)
            hashed_answer = bcrypt.hashpw(answer.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            security_questions_data.append({'question': question, 'answer_hash': hashed_answer})

        security_questions_json = json.dumps(security_questions_data)

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert the new user into the database
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Check username
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username already exists.")
                cursor.close()
                return_connection(conn)
                return

            # Check email
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Email address already registered.")
                cursor.close()
                return_connection(conn)
                return

            cursor.execute(
                "INSERT INTO users (username, email, password_hash, security_questions) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, security_questions_json)
            )
            conn.commit()
            cursor.close()
            return_connection(conn)
            
            messagebox.showinfo("Success", "Account created successfully! You can now log in.")
            self.master.destroy()
            
        except Exception as e:
            messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
            if 'cursor' in locals():
                cursor.close()
            return_connection(conn)
