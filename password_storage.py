import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from crud import create_entry
from config import encryption_manager
import logging
import datetime

logger = logging.getLogger(__name__)

class PasswordStorageDialog:
    def __init__(self, parent, password, user_id=None, is_passphrase=False):
        """Initialize the password storage dialog
        
        Args:
            parent: The parent widget
            password: The password to store
            user_id: The user ID to associate with the password
            is_passphrase: Whether the password is a passphrase
        """
        self.parent = parent
        self.password = password
        self.user_id = user_id
        self.is_passphrase = is_passphrase
        
        # Configure styles
        style = ttk.Style()
        style.configure("Passphrase.TEntry", fieldbackground="#E6F3FF")  # Light blue background
        style.configure("Passphrase.Treeview", background="#E6F3FF")
        style.configure("Passphrase.TFrame", background="#E6F3FF")
        
        self.dialog = None
        self.setup_dialog()
    
    def setup_dialog(self):
        """Setup the storage dialog"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Store Passphrase" if self.is_passphrase else "Store Password")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(
            self.dialog,
            padding="10",
            style="Passphrase.TFrame" if self.is_passphrase else ""
        )
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top button frame
        top_button_frame = ttk.Frame(main_frame)
        top_button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Add New button
        self.add_new_button = ttk.Button(
            top_button_frame,
            text="Add New Entry",
            command=self.add_new_entry,
            bootstyle=SUCCESS
        )
        self.add_new_button.pack(side=tk.LEFT, padx=5)
        
        # Generate Password button (initially disabled)
        self.generate_button = ttk.Button(
            top_button_frame,
            text="Generate Password",
            command=self.generate_password,
            state=DISABLED,
            bootstyle=INFO
        )
        self.generate_button.pack(side=tk.LEFT, padx=5)
        
        # Entry fields
        self.setup_entry_fields(main_frame)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame,
            text="Save",
            command=self.save_entry,
            bootstyle="primary"
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy,
            bootstyle="secondary"
        ).pack(side=tk.RIGHT)
    
    def setup_entry_fields(self, parent):
        """Setup the entry fields"""
        # Title
        title_frame = ttk.Frame(parent)
        title_frame.pack(fill=tk.X, pady=5)
        ttk.Label(title_frame, text="Title:").pack(side=tk.LEFT)
        self.title_var = tk.StringVar()
        ttk.Entry(
            title_frame,
            textvariable=self.title_var,
            style="Passphrase.TEntry" if self.is_passphrase else ""
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Website
        website_frame = ttk.Frame(parent)
        website_frame.pack(fill=tk.X, pady=5)
        ttk.Label(website_frame, text="Website:").pack(side=tk.LEFT)
        self.website_var = tk.StringVar()
        ttk.Entry(
            website_frame,
            textvariable=self.website_var,
            style="Passphrase.TEntry" if self.is_passphrase else ""
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Username/Email
        username_frame = ttk.Frame(parent)
        username_frame.pack(fill=tk.X, pady=5)
        ttk.Label(username_frame, text="Username:").pack(side=tk.LEFT)
        self.username_var = tk.StringVar()
        ttk.Entry(
            username_frame,
            textvariable=self.username_var,
            style="Passphrase.TEntry" if self.is_passphrase else ""
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Password
        password_frame = ttk.Frame(parent)
        password_frame.pack(fill=tk.X, pady=5)
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            style="Passphrase.TEntry" if self.is_passphrase else ""
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Notes
        notes_frame = ttk.Frame(parent)
        notes_frame.pack(fill=tk.X, pady=5)
        ttk.Label(notes_frame, text="Notes:").pack(side=tk.LEFT)
        self.notes_var = tk.StringVar()
        ttk.Entry(
            notes_frame,
            textvariable=self.notes_var,
            style="Passphrase.TEntry" if self.is_passphrase else ""
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    
    def save_entry(self):
        """Save the password/passphrase entry to the database"""
        try:
            # Get values from entry fields
            title = self.title_var.get()
            website = self.website_var.get()
            username = self.username_var.get()
            password = self.password_var.get()
            notes = self.notes_var.get()
            
            # Create entry with appropriate passphrase handling
            create_entry(
                user_id=self.user_id,
                title=title,
                username=username,
                encrypted_password=encryption_manager.encrypt(password),
                url=website,
                notes=notes,
                pass_phrase=password if self.is_passphrase else None
            )
            
            messagebox.showinfo(
                "Success",
                "Passphrase saved successfully!" if self.is_passphrase else "Password saved successfully!"
            )
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")
    
    def add_new_entry(self):
        """Handle add new entry button click"""
        self.clear_fields()
        self.generate_button.configure(state=NORMAL)
        self.add_new_button.configure(text="Cancel")

    def generate_password(self):
        """Generate a new password using the utility"""
        from password_utils import generate_password
        
        # Generate a secure password with default settings
        password = generate_password(
            length=16,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_punctuation=True
        )
        
        # Set the generated password
        self.password_var.set(password)

    def clear_fields(self):
        """Clear all entry fields"""
        self.title_var.set("")
        self.website_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        self.notes_var.set("")
    
    def show(self):
        """Show the dialog"""
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        self.dialog.mainloop()
