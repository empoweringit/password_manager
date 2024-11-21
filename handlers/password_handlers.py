import tkinter as tk
from tkinter import messagebox
import threading
import pyperclip
from ..utils.password_utils import generate_password, assess_strength, get_password_recommendations

class PasswordHandlers:
    def __init__(self, app):
        self.app = app
        
    def generate_password_event(self):
        """Handle password generation event."""
        try:
            length = int(self.app.length_var.get())
            if length < 4 or length > 128:
                raise ValueError("Password length must be between 4 and 128.")
                
            count = int(self.app.multiple_var.get())
            if count < 1 or count > 20:
                raise ValueError("Number of passwords must be between 1 and 20.")
                
            # Generate passwords
            passwords = []
            for _ in range(count):
                pwd = generate_password(
                    length=length,
                    use_upper=self.app.use_upper_var.get(),
                    use_lower=self.app.use_lower_var.get(),
                    use_digits=self.app.use_digits_var.get(),
                    use_punctuation=self.app.use_punctuation_var.get(),
                    exclude_similar=self.app.exclude_similar_var.get()
                )
                passwords.append(pwd)
                
            # Display passwords
            self.app.password_display.configure(state='normal')
            self.app.password_display.delete('1.0', tk.END)
            
            if count == 1:
                self.app.password_display.insert('1.0', passwords[0])
                self._update_password_feedback(passwords[0])
            else:
                for idx, pwd in enumerate(passwords, 1):
                    self.app.password_display.insert(tk.END, f"{idx}. {pwd}\n")
                self.app.update_strength_display("Varied", 50, 'info')
                self.app.feedback_var.set("")
                
            self.app.password_display.configure(state='disabled')
            self.app.status_var.set(f"{count} password(s) generated successfully!")
            self.app.status_label.configure(bootstyle="success")
            
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
            self.app.status_var.set("")
            self.app.update_strength_display()
            
    def _update_password_feedback(self, password):
        """Update password strength and feedback."""
        strength_label, value, color, entropy = assess_strength(password)
        self.app.update_strength_display(strength_label, value, color)
        
        settings = {
            'use_upper': self.app.use_upper_var.get(),
            'use_lower': self.app.use_lower_var.get(),
            'use_digits': self.app.use_digits_var.get(),
            'use_punctuation': self.app.use_punctuation_var.get(),
            'exclude_similar': self.app.exclude_similar_var.get()
        }
        
        feedback = f"Entropy: {entropy:.2f} bits.\n"
        if strength_label in ["Weak", "Moderate"]:
            recommendations = get_password_recommendations(password, settings)
            feedback += "Recommendations:\n- " + "\n- ".join(recommendations)
        else:
            feedback += "Your password is strong."
            
        self.app.feedback_var.set(feedback)
        
    def copy_to_clipboard(self):
        """Copy generated password(s) to clipboard."""
        passwords = self.app.password_display.get('1.0', tk.END).strip()
        if passwords:
            pyperclip.copy(passwords)
            self.app.status_var.set("Password(s) copied to clipboard! It will be cleared in 30 seconds.")
            self.app.status_label.configure(bootstyle="success")
            threading.Timer(30.0, self.clear_clipboard).start()
        else:
            self.app.status_var.set("No password to copy.")
            self.app.status_label.configure(bootstyle="danger")
            
    def clear_clipboard(self):
        """Clear clipboard after timeout."""
        pyperclip.copy('')
        self.app.status_var.set("Clipboard cleared.")
        self.app.status_label.configure(bootstyle="info")
