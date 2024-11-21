import tkinter as tk
from tkinter import messagebox
import secrets
import string
import pyperclip
import json
import os
import logging
from ..utils.password_utils import generate_password, assess_strength, get_password_recommendations

logger = logging.getLogger(__name__)

class PasswordGeneratorHandlers:
    def __init__(self, app):
        self.app = app
        self.word_lists_file = "word_lists.json"
        self.load_word_lists()

    def load_word_lists(self):
        """Load word lists from JSON file"""
        try:
            if os.path.exists(self.word_lists_file):
                with open(self.word_lists_file, 'r') as f:
                    self.app.categorized_word_lists = json.load(f)
            else:
                self.app.categorized_word_lists = {}
                self.save_word_lists()
        except Exception as e:
            logger.error(f"Error loading word lists: {str(e)}")
            messagebox.showerror("Error", "Failed to load word lists")
            self.app.categorized_word_lists = {}

    def save_word_lists(self, word_lists=None):
        """Save word lists to JSON file"""
        try:
            if word_lists is None:
                word_lists = self.app.categorized_word_lists
            with open(self.word_lists_file, 'w') as f:
                json.dump(word_lists, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving word lists: {str(e)}")
            messagebox.showerror("Error", "Failed to save word lists")

    def toggle_preset_word_options(self):
        """Toggle preset word options based on checkbox state"""
        state = 'readonly' if self.app.include_preset_word_var.get() else 'disabled'
        self.app.password_tab.preset_category_dropdown.configure(state=state)
        self.app.password_tab.preset_word_dropdown.configure(state=state)

    def update_preset_word_options(self, event=None):
        """Update preset word options when category is selected"""
        category = self.app.preset_category_var.get()
        if category in self.app.categorized_word_lists:
            self.app.password_tab.preset_word_dropdown['values'] = self.app.categorized_word_lists[category]
            if self.app.categorized_word_lists[category]:
                self.app.preset_word_var.set(self.app.categorized_word_lists[category][0])

    def toggle_custom_word_entry(self):
        """Toggle custom word entry based on checkbox state"""
        state = 'normal' if self.app.include_custom_word_var.get() else 'disabled'
        self.app.password_tab.custom_word_entry.configure(state=state)

    def validate_length(self, event=None):
        """Validate password length input"""
        try:
            length = int(self.app.length_var.get())
            if 4 <= length <= 128:
                self.app.password_tab.generate_button.configure(state=NORMAL)
                return True
            else:
                self.app.password_tab.generate_button.configure(state=DISABLED)
                messagebox.showerror("Invalid Length", "Password length must be between 4 and 128")
                return False
        except ValueError:
            self.app.password_tab.generate_button.configure(state=DISABLED)
            messagebox.showerror("Invalid Input", "Please enter a valid number")
            return False

    def generate_password_event(self):
        """Handle password generation event"""
        try:
            passwords = self.generate_password()
            if passwords:
                # Enable password display and set text
                self.app.password_tab.password_display.configure(state='normal')
                self.app.password_tab.password_display.delete(1.0, tk.END)
                self.app.password_tab.password_display.insert(tk.END, "\n".join(passwords))
                self.app.password_tab.password_display.configure(state='disabled')

                # Update strength for the first password
                if passwords:
                    strength, feedback = assess_strength(passwords[0])
                    self.app.update_strength_display(strength)
                    self.app.feedback_var.set(feedback)
                    recommendations = get_password_recommendations(passwords[0])
                    if recommendations:
                        self.app.feedback_var.set(f"{feedback}\n\nRecommendations:\n{recommendations}")

                self.app.status_var.set("Password(s) generated successfully!")
                logger.info("Password(s) generated successfully")

        except Exception as e:
            logger.error(f"Error generating password: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def generate_password(self):
        """Generate password(s) based on selected options"""
        try:
            length = int(self.app.length_var.get())
            num_passwords = self.app.multiple_var.get()
            
            # Validate input
            if not (4 <= length <= 128):
                messagebox.showerror("Invalid Length", "Password length must be between 4 and 128")
                return None

            if not (1 <= num_passwords <= 20):
                messagebox.showerror("Invalid Count", "Number of passwords must be between 1 and 20")
                return None

            # Get character set options
            use_upper = self.app.use_upper_var.get()
            use_lower = self.app.use_lower_var.get()
            use_digits = self.app.use_digits_var.get()
            use_punctuation = self.app.use_punctuation_var.get()
            exclude_similar = self.app.exclude_similar_var.get()

            if not any([use_upper, use_lower, use_digits, use_punctuation]):
                messagebox.showerror("Invalid Options", "Please select at least one character type")
                return None

            # Generate passwords
            passwords = []
            for _ in range(num_passwords):
                password = generate_password(
                    length=length,
                    use_upper=use_upper,
                    use_lower=use_lower,
                    use_digits=use_digits,
                    use_punctuation=use_punctuation,
                    exclude_similar=exclude_similar
                )
                passwords.append(password)

            return passwords

        except ValueError as e:
            logger.error(f"Invalid input for password generation: {str(e)}")
            messagebox.showerror("Invalid Input", str(e))
            return None
        except Exception as e:
            logger.error(f"Error in password generation: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            return None

    def copy_to_clipboard(self):
        """Copy generated password to clipboard"""
        try:
            password = self.app.password_tab.password_display.get(1.0, tk.END).strip()
            if password:
                pyperclip.copy(password)
                self.app.status_var.set("Password copied to clipboard!")
                logger.info("Password copied to clipboard")
            else:
                messagebox.showwarning("No Password", "No password to copy")
        except Exception as e:
            logger.error(f"Error copying to clipboard: {str(e)}")
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")

    def clear_generated_password(self):
        """Clear the generated password display"""
        self.app.password_tab.password_display.configure(state='normal')
        self.app.password_tab.password_display.delete(1.0, tk.END)
        self.app.password_tab.password_display.configure(state='disabled')
        self.app.status_var.set("Password cleared")
        logger.info("Generated password cleared")
