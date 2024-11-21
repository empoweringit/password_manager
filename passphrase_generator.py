# passphrase_generator.py

import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import secrets
import pyperclip
import threading
import math
import json
import os
import logging
import random

# Import necessary functions and variables from main.py if needed
from ui_helpers import create_tooltip
from config import encryption_manager

# Configure logging for this module
logger = logging.getLogger(__name__)

class PassphraseGenerator:
    def __init__(self, parent):
        self.parent = parent
        self.word_lists_file = "word_lists.json"
        self.word_lists = self.load_word_lists()
        self.setup_ui()

    def load_word_lists(self):
        """Load word lists from JSON file"""
        try:
            with open(self.word_lists_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load word lists: {str(e)}")
            return {
                "Animals": ["Lion", "Tiger", "Elephant", "Giraffe", "Zebra"],
                "Colors": ["Red", "Blue", "Green", "Yellow", "Purple"],
                "Cities": ["London", "Paris", "Tokyo", "Rome", "Cairo"],
                "Nature": ["Mountain", "Ocean", "Forest", "River", "Desert"]
            }

    def setup_ui(self):
        """Setup the passphrase generator UI"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left panel for generation
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Generation options
        options_frame = ttk.LabelFrame(left_panel, text="Generation Options", padding=10)
        options_frame.pack(fill=tk.X, pady=5)

        # Word count
        word_frame = ttk.Frame(options_frame)
        word_frame.pack(fill=tk.X, pady=5)
        ttk.Label(word_frame, text="Number of Words:").pack(side=tk.LEFT)
        self.word_count = ttk.Spinbox(word_frame, from_=3, to=10, width=5)
        self.word_count.set(4)
        self.word_count.pack(side=tk.LEFT, padx=5)

        # Separator
        sep_frame = ttk.Frame(options_frame)
        sep_frame.pack(fill=tk.X, pady=5)
        ttk.Label(sep_frame, text="Word Separator:").pack(side=tk.LEFT)
        self.separator = ttk.Entry(sep_frame, width=5)
        self.separator.insert(0, "-")
        self.separator.pack(side=tk.LEFT, padx=5)

        # Word List Categories
        categories_frame = ttk.LabelFrame(options_frame, text="Word Categories", padding=5)
        categories_frame.pack(fill=tk.X, pady=5)

        self.category_vars = {}
        for category in self.word_lists.keys():
            var = tk.BooleanVar(value=True)
            self.category_vars[category] = var
            ttk.Checkbutton(
                categories_frame,
                text=category,
                variable=var
            ).pack(anchor=tk.W)

        # Options
        self.capitalize_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Capitalize Words", variable=self.capitalize_var).pack(anchor=tk.W)

        self.add_number_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Add Number", variable=self.add_number_var).pack(anchor=tk.W)

        self.add_special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Add Special Character", variable=self.add_special_var).pack(anchor=tk.W)

        # Generated passphrase
        result_frame = ttk.LabelFrame(left_panel, text="Generated Passphrase", padding=10)
        result_frame.pack(fill=tk.X, pady=5)

        self.passphrase_var = tk.StringVar()
        self.passphrase_entry = ttk.Entry(
            result_frame,
            textvariable=self.passphrase_var,
            font=("Consolas", 10),
            style="Passphrase.TEntry"  # Custom style for passphrases
        )
        self.passphrase_entry.pack(fill=tk.X, pady=5)

        # Buttons
        button_frame = ttk.Frame(result_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            button_frame,
            text="Generate",
            command=self.generate_passphrase
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Copy",
            command=self.copy_passphrase
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Store",
            command=self.store_passphrase
        ).pack(side=tk.LEFT, padx=5)

        # Right panel for analysis
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Analysis results
        analysis_frame = ttk.LabelFrame(right_panel, text="Passphrase Analysis", padding=10)
        analysis_frame.pack(fill=tk.BOTH, expand=True)

        self.analysis_text = tk.Text(
            analysis_frame,
            wrap=tk.WORD,
            height=15,
            width=40
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags
        self.analysis_text.tag_configure("header", font=("TkDefaultFont", 10, "bold"))
        self.analysis_text.tag_configure("good", foreground="green")
        self.analysis_text.tag_configure("info", foreground="blue")

        # Configure custom style for passphrase entries
        style = ttk.Style()
        style.configure("Passphrase.TEntry", fieldbackground="#E6F3FF")  # Light blue background

    def generate_passphrase(self):
        """Generate a new passphrase based on current settings"""
        try:
            # Get selected categories
            selected_categories = [cat for cat, var in self.category_vars.items() if var.get()]

            if not selected_categories:
                messagebox.showerror("Error", "Please select at least one word category.")
                return

            # Combine words from selected categories
            available_words = []
            for category in selected_categories:
                available_words.extend(self.word_lists[category])

            # Check if we have enough words
            word_count = int(self.word_count.get())
            if len(available_words) < word_count:
                messagebox.showerror(
                    "Error",
                    f"Not enough words available. Need {word_count} words but only have {len(available_words)}."
                )
                return

            # Generate passphrase
            selected_words = random.sample(available_words, word_count)

            # Apply capitalization if enabled
            if self.capitalize_var.get():
                selected_words = [word.capitalize() for word in selected_words]

            # Join words with separator
            passphrase = self.separator.get().join(selected_words)

            # Add number if enabled
            if self.add_number_var.get():
                passphrase += str(random.randint(0, 999))

            # Add special character if enabled
            if self.add_special_var.get():
                special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
                passphrase += random.choice(special_chars)

            self.passphrase_var.set(passphrase)
            self.analyze_passphrase()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate passphrase: {str(e)}")

    def analyze_passphrase(self):
        """Analyze the current passphrase"""
        passphrase = self.passphrase_var.get()
        if not passphrase:
            return

        # Clear previous analysis
        self.analysis_text.delete(1.0, tk.END)

        # Basic stats
        self.analysis_text.insert(tk.END, "Passphrase Statistics:\n", "header")
        self.analysis_text.insert(tk.END, f"• Length: {len(passphrase)} characters\n")

        # Word analysis
        words = passphrase.split(self.separator.get())
        self.analysis_text.insert(tk.END, f"• Words: {len(words)}\n")

        # Character composition
        has_upper = any(c.isupper() for c in passphrase)
        has_lower = any(c.islower() for c in passphrase)
        has_digit = any(c.isdigit() for c in passphrase)
        has_special = any(not c.isalnum() for c in passphrase)

        self.analysis_text.insert(tk.END, "\nCharacter Types:\n", "header")
        self.analysis_text.insert(tk.END, f"• Uppercase: {'Yes' if has_upper else 'No'}\n", "good" if has_upper else None)
        self.analysis_text.insert(tk.END, f"• Lowercase: {'Yes' if has_lower else 'No'}\n", "good" if has_lower else None)
        self.analysis_text.insert(tk.END, f"• Numbers: {'Yes' if has_digit else 'No'}\n", "good" if has_digit else None)
        self.analysis_text.insert(tk.END, f"• Special: {'Yes' if has_special else 'No'}\n", "good" if has_special else None)

        # Entropy calculation
        char_set_size = 26 * (has_upper + has_lower) + 10 * has_digit + 30 * has_special
        entropy = len(passphrase) * math.log2(char_set_size)

        self.analysis_text.insert(tk.END, "\nSecurity Analysis:\n", "header")
        self.analysis_text.insert(tk.END, f"• Entropy: {entropy:.1f} bits\n", "info")

        # Time to crack estimates
        crack_speeds = {
            "Online Attack": 1000,  # 1000 guesses per second
            "Offline Fast Hash": 1000000000  # 1 billion guesses per second
        }

        self.analysis_text.insert(tk.END, "\nTime to Crack Estimates:\n", "header")
        for attack, speed in crack_speeds.items():
            seconds = (2 ** entropy) / speed
            if seconds < 60:
                time_str = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                time_str = f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                time_str = f"{seconds/86400:.1f} days"
            else:
                time_str = f"{seconds/31536000:.1f} years"
            self.analysis_text.insert(tk.END, f"• {attack}: {time_str}\n", "good")

    def copy_passphrase(self):
        """Copy passphrase to clipboard"""
        passphrase = self.passphrase_var.get()
        if passphrase:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(passphrase)
            messagebox.showinfo("Success", "Passphrase copied to clipboard!")

    def store_passphrase(self):
        """Store the passphrase in the database"""
        passphrase = self.passphrase_var.get()
        if not passphrase:
            messagebox.showerror("Error", "Please generate a passphrase first.")
            return

        try:
            # Create storage dialog
            from password_storage import PasswordStorageDialog
            dialog = PasswordStorageDialog(self.parent, passphrase)

            # Set the entry type to passphrase (this will be used for styling)
            dialog.entry_type = "passphrase"

            # Show the dialog
            dialog.show()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to store passphrase: {str(e)}")

def calculate_passphrase_entropy(word_count: int, word_list_size: int) -> float:
    """
    Calculates the entropy of a passphrase.
    """
    if word_list_size <= 0:
        return 0.0
    return word_count * math.log2(word_list_size)

def assess_passphrase_strength(word_count, word_pool_size):
    """
    Assesses the strength of the passphrase based on entropy.
    Returns a tuple of (strength_label, progress_value, color).
    """
    entropy = calculate_passphrase_entropy(word_count, word_pool_size)

    # Adjusted thresholds for better accuracy
    if entropy >= 80:
        return "Very Strong", 100, "success"
    elif entropy >= 60:
        return "Strong", 75, "warning"
    elif entropy >= 40:
        return "Moderate", 50, "info"
    else:
        return "Weak", 25, "danger"

def get_passphrase_recommendations(entropy: float) -> list:
    """
    Generates recommendations to improve passphrase strength based on entropy.
    """
    recommendations = []
    if entropy < 60:
        recommendations.append("Increase the number of words in the passphrase.")
        recommendations.append("Include more categories with diverse words.")
    return recommendations

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Passphrase Generator")
    passphrase_generator = PassphraseGenerator(root)
    root.mainloop()
