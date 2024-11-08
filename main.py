import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import secrets
import string
import pyperclip
import threading
import math
import json
import os

# ------------------- Font Definition -------------------
FONT_NAME = "Helvetica"

# ------------------- Helper Functions -------------------

SIMILAR_CHARACTERS = "il1Lo0O"

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_punctuation=True, exclude_similar=False, custom_words=None):
    """
    Generates a secure password based on specified criteria.
    If custom_words are provided, they are embedded into the password.
    """
    if not (use_upper or use_lower or use_digits or use_punctuation):
        raise ValueError("At least one character type must be selected.")

    characters = ""
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_punctuation:
        characters += string.punctuation

    if exclude_similar:
        characters = ''.join([c for c in characters if c not in SIMILAR_CHARACTERS])

    # If custom words are provided, ensure they fit within the length
    total_custom_length = sum(len(word) for word in custom_words) if custom_words else 0
    if total_custom_length > length:
        raise ValueError("Combined length of custom words exceeds the total password length.")

    remaining_length = length - total_custom_length

    # Ensure the password includes at least one character from each selected category
    password = []
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_punctuation:
        password.append(secrets.choice(string.punctuation))

    # Fill the rest of the password length
    while len(password) < remaining_length:
        password.append(secrets.choice(characters))

    # Insert custom words at random positions
    if custom_words:
        for word in custom_words:
            insert_pos = secrets.randbelow(len(password) + 1)
            password.insert(insert_pos, word)

    # Shuffle to prevent predictable sequences
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def calculate_password_entropy(length, pool_size):
    """
    Calculates the entropy of a password.
    """
    return length * math.log2(pool_size)

def calculate_passphrase_entropy(word_count, word_list_size):
    """
    Calculates the entropy of a passphrase.
    """
    return word_count * math.log2(word_list_size)

def assess_strength(password):
    """
    Assesses the strength of the password based on entropy.
    Returns a tuple of (strength_label, progress_value, color).
    """
    length = len(password)
    categories = 0
    if any(c.islower() for c in password):
        categories += 1
    if any(c.isupper() for c in password):
        categories += 1
    if any(c.isdigit() for c in password):
        categories += 1
    if any(c in string.punctuation for c in password):
        categories += 1

    # Calculate pool size
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    entropy = calculate_password_entropy(length, pool_size)

    if entropy >= 90:
        return "Very Strong", 100, "success"
    elif entropy >= 70:
        return "Strong", 75, "warning"
    elif entropy >= 50:
        return "Moderate", 50, "info"
    else:
        return "Weak", 25, "danger"

def create_tooltip(widget, text):
    """
    Creates a tooltip for a given widget using ttkbootstrap's ToolTip.
    """
    tooltip = ToolTip(widget, text=text)

# ------------------- Main Application Class -------------------

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Ultimate Password Generator")
        master.geometry("1000x900")
        master.minsize(1000, 900)

        # Initialize theme (Default theme from ttkbootstrap)
        self.style = ttk.Style("superhero")  # You can choose different themes
        self.is_dark_mode = False  # Track the current theme mode

        # Initialize categorized word lists
        self.word_lists_file = "word_lists.json"
        self.categorized_word_lists = self.load_word_lists()

        # Dictionary to hold category checkbox variables
        self.category_vars = {}
        for category in self.categorized_word_lists.keys():
            self.category_vars[category] = tk.BooleanVar(value=True)

        # Top Frame for Title and Theme Toggle
        self.top_frame = ttk.Frame(master, padding=10)
        self.top_frame.pack(fill=X)

        # Title Label
        self.title_label = ttk.Label(
            self.top_frame,
            text="Ultimate Password Generator",
            font=(FONT_NAME, 28, "bold"),
        )
        self.title_label.pack(side=LEFT, padx=10)

        # Theme Button
        self.theme_button = ttk.Button(
            self.top_frame,
            text="Switch Theme",
            command=self.toggle_theme,
            bootstyle=INFO
        )
        self.theme_button.pack(side=RIGHT, padx=10, pady=10)
        create_tooltip(self.theme_button, "Toggle between different themes")

        # ------------------- Password Generator UI -------------------
        # Create Notebook (Tabs)
        self.tab_control = ttk.Notebook(master)
        self.tab_control.pack(expand=1, fill=BOTH, padx=10, pady=10)

        # Password Tab
        self.password_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.password_tab, text='Password Generator')

        # Passphrase Tab
        self.passphrase_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.passphrase_tab, text='Passphrase Generator')

        # ------------------- Password Tab -------------------

        # Frame for Password Options
        self.options_frame = ttk.Labelframe(self.password_tab, text="Password Options")
        self.options_frame.pack(padx=20, pady=10, fill=X)
        for i in range(5):
            self.options_frame.columnconfigure(i, weight=1)

        # Password Length
        self.length_label = ttk.Label(self.options_frame, text="Password Length:")
        self.length_label.grid(row=0, column=0, sticky=W, pady=5, padx=5)

        self.length_var = tk.StringVar(value="16")
        self.length_entry = ttk.Entry(
            self.options_frame,
            textvariable=self.length_var,
            width=10,
            font=(FONT_NAME, 12)
        )
        self.length_entry.grid(row=0, column=1, sticky=W, pady=5, padx=5)
        self.length_entry.bind("<FocusOut>", self.validate_length)
        create_tooltip(self.length_entry, "Enter password length (4-128)")

        # Number of Passwords
        self.multiple_label = ttk.Label(self.options_frame, text="Number of Passwords:")
        self.multiple_label.grid(row=0, column=2, sticky=W, pady=5, padx=5)

        self.multiple_var = tk.IntVar(value=1)
        self.multiple_spinbox = ttk.Spinbox(
            self.options_frame,
            from_=1,
            to=20,
            textvariable=self.multiple_var,
            width=5,
            font=(FONT_NAME, 12)
        )
        self.multiple_spinbox.grid(row=0, column=3, sticky=W, pady=5, padx=5)
        create_tooltip(self.multiple_spinbox, "Choose the number of passwords to generate")

        # Character Types
        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_punctuation_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=False)

        self.upper_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Uppercase (A-Z)",
            variable=self.use_upper_var,
            bootstyle=SUCCESS
        )
        self.upper_check.grid(row=1, column=0, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.upper_check, "Include uppercase letters in the password")

        self.lower_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Lowercase (a-z)",
            variable=self.use_lower_var,
            bootstyle=SUCCESS
        )
        self.lower_check.grid(row=2, column=0, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.lower_check, "Include lowercase letters in the password")

        self.digits_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Digits (0-9)",
            variable=self.use_digits_var,
            bootstyle=SUCCESS
        )
        self.digits_check.grid(row=1, column=2, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.digits_check, "Include digits in the password")

        self.punctuation_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Punctuation (!@#$...)",
            variable=self.use_punctuation_var,
            bootstyle=SUCCESS
        )
        self.punctuation_check.grid(row=2, column=2, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.punctuation_check, "Include punctuation symbols in the password")

        self.exclude_similar_check = ttk.Checkbutton(
            self.options_frame,
            text="Exclude Similar Characters (e.g., l, 1, O, 0)",
            variable=self.exclude_similar_var,
            bootstyle=PRIMARY
        )
        self.exclude_similar_check.grid(row=3, column=0, columnspan=4, sticky=W, pady=5, padx=5)
        create_tooltip(self.exclude_similar_check, "Exclude characters that look similar to avoid confusion")

        # Include Preset Word
        self.include_preset_word_var = tk.BooleanVar(value=False)
        self.include_preset_word_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Preset Word",
            variable=self.include_preset_word_var,
            command=self.toggle_preset_word_options,
            bootstyle=INFO
        )
        self.include_preset_word_check.grid(row=4, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.include_preset_word_check, "Check to include a preset word from categories in the password")

        # Category Selection for Preset Word
        self.preset_category_label = ttk.Label(self.options_frame, text="Select Category:")
        self.preset_category_label.grid(row=4, column=1, sticky=W, pady=5, padx=5)

        self.preset_category_var = tk.StringVar()
        self.preset_category_dropdown = ttk.Combobox(
            self.options_frame,
            textvariable=self.preset_category_var,
            values=list(self.categorized_word_lists.keys()),
            state='disabled'
        )
        self.preset_category_dropdown.grid(row=4, column=2, sticky=W, pady=5, padx=5)
        self.preset_category_dropdown.bind("<<ComboboxSelected>>", self.update_preset_word_options)
        create_tooltip(self.preset_category_dropdown, "Select a category to choose a word from")

        # Word Selection from Category
        self.preset_word_label = ttk.Label(self.options_frame, text="Select Word:")
        self.preset_word_label.grid(row=4, column=3, sticky=W, pady=5, padx=5)

        self.preset_word_var = tk.StringVar()
        self.preset_word_dropdown = ttk.Combobox(
            self.options_frame,
            textvariable=self.preset_word_var,
            values=[],
            state='disabled'
        )
        self.preset_word_dropdown.grid(row=4, column=4, sticky=W, pady=5, padx=5)
        create_tooltip(self.preset_word_dropdown, "Select a word from the chosen category to include in the password")

        # Include Custom Word
        self.include_custom_word_var = tk.BooleanVar(value=False)
        self.include_custom_word_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Custom Word",
            variable=self.include_custom_word_var,
            command=self.toggle_custom_word_entry,
            bootstyle=INFO
        )
        self.include_custom_word_check.grid(row=5, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.include_custom_word_check, "Check to include your own word in the password")

        self.custom_word_var = tk.StringVar()
        self.custom_word_entry = ttk.Entry(
            self.options_frame,
            textvariable=self.custom_word_var,
            width=20,
            font=(FONT_NAME, 12),
            state='disabled'
        )
        self.custom_word_entry.grid(row=5, column=1, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.custom_word_entry, "Enter the custom word to include in the password")

        # Include Random Word
        self.include_random_word_var = tk.BooleanVar(value=False)
        self.include_random_word_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Random Word",
            variable=self.include_random_word_var,
            bootstyle=INFO
        )
        self.include_random_word_check.grid(row=6, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.include_random_word_check, "Include a random word from categories if no word is selected")

        # Generate Button
        self.generate_button = ttk.Button(
            self.password_tab,
            text="Generate Password",
            command=self.generate_password,
            bootstyle=SUCCESS,
            width=20
        )
        self.generate_button.pack(pady=10)
        create_tooltip(self.generate_button, "Click to generate password(s) based on the selected options")

        # Frame for Generated Password and Controls
        self.output_frame = ttk.Frame(self.password_tab)
        self.output_frame.pack(padx=20, pady=10, fill=BOTH, expand=True)
        self.output_frame.columnconfigure(0, weight=1)
        self.output_frame.columnconfigure(1, weight=0)

        # Generated Password Display
        self.password_display = ScrolledText(
            self.output_frame,
            wrap='word',
            font=(FONT_NAME, 14),
            state='disabled',
            height=10
        )
        self.password_display.grid(row=0, column=0, sticky=NSEW, padx=(0,10), pady=5)
        create_tooltip(self.password_display, "Generated password(s) will appear here")

        # Copy Button
        self.copy_button = ttk.Button(
            self.output_frame,
            text="Copy to Clipboard",
            command=self.copy_to_clipboard,
            bootstyle=INFO,
            width=20
        )
        self.copy_button.grid(row=0, column=1, sticky=N, pady=5)
        create_tooltip(self.copy_button, "Copy the generated password(s) to clipboard")

        # Password Strength Indicator
        self.strength_frame = ttk.Frame(self.password_tab)
        self.strength_frame.pack(padx=20, pady=10, fill=X)
        self.strength_frame.columnconfigure(1, weight=1)

        self.strength_label = ttk.Label(self.strength_frame, text="Password Strength:")
        self.strength_label.grid(row=0, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.strength_label, "Displays the strength of the generated password")

        self.strength_var = tk.StringVar(value="N/A")
        self.strength_display = ttk.Label(
            self.strength_frame,
            textvariable=self.strength_var,
            font=(FONT_NAME, 12, "bold")
        )
        self.strength_display.grid(row=0, column=1, sticky=W, pady=5, padx=5)

        self.strength_progress = ttk.Progressbar(
            self.strength_frame,
            orient='horizontal',
            length=400,
            mode='determinate'
        )
        self.strength_progress.grid(row=0, column=2, sticky=W, pady=5, padx=5)

        # Status Label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            self.password_tab,
            textvariable=self.status_var,
            font=(FONT_NAME, 10)
        )
        self.status_label.pack(pady=5)

        # ------------------- Passphrase Tab -------------------

        # Frame for Passphrase Options
        self.unique_frame = ttk.Labelframe(self.passphrase_tab, text="Passphrase Options")
        self.unique_frame.pack(padx=20, pady=10, fill=X)
        self.unique_frame.columnconfigure(0, weight=1)
        self.unique_frame.columnconfigure(1, weight=1)

        # Passphrase Length
        self.passphrase_label = ttk.Label(self.unique_frame, text="Passphrase Length (Words):")
        self.passphrase_label.grid(row=0, column=0, sticky=W, pady=5, padx=5)

        self.passphrase_var = tk.IntVar(value=4)
        self.passphrase_spinbox = ttk.Spinbox(
            self.unique_frame,
            from_=2,
            to=10,
            textvariable=self.passphrase_var,
            width=5,
            font=(FONT_NAME, 12)
        )
        self.passphrase_spinbox.grid(row=0, column=1, sticky=W, pady=5, padx=5)
        create_tooltip(self.passphrase_spinbox, "Choose the number of words in the passphrase")

        # Category Selection
        self.category_label = ttk.Label(self.unique_frame, text="Select Categories:")
        self.category_label.grid(row=1, column=0, sticky=W, pady=5, padx=5)

        # Frame for Category Checkboxes
        self.category_check_frame = ttk.Frame(self.unique_frame)
        self.category_check_frame.grid(row=2, column=0, columnspan=2, sticky=W, pady=5, padx=5)

        for idx, category in enumerate(self.categorized_word_lists.keys()):
            cb = ttk.Checkbutton(
                self.category_check_frame,
                text=category,
                variable=self.category_vars[category],
                bootstyle=PRIMARY
            )
            cb.grid(row=idx//4, column=idx%4, sticky=W, padx=5, pady=2)
            create_tooltip(cb, f"Include {category} words in the passphrase")

        # Custom Words Input
        self.custom_words_label = ttk.Label(self.unique_frame, text="Add Custom Words (comma-separated):")
        self.custom_words_label.grid(row=3, column=0, sticky=W, pady=5, padx=5)

        self.custom_words_var = tk.StringVar()
        self.custom_words_entry = ttk.Entry(
            self.unique_frame,
            textvariable=self.custom_words_var,
            width=50,
            font=(FONT_NAME, 12)
        )
        self.custom_words_entry.grid(row=3, column=1, sticky=W, pady=5, padx=5)
        create_tooltip(self.custom_words_entry, "Enter custom words separated by commas to include in the passphrase")

        # Select Category to Add Custom Words
        self.add_to_category_label = ttk.Label(self.unique_frame, text="Add to Category:")
        self.add_to_category_label.grid(row=4, column=0, sticky=W, pady=5, padx=5)

        self.add_to_category_var = tk.StringVar()
        self.add_to_category_dropdown = ttk.Combobox(
            self.unique_frame,
            textvariable=self.add_to_category_var,
            values=list(self.categorized_word_lists.keys()),
            state='readonly'
        )
        self.add_to_category_dropdown.grid(row=4, column=1, sticky=W, pady=5, padx=5)
        if self.categorized_word_lists:
            self.add_to_category_dropdown.current(0)
        create_tooltip(self.add_to_category_dropdown, "Select a category to add the custom words to")
        self.add_to_category_dropdown.bind("<<ComboboxSelected>>", self.update_current_words_display)

        # Add Custom Words Button
        self.add_custom_words_button = ttk.Button(
            self.unique_frame,
            text="Add Words",
            command=self.add_custom_words,
            bootstyle=SUCCESS
        )
        self.add_custom_words_button.grid(row=5, column=1, sticky=W, pady=5, padx=5)
        create_tooltip(self.add_custom_words_button, "Add the entered custom words to the selected category")

        # Current Words Display
        self.current_words_label = ttk.Label(self.unique_frame, text="Current Words in Selected Category:")
        self.current_words_label.grid(row=6, column=0, sticky=NW, pady=5, padx=5)

        self.current_words_listbox = tk.Listbox(
            self.unique_frame,
            height=10,
            width=50,
            font=(FONT_NAME, 12)
        )
        self.current_words_listbox.grid(row=6, column=1, sticky=W, pady=5, padx=5)
        create_tooltip(self.current_words_listbox, "Displays the current words in the selected category")

        # Search Words
        self.search_words_label = ttk.Label(self.unique_frame, text="Search Words:")
        self.search_words_label.grid(row=7, column=0, sticky=W, pady=5, padx=5)

        self.search_words_var = tk.StringVar()
        self.search_words_entry = ttk.Entry(
            self.unique_frame,
            textvariable=self.search_words_var,
            width=30,
            font=(FONT_NAME, 12)
        )
        self.search_words_entry.grid(row=7, column=1, sticky=W, pady=5, padx=5)
        create_tooltip(self.search_words_entry, "Enter keyword to search within the current category")

        self.search_words_button = ttk.Button(
            self.unique_frame,
            text="Search",
            command=self.search_words_in_category,
            bootstyle=INFO
        )
        self.search_words_button.grid(row=7, column=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.search_words_button, "Click to search words in the selected category")

        # Generate Passphrase Button
        self.generate_passphrase_button = ttk.Button(
            self.passphrase_tab,
            text="Generate Passphrase",
            command=self.generate_passphrase,
            bootstyle=SUCCESS,
            width=20
        )
        self.generate_passphrase_button.pack(pady=10)
        create_tooltip(self.generate_passphrase_button, "Click to generate a passphrase based on the selected options")

        # Frame for Generated Passphrase and Controls
        self.passphrase_frame = ttk.Frame(self.passphrase_tab)
        self.passphrase_frame.pack(padx=20, pady=10, fill=BOTH, expand=True)
        self.passphrase_frame.columnconfigure(0, weight=1)
        self.passphrase_frame.columnconfigure(1, weight=0)

        # Generated Passphrase Display
        self.passphrase_display = ScrolledText(
            self.passphrase_frame,
            wrap='word',
            font=(FONT_NAME, 14),
            state='disabled',
            height=10
        )
        self.passphrase_display.grid(row=0, column=0, sticky=NSEW, padx=(0,10), pady=5)
        create_tooltip(self.passphrase_display, "Generated passphrase will appear here")

        # Copy Passphrase Button
        self.copy_passphrase_button = ttk.Button(
            self.passphrase_frame,
            text="Copy Passphrase",
            command=self.copy_passphrase_to_clipboard,
            bootstyle=INFO,
            width=20
        )
        self.copy_passphrase_button.grid(row=0, column=1, sticky=N, pady=5)
        create_tooltip(self.copy_passphrase_button, "Copy the generated passphrase to clipboard")

        # Status Label for Passphrase
        self.passphrase_status_var = tk.StringVar()
        self.passphrase_status_label = ttk.Label(
            self.passphrase_tab,
            textvariable=self.passphrase_status_var,
            font=(FONT_NAME, 10)
        )
        self.passphrase_status_label.pack(pady=5)

        # Initialize current words display
        self.update_current_words_display()

        # Bind Keyboard Shortcuts
        self.bind_shortcuts()

        # Ensure word lists are saved on closing
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ------------------- Theme Toggle -------------------
    def toggle_theme(self):
        themes = ['superhero', 'flatly', 'cyborg', 'darkly', 'journal', 'solar', 'united', 'yeti']
        current_theme = self.style.theme.name
        index = themes.index(current_theme)
        next_theme = themes[(index + 1) % len(themes)]
        self.style.theme_use(next_theme)
        self.status_var.set(f"Theme switched to {next_theme.capitalize()}")

    # ------------------- Password Generation -------------------
    def generate_password(self):
        """
        Generates passwords based on user-selected options and displays them.
        """
        try:
            length = int(self.length_var.get())
            if length < 4 or length > 128:
                raise ValueError("Password length must be between 4 and 128.")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid password length: {ve}")
            self.status_var.set("")
            self.update_strength_display("N/A")
            return

        try:
            count = int(self.multiple_var.get())
            if count < 1 or count > 20:
                raise ValueError("Number of passwords must be between 1 and 20.")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid number of passwords: {ve}")
            self.status_var.set("")
            self.update_strength_display("N/A")
            return

        # Gather custom words to include
        custom_words = []

        # Include Preset Word
        if self.include_preset_word_var.get():
            selected_word = self.preset_word_var.get()
            if not selected_word:
                messagebox.showwarning("Input Error", "Preset word is selected but no word was chosen.")
                return
            custom_words.append(selected_word)

        # Include Custom Word
        if self.include_custom_word_var.get():
            custom_word = self.custom_word_var.get().strip()
            if not custom_word:
                messagebox.showwarning("Input Error", "Custom word is selected but no word was entered.")
                return
            custom_words.append(custom_word)

        # Include Random Word if no other word is selected
        if self.include_random_word_var.get() and not custom_words:
            all_words = []
            for words in self.categorized_word_lists.values():
                all_words.extend(words)
            if all_words:
                random_word = secrets.choice(all_words)
                custom_words.append(random_word)
            else:
                messagebox.showwarning("No Words Available", "No words available in categories to include as a random word.")
                return

        # Check total length of custom words
        total_custom_length = sum(len(word) for word in custom_words)
        if total_custom_length > length:
            messagebox.showerror("Input Error", "Combined length of custom words exceeds the total password length.")
            return

        try:
            passwords = []
            for _ in range(count):
                pwd = generate_password(
                    length=length,
                    use_upper=self.use_upper_var.get(),
                    use_lower=self.use_lower_var.get(),
                    use_digits=self.use_digits_var.get(),
                    use_punctuation=self.use_punctuation_var.get(),
                    exclude_similar=self.exclude_similar_var.get(),
                    custom_words=custom_words if custom_words else None
                )
                passwords.append(pwd)

            # Display passwords
            self.password_display.configure(state='normal')
            self.password_display.delete(1.0, tk.END)
            if count == 1:
                self.password_display.insert(tk.END, passwords[0])
                strength_label, value, color = assess_strength(passwords[0])
                self.strength_var.set(strength_label)
                self.update_strength_progress(value, color)
            else:
                for idx, pwd in enumerate(passwords, 1):
                    self.password_display.insert(tk.END, f"{idx}. {pwd}\n")
                self.strength_var.set("Varied")
                self.strength_progress['value'] = 50  # Average strength
                self.strength_progress.configure(bootstyle='info')
            self.password_display.configure(state='disabled')
            self.status_var.set(f"{count} password(s) generated successfully!")
            self.status_label.configure(bootstyle="success")
        except ValueError as ve:
            messagebox.showerror("Selection Error", str(ve))
            self.status_var.set("")
            self.update_strength_display("N/A")
            return

    # ------------------- Toggle Preset Word Options -------------------
    def toggle_preset_word_options(self):
        """
        Enables or disables the preset word selection options based on the checkbox state.
        """
        if self.include_preset_word_var.get():
            self.preset_category_dropdown.configure(state='readonly')
            self.preset_word_dropdown.configure(state='readonly')
            self.update_preset_word_options()
        else:
            self.preset_category_dropdown.configure(state='disabled')
            self.preset_word_dropdown.configure(state='disabled')
            self.preset_category_var.set('')
            self.preset_word_var.set('')

    def update_preset_word_options(self, event=None):
        """
        Updates the preset word dropdown based on the selected category.
        """
        selected_category = self.preset_category_var.get()
        if selected_category:
            words = self.categorized_word_lists.get(selected_category, [])
            self.preset_word_dropdown['values'] = words
            if words:
                self.preset_word_dropdown.current(0)
            else:
                self.preset_word_var.set('')
        else:
            self.preset_word_dropdown['values'] = []
            self.preset_word_var.set('')

    # ------------------- Toggle Custom Word Entry -------------------
    def toggle_custom_word_entry(self):
        """
        Enables or disables the custom word entry based on the checkbox state.
        """
        if self.include_custom_word_var.get():
            self.custom_word_entry.configure(state='normal')
        else:
            self.custom_word_entry.configure(state='disabled')
            self.custom_word_var.set("")

    # ------------------- Password Strength Indicator -------------------
    def update_strength_progress(self, value, color):
        """
        Updates the strength progress bar based on strength_label.
        """
        self.strength_progress['value'] = value
        self.strength_progress.configure(bootstyle=color)
        self.strength_label.configure(bootstyle=color)
        self.strength_display.configure(bootstyle=color)

    def update_strength_display(self, strength_label):
        """
        Resets the strength display.
        """
        if strength_label == "N/A":
            self.strength_var.set(strength_label)
            self.strength_progress['value'] = 0
            self.strength_progress.configure(bootstyle='secondary')
        else:
            strength_label, value, color = assess_strength(strength_label)
            self.strength_var.set(strength_label)
            self.update_strength_progress(value, color)

    # ------------------- Passphrase Generation -------------------
    def generate_passphrase(self):
        """
        Generates passphrases composed of random words from selected categories and custom inputs, then displays them.
        """
        try:
            word_count = int(self.passphrase_var.get())
            if word_count < 2 or word_count > 10:
                raise ValueError("Passphrase length must be between 2 and 10 words.")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid passphrase length: {ve}")
            self.passphrase_status_var.set("")
            return

        # Gather selected categories
        selected_categories = [category for category, var in self.category_vars.items() if var.get()]
        if not selected_categories:
            messagebox.showerror("No Categories Selected", "Please select at least one category for passphrase generation.")
            self.passphrase_status_var.set("")
            return

        # Combine words from selected categories
        selected_words = []
        for category in selected_categories:
            selected_words.extend(self.categorized_word_lists[category])

        # Include custom words
        custom_words_input = self.custom_words_var.get().strip()
        custom_words = [word.strip() for word in custom_words_input.split(",") if word.strip()]
        if custom_words:
            selected_words.extend(custom_words)

        if len(selected_words) < word_count:
            messagebox.showerror(
                "Insufficient Words",
                "Not enough words in the selected categories and custom inputs to generate the passphrase."
            )
            self.passphrase_status_var.set("")
            return

        # Ensure at least one word from each selected category if possible
        passphrase_words = []
        for category in selected_categories:
            if self.categorized_word_lists[category]:
                word = secrets.choice(self.categorized_word_lists[category])
                passphrase_words.append(word.capitalize())

        remaining_words_count = word_count - len(passphrase_words)
        if remaining_words_count > 0:
            remaining_words = [word.capitalize() for word in selected_words]
            passphrase_words.extend(secrets.choice(remaining_words) for _ in range(remaining_words_count))

        # Shuffle to mix category-specific words with others
        secrets.SystemRandom().shuffle(passphrase_words)
        passphrase = ' '.join(passphrase_words)

        # Display passphrase
        self.passphrase_display.configure(state='normal')
        self.passphrase_display.delete(1.0, tk.END)
        self.passphrase_display.insert(tk.END, passphrase)
        self.passphrase_display.configure(state='disabled')

        # Assess strength based on entropy
        strength_label, value, color = self.assess_passphrase_strength(word_count)
        self.passphrase_status_var.set(f"Passphrase generated successfully! Strength: {strength_label}")
        self.passphrase_status_label.configure(bootstyle=color)

    def assess_passphrase_strength(self, word_count):
        """
        Assesses the strength of the passphrase based on entropy.
        Returns a tuple of (strength_label, progress_value, color).
        """
        # Calculate the size of the combined word pool
        selected_categories = [category for category, var in self.category_vars.items() if var.get()]
        word_pool_size = sum(len(self.categorized_word_lists[cat]) for cat in selected_categories)

        # Include custom words in the pool size
        custom_words_input = self.custom_words_var.get().strip()
        custom_words = [word.strip() for word in custom_words_input.split(",") if word.strip()]
        word_pool_size += len(custom_words)

        entropy = calculate_passphrase_entropy(word_count, word_pool_size)

        if entropy >= 100:
            return "Very Strong", 100, "success"
        elif entropy >= 80:
            return "Strong", 75, "warning"
        elif entropy >= 60:
            return "Moderate", 50, "info"
        else:
            return "Weak", 25, "danger"

    # ------------------- Clipboard Functionality -------------------
    def copy_to_clipboard(self):
        """
        Copies the generated password(s) to the clipboard and clears it after 30 seconds.
        """
        pwd = self.password_display.get(1.0, tk.END).strip()
        if pwd:
            pyperclip.copy(pwd)
            self.status_var.set("Password(s) copied to clipboard! It will be cleared in 30 seconds.")
            self.status_label.configure(bootstyle="success")
            threading.Timer(30.0, self.clear_clipboard).start()
        else:
            self.status_var.set("No password to copy.")
            self.status_label.configure(bootstyle="danger")
            messagebox.showwarning("No Password", "Please generate a password first.")

    def copy_passphrase_to_clipboard(self):
        """
        Copies the generated passphrase to the clipboard and clears it after 30 seconds.
        """
        passphrase = self.passphrase_display.get(1.0, tk.END).strip()
        if passphrase:
            pyperclip.copy(passphrase)
            self.passphrase_status_var.set("Passphrase copied to clipboard! It will be cleared in 30 seconds.")
            self.passphrase_status_label.configure(bootstyle="success")
            threading.Timer(30.0, self.clear_clipboard).start()
        else:
            self.passphrase_status_var.set("No passphrase to copy.")
            self.passphrase_status_label.configure(bootstyle="danger")
            messagebox.showwarning("No Passphrase", "Please generate a passphrase first.")

    def clear_clipboard(self):
        """
        Clears the clipboard for security.
        """
        pyperclip.copy('')
        self.status_var.set("Clipboard cleared for security.")
        self.status_label.configure(bootstyle="danger")
        self.passphrase_status_var.set("Clipboard cleared for security.")
        self.passphrase_status_label.configure(bootstyle="danger")

    # ------------------- Validate Length -------------------
    def validate_length(self, event):
        """
        Validates the password length input.
        """
        try:
            length = int(self.length_var.get())
            if length < 4 or length > 128:
                raise ValueError("Password length must be between 4 and 128.")
            self.length_entry.configure(bootstyle='success')
            self.status_var.set("")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid password length: {ve}")
            self.length_var.set("16")
            self.length_entry.configure(bootstyle='danger')
            self.status_var.set("")
            self.update_strength_display("N/A")

    # ------------------- Manage Word Lists -------------------
    def add_custom_words(self):
        """
        Adds user-provided custom words to the selected category.
        """
        category = self.add_to_category_var.get()
        words_input = self.custom_words_var.get().strip()

        if not words_input:
            messagebox.showwarning("No Words Entered", "Please enter at least one word to add.")
            return

        # Split the input into individual words, removing extra spaces
        new_words = [word.strip() for word in words_input.split(",") if word.strip()]
        if not new_words:
            messagebox.showwarning("Invalid Input", "Please enter valid words separated by commas.")
            return

        # Add words to the selected category
        self.categorized_word_lists[category].extend(new_words)

        # Update the current words display
        self.update_current_words_display()

        # Clear the input field
        self.custom_words_var.set("")

        self.passphrase_status_var.set(f"Added {len(new_words)} word(s) to the '{category}' category.")
        self.passphrase_status_label.configure(bootstyle="success")

    # ------------------- Search Words -------------------
    def search_words_in_category(self):
        """
        Searches for words within the selected category based on user input.
        """
        search_query = self.search_words_var.get().strip().lower()
        if not search_query:
            messagebox.showwarning("Input Error", "Search query cannot be empty.")
            return

        category = self.add_to_category_var.get()
        if not category:
            messagebox.showwarning("Selection Error", "No category selected.")
            return

        matched_words = [word for word in self.categorized_word_lists[category] if search_query in word.lower()]

        # Display matched words
        self.current_words_listbox.delete(0, tk.END)
        if matched_words:
            for word in matched_words:
                self.current_words_listbox.insert(tk.END, word.capitalize())
            self.passphrase_status_var.set(f"Found {len(matched_words)} matching word(s).")
            self.passphrase_status_label.configure(bootstyle="success")
        else:
            self.passphrase_status_var.set("No matching words found.")
            self.passphrase_status_label.configure(bootstyle="danger")

    # ------------------- Update Current Words Display -------------------
    def update_current_words_display(self, event=None):
        """
        Updates the listbox to display current words in the selected category.
        """
        category = self.add_to_category_var.get()
        if not category:
            categories = list(self.categorized_word_lists.keys())
            if categories:
                category = categories[0]
                self.add_to_category_var.set(category)
            else:
                self.current_words_listbox.delete(0, tk.END)
                return

        # Clear the listbox
        self.current_words_listbox.delete(0, tk.END)

        # Insert current words
        for word in self.categorized_word_lists[category]:
            self.current_words_listbox.insert(tk.END, word.capitalize())

    # ------------------- Keyboard Shortcuts -------------------
    def bind_shortcuts(self):
        """
        Binds keyboard shortcuts for better accessibility.
        """
        self.master.bind('<Control-g>', lambda event: self.generate_password())
        self.master.bind('<Control-p>', lambda event: self.generate_passphrase())
        self.master.bind('<Control-c>', lambda event: self.copy_to_clipboard())

    # ------------------- Word Lists Persistence -------------------
    def load_word_lists(self):
        """
        Loads the categorized word lists from a JSON file if it exists.
        Merges with default word lists to include any new categories or words.
        """
        default_word_lists = self.get_default_word_lists()
        if os.path.exists(self.word_lists_file):
            try:
                with open(self.word_lists_file, "r") as f:
                    existing_word_lists = json.load(f)
                # Merge default_word_lists into existing_word_lists
                for category, words in default_word_lists.items():
                    if category not in existing_word_lists:
                        existing_word_lists[category] = words
                    else:
                        # Add any new words to existing categories
                        for word in words:
                            if word not in existing_word_lists[category]:
                                existing_word_lists[category].append(word)
                return existing_word_lists
            except Exception as e:
                messagebox.showerror("Error Loading Word Lists", f"An error occurred while loading word lists: {e}")
                return default_word_lists
        else:
            return default_word_lists

    def save_word_lists(self):
        """
        Saves the categorized word lists to a JSON file.
        """
        try:
            with open(self.word_lists_file, "w") as f:
                json.dump(self.categorized_word_lists, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error Saving Word Lists", f"An error occurred while saving word lists: {e}")

    def get_default_word_lists(self):
        """
        Returns the default categorized word lists.
        """
        return {
            "Sports": [
                "soccer", "basketball", "tennis", "golf", "hockey",
                "cricket", "rugby", "boxing", "swim", "run"
            ],
            "Entertainment": [
                "movie", "music", "concert", "dance", "game",
                "show", "cinema", "song", "play", "fun"
            ],
            "Technology": [
                "computer", "internet", "software", "robot",
                "network", "database", "code", "phone", "app", "tech"
            ],
            "Nature": [
                "mountain", "river", "forest", "ocean", "tree",
                "animal", "sun", "moon", "star", "sky"
            ],
            "Food": [
                "pizza", "sushi", "burger", "pasta", "salad",
                "taco", "bread", "fruit", "cheese", "cake"
            ],
            "Animals": [
                "cat", "dog", "bird", "fish", "lion",
                "tiger", "bear", "horse", "frog", "whale"
            ],
            "Colors": [
                "red", "blue", "green", "yellow", "purple",
                "orange", "black", "white", "pink", "gray"
            ],
            "Simple": [
                "happy", "love", "peace", "smile", "friend",
                "family", "home", "laugh", "hello", "world"
            ]
        }

    def on_closing(self):
        """
        Handles application closing by saving word lists and then exiting.
        """
        self.save_word_lists()
        self.master.destroy()

# ------------------- Main Function -------------------

def main():
    """
    Main function to run the Password and Passphrase Generator application.
    """
    root = ttk.Window(themename="superhero")  # Initial theme
    app = PasswordGeneratorApp(root)
    root.mainloop()

# ------------------- Entry Point -------------------

if __name__ == "__main__":
    main()
