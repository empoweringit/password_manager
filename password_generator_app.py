# password_generator_app.py

import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import threading
import pyperclip
import json
import os
import logging
import secrets

# Import custom modules
from config import encryption_manager
from crud import (
    read_entries,
    create_entry,
    update_entry,
    delete_entry
)
from ui_helpers import create_tooltip, validate_phone_number, format_address_input
from search_module import SearchModule
from feedback_module import FeedbackModule
from passphrase_generator import PassphraseGenerator
from password_utils import generate_password, assess_strength, get_password_recommendations

# ------------------- Configure Logging -------------------
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# ------------------- PasswordGeneratorApp Class -------------------
class PasswordGeneratorApp:
    def __init__(self, master, user):
        """Initialize the Password Generator App"""
        self.master = master
        self.user = user
        self.user_id = self.user['id']
        self.logger = logging.getLogger(__name__)
        self.is_new_entry = False  # Track if we're creating a new entry
        
        # Initialize buttons as None
        self.save_button = None
        self.update_button = None
        self.delete_button = None
        self.generate_button = None

        master.title(f"Ultimate Password Manager - {self.user['username']}")
        master.geometry("1000x800")
        master.minsize(900, 700)

        # Initialize theme
        self.style = ttk.Style("superhero")
        
        # Initialize variables
        self.initialize_variables()
        
        # Setup UI
        self.setup_ui()
        
        # Load word lists
        self.load_word_lists()

    # ------------------- Initialize Variables -------------------
    def initialize_variables(self):
        self.selected_file_path = None
        self.password_var = tk.StringVar()
        self.save_website_var = tk.StringVar()
        self.save_url_var = tk.StringVar()
        self.save_username_var = tk.StringVar()
        self.save_email_var = tk.StringVar()
        self.save_phone_var = tk.StringVar()
        self.save_subscription_var = tk.StringVar()
        self.save_pin_var = tk.StringVar()
        self.save_file_var = tk.StringVar()
        self.entry_file_var = tk.StringVar()
        self.entry_id_var = tk.StringVar()

        self.show_password_var = tk.BooleanVar()
        self.multiple_var = tk.IntVar(value=1)
        self.length_var = tk.StringVar(value="16")
        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_punctuation_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=False)
        self.include_preset_word_var = tk.BooleanVar(value=False)
        self.preset_category_var = tk.StringVar()
        self.preset_word_var = tk.StringVar()
        self.include_custom_word_var = tk.BooleanVar(value=False)
        self.custom_word_var = tk.StringVar()
        self.include_random_word_var = tk.BooleanVar(value=False)
        self.word_lists_file = "word_lists.json"
        self.categorized_word_lists = {}
        self.strength_var = tk.StringVar(value="N/A")
        self.status_var = tk.StringVar()
        self.feedback_var = tk.StringVar()
        self.security_questions = []
        self.stored_passwords_status_var = tk.StringVar()
        self.stored_passwords_status_label = None

    # ------------------- Setup UI -------------------
    def setup_ui(self):
        self.setup_top_frame()
        self.setup_tabs()
        self.bind_shortcuts()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.load_stored_passwords()

    # ------------------- Top Frame -------------------
    def setup_top_frame(self):
        self.top_frame = ttk.Frame(self.master, padding=10)
        self.top_frame.pack(fill=X)

        # Title Label
        self.title_label = ttk.Label(
            self.top_frame,
            text="Ultimate Password Manager",
            font=("Helvetica", 24, "bold"),
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

    # ------------------- Theme Toggle -------------------
    def toggle_theme(self):
        themes = ['superhero', 'flatly', 'cyborg', 'darkly', 'journal', 'solar', 'united', 'yeti']
        current_theme = self.style.theme_use()
        index = themes.index(current_theme) if current_theme in themes else 0
        next_theme = themes[(index + 1) % len(themes)]
        self.style.theme_use(next_theme)
        self.logger.info(f"Theme switched to {next_theme.capitalize()}")
        self.stored_passwords_status_var.set(f"Theme switched to {next_theme.capitalize()}.")
        if self.stored_passwords_status_label:
            self.stored_passwords_status_label.configure(bootstyle="info")

    # ------------------- Setup Tabs -------------------
    def setup_tabs(self):
        """Setup the main application tabs"""
        # Create tab control
        self.tab_control = ttk.Notebook(self.master)
        self.tab_control.pack(expand=1, fill=BOTH, padx=10, pady=10)

        # Password Generator Tab
        self.password_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.password_tab, text='Password Generator')
        self.setup_password_tab()

        # Passphrase Generator Tab
        self.passphrase_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.passphrase_tab, text='Passphrase Generator')
        self.passphrase_generator = PassphraseGenerator(self.passphrase_tab)

        # Stored Passwords Tab
        self.stored_passwords_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.stored_passwords_tab, text='Stored Passwords')
        self.setup_stored_passwords_tab()

        # Create Analysis tab
        self.analysis_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.analysis_tab, text='Password Analysis')
        
        # Initialize Feedback Module in the Analysis tab
        self.feedback_module = FeedbackModule(self.analysis_tab)
        self.feedback_module.user_id = self.user_id  # Set the user ID directly

    # ------------------- Password Tab Setup -------------------
    def setup_password_tab(self):
        # Create a canvas and scrollbar to make the password tab scrollable
        self.password_canvas = tk.Canvas(self.password_tab)
        self.password_canvas.pack(side=LEFT, fill=BOTH, expand=True)

        self.password_scrollbar = ttk.Scrollbar(self.password_tab, orient="vertical", command=self.password_canvas.yview)
        self.password_scrollbar.pack(side=RIGHT, fill=Y)

        self.password_canvas.configure(yscrollcommand=self.password_scrollbar.set)
        self.password_canvas.bind('<Configure>', lambda e: self.password_canvas.configure(scrollregion=self.password_canvas.bbox('all')))

        # Create a frame inside the canvas
        self.password_frame = ttk.Frame(self.password_canvas)
        self.password_canvas.create_window((0, 0), window=self.password_frame, anchor="nw")

        # Password Options
        self.setup_password_options()

        # Generate Button
        self.generate_button = ttk.Button(
            self.password_frame,
            text="Generate Password",
            command=self.generate_password_event,
            bootstyle=SUCCESS,
            width=20,
            state=DISABLED  # Set to disabled by default
        )
        self.generate_button.pack(pady=10)
        create_tooltip(self.generate_button, "Click to generate password(s) based on the selected options")

        # Output Frame
        self.setup_password_output()

        # Save Password Information
        self.setup_save_password_info()

        # Password Strength Indicator
        self.setup_password_strength_indicator()

        # Feedback Label
        self.feedback_label = ttk.Label(
            self.password_frame,
            textvariable=self.feedback_var,
            font=("Helvetica", 10),
            wraplength=600,
            justify=LEFT
        )
        self.feedback_label.pack(pady=5, padx=10, fill=X)

        # Status Label
        self.status_label = ttk.Label(
            self.password_frame,
            textvariable=self.status_var,
            font=("Helvetica", 10)
        )
        self.status_label.pack(pady=5)

        # Adjust the layout accordingly
        self.master.update_idletasks()
        self.master.geometry(f"{self.master.winfo_width()}x{self.master.winfo_height()}")

    # ------------------- Password Options -------------------
    def setup_password_options(self):
        self.options_frame = ttk.Labelframe(self.password_frame, text="Password Options")
        self.options_frame.pack(padx=10, pady=5, fill=X)
        for i in range(5):
            self.options_frame.columnconfigure(i, weight=1)

        # Password Length
        ttk.Label(self.options_frame, text="Password Length*:").grid(row=0, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.options_frame, "Password length is required (4-128)")
        self.length_entry = ttk.Entry(
            self.options_frame,
            textvariable=self.length_var,
            width=10,
            font=("Helvetica", 12)
        )
        self.length_entry.grid(row=0, column=1, sticky=W, pady=5, padx=5)
        self.length_entry.bind("<FocusOut>", self.validate_length)
        create_tooltip(self.length_entry, "Enter password length (4-128)")

        # Number of Passwords
        ttk.Label(self.options_frame, text="Number of Passwords*:").grid(row=0, column=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.options_frame, "Number of passwords is required (1-20)")
        self.multiple_spinbox = ttk.Spinbox(
            self.options_frame,
            from_=1,
            to=20,
            textvariable=self.multiple_var,
            width=5,
            font=("Helvetica", 12)
        )
        self.multiple_spinbox.grid(row=0, column=3, sticky=W, pady=5, padx=5)
        create_tooltip(self.multiple_spinbox, "Choose the number of passwords to generate")

        # Character Types
        self.setup_character_types()

        # Include Preset Word
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
        create_tooltip(self.preset_category_label, "Select a category to choose a word from")

        # Initialize categorized word lists
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
        create_tooltip(self.preset_word_label, "Select a word from the chosen category to include in the password")

        self.preset_word_dropdown = ttk.Combobox(
            self.options_frame,
            textvariable=self.preset_word_var,
            values=[],
            state='disabled'
        )
        self.preset_word_dropdown.grid(row=4, column=4, sticky=W, pady=5, padx=5)
        create_tooltip(self.preset_word_dropdown, "Select a word from the chosen category to include in the password")

        # Include Custom Word
        self.include_custom_word_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Custom Word",
            variable=self.include_custom_word_var,
            command=self.toggle_custom_word_entry,
            bootstyle=INFO
        )
        self.include_custom_word_check.grid(row=5, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.include_custom_word_check, "Check to include your own word in the password")

        self.custom_word_entry = ttk.Entry(
            self.options_frame,
            textvariable=self.custom_word_var,
            width=20,
            font=("Helvetica", 12),
            state='disabled'
        )
        self.custom_word_entry.grid(row=5, column=1, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.custom_word_entry, "Enter the custom word to include in the password")

        # Include Random Word
        self.include_random_word_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Random Word",
            variable=self.include_random_word_var,
            bootstyle=INFO
        )
        self.include_random_word_check.grid(row=6, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.include_random_word_check, "Include a random word from categories if no word is selected")

    # ------------------- Character Types -------------------
    def setup_character_types(self):
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

    # ------------------- Password Output -------------------
    def setup_password_output(self):
        self.output_frame = ttk.Frame(self.password_frame)
        self.output_frame.pack(padx=10, pady=5, fill=BOTH, expand=True)
        self.output_frame.columnconfigure(0, weight=1)
        self.output_frame.columnconfigure(1, weight=0)

        # Generated Password Display
        self.password_display = ScrolledText(
            self.output_frame,
            wrap='word',
            font=("Helvetica", 14),
            state='disabled',
            height=4
        )
        self.password_display.grid(row=0, column=0, sticky=NSEW, padx=(0, 10), pady=5)
        create_tooltip(self.password_display, "Generated password(s) will appear here")

        # Copy Button
        self.copy_button = ttk.Button(
            self.output_frame,
            text="Copy to Clipboard",
            command=self.copy_to_clipboard,
            bootstyle=INFO,
            width=20
        )
        self.copy_button.grid(row=0, column=1, sticky=N, pady=5, padx=5)
        create_tooltip(self.copy_button, "Copy the generated password(s) to clipboard")

        # Clear Button
        self.clear_password_button = ttk.Button(
            self.output_frame,
            text="Clear",
            command=self.clear_generated_password,
            bootstyle=SECONDARY,
            width=20
        )
        self.clear_password_button.grid(row=1, column=1, sticky=N, pady=5, padx=5)
        create_tooltip(self.clear_password_button, "Clear the generated password(s)")

    # ------------------- Save Password Info -------------------
    def setup_save_password_info(self):
        self.save_password_frame = ttk.Labelframe(self.password_frame, text="Save Password Information")
        self.save_password_frame.pack(padx=10, pady=5, fill=X)
        for i in range(4):
            self.save_password_frame.columnconfigure(i, weight=1)

        # Password Name
        ttk.Label(self.save_password_frame, text="Password Name:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.save_website_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_website_var)
        self.save_website_entry.grid(row=0, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_website_entry, "Enter a name for the password entry")

        # URL Entry
        ttk.Label(self.save_password_frame, text="URL:").grid(row=0, column=2, sticky=W, padx=5, pady=5)
        self.save_url_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_url_var)
        self.save_url_entry.grid(row=0, column=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_url_entry, "Enter the URL associated with this entry")

        # Browse File Button
        self.browse_entry_file_button = ttk.Button(
            self.save_password_frame,
            text="Browse File",
            command=lambda: self.browse_entry_file('password_tab'),
            bootstyle=INFO
        )
        self.browse_entry_file_button.grid(row=1, column=0, sticky=W, padx=5, pady=5)
        create_tooltip(self.browse_entry_file_button, "Select a file associated with this entry")

        # File Path Entry (read-only)
        self.file_path_entry = ttk.Entry(
            self.save_password_frame,
            textvariable=self.save_file_var,
            width=30,
            state='readonly',
            font=("Helvetica", 10)
        )
        self.file_path_entry.grid(row=1, column=1, columnspan=3, sticky=W, padx=5, pady=5)
        create_tooltip(self.file_path_entry, "Selected file path will appear here")

        # Username
        ttk.Label(self.save_password_frame, text="Username:").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_username_var)
        self.username_entry.grid(row=2, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.username_entry, "Enter the username (optional)")

        # Email
        ttk.Label(self.save_password_frame, text="Email:").grid(row=2, column=2, sticky=W, padx=5, pady=5)
        self.email_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_email_var)
        self.email_entry.grid(row=2, column=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.email_entry, "Enter the email (optional)")

        # Phone Number
        ttk.Label(self.save_password_frame, text="Phone Number:").grid(row=3, column=0, sticky=W, padx=5, pady=5)
        self.phone_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_phone_var)
        self.phone_entry.grid(row=3, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.phone_entry, "Enter the phone number (optional)")
        vcmd = (self.master.register(validate_phone_number), '%P')
        self.phone_entry.configure(validate='key', validatecommand=vcmd)

        # Address
        ttk.Label(self.save_password_frame, text="Address:").grid(row=3, column=2, sticky=NW, padx=5, pady=5)
        self.save_address_text = ScrolledText(self.save_password_frame, height=3)
        self.save_address_text.grid(row=3, column=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_address_text, "Enter the address (optional)")
        self.save_address_text.bind("<FocusOut>", format_address_input)

        # Subscription Provider
        ttk.Label(self.save_password_frame, text="Subscription Provider:").grid(row=4, column=0, sticky=W, padx=5, pady=5)
        self.save_subscription_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_subscription_var)
        self.save_subscription_entry.grid(row=4, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_subscription_entry, "Enter the subscription provider (optional)")

        # PIN
        ttk.Label(self.save_password_frame, text="PIN:").grid(row=4, column=2, sticky=W, padx=5, pady=5)
        self.save_pin_entry = ttk.Entry(self.save_password_frame, textvariable=self.save_pin_var, show='*')
        self.save_pin_entry.grid(row=4, column=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_pin_entry, "Enter the PIN (optional)")

        # Multi-Factor Authentication
        ttk.Label(self.save_password_frame, text="MFA Info:").grid(row=5, column=0, sticky=NW, padx=5, pady=5)
        self.save_mfa_text = ScrolledText(self.save_password_frame, height=3)
        self.save_mfa_text.grid(row=5, column=1, columnspan=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_mfa_text, "Enter MFA information like recovery codes or setup keys (optional)")

        # Notes
        ttk.Label(self.save_password_frame, text="Notes:").grid(row=6, column=0, sticky=NW, padx=5, pady=5)
        self.save_notes_text = ScrolledText(self.save_password_frame, height=3)
        self.save_notes_text.grid(row=6, column=1, columnspan=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_notes_text, "Enter any additional notes (optional)")

        # Save Button
        self.save_button = ttk.Button(
            self.password_frame,
            text="Save to Database",
            command=self.save_password_to_db,
            bootstyle=PRIMARY,
            width=20
        )
        self.save_button.pack(pady=10)
        create_tooltip(self.save_button, "Save the generated password(s) to the database")

    # ------------------- Password Strength Indicator -------------------
    def setup_password_strength_indicator(self):
        self.strength_frame = ttk.Frame(self.password_frame)
        self.strength_frame.pack(padx=10, pady=5, fill=X)
        self.strength_frame.columnconfigure(1, weight=1)

        self.strength_label = ttk.Label(self.strength_frame, text="Password Strength:")
        self.strength_label.grid(row=0, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.strength_label, "Displays the strength of the generated password")

        self.strength_display = ttk.Label(
            self.strength_frame,
            textvariable=self.strength_var,
            font=("Helvetica", 12, "bold")
        )
        self.strength_display.grid(row=0, column=1, sticky=W, pady=5, padx=5)

        self.strength_progress = ttk.Progressbar(
            self.strength_frame,
            orient='horizontal',
            length=200,
            mode='determinate'
        )
        self.strength_progress.grid(row=0, column=2, sticky=W, pady=5, padx=5)

    # ------------------- Stored Passwords Tab Setup -------------------
    def setup_stored_passwords_tab(self):
        """Setup the stored passwords tab"""
        # Configure grid weights
        self.stored_passwords_tab.grid_columnconfigure(0, weight=3)  # Left space takes 3/4
        self.stored_passwords_tab.grid_columnconfigure(1, weight=1)  # Right space takes 1/4
        self.stored_passwords_tab.grid_rowconfigure(3, weight=1)  # Increased to make room for button

        # Create stored frame
        self.stored_frame = ttk.Frame(self.stored_passwords_tab)
        self.stored_frame.grid(row=3, column=0, columnspan=2, sticky=NSEW, padx=10, pady=5)

        # Add New button and Generate Password button side by side
        button_frame = ttk.Frame(self.stored_passwords_tab)
        button_frame.grid(row=2, column=0, columnspan=2, sticky=E, padx=(0, 845), pady=5)

        self.add_new_button = ttk.Button(
            button_frame,
            text="➕ Add New Password",
            command=self.add_new_entry,
            style='Accent.TButton'
        )
        self.add_new_button.grid(row=0, column=0, padx=(0, 5))

        self.generate_button = ttk.Button(
            button_frame,
            text="🎲 Generate Password",
            command=self.generate_for_new_entry,
            style='Accent.TButton',
            state=DISABLED
        )
        self.generate_button.grid(row=0, column=1)

        # Configure weights for proper resizing
        self.stored_passwords_tab.grid_rowconfigure(1, weight=1)
        self.stored_passwords_tab.grid_columnconfigure(0, weight=1)
        
        # Configure stored frame weights
        self.stored_frame.grid_columnconfigure(0, weight=1)
        self.stored_frame.grid_rowconfigure(0, weight=1)

        # Create treeview frame
        self.treeview_frame = ttk.Frame(self.stored_frame)
        self.treeview_frame.grid(row=0, column=0, sticky="nsew")
        self.treeview_frame.grid_columnconfigure(0, weight=1)
        self.treeview_frame.grid_rowconfigure(0, weight=1)

        # Create treeview
        self.password_tree = ttk.Treeview(
            self.treeview_frame,
            columns=("id", "title", "username", "password", "url", "created_at"),
            show='headings',
            selectmode='browse'
        )

        # Configure columns
        self.password_tree.heading("id", text="ID", anchor="w")
        self.password_tree.heading("title", text="Title", anchor="w")
        self.password_tree.heading("username", text="Username", anchor="w")
        self.password_tree.heading("password", text="Password", anchor="w")
        self.password_tree.heading("url", text="URL", anchor="w")
        self.password_tree.heading("created_at", text="Created At", anchor="w")

        # Set column widths and anchors
        self.password_tree.column("id", width=50, anchor="w")
        self.password_tree.column("title", width=200, anchor="w")
        self.password_tree.column("username", width=150, anchor="w")
        self.password_tree.column("password", width=100, anchor="w")
        self.password_tree.column("url", width=200, anchor="w")
        self.password_tree.column("created_at", width=150, anchor="w")

        self.password_tree.grid(row=0, column=0, sticky="nsew")
        self.password_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Add scrollbar
        self.tree_scroll = ttk.Scrollbar(self.treeview_frame, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.grid(row=0, column=1, sticky="ns")

        # Entry Form Frame
        self.entry_form_frame = ttk.Frame(self.stored_frame)
        self.entry_form_frame.grid(row=0, column=1, sticky="nsew", padx=10)
        self.entry_form_frame.grid_columnconfigure(1, weight=1)

        # Initialize and populate the form
        self.initialize_entry_form_fields()
        self.populate_entry_form()

        # Initialize Search Module
        self.search_module = SearchModule(
            self.stored_passwords_tab,  # Parent is the tab itself
            self.password_tree,
            user_id=self.user_id
        )

    # ------------------- Initialize Entry Form Fields -------------------
    def initialize_entry_form_fields(self):
        self.save_address_text = ScrolledText(self.entry_form_frame, height=3)
        self.save_mfa_text = ScrolledText(self.entry_form_frame, height=3)
        self.save_notes_text = ScrolledText(self.entry_form_frame, height=3)
        self.security_questions = []

    # ------------------- Populate Entry Form -------------------
    def populate_entry_form(self):
        # Password Name
        ttk.Label(self.entry_form_frame, text="Password Name:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.save_website_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_website_var)
        self.save_website_entry.grid(row=0, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_website_entry, "Enter a name for the password entry")

        # URL Entry
        ttk.Label(self.entry_form_frame, text="URL:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.save_url_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_url_var)
        self.save_url_entry.grid(row=1, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_url_entry, "Enter the URL associated with this entry")

        # Browse File Button and File Path Entry
        self.browse_entry_file_button = ttk.Button(
            self.entry_form_frame,
            text="Browse File",
            command=lambda: self.browse_entry_file('entry_form_frame'),
            bootstyle=INFO
        )
        self.browse_entry_file_button.grid(row=1, column=2, sticky=W, padx=5, pady=5)
        create_tooltip(self.browse_entry_file_button, "Select a file associated with this entry")

        self.entry_file_path_entry = ttk.Entry(
            self.entry_form_frame,
            textvariable=self.entry_file_var,
            width=30,
            state='readonly',
            font=("Helvetica", 10)
        )
        self.entry_file_path_entry.grid(row=1, column=3, sticky=W, padx=5, pady=5)
        create_tooltip(self.entry_file_path_entry, "Selected file path will appear here")

        # Username
        ttk.Label(self.entry_form_frame, text="Username:").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_username_var)
        self.username_entry.grid(row=2, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.username_entry, "Enter the username (optional)")

        # Email
        ttk.Label(self.entry_form_frame, text="Email:").grid(row=3, column=0, sticky=W, padx=5, pady=5)
        self.email_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_email_var)
        self.email_entry.grid(row=3, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.email_entry, "Enter the email (optional)")

        # Phone Number
        ttk.Label(self.entry_form_frame, text="Phone Number:").grid(row=4, column=0, sticky=W, padx=5, pady=5)
        self.phone_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_phone_var)
        self.phone_entry.grid(row=4, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.phone_entry, "Enter the phone number (optional)")
        vcmd = (self.master.register(validate_phone_number), '%P')
        self.phone_entry.configure(validate='key', validatecommand=vcmd)

        # Address
        ttk.Label(self.entry_form_frame, text="Address:").grid(row=5, column=0, sticky=NW, padx=5, pady=5)
        self.save_address_text.grid(row=5, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_address_text, "Enter the address (optional)")
        self.save_address_text.bind("<FocusOut>", format_address_input)

        # Subscription Provider
        ttk.Label(self.entry_form_frame, text="Subscription Provider:").grid(row=6, column=0, sticky=W, padx=5, pady=5)
        self.save_subscription_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_subscription_var)
        self.save_subscription_entry.grid(row=6, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_subscription_entry, "Enter the subscription provider (optional)")

        # PIN
        ttk.Label(self.entry_form_frame, text="PIN:").grid(row=7, column=0, sticky=W, padx=5, pady=5)
        self.save_pin_entry = ttk.Entry(self.entry_form_frame, textvariable=self.save_pin_var, show='*')
        self.save_pin_entry.grid(row=7, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_pin_entry, "Enter the PIN (optional)")

        # Password
        ttk.Label(self.entry_form_frame, text="Password*:").grid(row=8, column=0, sticky=W, padx=5, pady=5)
        
        # Create a frame for password field and buttons
        password_frame = ttk.Frame(self.entry_form_frame)
        password_frame.grid(row=8, column=1, sticky=EW, padx=5, pady=5)
        password_frame.columnconfigure(0, weight=1)  # Make password entry expand

        # Password entry
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="•")
        self.password_entry.grid(row=0, column=0, sticky=EW)

        # Modern show/hide password button (using eye symbols)
        self.show_password_button = ttk.Button(
            password_frame,
            text="👁",  # Modern eye symbol
            width=3,
            command=self.toggle_show_password
        )
        self.show_password_button.grid(row=0, column=1, padx=(2, 0))
        create_tooltip(self.show_password_button, "Show/Hide Password")

        # Modern copy password button
        self.copy_password_button_entry = ttk.Button(
            password_frame,
            text="📋",  # Modern clipboard symbol
            width=3,
            command=self.copy_password_from_entry
        )
        self.copy_password_button_entry.grid(row=0, column=2, padx=(2, 0))
        create_tooltip(self.copy_password_button_entry, "Copy Password")

        # Save button with modern styling
        self.save_button = ttk.Button(
            self.entry_form_frame,
            text="💾 Save Entry",
            command=self.save_password_to_db,
            style='Accent.TButton'
        )
        self.save_button.grid(row=15, column=1, sticky=W, padx=5, pady=10)

        # Security Questions
        ttk.Label(self.entry_form_frame, text="Security Questions:").grid(row=9, column=0, sticky=NW, padx=5, pady=5)
        self.security_questions_frame = ttk.Frame(self.entry_form_frame)
        self.security_questions_frame.grid(row=9, column=1, sticky=EW, padx=5, pady=5)
        self.populate_security_questions()
        create_tooltip(self.security_questions_frame, "Enter up to 5 security questions and answers (optional)")

        # Multi-Factor Authentication
        ttk.Label(self.entry_form_frame, text="MFA Info:").grid(row=10, column=0, sticky=NW, padx=5, pady=5)
        self.save_mfa_text.grid(row=10, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_mfa_text, "Enter MFA information like recovery codes or setup keys (optional)")

        # Notes
        ttk.Label(self.entry_form_frame, text="Notes:").grid(row=11, column=0, sticky=NW, padx=5, pady=5)
        self.save_notes_text.grid(row=11, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_notes_text, "Enter any additional notes (optional)")

        # Action Buttons
        self.setup_entry_form_buttons()

    # ------------------- Populate Security Questions -------------------
    def populate_security_questions(self):
        for i in range(5):
            question_var = tk.StringVar()
            answer_var = tk.StringVar()
            ttk.Entry(self.security_questions_frame, textvariable=question_var, width=30).grid(row=i, column=0, sticky=W, pady=2)
            ttk.Entry(self.security_questions_frame, textvariable=answer_var, width=30, show='*').grid(row=i, column=1, sticky=W, pady=2)
            self.security_questions.append((question_var, answer_var))

    # ------------------- Entry Form Buttons -------------------
    def setup_entry_form_buttons(self):
        """Setup the buttons in the entry form"""
        self.buttons_frame = ttk.Frame(self.entry_form_frame)
        self.buttons_frame.grid(row=12, column=0, columnspan=4, pady=10)
        self.buttons_frame.grid_columnconfigure((0,1,2,3,4), weight=1)

        self.add_button = ttk.Button(
            self.buttons_frame,
            text="Add New",
            command=self.add_new_entry,
            bootstyle=SUCCESS,
            width=15
        )
        self.add_button.grid(row=0, column=0, padx=5)
        create_tooltip(self.add_button, "Add a new password entry")

        self.update_button = ttk.Button(
            self.buttons_frame,
            text="Update",
            command=self.update_existing_entry,
            bootstyle=PRIMARY,
            width=15,
            state=DISABLED
        )
        self.update_button.grid(row=0, column=1, padx=5)
        create_tooltip(self.update_button, "Update the selected password entry")

        self.clear_button = ttk.Button(
            self.buttons_frame,
            text="Clear",
            command=self.clear_entry_form,
            bootstyle=INFO,
            width=15
        )
        self.clear_button.grid(row=0, column=2, padx=5)
        create_tooltip(self.clear_button, "Clear the form fields")

        self.delete_button = ttk.Button(
            self.buttons_frame,
            text="Delete",
            command=self.delete_password,
            bootstyle=DANGER,
            width=15,
            state=DISABLED
        )
        self.delete_button.grid(row=0, column=3, padx=5)
        create_tooltip(self.delete_button, "Delete the selected password entry")

        self.copy_password_button = ttk.Button(
            self.buttons_frame,
            text="Copy Password",
            command=self.copy_password_from_entry,
            bootstyle=WARNING,
            width=15,
            state=DISABLED
        )
        self.copy_password_button.grid(row=0, column=4, padx=5)
        create_tooltip(self.copy_password_button, "Copy the password to clipboard")

    # ------------------- Load Word Lists -------------------
    def load_word_lists(self) -> dict:
        if not os.path.exists(self.word_lists_file):
            default_word_lists = {
                "Animals": ["Lion", "Tiger", "Elephant", "Giraffe", "Zebra"],
                "Fruits": ["Apple", "Banana", "Cherry", "Date", "Elderberry"],
                "Colors": ["Red", "Blue", "Green", "Yellow", "Purple"],
                "Cities": ["New York", "Paris", "Tokyo", "Sydney", "Cairo"],
                "Vehicles": ["Car", "Bicycle", "Airplane", "Boat", "Motorcycle"]
            }
            self.save_word_lists(default_word_lists)
            return default_word_lists
        else:
            try:
                with open(self.word_lists_file, 'r') as f:
                    word_lists = json.load(f)
                self.logger.info("Word lists loaded successfully.")
                return word_lists
            except Exception as e:
                self.logger.error(f"Failed to load word lists: {e}")
                messagebox.showerror("Load Error", "Failed to load word lists. Initializing with default categories.")
                default_word_lists = {
                    "Animals": ["Lion", "Tiger", "Elephant", "Giraffe", "Zebra"],
                    "Fruits": ["Apple", "Banana", "Cherry", "Date", "Elderberry"],
                    "Colors": ["Red", "Blue", "Green", "Yellow", "Purple"],
                    "Cities": ["New York", "Paris", "Tokyo", "Sydney", "Cairo"],
                    "Vehicles": ["Car", "Bicycle", "Airplane", "Boat", "Motorcycle"]
                }
                self.save_word_lists(default_word_lists)
                return default_word_lists

    # ------------------- Save Word Lists -------------------
    def save_word_lists(self, word_lists: dict = None):
        if word_lists is None:
            word_lists = self.categorized_word_lists
        try:
            with open(self.word_lists_file, 'w') as f:
                json.dump(word_lists, f, indent=4)
            self.logger.info("Word lists saved successfully.")
        except Exception as e:
            self.logger.error(f"Failed to save word lists: {e}")
            messagebox.showerror("Save Error", "Failed to save word lists.")

    # ------------------- Browse Entry File -------------------
    def browse_entry_file(self, frame_identifier):
        file_path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            self.logger.info(f"File selected: {file_path}")

            if frame_identifier == 'password_tab' and hasattr(self, 'save_file_var'):
                self.save_file_var.set(file_path)
            elif frame_identifier == 'entry_form_frame' and hasattr(self, 'entry_file_var'):
                self.entry_file_var.set(file_path)
        else:
            self.logger.info("No file selected.")

    # ------------------- Toggle Preset Word Options -------------------
    def toggle_preset_word_options(self):
        if self.include_preset_word_var.get():
            self.preset_category_dropdown.configure(state='readonly')
            if self.preset_category_var.get():
                self.update_preset_word_options()
        else:
            self.preset_category_dropdown.configure(state='disabled')
            self.preset_word_dropdown.configure(state='disabled')
            self.preset_word_var.set('')
            self.preset_category_var.set('')
            self.preset_word_dropdown.set('')

    # ------------------- Update Preset Word Options -------------------
    def update_preset_word_options(self, event=None):
        category = self.preset_category_var.get()
        words = self.categorized_word_lists.get(category, [])
        if words:
            self.preset_word_dropdown.configure(state='readonly', values=words)
            self.preset_word_dropdown.current(0)
        else:
            self.preset_word_dropdown.configure(state='disabled', values=[])
            self.preset_word_var.set('')

    # ------------------- Toggle Custom Word Entry -------------------
    def toggle_custom_word_entry(self):
        if self.include_custom_word_var.get():
            self.custom_word_entry.configure(state='normal')
        else:
            self.custom_word_entry.configure(state='disabled')
            self.custom_word_var.set('')

    # ------------------- Validate Password Length -------------------
    def validate_length(self, event=None):
        try:
            length = int(self.length_var.get())
            if length < 4 or length > 128:
                raise ValueError
            self.length_entry.configure(background='white')
        except ValueError:
            self.length_entry.configure(background='pink')
            messagebox.showerror("Invalid Input", "Password length must be between 4 and 128.")
            self.length_var.set("16")

    # ------------------- Generate Password Event Handler -------------------
    def generate_password_event(self):
        self.generate_password()

    # ------------------- Generate Password Logic -------------------
    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 4 or length > 128:
                raise ValueError("Password length must be between 4 and 128.")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid password length: {ve}")
            self.status_var.set("")
            self.update_strength_display()
            return

        try:
            count = int(self.multiple_var.get())
            if count < 1 or count > 20:
                raise ValueError("Number of passwords must be between 1 and 20.")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", f"Invalid number of passwords: {ve}")
            self.status_var.set("")
            self.update_strength_display()
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
            self.password_display.delete('1.0', tk.END)
            if count == 1:
                self.password_display.insert('1.0', passwords[0])
                strength_label, value, color, entropy = assess_strength(passwords[0])
                self.update_strength_display(strength_label, value, color)
                # Provide feedback
                settings = {
                    'use_upper': self.use_upper_var.get(),
                    'use_lower': self.use_lower_var.get(),
                    'use_digits': self.use_digits_var.get(),
                    'use_punctuation': self.use_punctuation_var.get(),
                    'exclude_similar': self.exclude_similar_var.get()
                }
                feedback = f"Entropy: {entropy:.2f} bits.\n"
                if strength_label in ["Weak", "Moderate"]:
                    recommendations = get_password_recommendations(passwords[0], settings)
                    feedback += "Recommendations:\n- " + "\n- ".join(recommendations)
                else:
                    feedback += "Your password is strong."
                self.feedback_var.set(feedback)
            else:
                for idx, pwd in enumerate(passwords, 1):
                    self.password_display.insert(tk.END, f"{idx}. {pwd}\n")
                self.update_strength_display("Varied", 50, 'info')
                self.feedback_var.set("")
            self.password_display.configure(state='disabled')
            self.status_var.set(f"{count} password(s) generated successfully!")
            self.status_label.configure(bootstyle="success")
        except ValueError as ve:
            messagebox.showerror("Selection Error", str(ve))
            self.status_var.set("")
            self.update_strength_display()
            return

    # ------------------- Update Strength Display -------------------
    def update_strength_display(self, strength_label="N/A", value=0, color='secondary'):
        self.strength_var.set(strength_label)
        self.strength_progress['value'] = value
        self.strength_progress.configure(bootstyle=color)
        self.feedback_var.set("")

    # ------------------- Save Password to Database -------------------
    def save_password_to_db(self):
        # Get password from either the display or the entry field
        display_passwords = self.password_display.get('1.0', tk.END).strip().split('\n')
        manual_password = self.password_var.get().strip()
        
        if not manual_password and (not display_passwords or display_passwords == ['']):
            messagebox.showwarning("No Password", "Please enter or generate a password.")
            return

        title = self.save_website_var.get().strip()
        if not title:
            messagebox.showwarning("Required Field", "Please enter a title/website name.")
            return

        # Use the manual password if entered, otherwise use generated passwords
        passwords = [manual_password] if manual_password else display_passwords

        url = self.save_url_var.get().strip()
        username = self.save_username_var.get().strip()
        email = self.save_email_var.get().strip()
        phone = self.save_phone_var.get().strip()
        address = self.save_address_text.get('1.0', tk.END).strip()
        subscription = self.save_subscription_var.get().strip()
        pin = self.save_pin_var.get().strip()
        mfa_info = self.save_mfa_text.get('1.0', tk.END).strip()
        notes = self.save_notes_text.get('1.0', tk.END).strip() or "N/A"
        file_path = self.save_file_var.get().strip() or None

        security_questions = []
        for q_var, a_var in self.security_questions:
            question = q_var.get().strip()
            answer = a_var.get().strip()
            if question and answer:
                security_questions.append({'question': question, 'answer': answer})

        for pwd in passwords:
            if pwd.startswith(tuple(f"{i}. " for i in range(1, 21))):
                pwd = pwd.split(". ", 1)[1]

            # Encrypt the password before saving
            encrypted_password = encryption_manager.encrypt(pwd)
            if not encrypted_password:
                messagebox.showerror("Encryption Error", "Failed to encrypt the password.")
                return

            # Encrypt PIN if provided
            encrypted_pin = encryption_manager.encrypt(pin) if pin else None

            # Encrypt MFA Info if provided
            encrypted_mfa_info = encryption_manager.encrypt(mfa_info) if mfa_info else None

            # Encrypt security answers
            encrypted_security_questions = []
            if security_questions:
                for qa in security_questions:
                    encrypted_answer = encryption_manager.encrypt(qa['answer'])
                    encrypted_security_questions.append({
                        'question': qa['question'],
                        'answer': encrypted_answer
                    })
                security_questions_json = json.dumps(encrypted_security_questions)
            else:
                security_questions_json = None

            # Create entry in database
            try:
                create_entry(
                    user_id=self.user_id,
                    title=title,
                    url=url,
                    username=username,
                    encrypted_password=encrypted_password,
                    email=email,
                    phone=phone,
                    address=address,
                    subscription=subscription,
                    pin=encrypted_pin,
                    security_questions=security_questions_json,
                    mfa_info=encrypted_mfa_info,
                    notes=notes,
                    file_path=file_path
                )
                self.logger.info(f"Password for {title} saved successfully.")
            except Exception as e:
                self.logger.error(f"Failed to save password for {title}: {e}")
                messagebox.showerror("Database Error", f"Failed to save password for '{title}': {e}")
                return

        messagebox.showinfo("Success", f"Password(s) for '{title}' saved successfully!")
        self.clear_save_password_form()
        self.load_stored_passwords()

    # ------------------- Clear Save Password Form -------------------
    def clear_save_password_form(self):
        self.save_website_var.set('')
        self.save_url_var.set('')
        self.save_username_var.set('')
        self.save_email_var.set('')
        self.save_phone_var.set('')
        self.save_address_text.delete('1.0', tk.END)
        self.save_subscription_var.set('')
        self.save_pin_var.set('')
        self.save_mfa_text.delete('1.0', tk.END)
        self.save_notes_text.delete('1.0', tk.END)
        self.save_file_var.set('')
        for q_var, a_var in self.security_questions:
            q_var.set('')
            a_var.set('')

    # ------------------- Update Existing Entry -------------------
    def update_existing_entry(self):
        entry_id = self.entry_id_var.get()
        if not entry_id:
            messagebox.showwarning("No Selection", "No entry selected for updating.")
            return

        title = self.save_website_var.get().strip()
        password = self.password_var.get().strip()

        if not title:
            messagebox.showwarning("Required Field", "Please enter a title/website name.")
            self.save_website_entry.focus()
            return

        if not password:
            messagebox.showwarning("Required Field", "Please enter a password.")
            self.password_entry.focus()
            return

        try:
            # Gather and encrypt data (similar to save_password_to_db)
            # Update the entry in the database
            # Show success message
            messagebox.showinfo("Success", f"Password entry '{title}' updated successfully!")
            self.load_stored_passwords()
        except Exception as e:
            self.logger.error(f"Failed to update password entry: {e}")
            messagebox.showerror("Error", f"Failed to update password entry: {str(e)}")

    # ------------------- Delete Password -------------------
    def delete_password(self):
        entry_id = self.entry_id_var.get()
        if not entry_id:
            messagebox.showwarning("No Selection", "No entry selected for deletion.")
            return

        title = self.save_website_var.get()
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for '{title}'?"):
            try:
                delete_entry(user_id=self.user_id, entry_id=int(entry_id))
                self.logger.info(f"Password entry {entry_id} deleted successfully.")
                messagebox.showinfo("Success", f"Password for '{title}' deleted successfully!")
                self.clear_entry_form()
                self.load_stored_passwords()
            except Exception as e:
                self.logger.error(f"Failed to delete password entry {entry_id}: {e}")
                messagebox.showerror("Database Error", f"Failed to delete password entry: {e}")

    # ------------------- Copy Password from Entry -------------------
    def copy_password_from_entry(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            self.stored_passwords_status_var.set("Password copied to clipboard! It will be cleared in 30 seconds.")
            self.stored_passwords_status_label.configure(bootstyle="success")
            threading.Timer(30.0, self.clear_clipboard_password_tab).start()
        else:
            self.stored_passwords_status_var.set("No password to copy.")
            self.stored_passwords_status_label.configure(bootstyle="danger")

    # ------------------- Clear Clipboard -------------------
    def clear_clipboard_password_tab(self):
        pyperclip.copy('')
        self.stored_passwords_status_var.set("Clipboard cleared.")
        self.stored_passwords_status_label.configure(bootstyle="info")

    # ------------------- Clear Entry Form -------------------
    def clear_entry_form(self):
        self.entry_id_var.set('')
        self.save_website_var.set('')
        self.save_url_var.set('')
        self.password_var.set('')
        self.save_email_var.set('')
        self.save_phone_var.set('')
        self.save_address_text.delete('1.0', tk.END)
        self.save_subscription_var.set('')
        self.save_pin_var.set('')
        self.save_mfa_text.delete('1.0', tk.END)
        self.save_notes_text.delete('1.0', tk.END)
        self.entry_file_var.set('')
        for q_var, a_var in self.security_questions:
            q_var.set('')
            a_var.set('')
        self.update_button.configure(state=DISABLED)
        self.delete_button.configure(state=DISABLED)
        self.copy_password_button.configure(state=DISABLED)

    # ------------------- Load Stored Passwords -------------------
    def load_stored_passwords(self, search_query=None):
        try:
            entries = read_entries(user_id=self.user_id, search_query=search_query)
            # Clear existing entries
            for item in self.password_tree.get_children():
                self.password_tree.delete(item)

            for entry in entries:
                # Format the display values
                values = (
                    entry['id'],
                    entry['title'] or '',
                    entry.get('username', '') or '',
                    '••••••••',  # Masked password
                    entry.get('url', '') or '',
                    entry['created_at'].strftime('%Y-%m-%d %H:%M') if entry['created_at'] else '',
                )
                
                self.password_tree.insert('', 'end', values=values)

            self.logger.info("Stored passwords loaded successfully.")
            
        except Exception as e:
            self.logger.error(f"Failed to load stored passwords: {e}")
            messagebox.showerror("Error", "Failed to load stored passwords")

    # ------------------- On Tree Select -------------------
    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
            
        try:
            # Get the selected item's values
            item = self.password_tree.item(selection[0])
            values = item['values']
            if not values:
                return
                
            # Get the ID from the first column (we know it's always the first column)
            entry_id = values[0]
            if not isinstance(entry_id, int):
                self.logger.warning(f"Invalid entry ID format: {entry_id}")
                return

            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
                
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button

            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')

            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')

            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            self.save_subscription_var.set(entry.get('subscription', '') or '')
            self.save_pin_var.set(entry.get('pin', '') or '')
            self.save_file_var.set(entry.get('file_path', '') or '')

            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')

            self.save_mfa_text.delete('1.0', tk.END)
            self.save_mfa_text.insert('1.0', entry.get('mfa_info', '') or '')

            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')

        except ValueError as e:
            self.logger.error(f"Failed to parse entry ID: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    # ------------------- Toggle Show Password -------------------
    def toggle_show_password(self):
        """Toggle password visibility"""
        current_state = self.password_entry.cget('show')
        if current_state == '•':
            self.password_entry.configure(show='')
            self.save_pin_entry.configure(show='')
            self.show_password_button.configure(text='🔒')  # Locked icon
        else:
            self.password_entry.configure(show='•')
            self.save_pin_entry.configure(show='*')
            self.show_password_button.configure(text='👁')  # Eye icon

    # ------------------- Clear Generated Password -------------------
    def clear_generated_password(self):
        self.password_display.configure(state='normal')
        self.password_display.delete('1.0', tk.END)
        self.password_display.configure(state='disabled')
        self.status_var.set("Generated password(s) cleared.")
        self.status_label.configure(bootstyle="info")

    # ------------------- Clipboard Functionality -------------------
    def copy_to_clipboard(self):
        passwords = self.password_display.get('1.0', tk.END).strip()
        if passwords:
            pyperclip.copy(passwords)
            self.status_var.set("Password(s) copied to clipboard! It will be cleared in 30 seconds.")
            self.status_label.configure(bootstyle="success")
            threading.Timer(30.0, self.clear_clipboard_password_tab).start()
        else:
            self.status_var.set("No password to copy.")
            self.status_label.configure(bootstyle="danger")

    def clear_clipboard_password_tab(self):
        pyperclip.copy('')
        self.status_var.set("Clipboard cleared.")
        self.status_label.configure(bootstyle="info")

    # ------------------- Keyboard Shortcuts -------------------
    def bind_shortcuts(self):
        self.master.bind('<Control-g>', lambda event: self.generate_password_event())
        self.master.bind('<Control-p>', lambda event: self.passphrase_generator.generate_passphrase_event())
        self.master.bind('<Control-c>', lambda event: self.copy_to_clipboard())

    # ------------------- On Closing -------------------
    def on_closing(self):
        self.save_word_lists()
        self.master.destroy()

    def display_stored_entries(self, entries=None):
        """Display stored password and passphrase entries in the treeview"""
        if entries is None:
            entries = read_entries(self.user_id)

        # Clear existing entries
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)

        for entry in entries:
            # Format the display values
            values = (
                entry['id'],
                entry['title'] or '',
                entry.get('username', '') or '',
                '••••••••',  # Masked password
                entry.get('url', '') or '',
                entry['created_at'].strftime('%Y-%m-%d %H:%M') if entry['created_at'] else '',
            )
            
            self.password_tree.insert('', 'end', values=values)

    def save_passphrase(self, title, passphrase, notes=""):
        """Save the generated passphrase"""
        try:
            # Encrypt the passphrase before storing
            encrypted_passphrase = encryption_manager.encrypt(passphrase)
            
            # Create entry with passphrase
            create_entry(
                user_id=self.user_id,
                title=title,
                pass_phrase=encrypted_passphrase,  # Store in pass_phrase field
                notes=notes,
                password=""  # Empty password field for passphrase entries
            )
            
            messagebox.showinfo("Success", "Passphrase saved successfully!")
            self.refresh_stored_entries()
            
        except Exception as e:
            logger.error(f"Error saving passphrase: {str(e)}")
            messagebox.showerror("Error", f"Failed to save passphrase: {str(e)}")

    def add_new_entry(self):
        """Prepare the form for a new entry"""
        self.clear_entry_form()
        self.is_new_entry = True
        self.entry_id_var.set("")  # Clear any selected entry ID
        self.save_button.configure(state=NORMAL)  # Enable save button
        self.update_button.configure(state=DISABLED)  # Disable update button
        self.delete_button.configure(state=DISABLED)  # Disable delete button
        self.copy_password_button.configure(state=DISABLED)  # Disable copy button
        self.save_website_entry.focus()  # Set focus to the first field

    def update_form_buttons(self):
        """Update the form buttons based on whether we're creating a new entry or viewing existing"""
        if self.is_new_entry:
            # Enable save button, disable others
            self.add_button.configure(state=NORMAL)
            self.generate_button.configure(state=NORMAL)  # Enable generate button for new entries
            self.update_button.configure(state=DISABLED)
            self.delete_button.configure(state=DISABLED)
            self.copy_password_button.configure(state=DISABLED)
        else:
            # Enable update, delete, and copy buttons
            self.add_button.configure(state=NORMAL)
            self.generate_button.configure(state=DISABLED)  # Disable generate button for existing entries
            self.update_button.configure(state=NORMAL)
            self.delete_button.configure(state=NORMAL)
            self.copy_password_button.configure(state=NORMAL)

    def update_password_entry(self):
        """Update an existing password entry"""
        entry_id = self.entry_id_var.get()
        if not entry_id:
            messagebox.showwarning("Error", "No entry selected to update.")
            return
            
        # Similar validation as save_password_to_db
        title = self.save_website_var.get().strip()
        password = self.password_var.get().strip()

        if not title:
            messagebox.showwarning("Required Field", "Please enter a title/website name.")
            self.save_website_entry.focus()
            return

        if not password:
            messagebox.showwarning("Required Field", "Please enter a password.")
            self.password_entry.focus()
            return

        try:
            # Gather and encrypt data (similar to save_password_to_db)
            # Update the entry in the database
            # Show success message
            messagebox.showinfo("Success", f"Password entry '{title}' updated successfully!")
            self.load_stored_passwords()
        except Exception as e:
            self.logger.error(f"Failed to update password entry: {e}")
            messagebox.showerror("Error", f"Failed to update password entry: {str(e)}")

    def delete_password_entry(self):
        """Delete the selected password entry"""
        entry_id = self.entry_id_var.get()
        if not entry_id:
            messagebox.showwarning("Error", "No entry selected to delete.")
            return
            
        title = self.save_website_var.get()
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the entry for '{title}'?"):
            try:
                # Delete the entry from the database
                # Show success message
                messagebox.showinfo("Success", f"Password entry '{title}' deleted successfully!")
                self.clear_entry_form()
                self.load_stored_passwords()
            except Exception as e:
                self.logger.error(f"Failed to delete password entry: {e}")
                messagebox.showerror("Error", f"Failed to delete password entry: {str(e)}")

    def setup_stored_passwords_ui(self):
        """Setup the stored passwords tab UI"""
        # Create the stored passwords frame
        self.stored_passwords_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stored_passwords_frame, text="Stored Passwords")
        
        # Configure grid
        self.stored_passwords_frame.grid_columnconfigure(0, weight=1)
        self.stored_passwords_frame.grid_rowconfigure(1, weight=1)

        # Top frame for the Add New button
        top_frame = ttk.Frame(self.stored_passwords_frame)
        top_frame.grid(row=0, column=0, sticky=EW, padx=5, pady=5)

        # Add New button
        self.add_new_button = ttk.Button(
            top_frame,
            text="➕ Add New Password",
            command=self.add_new_entry,
            style='Accent.TButton'
        )
        self.add_new_button.grid(row=0, column=0, sticky=W)

        # Setup the treeview
        self.setup_password_treeview()

        # Setup the entry form
        self.setup_entry_form()

    def setup_password_treeview(self):
        """Setup the treeview for stored passwords"""
        # Create frame for treeview
        self.treeview_frame = ttk.Frame(self.stored_passwords_frame)
        self.treeview_frame.grid(row=1, column=0, sticky="nsew")
        self.treeview_frame.grid_columnconfigure(0, weight=1)
        self.treeview_frame.grid_rowconfigure(0, weight=1)

        # Create treeview
        self.password_tree = ttk.Treeview(
            self.treeview_frame,
            columns=("id", "title", "username", "password", "url", "created_at"),
            show='headings',
            selectmode='browse'
        )

        # Configure columns
        self.password_tree.heading("id", text="ID", anchor="w")
        self.password_tree.heading("title", text="Title", anchor="w")
        self.password_tree.heading("username", text="Username", anchor="w")
        self.password_tree.heading("password", text="Password", anchor="w")
        self.password_tree.heading("url", text="URL", anchor="w")
        self.password_tree.heading("created_at", text="Created At", anchor="w")

        # Set column widths and anchors
        self.password_tree.column("id", width=50, anchor="w")
        self.password_tree.column("title", width=200, anchor="w")
        self.password_tree.column("username", width=150, anchor="w")
        self.password_tree.column("password", width=100, anchor="w")
        self.password_tree.column("url", width=200, anchor="w")
        self.password_tree.column("created_at", width=150, anchor="w")

        self.password_tree.grid(row=0, column=0, sticky="nsew")
        self.password_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Add scrollbar
        self.tree_scroll = ttk.Scrollbar(self.treeview_frame, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.grid(row=0, column=1, sticky="ns")

    def load_stored_passwords(self, search_query=None):
        """Load stored passwords into the treeview"""
        try:
            entries = read_entries(user_id=self.user_id, search_query=search_query)
            
            # Clear existing entries
            for item in self.password_tree.get_children():
                self.password_tree.delete(item)

            for entry in entries:
                # Format the display values
                values = (
                    entry['id'],
                    entry['title'] or '',
                    entry.get('username', '') or '',
                    '••••••••',  # Masked password
                    entry.get('url', '') or '',
                    entry['created_at'].strftime('%Y-%m-%d %H:%M') if entry['created_at'] else '',
                )
                
                self.password_tree.insert('', 'end', values=values)

            self.logger.info("Stored passwords loaded successfully.")
            
        except Exception as e:
            self.logger.error(f"Failed to load stored passwords: {e}")
            messagebox.showerror("Error", "Failed to load stored passwords")

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
            
        try:
            # Get the selected item's values
            item = self.password_tree.item(selection[0])
            values = item['values']
            if not values:
                return
                
            # Get the ID from the first column (we know it's always the first column)
            entry_id = values[0]
            if not isinstance(entry_id, int):
                self.logger.warning(f"Invalid entry ID format: {entry_id}")
                return

            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
                
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button

            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')

            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')

            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')

            self.save_mfa_text.delete('1.0', tk.END)
            self.save_mfa_text.insert('1.0', entry.get('mfa_info', '') or '')

            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')

        except ValueError as e:
            self.logger.error(f"Failed to parse entry ID: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def setup_button_frame(self):
        """Setup the button frame with all action buttons"""
        self.button_frame = ttk.Frame(self.password_frame)
        self.button_frame.pack(fill=X, padx=10, pady=5)

        # Add New button at the top
        self.add_new_button = ttk.Button(
            self.button_frame,
            text="Add New Entry",
            command=self.add_new_entry,
            bootstyle=SUCCESS
        )
        self.add_new_button.pack(side=LEFT, padx=5)
        create_tooltip(self.add_new_button, "Create a new password entry")

        # Generate Password button (initially disabled)
        self.generate_button = ttk.Button(
            self.button_frame,
            text="Generate Password",
            command=self.generate_for_new_entry,
            state=DISABLED,  # Set to disabled by default
            bootstyle=INFO
        )
        self.generate_button.pack(side=LEFT, padx=5)
        create_tooltip(self.generate_button, "Generate a new password using current settings")

        # Save Entry button (initially disabled)
        self.save_button = ttk.Button(
            self.button_frame,
            text="Save Entry",
            command=self.save_password_to_db,
            state=DISABLED,
            bootstyle=PRIMARY
        )
        self.save_button.pack(side=LEFT, padx=5)
        create_tooltip(self.save_button, "Save the current password entry")

        # Update button
        self.update_button = ttk.Button(
            self.button_frame,
            text="Update",
            command=self.update_existing_entry,
            state=DISABLED,
            bootstyle=WARNING
        )
        self.update_button.pack(side=LEFT, padx=5)
        create_tooltip(self.update_button, "Update the selected password entry")

        # Delete button
        self.delete_button = ttk.Button(
            self.button_frame,
            text="Delete",
            command=self.delete_password,
            state=DISABLED,
            bootstyle=DANGER
        )
        self.delete_button.pack(side=LEFT, padx=5)
        create_tooltip(self.delete_button, "Delete the selected password entry")

        # Copy Password button
        self.copy_password_button = ttk.Button(
            self.button_frame,
            text="Copy Password",
            command=self.copy_password_from_entry,
            state=DISABLED,
            bootstyle=INFO
        )
        self.copy_password_button.pack(side=LEFT, padx=5)
        create_tooltip(self.copy_password_button, "Copy the password to clipboard")

    def add_new_entry(self):
        """Prepare the form for a new entry"""
        self.clear_entry_form()
        self.is_new_entry = True
        self.entry_id_var.set("")  # Clear any selected entry ID
        self.save_button.configure(state=NORMAL)  # Enable save button
        self.update_button.configure(state=DISABLED)  # Disable update button
        self.delete_button.configure(state=DISABLED)  # Disable delete button
        self.copy_password_button.configure(state=DISABLED)  # Disable copy button
        self.save_website_entry.focus()  # Set focus to the first field

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        try:
            # Get the selected item's values
            values = self.password_tree.item(selection[0])['values']
            if not values:
                return
                
            # Get the ID from the first column
            entry_id = values[0]
            
            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
            
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button
            
            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')
            
            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')
            
            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')
            
            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')
            
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def generate_for_new_entry(self):
        """Generate a password for the new entry form"""
        if self.is_new_entry:  # Only generate if we're in new entry mode
            try:
                # Generate password using current settings
                pwd = generate_password(
                    length=int(self.length_var.get()),
                    use_upper=self.use_upper_var.get(),
                    use_lower=self.use_lower_var.get(),
                    use_digits=self.use_digits_var.get(),
                    use_punctuation=self.use_punctuation_var.get(),
                    exclude_similar=self.exclude_similar_var.get()
                )
                self.password_var.set(pwd)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def setup_stored_passwords_ui(self):
        """Setup the stored passwords tab UI"""
        # Create the stored passwords frame
        self.stored_passwords_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stored_passwords_frame, text="Stored Passwords")
        
        # Configure grid
        self.stored_passwords_frame.grid_columnconfigure(0, weight=1)
        self.stored_passwords_frame.grid_rowconfigure(1, weight=1)

        # Top frame for the Add New button
        top_frame = ttk.Frame(self.stored_passwords_frame)
        top_frame.grid(row=0, column=0, sticky=EW, padx=5, pady=5)

        # Add New button
        self.add_new_button = ttk.Button(
            top_frame,
            text="➕ Add New Password",
            command=self.add_new_entry,
            style='Accent.TButton'
        )
        self.add_new_button.grid(row=0, column=0, sticky=W)

        # Setup the treeview
        self.setup_password_treeview()

        # Setup the entry form
        self.setup_entry_form()

    def setup_password_treeview(self):
        """Setup the treeview for stored passwords"""
        # Create frame for treeview
        self.treeview_frame = ttk.Frame(self.stored_passwords_frame)
        self.treeview_frame.grid(row=1, column=0, sticky="nsew")
        self.treeview_frame.grid_columnconfigure(0, weight=1)
        self.treeview_frame.grid_rowconfigure(0, weight=1)

        # Create treeview
        self.password_tree = ttk.Treeview(
            self.treeview_frame,
            columns=("id", "title", "username", "password", "url", "created_at"),
            show='headings',
            selectmode='browse'
        )

        # Configure columns
        self.password_tree.heading("id", text="ID", anchor="w")
        self.password_tree.heading("title", text="Title", anchor="w")
        self.password_tree.heading("username", text="Username", anchor="w")
        self.password_tree.heading("password", text="Password", anchor="w")
        self.password_tree.heading("url", text="URL", anchor="w")
        self.password_tree.heading("created_at", text="Created At", anchor="w")

        # Set column widths and anchors
        self.password_tree.column("id", width=50, anchor="w")
        self.password_tree.column("title", width=200, anchor="w")
        self.password_tree.column("username", width=150, anchor="w")
        self.password_tree.column("password", width=100, anchor="w")
        self.password_tree.column("url", width=200, anchor="w")
        self.password_tree.column("created_at", width=150, anchor="w")

        self.password_tree.grid(row=0, column=0, sticky="nsew")
        self.password_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Add scrollbar
        self.tree_scroll = ttk.Scrollbar(self.treeview_frame, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.grid(row=0, column=1, sticky="ns")

    def load_stored_passwords(self, search_query=None):
        """Load stored passwords into the treeview"""
        try:
            entries = read_entries(user_id=self.user_id, search_query=search_query)
            
            # Clear existing entries
            for item in self.password_tree.get_children():
                self.password_tree.delete(item)

            for entry in entries:
                # Format the display values
                values = (
                    entry['id'],
                    entry['title'] or '',
                    entry.get('username', '') or '',
                    '••••••••',  # Masked password
                    entry.get('url', '') or '',
                    entry['created_at'].strftime('%Y-%m-%d %H:%M') if entry['created_at'] else '',
                )
                
                self.password_tree.insert('', 'end', values=values)

            self.logger.info("Stored passwords loaded successfully.")
            
        except Exception as e:
            self.logger.error(f"Failed to load stored passwords: {e}")
            messagebox.showerror("Error", "Failed to load stored passwords")

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
            
        try:
            # Get the selected item's values
            item = self.password_tree.item(selection[0])
            values = item['values']
            if not values:
                return
                
            # Get the ID from the first column (we know it's always the first column)
            entry_id = values[0]
            if not isinstance(entry_id, int):
                self.logger.warning(f"Invalid entry ID format: {entry_id}")
                return

            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
                
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button

            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')

            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')

            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')

            self.save_mfa_text.delete('1.0', tk.END)
            self.save_mfa_text.insert('1.0', entry.get('mfa_info', '') or '')

            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')

        except ValueError as e:
            self.logger.error(f"Failed to parse entry ID: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def setup_button_frame(self):
        """Setup the button frame with all action buttons"""
        self.button_frame = ttk.Frame(self.password_frame)
        self.button_frame.pack(fill=X, padx=10, pady=5)

        # Add New button at the top
        self.add_new_button = ttk.Button(
            self.button_frame,
            text="Add New Entry",
            command=self.add_new_entry,
            bootstyle=SUCCESS
        )
        self.add_new_button.pack(side=LEFT, padx=5)
        create_tooltip(self.add_new_button, "Create a new password entry")

        # Generate Password button (initially disabled)
        self.generate_button = ttk.Button(
            self.button_frame,
            text="Generate Password",
            command=self.generate_for_new_entry,
            state=DISABLED,  # Set to disabled by default
            bootstyle=INFO
        )
        self.generate_button.pack(side=LEFT, padx=5)
        create_tooltip(self.generate_button, "Generate a new password using current settings")

        # Save Entry button (initially disabled)
        self.save_button = ttk.Button(
            self.button_frame,
            text="Save Entry",
            command=self.save_password_to_db,
            state=DISABLED,
            bootstyle=PRIMARY
        )
        self.save_button.pack(side=LEFT, padx=5)
        create_tooltip(self.save_button, "Save the current password entry")

        # Update button
        self.update_button = ttk.Button(
            self.button_frame,
            text="Update",
            command=self.update_existing_entry,
            state=DISABLED,
            bootstyle=WARNING
        )
        self.update_button.pack(side=LEFT, padx=5)
        create_tooltip(self.update_button, "Update the selected password entry")

        # Delete button
        self.delete_button = ttk.Button(
            self.button_frame,
            text="Delete",
            command=self.delete_password,
            state=DISABLED,
            bootstyle=DANGER
        )
        self.delete_button.pack(side=LEFT, padx=5)
        create_tooltip(self.delete_button, "Delete the selected password entry")

        # Copy Password button
        self.copy_password_button = ttk.Button(
            self.button_frame,
            text="Copy Password",
            command=self.copy_password_from_entry,
            state=DISABLED,
            bootstyle=INFO
        )
        self.copy_password_button.pack(side=LEFT, padx=5)
        create_tooltip(self.copy_password_button, "Copy the password to clipboard")

    def add_new_entry(self):
        """Prepare the form for a new entry"""
        self.clear_entry_form()
        self.is_new_entry = True
        self.entry_id_var.set("")  # Clear any selected entry ID
        self.save_button.configure(state=NORMAL)  # Enable save button
        self.update_button.configure(state=DISABLED)  # Disable update button
        self.delete_button.configure(state=DISABLED)  # Disable delete button
        self.copy_password_button.configure(state=DISABLED)  # Disable copy button
        self.save_website_entry.focus()  # Set focus to the first field

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        try:
            # Get the selected item's values
            values = self.password_tree.item(selection[0])['values']
            if not values:
                return
                
            # Get the ID from the first column
            entry_id = values[0]
            
            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
            
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button
            
            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')
            
            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')
            
            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')
            
            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')
            
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def generate_for_new_entry(self):
        """Generate a password for the new entry form"""
        if self.is_new_entry:  # Only generate if we're in new entry mode
            try:
                # Generate password using current settings
                pwd = generate_password(
                    length=int(self.length_var.get()),
                    use_upper=self.use_upper_var.get(),
                    use_lower=self.use_lower_var.get(),
                    use_digits=self.use_digits_var.get(),
                    use_punctuation=self.use_punctuation_var.get(),
                    exclude_similar=self.exclude_similar_var.get()
                )
                self.password_var.set(pwd)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def setup_stored_passwords_ui(self):
        """Setup the stored passwords tab UI"""
        # Create the stored passwords frame
        self.stored_passwords_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stored_passwords_frame, text="Stored Passwords")
        
        # Configure grid
        self.stored_passwords_frame.grid_columnconfigure(0, weight=1)
        self.stored_passwords_frame.grid_rowconfigure(1, weight=1)

        # Top frame for the Add New button
        top_frame = ttk.Frame(self.stored_passwords_frame)
        top_frame.grid(row=0, column=0, sticky=EW, padx=5, pady=5)

        # Add New button
        self.add_new_button = ttk.Button(
            top_frame,
            text="➕ Add New Password",
            command=self.add_new_entry,
            style='Accent.TButton'
        )
        self.add_new_button.grid(row=0, column=0, sticky=W)

        # Setup the treeview
        self.setup_password_treeview()

        # Setup the entry form
        self.setup_entry_form()

    def setup_password_treeview(self):
        """Setup the treeview for stored passwords"""
        # Create frame for treeview
        self.treeview_frame = ttk.Frame(self.stored_passwords_frame)
        self.treeview_frame.grid(row=1, column=0, sticky="nsew")
        self.treeview_frame.grid_columnconfigure(0, weight=1)
        self.treeview_frame.grid_rowconfigure(0, weight=1)

        # Create treeview
        self.password_tree = ttk.Treeview(
            self.treeview_frame,
            columns=("id", "title", "username", "password", "url", "created_at"),
            show='headings',
            selectmode='browse'
        )

        # Configure columns
        self.password_tree.heading("id", text="ID", anchor="w")
        self.password_tree.heading("title", text="Title", anchor="w")
        self.password_tree.heading("username", text="Username", anchor="w")
        self.password_tree.heading("password", text="Password", anchor="w")
        self.password_tree.heading("url", text="URL", anchor="w")
        self.password_tree.heading("created_at", text="Created At", anchor="w")

        # Set column widths and anchors
        self.password_tree.column("id", width=50, anchor="w")
        self.password_tree.column("title", width=200, anchor="w")
        self.password_tree.column("username", width=150, anchor="w")
        self.password_tree.column("password", width=100, anchor="w")
        self.password_tree.column("url", width=200, anchor="w")
        self.password_tree.column("created_at", width=150, anchor="w")

        self.password_tree.grid(row=0, column=0, sticky="nsew")
        self.password_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Add scrollbar
        self.tree_scroll = ttk.Scrollbar(self.treeview_frame, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.grid(row=0, column=1, sticky="ns")

    def load_stored_passwords(self, search_query=None):
        """Load stored passwords into the treeview"""
        try:
            entries = read_entries(user_id=self.user_id, search_query=search_query)
            
            # Clear existing entries
            for item in self.password_tree.get_children():
                self.password_tree.delete(item)

            for entry in entries:
                # Format the display values
                values = (
                    entry['id'],
                    entry['title'] or '',
                    entry.get('username', '') or '',
                    '••••••••',  # Masked password
                    entry.get('url', '') or '',
                    entry['created_at'].strftime('%Y-%m-%d %H:%M') if entry['created_at'] else '',
                )
                
                self.password_tree.insert('', 'end', values=values)

            self.logger.info("Stored passwords loaded successfully.")
            
        except Exception as e:
            self.logger.error(f"Failed to load stored passwords: {e}")
            messagebox.showerror("Error", "Failed to load stored passwords")

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
            
        try:
            # Get the selected item's values
            item = self.password_tree.item(selection[0])
            values = item['values']
            if not values:
                return
                
            # Get the ID from the first column (we know it's always the first column)
            entry_id = values[0]
            if not isinstance(entry_id, int):
                self.logger.warning(f"Invalid entry ID format: {entry_id}")
                return

            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
                
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button

            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')

            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')

            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')

            self.save_mfa_text.delete('1.0', tk.END)
            self.save_mfa_text.insert('1.0', entry.get('mfa_info', '') or '')

            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')

        except ValueError as e:
            self.logger.error(f"Failed to parse entry ID: {e}")
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def setup_button_frame(self):
        """Setup the button frame with all action buttons"""
        self.button_frame = ttk.Frame(self.password_frame)
        self.button_frame.pack(fill=X, padx=10, pady=5)

        # Add New button at the top
        self.add_new_button = ttk.Button(
            self.button_frame,
            text="Add New Entry",
            command=self.add_new_entry,
            bootstyle=SUCCESS
        )
        self.add_new_button.pack(side=LEFT, padx=5)
        create_tooltip(self.add_new_button, "Create a new password entry")

        # Generate Password button (initially disabled)
        self.generate_button = ttk.Button(
            self.button_frame,
            text="Generate Password",
            command=self.generate_for_new_entry,
            state=DISABLED,  # Set to disabled by default
            bootstyle=INFO
        )
        self.generate_button.pack(side=LEFT, padx=5)
        create_tooltip(self.generate_button, "Generate a new password using current settings")

        # Save Entry button (initially disabled)
        self.save_button = ttk.Button(
            self.button_frame,
            text="Save Entry",
            command=self.save_password_to_db,
            state=DISABLED,
            bootstyle=PRIMARY
        )
        self.save_button.pack(side=LEFT, padx=5)
        create_tooltip(self.save_button, "Save the current password entry")

        # Update button
        self.update_button = ttk.Button(
            self.button_frame,
            text="Update",
            command=self.update_existing_entry,
            state=DISABLED,
            bootstyle=WARNING
        )
        self.update_button.pack(side=LEFT, padx=5)
        create_tooltip(self.update_button, "Update the selected password entry")

        # Delete button
        self.delete_button = ttk.Button(
            self.button_frame,
            text="Delete",
            command=self.delete_password,
            state=DISABLED,
            bootstyle=DANGER
        )
        self.delete_button.pack(side=LEFT, padx=5)
        create_tooltip(self.delete_button, "Delete the selected password entry")

        # Copy Password button
        self.copy_password_button = ttk.Button(
            self.button_frame,
            text="Copy Password",
            command=self.copy_password_from_entry,
            state=DISABLED,
            bootstyle=INFO
        )
        self.copy_password_button.pack(side=LEFT, padx=5)
        create_tooltip(self.copy_password_button, "Copy the password to clipboard")

    def add_new_entry(self):
        """Prepare the form for a new entry"""
        self.clear_entry_form()
        self.is_new_entry = True
        self.entry_id_var.set("")  # Clear any selected entry ID
        self.save_button.configure(state=NORMAL)  # Enable save button
        self.update_button.configure(state=DISABLED)  # Disable update button
        self.delete_button.configure(state=DISABLED)  # Disable delete button
        self.copy_password_button.configure(state=DISABLED)  # Disable copy button
        self.save_website_entry.focus()  # Set focus to the first field

    def on_tree_select(self, event):
        """Handle selection of a password entry from the tree"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        try:
            # Get the selected item's values
            values = self.password_tree.item(selection[0])['values']
            if not values:
                return
                
            # Get the ID from the first column
            entry_id = values[0]
            
            # Get the entry from the database
            entries = read_entries(self.user_id, entry_id=entry_id)
            if not entries or len(entries) == 0:
                return
            
            entry = entries[0]  # Get the first (and should be only) entry
            
            # Set form to viewing mode
            self.is_new_entry = False
            self.save_button.configure(state=DISABLED)  # Disable save button
            self.update_button.configure(state=NORMAL)  # Enable update button
            self.delete_button.configure(state=NORMAL)  # Enable delete button
            self.copy_password_button.configure(state=NORMAL)  # Enable copy button
            
            # Populate the form fields
            self.entry_id_var.set(entry['id'])
            self.save_website_var.set(entry['title'] or '')
            self.save_url_var.set(entry.get('url', '') or '')
            self.save_username_var.set(entry.get('username', '') or '')
            
            # Handle password decryption
            if entry.get('encrypted_password'):
                try:
                    decrypted_password = encryption_manager.decrypt(entry['encrypted_password'])
                    self.password_var.set(decrypted_password if decrypted_password else '')
                except Exception as e:
                    self.logger.error(f"Failed to decrypt password: {e}")
                    self.password_var.set('')
            else:
                self.password_var.set('')
            
            # Set other fields
            self.save_email_var.set(entry.get('email', '') or '')
            self.save_phone_var.set(entry.get('phone', '') or '')
            
            # Update text widgets
            self.save_address_text.delete('1.0', tk.END)
            self.save_address_text.insert('1.0', entry.get('address', '') or '')
            
            self.save_notes_text.delete('1.0', tk.END)
            self.save_notes_text.insert('1.0', entry.get('notes', '') or '')
            
        except Exception as e:
            self.logger.error(f"Failed to load password entry: {e}")
            messagebox.showerror("Error", "Failed to load password entry")

    def generate_for_new_entry(self):
        """Generate a password for the new entry form"""
        if self.is_new_entry:  # Only generate if we're in new entry mode
            try:
                # Generate password using current settings
                pwd = generate_password(
                    length=int(self.length_var.get()),
                    use_upper=self.use_upper_var.get(),
                    use_lower=self.use_lower_var.get(),
                    use_digits=self.use_digits_var.get(),
                    use_punctuation=self.use_punctuation_var.get(),
                    exclude_similar=self.exclude_similar_var.get()
                )
                self.password_var.set(pwd)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
