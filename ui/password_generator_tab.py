import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from ttkbootstrap.constants import *
import pyperclip
from ..utils.ui_helpers import create_tooltip

class PasswordGeneratorTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.setup_password_tab()

    def setup_password_tab(self):
        """Setup the password generator tab"""
        # Create a canvas and scrollbar to make the password tab scrollable
        self.password_canvas = tk.Canvas(self.parent)
        self.password_canvas.pack(side=LEFT, fill=BOTH, expand=True)

        self.password_scrollbar = ttk.Scrollbar(self.parent, orient="vertical", command=self.password_canvas.yview)
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
            command=self.app.generate_password_event,
            bootstyle=SUCCESS,
            width=20,
            state=DISABLED
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
            textvariable=self.app.feedback_var,
            font=("Helvetica", 10),
            wraplength=600,
            justify=LEFT
        )
        self.feedback_label.pack(pady=5, padx=10, fill=X)

        # Status Label
        self.status_label = ttk.Label(
            self.password_frame,
            textvariable=self.app.status_var,
            font=("Helvetica", 10)
        )
        self.status_label.pack(pady=5)

    def setup_password_options(self):
        """Setup password generation options"""
        self.options_frame = ttk.Labelframe(self.password_frame, text="Password Options")
        self.options_frame.pack(padx=10, pady=5, fill=X)
        for i in range(5):
            self.options_frame.columnconfigure(i, weight=1)

        # Password Length
        ttk.Label(self.options_frame, text="Password Length*:").grid(row=0, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.options_frame, "Password length is required (4-128)")
        self.length_entry = ttk.Entry(
            self.options_frame,
            textvariable=self.app.length_var,
            width=10,
            font=("Helvetica", 12)
        )
        self.length_entry.grid(row=0, column=1, sticky=W, pady=5, padx=5)
        self.length_entry.bind("<FocusOut>", self.app.validate_length)
        create_tooltip(self.length_entry, "Enter password length (4-128)")

        # Number of Passwords
        ttk.Label(self.options_frame, text="Number of Passwords*:").grid(row=0, column=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.options_frame, "Number of passwords is required (1-20)")
        self.multiple_spinbox = ttk.Spinbox(
            self.options_frame,
            from_=1,
            to=20,
            textvariable=self.app.multiple_var,
            width=5,
            font=("Helvetica", 12)
        )
        self.multiple_spinbox.grid(row=0, column=3, sticky=W, pady=5, padx=5)
        create_tooltip(self.multiple_spinbox, "Choose the number of passwords to generate")

        # Character Types
        self.setup_character_types()

    def setup_character_types(self):
        """Setup character type options"""
        self.upper_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Uppercase (A-Z)",
            variable=self.app.use_upper_var,
            bootstyle=SUCCESS
        )
        self.upper_check.grid(row=1, column=0, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.upper_check, "Include uppercase letters in the password")

        self.lower_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Lowercase (a-z)",
            variable=self.app.use_lower_var,
            bootstyle=SUCCESS
        )
        self.lower_check.grid(row=2, column=0, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.lower_check, "Include lowercase letters in the password")

        self.digits_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Digits (0-9)",
            variable=self.app.use_digits_var,
            bootstyle=SUCCESS
        )
        self.digits_check.grid(row=1, column=2, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.digits_check, "Include digits in the password")

        self.punctuation_check = ttk.Checkbutton(
            self.options_frame,
            text="Include Punctuation (!@#$...)",
            variable=self.app.use_punctuation_var,
            bootstyle=SUCCESS
        )
        self.punctuation_check.grid(row=2, column=2, columnspan=2, sticky=W, pady=5, padx=5)
        create_tooltip(self.punctuation_check, "Include punctuation symbols in the password")

        self.exclude_similar_check = ttk.Checkbutton(
            self.options_frame,
            text="Exclude Similar Characters (e.g., l, 1, O, 0)",
            variable=self.app.exclude_similar_var,
            bootstyle=PRIMARY
        )
        self.exclude_similar_check.grid(row=3, column=0, columnspan=4, sticky=W, pady=5, padx=5)
        create_tooltip(self.exclude_similar_check, "Exclude characters that look similar to avoid confusion")

    def setup_password_output(self):
        """Setup password output display"""
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
            command=self.app.copy_to_clipboard,
            bootstyle=INFO,
            width=20
        )
        self.copy_button.grid(row=0, column=1, sticky=N, pady=5, padx=5)
        create_tooltip(self.copy_button, "Copy the generated password(s) to clipboard")

        # Clear Button
        self.clear_password_button = ttk.Button(
            self.output_frame,
            text="Clear",
            command=self.app.clear_generated_password,
            bootstyle=SECONDARY,
            width=20
        )
        self.clear_password_button.grid(row=1, column=1, sticky=N, pady=5, padx=5)
        create_tooltip(self.clear_password_button, "Clear the generated password(s)")

    def setup_save_password_info(self):
        """Setup save password information form"""
        self.save_password_frame = ttk.Labelframe(self.password_frame, text="Save Password Information")
        self.save_password_frame.pack(padx=10, pady=5, fill=X)
        for i in range(4):
            self.save_password_frame.columnconfigure(i, weight=1)

        # Password Name
        ttk.Label(self.save_password_frame, text="Password Name:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.save_website_entry = ttk.Entry(self.save_password_frame, textvariable=self.app.save_website_var)
        self.save_website_entry.grid(row=0, column=1, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_website_entry, "Enter a name for the password entry")

        # URL Entry
        ttk.Label(self.save_password_frame, text="URL:").grid(row=0, column=2, sticky=W, padx=5, pady=5)
        self.save_url_entry = ttk.Entry(self.save_password_frame, textvariable=self.app.save_url_var)
        self.save_url_entry.grid(row=0, column=3, sticky=EW, padx=5, pady=5)
        create_tooltip(self.save_url_entry, "Enter the URL associated with this entry")

        # Save Button
        self.save_button = ttk.Button(
            self.password_frame,
            text="Save to Database",
            command=self.app.save_password_to_db,
            bootstyle=PRIMARY,
            width=20
        )
        self.save_button.pack(pady=10)
        create_tooltip(self.save_button, "Save the generated password(s) to the database")

    def setup_password_strength_indicator(self):
        """Setup password strength indicator"""
        self.strength_frame = ttk.Frame(self.password_frame)
        self.strength_frame.pack(padx=10, pady=5, fill=X)
        self.strength_frame.columnconfigure(1, weight=1)

        self.strength_label = ttk.Label(self.strength_frame, text="Password Strength:")
        self.strength_label.grid(row=0, column=0, sticky=W, pady=5, padx=5)
        create_tooltip(self.strength_label, "Displays the strength of the generated password")

        self.strength_display = ttk.Label(
            self.strength_frame,
            textvariable=self.app.strength_var,
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
