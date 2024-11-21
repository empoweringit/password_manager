import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from ttkbootstrap.constants import *
from ..utils.ui_helpers import create_tooltip

class PasswordTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.setup_password_tab()

    def setup_password_tab(self):
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

        # Setup components
        self.setup_password_options()
        self.setup_generate_button()
        self.setup_password_output()
        self.setup_save_password_info()
        self.setup_password_strength_indicator()
        self.setup_feedback_labels()

    def setup_generate_button(self):
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
