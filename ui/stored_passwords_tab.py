import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from ttkbootstrap.constants import *
from ..utils.ui_helpers import create_tooltip

class StoredPasswordsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.setup_stored_passwords_tab()

    def setup_stored_passwords_tab(self):
        """Setup the stored passwords tab"""
        # Configure grid weights
        self.parent.grid_columnconfigure(0, weight=3)  # Left space takes 3/4
        self.parent.grid_columnconfigure(1, weight=1)  # Right space takes 1/4
        self.parent.grid_rowconfigure(3, weight=1)

        # Create stored frame
        self.stored_frame = ttk.Frame(self.parent)
        self.stored_frame.grid(row=3, column=0, columnspan=2, sticky=NSEW, padx=10, pady=5)

        # Add New button and Generate Password button side by side
        button_frame = ttk.Frame(self.parent)
        button_frame.grid(row=2, column=0, columnspan=2, sticky=E, padx=(0, 845), pady=5)

        self.add_new_button = ttk.Button(
            button_frame,
            text="➕ Add New Password",
            command=self.app.add_new_entry,
            style='Accent.TButton'
        )
        self.add_new_button.grid(row=0, column=0, padx=(0, 5))

        # Setup the treeview
        self.setup_password_treeview()

    def setup_password_treeview(self):
        """Setup the treeview for stored passwords"""
        # Create frame for treeview
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
        self.password_tree.bind('<<TreeviewSelect>>', self.app.on_tree_select)

        # Add scrollbar
        self.tree_scroll = ttk.Scrollbar(self.treeview_frame, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.grid(row=0, column=1, sticky="ns")
