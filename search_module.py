# search_module.py

import tkinter as tk
from tkinter import ttk, messagebox
import logging
from crud import read_entries
from ui_helpers import create_tooltip


class SearchModule:
    """
    A module for adding search functionality to the application.
    """
    def __init__(self, parent: tk.Frame, treeview: ttk.Treeview, user_id: int):
        """
        Initialize the SearchModule.

        :param parent: The parent widget where the search bar will be placed.
        :param treeview: The Treeview widget to display search results.
        :param user_id: The user ID to be used in database queries.
        """
        self.parent = parent
        self.treeview = treeview
        self.user_id = user_id  # Store user_id for use in methods
        self.logger = logging.getLogger(__name__)
        self.setup_search_bar()

    def setup_search_bar(self):
        """
        Sets up the search bar at the top of the parent widget.
        """
        self.search_frame = ttk.Frame(self.parent)
        self.search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        self.search_frame.grid_columnconfigure(1, weight=1)  # Make search entry expandable

        # Search Label
        self.search_label = ttk.Label(self.search_frame, text="Search:")
        self.search_label.grid(row=0, column=0, padx=(0, 5))
        create_tooltip(self.search_label, "Enter keyword to search stored passwords")

        # Search Entry
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.search_entry.bind('<Return>', self.perform_search)
        create_tooltip(self.search_entry, "Enter keyword and press Enter to search")

        # Search Button
        self.search_button = ttk.Button(
            self.search_frame,
            text="Search",
            command=self.perform_search,
            bootstyle="primary"
        )
        self.search_button.grid(row=0, column=2, padx=(0, 5))
        create_tooltip(self.search_button, "Click to search stored passwords")

        # Clear Button
        self.clear_button = ttk.Button(
            self.search_frame,
            text="Clear",
            command=self.clear_search,
            bootstyle="secondary"
        )
        self.clear_button.grid(row=0, column=3)
        create_tooltip(self.clear_button, "Click to clear search and show all entries")

    def perform_search(self, event=None):
        """
        Performs a search and updates the Treeview with the results.

        :param event: The event object for key bindings (default: None).
        """
        query = self.search_var.get().strip()
        if not query:
            messagebox.showwarning("Input Error", "Please enter a search query.")
            return

        try:
            # Call read_entries with search_query and user_id
            entries = read_entries(user_id=self.user_id, search_query=query)
            self.update_treeview(entries)
            self.logger.info(f"Search performed with query: '{query}'. {len(entries)} entries found.")
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            messagebox.showerror("Search Error", f"An error occurred during search: {e}")

    def clear_search(self):
        """
        Clears the search bar and reloads all entries.
        """
        self.search_var.set('')  # Clear the search entry field
        try:
            # Reload all entries with user_id
            entries = read_entries(user_id=self.user_id)
            self.update_treeview(entries)
            self.logger.info("Search cleared. All entries reloaded.")
        except Exception as e:
            self.logger.error(f"Failed to reload entries: {e}")
            messagebox.showerror("Error", f"Failed to reload entries: {e}")

    def update_treeview(self, entries):
        """
        Updates the Treeview with the provided entries.

        :param entries: A list of dictionary entries to populate the Treeview.
        """
        # Clear all existing rows in the Treeview
        for item in self.treeview.get_children():
            self.treeview.delete(item)

        # Populate Treeview with new data
        for entry in entries:
            self.treeview.insert('', 'end', values=(
                entry['id'],
                entry['title'],
                entry.get('username', '') or '',
                entry.get('email', '') or '',
                entry.get('phone', '') or '',
                entry.get('notes', '') or '',
                entry['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                entry['updated_at'].strftime("%Y-%m-%d %H:%M:%S")
            ))
