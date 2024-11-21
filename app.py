import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import logging
import os

# Import UI components
from ui.password_generator_tab import PasswordGeneratorTab
from ui.stored_passwords_tab import StoredPasswordsTab
from ui.theme_manager import ThemeManager

# Import handlers
from handlers.password_generator_handlers import PasswordGeneratorHandlers
from handlers.stored_passwords_handlers import StoredPasswordsHandlers

# Import database and config
from database.password_db import PasswordDatabase
from config.settings import Settings

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class PasswordManagerApp:
    def __init__(self, master, user):
        """Initialize the Password Manager App"""
        self.master = master
        self.user = user
        self.user_id = self.user['id']
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.settings = Settings()
        self.theme_manager = ThemeManager()
        self.db = PasswordDatabase()

        # Apply theme
        self.theme_manager.apply_theme(self.master)

        # Setup UI
        self.setup_window()
        self.create_notebook()
        self.create_menu()

    def setup_window(self):
        """Setup the main window"""
        self.master.title("Password Manager")
        self.master.geometry("800x600")
        self.master.minsize(800, 600)

    def create_notebook(self):
        """Create the main notebook with tabs"""
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        # Initialize handlers
        password_gen_handlers = PasswordGeneratorHandlers(self.settings)
        stored_pass_handlers = StoredPasswordsHandlers(self.db, self.user_id)

        # Create tabs
        self.password_gen_tab = PasswordGeneratorTab(self.notebook, password_gen_handlers)
        self.stored_passwords_tab = StoredPasswordsTab(self.notebook, stored_pass_handlers)

        # Add tabs to notebook
        self.notebook.add(self.password_gen_tab, text="Generate Password")
        self.notebook.add(self.stored_passwords_tab, text="Stored Passwords")

    def create_menu(self):
        """Create the application menu"""
        self.menubar = ttk.Menu(self.master)
        self.master.config(menu=self.menubar)

        # File menu
        file_menu = ttk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Settings", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)

        # Theme menu
        self.theme_manager.create_theme_menu(self.menubar, self.master)

        # Help menu
        help_menu = ttk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def show_settings(self):
        """Show settings dialog"""
        settings_window = ttk.Toplevel(self.master)
        settings_window.title("Settings")
        settings_window.geometry("400x500")
        settings_window.transient(self.master)
        settings_window.grab_set()

        # Create settings UI here...

    def show_about(self):
        """Show about dialog"""
        about_window = ttk.Toplevel(self.master)
        about_window.title("About Password Manager")
        about_window.geometry("300x200")
        about_window.transient(self.master)
        about_window.grab_set()

        ttk.Label(
            about_window,
            text="Password Manager\nVersion 1.0\n\nA secure password management solution",
            justify=tk.CENTER,
            padding=20
        ).pack(expand=True)

        ttk.Button(
            about_window,
            text="OK",
            command=about_window.destroy,
            width=10
        ).pack(pady=10)

if __name__ == "__main__":
    root = ttk.Window()
    # For testing purposes
    test_user = {"id": 1, "username": "test"}
    app = PasswordManagerApp(root, test_user)
    root.mainloop()
