import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import json
import os
import logging

logger = logging.getLogger(__name__)

class ThemeManager:
    def __init__(self):
        self.themes = [
            "cosmo", "flatly", "litera", "minty", "lumen", "sandstone",
            "yeti", "pulse", "united", "morph", "journal", "darkly",
            "superhero", "solar", "cyborg", "vapor", "simplex"
        ]
        self.current_theme = "darkly"  # Default theme
        self.load_theme_preference()

    def load_theme_preference(self):
        """Load saved theme preference"""
        try:
            if os.path.exists('theme_preference.json'):
                with open('theme_preference.json', 'r') as f:
                    data = json.load(f)
                    self.current_theme = data.get('theme', 'darkly')
        except Exception as e:
            logger.error(f"Error loading theme preference: {str(e)}")

    def save_theme_preference(self):
        """Save current theme preference"""
        try:
            with open('theme_preference.json', 'w') as f:
                json.dump({'theme': self.current_theme}, f)
        except Exception as e:
            logger.error(f"Error saving theme preference: {str(e)}")

    def apply_theme(self, root):
        """Apply the current theme to the application"""
        try:
            style = ttk.Style(theme=self.current_theme)
            root.style = style
        except Exception as e:
            logger.error(f"Error applying theme: {str(e)}")
            # Fallback to default theme
            self.current_theme = "darkly"
            style = ttk.Style(theme="darkly")
            root.style = style

    def create_theme_menu(self, menubar, root):
        """Create the theme selection menu"""
        theme_menu = ttk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Theme", menu=theme_menu)
        
        for theme in self.themes:
            theme_menu.add_radiobutton(
                label=theme.capitalize(),
                value=theme,
                variable=ttk.StringVar(value=self.current_theme),
                command=lambda t=theme: self.change_theme(t, root)
            )
        return theme_menu

    def change_theme(self, theme_name, root):
        """Change the application theme"""
        try:
            self.current_theme = theme_name
            self.apply_theme(root)
            self.save_theme_preference()
        except Exception as e:
            logger.error(f"Error changing theme: {str(e)}")
            messagebox.showerror("Error", f"Failed to change theme: {str(e)}")
