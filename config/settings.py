import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class Settings:
    def __init__(self):
        self.config_file = 'config.json'
        self.default_settings = {
            'database_path': 'passwords.db',
            'log_level': 'INFO',
            'auto_copy': True,
            'show_password': False,
            'password_length': 16,
            'use_uppercase': True,
            'use_lowercase': True,
            'use_numbers': True,
            'use_symbols': True,
            'backup_enabled': True,
            'backup_interval': 7,  # days
            'backup_location': str(Path.home() / 'password_manager_backup'),
            'session_timeout': 30,  # minutes
            'max_login_attempts': 3,
            'password_history': 5,  # number of old passwords to remember
            'minimum_password_length': 8,
            'require_special_chars': True,
            'auto_lock': True,
            'lock_timeout': 5,  # minutes
            'theme': 'darkly'
        }
        self.settings = self.load_settings()

    def load_settings(self):
        """Load settings from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    saved_settings = json.load(f)
                    # Merge with defaults, keeping saved values and adding any new defaults
                    return {**self.default_settings, **saved_settings}
            return self.default_settings.copy()
        except Exception as e:
            logger.error(f"Error loading settings: {str(e)}")
            return self.default_settings.copy()

    def save_settings(self):
        """Save current settings to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving settings: {str(e)}")

    def get(self, key, default=None):
        """Get a setting value"""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Set a setting value and save"""
        if key in self.default_settings:
            self.settings[key] = value
            self.save_settings()
        else:
            logger.warning(f"Attempted to set unknown setting: {key}")

    def reset_to_defaults(self):
        """Reset all settings to defaults"""
        self.settings = self.default_settings.copy()
        self.save_settings()

    def create_backup_directory(self):
        """Create backup directory if it doesn't exist"""
        backup_location = self.get('backup_location')
        try:
            os.makedirs(backup_location, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating backup directory: {str(e)}")

    def validate_settings(self):
        """Validate current settings"""
        issues = []
        
        # Validate numeric values
        if self.get('password_length') < self.get('minimum_password_length'):
            issues.append("Password length cannot be less than minimum password length")
        
        if self.get('session_timeout') < 1:
            issues.append("Session timeout must be at least 1 minute")
        
        if self.get('max_login_attempts') < 1:
            issues.append("Maximum login attempts must be at least 1")
        
        # Validate backup location
        backup_location = self.get('backup_location')
        if not os.path.exists(backup_location) and self.get('backup_enabled'):
            try:
                self.create_backup_directory()
            except Exception as e:
                issues.append(f"Invalid backup location: {str(e)}")
        
        return issues

    def export_settings(self, filepath):
        """Export settings to a file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.settings, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Error exporting settings: {str(e)}")
            return False

    def import_settings(self, filepath):
        """Import settings from a file"""
        try:
            with open(filepath, 'r') as f:
                imported_settings = json.load(f)
                # Validate imported settings
                for key in imported_settings:
                    if key not in self.default_settings:
                        raise ValueError(f"Unknown setting: {key}")
                self.settings = {**self.default_settings, **imported_settings}
                self.save_settings()
            return True
        except Exception as e:
            logger.error(f"Error importing settings: {str(e)}")
            return False
