import tkinter as tk
from tkinter import ttk, Text, scrolledtext, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import re
import logging
import zxcvbn
from typing import Dict, List, Tuple
from config import encryption_manager
from crud import read_entries
from ui_helpers import create_tooltip
from password_utils import generate_password, assess_strength, get_password_recommendations
from password_standards import PasswordStandards
from password_requirements import PasswordRequirements
import math
import random
import string
import bcrypt
from password_standards import PasswordStandards

class PasswordAnalyzer:
    def __init__(self):
        self.standards = {
            "NIST SP 800-63B": {
                "min_length": 8,
                "require_special": False,
                "require_uppercase": False,
                "require_numbers": False,
                "max_length": 64,
                "description": "NIST guidelines focus on length over complexity."
            },
            "PCI DSS": {
                "min_length": 8,
                "require_special": True,
                "require_uppercase": True,
                "require_numbers": True,
                "max_length": None,
                "description": "Payment Card Industry Data Security Standard."
            },
            "HIPAA": {
                "min_length": 8,
                "require_special": True,
                "require_uppercase": True,
                "require_numbers": True,
                "max_length": None,
                "description": "Healthcare Information Protection standards."
            },
            "Microsoft AD": {
                "min_length": 8,
                "require_special": True,
                "require_uppercase": True,
                "require_numbers": True,
                "max_length": 256,
                "description": "Microsoft Active Directory default policy."
            }
        }
    
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        result = {
            "length": len(password),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_numbers": bool(re.search(r'\d', password)),
            "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            "standards_compliance": {},
            "strength_score": 0,
            "feedback": [],
            "time_to_crack": "",
            "suggestions": []
        }
        
        # Use zxcvbn for advanced analysis
        zxcvbn_result = zxcvbn.zxcvbn(password)
        result["strength_score"] = zxcvbn_result["score"]
        result["time_to_crack"] = zxcvbn_result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
        
        if zxcvbn_result["feedback"]["warning"]:
            result["feedback"].append(zxcvbn_result["feedback"]["warning"])
        result["suggestions"].extend(zxcvbn_result["feedback"]["suggestions"])
        
        # Check compliance with different standards
        for standard, requirements in self.standards.items():
            compliant = True
            reasons = []
            
            if len(password) < requirements["min_length"]:
                compliant = False
                reasons.append(f"Minimum length of {requirements['min_length']} not met")
            
            if requirements["max_length"] and len(password) > requirements["max_length"]:
                compliant = False
                reasons.append(f"Exceeds maximum length of {requirements['max_length']}")
            
            if requirements["require_special"] and not result["has_special"]:
                compliant = False
                reasons.append("Missing special characters")
            
            if requirements["require_uppercase"] and not result["has_uppercase"]:
                compliant = False
                reasons.append("Missing uppercase letters")
            
            if requirements["require_numbers"] and not result["has_numbers"]:
                compliant = False
                reasons.append("Missing numbers")
            
            result["standards_compliance"][standard] = {
                "compliant": compliant,
                "reasons": reasons
            }
        
        return result

class FeedbackModule:
    def __init__(self, parent):
        """Initialize the feedback module
        
        Args:
            parent: The parent widget (Frame) to add the feedback components to
        """
        self.parent = parent
        self.logger = logging.getLogger(__name__)
        self.analyzer = PasswordAnalyzer()
        self.user_id = None  # Will be set by the main app
        
        # Initialize variables for stored password analysis
        self.stored_passwords_frame = None
        self.analysis_results_text = None
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar()
        
        # Password variables
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.on_password_change)
        
        # Password requirement variables
        self.upper_var = tk.IntVar(value=0)
        self.numbers_var = tk.IntVar(value=0)
        self.special_var = tk.IntVar(value=0)
        self.length_var = tk.IntVar()
        self.unique_var = tk.BooleanVar(value=False)
        
        self.setup_analysis_tab()
        self.setup_feedback_section()

    def set_user_id(self, user_id):
        """Set the user ID for the feedback module"""
        self.user_id = user_id

    def setup_analysis_tab(self):
        """Setup the password analysis interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.parent)
        self.notebook.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        self.parent.grid_rowconfigure(0, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)

        # Analysis Tab
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text='Analysis')

        # Best Practices Tab
        best_practices_frame = ttk.Frame(self.notebook)
        self.notebook.add(best_practices_frame, text='Best Practices')
        self.setup_best_practices_tab(best_practices_frame)

        # Recommendations Tab
        recommendations_frame = ttk.Frame(self.notebook)
        self.notebook.add(recommendations_frame, text='Recommendations')
        self.setup_recommendations_tab(recommendations_frame)

        # Quick Actions Tab (moved next to Recommendations)
        quick_actions_frame = ttk.Frame(self.notebook)
        self.notebook.add(quick_actions_frame, text='Quick Actions')
        self.setup_quick_actions_tab(quick_actions_frame)

        # Main container in analysis tab
        main_container = ttk.Frame(analysis_frame)
        main_container.grid(row=0, column=0, sticky='nsew', padx=10, pady=5)
        analysis_frame.grid_rowconfigure(0, weight=1)
        analysis_frame.grid_columnconfigure(0, weight=1)

        # Input section at the top
        input_frame = ttk.LabelFrame(main_container, text="Password Input & Analysis", padding=10)
        input_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        main_container.grid_columnconfigure(0, weight=1)

        # Password entry with visibility toggle
        password_frame = ttk.Frame(input_frame)
        password_frame.grid(row=0, column=0, sticky='ew', pady=5)
        input_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, padx=(0, 5))
        
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="•"
        )
        self.password_entry.grid(row=0, column=1, sticky='ew')
        password_frame.grid_columnconfigure(1, weight=1)
        
        self.toggle_btn = ttk.Button(
            password_frame,
            text="👁",
            width=3,
            command=self.toggle_password_visibility
        )
        self.toggle_btn.grid(row=0, column=2, padx=5)
        create_tooltip(self.toggle_btn, "Toggle password visibility")

        # Standard selection with improved styling
        standard_frame = ttk.Frame(input_frame)
        standard_frame.grid(row=1, column=0, sticky='ew', pady=5)
        
        ttk.Label(standard_frame, text="Target Standard:").grid(row=0, column=0, padx=(0, 5))
        
        self.standard_var = tk.StringVar(value="")
        standards_combo = ttk.Combobox(
            standard_frame,
            textvariable=self.standard_var,
            values=[""] + list(PasswordStandards.STANDARDS.keys()),
            state="readonly",
            width=40
        )
        standards_combo.grid(row=0, column=1, sticky='ew', padx=5)
        standard_frame.grid_columnconfigure(1, weight=1)
        create_tooltip(standards_combo, "Select a specific standard to target, or leave empty for general analysis")
        self.standard_var.trace_add("write", self.on_standard_change)

        # Strength meter with improved styling
        meter_frame = ttk.Frame(input_frame)
        meter_frame.grid(row=2, column=0, sticky='ew', pady=5)
        
        ttk.Label(meter_frame, text="Strength:").grid(row=0, column=0, padx=(0, 5))
        self.strength_meter = ttk.Progressbar(
            meter_frame,
            length=200,
            mode='determinate',
            style='success.Horizontal.TProgressbar'
        )
        self.strength_meter.grid(row=0, column=1, sticky='ew')
        meter_frame.grid_columnconfigure(1, weight=1)
        
        self.strength_label = ttk.Label(meter_frame, text="")
        self.strength_label.grid(row=0, column=2, padx=5)

        # Current Password Analysis Results
        analysis_frame = ttk.LabelFrame(input_frame, text="Password Analysis Results", padding=10)
        analysis_frame.grid(row=3, column=0, sticky='nsew', pady=5)
        input_frame.grid_rowconfigure(3, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(
            analysis_frame,
            wrap=tk.WORD,
            height=10,
            font=('TkDefaultFont', 10)
        )
        self.results_text.grid(row=0, column=0, sticky='nsew')
        analysis_frame.grid_rowconfigure(0, weight=1)
        analysis_frame.grid_columnconfigure(0, weight=1)
        
        # Configure tags for colored text
        self.results_text.tag_configure("header", font=('TkDefaultFont', 10, 'bold'))
        self.results_text.tag_configure("good", foreground="green")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("critical", foreground="red")

        # Quick Actions
        quick_actions_frame = ttk.LabelFrame(main_container, text="Quick Actions", padding=10)
        quick_actions_frame.grid(row=1, column=0, sticky='ew', pady=10)

        # Primary Actions (Top Row)
        primary_actions = ttk.Frame(quick_actions_frame)
        primary_actions.grid(row=0, column=0, sticky='ew', pady=(0, 5))
        
        self.generate_btn = ttk.Button(
            primary_actions,
            text="Generate Password",
            command=self.generate_and_analyze_password,
            style="success.TButton"
        )
        self.generate_btn.grid(row=0, column=0, padx=2)

        self.history_btn = ttk.Button(
            primary_actions,
            text="View History",
            command=self.show_password_history
        )
        self.history_btn.grid(row=0, column=1, padx=2)

        self.check_history_btn = ttk.Button(
            primary_actions,
            text="Check History Patterns",
            command=self.check_password_history
        )
        self.check_history_btn.grid(row=0, column=2, padx=2)

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        self.password_entry.config(show="" if self.toggle_btn['text'] == "👁" else "•")
        self.toggle_btn['text'] = "🔒" if self.toggle_btn['text'] == "👁" else "👁"

    def update_strength_label(self, strength_label, score):
        """Update the strength label based on the score"""
        labels = {
            0: ("Very Weak", "danger"),
            1: ("Weak", "warning"),
            2: ("Moderate", "warning"),
            3: ("Strong", "success"),
            4: ("Very Strong", "success")
        }
        text, style = labels.get(score, ("Unknown", "secondary"))
        self.strength_label.config(text=text, bootstyle=style)

    def generate_strong_password(self):
        """Generate a strong password using the password generator"""
        try:
            # Generate a strong password with good defaults
            password = generate_password(
                length=16,
                use_upper=True,
                use_lower=True,
                use_digits=True,
                use_punctuation=True,
                exclude_similar=False
            )
            
            # Update the password entry
            self.password_var.set(password)
            # Analysis will happen automatically due to the trace
            
            # Ask if user wants to store the password
            if messagebox.askyesno("Store Password", "Would you like to store this generated password?"):
                from password_storage import PasswordStorageDialog
                storage_dialog = PasswordStorageDialog(self.parent, password, self.user_id)
                storage_dialog.show()
            
        except Exception as e:
            self.logger.error(f"Error generating strong password: {str(e)}")
            messagebox.showerror("Error", "Failed to generate password. Please try again.")

    def check_password_history(self):
        """Check password history for patterns and improvements"""
        if self.user_id is None:
            messagebox.showerror("Error", "User ID not set. Please log in again.")
            return
            
        try:
            # Get stored entries with user_id
            entries = read_entries(user_id=self.user_id)
            
            if not entries:
                messagebox.showinfo("Password History", "No stored passwords found in history.")
                return
                
            # Analyze patterns
            self.analyze_password_patterns(entries)
            
        except Exception as e:
            self.logger.error(f"Error checking password history: {str(e)}")
            messagebox.showerror("Error", "Failed to check password history. Please try again.")

    def on_password_change(self, *args):
        """Handle password changes and update analysis"""
        current_password = self.password_var.get()
        if not current_password:
            self.results_text.delete(1.0, tk.END)
            self.update_strength_label("", 0)
            self.update_requirement_counts()  # Reset counts when password is empty
            return

        # Get detailed analysis
        counts = PasswordRequirements.analyze_password(current_password)
        strength_label, score = PasswordRequirements.assess_strength(current_password)
        
        # Update strength meter and counts
        self.update_strength_label(strength_label, score)
        self.update_requirement_counts()
        
        # Update analysis text
        self.results_text.delete(1.0, tk.END)
        
        # Overall Statistics
        self.results_text.insert(tk.END, "Current Password Analysis\n\n", "header")
        
        # Strength Assessment
        self.results_text.insert(tk.END, "Strength Assessment\n", "header")
        color_tag = "good" if score >= 80 else "warning" if score >= 40 else "critical"
        self.results_text.insert(tk.END, f"• Overall Strength: {strength_label} ({score}%)\n", color_tag)
        self.results_text.insert(tk.END, f"• Length: {counts['length']} characters\n\n")
        
        # Character Composition
        self.results_text.insert(tk.END, "Character Composition\n", "header")
        self.results_text.insert(tk.END, f"• Uppercase Letters: {counts['uppercase']}\n")
        self.results_text.insert(tk.END, f"• Lowercase Letters: {counts['lowercase']}\n")
        self.results_text.insert(tk.END, f"• Numbers: {counts['numbers']}\n")
        self.results_text.insert(tk.END, f"• Special Characters: {counts['special']}\n\n")
        
        # Requirements Check
        self.results_text.insert(tk.END, "Requirements Check\n", "header")
        
        # Length check
        if counts['length'] >= 12:
            self.results_text.insert(tk.END, "✓ Length is sufficient (12+ characters)\n", "good")
        else:
            self.results_text.insert(tk.END, "✗ Password should be at least 12 characters long\n", "critical")
        
        # Character diversity
        if counts['uppercase'] > 0:
            self.results_text.insert(tk.END, "✓ Contains uppercase letters\n", "good")
        else:
            self.results_text.insert(tk.END, "✗ Missing uppercase letters\n", "critical")
        
        if counts['lowercase'] > 0:
            self.results_text.insert(tk.END, "✓ Contains lowercase letters\n", "good")
        else:
            self.results_text.insert(tk.END, "✗ Missing lowercase letters\n", "critical")
        
        if counts['numbers'] > 0:
            self.results_text.insert(tk.END, "✓ Contains numbers\n", "good")
        else:
            self.results_text.insert(tk.END, "✗ Missing numbers\n", "critical")
        
        if counts['special'] > 0:
            self.results_text.insert(tk.END, "✓ Contains special characters\n", "good")
        else:
            self.results_text.insert(tk.END, "✗ Missing special characters\n", "critical")
        
        # Pattern Analysis
        self.results_text.insert(tk.END, "\nPattern Analysis\n", "header")
        patterns = {
            "sequential": bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', current_password.lower())),
            "repeated": bool(re.search(r'(.)\1{2,}', current_password)),
            "keyboard": bool(re.search(r'(qwert|asdfg|zxcvb|poiuy|lkjhg|mnbvc)', current_password.lower())),
            "common_words": bool(re.search(r'(password|admin|user|login|welcome|123456|qwerty)', current_password.lower()))
        }
        
        if any(patterns.values()):
            self.results_text.insert(tk.END, "Warning: Found potentially weak patterns:\n", "warning")
            if patterns["sequential"]:
                self.results_text.insert(tk.END, "✗ Contains sequential characters\n", "critical")
            if patterns["repeated"]:
                self.results_text.insert(tk.END, "✗ Contains repeated characters\n", "critical")
            if patterns["keyboard"]:
                self.results_text.insert(tk.END, "✗ Contains keyboard patterns\n", "critical")
            if patterns["common_words"]:
                self.results_text.insert(tk.END, "✗ Contains common words/patterns\n", "critical")
        else:
            self.results_text.insert(tk.END, "✓ No common patterns detected\n", "good")
        
        # Recommendations
        if score < 80:
            self.results_text.insert(tk.END, "\nRecommendations\n", "header")
            if counts['length'] < 12:
                self.results_text.insert(tk.END, "• Increase password length to at least 12 characters\n", "warning")
            if counts['uppercase'] == 0:
                self.results_text.insert(tk.END, "• Add uppercase letters\n", "warning")
            if counts['numbers'] == 0:
                self.results_text.insert(tk.END, "• Add numbers\n", "warning")
            if counts['special'] == 0:
                self.results_text.insert(tk.END, "• Add special characters\n", "warning")
            if any(patterns.values()):
                self.results_text.insert(tk.END, "• Avoid common patterns and dictionary words\n", "warning")
        else:
            self.results_text.insert(tk.END, "\n✓ Password meets recommended security criteria\n", "good")

    def update_password_requirements(self, requirement_type):
        """Updates the password based on the changed requirement"""
        if not hasattr(self, 'password_entry') or not self.password_entry:
            return

        current_password = self.password_entry.get()
        if not current_password:
            return

        try:
            # Get current counts
            current_counts = PasswordRequirements.analyze_password(current_password)
            
            # Get target count from spinbutton
            target_count = 0
            if requirement_type == 'uppercase':
                target_count = self.upper_var.get()
            elif requirement_type == 'numbers':
                target_count = self.numbers_var.get()
            elif requirement_type == 'special':
                target_count = self.special_var.get()
            elif requirement_type == 'length':
                target_count = self.length_var.get()

            current_count = current_counts[requirement_type] if requirement_type != 'length' else len(current_password)
            modified_password = current_password

            # Only make changes if the counts are different
            if target_count != current_count:
                if target_count > current_count:
                    # Need to add characters
                    chars_to_add = target_count - current_count
                    if requirement_type == 'uppercase':
                        available_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                    elif requirement_type == 'numbers':
                        available_chars = '0123456789'
                    elif requirement_type == 'special':
                        available_chars = '!@#$%^&*(),.?":{}|<>'
                    elif requirement_type == 'length':
                        available_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'

                    # Add one character at a time at a random position
                    for _ in range(chars_to_add):
                        pos = random.randint(0, len(modified_password))
                        char_to_add = random.choice(available_chars)
                        modified_password = modified_password[:pos] + char_to_add + modified_password[pos:]

                elif target_count < current_count:
                    # Need to remove characters
                    chars_to_remove = current_count - target_count
                    if requirement_type == 'uppercase':
                        pattern = r'[A-Z]'
                    elif requirement_type == 'numbers':
                        pattern = r'[0-9]'
                    elif requirement_type == 'special':
                        pattern = r'[!@#$%^&*(),.?":{}|<>]'
                    elif requirement_type == 'length':
                        # For length, just truncate from the end
                        modified_password = modified_password[:target_count]
                        chars_to_remove = 0  # Skip the character removal logic

                    if chars_to_remove > 0:
                        # Find all matching characters
                        matches = list(re.finditer(pattern, modified_password))
                        if matches:
                            # Remove one character at a time from the end
                            chars_list = list(modified_password)
                            for _ in range(min(chars_to_remove, len(matches))):
                                # Always remove the last matching character
                                match = matches.pop()
                                chars_list.pop(match.start())
                            modified_password = ''.join(chars_list)

            # Update the password entry
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, modified_password)
            
            # Update analysis and counts
            self.password_var.set(modified_password)  # This will trigger on_password_change
            self.update_requirement_counts()  # Update the spinbutton values to reflect actual counts
            
        except Exception as e:
            self.logger.error(f"Error updating password requirements: {str(e)}")
            messagebox.showerror("Error", "Failed to update password. Please try again.")

    def on_standard_change(self, *args):
        """Handle changes to the selected standard"""
        current_password = self.password_var.get()
        if current_password:
            self.on_password_change()  # This will trigger a reanalysis with the new standard

    def analyze_password_patterns(self, entries):
        """Analyze password patterns in history"""
        patterns = {
            "length": [],
            "character_types": set(),
            "common_words": set()
        }
        
        for entry in entries:
            password = encryption_manager.decrypt(entry['encrypted_password'])
            
            # Analyze length
            patterns["length"].append(len(password))
            
            # Analyze character types used
            if re.search(r'[A-Z]', password):
                patterns["character_types"].add("uppercase")
            if re.search(r'[a-z]', password):
                patterns["character_types"].add("lowercase")
            if re.search(r'\d', password):
                patterns["character_types"].add("numbers")
            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                patterns["character_types"].add("special")
                
            # Check for common dictionary words
            words = re.findall(r'[a-zA-Z]{3,}', password)
            patterns["common_words"].update(words)
        
        self.show_pattern_analysis(patterns)

    def show_pattern_analysis(self, patterns):
        """Show the pattern analysis results"""
        avg_length = sum(patterns["length"]) / len(patterns["length"]) if patterns["length"] else 0
        char_types = ", ".join(patterns["character_types"])
        
        analysis = f"""Password History Analysis:

Average Length: {avg_length:.1f} characters
Character Types Used: {char_types}

Recommendations:
1. {"✓" if avg_length >= 12 else "✗"} Your passwords are {"" if avg_length >= 12 else "not "}long enough on average
2. {"✓" if len(patterns["character_types"]) >= 4 else "✗"} You {"" if len(patterns["character_types"]) >= 4 else "should "}use all character types
3. {"✓" if not patterns["common_words"] else "✗"} {"No common dictionary words found" if not patterns["common_words"] else "Avoid using common words in passwords"}
"""
        
        messagebox.showinfo("Password History Analysis", analysis)

    def setup_requirements_section(self):
        """Sets up the requirements section with toggle switches"""
        # This section is no longer needed as we're using the one in setup_feedback_section
        pass

    def update_requirement_counts(self, event=None):
        """Update spinbutton values based on current password content"""
        if not hasattr(self, 'password_entry'):
            return

        current_password = self.password_entry.get()
        if not current_password:
            # Reset all counts to 0 if no password
            self.upper_var.set(0)
            self.numbers_var.set(0)
            self.special_var.set(0)
            self.length_var.set(0)
            return

        # Analyze current password
        counts = PasswordRequirements.analyze_password(current_password)
        
        # Update spinbutton values without triggering their commands
        self.upper_var.set(counts['uppercase'])
        self.numbers_var.set(counts['numbers'])
        self.special_var.set(counts['special'])
        self.length_var.set(counts['length'])

    def setup_feedback_section(self):
        """Sets up the feedback section for stored passwords"""
        # Password entry at the top
        entry_frame = ttk.Frame(self.parent)
        entry_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=5)
        self.parent.grid_rowconfigure(1, weight=0)
        self.parent.grid_columnconfigure(0, weight=1)

        ttk.Label(entry_frame, text="Password:").grid(row=0, column=0)
        self.password_entry = ttk.Entry(
            entry_frame,
            textvariable=self.password_var,
            show="•"
        )
        self.password_entry.grid(row=0, column=1, sticky='ew', padx=5)
        entry_frame.grid_columnconfigure(1, weight=1)

        self.toggle_btn = ttk.Button(
            entry_frame,
            text="👁",
            width=3,
            command=self.toggle_password_visibility,
            bootstyle="secondary-outline"
        )
        self.toggle_btn.grid(row=0, column=2)

        # Main container for side-by-side layout
        main_container = ttk.Frame(self.parent)
        main_container.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)
        self.parent.grid_rowconfigure(2, weight=1)
        self.parent.grid_columnconfigure(0, weight=1)

        # Create a frame for side-by-side layout
        side_by_side_frame = ttk.Frame(main_container)
        side_by_side_frame.grid(row=0, column=0, sticky='nsew')
        main_container.grid_rowconfigure(0, weight=1)
        main_container.grid_columnconfigure(0, weight=1)

        # Left panel - Password Requirements
        requirements_frame = ttk.LabelFrame(side_by_side_frame, text="Password Requirements", padding=10)
        requirements_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        side_by_side_frame.grid_columnconfigure(0, weight=1)

        # Requirements controls
        reqs_frame = ttk.Frame(requirements_frame)
        reqs_frame.grid(row=0, column=0, sticky='ew', pady=5)
        requirements_frame.grid_columnconfigure(0, weight=1)

        # Length requirement with modern spinbox
        length_frame = ttk.Frame(reqs_frame)
        length_frame.grid(row=0, column=0, sticky='ew', pady=5)
        reqs_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(length_frame, text="Length:", font=('TkDefaultFont', 10)).grid(row=0, column=0)
        length_spinbox = ttk.Spinbox(
            length_frame,
            from_=4,
            to=128,
            width=5,
            textvariable=self.length_var,
            bootstyle="primary",
            command=lambda: self.update_password_requirements('length')
        )
        length_spinbox.grid(row=0, column=1, padx=5)
        length_frame.grid_columnconfigure(1, weight=1)
        length_spinbox.bind('<KeyRelease>', lambda e: self.update_password_requirements('length'))
        
        # Character requirements with modern styling
        chars_frame = ttk.Frame(reqs_frame)
        chars_frame.grid(row=1, column=0, sticky='ew', pady=5)
        reqs_frame.grid_rowconfigure(1, weight=1)
        
        # Upper case with toggle and spinbox
        upper_frame = ttk.Frame(chars_frame)
        upper_frame.grid(row=0, column=0, sticky='ew', pady=5)
        chars_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(upper_frame, text="Uppercase:", font=('TkDefaultFont', 10)).grid(row=0, column=0)
        
        # Create a container for the spinbox and toggle
        upper_controls = ttk.Frame(upper_frame)
        upper_controls.grid(row=0, column=1, padx=5)
        upper_frame.grid_columnconfigure(1, weight=1)
        
        self.upper_enabled = tk.BooleanVar(value=True)
        upper_toggle = ttk.Checkbutton(
            upper_controls,
            variable=self.upper_enabled,
            bootstyle="primary-round-toggle",
            command=lambda: self.toggle_requirement('uppercase')
        )
        upper_toggle.grid(row=0, column=0, padx=(0, 5))
        
        self.upper_spinbox = ttk.Spinbox(
            upper_controls,
            from_=0,
            to=128,
            width=5,
            textvariable=self.upper_var,
            bootstyle="primary",
            command=lambda: self.update_password_requirements('uppercase')
        )
        self.upper_spinbox.grid(row=0, column=1)
        upper_controls.grid_columnconfigure(1, weight=1)
        self.upper_spinbox.bind('<KeyRelease>', lambda e: self.update_password_requirements('uppercase'))

        # Numbers with toggle and spinbox
        numbers_frame = ttk.Frame(chars_frame)
        numbers_frame.grid(row=1, column=0, sticky='ew', pady=5)
        chars_frame.grid_rowconfigure(1, weight=1)
        
        ttk.Label(numbers_frame, text="Numbers:", font=('TkDefaultFont', 10)).grid(row=0, column=0)
        
        numbers_controls = ttk.Frame(numbers_frame)
        numbers_controls.grid(row=0, column=1, padx=5)
        numbers_frame.grid_columnconfigure(1, weight=1)
        
        self.numbers_enabled = tk.BooleanVar(value=True)
        numbers_toggle = ttk.Checkbutton(
            numbers_controls,
            variable=self.numbers_enabled,
            bootstyle="primary-round-toggle",
            command=lambda: self.toggle_requirement('numbers')
        )
        numbers_toggle.grid(row=0, column=0, padx=(0, 5))
        
        self.numbers_spinbox = ttk.Spinbox(
            numbers_controls,
            from_=0,
            to=128,
            width=5,
            textvariable=self.numbers_var,
            bootstyle="primary",
            command=lambda: self.update_password_requirements('numbers')
        )
        self.numbers_spinbox.grid(row=0, column=1)
        numbers_controls.grid_columnconfigure(1, weight=1)
        self.numbers_spinbox.bind('<KeyRelease>', lambda e: self.update_password_requirements('numbers'))

        # Special characters with toggle and spinbox
        special_frame = ttk.Frame(chars_frame)
        special_frame.grid(row=2, column=0, sticky='ew', pady=5)
        chars_frame.grid_rowconfigure(2, weight=1)
        
        ttk.Label(special_frame, text="Special:", font=('TkDefaultFont', 10)).grid(row=0, column=0)
        
        special_controls = ttk.Frame(special_frame)
        special_controls.grid(row=0, column=1, padx=5)
        special_frame.grid_columnconfigure(1, weight=1)
        
        self.special_enabled = tk.BooleanVar(value=True)
        special_toggle = ttk.Checkbutton(
            special_controls,
            variable=self.special_enabled,
            bootstyle="primary-round-toggle",
            command=lambda: self.toggle_requirement('special')
        )
        special_toggle.grid(row=0, column=0, padx=(0, 5))
        
        self.special_spinbox = ttk.Spinbox(
            special_controls,
            from_=0,
            to=128,
            width=5,
            textvariable=self.special_var,
            bootstyle="primary",
            command=lambda: self.update_password_requirements('special')
        )
        self.special_spinbox.grid(row=0, column=1)
        special_controls.grid_columnconfigure(1, weight=1)
        self.special_spinbox.bind('<KeyRelease>', lambda e: self.update_password_requirements('special'))

        # Right panel - Stored Password Analysis
        stored_frame = ttk.LabelFrame(side_by_side_frame, text="Stored Password Analysis", padding=10)
        stored_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))
        side_by_side_frame.grid_columnconfigure(1, weight=1)
        
        # Analysis options with tooltips
        options_frame = ttk.LabelFrame(stored_frame, text="Analysis Options", padding=5)
        options_frame.grid(row=0, column=0, sticky='ew', pady=(0, 5))
        stored_frame.grid_rowconfigure(0, weight=0)
        
        self.check_reuse_var = tk.BooleanVar(value=True)
        self.check_strength_var = tk.BooleanVar(value=True)
        
        reuse_check = ttk.Checkbutton(
            options_frame,
            text="Check for Password Reuse",
            variable=self.check_reuse_var,
            bootstyle="success-round-toggle"
        )
        reuse_check.grid(row=0, column=0, sticky='ew', pady=2)
        create_tooltip(reuse_check, "Identify passwords that are used across multiple accounts")
        
        strength_check = ttk.Checkbutton(
            options_frame,
            text="Check Password Strength",
            variable=self.check_strength_var,
            bootstyle="warning-round-toggle"
        )
        strength_check.grid(row=1, column=0, sticky='ew', pady=2)
        create_tooltip(strength_check, "Analyze the strength of each stored password")

        # Analyze button
        analyze_btn = ttk.Button(
            stored_frame,
            text="Analyze Stored Passwords",
            command=self.analyze_stored_passwords,
            bootstyle="primary",
            padding=(5, 5)
        )
        analyze_btn.grid(row=1, column=0, sticky='ew', pady=5)
        create_tooltip(analyze_btn, "Click to analyze all stored passwords")

        # Progress and status
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready to analyze")
        
        status_label = ttk.Label(stored_frame, textvariable=self.status_var)
        status_label.grid(row=2, column=0, sticky='ew', pady=(0, 2))
        
        progress_bar = ttk.Progressbar(
            stored_frame,
            variable=self.progress_var,
            mode='determinate',
            bootstyle="success-striped"
        )
        progress_bar.grid(row=3, column=0, sticky='ew', pady=(0, 5))

        # Results text widget with increased height
        self.analysis_results_text = scrolledtext.ScrolledText(
            stored_frame,
            wrap=tk.WORD,
            height=20,  # Increased height
            width=50,   # Adjusted width
            font=('TkDefaultFont', 10)
        )
        self.analysis_results_text.grid(row=4, column=0, sticky='nsew')
        stored_frame.grid_rowconfigure(4, weight=1)
        stored_frame.grid_columnconfigure(0, weight=1)

        # Configure text tags for formatting
        self.analysis_results_text.tag_configure("header", font=('TkDefaultFont', 11, 'bold'))
        self.analysis_results_text.tag_configure("subheader", font=('TkDefaultFont', 10, 'bold'))
        self.analysis_results_text.tag_configure("good", foreground="green")
        self.analysis_results_text.tag_configure("warning", foreground="orange")
        self.analysis_results_text.tag_configure("critical", foreground="red")
        self.analysis_results_text.tag_configure("highlight", background="#e8e8e8")

    def update_strength_label(self, strength_label, score):
        """Update the strength label based on the score"""
        # Update progress bar
        self.strength_meter['value'] = score
        
        # Update color based on score
        if score >= 80:
            color = "success"
            self.strength_meter.configure(bootstyle="success")
        elif score >= 60:
            color = "warning"
            self.strength_meter.configure(bootstyle="warning")
        elif score >= 40:
            color = "info"
            self.strength_meter.configure(bootstyle="info")
        else:
            color = "danger"
            self.strength_meter.configure(bootstyle="danger")
        
        # Update label text and color
        self.strength_label.configure(
            text=strength_label,
            bootstyle=color
        )

    def analyze_stored_passwords(self):
        """Analyze all stored passwords with modern UI feedback"""
        try:
            self.status_var.set("Starting analysis...")
            self.progress_var.set(0)
            self.analysis_results_text.delete(1.0, tk.END)
            
            # Get stored entries with user_id
            entries = read_entries(user_id=self.user_id)
            
            if not entries:
                self.status_var.set("No stored passwords found")
                messagebox.showinfo("Analysis Complete", "No stored passwords found in the database.")
                return
            
            total_entries = len(entries)
            self.progress_var.set(10)  # Show initial progress
            
            # Initialize analysis results
            analysis_results = {
                "total_passwords": total_entries,
                "strength_categories": {"weak": 0, "moderate": 0, "strong": 0, "very_strong": 0},
                "reused_passwords": {},
                "length_stats": {"min": float('inf'), "max": 0, "avg": 0},
                "character_types": {"uppercase": 0, "lowercase": 0, "numbers": 0, "special": 0},
                "common_patterns": set()
            }
            
            # Analyze each password
            total_length = 0
            for i, entry in enumerate(entries):
                self.status_var.set(f"Analyzing password {i+1} of {total_entries}...")
                self.progress_var.set(10 + (i / total_entries * 80))  # Progress from 10% to 90%
                
                try:
                    password = encryption_manager.decrypt(entry['encrypted_password'])
                    
                    # Update length statistics
                    length = len(password)
                    total_length += length
                    analysis_results["length_stats"]["min"] = min(analysis_results["length_stats"]["min"], length)
                    analysis_results["length_stats"]["max"] = max(analysis_results["length_stats"]["max"], length)
                    
                    # Check for password reuse
                    if password in analysis_results["reused_passwords"]:
                        analysis_results["reused_passwords"][password].append(entry['title'])
                    else:
                        analysis_results["reused_passwords"][password] = [entry['title']]
                    
                    # Analyze character types
                    counts = PasswordRequirements.analyze_password(password)
                    analysis_results["character_types"]["uppercase"] += counts['uppercase'] > 0
                    analysis_results["character_types"]["lowercase"] += counts['lowercase'] > 0
                    analysis_results["character_types"]["numbers"] += counts['numbers'] > 0
                    analysis_results["character_types"]["special"] += counts['special'] > 0
                    
                    # Get strength score
                    strength_result = PasswordRequirements.assess_strength(password)
                    if strength_result[0] == "Very Strong":
                        analysis_results["strength_categories"]["very_strong"] += 1
                    elif strength_result[0] == "Strong":
                        analysis_results["strength_categories"]["strong"] += 1
                    elif strength_result[0] == "Moderate":
                        analysis_results["strength_categories"]["moderate"] += 1
                    else:
                        analysis_results["strength_categories"]["weak"] += 1
                except Exception as e:
                    self.logger.error(f"Error analyzing password for entry {entry.get('title', 'Unknown')}: {str(e)}")
                    continue
            
            # Calculate average length
            analysis_results["length_stats"]["avg"] = total_length / total_entries if total_entries > 0 else 0
            
            # Display results
            self.display_analysis_results(analysis_results)
            
            self.progress_var.set(100)
            self.status_var.set("Analysis complete!")
            
        except Exception as e:
            self.logger.error(f"Error analyzing stored passwords: {str(e)}")
            self.status_var.set("Analysis failed!")
            messagebox.showerror("Error", "An error occurred while analyzing stored passwords.")

    def display_analysis_results(self, results):
        """Display the analysis results in a user-friendly format"""
        self.analysis_results_text.delete(1.0, tk.END)
        
        # Overall Summary
        self.analysis_results_text.insert(tk.END, "📊 Password Analysis Summary\n", "header")
        self.analysis_results_text.insert(tk.END, f"\nTotal Passwords Analyzed: {results['total_passwords']}\n\n")
        
        # Strength Distribution
        self.analysis_results_text.insert(tk.END, "🔒 Password Strength Distribution\n", "subheader")
        total = results['total_passwords']
        for category, count in results['strength_categories'].items():
            percentage = self.format_percentage(count / total)
            color = "good" if category in ["strong", "very_strong"] else "warning" if category == "moderate" else "critical"
            self.analysis_results_text.insert(tk.END, f"{category.title()}: {count} ({percentage})\n", color)
        
        # Length Statistics
        self.analysis_results_text.insert(tk.END, "\n📏 Password Length Analysis\n", "subheader")
        avg_length = results['length_stats'].get('avg', 0)
        self.analysis_results_text.insert(tk.END, 
            f"Shortest: {results['length_stats']['min']} characters\n"
            f"Longest: {results['length_stats']['max']} characters\n"
            f"Average: {avg_length:.1f} characters\n"
        )
        
        # Character Type Usage
        self.analysis_results_text.insert(tk.END, "\n🔤 Character Type Usage\n", "subheader")
        for char_type, count in results['character_types'].items():
            percentage = self.format_percentage(count / total)
            self.analysis_results_text.insert(tk.END, 
                f"{char_type.title()}: {count} passwords ({percentage})\n"
            )
        
        # Password Reuse Analysis
        self.analysis_results_text.insert(tk.END, "\n🔄 Password Reuse Analysis\n", "subheader")
        reused = {pwd: titles for pwd, titles in results['reused_passwords'].items() if len(titles) > 1}
        if reused:
            self.analysis_results_text.insert(tk.END, 
                f"Found {len(reused)} reused passwords across multiple accounts:\n", 
                "critical"
            )
            for titles in reused.values():
                self.analysis_results_text.insert(tk.END, 
                    f"• Reused across: {', '.join(titles)}\n", 
                    "highlight"
                )
        else:
            self.analysis_results_text.insert(tk.END, 
                "No password reuse detected - Excellent!\n", 
                "good"
            )
        
        # Recommendations
        self.analysis_results_text.insert(tk.END, "\n💡 Recommendations\n", "subheader")
        if results['strength_categories']['weak'] > 0:
            self.analysis_results_text.insert(tk.END, 
                "• Consider updating weak passwords to improve overall security\n",
                "warning"
            )
        if reused:
            self.analysis_results_text.insert(tk.END, 
                "• Use unique passwords for each account to prevent credential stuffing attacks\n",
                "warning"
            )
        if avg_length < 12:
            self.analysis_results_text.insert(tk.END, 
                "• Increase password length to at least 12 characters for better security\n",
                "warning"
            )
        
        self.status_var.set("Analysis complete!")
        self.progress_var.set(100)

    def generate_and_analyze_password(self):
        """Generate a strong password and analyze it"""
        # Generate a strong password using the password generator
        password = generate_password(
            length=16,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_punctuation=True
        )
        
        # Set the generated password in the entry field
        self.password_var.set(password)
        
        # Trigger password analysis
        self.on_password_change()

    def show_password_history(self):
        """Show the password history dialog"""
        if not self.user_id:
            messagebox.showwarning("Warning", "Please log in to view password history.")
            return

        history_dialog = tk.Toplevel(self.parent)
        history_dialog.title("Password History")
        history_dialog.geometry("600x400")
        history_dialog.transient(self.parent)
        history_dialog.grab_set()

        # Create treeview for password history
        columns = ("title", "username", "website", "created_at")
        tree = ttk.Treeview(history_dialog, columns=columns, show="headings")

        # Define column headings
        tree.heading("title", text="Title")
        tree.heading("username", text="Username")
        tree.heading("website", text="Website")
        tree.heading("created_at", text="Created")

        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_dialog, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        # Pack widgets
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Fetch and display password history
        try:
            entries = read_entries(self.user_id)
            for entry in entries:
                tree.insert("", tk.END, values=(
                    entry.get("title", ""),
                    entry.get("username", ""),
                    entry.get("url", ""),
                    entry.get("created_at").strftime("%Y-%m-%d %H:%M:%S")
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load password history: {str(e)}")

    def setup_best_practices_tab(self, parent):
        """Setup the best practices tab"""
        container = ttk.Frame(parent)
        container.grid(row=0, column=0, sticky='nsew', padx=10, pady=5)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Header
        header = ttk.Label(
            container,
            text="Password Security Best Practices",
            font=('TkDefaultFont', 12, 'bold')
        )
        header.grid(row=0, column=0, sticky='w', pady=(0, 10))

        # Create scrolled text widget for content
        content = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            width=60,
            height=20,
            font=('TkDefaultFont', 10)
        )
        content.grid(row=1, column=0, sticky='nsew')
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        best_practices = """
Password Best Practices:

1. Length and Complexity
   • Use passwords that are at least 12 characters long
   • Mix uppercase and lowercase letters
   • Include numbers and special characters
   • Avoid common substitutions (e.g., 'a' to '@')

2. Password Creation
   • Use unique passwords for each account
   • Create memorable but secure passphrases
   • Avoid personal information in passwords
   • Don't use common patterns or sequences

3. Security Measures
   • Enable two-factor authentication when available
   • Use a password manager
   • Regularly update critical passwords
   • Keep backup codes in a secure location

4. Common Mistakes to Avoid
   • Don't reuse passwords across accounts
   • Avoid using dictionary words alone
   • Don't use keyboard patterns (qwerty, 12345)
   • Never share passwords via unsecured channels

5. Account Protection
   • Monitor accounts for suspicious activity
   • Use security questions wisely
   • Keep software and systems updated
   • Be cautious of phishing attempts
"""
        content.insert(tk.END, best_practices)
        content.config(state=tk.DISABLED)

    def setup_recommendations_tab(self, parent):
        """Setup the recommendations tab"""
        container = ttk.Frame(parent)
        container.grid(row=0, column=0, sticky='nsew', padx=10, pady=5)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Header
        header = ttk.Label(
            container,
            text="Password Recommendations",
            font=('TkDefaultFont', 12, 'bold')
        )
        header.grid(row=0, column=0, sticky='w', pady=(0, 10))

        # Create scrolled text widget for recommendations
        self.recommendations_text = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            width=60,
            height=20,
            font=('TkDefaultFont', 10)
        )
        self.recommendations_text.grid(row=1, column=0, sticky='nsew')
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        recommendations = """
Password Recommendations:

1. Creating Strong Passwords
   • Combine multiple random words
   • Add numbers and special characters
   • Make it at least 12 characters long
   • Use our password generator for best results

2. Managing Your Passwords
   • Use a password manager
   • Change passwords periodically
   • Don't store passwords in plain text
   • Keep backup codes secure

3. Account Security
   • Enable two-factor authentication
   • Use unique passwords for each account
   • Monitor for security breaches
   • Regular security audits

4. Best Practices
   • Use passphrases for better memorability
   • Implement password rotation for critical accounts
   • Regular password strength assessment
   • Keep software and systems updated
"""
        self.recommendations_text.insert(tk.END, recommendations)
        self.recommendations_text.config(state=tk.DISABLED)

    def setup_quick_actions_tab(self, parent):
        """Setup the quick actions tab"""
        container = ttk.Frame(parent)
        container.grid(row=0, column=0, sticky='nsew', padx=10, pady=5)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Actions Frame
        actions_frame = ttk.LabelFrame(container, text="Available Actions", padding=10)
        actions_frame.grid(row=0, column=0, sticky='nsew')
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Generate Password Button
        generate_btn = ttk.Button(
            actions_frame,
            text="Generate Strong Password",
            command=self.generate_strong_password,
            bootstyle="success"
        )
        generate_btn.grid(row=0, column=0, sticky='ew', pady=5)
        actions_frame.grid_columnconfigure(0, weight=1)

        # Check History Button
        history_btn = ttk.Button(
            actions_frame,
            text="Check Password History",
            command=self.check_password_history,
            bootstyle="info"
        )
        history_btn.grid(row=1, column=0, sticky='ew', pady=5)

        # Analyze Current Button
        analyze_btn = ttk.Button(
            actions_frame,
            text="Analyze Current Password",
            command=self.analyze_current_password,
            bootstyle="warning"
        )
        analyze_btn.grid(row=2, column=0, sticky='ew', pady=5)

    def format_percentage(self, value):
        return f"{value*100:.1f}%"

    def toggle_requirement(self, requirement_type):
        """Toggle a password requirement on/off"""
        spinbox = None
        enabled_var = None
        value_var = None
        
        if requirement_type == 'uppercase':
            spinbox = self.upper_spinbox
            enabled_var = self.upper_enabled
            value_var = self.upper_var
        elif requirement_type == 'numbers':
            spinbox = self.numbers_spinbox
            enabled_var = self.numbers_enabled
            value_var = self.numbers_var
        elif requirement_type == 'special':
            spinbox = self.special_spinbox
            enabled_var = self.special_enabled
            value_var = self.special_var
            
        if spinbox and enabled_var and value_var:
            if enabled_var.get():
                spinbox.configure(state='normal')
                # Set minimum value to 1 when enabled
                current_val = int(value_var.get())
                if current_val == 0:
                    value_var.set(1)
            else:
                spinbox.configure(state='disabled')
                value_var.set(0)
            
            self.update_password_requirements(requirement_type)

    def analyze_current_password(self):
        """Analyze the currently entered password"""
        password = self.password_var.get()
        if not password:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Please enter a password to analyze.")
            return
        
        # Get selected standard (if any)
        target_standard = self.standard_var.get() or None
        
        # Analyze password using the standards system
        analysis = PasswordStandards.analyze_password(password, target_standard)
        
        # Update strength meter based on entropy and standard
        if target_standard:
            # Get standard-specific requirements
            standard_info = analysis["compliance"][target_standard]
            min_length = standard_info["min_length"]
            
            # Adjust entropy score based on standard requirements
            max_possible_entropy = min_length * math.log2(94)  # 94 printable ASCII chars
            relative_entropy = min(100, (analysis["entropy"] / max_possible_entropy) * 100)
            self.strength_meter["value"] = relative_entropy
            
            # Update strength label based on compliance
            if standard_info["compliant"]:
                self.update_strength_label("Very Strong", 100)
            else:
                issues_count = len(standard_info["issues"])
                if issues_count <= 1:
                    self.update_strength_label("Strong", 75)
                elif issues_count <= 2:
                    self.update_strength_label("Moderate", 50)
                else:
                    self.update_strength_label("Weak", 25)
        else:
            # Use general entropy-based assessment
            if analysis["entropy"] >= 90:
                self.update_strength_label("Very Strong", 100)
            elif analysis["entropy"] >= 70:
                self.update_strength_label("Strong", 75)
            elif analysis["entropy"] >= 50:
                self.update_strength_label("Moderate", 50)
            else:
                self.update_strength_label("Weak", 25)
        
        # Format and display results
        self.results_text.delete(1.0, tk.END)
        
        # Show standard-specific information first if selected
        if target_standard:
            standard_info = analysis["compliance"][target_standard]
            self.results_text.insert(tk.END, f"Analysis for {target_standard}\n", "header")
            self.results_text.insert(tk.END, f"{standard_info['description']}\n\n")
            
            status = "✓" if standard_info["compliant"] else "✗"
            status_tag = "good" if standard_info["compliant"] else "critical"
            self.results_text.insert(tk.END, f"Status: {status}\n\n", status_tag)
        
        # Basic stats
        self.results_text.insert(tk.END, "Password Statistics:\n", "header")
        self.results_text.insert(tk.END, f"• Length: {analysis['length']} characters\n")
        self.results_text.insert(tk.END, f"• Entropy: {analysis['entropy']:.1f} bits\n")
        
        # Time to crack estimates
        self.results_text.insert(tk.END, "\nEstimated Time to Crack:\n", "header")
        for attack, seconds in analysis["time_to_crack"].items():
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
            self.results_text.insert(tk.END, f"• {attack.replace('_', ' ').title()}: {time_str}\n")
        
        # Character composition
        self.results_text.insert(tk.END, "\nCharacter Composition:\n", "header")
        char_sets = analysis["character_sets"]
        self.results_text.insert(tk.END, f"• Unique Characters: {char_sets['unique_count']}\n")
        
        for char_type in ["uppercase", "lowercase", "numbers", "special"]:
            status = "Yes" if char_sets[char_type] else "No"
            color_tag = "good" if char_sets[char_type] else ("warning" if target_standard and 
                analysis["compliance"][target_standard].get(f"require_{char_type}", False) else None)
            self.results_text.insert(tk.END, f"• {char_type.title()}: {status}\n", color_tag if color_tag else "")
        
        # Pattern analysis
        self.results_text.insert(tk.END, "\nPattern Analysis:\n", "header")
        patterns = analysis["patterns"]
        sequential_warning = patterns["max_sequential"] > 2
        repeated_warning = patterns["max_repeated"] > 2
        
        self.results_text.insert(tk.END, 
            f"• Sequential Characters: {patterns['max_sequential']} in a row\n",
            "warning" if sequential_warning else "")
        self.results_text.insert(tk.END, 
            f"• Repeated Characters: {patterns['max_repeated']} times maximum\n",
            "warning" if repeated_warning else "")
        
        # Standards compliance
        if not target_standard:
            self.results_text.insert(tk.END, "\nStandards Compliance:\n", "header")
            for standard, result in analysis["compliance"].items():
                status = "✓" if result["compliant"] else "✗"
                color_tag = "good" if result["compliant"] else "critical"
                self.results_text.insert(tk.END, f"{status} {standard}\n", color_tag)
                
                if not result["compliant"]:
                    for issue in result["issues"]:
                        self.results_text.insert(tk.END, f"  • {issue}\n", "warning")
        
        # Get and display recommendations
        recommendations = PasswordStandards.get_recommendations(analysis, target_standard)
        if recommendations:
            self.results_text.insert(tk.END, "\nRecommendations:\n", "header")
            for rec in recommendations:
                self.results_text.insert(tk.END, f"{rec}\n")
