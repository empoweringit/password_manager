# ui_helpers.py

import tkinter as tk
from ttkbootstrap.tooltip import ToolTip
import re
import logging

def create_tooltip(widget, text):
    """
    Creates a tooltip for the given widget with the specified text.
    """
    try:
        tooltip = ToolTip(widget, text=text)
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to create tooltip: {e}")

def validate_phone_number(P):
    """
    Validates the phone number input.
    Allows digits, +, -, and spaces.
    """
    pattern = re.compile(r'^[+\-\s\d]*$')
    return bool(pattern.fullmatch(P))

def format_address_input(event):
    """
    Formats the address input by capitalizing each word.
    """
    widget = event.widget
    text = widget.get('1.0', tk.END).strip()
    formatted_text = '\n'.join(word.capitalize() for word in text.split('\n'))
    widget.delete('1.0', tk.END)
    widget.insert('1.0', formatted_text)
