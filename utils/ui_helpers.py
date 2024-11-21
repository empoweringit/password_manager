import tkinter as tk

def create_tooltip(widget, text):
    """Create a tooltip for a given widget"""
    def show_tooltip(event=None):
        tooltip = tk.Toplevel()
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")

        label = tk.Label(tooltip, text=text, justify='left',
                        background="#ffffe0", relief='solid', borderwidth=1)
        label.pack()

        def hide_tooltip():
            tooltip.destroy()

        tooltip.bind('<Leave>', lambda e: hide_tooltip())
        widget.bind('<Leave>', lambda e: hide_tooltip())

    widget.bind('<Enter>', show_tooltip)

def validate_numeric_input(P):
    """Validate that input is numeric"""
    if P == "":
        return True
    try:
        int(P)
        return True
    except ValueError:
        return False
