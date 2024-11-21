import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import pyperclip

class StoredPasswordsHandlers:
    def __init__(self, app):
        self.app = app
        self.selected_item = None

    def add_new_entry(self):
        """Handle adding a new password entry"""
        # Create a new window for adding entry
        add_window = tk.Toplevel(self.app.root)
        add_window.title("Add New Password")
        add_window.geometry("400x300")
        add_window.resizable(False, False)

        # Create and pack widgets
        ttk.Label(add_window, text="Title:").pack(pady=5)
        title_entry = ttk.Entry(add_window)
        title_entry.pack(pady=5)

        ttk.Label(add_window, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(add_window)
        username_entry.pack(pady=5)

        ttk.Label(add_window, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(add_window, show="*")
        password_entry.pack(pady=5)

        ttk.Label(add_window, text="URL:").pack(pady=5)
        url_entry = ttk.Entry(add_window)
        url_entry.pack(pady=5)

        def save_entry():
            """Save the new entry to database"""
            title = title_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            url = url_entry.get()

            if not all([title, username, password]):
                messagebox.showerror("Error", "Please fill in all required fields")
                return

            try:
                with sqlite3.connect('passwords.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO passwords (title, username, password, url, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (title, username, password, url, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                    conn.commit()

                self.refresh_password_list()
                add_window.destroy()
                messagebox.showinfo("Success", "Password entry added successfully!")

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")

        ttk.Button(add_window, text="Save", command=save_entry).pack(pady=20)

    def refresh_password_list(self):
        """Refresh the password list in the treeview"""
        # Clear existing items
        for item in self.app.stored_passwords_tab.password_tree.get_children():
            self.app.stored_passwords_tab.password_tree.delete(item)

        try:
            # Fetch and display passwords from database
            with sqlite3.connect('passwords.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM passwords ORDER BY created_at DESC')
                for row in cursor.fetchall():
                    # Replace actual password with asterisks
                    masked_row = list(row)
                    masked_row[3] = '*' * 8  # Mask the password
                    self.app.stored_passwords_tab.password_tree.insert('', 'end', values=masked_row)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {str(e)}")

    def on_tree_select(self, event):
        """Handle treeview selection"""
        selected_items = self.app.stored_passwords_tab.password_tree.selection()
        if not selected_items:
            return

        self.selected_item = selected_items[0]
        item_values = self.app.stored_passwords_tab.password_tree.item(self.selected_item)['values']

        # Create a context menu
        context_menu = tk.Menu(self.app.root, tearoff=0)
        context_menu.add_command(label="Copy Username", command=lambda: self.copy_field("username"))
        context_menu.add_command(label="Copy Password", command=lambda: self.copy_field("password"))
        context_menu.add_command(label="Edit Entry", command=self.edit_entry)
        context_menu.add_command(label="Delete Entry", command=self.delete_entry)

        # Display the context menu
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def copy_field(self, field):
        """Copy a field to clipboard"""
        if not self.selected_item:
            return

        try:
            with sqlite3.connect('passwords.db') as conn:
                cursor = conn.cursor()
                item_id = self.app.stored_passwords_tab.password_tree.item(self.selected_item)['values'][0]
                cursor.execute(f'SELECT {field} FROM passwords WHERE id = ?', (item_id,))
                value = cursor.fetchone()[0]
                pyperclip.copy(value)
                messagebox.showinfo("Success", f"{field.title()} copied to clipboard!")

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {str(e)}")

    def edit_entry(self):
        """Edit the selected password entry"""
        if not self.selected_item:
            return

        item_values = self.app.stored_passwords_tab.password_tree.item(self.selected_item)['values']
        
        # Create edit window
        edit_window = tk.Toplevel(self.app.root)
        edit_window.title("Edit Password Entry")
        edit_window.geometry("400x300")
        edit_window.resizable(False, False)

        # Create and pack widgets with current values
        ttk.Label(edit_window, text="Title:").pack(pady=5)
        title_entry = ttk.Entry(edit_window)
        title_entry.insert(0, item_values[1])
        title_entry.pack(pady=5)

        ttk.Label(edit_window, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(edit_window)
        username_entry.insert(0, item_values[2])
        username_entry.pack(pady=5)

        ttk.Label(edit_window, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(edit_window, show="*")
        # Get actual password from database
        with sqlite3.connect('passwords.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM passwords WHERE id = ?', (item_values[0],))
            password_entry.insert(0, cursor.fetchone()[0])
        password_entry.pack(pady=5)

        ttk.Label(edit_window, text="URL:").pack(pady=5)
        url_entry = ttk.Entry(edit_window)
        url_entry.insert(0, item_values[4])
        url_entry.pack(pady=5)

        def save_changes():
            """Save the edited entry to database"""
            try:
                with sqlite3.connect('passwords.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE passwords 
                        SET title = ?, username = ?, password = ?, url = ?
                        WHERE id = ?
                    ''', (
                        title_entry.get(),
                        username_entry.get(),
                        password_entry.get(),
                        url_entry.get(),
                        item_values[0]
                    ))
                    conn.commit()

                self.refresh_password_list()
                edit_window.destroy()
                messagebox.showinfo("Success", "Password entry updated successfully!")

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")

        ttk.Button(edit_window, text="Save Changes", command=save_changes).pack(pady=20)

    def delete_entry(self):
        """Delete the selected password entry"""
        if not self.selected_item:
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            try:
                with sqlite3.connect('passwords.db') as conn:
                    cursor = conn.cursor()
                    item_id = self.app.stored_passwords_tab.password_tree.item(self.selected_item)['values'][0]
                    cursor.execute('DELETE FROM passwords WHERE id = ?', (item_id,))
                    conn.commit()

                self.refresh_password_list()
                messagebox.showinfo("Success", "Password entry deleted successfully!")

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
