# main.py

import ttkbootstrap as ttk
import os
import logging

# Import custom modules
from password_generator_app import PasswordGeneratorApp  # Import your main app
from login_screen import LoginScreen  # Import the login screen

# ------------------- Configure Logging -------------------
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# ------------------- Entry Point -------------------
def main():
    # Create the main root window
    root = ttk.Window(themename="superhero")
    root.withdraw()  # Hide the main window initially

    # Start the login screen as a Toplevel window
    login_app = LoginScreen(root)
    root.wait_window(login_app.top_level)  # Wait until the login window is closed

    # After login screen closes, check if user is authenticated
    if hasattr(login_app, 'user') and login_app.user:
        # Show the main application window
        root.deiconify()
        app = PasswordGeneratorApp(root, user=login_app.user)
        root.mainloop()
    else:
        logger.info("User did not log in.")
        print("User did not log in.")
        root.destroy()
        exit()

if __name__ == "__main__":
    main()
