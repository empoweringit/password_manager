# generate_env.py

import os
import base64
import getpass
import re

def generate_base64_bytes(byte_length):
    return base64.b64encode(os.urandom(byte_length)).decode('utf-8')

def is_strong_password(password):
    """
    Validates the strength of the provided password.
    Criteria:
    - At least 8 characters
    - Contains uppercase and lowercase letters
    - Includes digits
    - Contains special characters
    """
    pattern = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
    )
    return bool(pattern.match(password))

def main():
    print("=== .env File Generator ===\n")
    
    # Prompt user for the database password securely
    while True:
        db_password = getpass.getpass("Enter your database password: ")
        if is_strong_password(db_password):
            confirm_password = getpass.getpass("Confirm your database password: ")
            if db_password == confirm_password:
                break
            else:
                print("Passwords do not match. Please try again.\n")
        else:
            print("Password must be at least 8 characters long and include uppercase, lowercase, digits, and special characters.\n")
    
    # Generate DB_SALT and ENCRYPTION_KEY
    db_salt = generate_base64_bytes(16)  # 16 bytes = 128 bits
    encryption_key = generate_base64_bytes(32)  # 32 bytes = 256 bits
    
    env_content = f"""# .env

# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=password_manager
DB_USER=app_user
DB_PASSWORD={db_password}

# Encryption configuration
DB_SALT={db_salt}
ENCRYPTION_KEY={encryption_key}
"""
    with open('.env', 'w') as f:
        f.write(env_content)
    print("\n.env file generated successfully.")

if __name__ == "__main__":
    main()
