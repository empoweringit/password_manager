import os
import base64

# Generate 16 bytes of cryptographically secure random data
salt = os.urandom(16)

# Encode the salt using base64 to make it safe for storage and transmission
encoded_salt = base64.b64encode(salt).decode('utf-8')

# Output the encoded salt
print(f"Your generated salt (add this to your .env file as DB_SALT):\n{encoded_salt}")
