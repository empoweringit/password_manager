# config.py

from dotenv import load_dotenv
import os
import base64

# Load environment variables from .env file
load_dotenv()

DATABASE_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'password_manager'),
    'user': os.getenv('DB_USER', 'app_user'),
    'password': os.getenv('DB_PASSWORD'),
}

# Decode the base64-encoded salt
SALT = base64.b64decode(os.getenv('DB_SALT'))
