from dotenv import load_dotenv
import os
import base64
import sys
import logging
from encryption import EncryptionManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# -------------------- Database Configuration -------------------- #

DATABASE_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'password_manager'),
    'user': os.getenv('DB_USER', 'app_user'),
    'password': os.getenv('DB_PASSWORD'),
}

# Validate essential database configurations
missing_db_configs = [key for key, value in DATABASE_CONFIG.items() if not value]
if missing_db_configs:
    logger.error(f"Missing database configurations: {', '.join(missing_db_configs)}")
    sys.exit(1)

logger.info("Database configuration loaded successfully.")

# -------------------- Encryption Configuration -------------------- #

# Retrieve and decode the encryption key
ENCRYPTION_KEY_BASE64 = os.getenv('ENCRYPTION_KEY')
if ENCRYPTION_KEY_BASE64:
    try:
        ENCRYPTION_KEY = base64.b64decode(ENCRYPTION_KEY_BASE64)
        if len(ENCRYPTION_KEY) != 32:
            logger.error("ENCRYPTION_KEY must decode to 32 bytes for AES-256.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error decoding ENCRYPTION_KEY: {e}")
        sys.exit(1)
else:
    logger.error("ENCRYPTION_KEY is not set in the .env file.")
    sys.exit(1)

# Retrieve and decode the salt
SALT_BASE64 = os.getenv('DB_SALT')  # Correct variable name from .env
if SALT_BASE64:
    try:
        SALT = base64.b64decode(SALT_BASE64)
        if len(SALT) < 16:
            logger.error("SALT must be at least 16 bytes.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error decoding SALT: {e}")
        sys.exit(1)
else:
    logger.error("SALT is not set in the .env file.")
    sys.exit(1)

logger.info("Encryption configuration loaded successfully.")

# Initialize EncryptionManager with both key and salt
encryption_manager = EncryptionManager(ENCRYPTION_KEY, SALT)

# -------------------- Additional Configurations -------------------- #

# Example: Setting a custom logging level
# LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
# logger.setLevel(LOG_LEVEL)
