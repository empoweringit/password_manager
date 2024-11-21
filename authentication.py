# authentication.py

import logging
from crud import get_user_by_username
from encryption import EncryptionManager, EncryptionError

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """
    Hashes the password using the same method used when storing the password in the database.
    """
    # Assuming you use the same encryption manager to hash passwords
    # Alternatively, if you use a different hashing method, adjust accordingly
    try:
        # We can use SHA-256 for hashing passwords
        import hashlib
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise

def login_user(username: str, password: str) -> dict:
    """
    Authenticates the user by verifying the username and password.
    
    Returns:
        dict: User data if authentication is successful.
    Raises:
        ValueError: If authentication fails.
    """
    user = get_user_by_username(username)
    if not user:
        logger.error(f"User '{username}' not found.")
        raise ValueError("Invalid username or password.")
    
    # Hash the provided password
    hashed_password = hash_password(password)
    
    if hashed_password == user['password_hash']:
        logger.info(f"User '{username}' authenticated successfully.")
        return user
    else:
        logger.error(f"Authentication failed for user '{username}'.")
        raise ValueError("Invalid username or password.")
