# user_management.py

import bcrypt
import logging
from typing import Optional
from database import get_connection, return_connection
import psycopg2

logger = logging.getLogger(__name__)

class UserRegistrationError(Exception):
    """Exception raised for errors during user registration."""
    pass

class UserAuthenticationError(Exception):
    """Exception raised for errors during user authentication."""
    pass

def register_user(username: str, email: str, plain_password: str) -> Optional[int]:
    """
    Registers a new user by hashing their password and storing their details in the database.
    
    Args:
        username (str): The desired username.
        email (str): The user's email address.
        plain_password (str): The user's plaintext password.
    
    Returns:
        Optional[int]: The newly created user's ID if successful, else None.
    """
    if not plain_password:
        logger.error("Password cannot be empty.")
        return None

    # Hash the password with bcrypt
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = get_connection()
    if conn is None:
        logger.error("Failed to obtain database connection.")
        return None

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id;
            """, (username, email, hashed_password))
            user_id = cursor.fetchone()[0]
            conn.commit()
            logger.info(f"User registered with ID: {user_id}")
            return user_id
    except psycopg2.IntegrityError as e:
        conn.rollback()
        logger.error(f"Integrity error during user registration: {e}")
        raise UserRegistrationError("Username or email already exists.") from e
    except Exception as e:
        conn.rollback()
        logger.error(f"Error during user registration: {e}")
        raise UserRegistrationError("Failed to register user.") from e
    finally:
        return_connection(conn)

def authenticate_user(username_or_email: str, plain_password: str) -> Optional[int]:
    """
    Authenticates a user by verifying their password.
    
    Args:
        username_or_email (str): The user's username or email address.
        plain_password (str): The user's plaintext password.
    
    Returns:
        Optional[int]: The user's ID if authentication is successful, else None.
    """
    if not plain_password:
        logger.error("Password cannot be empty.")
        return None

    conn = get_connection()
    if conn is None:
        logger.error("Failed to obtain database connection.")
        return None

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, password_hash FROM users
                WHERE username = %s OR email = %s;
            """, (username_or_email, username_or_email))
            result = cursor.fetchone()
            if result:
                user_id, password_hash = result
                if bcrypt.checkpw(plain_password.encode('utf-8'), password_hash.encode('utf-8')):
                    logger.info(f"User authenticated with ID: {user_id}")
                    return user_id
            logger.warning("Authentication failed: Invalid credentials.")
            return None
    except Exception as e:
        logger.error(f"Error during user authentication: {e}")
        raise UserAuthenticationError("Failed to authenticate user.") from e
    finally:
        return_connection(conn)
