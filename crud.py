# crud.py

import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from typing import Optional, List, Dict, Any
from database import get_connection, return_connection
from encryption import EncryptionError
import json

# Configure logging
logger = logging.getLogger(__name__)

# Custom Exceptions
class DatabaseConnectionError(Exception):
    """Exception raised when the database connection fails."""
    pass

class CRUDOperationError(Exception):
    """Exception raised for errors during CRUD operations."""
    pass

def create_entry(
    user_id: int,
    title: str = "",
    website: str = "",
    username: str = "",
    encrypted_password: str = "",
    notes: str = "",
    url: str = "",
    email: str = "",
    phone: str = "",
    address: str = "",
    subscription: str = "",
    pin: Optional[str] = None,
    security_questions: Optional[str] = None,
    mfa_info: Optional[str] = None,
    file_path: Optional[str] = None,
    pass_phrase: Optional[str] = None
) -> int:
    """
    Inserts a new password or passphrase entry into the database.
    """
    if not encrypted_password and not pass_phrase:
        raise ValueError("Either encrypted password or passphrase must be provided.")

    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO password_entries (
                    user_id, website, username, encrypted_password, notes,
                    created_at, updated_at, is_deleted, title, url,
                    email, phone, address, subscription, pin,
                    security_questions, mfa_info, file_path, pass_phrase
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, FALSE, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                ) RETURNING id;
            """, (
                user_id, website, username, encrypted_password, notes,
                title, url, email, phone, address,
                subscription, pin, security_questions, mfa_info,
                file_path, pass_phrase
            ))
            
            entry_id = cur.fetchone()[0]
            conn.commit()
            
            entry_type = 'passphrase' if pass_phrase else 'password'
            logger.info(f"Created new {entry_type} entry with ID: {entry_id}")
            return entry_id

    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Database error while creating entry: {e}")
        raise CRUDOperationError(f"Failed to create entry: {str(e)}")
    finally:
        return_connection(conn)

def read_entries(
    user_id: int,
    entry_id: Optional[int] = None,
    search_query: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves password entries from the database.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection")

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            if entry_id is not None:
                cursor.execute("""
                    SELECT id, website, username, encrypted_password, notes,
                           created_at, updated_at, is_deleted, title, url,
                           email, phone, address, subscription, pin,
                           security_questions, mfa_info, file_path, pass_phrase
                    FROM password_entries
                    WHERE user_id = %s AND id = %s AND is_deleted = FALSE;
                """, (user_id, int(entry_id)))
            elif search_query:
                search_pattern = f"%{search_query.lower()}%"
                cursor.execute("""
                    SELECT id, website, username, encrypted_password, notes,
                           created_at, updated_at, is_deleted, title, url,
                           email, phone, address, subscription, pin,
                           security_questions, mfa_info, file_path, pass_phrase
                    FROM password_entries
                    WHERE
                        user_id = %s AND
                        is_deleted = FALSE AND (
                            LOWER(title) LIKE %s OR
                            LOWER(username) LIKE %s OR
                            LOWER(website) LIKE %s OR
                            LOWER(url) LIKE %s OR
                            LOWER(notes) LIKE %s
                        )
                    ORDER BY created_at DESC;
                """, (
                    user_id,
                    search_pattern,
                    search_pattern,
                    search_pattern,
                    search_pattern,
                    search_pattern
                ))
            else:
                cursor.execute("""
                    SELECT id, website, username, encrypted_password, notes,
                           created_at, updated_at, is_deleted, title, url,
                           email, phone, address, subscription, pin,
                           security_questions, mfa_info, file_path, pass_phrase
                    FROM password_entries
                    WHERE user_id = %s AND is_deleted = FALSE
                    ORDER BY created_at DESC;
                """, (user_id,))

            entries = []
            for row in cursor.fetchall():
                # Determine entry type based on whether it's a passphrase or password
                entry_type = 'passphrase' if row['pass_phrase'] else 'password'
                
                entry = {
                    'id': row['id'],
                    'website': row['website'],
                    'title': row['title'],
                    'username': row['username'],
                    'url': row['url'],
                    'encrypted_password': row['encrypted_password'],
                    'email': row['email'],
                    'phone': row['phone'],
                    'address': row['address'],
                    'subscription': row['subscription'],
                    'pin': row['pin'],
                    'notes': row['notes'],
                    'mfa_info': row['mfa_info'],
                    'file_path': row['file_path'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'security_questions': row['security_questions'],
                    'pass_phrase': row['pass_phrase'],
                    'entry_type': entry_type
                }
                entries.append(entry)
            
            logger.info(f"Retrieved {len(entries)} entries from the database for user ID: {user_id}")
            return entries
            
    except psycopg2.Error as e:
        logger.error(f"Error reading entries: {e}")
        raise CRUDOperationError(f"Error reading entries: {e}")
    finally:
        return_connection(conn)

def update_entry(
    user_id: int,
    entry_id: int,
    title: Optional[str] = None,
    website: Optional[str] = None,
    username: Optional[str] = None,
    encrypted_password: Optional[str] = None,
    notes: Optional[str] = None,
    url: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    address: Optional[str] = None,
    subscription: Optional[str] = None,
    pin: Optional[str] = None,
    security_questions: Optional[str] = None,
    mfa_info: Optional[str] = None,
    file_path: Optional[str] = None,
    pass_phrase: Optional[str] = None,
    entry_type: Optional[str] = None,
) -> None:
    """
    Updates an existing password entry in the database.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")

    try:
        fields = []
        values = []

        # Set fields if provided
        if title is not None:
            fields.append("title = %s")
            values.append(title)
        if website is not None:
            fields.append("website = %s")
            values.append(website)
        if username is not None:
            fields.append("username = %s")
            values.append(username)
        if encrypted_password is not None:
            fields.append("encrypted_password = %s")
            values.append(encrypted_password)
        if notes is not None:
            fields.append("notes = %s")
            values.append(notes)
        if url is not None:
            fields.append("url = %s")
            values.append(url)
        if email is not None:
            fields.append("email = %s")
            values.append(email)
        if phone is not None:
            fields.append("phone = %s")
            values.append(phone)
        if address is not None:
            fields.append("address = %s")
            values.append(address)
        if subscription is not None:
            fields.append("subscription = %s")
            values.append(subscription)
        if pin is not None:
            fields.append("pin = %s")
            values.append(pin)
        if security_questions is not None:
            fields.append("security_questions = %s")
            values.append(security_questions)
        if mfa_info is not None:
            fields.append("mfa_info = %s")
            values.append(mfa_info)
        if file_path is not None:
            fields.append("file_path = %s")
            values.append(file_path)
        if pass_phrase is not None:
            fields.append("pass_phrase = %s")
            values.append(pass_phrase)
        if entry_type is not None:
            fields.append("entry_type = %s")
            values.append(entry_type)

        if not fields:
            raise ValueError("No fields provided for update.")

        # Append entry_id and user_id for WHERE clause
        values.extend([entry_id, user_id])

        set_clause = ", ".join(fields)
        sql = f"""
            UPDATE password_entries
            SET {set_clause},
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND user_id = %s AND is_deleted = FALSE;
        """

        with conn.cursor() as cursor:
            cursor.execute(sql, tuple(values))
            if cursor.rowcount == 0:
                raise CRUDOperationError(f"No entry found with ID {entry_id} for the user to update.")
            conn.commit()
            logger.info(f"Password entry with ID {entry_id} updated successfully for user ID: {user_id}.")
    except (psycopg2.Error, ValueError, EncryptionError) as e:
        conn.rollback()
        logger.error(f"Error updating entry with ID {entry_id}: {e}")
        raise CRUDOperationError(f"Error updating entry with ID {entry_id}: {e}") from e
    finally:
        return_connection(conn)

def delete_entry(user_id: int, entry_id: int) -> None:
    """
    Soft deletes a password entry by setting is_deleted to TRUE.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE password_entries
                SET is_deleted = TRUE,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s AND is_deleted = FALSE;
            """, (entry_id, user_id))
            if cursor.rowcount == 0:
                raise CRUDOperationError(f"No entry found with ID {entry_id} for the user to delete.")
            conn.commit()
            logger.info(f"Password entry with ID {entry_id} soft deleted successfully for user ID: {user_id}.")
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error deleting entry with ID {entry_id}: {e}")
        raise CRUDOperationError(f"Error deleting entry with ID {entry_id}: {e}") from e
    finally:
        return_connection(conn)

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a user from the database by username.

    Args:
        username (str): The username to search for.

    Returns:
        Optional[Dict[str, Any]]: The user data if found, otherwise None.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT id, username, email, password_hash, security_questions, created_at
                FROM users
                WHERE username = %s;
            """, (username,))
            user = cursor.fetchone()
            if user:
                logger.info(f"User '{username}' retrieved from database.")
                return user
            else:
                logger.warning(f"User '{username}' not found in database.")
                return None
    except psycopg2.Error as e:
        logger.error(f"Error retrieving user '{username}': {e}")
        raise CRUDOperationError(f"Error retrieving user '{username}': {e}") from e
    finally:
        return_connection(conn)

def update_user_password(user_id: int, new_password_hash: str) -> None:
    """
    Updates the user's password hash in the database.

    Args:
        user_id (int): The ID of the user whose password is to be updated.
        new_password_hash (str): The new hashed password.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE users
                SET password_hash = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s;
            """, (new_password_hash, user_id))
            if cursor.rowcount == 0:
                raise CRUDOperationError(f"No user found with ID {user_id} to update the password.")
            conn.commit()
            logger.info(f"Password updated successfully for user ID: {user_id}.")
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error updating password for user ID {user_id}: {e}")
        raise CRUDOperationError(f"Error updating password for user ID {user_id}: {e}") from e
    finally:
        return_connection(conn)
