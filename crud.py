# crud.py

from database import get_connection, return_connection
from encryption import encrypt_password, decrypt_password
import psycopg2.extras
from psycopg2.extras import RealDictCursor  # Correctly imported
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom Exceptions
class DatabaseConnectionError(Exception):
    pass

class EncryptionError(Exception):
    pass

class CRUDOperationError(Exception):
    pass

def validate_entry(website, username, plaintext_password):
    """
    Validates the input data for a password entry.
    """
    if not website or not isinstance(website, str):
        raise ValueError("Website must be a non-empty string.")
    if not username or not isinstance(username, str):
        raise ValueError("Username must be a non-empty string.")
    if not plaintext_password or not isinstance(plaintext_password, str):
        raise ValueError("Password must be a non-empty string.")

def create_entry(website, username, plaintext_password, notes=""):
    """
    Inserts a new password entry into the database.
    Returns the ID of the new entry.
    """
    validate_entry(website, username, plaintext_password)
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")
    try:
        encrypted_password = encrypt_password(plaintext_password, conn)
        if encrypted_password is None:
            raise EncryptionError("Password encryption failed.")
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO password_entries (website, username, encrypted_password, notes)
                VALUES (%s, %s, %s, %s)
                RETURNING id;
            """, (website, username, encrypted_password, notes))
            entry_id = cursor.fetchone()[0]
            conn.commit()
            logger.info(f"Password entry created with ID: {entry_id}")
            return entry_id
    except (EncryptionError, psycopg2.Error) as e:
        conn.rollback()
        logger.error(f"Error creating entry: {e}")
        raise CRUDOperationError(f"Error creating entry: {e}") from e
    finally:
        return_connection(conn)

def read_entries(search_query=None):
    """
    Retrieves all non-deleted password entries from the database.
    If search_query is provided, filters entries by website or username.
    Returns a list of dictionaries with decrypted passwords.
    """
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            if search_query:
                cursor.execute("""
                    SELECT id, website, username, encrypted_password, notes, created_at, updated_at
                    FROM password_entries
                    WHERE (LOWER(website) LIKE %s OR LOWER(username) LIKE %s)
                      AND is_deleted = FALSE
                    ORDER BY website ASC;
                """, (f"%{search_query.lower()}%", f"%{search_query.lower()}%"))
            else:
                cursor.execute("""
                    SELECT id, website, username, encrypted_password, notes, created_at, updated_at
                    FROM password_entries
                    WHERE is_deleted = FALSE
                    ORDER BY website ASC;
                """)
            entries = cursor.fetchall()
            # Decrypt passwords
            for entry in entries:
                decrypted = decrypt_password(entry['encrypted_password'], conn)
                if decrypted:
                    entry['decrypted_password'] = decrypted
                else:
                    entry['decrypted_password'] = "Decryption Failed"
            logger.info(f"Retrieved {len(entries)} entries from the database.")
            return entries
    except psycopg2.Error as e:
        logger.error(f"Error reading entries: {e}")
        raise CRUDOperationError(f"Error reading entries: {e}") from e
    finally:
        return_connection(conn)

def update_entry(entry_id, website, username, plaintext_password, notes):
    """
    Updates an existing password entry in the database.
    """
    validate_entry(website, username, plaintext_password)
    conn = get_connection()
    if conn is None:
        raise DatabaseConnectionError("Failed to obtain database connection.")
    try:
        encrypted_password = encrypt_password(plaintext_password, conn)
        if encrypted_password is None:
            raise EncryptionError("Password encryption failed.")
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE password_entries
                SET website = %s,
                    username = %s,
                    encrypted_password = %s,
                    notes = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s;
            """, (website, username, encrypted_password, notes, entry_id))
            conn.commit()
            logger.info(f"Password entry with ID {entry_id} updated successfully.")
    except (EncryptionError, psycopg2.Error) as e:
        conn.rollback()
        logger.error(f"Error updating entry with ID {entry_id}: {e}")
        raise CRUDOperationError(f"Error updating entry with ID {entry_id}: {e}") from e
    finally:
        return_connection(conn)

def delete_entry(entry_id):
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
                WHERE id = %s;
            """, (entry_id,))
            conn.commit()
            logger.info(f"Password entry with ID {entry_id} soft deleted successfully.")
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"Error deleting entry with ID {entry_id}: {e}")
        raise CRUDOperationError(f"Error deleting entry with ID {entry_id}: {e}") from e
    finally:
        return_connection(conn)
