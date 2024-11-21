import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PasswordDatabase:
    def __init__(self, db_path='passwords.db'):
        self.db_path = db_path
        self.setup_database()

    def setup_database(self):
        """Initialize the database and create necessary tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        username TEXT,
                        password TEXT NOT NULL,
                        url TEXT,
                        email TEXT,
                        phone TEXT,
                        address TEXT,
                        subscription TEXT,
                        pin TEXT,
                        mfa_info TEXT,
                        notes TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database setup error: {str(e)}")
            raise

    def create_entry(self, user_id, title, password, **kwargs):
        """Create a new password entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                fields = ['user_id', 'title', 'password'] + list(kwargs.keys())
                values = [user_id, title, password] + list(kwargs.values())
                placeholders = ','.join(['?' for _ in range(len(fields))])
                fields_str = ','.join(fields)
                
                query = f'''
                    INSERT INTO passwords ({fields_str})
                    VALUES ({placeholders})
                '''
                cursor.execute(query, values)
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error creating entry: {str(e)}")
            raise

    def read_entries(self, user_id, search_query=None):
        """Read password entries for a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if search_query:
                    query = '''
                        SELECT * FROM passwords 
                        WHERE user_id = ? AND 
                        (title LIKE ? OR username LIKE ? OR url LIKE ?)
                        ORDER BY created_at DESC
                    '''
                    search_pattern = f'%{search_query}%'
                    cursor.execute(query, (user_id, search_pattern, search_pattern, search_pattern))
                else:
                    cursor.execute('SELECT * FROM passwords WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error reading entries: {str(e)}")
            raise

    def update_entry(self, entry_id, user_id, **kwargs):
        """Update a password entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                set_clause = ','.join([f'{key}=?' for key in kwargs.keys()])
                values = list(kwargs.values()) + [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), entry_id, user_id]
                
                query = f'''
                    UPDATE passwords 
                    SET {set_clause}, updated_at=?
                    WHERE id=? AND user_id=?
                '''
                cursor.execute(query, values)
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error updating entry: {str(e)}")
            raise

    def delete_entry(self, entry_id, user_id):
        """Delete a password entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM passwords WHERE id=? AND user_id=?', (entry_id, user_id))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error deleting entry: {str(e)}")
            raise

    def get_entry(self, entry_id, user_id):
        """Get a specific password entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM passwords WHERE id=? AND user_id=?', (entry_id, user_id))
                return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error getting entry: {str(e)}")
            raise
