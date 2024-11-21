# database.py

import psycopg2
from psycopg2 import pool
from config import DATABASE_CONFIG
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    # Initialize connection pool
    connection_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=20,
        host=DATABASE_CONFIG['host'],
        port=DATABASE_CONFIG['port'],
        database=DATABASE_CONFIG['database'],
        user=DATABASE_CONFIG['user'],
        password=DATABASE_CONFIG['password']
    )
    if connection_pool:
        logger.info("Connection pool created successfully")
except psycopg2.Error as e:
    logger.error(f"Error creating connection pool: {e}")
    sys.exit(1)

def get_connection():
    """
    Retrieves a connection from the pool.
    """
    try:
        conn = connection_pool.getconn()
        if conn:
            logger.debug("Connection retrieved from pool.")
            return conn
    except psycopg2.Error as e:
        logger.error(f"Error getting connection from pool: {e}")
        return None

def return_connection(conn):
    """
    Returns a connection to the pool.
    """
    try:
        connection_pool.putconn(conn)
        logger.debug("Connection returned to pool.")
    except psycopg2.Error as e:
        logger.error(f"Error returning connection to pool: {e}")

def close_all_connections():
    """
    Closes all connections in the pool.
    """
    try:
        connection_pool.closeall()
        logger.info("All connections in the pool have been closed.")
    except psycopg2.Error as e:
        logger.error(f"Error closing connections: {e}")
