# encryption.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import SALT, ENCRYPTION_KEY
import base64
import os
import getpass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_master_password():
    """
    Prompts the user to enter the master password securely.
    """
    return getpass.getpass("Enter master password: ")

def derive_key(master_password):
    """
    Derives a symmetric encryption key from the master password using PBKDF2.
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=SALT,
            iterations=200000,  # Increased iterations for better security
            backend=default_backend()
        )
        key = kdf.derive(master_password.encode())
        return key
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        raise e

def encrypt_password(plaintext, key):
    """
    Encrypts the plaintext password using AES-GCM and returns it as a base64-encoded string.
    """
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # Recommended nonce size for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
        return encrypted
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return None

def decrypt_password(encrypted, key):
    """
    Decrypts the base64-encoded encrypted password using AES-GCM and returns the plaintext.
    """
    try:
        encrypted_data = base64.b64decode(encrypted)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None
