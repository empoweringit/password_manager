# encryption.py

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Exception raised for errors during encryption or decryption."""
    pass

class EncryptionManager:
    """
    Manages encryption and decryption of data using AES-GCM with key derivation.
    """
    def __init__(self, key: bytes, salt: bytes):
        """
        Initializes the EncryptionManager with a derived key using PBKDF2HMAC.

        Args:
            key (bytes): The base encryption key (passphrase).
            salt (bytes): The salt for key derivation.
        """
        self.key = self.derive_key(key, salt)
        self.aesgcm = AESGCM(self.key)
        logger.info("EncryptionManager initialized with derived key.")
    
    @staticmethod
    def derive_key(password: bytes, salt: bytes) -> bytes:
        """
        Derives a secure key from the given password and salt using PBKDF2HMAC.

        Args:
            password (bytes): The base password or key.
            salt (bytes): The salt for key derivation.

        Returns:
            bytes: The derived key suitable for AES-256.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 requires 32-byte keys
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            derived_key = kdf.derive(password)
            logger.info("Key derivation successful.")
            return derived_key
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise EncryptionError("Key derivation failed.") from e
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext and returns the encrypted data as a base64-encoded string.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded encrypted data (nonce + ciphertext).
        """
        try:
            nonce = os.urandom(12)  # Recommended nonce size for GCM
            ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode(), None)
            encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
            logger.info("Data encrypted successfully.")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError("Encryption failed.") from e
    
    def decrypt(self, encrypted: str) -> str:
        """
        Decrypts the encrypted data and returns the plaintext.

        Args:
            encrypted (str): The base64-encoded encrypted data (nonce + ciphertext).

        Returns:
            str: The decrypted plaintext.
        """
        try:
            encrypted_data = base64.b64decode(encrypted)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            logger.info("Data decrypted successfully.")
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise EncryptionError("Decryption failed.") from e
