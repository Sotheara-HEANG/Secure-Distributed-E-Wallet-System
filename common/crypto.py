"""
crypto.py — Cryptographic Utilities Module
============================================
Provides wrapper functions for:
  - RSA (Asymmetric) key generation, encryption, and decryption
  - AES-256-GCM (Symmetric) authenticated encryption and decryption
  - Key serialization/deserialization for network transport

Used by all components (Auth Service, App Server, Client) for secure communication.
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =============================================================================
#  RSA (Asymmetric Encryption) — Used for authentication & key exchange
# =============================================================================

def generate_rsa_keypair(key_size=2048):
    """
    Generate a new RSA key pair.
    
    Args:
        key_size: RSA key size in bits (default: 2048 for good security)
    
    Returns:
        tuple: (private_key, public_key) objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filepath):
    """Save an RSA private key to a PEM file (unencrypted for demo purposes)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(pem)


def save_public_key(public_key, filepath):
    """Save an RSA public key to a PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(pem)


def load_private_key(filepath):
    """Load an RSA private key from a PEM file."""
    with open(filepath, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key


def load_public_key(filepath):
    """Load an RSA public key from a PEM file."""
    with open(filepath, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key


def serialize_public_key(public_key):
    """
    Serialize an RSA public key to PEM-encoded string (for sending over network).
    
    Returns:
        str: Base64-encoded PEM string
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")


def deserialize_public_key(pem_string):
    """
    Deserialize an RSA public key from a PEM-encoded string (received from network).
    
    Args:
        pem_string: PEM-encoded public key string
    
    Returns:
        RSA public key object
    """
    pem_bytes = pem_string.encode("utf-8")
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, plaintext_bytes):
    """
    Encrypt data using RSA public key with OAEP padding.
    
    RSA can only encrypt small payloads (up to ~190 bytes for 2048-bit key).
    This is used to encrypt session keys and small authentication tokens.
    
    Args:
        public_key: RSA public key object
        plaintext_bytes: bytes to encrypt (must be small, e.g., a 32-byte AES key)
    
    Returns:
        str: Base64-encoded ciphertext string (safe for JSON transport)
    """
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(private_key, ciphertext_b64):
    """
    Decrypt data using RSA private key with OAEP padding.
    
    Args:
        private_key: RSA private key object
        ciphertext_b64: Base64-encoded ciphertext string
    
    Returns:
        bytes: Decrypted plaintext bytes
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


# =============================================================================
#  AES-256-GCM (Symmetric Encryption) — Used for fast, secure RPC payloads
# =============================================================================

def generate_session_key():
    """
    Generate a random 256-bit (32-byte) AES session key.
    
    Returns:
        bytes: 32-byte random key
    """
    return os.urandom(32)


def aes_encrypt(session_key, plaintext_bytes):
    """
    Encrypt data using AES-256-GCM (Authenticated Encryption).
    
    GCM mode provides both confidentiality AND integrity/authenticity:
    - Confidentiality: Data is encrypted, unreadable without the key
    - Integrity: Any tampering with the ciphertext will be detected
    
    Args:
        session_key: 32-byte AES key
        plaintext_bytes: bytes to encrypt
    
    Returns:
        str: Base64-encoded string of (nonce + ciphertext) for JSON transport
    """
    # Generate a random 12-byte nonce (number used once) for GCM
    nonce = os.urandom(12)
    
    aesgcm = AESGCM(session_key)
    # GCM appends a 16-byte authentication tag to the ciphertext automatically
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    # Prepend nonce to ciphertext so the receiver can extract it
    # Format: [12-byte nonce][ciphertext + 16-byte auth tag]
    encrypted_payload = nonce + ciphertext
    return base64.b64encode(encrypted_payload).decode("utf-8")


def aes_decrypt(session_key, encrypted_b64):
    """
    Decrypt data using AES-256-GCM (Authenticated Decryption).
    
    Verifies the authentication tag to ensure data was not tampered with.
    
    Args:
        session_key: 32-byte AES key
        encrypted_b64: Base64-encoded string of (nonce + ciphertext)
    
    Returns:
        bytes: Decrypted plaintext bytes
    
    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext was tampered with
    """
    encrypted_payload = base64.b64decode(encrypted_b64)
    
    # Extract the 12-byte nonce from the beginning
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
