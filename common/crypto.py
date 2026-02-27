"""
Cryptographic utilities for the Remote Shutdown System.

Provides:
- AES-256-GCM symmetric encryption/decryption
- ECDSA P-256 key pair generation, signing, and verification
- Key serialization (PEM format)
"""

import os
import time
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDSA,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.backends import default_backend


# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

NONCE_SIZE = 12          # 96-bit nonce for AES-GCM
AES_KEY_SIZE = 32        # 256-bit key
SIGNATURE_SIZE = 64      # P-256 ECDSA signature (r || s)
TIMESTAMP_SIZE = 8       # 64-bit epoch timestamp


# --------------------------------------------------------------------------- #
#  Symmetric Encryption  (AES-256-GCM)
# --------------------------------------------------------------------------- #

def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Returns:
        (nonce, ciphertext) — nonce is 12 bytes, ciphertext includes 16-byte auth tag.
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data or None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Returns:
        The original plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag on tampered data.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data or None)


# --------------------------------------------------------------------------- #
#  Asymmetric Keys  (ECDSA P-256)
# --------------------------------------------------------------------------- #

def generate_key_pair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDSA P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()


def sign(data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Sign data with ECDSA P-256 / SHA-256."""
    return private_key.sign(data, ECDSA(SHA256()))


def verify(data: bytes, signature: bytes, public_key: EllipticCurvePublicKey) -> bool:
    """
    Verify an ECDSA signature.

    Returns:
        True if valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, ECDSA(SHA256()))
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Key Serialization
# --------------------------------------------------------------------------- #

def private_key_to_pem(key: EllipticCurvePrivateKey) -> bytes:
    """Serialize a private key to PEM bytes."""
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def public_key_to_pem(key: EllipticCurvePublicKey) -> bytes:
    """Serialize a public key to PEM bytes."""
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem_data: bytes) -> EllipticCurvePrivateKey:
    """Deserialize a PEM private key."""
    return load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_public_key(pem_data: bytes) -> EllipticCurvePublicKey:
    """Deserialize a PEM public key."""
    return load_pem_public_key(pem_data, backend=default_backend())


def save_key_pair(private_key: EllipticCurvePrivateKey, directory: str, prefix: str = "agent") -> Tuple[str, str]:
    """
    Save key pair to PEM files in the given directory.

    Returns:
        (private_key_path, public_key_path)
    """
    os.makedirs(directory, exist_ok=True)
    priv_path = os.path.join(directory, f"{prefix}_private.pem")
    pub_path = os.path.join(directory, f"{prefix}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key_to_pem(private_key))
    os.chmod(priv_path, 0o600)

    with open(pub_path, "wb") as f:
        f.write(public_key_to_pem(private_key.public_key()))

    return priv_path, pub_path


def load_key_pair(directory: str, prefix: str = "agent") -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Load key pair from PEM files."""
    priv_path = os.path.join(directory, f"{prefix}_private.pem")
    pub_path = os.path.join(directory, f"{prefix}_public.pem")

    with open(priv_path, "rb") as f:
        private_key = load_private_key(f.read())

    with open(pub_path, "rb") as f:
        public_key = load_public_key(f.read())

    return private_key, public_key
