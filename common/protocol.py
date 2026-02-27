"""
Secure message protocol for the Remote Shutdown System.

Frame format:
    [Header: 32 bytes]
        - Nonce        (12 bytes)  — AES-GCM nonce
        - Timestamp    ( 8 bytes)  — uint64 epoch seconds
        - Payload len  ( 4 bytes)  — uint32, length of encrypted payload
        - Reserved     ( 8 bytes)  — future use (zeroed)

    [Encrypted Payload: variable]
        - Command/Response JSON encrypted with AES-256-GCM
        - Auth tag appended by AES-GCM (16 bytes)

    [Signature: variable]
        - ECDSA P-256 signature over (header || encrypted_payload)
"""

import struct
import time
import logging
from typing import Tuple, Optional

from common.crypto import (
    encrypt,
    decrypt,
    sign,
    verify,
    NONCE_SIZE,
    TIMESTAMP_SIZE,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

HEADER_SIZE = 32
PAYLOAD_LEN_SIZE = 4
RESERVED_SIZE = 8
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1 MB cap
MAX_CLOCK_DRIFT = 300           # 5-minute tolerance

MAGIC = b"RSHD"  # Protocol identifier


# --------------------------------------------------------------------------- #
#  Frame Encoder / Decoder
# --------------------------------------------------------------------------- #

class ProtocolError(Exception):
    """Raised on malformed or invalid frames."""
    pass


def encode_frame(
    payload: bytes,
    aes_key: bytes,
    private_key: Optional[EllipticCurvePrivateKey] = None,
) -> bytes:
    """
    Encode a payload into a secure frame.

    Args:
        payload:     Raw bytes (typically Command.to_bytes() or Response.to_bytes())
        aes_key:     256-bit symmetric encryption key
        private_key: Optional ECDSA key for signing

    Returns:
        Complete frame bytes ready for transmission.
    """
    timestamp = int(time.time())
    nonce, ciphertext = encrypt(payload, aes_key)

    # Build header
    header = struct.pack(
        f"!{NONCE_SIZE}sQI{RESERVED_SIZE}s",
        nonce,
        timestamp,
        len(ciphertext),
        b"\x00" * RESERVED_SIZE,
    )
    assert len(header) == HEADER_SIZE

    # Signature (optional but recommended)
    frame_data = header + ciphertext
    if private_key:
        signature = sign(frame_data, private_key)
        sig_len = struct.pack("!H", len(signature))
        return frame_data + sig_len + signature
    else:
        # No signature — append zero-length marker
        return frame_data + struct.pack("!H", 0)


def decode_frame(
    frame: bytes,
    aes_key: bytes,
    public_key: Optional[EllipticCurvePublicKey] = None,
) -> bytes:
    """
    Decode and verify a secure frame.

    Args:
        frame:      Raw frame bytes from the network
        aes_key:    256-bit symmetric decryption key
        public_key: Optional ECDSA key for signature verification

    Returns:
        Decrypted payload bytes.

    Raises:
        ProtocolError on invalid frame structure, expired timestamp, or bad signature.
    """
    if len(frame) < HEADER_SIZE + 2:
        raise ProtocolError(f"Frame too short: {len(frame)} bytes")

    # Parse header
    nonce = frame[:NONCE_SIZE]
    timestamp = struct.unpack("!Q", frame[NONCE_SIZE : NONCE_SIZE + TIMESTAMP_SIZE])[0]
    payload_len = struct.unpack(
        "!I",
        frame[NONCE_SIZE + TIMESTAMP_SIZE : NONCE_SIZE + TIMESTAMP_SIZE + PAYLOAD_LEN_SIZE],
    )[0]

    # Validate timestamp (anti-replay)
    now = int(time.time())
    if abs(now - timestamp) > MAX_CLOCK_DRIFT:
        raise ProtocolError(f"Timestamp drift too large: {abs(now - timestamp)}s")

    if payload_len > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"Payload too large: {payload_len} bytes")

    # Extract encrypted payload
    ciphertext_start = HEADER_SIZE
    ciphertext_end = HEADER_SIZE + payload_len
    if ciphertext_end + 2 > len(frame):
        raise ProtocolError("Frame truncated: missing ciphertext or signature length")

    ciphertext = frame[ciphertext_start:ciphertext_end]

    # Extract signature
    sig_len = struct.unpack("!H", frame[ciphertext_end : ciphertext_end + 2])[0]
    if sig_len > 0:
        signature = frame[ciphertext_end + 2 : ciphertext_end + 2 + sig_len]
        if len(signature) != sig_len:
            raise ProtocolError("Frame truncated: incomplete signature")

        # Verify signature
        signed_data = frame[:ciphertext_end]
        if public_key:
            if not verify(signed_data, signature, public_key):
                raise ProtocolError("Signature verification failed")
        else:
            logger.warning("Frame has signature but no public key provided — skipping verification")
    elif public_key:
        raise ProtocolError("Frame has no signature but verification was requested")

    # Decrypt
    try:
        plaintext = decrypt(nonce, ciphertext, aes_key)
    except Exception as e:
        raise ProtocolError(f"Decryption failed: {e}") from e

    return plaintext


# --------------------------------------------------------------------------- #
#  Stream helpers  (length-prefixed framing over TCP)
# --------------------------------------------------------------------------- #

async def send_frame(writer, frame: bytes) -> None:
    """Send a length-prefixed frame over an asyncio StreamWriter."""
    length_prefix = struct.pack("!I", len(frame))
    writer.write(length_prefix + frame)
    await writer.drain()


async def recv_frame(reader, max_size: int = MAX_PAYLOAD_SIZE + HEADER_SIZE + 256) -> bytes:
    """Receive a length-prefixed frame from an asyncio StreamReader."""
    length_bytes = await reader.readexactly(4)
    frame_len = struct.unpack("!I", length_bytes)[0]
    if frame_len > max_size:
        raise ProtocolError(f"Incoming frame too large: {frame_len}")
    return await reader.readexactly(frame_len)
