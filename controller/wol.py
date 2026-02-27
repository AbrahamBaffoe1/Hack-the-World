"""
Wake-on-LAN module.

Sends magic packets to wake sleeping/powered-off devices
that support Wake-on-LAN (WoL).
"""

import socket
import struct
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

WOL_PORT = 9
BROADCAST_ADDR = "255.255.255.255"


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to colon-separated format."""
    mac = mac.strip().upper()
    # Remove common separators
    mac = re.sub(r"[.:\-]", "", mac)
    if len(mac) != 12 or not all(c in "0123456789ABCDEF" for c in mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


def _mac_to_bytes(mac: str) -> bytes:
    """Convert a MAC address string to 6 bytes."""
    mac = _normalize_mac(mac)
    return bytes(int(b, 16) for b in mac.split(":"))


def build_magic_packet(mac: str) -> bytes:
    """
    Build a Wake-on-LAN magic packet.

    Format: 6 bytes of 0xFF followed by the target MAC address repeated 16 times.
    """
    mac_bytes = _mac_to_bytes(mac)
    return b"\xff" * 6 + mac_bytes * 16


def send_wol(
    mac: str,
    broadcast: str = BROADCAST_ADDR,
    port: int = WOL_PORT,
    interface: Optional[str] = None,
) -> bool:
    """
    Send a Wake-on-LAN magic packet.

    Args:
        mac:        Target MAC address (any common format)
        broadcast:  Broadcast address (default 255.255.255.255)
        port:       UDP port (default 9)
        interface:  Optional source IP to bind to

    Returns:
        True on success, False on failure.
    """
    try:
        packet = build_magic_packet(mac)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if interface:
            sock.bind((interface, 0))

        sock.sendto(packet, (broadcast, port))
        sock.close()

        logger.info(f"WoL magic packet sent to {_normalize_mac(mac)} via {broadcast}:{port}")
        return True

    except Exception as e:
        logger.error(f"Failed to send WoL packet: {e}")
        return False


def send_wol_multiple(macs: list, broadcast: str = BROADCAST_ADDR) -> dict:
    """
    Send WoL packets to multiple devices.

    Returns:
        Dict mapping MAC → success boolean.
    """
    results = {}
    for mac in macs:
        results[mac] = send_wol(mac, broadcast)
    return results
