"""
Network device discovery for the controller.

Two discovery methods:
  1. mDNS — browse for `_remoteshutdown._tcp.local.` services
  2. TCP port scan — scan local subnet for agent ports
"""

import asyncio
import socket
import logging
import time
from typing import List, Dict, Any, Optional

from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
from common.models import Device, DeviceStatus

logger = logging.getLogger(__name__)

SERVICE_TYPE = "_remoteshutdown._tcp.local."
DEFAULT_AGENT_PORT = 9876
SCAN_TIMEOUT = 3.0


# --------------------------------------------------------------------------- #
#  mDNS Discovery
# --------------------------------------------------------------------------- #

class _MDNSListener(ServiceListener):
    """Internal listener for Zeroconf service browsing."""

    def __init__(self):
        self.devices: List[Device] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            props = {k.decode(): v.decode() if isinstance(v, bytes) else v
                     for k, v in info.properties.items()}

            for addr in addresses:
                device = Device(
                    device_id=props.get("device_id", ""),
                    hostname=props.get("hostname", name.split(".")[0]),
                    ip_address=addr,
                    platform=props.get("platform", "unknown"),
                    agent_version=props.get("version", "unknown"),
                    port=info.port,
                    status=DeviceStatus.ONLINE,
                    last_seen=time.time(),
                )
                self.devices.append(device)
                logger.info(f"Discovered via mDNS: {device.hostname} @ {addr}:{info.port}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        logger.debug(f"Service removed: {name}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


def discover_mdns(timeout: float = 5.0) -> List[Device]:
    """
    Discover agents via mDNS.

    Args:
        timeout: How long to listen for responses (seconds)

    Returns:
        List of discovered Device objects.
    """
    zc = Zeroconf()
    listener = _MDNSListener()
    browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

    import time as _time
    _time.sleep(timeout)

    zc.close()
    logger.info(f"mDNS discovery found {len(listener.devices)} device(s)")
    return listener.devices


# --------------------------------------------------------------------------- #
#  TCP Port Scan Discovery
# --------------------------------------------------------------------------- #

async def _check_port(ip: str, port: int, timeout: float) -> Optional[str]:
    """Check if a port is open on an IP address."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return ip
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_subnet(
    subnet_prefix: str,
    port: int = DEFAULT_AGENT_PORT,
    timeout: float = SCAN_TIMEOUT,
    start: int = 1,
    end: int = 254,
) -> List[str]:
    """
    Scan a /24 subnet for open agent ports.

    Args:
        subnet_prefix: e.g. "192.168.1"
        port: Port to scan (default 9876)
        timeout: Per-host timeout
        start: First host octet
        end: Last host octet

    Returns:
        List of IP addresses with open ports.
    """
    tasks = [
        _check_port(f"{subnet_prefix}.{i}", port, timeout)
        for i in range(start, end + 1)
    ]

    results = await asyncio.gather(*tasks)
    found = [ip for ip in results if ip is not None]
    logger.info(f"TCP scan of {subnet_prefix}.0/24:{port} found {len(found)} host(s)")
    return found


def get_local_subnet_prefix() -> str:
    """Get the local subnet prefix (e.g. '192.168.1')."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return ".".join(parts[:3])
    except Exception:
        return "192.168.1"


async def discover_tcp(
    port: int = DEFAULT_AGENT_PORT,
    timeout: float = SCAN_TIMEOUT,
) -> List[Device]:
    """
    Discover agents by scanning the local subnet.

    Returns:
        List of Device objects for hosts with open agent ports.
    """
    prefix = get_local_subnet_prefix()
    ips = await scan_subnet(prefix, port, timeout)

    devices = []
    for ip in ips:
        devices.append(Device(
            hostname=ip,
            ip_address=ip,
            port=port,
            status=DeviceStatus.ONLINE,
            last_seen=time.time(),
        ))

    return devices


async def discover_all(
    mdns_timeout: float = 3.0,
    tcp_port: int = DEFAULT_AGENT_PORT,
    tcp_timeout: float = SCAN_TIMEOUT,
) -> List[Device]:
    """
    Run both mDNS and TCP discovery and merge results.

    Returns:
        Deduplicated list of discovered devices.
    """
    # Run mDNS in a thread (it's blocking)
    loop = asyncio.get_event_loop()
    mdns_devices = await loop.run_in_executor(None, discover_mdns, mdns_timeout)

    # Run TCP scan
    tcp_devices = await discover_tcp(tcp_port, tcp_timeout)

    # Merge and deduplicate by IP
    seen_ips = set()
    merged = []
    for device in mdns_devices + tcp_devices:
        if device.ip_address not in seen_ips:
            seen_ips.add(device.ip_address)
            merged.append(device)

    logger.info(f"Total discovered: {len(merged)} unique device(s)")
    return merged
