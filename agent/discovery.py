"""
mDNS service announcer for the Remote Shutdown agent.

Registers the agent as a discoverable service on the local network
using Zeroconf (mDNS/DNS-SD).
"""

import socket
import logging
import platform
from typing import Optional

from zeroconf import Zeroconf, ServiceInfo

logger = logging.getLogger(__name__)

SERVICE_TYPE = "_remoteshutdown._tcp.local."


class AgentAnnouncer:
    """Manages mDNS service registration for the agent."""

    def __init__(self, port: int, device_id: str, agent_version: str = "1.0.0"):
        self.port = port
        self.device_id = device_id
        self.agent_version = agent_version
        self.zeroconf: Optional[Zeroconf] = None
        self.service_info: Optional[ServiceInfo] = None

    def _get_local_ip(self) -> str:
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self) -> None:
        """Register the mDNS service."""
        hostname = platform.node()
        local_ip = self._get_local_ip()

        self.service_info = ServiceInfo(
            SERVICE_TYPE,
            f"{hostname}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={
                "device_id": self.device_id,
                "hostname": hostname,
                "platform": platform.system().lower(),
                "version": self.agent_version,
            },
            server=f"{hostname}.local.",
        )

        self.zeroconf = Zeroconf()
        self.zeroconf.register_service(self.service_info)
        logger.info(f"mDNS service registered: {hostname} @ {local_ip}:{self.port}")

    def stop(self) -> None:
        """Unregister the mDNS service."""
        if self.zeroconf and self.service_info:
            self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            logger.info("mDNS service unregistered")
            self.zeroconf = None
            self.service_info = None
