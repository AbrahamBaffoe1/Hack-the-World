"""
Data models for the Remote Shutdown System.

All models are plain dataclasses for easy serialization and zero external deps.
"""

import time
import uuid
import platform as _platform
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional, Dict, Any
import json


# --------------------------------------------------------------------------- #
#  Command Types
# --------------------------------------------------------------------------- #

class CommandType(IntEnum):
    """Supported command codes."""
    PING = 0x01
    SHUTDOWN = 0x02
    SHUTDOWN_DELAYED = 0x03
    REBOOT = 0x04
    SLEEP = 0x05
    HIBERNATE = 0x06
    STATUS = 0x10
    LOCK_SCREEN = 0x11
    AUTHORIZE = 0x20       # Controller authorization handshake
    DEAUTHORIZE = 0x21
    # ── Restricted (TODO) ──────────────────────────────────────────────────
    # WIPE_STORAGE = 0x07      # TODO: Requires explicit user consent flow
    # LOCKOUT = 0x08           # TODO: Disable local input — needs consent
    # EXFILTRATE = 0x09        # TODO: Credential dump — NOT IMPLEMENTED
    # SELF_DESTRUCT = 0xFF     # TODO: Listener removal — needs consent


class DeviceStatus(IntEnum):
    """Device connection status."""
    UNKNOWN = 0
    ONLINE = 1
    OFFLINE = 2
    SLEEPING = 3
    SHUTTING_DOWN = 4


# --------------------------------------------------------------------------- #
#  Device
# --------------------------------------------------------------------------- #

@dataclass
class Device:
    """Represents a network device running the agent."""
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    platform: str = field(default_factory=lambda: _platform.system().lower())
    platform_version: str = field(default_factory=_platform.version)
    agent_version: str = "1.0.0"
    status: int = DeviceStatus.UNKNOWN
    last_seen: float = field(default_factory=time.time)
    port: int = 9876
    authorized: bool = False
    consent: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, raw: str) -> "Device":
        return cls.from_dict(json.loads(raw))


# --------------------------------------------------------------------------- #
#  Command
# --------------------------------------------------------------------------- #

@dataclass
class Command:
    """A command to be sent to a device."""
    command_type: int
    command_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    params: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    sender_id: str = ""

    def to_bytes(self) -> bytes:
        """Serialize to bytes for transmission."""
        return json.dumps(asdict(self)).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Command":
        """Deserialize from bytes."""
        d = json.loads(data.decode("utf-8"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @property
    def type_name(self) -> str:
        try:
            return CommandType(self.command_type).name
        except ValueError:
            return f"UNKNOWN_0x{self.command_type:02X}"


# --------------------------------------------------------------------------- #
#  Response
# --------------------------------------------------------------------------- #

@dataclass
class Response:
    """Response sent back by an agent after executing a command."""
    command_id: str
    success: bool
    message: str = ""
    device_info: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        return json.dumps(asdict(self)).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Response":
        d = json.loads(data.decode("utf-8"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
