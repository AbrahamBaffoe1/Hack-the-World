"""
Agent configuration management.

Handles loading/saving agent settings from a JSON config file,
including device identity, port, authorized controllers, and consent prefs.
"""

import os
import json
import uuid
import platform
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = os.path.expanduser("~/.remote-shutdown")
DEFAULT_CONFIG_FILE = "agent_config.json"
DEFAULT_PORT = 9876


@dataclass
class AgentConfig:
    """Agent runtime configuration."""
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = field(default_factory=lambda: platform.node())
    port: int = DEFAULT_PORT
    platform_name: str = field(default_factory=lambda: platform.system().lower())
    agent_version: str = "1.0.0"

    # Security
    config_dir: str = DEFAULT_CONFIG_DIR
    authorized_controllers: List[str] = field(default_factory=list)  # Public key fingerprints

    # Consent defaults  (True = allowed without prompt)
    consent: Dict[str, bool] = field(default_factory=lambda: {
        "PING": True,
        "STATUS": True,
        "SHUTDOWN": True,
        "SHUTDOWN_DELAYED": True,
        "REBOOT": True,
        "SLEEP": True,
        "HIBERNATE": True,
        "LOCK_SCREEN": True,
    })

    # Persistence
    auto_start: bool = True
    log_level: str = "INFO"

    def save(self, path: Optional[str] = None) -> str:
        """Save config to JSON file."""
        path = path or os.path.join(self.config_dir, DEFAULT_CONFIG_FILE)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
        logger.info(f"Config saved to {path}")
        return path

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AgentConfig":
        """Load config from JSON file, or create default."""
        path = path or os.path.join(DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE)
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            logger.info(f"Config loaded from {path}")
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        else:
            logger.info("No config found, creating default")
            config = cls()
            config.save(path)
            return config

    @property
    def keys_dir(self) -> str:
        return os.path.join(self.config_dir, "keys")

    @property
    def db_path(self) -> str:
        return os.path.join(self.config_dir, "agent.db")
