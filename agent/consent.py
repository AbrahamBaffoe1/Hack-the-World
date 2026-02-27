"""
Consent / Permission system for the agent.

Every command must pass through the consent gate before execution.
Devices explicitly opt-in to which commands they allow.
First-run generates a consent config; users can modify via config file.
"""

import logging
from typing import Optional
from common.models import CommandType
from agent.config import AgentConfig

logger = logging.getLogger(__name__)


class ConsentDenied(Exception):
    """Raised when a command is denied by the consent system."""
    pass


class ConsentGate:
    """
    Gates command execution based on user-configured consent.

    The consent system ensures:
    1. Only explicitly allowed commands can execute
    2. Unknown command types are denied by default
    3. The user has full control over what their device will do
    """

    def __init__(self, config: AgentConfig):
        self.config = config

    def check(self, command_type: int) -> bool:
        """
        Check if a command type is allowed.

        Returns True if allowed, False if denied.
        """
        try:
            cmd_name = CommandType(command_type).name
        except ValueError:
            logger.warning(f"Unknown command type 0x{command_type:02X} — denied")
            return False

        allowed = self.config.consent.get(cmd_name, False)
        if not allowed:
            logger.info(f"Command {cmd_name} denied by consent policy")
        return allowed

    def require(self, command_type: int) -> None:
        """
        Require consent for a command type. Raises ConsentDenied if not allowed.
        """
        if not self.check(command_type):
            try:
                cmd_name = CommandType(command_type).name
            except ValueError:
                cmd_name = f"0x{command_type:02X}"
            raise ConsentDenied(
                f"Command '{cmd_name}' is not permitted on this device. "
                f"Update consent in ~/.remote-shutdown/agent_config.json"
            )

    def allow(self, command_type: int) -> None:
        """Grant consent for a command type."""
        try:
            cmd_name = CommandType(command_type).name
            self.config.consent[cmd_name] = True
            self.config.save()
            logger.info(f"Consent granted for {cmd_name}")
        except ValueError:
            logger.error(f"Cannot grant consent for unknown command 0x{command_type:02X}")

    def deny(self, command_type: int) -> None:
        """Revoke consent for a command type."""
        try:
            cmd_name = CommandType(command_type).name
            self.config.consent[cmd_name] = False
            self.config.save()
            logger.info(f"Consent revoked for {cmd_name}")
        except ValueError:
            pass

    def list_permissions(self) -> dict:
        """Return the current consent state."""
        return dict(self.config.consent)

    def is_controller_authorized(self, controller_fingerprint: str) -> bool:
        """Check if a controller is authorized to send commands to this agent."""
        if not self.config.authorized_controllers:
            # First connection — no controllers authorized yet
            # In production, this would trigger a pairing flow
            logger.warning("No authorized controllers configured — accepting first connection")
            return True
        return controller_fingerprint in self.config.authorized_controllers

    def authorize_controller(self, fingerprint: str) -> None:
        """Add a controller to the authorized list."""
        if fingerprint not in self.config.authorized_controllers:
            self.config.authorized_controllers.append(fingerprint)
            self.config.save()
            logger.info(f"Controller {fingerprint[:16]}... authorized")
