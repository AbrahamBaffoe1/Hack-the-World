"""
Hybrid remote command executor.

Supports two control modes:
1) Agent mode (IP + agent/listener protocol, no SSH credentials required)
2) SSH mode (classic remote shell commands)
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

import paramiko

logger = logging.getLogger(__name__)

SSH_TIMEOUT = 10
COMMAND_TIMEOUT = 15
AGENT_TIMEOUT = 3


class TargetPlatform(Enum):
    LINUX = "linux"
    MACOS = "darwin"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class AgentConnection:
    host: str
    port: int = 9999
    secret: str = ""
    xor_key: str = ""
    hostname: str = ""
    platform: str = "unknown"


# --------------------------------------------------------------------------- #
#  Platform-specific command maps
# --------------------------------------------------------------------------- #

COMMANDS = {
    TargetPlatform.LINUX: {
        "shutdown": "sudo shutdown -h now",
        "shutdown_delayed": "sudo shutdown -h +{delay}",
        "reboot": "sudo shutdown -r now",
        "sleep": "sudo systemctl suspend",
        "hibernate": "sudo systemctl hibernate",
        "lock_screen": "loginctl lock-session 2>/dev/null || xdg-screensaver lock 2>/dev/null || echo 'no lock method'",
        "status": "hostname && uname -a && uptime && free -h 2>/dev/null | head -2",
        "ping": "echo pong",
        "detect_platform": "uname -s",
    },
    TargetPlatform.MACOS: {
        "shutdown": "sudo shutdown -h now",
        "shutdown_delayed": "sudo shutdown -h +{delay}",
        "reboot": "sudo shutdown -r now",
        "sleep": "pmset sleepnow",
        "hibernate": "pmset sleepnow",
        "lock_screen": "osascript -e 'tell application \"System Events\" to keystroke \"q\" using {{command down, control down}}'",
        "status": "hostname && uname -a && uptime",
        "ping": "echo pong",
        "detect_platform": "uname -s",
    },
    TargetPlatform.WINDOWS: {
        "shutdown": "shutdown /s /t 0",
        "shutdown_delayed": "shutdown /s /t {delay}",
        "reboot": "shutdown /r /t 0",
        "sleep": "rundll32.exe powrprof.dll,SetSuspendState 0,1,0",
        "hibernate": "shutdown /h",
        "lock_screen": "rundll32.exe user32.dll,LockWorkStation",
        "status": "hostname & systeminfo | findstr /B /C:\"OS Name\" /C:\"System Boot Time\" /C:\"Total Physical Memory\"",
        "ping": "echo pong",
        "detect_platform": "ver",
    },
}


# --------------------------------------------------------------------------- #
#  SSH Connection Manager
# --------------------------------------------------------------------------- #

class SSHConnection:
    """Manages an SSH connection to a remote device."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.username = username or self._get_default_username()
        self.password = password
        self.key_path = key_path
        self.client: Optional[paramiko.SSHClient] = None
        self.detected_platform: TargetPlatform = TargetPlatform.UNKNOWN

    @staticmethod
    def _get_default_username() -> str:
        import getpass

        return getpass.getuser()

    @staticmethod
    def _find_ssh_keys() -> list:
        ssh_dir = os.path.expanduser("~/.ssh")
        key_patterns = [
            "remote_shutdown_controller_ed25519",
            "remote_shutdown_controller_rsa",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
        ]
        found = []
        for name in key_patterns:
            path = os.path.join(ssh_dir, name)
            if os.path.isfile(path):
                found.append(path)
        return found

    def connect(self) -> bool:
        """
        Establish SSH connection.

        Auto-tries:
        1) Explicit key if given
        2) auto-discovered ~/.ssh keys
        3) SSH agent keys
        4) password fallback if supplied
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": SSH_TIMEOUT,
                "allow_agent": True,
                "look_for_keys": True,
            }

            if self.key_path:
                connect_kwargs["key_filename"] = self.key_path
            else:
                keys = self._find_ssh_keys()
                if keys:
                    connect_kwargs["key_filename"] = keys
                    logger.info(f"Auto-discovered {len(keys)} SSH key(s)")

            if self.password:
                connect_kwargs["password"] = self.password

            self.client.connect(**connect_kwargs)
            logger.info(f"SSH connected to {self.host}:{self.port} as {self.username}")
            return True

        except paramiko.AuthenticationException:
            logger.error(f"SSH auth failed for {self.username}@{self.host}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {e}")
            return False

    def disconnect(self) -> None:
        if self.client:
            self.client.close()
            self.client = None
            logger.debug(f"SSH disconnected from {self.host}")

    def is_connected(self) -> bool:
        if not self.client:
            return False
        transport = self.client.get_transport()
        return transport is not None and transport.is_active()

    def execute(self, command: str, timeout: int = COMMAND_TIMEOUT) -> Tuple[str, str, int]:
        if not self.is_connected():
            if not self.connect():
                return "", "Not connected", -1

        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            logger.debug(f"[{self.host}] $ {command} -> exit={exit_code}")
            return out, err, exit_code
        except Exception as e:
            logger.error(f"Command execution failed on {self.host}: {e}")
            return "", str(e), -1

    def detect_platform(self) -> TargetPlatform:
        out, err, _code = self.execute("uname -s 2>/dev/null || ver 2>nul", timeout=5)
        output = (out + err).lower()

        if "linux" in output:
            self.detected_platform = TargetPlatform.LINUX
        elif "darwin" in output:
            self.detected_platform = TargetPlatform.MACOS
        elif "windows" in output or "microsoft" in output:
            self.detected_platform = TargetPlatform.WINDOWS
        else:
            self.detected_platform = TargetPlatform.UNKNOWN

        logger.info(f"Detected platform for {self.host}: {self.detected_platform.value}")
        return self.detected_platform

    def get_hostname(self) -> str:
        out, _, _ = self.execute("hostname", timeout=5)
        return out.strip() or self.host


# --------------------------------------------------------------------------- #
#  Remote Executor
# --------------------------------------------------------------------------- #

class RemoteExecutor:
    """Executes power commands through either agent mode or SSH mode."""

    def __init__(self):
        self.connections: Dict[str, SSHConnection] = {}
        self.agent_connections: Dict[str, AgentConnection] = {}

    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        if not key:
            return data
        out = bytearray(len(data))
        klen = len(key)
        for idx, value in enumerate(data):
            out[idx] = value ^ key[idx % klen]
        return bytes(out)

    @staticmethod
    def _canonical_agent_payload(frame: Dict[str, Any]) -> bytes:
        payload = {
            "type": frame.get("type"),
            "delay_sec": int(frame.get("delay_sec", 0)),
            "ts_ms": int(frame.get("ts_ms", 0)),
            "nonce": frame.get("nonce"),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _compute_agent_auth(self, secret: str, frame: Dict[str, Any]) -> str:
        body = self._canonical_agent_payload(frame)
        return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def _encode_agent_payload(self, payload: Dict[str, Any], xor_key: str) -> bytes:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if xor_key:
            raw = self._xor_bytes(raw, xor_key.encode("utf-8"))
            raw = base64.urlsafe_b64encode(raw)
        return raw + b"\n"

    def _decode_agent_payload(self, raw: bytes, xor_key: str) -> Dict[str, Any]:
        line = raw.strip()
        if xor_key:
            line = base64.urlsafe_b64decode(line)
            line = self._xor_bytes(line, xor_key.encode("utf-8"))
        return json.loads(line.decode("utf-8"))

    def _send_agent_command(self, conn: AgentConnection, command_type: str, delay_sec: int = 0) -> Dict[str, Any]:
        frame = {
            "type": command_type,
            "delay_sec": int(delay_sec),
            "ts_ms": int(time.time() * 1000),
            "nonce": str(uuid4()),
        }
        if conn.secret:
            frame["auth"] = self._compute_agent_auth(conn.secret, frame)

        payload = self._encode_agent_payload(frame, conn.xor_key)

        try:
            with socket.create_connection((conn.host, conn.port), timeout=AGENT_TIMEOUT) as sock:
                sock.settimeout(AGENT_TIMEOUT)
                sock.sendall(payload)

                data = bytearray()
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                    if b"\n" in chunk:
                        break

            if not data:
                return {"success": False, "error": "No response from agent listener"}

            response = self._decode_agent_payload(bytes(data), conn.xor_key)
            success = str(response.get("status", "")).upper() == "OK"
            return {
                "success": success,
                "response": response,
                "output": response.get("message", ""),
                "error": "" if success else response.get("message", "Agent command failed"),
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Agent connection failed to {conn.host}:{conn.port} ({e})",
            }

    def add_agent_device(self, host: str, port: int = 9999, secret: str = "", xor_key: str = "") -> Dict[str, Any]:
        """Add/register a listener-based agent target."""
        conn = AgentConnection(host=host, port=port, secret=secret or "", xor_key=xor_key or "")
        ping = self._send_agent_command(conn, "PING", 0)
        if not ping["success"]:
            return {
                "success": False,
                "error": ping.get("error", f"Agent ping failed for {host}:{port}"),
            }

        response = ping.get("response", {})
        conn.hostname = response.get("host", host)
        conn.platform = response.get("os", "unknown")
        self.agent_connections[host] = conn

        return {
            "success": True,
            "mode": "agent",
            "host": host,
            "port": port,
            "hostname": conn.hostname,
            "platform": conn.platform,
            "username": "",
        }

    def add_device(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        prefer_ssh: bool = False,
    ) -> Dict[str, Any]:
        """
        Add device by IP/host.

        Auto mode:
        - If username is empty, try agent mode first (port 9999 by default).
        - Fallback to SSH.
        """
        # Explicit marker used by the server to restore persisted agent entries.
        if username == "__agent__":
            agent_port = 9999 if port == 22 else port
            return self.add_agent_device(host, agent_port, secret=password or "", xor_key=key_path or "")

        if not prefer_ssh and not username and not key_path:
            agent_port = 9999 if port == 22 else port
            agent_result = self.add_agent_device(host, agent_port, secret=password or "", xor_key="")
            if agent_result.get("success"):
                return agent_result

        conn = SSHConnection(host, port, username, password, key_path)
        if not conn.connect():
            return {
                "success": False,
                "error": (
                    f"SSH connection failed to {host}:{port} as '{conn.username}'. "
                    "If target runs the agent listener, use add <ip> without SSH credentials "
                    "or set mode=agent on port 9999."
                ),
            }

        platform = conn.detect_platform()
        hostname = conn.get_hostname()
        self.connections[host] = conn

        return {
            "success": True,
            "mode": "ssh",
            "host": host,
            "port": port,
            "hostname": hostname,
            "platform": platform.value,
            "username": conn.username,
        }

    def remove_device(self, host: str) -> None:
        conn = self.connections.pop(host, None)
        if conn:
            conn.disconnect()
        self.agent_connections.pop(host, None)

    def execute_command(self, host: str, command: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        conn = self.connections.get(host)
        agent_conn = self.agent_connections.get(host)
        if not conn and not agent_conn:
            return {"success": False, "error": f"Device {host} not registered. Add it first."}

        if agent_conn:
            cmd_key = command.lower().replace("-", "_")
            delay = int((params or {}).get("delay", 0))

            if cmd_key == "ping":
                result = self._send_agent_command(agent_conn, "PING", 0)
            elif cmd_key == "shutdown":
                result = self._send_agent_command(
                    agent_conn,
                    "SHUTDOWN_DELAYED" if delay > 0 else "SHUTDOWN_NOW",
                    delay,
                )
            elif cmd_key == "reboot":
                result = self._send_agent_command(
                    agent_conn,
                    "REBOOT_DELAYED" if delay > 0 else "REBOOT_NOW",
                    delay,
                )
            else:
                return {
                    "success": False,
                    "command": command,
                    "host": host,
                    "error": "Agent mode supports: ping, shutdown, reboot",
                    "mode": "agent",
                }

            return {
                "success": result.get("success", False),
                "command": command,
                "host": host,
                "output": result.get("output", ""),
                "error": result.get("error", ""),
                "mode": "agent",
            }

        if not conn.is_connected():
            if not conn.connect():
                return {"success": False, "error": f"Cannot reconnect to {host}", "mode": "ssh"}

        platform = conn.detected_platform
        if platform == TargetPlatform.UNKNOWN:
            platform = conn.detect_platform()

        cmd_map = COMMANDS.get(platform)
        if not cmd_map:
            return {"success": False, "error": f"Unsupported platform: {platform.value}", "mode": "ssh"}

        cmd_key = command.lower().replace("-", "_")
        if cmd_key == "shutdown" and params and params.get("delay", 0) > 0:
            cmd_key = "shutdown_delayed"

        ssh_cmd = cmd_map.get(cmd_key)
        if not ssh_cmd:
            return {"success": False, "error": f"Unknown command: {command}", "mode": "ssh"}

        if params:
            delay_seconds = int(params.get("delay", 0))
            delay_minutes = max(1, delay_seconds // 60)
            ssh_cmd = ssh_cmd.format(
                delay=delay_minutes if platform != TargetPlatform.WINDOWS else delay_seconds,
            )

        stdout, stderr, exit_code = conn.execute(ssh_cmd)
        success = exit_code == 0 or cmd_key == "ping"

        return {
            "success": success,
            "command": command,
            "host": host,
            "output": stdout,
            "error": stderr if not success else "",
            "exit_code": exit_code,
            "mode": "ssh",
        }

    def ping_device(self, host: str) -> Dict[str, Any]:
        return self.execute_command(host, "ping")

    def get_status(self, host: str) -> Dict[str, Any]:
        return self.execute_command(host, "status")

    def check_connectivity(self, host: str) -> bool:
        conn = self.connections.get(host)
        if conn:
            if conn.is_connected():
                return True
            return conn.connect()

        agent_conn = self.agent_connections.get(host)
        if agent_conn:
            result = self._send_agent_command(agent_conn, "PING", 0)
            return bool(result.get("success"))

        return False

    def get_all_connections(self) -> Dict[str, Dict[str, Any]]:
        result = {}

        for host, conn in self.connections.items():
            result[host] = {
                "host": host,
                "connected": conn.is_connected(),
                "platform": conn.detected_platform.value,
                "username": conn.username,
                "mode": "ssh",
            }

        for host, conn in self.agent_connections.items():
            result[host] = {
                "host": host,
                "connected": True,
                "platform": conn.platform,
                "username": "",
                "mode": "agent",
            }

        return result
