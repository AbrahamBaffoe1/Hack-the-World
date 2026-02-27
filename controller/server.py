"""
Controller HTTP API + WebSocket server — Hybrid mode.

Devices can be controlled either by:
1) Agent listener protocol (IP-only after enrollment), or
2) SSH credentials.

API:
  POST /api/devices/add          — Add device by IP + SSH credentials
  POST /api/devices/register     — Self-register a device after local setup
  GET  /api/controller/status    — Controller health + SSH key status
  GET  /api/devices              — List all devices
  POST /api/devices/{id}/command — Send command (shutdown, reboot, sleep, etc.)
  POST /api/devices/{id}/ping    — Check SSH connectivity
  POST /api/devices/{id}/wake    — Send WoL magic packet
  PUT  /api/devices/{id}/mac     — Set MAC for WoL
  DELETE /api/devices/{id}       — Remove device
  POST /api/devices/discover     — Scan network for SSH hosts
  WS   /ws                       — Real-time status updates
"""

import asyncio
import base64
import os
import sys
import json
import time
import logging
import argparse
import subprocess
import platform
import smtplib
import hashlib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Set
from concurrent.futures import ThreadPoolExecutor

from aiohttp import web, WSMsgType

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Device, DeviceStatus
from controller.device_store import DeviceStore
from controller.remote_executor import RemoteExecutor, TargetPlatform
from controller.wol import send_wol

logger = logging.getLogger("controller")

DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
SETUP_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "setup_device.py")
CONTROLLER_SSH_DIR = os.path.expanduser("~/.ssh")
CONTROLLER_KEY_BASENAME = "remote_shutdown_controller_ed25519"

# Thread pool for blocking SSH operations
ssh_pool = ThreadPoolExecutor(max_workers=10)


class ControllerServer:
    """Hybrid controller server — agent mode + SSH mode."""

    def __init__(self, port: int = 8080):
        self.port = port
        self.store = DeviceStore()
        self.executor = RemoteExecutor()
        self.ws_clients: Set[web.WebSocketResponse] = set()

    def _reconnect_devices(self):
        """Reconnect to previously stored devices on startup."""
        devices = self.store.get_all()
        for device in devices:
            creds = self.store.get_credentials(device.device_id)
            if creds and creds["username"]:
                try:
                    if creds["username"] == "__agent__":
                        self.executor.add_agent_device(
                            host=creds["host"],
                            port=creds["port"] or 9999,
                            secret=creds["password"] or "",
                            xor_key=creds["key_path"] or "",
                        )
                    else:
                        self.executor.add_device(
                            host=creds["host"],
                            port=creds["port"],
                            username=creds["username"],
                            password=creds["password"],
                            key_path=creds["key_path"],
                        )
                    self.store.update_status(device.device_id, DeviceStatus.ONLINE)
                    logger.info(f"Reconnected to {device.hostname} ({creds['host']})")
                except Exception as e:
                    self.store.update_status(device.device_id, DeviceStatus.OFFLINE)
                    logger.warning(f"Could not reconnect to {device.hostname}: {e}")

    async def _broadcast_ws(self, event: dict) -> None:
        """Send event to all WebSocket clients."""
        message = json.dumps(event)
        dead = set()
        for ws in self.ws_clients:
            try:
                await ws.send_str(message)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    async def _run_ssh(self, func, *args):
        """Run a blocking SSH operation in the thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(ssh_pool, func, *args)

    @staticmethod
    def _ssh_public_key_fingerprint(public_key: str) -> str:
        """Return OpenSSH-style SHA256 fingerprint for a public key line."""
        parts = public_key.strip().split()
        if len(parts) < 2:
            return ""
        digest = hashlib.sha256(base64.b64decode(parts[1].encode("ascii"))).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    @staticmethod
    def _controller_public_key_candidates():
        return [
            os.path.join(CONTROLLER_SSH_DIR, f"{CONTROLLER_KEY_BASENAME}.pub"),
            os.path.join(CONTROLLER_SSH_DIR, "id_ed25519.pub"),
            os.path.join(CONTROLLER_SSH_DIR, "id_rsa.pub"),
            os.path.join(CONTROLLER_SSH_DIR, "id_ecdsa.pub"),
        ]

    @staticmethod
    def _get_controller_key_status() -> dict:
        """Return controller SSH key status without generating a new key."""
        for candidate in ControllerServer._controller_public_key_candidates():
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8") as handle:
                    public_key = handle.read().strip()
                name = os.path.basename(candidate)
                return {
                    "exists": True,
                    "path": candidate,
                    "fingerprint": ControllerServer._ssh_public_key_fingerprint(public_key),
                    "source": "dedicated" if name.startswith(CONTROLLER_KEY_BASENAME) else "default",
                }
        return {
            "exists": False,
            "path": "",
            "fingerprint": "",
            "source": "missing",
        }

    @staticmethod
    def _ensure_controller_public_key() -> dict:
        """Return an existing controller SSH public key, or generate a dedicated one."""
        os.makedirs(CONTROLLER_SSH_DIR, exist_ok=True)

        for candidate in ControllerServer._controller_public_key_candidates():
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8") as handle:
                    public_key = handle.read().strip()
                return {
                    "public_key": public_key,
                    "path": candidate,
                    "fingerprint": ControllerServer._ssh_public_key_fingerprint(public_key),
                    "generated": False,
                }

        private_key_path = os.path.join(CONTROLLER_SSH_DIR, CONTROLLER_KEY_BASENAME)
        public_key_path = f"{private_key_path}.pub"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                private_key_path,
                "-N",
                "",
                "-C",
                "remote-shutdown-controller",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)
        with open(public_key_path, "r", encoding="utf-8") as handle:
            public_key = handle.read().strip()
        return {
            "public_key": public_key,
            "path": public_key_path,
            "fingerprint": ControllerServer._ssh_public_key_fingerprint(public_key),
            "generated": True,
        }

    # --------------------------------------------------------------------- #
    #  Route Handlers
    # --------------------------------------------------------------------- #

    async def handle_index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))

    async def handle_static(self, request: web.Request) -> web.FileResponse:
        filename = request.match_info["filename"]
        filepath = os.path.join(DASHBOARD_DIR, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            return web.FileResponse(filepath)
        raise web.HTTPNotFound()

    async def handle_add_device(self, request: web.Request) -> web.Response:
        """POST /api/devices/add — Add by agent mode (default) or SSH mode."""
        body = await request.json()
        ip = body.get("ip", "").strip()
        try:
            port = int(body.get("port", 22))
        except (TypeError, ValueError):
            port = 22
        username = body.get("username", "").strip()
        password = body.get("password", "")
        key_path = body.get("key_path", "")
        mac = body.get("mac", "").strip()
        mode = body.get("mode", "auto").strip().lower()
        try:
            agent_port = int(body.get("agent_port", 9999))
        except (TypeError, ValueError):
            agent_port = 9999
        agent_secret = body.get("agent_secret", "")
        agent_xor_key = body.get("agent_xor_key", "")

        if not ip:
            return web.json_response({"error": "IP address is required"}, status=400)

        existing = self.store.get_by_ip(ip)

        result = None

        # Prefer agent mode for IP-only flow.
        if mode in {"agent", "auto"} and not username:
            result = await self._run_ssh(
                self.executor.add_agent_device,
                ip,
                agent_port if agent_port > 0 else 9999,
                agent_secret,
                agent_xor_key,
            )
            if not result["success"] and mode == "agent":
                return web.json_response({"error": result["error"]}, status=400)

        # Fallback or explicit SSH mode.
        if result is None or not result.get("success"):
            result = await self._run_ssh(
                self.executor.add_device, ip, port, username, password, key_path, mode == "ssh"
            )

        if not result["success"]:
            return web.json_response({"error": result["error"]}, status=400)

        conn_mode = result.get("mode", "ssh")
        stored_username = "__agent__" if conn_mode == "agent" else username
        stored_password = agent_secret if conn_mode == "agent" else password
        stored_key_path = agent_xor_key if conn_mode == "agent" else key_path
        stored_port = int(result.get("port") or (agent_port if conn_mode == "agent" else port))

        # Store in database
        device = self.store.add_device(
            ip_address=ip,
            hostname=result.get("hostname", ip),
            platform=result.get("platform", "unknown"),
            port=stored_port,
            ssh_username=stored_username,
            ssh_password=stored_password,
            ssh_key_path=stored_key_path,
            mac_address=mac,
        )
        report = self.store.get_report_by_ip(ip)

        device.hostname = result.get("hostname", ip)
        device.platform = result.get("platform", "unknown")

        await self._broadcast_ws({
            "type": "device_updated" if existing else "device_added",
            "device": {**device.to_dict(), "report": report},
        })

        return web.json_response({
            "success": True,
            "device": {**device.to_dict(), "report": report},
            "connection": {
                "mode": conn_mode,
                "hostname": result.get("hostname"),
                "platform": result.get("platform"),
                "port": stored_port,
            }
        })

    async def handle_get_devices(self, request: web.Request) -> web.Response:
        """GET /api/devices — list all known devices."""
        devices = self.store.get_all()
        payload = []
        for device in devices:
            item = device.to_dict()
            report = self.store.get_report_by_device_id(device.device_id) or self.store.get_report_by_ip(device.ip_address)
            if report:
                item["report"] = report
            payload.append(item)
        return web.json_response(payload)

    async def handle_register_device(self, request: web.Request) -> web.Response:
        """POST /api/devices/register — store target metadata and auto-enroll if possible."""
        body = await request.json()
        ip = (body.get("ip") or request.remote or "").strip()
        hostname = body.get("hostname", "").strip() or ip
        mac = body.get("mac", "").strip()
        username = body.get("username", "").strip()
        platform_name = body.get("platform", "").strip() or "unknown"
        platform_version = body.get("platform_version", "").strip()
        ssh_enabled = bool(body.get("ssh_enabled", False))
        try:
            ssh_port = int(body.get("ssh_port", 22) or 22)
        except (TypeError, ValueError):
            ssh_port = 22
        try:
            agent_port = int(body.get("agent_port", 9999) or 9999)
        except (TypeError, ValueError):
            agent_port = 9999
        agent_secret = body.get("agent_secret", "")
        agent_xor_key = body.get("agent_xor_key", "")
        requested_mode = body.get("mode", "auto").strip().lower()

        if not ip:
            return web.json_response({"error": "IP address is required"}, status=400)

        report = {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "username": username,
            "platform": platform_name,
            "platform_version": platform_version,
            "ssh_enabled": ssh_enabled,
            "ssh_port": ssh_port,
            "ssh_dir": body.get("ssh_dir", "").strip(),
            "authorized_keys_path": body.get("authorized_keys_path", "").strip(),
            "public_key_paths": body.get("public_key_paths", []),
            "agent_port": agent_port,
            "reported_at": time.time(),
        }

        existing = self.store.get_by_ip(ip)
        self.store.upsert_report(ip, report, device_id=existing.device_id if existing else "")

        result = None
        attempt_errors = []

        if requested_mode in {"agent", "auto"} and body.get("agent_enabled"):
            result = await self._run_ssh(
                self.executor.add_agent_device,
                ip,
                agent_port,
                agent_secret,
                agent_xor_key,
            )
            if not result.get("success"):
                attempt_errors.append(result.get("error", "agent registration failed"))

        if (result is None or not result.get("success")) and requested_mode in {"ssh", "auto"} and ssh_enabled and username:
            result = await self._run_ssh(
                self.executor.add_device,
                ip,
                ssh_port,
                username,
                "",
                "",
                True,
            )
            if not result.get("success"):
                attempt_errors.append(result.get("error", "ssh registration failed"))

        if result and result.get("success"):
            conn_mode = result.get("mode", "ssh")
            stored_username = "__agent__" if conn_mode == "agent" else username
            stored_password = agent_secret if conn_mode == "agent" else ""
            stored_key_path = agent_xor_key if conn_mode == "agent" else ""
            stored_port = int(result.get("port") or (agent_port if conn_mode == "agent" else ssh_port))

            device = self.store.add_device(
                ip_address=ip,
                hostname=result.get("hostname", hostname),
                platform=result.get("platform", platform_name),
                port=stored_port,
                ssh_username=stored_username,
                ssh_password=stored_password,
                ssh_key_path=stored_key_path,
                mac_address=mac,
            )
            self.store.upsert_report(ip, report, device_id=device.device_id)

            payload = device.to_dict()
            payload["report"] = report
            await self._broadcast_ws({
                "type": "device_updated" if existing else "device_added",
                "device": payload,
            })

            return web.json_response({
                "success": True,
                "device": payload,
                "connection": {
                    "mode": conn_mode,
                    "hostname": result.get("hostname", hostname),
                    "platform": result.get("platform", platform_name),
                    "port": stored_port,
                    "status": "connected",
                },
            })

        if not existing:
            device = self.store.add_device(
                ip_address=ip,
                hostname=hostname,
                platform=platform_name,
                port=ssh_port if ssh_enabled else agent_port,
                ssh_username=username,
                ssh_password="",
                ssh_key_path="",
                mac_address=mac,
            )
            self.store.update_status(device.device_id, DeviceStatus.UNKNOWN)
            self.store.upsert_report(ip, report, device_id=device.device_id)
        else:
            device = existing
            if hostname:
                self.store.update_hostname(device.device_id, hostname, platform_name)
            if mac:
                self.store.update_mac(device.device_id, mac)
            device = self.store.get(device.device_id) or device
            self.store.upsert_report(ip, report, device_id=device.device_id)

        payload = device.to_dict()
        payload["report"] = report
        await self._broadcast_ws({
            "type": "device_updated" if existing else "device_added",
            "device": payload,
        })

        return web.json_response({
            "success": True,
            "device": payload,
            "connection": {
                "mode": "pending",
                "status": "pending",
                "port": ssh_port if ssh_enabled else agent_port,
            },
            "message": (
                "Device metadata stored, but automatic connection is still pending. "
                "For SSH mode, the target must trust a public key from this controller "
                "or you must add credentials explicitly."
            ),
            "errors": attempt_errors,
        })

    async def handle_controller_public_key(self, request: web.Request) -> web.Response:
        """GET /api/controller/public-key — return the controller SSH public key."""
        try:
            key_info = await self._run_ssh(self._ensure_controller_public_key)
            return web.json_response({
                "success": True,
                **key_info,
            })
        except FileNotFoundError:
            return web.json_response(
                {"error": "ssh-keygen not found and no controller public key is available."},
                status=500,
            )
        except subprocess.CalledProcessError as exc:
            logger.error(f"Failed to prepare controller SSH key: {exc}")
            return web.json_response(
                {"error": "Failed to prepare controller SSH key."},
                status=500,
            )
        except Exception as exc:
            logger.error(f"Failed to load controller SSH key: {exc}")
            return web.json_response(
                {"error": "Failed to load controller SSH key."},
                status=500,
            )

    async def handle_controller_status(self, request: web.Request) -> web.Response:
        """GET /api/controller/status — return non-mutating controller health info."""
        try:
            key_status = await self._run_ssh(self._get_controller_key_status)
            devices = self.store.get_all()
            online = len([device for device in devices if device.status == DeviceStatus.ONLINE])
            return web.json_response({
                "success": True,
                "websocket_clients": len(self.ws_clients),
                "device_count": len(devices),
                "online_count": online,
                "ssh_key": key_status,
            })
        except Exception as exc:
            logger.error(f"Failed to load controller status: {exc}")
            return web.json_response(
                {"error": "Failed to load controller status."},
                status=500,
            )

    async def handle_send_command(self, request: web.Request) -> web.Response:
        """POST /api/devices/{device_id}/command — execute command via SSH."""
        device_id = request.match_info["device_id"]
        device = self.store.get(device_id)

        if not device:
            return web.json_response({"error": "Device not found"}, status=404)

        body = await request.json()
        command = body.get("command", "").lower()
        params = body.get("params", {})

        if not command:
            return web.json_response({"error": "Command is required"}, status=400)

        # Execute via SSH in thread pool
        result = await self._run_ssh(
            self.executor.execute_command, device.ip_address, command, params
        )

        if result["success"]:
            self.store.update_status(device.device_id, DeviceStatus.ONLINE)
        else:
            # Check if it's a connection issue vs command issue
            connectivity = await self._run_ssh(self.executor.check_connectivity, device.ip_address)
            if not connectivity:
                self.store.update_status(device.device_id, DeviceStatus.OFFLINE)

        await self._broadcast_ws({
            "type": "command_result",
            "device_id": device_id,
            "command": command.upper(),
            "success": result["success"],
            "message": result.get("output", "") or result.get("error", ""),
        })

        return web.json_response(result)

    async def handle_push_key(self, request: web.Request) -> web.Response:
        """POST /api/devices/{device_id}/keyauth — push controller SSH key to device."""
        device_id = request.match_info["device_id"]
        device = self.store.get(device_id)

        if not device:
            return web.json_response({"error": "Device not found"}, status=404)

        # Get or generate controller public key
        try:
            key_info = await self._run_ssh(self._ensure_controller_public_key)
        except Exception as e:
            return web.json_response({"error": f"Cannot prepare controller key: {e}"}, status=500)

        public_key = key_info.get("public_key", "")
        if not public_key:
            return web.json_response({"error": "No controller public key available"}, status=500)

        # Push the key to the remote device via SSH
        conn = self.executor.connections.get(device.ip_address)
        if not conn or not conn.is_connected():
            return web.json_response(
                {"error": f"No active SSH connection to {device.ip_address}. Connect first via 'add' with credentials."},
                status=400,
            )

        # Platform-aware authorized_keys install
        def push_key():
            platform_type = conn.detected_platform
            escaped_key = public_key.replace('"', '\\"')

            if platform_type == TargetPlatform.WINDOWS:
                # Windows OpenSSH uses administrators_authorized_keys or .ssh/authorized_keys
                cmds = [
                    'if not exist "%USERPROFILE%\\.ssh" mkdir "%USERPROFILE%\\.ssh"',
                    f'echo {escaped_key}>> "%USERPROFILE%\\.ssh\\authorized_keys"',
                ]
                # Also try the admin file
                admin_cmd = f'echo {escaped_key}>> "C:\\ProgramData\\ssh\\administrators_authorized_keys"'
                for cmd in cmds:
                    conn.execute(cmd, timeout=10)
                conn.execute(admin_cmd, timeout=10)
            else:
                # Linux/macOS
                cmds = [
                    "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
                    f'grep -qF "{escaped_key}" ~/.ssh/authorized_keys 2>/dev/null || echo "{escaped_key}" >> ~/.ssh/authorized_keys',
                    "chmod 600 ~/.ssh/authorized_keys",
                ]
                for cmd in cmds:
                    conn.execute(cmd, timeout=10)

            return {"success": True}

        try:
            result = await self._run_ssh(push_key)
            logger.info(f"Controller SSH key pushed to {device.ip_address}")
            return web.json_response({
                "success": True,
                "device_id": device_id,
                "host": device.ip_address,
                "message": f"Controller SSH key installed on {device.hostname}. Passwordless login is now enabled.",
                "fingerprint": key_info.get("fingerprint", ""),
            })
        except Exception as e:
            logger.error(f"Failed to push key to {device.ip_address}: {e}")
            return web.json_response({"error": f"Failed to push key: {e}"}, status=500)

    @staticmethod
    def _icmp_ping(ip: str, count: int = 3, timeout: int = 2) -> dict:
        """Raw ICMP ping — works without SSH, no auth needed."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
            cmd = ['ping', param, str(count), timeout_flag, str(timeout), ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 5)
            output = result.stdout + result.stderr

            alive = result.returncode == 0

            # Parse latency from output
            latency = None
            for line in output.splitlines():
                if 'avg' in line or 'Average' in line:
                    parts = line.split('/')
                    if len(parts) >= 5:
                        try:
                            latency = float(parts[4])
                        except ValueError:
                            pass

            return {
                "alive": alive,
                "ip": ip,
                "latency_ms": latency,
                "output": output.strip(),
                "packets_sent": count,
            }
        except subprocess.TimeoutExpired:
            return {"alive": False, "ip": ip, "output": "Ping timed out", "latency_ms": None}
        except Exception as e:
            return {"alive": False, "ip": ip, "output": str(e), "latency_ms": None}

    async def handle_ping_device(self, request: web.Request) -> web.Response:
        """POST /api/devices/{device_id}/ping — ICMP ping + SSH check."""
        device_id = request.match_info["device_id"]
        device = self.store.get(device_id)

        if not device:
            return web.json_response({"error": "Device not found"}, status=404)

        # ICMP ping first (no auth needed)
        icmp = await self._run_ssh(self._icmp_ping, device.ip_address)

        if icmp["alive"]:
            self.store.update_status(device.device_id, DeviceStatus.ONLINE)
        else:
            self.store.update_status(device.device_id, DeviceStatus.OFFLINE)

        # Refresh the device list after status change
        devices = self.store.get_all()
        await self._broadcast_ws({
            "type": "devices_updated",
            "devices": [d.to_dict() for d in devices],
        })

        return web.json_response({
            "online": icmp["alive"],
            "latency_ms": icmp.get("latency_ms"),
            "output": icmp.get("output", ""),
        })

    async def handle_quick_ping(self, request: web.Request) -> web.Response:
        """POST /api/ping — ICMP ping any IP without registering it."""
        body = await request.json()
        ip = body.get("ip", "").strip()
        count = min(int(body.get("count", 3)), 10)

        if not ip:
            return web.json_response({"error": "IP address required"}, status=400)

        result = await self._run_ssh(self._icmp_ping, ip, count)
        return web.json_response(result)

    async def handle_wake(self, request: web.Request) -> web.Response:
        """POST /api/devices/{device_id}/wake — send WoL magic packet."""
        device_id = request.match_info["device_id"]
        device = self.store.get(device_id)

        if not device:
            return web.json_response({"error": "Device not found"}, status=404)
        if not device.mac_address:
            return web.json_response({"error": "No MAC address stored. Set it first."}, status=400)

        success = send_wol(device.mac_address)

        await self._broadcast_ws({
            "type": "wol_sent",
            "device_id": device_id,
            "mac": device.mac_address,
            "success": success,
        })

        return web.json_response({"success": success, "mac": device.mac_address})

    async def handle_delete_device(self, request: web.Request) -> web.Response:
        """DELETE /api/devices/{device_id}."""
        device_id = request.match_info["device_id"]
        device = self.store.get(device_id)

        if device:
            self.executor.remove_device(device.ip_address)

        deleted = self.store.delete(device_id)
        if deleted:
            await self._broadcast_ws({"type": "device_removed", "device_id": device_id})
        return web.json_response({"deleted": deleted})

    async def handle_update_mac(self, request: web.Request) -> web.Response:
        """PUT /api/devices/{device_id}/mac."""
        device_id = request.match_info["device_id"]
        body = await request.json()
        mac = body.get("mac", "")
        if not mac:
            return web.json_response({"error": "MAC address required"}, status=400)
        self.store.update_mac(device_id, mac)
        return web.json_response({"success": True})

    async def handle_discover(self, request: web.Request) -> web.Response:
        """POST /api/devices/discover — scan network for SSH-reachable hosts."""
        from controller.discovery import discover_all
        await self._broadcast_ws({"type": "discovery_started"})

        devices = await discover_all(mdns_timeout=2.0, tcp_port=22, tcp_timeout=2.0)

        for device in devices:
            existing = self.store.get_by_ip(device.ip_address)
            if not existing:
                # Just note that SSH is open, user still needs to add credentials
                device.status = DeviceStatus.UNKNOWN
                self.store.add_device(
                    ip_address=device.ip_address,
                    hostname=device.hostname or device.ip_address,
                    port=22,
                )

        all_devices = self.store.get_all()
        await self._broadcast_ws({
            "type": "discovery_complete",
            "devices": [d.to_dict() for d in all_devices],
            "new_count": len(devices),
        })

        return web.json_response({
            "discovered": len(devices),
            "total": len(all_devices),
            "devices": [d.to_dict() for d in all_devices],
        })

    async def handle_send_invite(self, request: web.Request) -> web.Response:
        """POST /api/invite — send setup instructions via email."""
        body = await request.json()
        to_email = body.get("to", "").strip()
        subject = body.get("subject", "Set up Remote Shutdown on your device").strip()
        personal_msg = body.get("message", "").strip()
        smtp_host = body.get("smtp_host", "smtp.gmail.com").strip()
        smtp_port = int(body.get("smtp_port", 587))
        smtp_user = body.get("smtp_user", "").strip()
        smtp_pass = body.get("smtp_pass", "")

        if not to_email:
            return web.json_response({"error": "Recipient email is required"}, status=400)
        if not smtp_user or not smtp_pass:
            return web.json_response({"error": "SMTP credentials required (expand SMTP Settings)"}, status=400)

        # Build email
        email_msg = MIMEMultipart()
        email_msg["From"] = smtp_user
        email_msg["To"] = to_email
        email_msg["Subject"] = subject

        controller_ip = self._get_local_ip()
        html_body = f"""
        <div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #0a0e17; color: #e0e0e0; padding: 30px; border-radius: 12px;">
                <h1 style="color: #00e5ff; margin: 0 0 10px;">⚡ Remote Shutdown</h1>
                <p style="color: #888; margin: 0 0 20px;">Device Setup Invitation</p>

                {f'<div style="background: #1a1e2e; padding: 16px; border-radius: 8px; margin-bottom: 20px; border-left: 3px solid #00e5ff;"><p style="margin: 0; color: #ccc;">{personal_msg}</p></div>' if personal_msg else ''}

                <h2 style="color: #fff; font-size: 16px;">What is this?</h2>
                <p>Someone wants to be able to remotely manage your device (shutdown, reboot, sleep)
                over your local network. This is a home/lab tool — it only works on your WiFi.</p>

                <h2 style="color: #fff; font-size: 16px;">How to set up</h2>
                <ol style="color: #ccc;">
                    <li>Save the attached <code>setup_device.py</code> file</li>
                    <li>Open a terminal (Command Prompt on Windows)</li>
                    <li>Run: <code style="background: #1a1e2e; padding: 2px 6px; border-radius: 4px;">python3 setup_device.py --controller-url http://{controller_ip}:{self.port} --approve-controller-key</code></li>
                    <li>Follow the prompts — it will ask your permission before making changes</li>
                </ol>

                <div style="background: #1a1e2e; padding: 16px; border-radius: 8px; margin-top: 20px;">
                    <h3 style="color: #ffc107; font-size: 14px; margin: 0 0 8px;">What it does</h3>
                    <ul style="color: #ccc; margin: 0;">
                        <li>Enables SSH (secure remote access) on your device</li>
                        <li>Optionally registers the device with the controller you approve</li>
                        <li>Does <strong>NOT</strong> install spyware or access your files</li>
                    </ul>
                </div>

                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 12px;">
                    Controller: http://{controller_ip}:8080
                </div>
            </div>
        </div>
        """

        email_msg.attach(MIMEText(html_body, "html"))

        # Attach setup_device.py
        if os.path.exists(SETUP_SCRIPT):
            with open(SETUP_SCRIPT, "rb") as f:
                attachment = MIMEApplication(f.read(), Name="setup_device.py")
                attachment["Content-Disposition"] = 'attachment; filename="setup_device.py"'
                email_msg.attach(attachment)

        # Send via SMTP in thread pool
        def send_email():
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, to_email, email_msg.as_string())

        try:
            await self._run_ssh(send_email)
            logger.info(f"Invite email sent to {to_email}")
            return web.json_response({"success": True, "to": to_email})
        except smtplib.SMTPAuthenticationError:
            return web.json_response(
                {"error": "SMTP auth failed. For Gmail, use an App Password (not your regular password)."},
                status=401,
            )
        except Exception as e:
            logger.error(f"Failed to send invite: {e}")
            return web.json_response({"error": f"Failed to send: {str(e)}"}, status=500)

    @staticmethod
    def _get_local_ip():
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "localhost"

    async def handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """WebSocket /ws — real-time updates."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.ws_clients.add(ws)
        logger.info(f"WebSocket client connected ({len(self.ws_clients)} total)")

        devices = self.store.get_all()
        await ws.send_json({
            "type": "init",
            "devices": [d.to_dict() for d in devices],
        })

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    logger.debug(f"WS: {data}")
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WS error: {ws.exception()}")
        finally:
            self.ws_clients.discard(ws)
        return ws

    # --------------------------------------------------------------------- #
    #  App Setup
    # --------------------------------------------------------------------- #

    def create_app(self) -> web.Application:
        app = web.Application()

        # API routes
        app.router.add_post("/api/devices/add", self.handle_add_device)
        app.router.add_post("/api/devices/register", self.handle_register_device)
        app.router.add_post("/api/agents/register", self.handle_register_device)
        app.router.add_get("/api/controller/status", self.handle_controller_status)
        app.router.add_get("/api/controller/public-key", self.handle_controller_public_key)
        app.router.add_post("/api/devices/discover", self.handle_discover)
        app.router.add_post("/api/ping", self.handle_quick_ping)
        app.router.add_post("/api/invite", self.handle_send_invite)
        app.router.add_get("/api/devices", self.handle_get_devices)
        app.router.add_post("/api/devices/{device_id}/command", self.handle_send_command)
        app.router.add_post("/api/devices/{device_id}/keyauth", self.handle_push_key)
        app.router.add_post("/api/devices/{device_id}/wake", self.handle_wake)
        app.router.add_post("/api/devices/{device_id}/ping", self.handle_ping_device)
        app.router.add_put("/api/devices/{device_id}/mac", self.handle_update_mac)
        app.router.add_delete("/api/devices/{device_id}", self.handle_delete_device)

        # WebSocket
        app.router.add_get("/ws", self.handle_websocket)

        # Dashboard
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/{filename}", self.handle_static)

        return app

    def run(self) -> None:
        """Start the controller."""
        # Reconnect to stored devices
        self._reconnect_devices()

        app = self.create_app()

        print("=" * 60)
        print(f"  ⚡ Remote Shutdown Controller (Agentless)")
        print(f"  🌐 Dashboard: http://localhost:{self.port}")
        print(f"  📡 API: http://localhost:{self.port}/api/devices")
        print(f"  🔌 WebSocket: ws://localhost:{self.port}/ws")
        print(f"  📊 Known devices: {self.store.count()}")
        print(f"  🔑 Mode: SSH (no agent required)")
        print("=" * 60)

        web.run_app(app, host="0.0.0.0", port=self.port, print=None)


def main():
    parser = argparse.ArgumentParser(description="Remote Shutdown Controller (Agentless)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    server = ControllerServer(port=args.port)
    server.run()


if __name__ == "__main__":
    main()
