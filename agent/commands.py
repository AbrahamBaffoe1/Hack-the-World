"""
Cross-platform command handlers for the Remote Shutdown agent.

Each handler detects the platform and runs the appropriate system command.
"""

import os
import sys
import platform
import subprocess
import logging
import time
from typing import Dict, Any, Optional

from common.models import CommandType

logger = logging.getLogger(__name__)


def _get_platform() -> str:
    """Detect the current platform."""
    return platform.system().lower()


def _run(cmd: list, shell: bool = False) -> subprocess.CompletedProcess:
    """Execute a system command safely."""
    logger.info(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(
        cmd,
        shell=shell,
        capture_output=True,
        text=True,
        timeout=30,
    )


# --------------------------------------------------------------------------- #
#  Command Handlers
# --------------------------------------------------------------------------- #

def handle_ping(**params) -> Dict[str, Any]:
    """Respond to a ping."""
    return {
        "status": "pong",
        "hostname": platform.node(),
        "platform": _get_platform(),
        "timestamp": time.time(),
    }


def handle_status(**params) -> Dict[str, Any]:
    """Return system status information."""
    try:
        import psutil
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        battery = psutil.sensors_battery()

        return {
            "hostname": platform.node(),
            "platform": _get_platform(),
            "platform_version": platform.version(),
            "uptime_seconds": int(uptime),
            "cpu_percent": cpu_percent,
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "memory_used_percent": memory.percent,
            "battery_percent": battery.percent if battery else None,
            "battery_charging": battery.power_plugged if battery else None,
        }
    except ImportError:
        return {
            "hostname": platform.node(),
            "platform": _get_platform(),
            "platform_version": platform.version(),
            "note": "Install psutil for detailed status",
        }


def handle_shutdown(delay: int = 0, **params) -> Dict[str, Any]:
    """Shutdown the machine."""
    plat = _get_platform()

    if plat == "linux":
        cmd = ["shutdown", "-h", f"+{delay // 60}" if delay else "now"]
    elif plat == "darwin":
        if delay:
            cmd = ["sudo", "shutdown", "-h", f"+{delay // 60}"]
        else:
            cmd = ["sudo", "shutdown", "-h", "now"]
    elif plat == "windows":
        cmd = ["shutdown", "/s", f"/t", str(delay)]
    else:
        return {"error": f"Unsupported platform: {plat}"}

    try:
        result = _run(cmd)
        return {"status": "shutdown_initiated", "delay": delay, "output": result.stdout or result.stderr}
    except Exception as e:
        return {"error": str(e)}


def handle_reboot(delay: int = 0, **params) -> Dict[str, Any]:
    """Reboot the machine."""
    plat = _get_platform()

    if plat == "linux":
        cmd = ["shutdown", "-r", f"+{delay // 60}" if delay else "now"]
    elif plat == "darwin":
        if delay:
            cmd = ["sudo", "shutdown", "-r", f"+{delay // 60}"]
        else:
            cmd = ["sudo", "shutdown", "-r", "now"]
    elif plat == "windows":
        cmd = ["shutdown", "/r", f"/t", str(delay)]
    else:
        return {"error": f"Unsupported platform: {plat}"}

    try:
        result = _run(cmd)
        return {"status": "reboot_initiated", "delay": delay, "output": result.stdout or result.stderr}
    except Exception as e:
        return {"error": str(e)}


def handle_sleep(**params) -> Dict[str, Any]:
    """Put the machine to sleep."""
    plat = _get_platform()

    if plat == "darwin":
        cmd = ["pmset", "sleepnow"]
    elif plat == "linux":
        cmd = ["systemctl", "suspend"]
    elif plat == "windows":
        cmd = ["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"]
    else:
        return {"error": f"Unsupported platform: {plat}"}

    try:
        result = _run(cmd)
        return {"status": "sleep_initiated", "output": result.stdout or result.stderr}
    except Exception as e:
        return {"error": str(e)}


def handle_hibernate(**params) -> Dict[str, Any]:
    """Hibernate the machine."""
    plat = _get_platform()

    if plat == "darwin":
        cmd = ["pmset", "sleepnow"]  # macOS doesn't truly hibernate easily
        note = "macOS uses deep sleep instead of true hibernate"
    elif plat == "linux":
        cmd = ["systemctl", "hibernate"]
        note = None
    elif plat == "windows":
        cmd = ["shutdown", "/h"]
        note = None
    else:
        return {"error": f"Unsupported platform: {plat}"}

    try:
        result = _run(cmd)
        resp = {"status": "hibernate_initiated", "output": result.stdout or result.stderr}
        if note:
            resp["note"] = note
        return resp
    except Exception as e:
        return {"error": str(e)}


def handle_lock_screen(**params) -> Dict[str, Any]:
    """Lock the screen."""
    plat = _get_platform()

    if plat == "darwin":
        cmd = [
            "osascript", "-e",
            'tell application "System Events" to keystroke "q" using {command down, control down}'
        ]
    elif plat == "linux":
        # Try multiple lock commands
        for lock_cmd in [
            ["loginctl", "lock-session"],
            ["xdg-screensaver", "lock"],
            ["gnome-screensaver-command", "-l"],
        ]:
            try:
                result = _run(lock_cmd)
                if result.returncode == 0:
                    return {"status": "screen_locked"}
            except Exception:
                continue
        return {"error": "No supported screen lock method found"}
    elif plat == "windows":
        cmd = ["rundll32.exe", "user32.dll,LockWorkStation"]
    else:
        return {"error": f"Unsupported platform: {plat}"}

    try:
        result = _run(cmd)
        return {"status": "screen_locked", "output": result.stdout or result.stderr}
    except Exception as e:
        return {"error": str(e)}


# --------------------------------------------------------------------------- #
#  TODO: Restricted commands (not implemented for safety)
# --------------------------------------------------------------------------- #

# TODO: WIPE_STORAGE (0x07)
#   - Would require explicit multi-step user consent
#   - Requires elevated privileges
#   - Implementation: shred/dd on Linux, diskutil on macOS, cipher on Windows
#   - NOT IMPLEMENTED: Potential for irreversible data loss

# TODO: LOCKOUT (0x08)
#   - Disable local keyboard/mouse input
#   - Requires kernel-level access
#   - Implementation: evdev grab on Linux, IOKit on macOS, BlockInput on Windows
#   - NOT IMPLEMENTED: Could lock users out of their own machines

# TODO: EXFILTRATE (0x09)
#   - Credential/data extraction
#   - NOT IMPLEMENTED: Privacy violation, potential for misuse

# TODO: SELF_DESTRUCT (0xFF)
#   - Remove agent and all traces
#   - Would require cleanup of persistence mechanisms
#   - NOT IMPLEMENTED: Anti-forensics concern


# --------------------------------------------------------------------------- #
#  Command Dispatcher
# --------------------------------------------------------------------------- #

COMMAND_HANDLERS = {
    CommandType.PING: handle_ping,
    CommandType.STATUS: handle_status,
    CommandType.SHUTDOWN: handle_shutdown,
    CommandType.SHUTDOWN_DELAYED: handle_shutdown,
    CommandType.REBOOT: handle_reboot,
    CommandType.SLEEP: handle_sleep,
    CommandType.HIBERNATE: handle_hibernate,
    CommandType.LOCK_SCREEN: handle_lock_screen,
}


def dispatch_command(command_type: int, params: dict = None) -> Dict[str, Any]:
    """
    Dispatch a command to the appropriate handler.

    Args:
        command_type: CommandType enum value
        params: Optional dict of parameters for the handler

    Returns:
        Dict with execution result
    """
    handler = COMMAND_HANDLERS.get(command_type)
    if handler is None:
        return {"error": f"Unknown or unsupported command: 0x{command_type:02X}"}

    params = params or {}
    try:
        return handler(**params)
    except Exception as e:
        logger.exception(f"Command handler failed: {e}")
        return {"error": f"Handler exception: {str(e)}"}
