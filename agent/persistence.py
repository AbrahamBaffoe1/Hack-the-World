"""
Cross-platform persistence for the Remote Shutdown agent.

Installs the agent as a system service that starts on boot:
  - macOS:   LaunchDaemon plist
  - Linux:   systemd unit file
  - Windows: Task Scheduler

All persistence is transparent and can be fully uninstalled.
"""

import os
import sys
import platform
import subprocess
import logging
import json
from typing import Optional

logger = logging.getLogger(__name__)

AGENT_NAME = "com.remoteshutdown.agent"
AGENT_DESCRIPTION = "Remote Shutdown Agent — Home device control service"


def _get_python_path() -> str:
    """Get the absolute path to the current Python interpreter."""
    return sys.executable


def _get_agent_module_path() -> str:
    """Get the path to the agent module."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
#  macOS — LaunchDaemon
# --------------------------------------------------------------------------- #

def _macos_plist_path() -> str:
    return os.path.expanduser(f"~/Library/LaunchAgents/{AGENT_NAME}.plist")


def _macos_plist_content(port: int) -> str:
    python_path = _get_python_path()
    agent_dir = _get_agent_module_path()

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AGENT_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>-m</string>
        <string>agent.main</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{agent_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/{AGENT_NAME}.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{AGENT_NAME}.stderr.log</string>
</dict>
</plist>"""


def install_macos(port: int = 9876) -> bool:
    """Install LaunchAgent on macOS."""
    plist_path = _macos_plist_path()
    os.makedirs(os.path.dirname(plist_path), exist_ok=True)

    with open(plist_path, "w") as f:
        f.write(_macos_plist_content(port))

    result = subprocess.run(
        ["launchctl", "load", "-w", plist_path],
        capture_output=True, text=True,
    )

    if result.returncode == 0:
        logger.info(f"macOS LaunchAgent installed: {plist_path}")
        return True
    else:
        logger.error(f"Failed to install LaunchAgent: {result.stderr}")
        return False


def uninstall_macos() -> bool:
    """Remove LaunchAgent on macOS."""
    plist_path = _macos_plist_path()
    subprocess.run(["launchctl", "unload", "-w", plist_path], capture_output=True)

    if os.path.exists(plist_path):
        os.remove(plist_path)
        logger.info("macOS LaunchAgent removed")
    return True


# --------------------------------------------------------------------------- #
#  Linux — systemd
# --------------------------------------------------------------------------- #

def _linux_service_path() -> str:
    return os.path.expanduser(f"~/.config/systemd/user/{AGENT_NAME}.service")


def _linux_service_content(port: int) -> str:
    python_path = _get_python_path()
    agent_dir = _get_agent_module_path()

    return f"""[Unit]
Description={AGENT_DESCRIPTION}
After=network.target

[Service]
Type=simple
ExecStart={python_path} -m agent.main --port {port}
WorkingDirectory={agent_dir}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""


def install_linux(port: int = 9876) -> bool:
    """Install systemd user service on Linux."""
    service_path = _linux_service_path()
    os.makedirs(os.path.dirname(service_path), exist_ok=True)

    with open(service_path, "w") as f:
        f.write(_linux_service_content(port))

    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    result = subprocess.run(
        ["systemctl", "--user", "enable", "--now", AGENT_NAME],
        capture_output=True, text=True,
    )

    if result.returncode == 0:
        logger.info(f"Linux systemd service installed: {service_path}")
        return True
    else:
        logger.error(f"Failed to install systemd service: {result.stderr}")
        return False


def uninstall_linux() -> bool:
    """Remove systemd user service on Linux."""
    subprocess.run(
        ["systemctl", "--user", "disable", "--now", AGENT_NAME],
        capture_output=True,
    )
    service_path = _linux_service_path()
    if os.path.exists(service_path):
        os.remove(service_path)
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    logger.info("Linux systemd service removed")
    return True


# --------------------------------------------------------------------------- #
#  Windows — Task Scheduler
# --------------------------------------------------------------------------- #

def install_windows(port: int = 9876) -> bool:
    """Create a Windows Scheduled Task for the agent."""
    python_path = _get_python_path()
    agent_dir = _get_agent_module_path()

    cmd = [
        "schtasks", "/Create",
        "/TN", AGENT_NAME,
        "/TR", f'"{python_path}" -m agent.main --port {port}',
        "/SC", "ONLOGON",
        "/RL", "HIGHEST",
        "/F",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        logger.info("Windows Scheduled Task installed")
        return True
    else:
        logger.error(f"Failed to install Scheduled Task: {result.stderr}")
        return False


def uninstall_windows() -> bool:
    """Remove the Windows Scheduled Task."""
    result = subprocess.run(
        ["schtasks", "/Delete", "/TN", AGENT_NAME, "/F"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        logger.info("Windows Scheduled Task removed")
    return True


# --------------------------------------------------------------------------- #
#  Cross-Platform Interface
# --------------------------------------------------------------------------- #

def install(port: int = 9876) -> bool:
    """Install persistence for the current platform."""
    plat = platform.system().lower()
    if plat == "darwin":
        return install_macos(port)
    elif plat == "linux":
        return install_linux(port)
    elif plat == "windows":
        return install_windows(port)
    else:
        logger.error(f"Unsupported platform for persistence: {plat}")
        return False


def uninstall() -> bool:
    """Remove persistence for the current platform."""
    plat = platform.system().lower()
    if plat == "darwin":
        return uninstall_macos()
    elif plat == "linux":
        return uninstall_linux()
    elif plat == "windows":
        return uninstall_windows()
    else:
        logger.error(f"Unsupported platform for persistence removal: {plat}")
        return False


def is_installed() -> bool:
    """Check if persistence is currently installed."""
    plat = platform.system().lower()
    if plat == "darwin":
        return os.path.exists(_macos_plist_path())
    elif plat == "linux":
        return os.path.exists(_linux_service_path())
    elif plat == "windows":
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", AGENT_NAME],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    return False
