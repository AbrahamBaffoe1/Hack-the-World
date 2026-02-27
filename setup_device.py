#!/usr/bin/env python3
"""
Remote Shutdown — Device Setup Script

Run this on any device you want to control remotely.
It will:
  1. Clearly explain what it does
  2. Ask for your permission
  3. Enable SSH so the controller can reach this device
  4. Show you the IP address to enter in the controller

Works on: macOS, Linux, Windows

Usage:
  python3 setup_device.py
  python3 setup_device.py --controller-url http://192.168.1.10:8080
  python3 setup_device.py --controller-url http://192.168.1.10:8080 --approve-controller-key --approve-registration --no-pause
"""

import ctypes
import argparse
import getpass
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

# ─────────────────────────────────────────────────────────────
#  Colors for terminal output
# ─────────────────────────────────────────────────────────────

class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

def banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════╗
║         ⚡  Remote Shutdown — Device Setup           ║
╚══════════════════════════════════════════════════════╝{Colors.RESET}
""")

def info(msg):
    print(f"  {Colors.CYAN}ℹ{Colors.RESET}  {msg}")

def success(msg):
    print(f"  {Colors.GREEN}✅{Colors.RESET} {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}⚠️{Colors.RESET}  {msg}")

def error(msg):
    print(f"  {Colors.RED}❌{Colors.RESET} {msg}")

def step(n, msg):
    print(f"\n  {Colors.BOLD}[{n}]{Colors.RESET} {msg}")

def pause():
    """Wait for user before exiting so they can read output."""
    print()
    try:
        input(f"  {Colors.DIM}Press Enter to exit...{Colors.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enable remote management on this device with explicit user consent."
    )
    parser.add_argument(
        "--controller-url",
        default="",
        help="Controller base URL, for example http://192.168.1.10:8080",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "ssh", "agent"),
        default="ssh",
        help="Preferred registration mode when reporting to a controller.",
    )
    parser.add_argument(
        "--agent-port",
        type=int,
        default=9999,
        help="Agent/listener port to report when using agent mode.",
    )
    parser.add_argument(
        "--agent-secret",
        default="",
        help="Optional shared secret for agent mode registration.",
    )
    parser.add_argument(
        "--agent-xor-key",
        default="",
        help="Optional XOR key for agent mode registration.",
    )
    parser.add_argument(
        "--approve-controller-key",
        action="store_true",
        help="Approve installing the controller SSH public key without an extra prompt.",
    )
    parser.add_argument(
        "--approve-registration",
        action="store_true",
        help="Approve sending device metadata to the controller without an extra prompt.",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Exit immediately without waiting for Enter at the end.",
    )
    return parser.parse_args()


def is_admin():
    """Check if we're running with admin/root privileges."""
    os_type = get_os()
    if os_type == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def auto_elevate_windows():
    """Re-launch this script as Administrator on Windows via UAC prompt."""
    if is_admin():
        return  # Already admin
    info("Requesting Administrator privileges...")
    info("Click YES on the UAC popup to continue.\n")
    try:
        # ShellExecuteW with 'runas' triggers the UAC dialog
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
    except Exception as e:
        error(f"Could not elevate: {e}")
        error("Right-click the script and choose 'Run as administrator'.")
        pause()
    sys.exit(0)  # Exit the non-admin instance


# ─────────────────────────────────────────────────────────────
#  System detection
# ─────────────────────────────────────────────────────────────

def get_os():
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    return "unknown"

def get_local_ip():
    """Get the device's local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "couldn't detect"

def get_mac_address():
    """Get the primary MAC address."""
    import uuid
    mac = uuid.getnode()
    return ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2)).upper()


def get_ssh_metadata():
    """Return non-sensitive SSH metadata for safe registration."""
    ssh_dir = os.path.expanduser("~/.ssh")
    public_key_paths = []
    if os.path.isdir(ssh_dir):
        for name in sorted(os.listdir(ssh_dir)):
            if name.endswith(".pub"):
                public_key_paths.append(os.path.join(ssh_dir, name))
    return {
        "ssh_dir": ssh_dir if os.path.isdir(ssh_dir) else "",
        "authorized_keys_path": os.path.join(ssh_dir, "authorized_keys") if os.path.isdir(ssh_dir) else "",
        "public_key_paths": public_key_paths,
        "ssh_port": 22,
    }


def normalize_controller_url(url):
    return url.rstrip("/")


def maybe_pause(args):
    if not args.no_pause:
        pause()


def register_with_controller(controller_url, payload):
    """POST local device metadata to the controller."""
    url = normalize_controller_url(controller_url) + "/api/devices/register"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def fetch_controller_public_key(controller_url):
    """Fetch the controller SSH public key."""
    url = normalize_controller_url(controller_url) + "/api/controller/public-key"
    with urllib.request.urlopen(url, timeout=10) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def install_authorized_key(public_key):
    """Append the controller public key to authorized_keys if needed."""
    ssh_dir = os.path.expanduser("~/.ssh")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")
    os.makedirs(ssh_dir, exist_ok=True)
    try:
        os.chmod(ssh_dir, 0o700)
    except OSError:
        pass

    existing = ""
    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path, "r", encoding="utf-8") as handle:
            existing = handle.read()

    if public_key.strip() in existing:
        return {"path": authorized_keys_path, "changed": False}

    with open(authorized_keys_path, "a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(public_key.strip() + "\n")

    try:
        os.chmod(authorized_keys_path, 0o600)
    except OSError:
        pass

    return {"path": authorized_keys_path, "changed": True}


def maybe_authorize_controller_key(args):
    """Optionally install the controller public key for passwordless SSH."""
    if not args.controller_url or args.mode not in ("ssh", "auto"):
        return False

    step("K", "Authorize Controller SSH Key")
    try:
        key_info = fetch_controller_public_key(args.controller_url)
    except urllib.error.HTTPError as e:
        error(f"Controller key request failed ({e.code}).")
        return False
    except Exception as e:
        error(f"Could not fetch controller public key: {e}")
        return False

    public_key = key_info.get("public_key", "").strip()
    if not public_key:
        error("Controller did not return a usable SSH public key.")
        return False

    print(f"""
      This can authorize the controller for passwordless SSH access to this account.

        Controller URL: {Colors.CYAN}{normalize_controller_url(args.controller_url)}{Colors.RESET}
        Key fingerprint: {Colors.CYAN}{key_info.get('fingerprint', 'unknown')}{Colors.RESET}
        Target file: {Colors.CYAN}{os.path.expanduser('~/.ssh/authorized_keys')}{Colors.RESET}

      {Colors.DIM}This adds a public key only. It does not copy passwords or private keys.{Colors.RESET}
    """)

    approved = args.approve_controller_key
    if not approved:
        try:
            consent = input(
                f"  {Colors.BOLD}Install this controller public key now? (yes/no): {Colors.RESET}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {Colors.DIM}Skipped controller key authorization.{Colors.RESET}")
            return False
        approved = consent in ("yes", "y")

    if not approved:
        print(f"\n  {Colors.DIM}Skipped controller key authorization.{Colors.RESET}")
        return False

    try:
        result = install_authorized_key(public_key)
        if result["changed"]:
            success(f"Controller SSH key installed in {result['path']}")
        else:
            info(f"Controller SSH key already present in {result['path']}")
        return True
    except Exception as e:
        error(f"Failed to install controller SSH key: {e}")
        return False


def maybe_register(args, hostname, local_ip, mac_addr, username, ssh_enabled, ssh_meta, os_type):
    """Optionally register this device with a controller after explicit consent."""
    if not args.controller_url:
        return

    step("R", "Register With Controller")
    print(f"""
      This will send the following device metadata to:
        {Colors.CYAN}{normalize_controller_url(args.controller_url)}{Colors.RESET}

        • Hostname, IP address, MAC address
        • Local username and OS details
        • SSH status and non-sensitive SSH paths

      {Colors.DIM}It does not send private keys, files, or passwords.{Colors.RESET}
    """)

    approved = args.approve_registration
    if not approved:
        try:
            consent = input(
                f"  {Colors.BOLD}Send this device info to the controller now? (yes/no): {Colors.RESET}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {Colors.DIM}Skipped controller registration.{Colors.RESET}")
            return
        approved = consent in ("yes", "y")

    if not approved:
        print(f"\n  {Colors.DIM}Skipped controller registration.{Colors.RESET}")
        return

    payload = {
        "mode": args.mode,
        "hostname": hostname,
        "ip": local_ip,
        "mac": mac_addr,
        "username": username,
        "platform": os_type,
        "platform_version": platform.release(),
        "ssh_enabled": ssh_enabled,
        "ssh_port": ssh_meta.get("ssh_port", 22),
        "ssh_dir": ssh_meta.get("ssh_dir", ""),
        "authorized_keys_path": ssh_meta.get("authorized_keys_path", ""),
        "public_key_paths": ssh_meta.get("public_key_paths", []),
        "agent_enabled": args.mode in ("agent", "auto"),
        "agent_port": args.agent_port,
        "agent_secret": args.agent_secret,
        "agent_xor_key": args.agent_xor_key,
        "controller_key_requested": args.mode in ("ssh", "auto"),
    }

    info("Sending metadata to controller...")
    try:
        response = register_with_controller(args.controller_url, payload)
        connection = response.get("connection", {})
        status = connection.get("status", "pending")
        if response.get("success"):
            success(f"Controller registration complete ({status}).")
            if connection.get("mode"):
                info(
                    f"Controller mode: {connection.get('mode')} on port {connection.get('port', 'n/a')}"
                )
            if response.get("message"):
                warn(response["message"])
        else:
            error(response.get("error", "Controller registration failed."))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace").strip()
        error(f"Controller rejected registration ({e.code}).")
        if body:
            warn(body)
    except Exception as e:
        error(f"Could not reach controller: {e}")

def is_ssh_running():
    """Check if SSH server is already running."""
    os_type = get_os()
    try:
        if os_type == "macos":
            # Check if SSH port 22 is listening (doesn't need sudo)
            result = subprocess.run(
                ["lsof", "-i", ":22", "-sTCP:LISTEN"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and "ssh" in result.stdout.lower():
                return True
            # Fallback: try launchctl (no sudo needed)
            result = subprocess.run(
                ["launchctl", "list", "com.openssh.sshd"],
                capture_output=True, text=True
            )
            return result.returncode == 0
        elif os_type == "linux":
            result = subprocess.run(
                ["systemctl", "is-active", "sshd"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                result = subprocess.run(
                    ["systemctl", "is-active", "ssh"],
                    capture_output=True, text=True
                )
            return result.returncode == 0
        elif os_type == "windows":
            result = subprocess.run(
                ["sc", "query", "sshd"],
                capture_output=True, text=True
            )
            return "RUNNING" in result.stdout
    except Exception:
        return False
    return False


# ─────────────────────────────────────────────────────────────
#  SSH Enable (per platform)
#  NOTE: We do NOT use capture_output for sudo commands
#  so the password prompt is visible to the user.
# ─────────────────────────────────────────────────────────────

def enable_ssh_macos():
    """Enable Remote Login (SSH) on macOS."""
    info("Enabling Remote Login via systemsetup...")
    info("You may be asked for your Mac password below.\n")
    try:
        # Use sys.stdout so the sudo password prompt shows
        result = subprocess.run(
            ["sudo", "systemsetup", "-setremotelogin", "on"],
            stdin=sys.stdin
        )
        if result.returncode == 0:
            success("SSH enabled on macOS!")
            return True
        else:
            # Fallback: launchctl
            info("Trying launchctl fallback...")
            result = subprocess.run(
                ["sudo", "launchctl", "load", "-w",
                 "/System/Library/LaunchDaemons/ssh.plist"],
                stdin=sys.stdin
            )
            if result.returncode == 0:
                success("SSH enabled via launchctl!")
                return True
            else:
                error("Both methods failed.")
                return False
    except Exception as e:
        error(f"Failed to enable SSH: {e}")
        return False


def enable_ssh_linux():
    """Install and enable OpenSSH Server on Linux."""
    # Detect package manager
    pkg_mgr = None
    if os.path.exists("/usr/bin/apt"):
        pkg_mgr = "apt"
    elif os.path.exists("/usr/bin/dnf"):
        pkg_mgr = "dnf"
    elif os.path.exists("/usr/bin/yum"):
        pkg_mgr = "yum"
    elif os.path.exists("/usr/bin/pacman"):
        pkg_mgr = "pacman"

    info("You may be asked for your password below.\n")

    try:
        if pkg_mgr == "apt":
            info("Installing OpenSSH Server (apt)...")
            subprocess.run(
                ["sudo", "apt", "install", "-y", "openssh-server"],
                stdin=sys.stdin, check=True
            )
        elif pkg_mgr == "dnf":
            info("Installing OpenSSH Server (dnf)...")
            subprocess.run(
                ["sudo", "dnf", "install", "-y", "openssh-server"],
                stdin=sys.stdin, check=True
            )
        elif pkg_mgr == "yum":
            info("Installing OpenSSH Server (yum)...")
            subprocess.run(
                ["sudo", "yum", "install", "-y", "openssh-server"],
                stdin=sys.stdin, check=True
            )
        elif pkg_mgr == "pacman":
            info("Installing OpenSSH Server (pacman)...")
            subprocess.run(
                ["sudo", "pacman", "-S", "--noconfirm", "openssh"],
                stdin=sys.stdin, check=True
            )
        else:
            warn("Could not detect package manager. Trying systemctl directly...")

        # Enable and start
        info("Starting SSH service...")
        subprocess.run(["sudo", "systemctl", "enable", "sshd"], stdin=sys.stdin, capture_output=True)
        subprocess.run(["sudo", "systemctl", "start", "sshd"], stdin=sys.stdin, capture_output=True)
        subprocess.run(["sudo", "systemctl", "enable", "ssh"], stdin=sys.stdin, capture_output=True)
        subprocess.run(["sudo", "systemctl", "start", "ssh"], stdin=sys.stdin, capture_output=True)

        success("SSH enabled on Linux!")
        return True
    except Exception as e:
        error(f"Failed to enable SSH: {e}")
        return False


def enable_ssh_windows():
    """Install and enable OpenSSH Server on Windows."""
    info("Installing OpenSSH Server on Windows...")
    info("This may take a minute...\n")
    try:
        # Install OpenSSH Server capability
        info("Step 1/4: Installing OpenSSH Server feature...")
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command",
             "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            output = (result.stdout + result.stderr).lower()
            if "already" not in output and "installed" not in output:
                error(f"Install failed: {result.stderr.strip()}")
                warn("Output: " + result.stdout.strip())
                return False
            else:
                info("OpenSSH Server is already installed.")
        else:
            success("OpenSSH Server installed!")

        # Start service
        info("Step 2/4: Starting SSH service...")
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command",
             "Start-Service sshd"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            success("SSH service started!")
        else:
            warn(f"Start service: {result.stderr.strip()}")

        # Set auto-start
        info("Step 3/4: Setting SSH to start automatically...")
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command",
             "Set-Service -Name sshd -StartupType 'Automatic'"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            success("SSH set to auto-start!")
        else:
            warn(f"Auto-start: {result.stderr.strip()}")

        # Firewall rule
        info("Step 4/4: Configuring firewall...")
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command",
             "$r = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue; "
             "if (-not $r) { New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' "
             "-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 }"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            success("Firewall configured!")
        else:
            warn(f"Firewall: {result.stderr.strip()}")

        success("SSH setup complete on Windows!")
        return True
    except subprocess.TimeoutExpired:
        error("A command timed out. Try running as Administrator.")
        return False
    except Exception as e:
        error(f"Failed to enable SSH: {e}")
        return False


# ─────────────────────────────────────────────────────────────
#  Main Flow
# ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    banner()

    os_type = get_os()

    # On Windows, auto-elevate to admin if not already
    if os_type == "windows" and not is_admin():
        warn("This script needs Administrator privileges on Windows.")
        auto_elevate_windows()
    local_ip = get_local_ip()
    mac_addr = get_mac_address()
    hostname = socket.gethostname()
    username = getpass.getuser()
    ssh_meta = get_ssh_metadata()

    # ── Step 1: Show device info ──
    step(1, "Device Information")
    print(f"""
      Hostname:   {Colors.BOLD}{hostname}{Colors.RESET}
      OS:         {Colors.BOLD}{platform.system()} {platform.release()}{Colors.RESET}
      IP Address: {Colors.BOLD}{local_ip}{Colors.RESET}
      MAC:        {Colors.BOLD}{mac_addr}{Colors.RESET}
      Username:   {Colors.BOLD}{username}{Colors.RESET}
    """)

    # ── Step 2: Explain what this does ──
    step(2, "What This Script Does")
    print(f"""
      This script enables {Colors.BOLD}SSH (Secure Shell){Colors.RESET} on this device
      so it can be controlled remotely from the controller PC.

      {Colors.CYAN}What this allows:{Colors.RESET}
        • Shutdown, reboot, or sleep this device remotely
        • Check if this device is online
        • Wake this device up (with Wake-on-LAN)
        • Optionally trust a controller SSH public key for passwordless access

      {Colors.YELLOW}What this does NOT do:{Colors.RESET}
        • Does NOT install spyware or monitoring software
        • Does NOT access your files or personal data
        • Does not send any data anywhere unless you explicitly provide a controller URL
        • Only works on your local network

      {Colors.DIM}SSH uses encrypted connections. Automatic SSH access only
      works if this device already trusts a public key from the controller
      or if you later add credentials explicitly.{Colors.RESET}
    """)

    if args.controller_url:
        info(f"Controller registration URL: {normalize_controller_url(args.controller_url)}")

    # ── Step 3: Check if SSH is already running ──
    if is_ssh_running():
        success("SSH is already running on this device!")
        maybe_authorize_controller_key(args)
        print(f"""
    {Colors.GREEN}You're all set!{Colors.RESET} Give the controller this info:

      {Colors.BOLD}IP Address:{Colors.RESET}  {Colors.CYAN}{local_ip}{Colors.RESET}
      {Colors.BOLD}MAC Address:{Colors.RESET} {Colors.CYAN}{mac_addr}{Colors.RESET}
      {Colors.BOLD}Username:{Colors.RESET}    {Colors.CYAN}{username}{Colors.RESET}
        """)
        maybe_register(
            args,
            hostname=hostname,
            local_ip=local_ip,
            mac_addr=mac_addr,
            username=username,
            ssh_enabled=True,
            ssh_meta=ssh_meta,
            os_type=os_type,
        )
        maybe_pause(args)
        return

    # ── Step 4: Ask for permission ──
    step(3, "Permission Required")
    print(f"""
      {Colors.YELLOW}To enable remote control, SSH needs to be turned on.{Colors.RESET}
      This requires administrator/sudo permission.
    """)

    try:
        consent = input(f"  {Colors.BOLD}Do you want to enable SSH on this device? (yes/no): {Colors.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {Colors.DIM}Cancelled.{Colors.RESET}")
        maybe_pause(args)
        return

    if consent not in ("yes", "y"):
        print(f"\n  {Colors.DIM}Cancelled. No changes were made.{Colors.RESET}")
        maybe_pause(args)
        return

    # ── Step 5: Enable SSH ──
    step(4, "Enabling SSH...")

    ok = False
    if os_type == "macos":
        ok = enable_ssh_macos()
    elif os_type == "linux":
        ok = enable_ssh_linux()
    elif os_type == "windows":
        ok = enable_ssh_windows()
    else:
        error(f"Unsupported OS: {platform.system()}")
        maybe_pause(args)
        return

    if not ok:
        error("Failed to enable SSH. You may need to do it manually.")
        if os_type == "macos":
            print(f"""
      {Colors.YELLOW}Manual steps for macOS:{Colors.RESET}
        1. Open System Settings → General → Sharing
        2. Turn on "Remote Login"
        3. Or run: {Colors.DIM}sudo systemsetup -setremotelogin on{Colors.RESET}
            """)
        elif os_type == "windows":
            print(f"""
      {Colors.YELLOW}Manual steps for Windows:{Colors.RESET}
        1. Open Settings → Apps → Optional Features
        2. Click "Add a feature"
        3. Search "OpenSSH Server" → Install
        4. Open Services → Start "OpenSSH SSH Server"
            """)
        elif os_type == "linux":
            print(f"""
      {Colors.YELLOW}Manual steps for Linux:{Colors.RESET}
        1. sudo apt install openssh-server   (Debian/Ubuntu)
        2. sudo systemctl enable --now ssh
            """)
        maybe_pause(args)
        return

    # ── Step 6: Verify ──
    step(5, "Verifying...")
    time.sleep(2)

    if is_ssh_running():
        success("SSH is running!")
    else:
        warn("SSH may still be starting up. Give it a moment.")

    maybe_authorize_controller_key(args)

    maybe_register(
        args,
        hostname=hostname,
        local_ip=local_ip,
        mac_addr=mac_addr,
        username=username,
        ssh_enabled=is_ssh_running(),
        ssh_meta=ssh_meta,
        os_type=os_type,
    )

    # ── Step 7: Show connection info ──
    print(f"""
    {Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════╗
    ║            ✅  Setup Complete!                ║
    ╚══════════════════════════════════════════════╝{Colors.RESET}

      Give the controller this info:

      {Colors.BOLD}IP Address:{Colors.RESET}  {Colors.CYAN}{local_ip}{Colors.RESET}
      {Colors.BOLD}MAC Address:{Colors.RESET} {Colors.CYAN}{mac_addr}{Colors.RESET}
      {Colors.BOLD}Username:{Colors.RESET}    {Colors.CYAN}{username}{Colors.RESET}

      On the controller, run:
        {Colors.DIM}add {local_ip} {username}{Colors.RESET}

      Or enter the IP in the dashboard at:
        {Colors.DIM}http://<controller-ip>:8080{Colors.RESET}
    """)

    maybe_pause(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {Colors.DIM}Interrupted.{Colors.RESET}\n")
    except Exception as e:
        print(f"\n  {Colors.RED}❌ Unexpected error: {e}{Colors.RESET}\n")
        input("  Press Enter to exit...")
