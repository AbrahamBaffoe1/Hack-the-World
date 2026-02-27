# ⚡ Remote Shutdown System

A cross-platform remote device control system for personal home use. Remotely
shutdown, reboot, sleep, or wake your own devices from a slick web dashboard.

## Features

- **Remote Commands** — Shutdown, reboot, sleep, hibernate, lock screen
- **IP-only Agent Mode** — Add a target by IP (agent/listener protocol)
- **SSH Mode** — Optional credential-based control path
- **Self-Registration** — Target can report IP, MAC, username, and SSH status back to the controller
- **Wake-on-LAN** — Wake sleeping/off devices via magic packets
- **Device Discovery** — Auto-find agents via mDNS + TCP port scanning
- **Encrypted Communication** — AES-256-GCM + ECDSA P-256 signatures
- **Consent System** — Devices opt-in to which commands they allow
- **Cross-Platform** — Linux, macOS, Windows agents
- **Persistence** — Auto-start on boot (systemd / LaunchDaemon / Task Scheduler)
- **Web Dashboard** — Dark terminal-themed control panel with real-time updates
- **Terminal CLI** — Built-in command terminal in the dashboard

## Quick Start

### 1. Install Dependencies

```bash
cd remote-shutdown
pip install -r requirements.txt
```

### 2. Start the Agent (on device to control)

```bash
python -m agent.main --port 9876

# Install persistence (auto-start on boot):
python -m agent.main --install

# Remove persistence:
python -m agent.main --uninstall
```

### 3. Start the Controller (on your control machine)

```bash
python -m controller.server --port 8080
```

### 4. Open the Dashboard

Navigate to `http://localhost:8080` in your browser.

## Safe Enrollment Flow

You cannot safely or legally install control software without user consent.
Use explicit onboarding links instead:

1. User receives trusted install instructions.
2. User runs the installer script themselves (admin/root prompt visible).
3. Agent/listener starts with approved configuration.
4. Controller can add target by IP (`add <ip>` in terminal).

No hidden email payloads, no exploit-based installation.

## Device Self-Registration

If the target user runs the setup script with a controller URL, the script can
send approved device metadata back to the controller and attempt enrollment:

```bash
python3 setup_device.py --controller-url http://<controller-ip>:8080
```

If the user wants a low-interaction run, they can explicitly pre-approve the
controller key install and registration:

```bash
python3 setup_device.py --controller-url http://<controller-ip>:8080 --approve-controller-key --approve-registration --no-pause
```

That is still explicit user approval. The setup flow does not hide changes.

What gets reported:

- Hostname, IP address, MAC address
- Local username and platform/version
- SSH enabled state and non-sensitive SSH paths

What can also happen with approval:

- The target appends the controller SSH public key to `~/.ssh/authorized_keys`
- The controller can then complete SSH registration without password entry

What does not get reported:

- Passwords
- Private SSH keys
- File contents

If the controller already has a matching SSH private key for that user, it can
connect automatically. Otherwise the device is stored in a pending state until
you explicitly finish SSH or use agent mode.

## Architecture

```
┌──────────────┐   Encrypted TCP/9876   ┌──────────────┐
│  Controller   │ ◄────────────────────► │    Agent      │
│  (server.py)  │   AES-256-GCM + ECDSA │  (main.py)    │
│               │                        │               │
│  REST API     │                        │  Commands     │
│  WebSocket    │                        │  Consent Gate │
│  WoL          │                        │  mDNS         │
│  Discovery    │                        │  Persistence  │
└──────┬───────┘                        └───────────────┘
       │ HTTP/8080
       ▼
┌──────────────┐
│  Dashboard    │
│  (HTML/JS)    │
│               │
│  Device Grid  │
│  Terminal     │
│  Logs         │
└──────────────┘
```

## Shared Key Setup

The agent and controller must share the same AES symmetric key for
communication. On first run, both generate a key at:

```
~/.remote-shutdown/keys/shared.key
```

To pair them, copy the `shared.key` from one machine to the other, e.g.:

```bash
scp ~/.remote-shutdown/keys/shared.key user@controller:~/.remote-shutdown/keys/
```

## Configuration

Agent config is stored at `~/.remote-shutdown/agent_config.json`:

```json
{
  "device_id": "auto-generated-uuid",
  "hostname": "my-machine",
  "port": 9876,
  "consent": {
    "PING": true,
    "STATUS": true,
    "SHUTDOWN": true,
    "REBOOT": true,
    "SLEEP": true,
    "HIBERNATE": true,
    "LOCK_SCREEN": true
  },
  "auto_start": true
}
```

Set any command to `false` in the `consent` object to block it.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/devices` | List all known devices |
| GET | `/api/controller/public-key` | Return or generate the controller SSH public key |
| POST | `/api/devices/register` | Target self-registration endpoint |
| POST | `/api/devices/discover` | Trigger network discovery |
| POST | `/api/devices/{id}/command` | Send command to device |
| POST | `/api/devices/{id}/wake` | Send WoL magic packet |
| POST | `/api/devices/{id}/ping` | Ping device |
| PUT | `/api/devices/{id}/mac` | Set MAC for WoL |
| DELETE | `/api/devices/{id}` | Remove device |
| WS | `/ws` | Real-time status updates |

## Terminal Quick Usage

From the dashboard terminal:

```text
add <ip>
add <ip> agent [port] [secret]
add <ip> <username> [password]
shutdown <id|ip>
reboot <id|ip>
```

## License

Personal use only. This is a home lab tool.
