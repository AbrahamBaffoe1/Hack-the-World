"""
Remote Shutdown Agent — Main entry point.

Starts an encrypted TCP listener that:
  1. Generates or loads ECDSA key pair
  2. Accepts connections from authorized controllers
  3. Decrypts and verifies incoming commands
  4. Checks consent gate before executing
  5. Returns encrypted responses
  6. Announces itself via mDNS
  7. Optionally installs persistence
"""

import asyncio
import argparse
import logging
import os
import sys
import signal
import ssl
import json
import struct
import time
from typing import Optional

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import (
    generate_key_pair,
    generate_aes_key,
    save_key_pair,
    load_key_pair,
    encrypt,
    decrypt,
    public_key_to_pem,
)
from common.protocol import (
    encode_frame,
    decode_frame,
    send_frame,
    recv_frame,
    ProtocolError,
)
from common.models import Command, Response, CommandType
from agent.config import AgentConfig
from agent.consent import ConsentGate, ConsentDenied
from agent.commands import dispatch_command
from agent.discovery import AgentAnnouncer

logger = logging.getLogger("agent")


class ShutdownAgent:
    """Main agent server class."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.consent_gate = ConsentGate(config)
        self.announcer: Optional[AgentAnnouncer] = None
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False

        # Crypto material
        self.private_key = None
        self.public_key = None
        self.shared_key = None  # Symmetric key for AES (exchanged during handshake)

    def _init_keys(self) -> None:
        """Generate or load ECDSA key pair."""
        keys_dir = self.config.keys_dir
        try:
            self.private_key, self.public_key = load_key_pair(keys_dir, prefix="agent")
            logger.info("Loaded existing key pair")
        except (FileNotFoundError, Exception):
            logger.info("Generating new key pair...")
            self.private_key, self.public_key = generate_key_pair()
            save_key_pair(self.private_key, keys_dir, prefix="agent")
            logger.info(f"Key pair saved to {keys_dir}")

        # Generate a shared symmetric key (in production, this would be negotiated per-session)
        shared_key_path = os.path.join(keys_dir, "shared.key")
        if os.path.exists(shared_key_path):
            with open(shared_key_path, "rb") as f:
                self.shared_key = f.read()
        else:
            self.shared_key = generate_aes_key()
            os.makedirs(keys_dir, exist_ok=True)
            with open(shared_key_path, "wb") as f:
                f.write(self.shared_key)
            os.chmod(shared_key_path, 0o600)
            logger.info("Generated new shared symmetric key")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single client connection."""
        peer = writer.get_extra_info("peername")
        logger.info(f"Connection from {peer}")

        try:
            while True:
                try:
                    # Receive frame
                    raw_frame = await asyncio.wait_for(recv_frame(reader), timeout=60.0)

                    # Decode and decrypt
                    payload = decode_frame(raw_frame, self.shared_key)

                    # Parse command
                    command = Command.from_bytes(payload)
                    logger.info(f"Received command: {command.type_name} from {peer}")

                    # Check consent
                    try:
                        self.consent_gate.require(command.command_type)
                    except ConsentDenied as e:
                        response = Response(
                            command_id=command.command_id,
                            success=False,
                            message=str(e),
                        )
                        await self._send_response(writer, response)
                        continue

                    # Execute command
                    result = dispatch_command(command.command_type, command.params)

                    # Build response
                    success = "error" not in result
                    response = Response(
                        command_id=command.command_id,
                        success=success,
                        message=result.get("error", "OK"),
                        device_info=result if success else None,
                    )

                    await self._send_response(writer, response)

                except asyncio.TimeoutError:
                    logger.debug(f"Connection from {peer} idle timeout")
                    break
                except asyncio.IncompleteReadError:
                    logger.info(f"Client {peer} disconnected")
                    break
                except ProtocolError as e:
                    logger.warning(f"Protocol error from {peer}: {e}")
                    break

        except Exception as e:
            logger.exception(f"Error handling client {peer}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"Connection from {peer} closed")

    async def _send_response(self, writer: asyncio.StreamWriter, response: Response) -> None:
        """Encrypt and send a response frame."""
        payload = response.to_bytes()
        frame = encode_frame(payload, self.shared_key, self.private_key)
        await send_frame(writer, frame)

    async def start(self) -> None:
        """Start the agent server."""
        self._init_keys()

        # Start TCP server
        self.server = await asyncio.start_server(
            self.handle_client,
            host="0.0.0.0",
            port=self.config.port,
        )
        self.running = True

        addrs = ", ".join(str(s.getsockname()) for s in self.server.sockets)
        logger.info(f"Agent listening on {addrs}")

        # Start mDNS announcer
        try:
            self.announcer = AgentAnnouncer(
                port=self.config.port,
                device_id=self.config.device_id,
                agent_version=self.config.agent_version,
            )
            self.announcer.start()
        except Exception as e:
            logger.warning(f"mDNS announcer failed to start: {e}")

        # Print connection info
        print("=" * 60)
        print(f"  ⚡ Remote Shutdown Agent v{self.config.agent_version}")
        print(f"  📍 Listening on port {self.config.port}")
        print(f"  🔑 Device ID: {self.config.device_id[:8]}...")
        print(f"  💻 Platform: {self.config.platform_name}")
        print(f"  📡 mDNS: {'active' if self.announcer else 'disabled'}")
        print("=" * 60)

        # Serve forever
        async with self.server:
            await self.server.serve_forever()

    async def stop(self) -> None:
        """Gracefully stop the agent."""
        logger.info("Shutting down agent...")
        self.running = False

        if self.announcer:
            self.announcer.stop()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("Agent stopped")


def main():
    parser = argparse.ArgumentParser(description="Remote Shutdown Agent")
    parser.add_argument("--port", type=int, default=9876, help="Port to listen on")
    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--generate-keys", action="store_true", help="Force regenerate keys")
    parser.add_argument("--install", action="store_true", help="Install persistence (auto-start on boot)")
    parser.add_argument("--uninstall", action="store_true", help="Remove persistence")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    # Logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Load config
    config = AgentConfig.load(args.config)
    config.port = args.port

    # Handle persistence commands
    if args.install:
        from agent.persistence import install
        success = install(config.port)
        print(f"Persistence {'installed' if success else 'FAILED'}")
        sys.exit(0 if success else 1)

    if args.uninstall:
        from agent.persistence import uninstall
        success = uninstall()
        print(f"Persistence {'removed' if success else 'FAILED'}")
        sys.exit(0 if success else 1)

    # Force key regeneration
    if args.generate_keys:
        import shutil
        keys_dir = config.keys_dir
        if os.path.exists(keys_dir):
            shutil.rmtree(keys_dir)
        logger.info("Existing keys removed — will generate fresh keys on start")

    # Start agent
    agent = ShutdownAgent(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Handle signals for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(agent.stop()))

    try:
        loop.run_until_complete(agent.start())
    except KeyboardInterrupt:
        loop.run_until_complete(agent.stop())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
