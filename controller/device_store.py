"""
Persistent device store backed by SQLite.

Stores device information, connection details, and target-reported metadata
so devices can be managed across restarts without re-enrollment.
"""

import os
import json
import time
import sqlite3
import logging
from typing import List, Optional, Dict
from contextlib import contextmanager

from common.models import Device, DeviceStatus

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.expanduser("~/.remote-shutdown/devices.db")


class DeviceStore:
    """SQLite-backed device registry with connection and report storage."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT UNIQUE,
                    mac_address TEXT,
                    platform TEXT,
                    platform_version TEXT,
                    agent_version TEXT,
                    status INTEGER DEFAULT 0,
                    last_seen REAL,
                    port INTEGER DEFAULT 22,
                    ssh_username TEXT DEFAULT '',
                    ssh_password TEXT DEFAULT '',
                    ssh_key_path TEXT DEFAULT '',
                    authorized INTEGER DEFAULT 0,
                    consent TEXT DEFAULT '{}',
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_reports (
                    ip_address TEXT PRIMARY KEY,
                    device_id TEXT DEFAULT '',
                    report_json TEXT DEFAULT '{}',
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_reports_device_id ON device_reports(device_id)
            """)

    @contextmanager
    def _conn(self):
        """Context manager for database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add_device(
        self,
        ip_address: str,
        hostname: str = "",
        platform: str = "",
        port: int = 22,
        ssh_username: str = "",
        ssh_password: str = "",
        ssh_key_path: str = "",
        mac_address: str = "",
    ) -> Device:
        """Add or update a device by IP. Returns the Device object."""
        import uuid
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT device_id FROM devices WHERE ip_address = ?",
                (ip_address,),
            ).fetchone()
            device = Device(
                device_id=existing["device_id"] if existing else str(uuid.uuid4()),
                hostname=hostname or ip_address,
                ip_address=ip_address,
                mac_address=mac_address,
                platform=platform,
                port=port,
                status=DeviceStatus.ONLINE,
                last_seen=time.time(),
            )
            conn.execute("""
                INSERT OR REPLACE INTO devices
                    (device_id, hostname, ip_address, mac_address, platform,
                     port, ssh_username, ssh_password, ssh_key_path,
                     status, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id, device.hostname, device.ip_address,
                device.mac_address, device.platform,
                port, ssh_username, ssh_password, ssh_key_path,
                device.status, device.last_seen, time.time(),
            ))
            conn.execute(
                """
                UPDATE device_reports
                SET device_id = ?, updated_at = ?
                WHERE ip_address = ?
                """,
                (device.device_id, time.time(), ip_address),
            )

        logger.info(f"Added device: {hostname} @ {ip_address}")
        return device

    def get(self, device_id: str) -> Optional[Device]:
        """Get a device by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            return self._row_to_device(row) if row else None

    def get_by_ip(self, ip: str) -> Optional[Device]:
        """Get a device by IP address."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE ip_address = ?", (ip,)
            ).fetchone()
            return self._row_to_device(row) if row else None

    def get_credentials(self, device_id: str) -> Optional[Dict]:
        """Get connection details for a device."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT ip_address, port, ssh_username, ssh_password, ssh_key_path FROM devices WHERE device_id = ?",
                (device_id,)
            ).fetchone()
            if row:
                return {
                    "host": row["ip_address"],
                    "port": row["port"],
                    "username": row["ssh_username"],
                    "password": row["ssh_password"],
                    "key_path": row["ssh_key_path"],
                }
            return None

    def upsert_report(self, ip_address: str, report: Dict, device_id: str = "") -> None:
        """Store or update target-reported metadata for a device IP."""
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO device_reports (ip_address, device_id, report_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    device_id = CASE
                        WHEN excluded.device_id != '' THEN excluded.device_id
                        ELSE device_reports.device_id
                    END,
                    report_json = excluded.report_json,
                    updated_at = excluded.updated_at
                """,
                (ip_address, device_id, json.dumps(report), now, now),
            )

    def get_report_by_ip(self, ip_address: str) -> Optional[Dict]:
        """Return the latest target-reported metadata for an IP."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT report_json FROM device_reports WHERE ip_address = ?",
                (ip_address,),
            ).fetchone()
            if not row or not row["report_json"]:
                return None
            return json.loads(row["report_json"])

    def get_report_by_device_id(self, device_id: str) -> Optional[Dict]:
        """Return the latest target-reported metadata linked to a device."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT report_json FROM device_reports WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if not row or not row["report_json"]:
                return None
            return json.loads(row["report_json"])

    def get_all(self) -> List[Device]:
        """Get all known devices."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC"
            ).fetchall()
            return [self._row_to_device(row) for row in rows]

    def delete(self, device_id: str) -> bool:
        """Remove a device from the store."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM device_reports WHERE device_id = ?",
                (device_id,),
            )
            cursor = conn.execute(
                "DELETE FROM devices WHERE device_id = ?", (device_id,)
            )
            return cursor.rowcount > 0

    def update_status(self, device_id: str, status: int) -> None:
        """Update a device's status and last_seen."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE devices SET status = ?, last_seen = ?, updated_at = ? WHERE device_id = ?",
                (status, time.time(), time.time(), device_id),
            )

    def update_mac(self, device_id: str, mac: str) -> None:
        """Store/update a device's MAC address for WoL."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE devices SET mac_address = ?, updated_at = ? WHERE device_id = ?",
                (mac, time.time(), device_id),
            )

    def update_hostname(self, device_id: str, hostname: str, platform: str = "") -> None:
        """Update hostname and platform after detection."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE devices SET hostname = ?, platform = ?, updated_at = ? WHERE device_id = ?",
                (hostname, platform, time.time(), device_id),
            )

    def count(self) -> int:
        """Get total device count."""
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    @staticmethod
    def _row_to_device(row: sqlite3.Row) -> Device:
        """Convert a database row to a Device object."""
        return Device(
            device_id=row["device_id"],
            hostname=row["hostname"] or "",
            ip_address=row["ip_address"] or "",
            mac_address=row["mac_address"] or "",
            platform=row["platform"] or "",
            platform_version=row["platform_version"] if "platform_version" in row.keys() else "",
            agent_version=row["agent_version"] if "agent_version" in row.keys() else "",
            status=row["status"],
            last_seen=row["last_seen"] or 0,
            port=row["port"] or 22,
            authorized=bool(row["authorized"]) if "authorized" in row.keys() else False,
            consent=json.loads(row["consent"]) if "consent" in row.keys() and row["consent"] else {},
        )
