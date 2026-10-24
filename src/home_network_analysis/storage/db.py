"""SQLite database manager and schema initialization.

Implements Write-Ahead Logging (WAL) mode, connection pooling pragmas,
and idempotent DDL migrations.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    fingerprint_id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    is_randomized_mac INTEGER NOT NULL DEFAULT 0,
    hostname TEXT,
    vendor TEXT,
    reachability TEXT NOT NULL DEFAULT 'ONLINE',
    latency_ms REAL,
    consecutive_misses INTEGER NOT NULL DEFAULT 0,
    last_port_scan_utc TEXT,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_reachability ON devices(reachability);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);

CREATE TABLE IF NOT EXISTS device_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT,
    service_version TEXT,
    state TEXT NOT NULL,
    last_checked_utc TEXT NOT NULL,
    FOREIGN KEY(fingerprint_id) REFERENCES devices(fingerprint_id) ON DELETE CASCADE,
    UNIQUE(fingerprint_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id TEXT PRIMARY KEY,
    timestamp_utc TEXT NOT NULL,
    collector_source TEXT NOT NULL,
    network_scope TEXT NOT NULL,
    devices_found INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS presence_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT,
    timestamp_utc TEXT NOT NULL,
    FOREIGN KEY(fingerprint_id) REFERENCES devices(fingerprint_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_presence_timestamp ON presence_logs(timestamp_utc DESC);
"""


class DatabaseManager:
    """Manages asynchronous SQLite connections and transactional integrity."""

    def __init__(self, db_path: Path | str = "data/network.db") -> None:
        """Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)

    async def initialize(self) -> None:
        """Create database directory, enable WAL mode, and execute migrations."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with self.connect() as db:
            await db.execute("PRAGMA journal_mode = WAL;")
            await db.execute("PRAGMA synchronous = NORMAL;")
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.executescript(SCHEMA_SQL)
            # Ensure last_port_scan_utc exists on pre-existing databases
            cursor = await db.execute("PRAGMA table_info(devices);")
            cols = [row["name"] for row in await cursor.fetchall()]
            if "last_port_scan_utc" not in cols:
                await db.execute("ALTER TABLE devices ADD COLUMN last_port_scan_utc TEXT;")
            await db.commit()

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[aiosqlite.Connection]:
        """Provide an asynchronous connection context with standard pragmas.

        Yields:
            Configured aiosqlite Connection object.
        """
        conn = await aiosqlite.connect(str(self.db_path))
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA busy_timeout = 5000;")
        await conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            await conn.close()
