"""Repository for device entity lifecycle, presence tracking, and scan persistence.

Incorporates hysteresis debouncing to prevent flapping and tracks historical
presence transitions.
"""

from datetime import datetime, timezone
from typing import Any

from home_network_analysis.core.contracts import (
    NetworkScanSnapshot,
    ReachabilityState,
)
from home_network_analysis.storage.db import DatabaseManager

HYSTERESIS_MISS_THRESHOLD = 3


class NetworkRepository:
    """Data access layer managing device entities, services, and audit logs."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize repository with a DatabaseManager instance.

        Args:
            db_manager: Configured database manager.
        """
        self.db = db_manager

    async def record_snapshot(self, snapshot: NetworkScanSnapshot) -> list[dict[str, Any]]:
        """Atomically persist a discovery snapshot and update device presence.

        Applies hysteresis logic: devices not observed in the current sweep increment
        their miss counter and only transition to OFFLINE after reaching the threshold.

        Args:
            snapshot: Validated discovery snapshot.

        Returns:
            A list of transition events generated during this sweep.
        """
        now_str = snapshot.timestamp_utc.isoformat()
        events_generated: list[dict[str, Any]] = []

        async with self.db.connect() as conn:
            async with conn.cursor() as cursor:
                # 1. Record the scan execution metadata
                await cursor.execute(
                    """
                    INSERT INTO scan_history (scan_id, timestamp_utc, collector_source, network_scope, devices_found)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(snapshot.scan_id),
                        now_str,
                        snapshot.collector_source.value,
                        snapshot.network_scope,
                        len(snapshot.endpoints),
                    ),
                )

                observed_ids: set[str] = set()

                # 2. Process each observed endpoint
                for ep in snapshot.endpoints:
                    observed_ids.add(ep.fingerprint_id)

                    # Check for existing device
                    await cursor.execute(
                        "SELECT ip_address, reachability, hostname, vendor FROM devices WHERE fingerprint_id = ?",
                        (ep.fingerprint_id,),
                    )
                    row = await cursor.fetchone()

                    if row is None:
                        # Novel device discovery
                        await cursor.execute(
                            """
                            INSERT INTO devices (
                                fingerprint_id, ip_address, mac_address, is_randomized_mac,
                                hostname, vendor, reachability, latency_ms, consecutive_misses,
                                first_seen_utc, last_seen_utc
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                            """,
                            (
                                ep.fingerprint_id,
                                str(ep.observed_ip),
                                ep.observed_mac,
                                1 if ep.is_randomized_mac else 0,
                                ep.hostname,
                                ep.vendor,
                                ReachabilityState.ONLINE.value,
                                ep.latency_ms,
                                now_str,
                                now_str,
                            ),
                        )
                        event = {
                            "fingerprint_id": ep.fingerprint_id,
                            "event_type": "JOINED",
                            "details": f"New device detected at {ep.observed_ip} ({ep.hostname or 'unknown'})",
                            "timestamp_utc": now_str,
                        }
                        events_generated.append(event)
                        await cursor.execute(
                            "INSERT INTO presence_logs (fingerprint_id, event_type, details, timestamp_utc) VALUES (?, ?, ?, ?)",
                            (ep.fingerprint_id, event["event_type"], event["details"], now_str),
                        )
                    else:
                        existing_ip, existing_reachability, existing_host, existing_vendor = (
                            row["ip_address"],
                            row["reachability"],
                            row["hostname"],
                            row["vendor"],
                        )
                        # Check for IP change
                        if existing_ip != str(ep.observed_ip):
                            ip_event = {
                                "fingerprint_id": ep.fingerprint_id,
                                "event_type": "IP_CHANGED",
                                "details": f"IP shifted from {existing_ip} to {ep.observed_ip}",
                                "timestamp_utc": now_str,
                            }
                            events_generated.append(ip_event)
                            await cursor.execute(
                                "INSERT INTO presence_logs (fingerprint_id, event_type, details, timestamp_utc) VALUES (?, ?, ?, ?)",
                                (
                                    ep.fingerprint_id,
                                    ip_event["event_type"],
                                    ip_event["details"],
                                    now_str,
                                ),
                            )

                        # Check for reconnection from OFFLINE
                        if existing_reachability != ReachabilityState.ONLINE.value:
                            reconnect_event = {
                                "fingerprint_id": ep.fingerprint_id,
                                "event_type": "RECONNECTED",
                                "details": f"Device returned online at {ep.observed_ip}",
                                "timestamp_utc": now_str,
                            }
                            events_generated.append(reconnect_event)
                            await cursor.execute(
                                "INSERT INTO presence_logs (fingerprint_id, event_type, details, timestamp_utc) VALUES (?, ?, ?, ?)",
                                (
                                    ep.fingerprint_id,
                                    reconnect_event["event_type"],
                                    reconnect_event["details"],
                                    now_str,
                                ),
                            )

                        # Keep freshest hostname/vendor if newly resolved
                        merged_host = ep.hostname or existing_host
                        merged_vendor = ep.vendor or existing_vendor

                        await cursor.execute(
                            """
                            UPDATE devices
                            SET ip_address = ?,
                                hostname = ?,
                                vendor = ?,
                                reachability = 'ONLINE',
                                latency_ms = COALESCE(?, latency_ms),
                                consecutive_misses = 0,
                                last_seen_utc = ?
                            WHERE fingerprint_id = ?
                            """,
                            (
                                str(ep.observed_ip),
                                merged_host,
                                merged_vendor,
                                ep.latency_ms,
                                now_str,
                                ep.fingerprint_id,
                            ),
                        )

                    # Save any detected services
                    if ep.services:
                        for s in ep.services:
                            await cursor.execute(
                                """
                                INSERT INTO device_services (
                                    fingerprint_id, port, protocol, service_name, service_version, state, last_checked_utc
                                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(fingerprint_id, port, protocol) DO UPDATE SET
                                    service_name = excluded.service_name,
                                    service_version = excluded.service_version,
                                    state = excluded.state,
                                    last_checked_utc = excluded.last_checked_utc
                                """,
                                (
                                    ep.fingerprint_id,
                                    s.port,
                                    s.protocol.value,
                                    s.service_name,
                                    s.service_version,
                                    s.state.value,
                                    now_str,
                                ),
                            )

                # 3. Apply hysteresis to unobserved devices that were previously ONLINE
                await cursor.execute(
                    "SELECT fingerprint_id, ip_address, hostname, consecutive_misses FROM devices WHERE reachability = 'ONLINE'"
                )
                active_rows = await cursor.fetchall()
                for active_row in active_rows:
                    fid = active_row["fingerprint_id"]
                    if fid not in observed_ids:
                        new_misses = active_row["consecutive_misses"] + 1
                        if new_misses >= HYSTERESIS_MISS_THRESHOLD:
                            # State transition to OFFLINE
                            await cursor.execute(
                                "UPDATE devices SET reachability = 'OFFLINE', consecutive_misses = ? WHERE fingerprint_id = ?",
                                (new_misses, fid),
                            )
                            leave_event = {
                                "fingerprint_id": fid,
                                "event_type": "LEFT",
                                "details": f"Device {active_row['hostname'] or active_row['ip_address']} transitioned offline after {new_misses} misses",
                                "timestamp_utc": now_str,
                            }
                            events_generated.append(leave_event)
                            await cursor.execute(
                                "INSERT INTO presence_logs (fingerprint_id, event_type, details, timestamp_utc) VALUES (?, ?, ?, ?)",
                                (fid, leave_event["event_type"], leave_event["details"], now_str),
                            )
                        else:
                            await cursor.execute(
                                "UPDATE devices SET consecutive_misses = ? WHERE fingerprint_id = ?",
                                (new_misses, fid),
                            )

            await conn.commit()

        return events_generated

    async def get_all_devices(self) -> list[dict[str, Any]]:
        """Retrieve all registered devices with their currently open services.

        Returns:
            List of device records with associated service dictionaries.
        """
        async with self.db.connect() as conn:
            cursor = await conn.execute(
                """
                SELECT fingerprint_id, ip_address, mac_address, is_randomized_mac,
                       custom_name, hostname, vendor, reachability, latency_ms, consecutive_misses,
                       last_port_scan_utc, first_seen_utc, last_seen_utc
                FROM devices
                ORDER BY
                    CASE reachability WHEN 'ONLINE' THEN 1 ELSE 2 END,
                    last_seen_utc DESC
                """
            )
            device_rows = await cursor.fetchall()

            devices: list[dict[str, Any]] = []
            for row in device_rows:
                dev = dict(row)
                # Fetch services
                s_cursor = await conn.execute(
                    "SELECT port, protocol, service_name, service_version, state FROM device_services WHERE fingerprint_id = ? ORDER BY port",
                    (dev["fingerprint_id"],),
                )
                services = [dict(s) for s in await s_cursor.fetchall()]
                dev["services"] = services
                devices.append(dev)

            return devices

    async def get_presence_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve the most recent presence transition audit logs.

        Args:
            limit: Maximum records to return.

        Returns:
            List of presence log entries.
        """
        async with self.db.connect() as conn:
            cursor = await conn.execute(
                """
                SELECT p.id, p.fingerprint_id, p.event_type, p.details, p.timestamp_utc,
                       d.hostname, d.ip_address
                FROM presence_logs p
                LEFT JOIN devices d ON p.fingerprint_id = d.fingerprint_id
                ORDER BY p.id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def update_device_name(self, fingerprint_id: str, custom_name: str | None) -> bool:
        """Assign or clear a user-defined friendly alias for a device.

        Args:
            fingerprint_id: Unique device fingerprint identifier.
            custom_name: Friendly alias string, or None/empty to revert to hostname.

        Returns:
            True if device was found and updated, False otherwise.
        """
        cleaned_name = custom_name.strip() if custom_name else None
        now_str = datetime.now(timezone.utc).isoformat()
        async with self.db.connect() as conn:
            cursor = await conn.execute(
                "UPDATE devices SET custom_name = ? WHERE fingerprint_id = ?",
                (cleaned_name, fingerprint_id),
            )
            if cursor.rowcount == 0:
                return False

            label = cleaned_name or "default network hostname"
            await conn.execute(
                "INSERT INTO presence_logs (fingerprint_id, event_type, details, timestamp_utc) VALUES (?, ?, ?, ?)",
                (fingerprint_id, "RENAMED", f"Endpoint alias set to '{label}'", now_str),
            )
            await conn.commit()
            return True
