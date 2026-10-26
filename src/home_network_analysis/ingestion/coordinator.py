"""Tiered scan coordinator orchestrating fast sweeps and event-driven deep scans.

Maintains background polling intervals, manages lazy port scans for novel devices,
and dispatches real-time presence events to registered listeners.
"""

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from home_network_analysis.core.contracts import NetworkScanSnapshot
from home_network_analysis.ingestion.scanner import NmapScanner, detect_local_subnet
from home_network_analysis.storage.repository import NetworkRepository

logger = logging.getLogger(__name__)

EventCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class ScanCoordinator:
    """Orchestrates periodic sweeps, lazy service scans, and event propagation."""

    def __init__(
        self,
        scanner: NmapScanner,
        repository: NetworkRepository,
        sweep_interval_seconds: int = 60,
    ) -> None:
        """Initialize the coordinator.

        Args:
            scanner: Configured NmapScanner instance.
            repository: Configured NetworkRepository.
            sweep_interval_seconds: Polling frequency for fast ARP/ICMP sweeps.
        """
        self.scanner = scanner
        self.repository = repository
        self.sweep_interval = sweep_interval_seconds
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._event_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a subscriber queue for real-time SSE presence events.

        Returns:
            An asyncio.Queue yielding event dicts.
        """
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._event_subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        """Remove a subscriber queue when client disconnects.

        Args:
            q: Subscriber queue to remove.
        """
        self._event_subscribers.discard(q)

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Dispatch an event to all active subscriber queues."""
        for q in list(self._event_subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Discard slow consumer without blocking others
                pass

    async def execute_manual_sweep(self, target_subnet: str | None = None) -> NetworkScanSnapshot:
        """Trigger an immediate discovery sweep on demand.

        Args:
            target_subnet: Explicit subnet or None for local subnet.

        Returns:
            The resulting NetworkScanSnapshot.
        """
        snapshot = await self.scanner.run_discovery_sweep(target_subnet)
        events = await self.repository.record_snapshot(snapshot)
        for ev in events:
            await self.broadcast(ev)
            # If novel device, queue lazy port scan
            if ev.get("event_type") == "JOINED":
                fid = ev["fingerprint_id"]
                # Look up IP
                for ep in snapshot.endpoints:
                    if ep.fingerprint_id == fid:
                        asyncio.create_task(self._lazy_port_scan(fid, str(ep.observed_ip)))
                        break
        return snapshot

    async def _lazy_port_scan(self, fingerprint_id: str, ip_str: str) -> None:
        """Execute non-blocking background port scan for a novel device."""
        try:
            logger.info("Executing lazy port scan for new device %s at %s", fingerprint_id, ip_str)
            services = await self.scanner.run_targeted_port_scan(ip_str, top_ports=30)
            async with self.repository.db.connect() as conn:
                await conn.execute(
                    "UPDATE devices SET last_port_scan_utc = datetime('now') WHERE fingerprint_id = ?",
                    (fingerprint_id,),
                )
                for s in services:
                    await conn.execute(
                        """
                        INSERT INTO device_services (
                            fingerprint_id, port, protocol, service_name, service_version, state, last_checked_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(fingerprint_id, port, protocol) DO UPDATE SET
                            service_name = excluded.service_name,
                            service_version = excluded.service_version,
                            state = excluded.state,
                            last_checked_utc = excluded.last_checked_utc
                        """,
                        (
                            fingerprint_id,
                            s.port,
                            s.protocol.value,
                            s.service_name,
                            s.service_version,
                            s.state.value,
                        ),
                    )
                await conn.commit()
            await self.broadcast(
                {
                    "fingerprint_id": fingerprint_id,
                    "event_type": "SERVICES_UPDATED",
                    "details": f"Discovered {len(services)} open ports on {ip_str}",
                }
            )
        except (OSError, RuntimeError, ValueError) as err:
            logger.error("Lazy port scan failed for %s: %s", ip_str, err, exc_info=True)

    async def _sweep_loop(self) -> None:
        """Internal background polling loop."""
        subnet = detect_local_subnet()
        logger.info(
            "Starting background sweep loop on subnet %s (interval: %ss)",
            subnet,
            self.sweep_interval,
        )
        while self._running:
            try:
                await self.execute_manual_sweep(subnet)
            except (OSError, RuntimeError, ValueError) as err:
                logger.error(
                    "Background sweep iteration encountered error: %s", err, exc_info=True
                )

            try:
                await asyncio.sleep(self.sweep_interval)
            except asyncio.CancelledError:
                break

    def start(self) -> None:
        """Start the background sweep task."""
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        """Gracefully stop background scanning."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
