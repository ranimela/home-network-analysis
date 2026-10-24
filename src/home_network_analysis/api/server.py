"""FastAPI web server exposing REST endpoints, SSE streams, and dashboard UI."""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from home_network_analysis.ingestion.coordinator import ScanCoordinator
from home_network_analysis.ingestion.scanner import (
    NmapScanner,
    detect_local_subnet,
    validate_network_target,
)
from home_network_analysis.storage.db import DatabaseManager
from home_network_analysis.storage.repository import NetworkRepository

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class DeviceScanRequest(BaseModel):
    """Payload for on-demand single host port scanning."""

    ip_address: str
    top_ports: int = 50


class SubnetScanRequest(BaseModel):
    """Payload for on-demand subnet scanning."""

    subnet: str | None = None


def create_app(
    db_path: Path | str = "data/network.db",
    auto_start_scanner: bool = True,
    sweep_interval_seconds: int = 60,
) -> FastAPI:
    """Factory creating and configuring the FastAPI application instance.

    Args:
        db_path: SQLite storage path.
        auto_start_scanner: Whether to launch the periodic background sweeper.
        sweep_interval_seconds: Interval between passive sweeps.

    Returns:
        Configured FastAPI app.
    """
    db_manager = DatabaseManager(db_path)
    repository = NetworkRepository(db_manager)
    scanner = NmapScanner()
    coordinator = ScanCoordinator(scanner, repository, sweep_interval_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Manage background tasks lifecycle."""
        await db_manager.initialize()
        app.state.db_manager = db_manager
        app.state.repository = repository
        app.state.scanner = scanner
        app.state.coordinator = coordinator

        if auto_start_scanner:
            coordinator.start()

        yield

        if auto_start_scanner:
            await coordinator.stop()

    app = FastAPI(
        title="Home Network Analysis Engine",
        description="On-premise real-time network topology and device monitor",
        lifespan=lifespan,
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve the responsive web dashboard."""
        html_file = TEMPLATES_DIR / "dashboard.html"
        if not html_file.is_file():
            raise HTTPException(status_code=404, detail="Dashboard template not found")
        content = html_file.read_text(encoding="utf-8")
        return HTMLResponse(content=content)

    @app.get("/api/status")
    async def get_status() -> dict[str, Any]:
        """Return operational engine health and current subnet."""
        return {
            "status": "ONLINE",
            "subnet": detect_local_subnet(),
            "active_subscribers": len(coordinator._event_subscribers),
            "sweep_interval": coordinator.sweep_interval,
        }

    @app.get("/api/devices")
    async def get_devices() -> list[dict[str, Any]]:
        """Return all discovered devices and associated ports."""
        return await repository.get_all_devices()

    @app.get("/api/logs")
    async def get_logs(limit: int = 50) -> list[dict[str, Any]]:
        """Return recent presence transition logs."""
        return await repository.get_presence_logs(limit=limit)

    @app.post("/api/scan")
    async def trigger_subnet_scan(body: SubnetScanRequest | None = None) -> dict[str, Any]:
        """Trigger an immediate subnet discovery pass."""
        target = body.subnet if body and body.subnet else None
        try:
            snapshot = await coordinator.execute_manual_sweep(target)
            return {
                "scan_id": str(snapshot.scan_id),
                "scope": snapshot.network_scope,
                "endpoints_found": len(snapshot.endpoints),
            }
        except Exception as exc:
            logger.error("Scan trigger failed: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/scan/device")
    async def trigger_device_port_scan(body: DeviceScanRequest) -> dict[str, Any]:
        """Execute deep port discovery on a specific host."""
        try:
            validated_ip = validate_network_target(body.ip_address)
            # Remove /32 if present
            clean_ip = validated_ip.split("/")[0]
            services = await scanner.run_targeted_port_scan(clean_ip, top_ports=body.top_ports)

            # Persist to repository (replace with fresh open ports)
            async with db_manager.connect() as conn:
                await conn.execute(
                    """
                    DELETE FROM device_services
                    WHERE fingerprint_id IN (SELECT fingerprint_id FROM devices WHERE ip_address = ?)
                    """,
                    (clean_ip,),
                )
                for s in services:
                    await conn.execute(
                        """
                        INSERT INTO device_services (
                            fingerprint_id, port, protocol, service_name, service_version, state, last_checked_utc
                        )
                        SELECT fingerprint_id, ?, ?, ?, ?, ?, datetime('now')
                        FROM devices WHERE ip_address = ?
                        ON CONFLICT(fingerprint_id, port, protocol) DO UPDATE SET
                            service_name = excluded.service_name,
                            service_version = excluded.service_version,
                            state = excluded.state,
                            last_checked_utc = excluded.last_checked_utc
                        """,
                        (
                            s.port,
                            s.protocol.value,
                            s.service_name,
                            s.service_version,
                            s.state.value,
                            clean_ip,
                        ),
                    )
                await conn.commit()

            await coordinator.broadcast(
                {
                    "event_type": "SERVICES_UPDATED",
                    "details": f"Port scan completed for {clean_ip}: found {len(services)} services",
                }
            )

            return {
                "ip": clean_ip,
                "services": [s.model_dump() for s in services],
            }
        except Exception as exc:
            logger.error("Device scan failed: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/events")
    async def event_stream(request: Request) -> StreamingResponse:
        """Stream real-time presence events over Server-Sent Events (SSE)."""
        subscriber_q = coordinator.subscribe()

        async def generator() -> AsyncIterator[str]:
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        # 10s wait for events or yield heartbeat
                        event = await asyncio.wait_for(subscriber_q.get(), timeout=10.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        yield f"data: {json.dumps({'heartbeat': True})}\n\n"
            finally:
                coordinator.unsubscribe(subscriber_q)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app
