"""API and endpoint integration tests."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from home_network_analysis.api.server import create_app


@pytest.fixture
def app_instance(tmp_path: Path):
    """Fixture providing a configured FastAPI app using an isolated SQLite database."""
    db_file = tmp_path / "test_api.db"
    return create_app(db_path=db_file, auto_start_scanner=False)


async def test_get_dashboard_html(app_instance) -> None:
    """Verify root endpoint returns the dashboard HTML document."""
    async with AsyncClient(
        transport=ASGITransport(app=app_instance), base_url="http://test"
    ) as client:
        res = await client.get("/")
        assert res.status_code == 200
        assert "Home Network Monitor" in res.text
        assert "text/html" in res.headers["content-type"]


async def test_api_status_endpoint(app_instance) -> None:
    """Verify system status endpoint."""
    async with AsyncClient(
        transport=ASGITransport(app=app_instance), base_url="http://test"
    ) as client:
        res = await client.get("/api/status")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ONLINE"
        assert "subnet" in data


async def test_api_devices_empty_initially(app_instance) -> None:
    """Verify empty device listing initially."""
    # Lifespan needs to run to initialize DB
    async with (
        app_instance.router.lifespan_context(app_instance),
        AsyncClient(transport=ASGITransport(app=app_instance), base_url="http://test") as client,
    ):
        res = await client.get("/api/devices")
        assert res.status_code == 200
        assert res.json() == []


async def test_scan_device_rejects_injection(app_instance) -> None:
    """Verify malicious or invalid IP targets are rejected with HTTP 400."""
    async with (
        app_instance.router.lifespan_context(app_instance),
        AsyncClient(transport=ASGITransport(app=app_instance), base_url="http://test") as client,
    ):
            res = await client.post(
                "/api/scan/device",
                json={"ip_address": "192.168.1.1; rm -rf /"},
            )
            assert res.status_code == 400
            assert "Malformed or unsafe characters" in res.json()["detail"]
