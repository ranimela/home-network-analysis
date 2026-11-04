"""Integration tests for SQLite persistence and hysteresis presence tracking."""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from home_network_analysis.core.contracts import (
    CollectorSource,
    DiscoveredEndpoint,
    NetworkScanSnapshot,
    PortProtocol,
    PortState,
    ServiceProfile,
    generate_fingerprint_id,
)
from home_network_analysis.storage.db import DatabaseManager
from home_network_analysis.storage.repository import NetworkRepository


@pytest.fixture
async def temp_repo(tmp_path: Path) -> NetworkRepository:
    """Fixture providing an initialized repository backed by a temporary SQLite file."""
    db_file = tmp_path / "test_net.db"
    manager = DatabaseManager(db_file)
    await manager.initialize()
    return NetworkRepository(manager)


async def test_initial_device_discovery_and_query(temp_repo: NetworkRepository) -> None:
    """Verify novel device insertion, service association, and query."""
    fid = generate_fingerprint_id("00:11:22:33:44:55", "192.168.1.100")
    endpoint = DiscoveredEndpoint(
        fingerprint_id=fid,
        observed_ip=IPv4Address("192.168.1.100"),
        observed_mac="00:11:22:33:44:55",
        hostname="smart-tv.lan",
        vendor="Samsung",
        services=[
            ServiceProfile(
                port=8080, protocol=PortProtocol.TCP, service_name="http", state=PortState.OPEN
            )
        ],
    )
    snapshot = NetworkScanSnapshot(
        collector_source=CollectorSource.ARP_SWEEP,
        network_scope="192.168.1.0/24",
        endpoints=[endpoint],
    )

    events = await temp_repo.record_snapshot(snapshot)
    assert len(events) == 1
    assert events[0]["event_type"] == "JOINED"

    devices = await temp_repo.get_all_devices()
    assert len(devices) == 1
    assert devices[0]["fingerprint_id"] == fid
    assert devices[0]["hostname"] == "smart-tv.lan"
    assert devices[0]["reachability"] == "ONLINE"
    assert len(devices[0]["services"]) == 1
    assert devices[0]["services"][0]["port"] == 8080


async def test_hysteresis_debouncing(temp_repo: NetworkRepository) -> None:
    """Verify that devices only transition to OFFLINE after 3 consecutive missed sweeps."""
    fid = generate_fingerprint_id("00:11:22:33:44:55", "192.168.1.50")
    ep = DiscoveredEndpoint(
        fingerprint_id=fid,
        observed_ip=IPv4Address("192.168.1.50"),
        observed_mac="00:11:22:33:44:55",
        hostname="my-laptop",
    )

    # Sweep 1: Discovered
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[ep],
        )
    )

    # Empty sweep 2: 1st miss -> Should remain ONLINE
    events2 = await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[],
        )
    )
    assert len(events2) == 0
    devs = await temp_repo.get_all_devices()
    assert devs[0]["reachability"] == "ONLINE"
    assert devs[0]["consecutive_misses"] == 1

    # Empty sweep 3: 2nd miss -> Should remain ONLINE
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[],
        )
    )
    devs = await temp_repo.get_all_devices()
    assert devs[0]["reachability"] == "ONLINE"
    assert devs[0]["consecutive_misses"] == 2

    # Empty sweep 4: 3rd miss -> Threshold reached, transitions to OFFLINE
    events4 = await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[],
        )
    )
    assert len(events4) == 1
    assert events4[0]["event_type"] == "LEFT"
    devs = await temp_repo.get_all_devices()
    assert devs[0]["reachability"] == "OFFLINE"
    assert devs[0]["consecutive_misses"] == 3


async def test_ip_change_audit_event(temp_repo: NetworkRepository) -> None:
    """Verify that DHCP IP change is detected and logged without creating a duplicate device."""
    mac = "AA:BB:CC:DD:EE:FF"
    fid = generate_fingerprint_id(mac, "192.168.1.20")

    # Day 1: Device at .20
    ep1 = DiscoveredEndpoint(
        fingerprint_id=fid,
        observed_ip=IPv4Address("192.168.1.20"),
        observed_mac=mac,
        hostname="phone-user",
    )
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[ep1],
        )
    )

    # Day 2: Device gets new lease at .25
    ep2 = DiscoveredEndpoint(
        fingerprint_id=fid,
        observed_ip=IPv4Address("192.168.1.25"),
        observed_mac=mac,
        hostname="phone-user",
    )
    events = await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[ep2],
        )
    )

    assert any(e["event_type"] == "IP_CHANGED" for e in events)

    # Ensure device count is strictly 1 (no identity duplication)
    devices = await temp_repo.get_all_devices()
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.25"


async def test_device_custom_name_persists_across_sweeps(temp_repo: NetworkRepository) -> None:
    """Verify user-assigned custom_name is preserved across future discovery sweeps."""
    fid = generate_fingerprint_id("11:22:33:44:55:66", "192.168.1.77")
    ep = DiscoveredEndpoint(
        fingerprint_id=fid,
        observed_ip=IPv4Address("192.168.1.77"),
        observed_mac="11:22:33:44:55:66",
        hostname="ESP_323834.lan",
    )
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[ep],
        )
    )

    updated = await temp_repo.update_device_name(fid, "Living Room Smart Plug")
    assert updated is True

    # Run another sweep and verify custom_name is untouched
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[ep],
        )
    )
    devices = await temp_repo.get_all_devices()
    assert devices[0]["custom_name"] == "Living Room Smart Plug"
    assert devices[0]["hostname"] == "ESP_323834.lan"


async def test_network_scope_isolation_and_persistence(temp_repo: NetworkRepository) -> None:
    """Verify devices from past networks remain stored in DB but are filtered by active scope."""
    home_fid = generate_fingerprint_id("AA:11:22:33:44:55", "192.168.1.10")
    office_fid = generate_fingerprint_id("BB:11:22:33:44:55", "10.0.0.25")

    home_ep = DiscoveredEndpoint(
        fingerprint_id=home_fid,
        observed_ip=IPv4Address("192.168.1.10"),
        observed_mac="AA:11:22:33:44:55",
        hostname="home-nas.lan",
    )
    office_ep = DiscoveredEndpoint(
        fingerprint_id=office_fid,
        observed_ip=IPv4Address("10.0.0.25"),
        observed_mac="BB:11:22:33:44:55",
        hostname="office-printer.local",
    )

    # 1. Connect to Home network (192.168.1.0/24)
    await temp_repo.record_snapshot(
        NetworkScanSnapshot(
            collector_source=CollectorSource.ARP_SWEEP,
            network_scope="192.168.1.0/24",
            endpoints=[home_ep],
        )
    )

    # 2. Switch to Office network (10.0.0.0/24) and run 4 sweeps
    # Home devices must NOT be marked offline while scanning the Office network
    for _ in range(4):
        await temp_repo.record_snapshot(
            NetworkScanSnapshot(
                collector_source=CollectorSource.ARP_SWEEP,
                network_scope="10.0.0.0/24",
                endpoints=[office_ep],
            )
        )

    # Querying active Office scope returns only Office device
    office_devices = await temp_repo.get_all_devices(network_scope="10.0.0.0/24")
    assert len(office_devices) == 1
    assert office_devices[0]["fingerprint_id"] == office_fid
    assert office_devices[0]["hostname"] == "office-printer.local"

    # Querying Home scope returns only Home device (still preserved and ONLINE in DB)
    home_devices = await temp_repo.get_all_devices(network_scope="192.168.1.0/24")
    assert len(home_devices) == 1
    assert home_devices[0]["fingerprint_id"] == home_fid
    assert home_devices[0]["reachability"] == "ONLINE"
    assert home_devices[0]["consecutive_misses"] == 0

    # Presence logs are also scoped per network
    office_logs = await temp_repo.get_presence_logs(network_scope="10.0.0.0/24")
    assert all(log["fingerprint_id"] == office_fid for log in office_logs)
    home_logs = await temp_repo.get_presence_logs(network_scope="192.168.1.0/24")
    assert all(log["fingerprint_id"] == home_fid for log in home_logs)

    # 3. Clear history for Office network only; verify Home network remains intact
    deleted = await temp_repo.clear_network_history("10.0.0.0/24")
    assert deleted == 1
    assert await temp_repo.get_all_devices(network_scope="10.0.0.0/24") == []
    assert await temp_repo.get_presence_logs(network_scope="10.0.0.0/24") == []
    assert len(await temp_repo.get_all_devices(network_scope="192.168.1.0/24")) == 1


