"""Unit tests for core data contracts and entity identity generation."""

from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from home_network_analysis.core.contracts import (
    CollectorSource,
    DiscoveredEndpoint,
    NetworkScanSnapshot,
    PortProtocol,
    PortState,
    ReachabilityState,
    ServiceProfile,
    generate_fingerprint_id,
    is_locally_administered_mac,
)


def test_locally_administered_mac_detection() -> None:
    """Verify IEEE 802 locally administered bit parsing."""
    # Globally unique (OUI) MACs (bit 1 of byte 0 is 0)
    assert not is_locally_administered_mac("00:50:56:C0:00:08")
    assert not is_locally_administered_mac("B8:27:EB:AA:BB:CC")
    assert not is_locally_administered_mac("d8:3a:dd:11:22:33")

    # Locally administered / randomized MACs (bit 1 of byte 0 is 1: e.g. 02, 06, 0A, 0E, etc.)
    assert is_locally_administered_mac("02:50:56:C0:00:08")
    assert is_locally_administered_mac("da:a1:19:bb:cc:dd")
    assert is_locally_administered_mac("FE:ED:FA:CE:00:01")

    # Edge cases
    assert not is_locally_administered_mac(None)
    assert not is_locally_administered_mac("")


def test_fingerprint_generation_stability() -> None:
    """Verify deterministic hashing across runs."""
    # Physical MAC produces identical hash regardless of IP change (DHCP churn resilience)
    hash1 = generate_fingerprint_id("00:50:56:C0:00:08", "192.168.1.50")
    hash2 = generate_fingerprint_id("00-50-56-C0-00-08", "192.168.1.99")
    assert hash1 == hash2

    # Randomized MAC falls back to hostname + vendor
    rand_hash1 = generate_fingerprint_id(
        "02:00:00:00:00:01", "192.168.1.10", "iphone-rani", "apple"
    )
    rand_hash2 = generate_fingerprint_id(
        "06:aa:bb:cc:dd:ee", "192.168.1.11", "iphone-rani", "apple"
    )
    assert rand_hash1 == rand_hash2


def test_service_profile_validation() -> None:
    """Verify valid port boundaries."""
    profile = ServiceProfile(
        port=80,
        protocol=PortProtocol.TCP,
        service_name="http",
        state=PortState.OPEN,
    )
    assert profile.port == 80

    with pytest.raises(ValidationError):
        ServiceProfile(port=0)  # ge=1

    with pytest.raises(ValidationError):
        ServiceProfile(port=70000)  # le=65535


def test_snapshot_schema_integrity() -> None:
    """Verify complete snapshot construction and immutability."""
    endpoint = DiscoveredEndpoint(
        fingerprint_id="test_fingerprint",
        observed_ip=IPv4Address("192.168.1.1"),
        observed_mac="00:11:22:33:44:55",
        is_randomized_mac=False,
        hostname="router.lan",
        vendor="Netgear",
        reachability=ReachabilityState.ONLINE,
        services=[
            ServiceProfile(port=53, protocol=PortProtocol.UDP, service_name="domain"),
            ServiceProfile(port=80, protocol=PortProtocol.TCP, service_name="http"),
        ],
    )

    snapshot = NetworkScanSnapshot(
        collector_source=CollectorSource.ARP_SWEEP,
        network_scope="192.168.1.0/24",
        endpoints=[endpoint],
    )

    assert len(snapshot.endpoints) == 1
    assert str(snapshot.endpoints[0].observed_ip) == "192.168.1.1"

    # Frozen model validation (immutability check)
    with pytest.raises(ValidationError):
        snapshot.network_scope = "10.0.0.0/8"  # type: ignore[misc]
