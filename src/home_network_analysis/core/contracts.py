"""Domain models and immutable data contracts for network discovery.

Defines the normalized schemas and state structures shared between the
ingestion engine, persistence layer, and API broadcaster.
"""

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class CollectorSource(str, Enum):
    """Enumeration of active discovery collectors."""

    ARP_SWEEP = "ARP_SWEEP"
    NMAP_TARGETED = "NMAP_TARGETED"
    MDNS_SSDP = "MDNS_SSDP"


class ReachabilityState(str, Enum):
    """Enumeration of endpoint connectivity states."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"


class PortProtocol(str, Enum):
    """Transport protocol types."""

    TCP = "TCP"
    UDP = "UDP"


class PortState(str, Enum):
    """Operational port states reported by Nmap."""

    OPEN = "OPEN"
    FILTERED = "FILTERED"
    CLOSED = "CLOSED"


def is_locally_administered_mac(mac: str | None) -> bool:
    """Detect whether a MAC address is locally administered (randomized).

    In IEEE 802 addressing, if the second least-significant bit of the
    first octet is set to 1, the address is locally administered.

    Args:
        mac: Hardware address in standard colon or hyphen notation.

    Returns:
        True if the MAC is randomized/locally administered, False otherwise.
    """
    if not mac:
        return False
    clean_mac = re.sub(r"[^a-fA-F0-9]", "", mac)
    if len(clean_mac) < 2:
        return False
    try:
        first_byte = int(clean_mac[:2], 16)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def generate_fingerprint_id(
    mac: str | None,
    ip: str,
    hostname: str | None = None,
    vendor: str | None = None,
) -> str:
    """Generate a deterministic identity hash for entity resolution.

    If a physical (non-randomized) MAC exists, it forms the immutable anchor.
    If the MAC is missing or randomized, combines available stable host attributes
    (hostname and vendor) or falls back to IP to minimize identity churn.

    Args:
        mac: Observed hardware MAC address.
        ip: Observed IPv4 address.
        hostname: Resolvable network hostname if known.
        vendor: Hardware manufacturer string if known.

    Returns:
        A SHA-256 hex digest representing the device identity.
    """
    if mac and not is_locally_administered_mac(mac):
        canonical_mac = mac.upper().replace("-", ":")
        return hashlib.sha256(f"MAC:{canonical_mac}".encode()).hexdigest()

    # For randomized MACs or missing MACs, combine stable attributes
    parts = [
        f"HOST:{hostname.lower() if hostname else 'UNKNOWN'}",
        f"VENDOR:{vendor.lower() if vendor else 'UNKNOWN'}",
    ]
    if not hostname and not vendor:
        parts.append(f"IP:{ip}")

    seed = "|".join(parts)
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


class ServiceProfile(BaseModel):
    """Network service and exposed port profile."""

    model_config = ConfigDict(frozen=True)

    port: Annotated[int, Field(ge=1, le=65535, description="Port number")]
    protocol: PortProtocol = PortProtocol.TCP
    service_name: str | None = None
    service_version: str | None = None
    state: PortState = PortState.OPEN


class DiscoveredEndpoint(BaseModel):
    """Normalized representation of a single network endpoint."""

    model_config = ConfigDict(frozen=True)

    fingerprint_id: str
    observed_ip: IPv4Address
    observed_mac: str | None = None
    is_randomized_mac: bool = False
    hostname: str | None = None
    vendor: str | None = None
    reachability: ReachabilityState = ReachabilityState.ONLINE
    latency_ms: float | None = None
    services: list[ServiceProfile] = Field(default_factory=list)
    first_seen_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkScanSnapshot(BaseModel):
    """Immutable snapshot payload emitted by any discovery pass."""

    model_config = ConfigDict(frozen=True)

    scan_id: UUID = Field(default_factory=uuid4)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    collector_source: CollectorSource
    network_scope: str = Field(..., description="Target subnet CIDR or IP range")
    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
