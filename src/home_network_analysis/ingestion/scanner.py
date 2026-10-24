"""Asynchronous Nmap scanner wrapper with defensive process management.

Executes native nmap binary, enforces strict timeout containment, writes outputs
to isolated temporary files to prevent pipe deadlocks, and parses structured XML.
"""

import asyncio
import logging
import shutil
import socket
import tempfile
import xml.etree.ElementTree as ET
from ipaddress import IPv4Address, ip_network
from pathlib import Path
from typing import Final

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

logger = logging.getLogger(__name__)

STANDARD_NMAP_PATHS: Final[list[Path]] = [
    Path("C:/Program Files (x86)/Nmap/nmap.exe"),
    Path("C:/Program Files/Nmap/nmap.exe"),
]


def resolve_nmap_executable() -> Path:
    """Locate the nmap binary from system PATH or standard install paths.

    Returns:
        Path to the verified executable.

    Raises:
        FileNotFoundError: If nmap cannot be found on the host.
    """
    path_bin = shutil.which("nmap")
    if path_bin:
        return Path(path_bin)

    for candidate in STANDARD_NMAP_PATHS:
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "Nmap executable not found. Ensure Nmap is installed and present in PATH or Program Files."
    )


def detect_local_subnet() -> str:
    """Detect the active physical IPv4 subnet by probing default routing.

    Returns:
        Subnet string in CIDR notation (e.g. '192.168.1.0/24').
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual packets; resolves local adapter bound toward internet
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "192.168.1.1"
    finally:
        s.close()

    # Default to /24 for standard Class C consumer LANs
    network = ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def validate_network_target(target: str) -> str:
    """Sanitize and validate target subnet/IP preventing command injection.

    Args:
        target: IP or CIDR notation string.

    Returns:
        Validated canonical network string.

    Raises:
        ValueError: If input fails validation or contains malicious characters.
    """
    cleaned = target.strip()
    if any(c in cleaned for c in [" ", ";", "&", "|", "`", "$", "-", ">", "<"]):
        raise ValueError(f"Malformed or unsafe characters in target: {target}")

    try:
        net = ip_network(cleaned, strict=False)
        return str(net)
    except ValueError as exc:
        raise ValueError(f"Invalid IP network target: {cleaned}") from exc


def parse_nmap_xml(xml_content: str) -> list[DiscoveredEndpoint]:
    """Parse Nmap XML output into normalized DiscoveredEndpoint records.

    Args:
        xml_content: Raw XML string from Nmap -oX.

    Returns:
        List of DiscoveredEndpoint models.
    """
    endpoints: list[DiscoveredEndpoint] = []
    if not xml_content.strip():
        return endpoints

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        logger.error("Failed to parse Nmap XML: %s", err)
        return endpoints

    for host in root.findall("host"):
        # Check host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_addr_str: str | None = None
        mac_addr_str: str | None = None
        vendor_str: str | None = None

        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip_addr_str = addr.get("addr")
            elif addr_type == "mac":
                mac_addr_str = addr.get("addr")
                vendor_str = addr.get("vendor")

        if not ip_addr_str:
            continue

        # Extract hostname
        hostname: str | None = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for h in hostnames.findall("hostname"):
                name = h.get("name")
                if name:
                    hostname = name
                    break

        # Extract round-trip latency
        latency: float | None = None
        times = host.find("times")
        if times is not None:
            srtt = times.get("srtt")
            if srtt and srtt.isdigit():
                # srtt is in microseconds
                latency = round(int(srtt) / 1000.0, 2)

        # Extract port services
        services: list[ServiceProfile] = []
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                port_id_raw = p.get("portid")
                proto_raw = p.get("protocol", "tcp").upper()
                if not port_id_raw or not port_id_raw.isdigit():
                    continue

                state_el = p.find("state")
                state_str = (
                    state_el.get("state", "open").upper() if state_el is not None else "OPEN"
                )
                if state_str not in ("OPEN", "FILTERED", "CLOSED"):
                    state_str = "OPEN"

                service_el = p.find("service")
                service_name = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                full_version = f"{product} {version}".strip() if product or version else None

                services.append(
                    ServiceProfile(
                        port=int(port_id_raw),
                        protocol=PortProtocol[proto_raw]
                        if proto_raw in PortProtocol.__members__
                        else PortProtocol.TCP,
                        service_name=service_name,
                        service_version=full_version,
                        state=PortState[state_str],
                    )
                )

        is_random = is_locally_administered_mac(mac_addr_str)
        fingerprint = generate_fingerprint_id(
            mac=mac_addr_str,
            ip=ip_addr_str,
            hostname=hostname,
            vendor=vendor_str,
        )

        endpoints.append(
            DiscoveredEndpoint(
                fingerprint_id=fingerprint,
                observed_ip=IPv4Address(ip_addr_str),
                observed_mac=mac_addr_str,
                is_randomized_mac=is_random,
                hostname=hostname,
                vendor=vendor_str,
                reachability=ReachabilityState.ONLINE,
                latency_ms=latency,
                services=services,
            )
        )

    return endpoints


class NmapScanner:
    """Thread-safe asynchronous runner for host Nmap invocations."""

    def __init__(self, nmap_bin: Path | None = None) -> None:
        """Initialize scanner with binary path resolution and concurrency lock.

        Args:
            nmap_bin: Explicit path to nmap executable, or None to auto-detect.
        """
        self.nmap_bin = nmap_bin or resolve_nmap_executable()
        self._lock = asyncio.Lock()

    async def run_discovery_sweep(
        self,
        target_subnet: str | None = None,
        timeout_seconds: int = 60,
    ) -> NetworkScanSnapshot:
        """Execute a non-intrusive ping/ARP sweep across the subnet.

        Uses '-sn' to rapidly discover live hosts without triggering port scans.
        Output is isolated to a secure temporary XML file.

        Args:
            target_subnet: Target CIDR (e.g. '192.168.1.0/24') or auto-detected.
            timeout_seconds: Hard execution deadline before process pruning.

        Returns:
            NetworkScanSnapshot containing discovered endpoints.
        """
        target = validate_network_target(target_subnet or detect_local_subnet())

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = Path(tmp.name)

        # Arguments: -sn (ping sweep), --max-retries 1, -oX <xml_path>
        cmd = [
            str(self.nmap_bin),
            "-sn",
            "--max-retries",
            "1",
            "--host-timeout",
            "800ms",
            "-oX",
            str(xml_path),
            target,
        ]

        async with self._lock:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
                except asyncio.TimeoutError:
                    logger.warning("Nmap discovery sweep timed out. Terminating PID %s", proc.pid)
                    kill_proc = await asyncio.create_subprocess_exec(
                        "taskkill", "/F", "/T", "/PID", str(proc.pid),
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await kill_proc.wait()
                    await proc.wait()

                xml_content = xml_path.read_text(encoding="utf-8", errors="replace")
                endpoints = parse_nmap_xml(xml_content)

                return NetworkScanSnapshot(
                    collector_source=CollectorSource.ARP_SWEEP,
                    network_scope=target,
                    endpoints=endpoints,
                )
            finally:
                if xml_path.exists():
                    try:
                        xml_path.unlink()
                    except OSError:
                        pass

    async def run_targeted_port_scan(
        self,
        ip_address: str,
        top_ports: int = 50,
        timeout_seconds: int = 90,
    ) -> list[ServiceProfile]:
        """Execute a targeted port and service detection scan against a single IP.

        Args:
            ip_address: Validated IPv4 target.
            top_ports: Number of common ports to scan.
            timeout_seconds: Execution deadline.

        Returns:
            List of detected ServiceProfiles.
        """
        target = validate_network_target(ip_address)
        clean_target = target.split("/")[0]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = Path(tmp.name)

        cmd = [
            str(self.nmap_bin),
            "-sT",  # Connect scan
            "-T4",  # Aggressive timing for rapid feedback
            "--top-ports",
            str(top_ports),
            "-oX",
            str(xml_path),
            clean_target,
        ]

        async with self._lock:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
                except asyncio.TimeoutError:
                    logger.warning(
                        "Nmap targeted scan timed out for %s. Pruning PID %s", target, proc.pid
                    )
                    kill_proc = await asyncio.create_subprocess_exec(
                        "taskkill", "/F", "/T", "/PID", str(proc.pid),
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await kill_proc.wait()
                    await proc.wait()

                xml_content = xml_path.read_text(encoding="utf-8", errors="replace")
                endpoints = parse_nmap_xml(xml_content)
                if endpoints:
                    return endpoints[0].services
                return []
            finally:
                if xml_path.exists():
                    try:
                        xml_path.unlink()
                    except OSError:
                        pass
