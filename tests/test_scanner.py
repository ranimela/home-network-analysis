"""Unit tests for Nmap scanner parser, validation, and executable detection."""

import pytest

from home_network_analysis.ingestion.scanner import (
    parse_nmap_xml,
    resolve_nmap_executable,
    validate_network_target,
)

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.0/24" start="1700000000">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Netgear"/>
    <hostnames>
      <hostname name="router.home" type="PTR"/>
    </hostnames>
    <times srtt="1200"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="lighttpd" version="1.4.55"/>
      </port>
      <port protocol="tcp" portid="53">
        <state state="open"/>
        <service name="domain" product="dnsmasq"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.42" addrtype="ipv4"/>
    <address addr="da:a1:19:00:11:22" addrtype="mac" vendor="Apple"/>
    <hostnames>
      <hostname name="iphone-user.lan" type="PTR"/>
    </hostnames>
    <times srtt="45000"/>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_validate_network_target_safe() -> None:
    """Verify standard IP and CIDR formats pass validation."""
    assert validate_network_target("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_network_target("10.0.0.5") == "10.0.0.5/32"
    assert validate_network_target(" 172.16.0.0/16 ") == "172.16.0.0/16"


def test_validate_network_target_rejects_injections() -> None:
    """Verify command injection attempts and invalid inputs are blocked."""
    with pytest.raises(ValueError, match="Malformed or unsafe characters"):
        validate_network_target("192.168.1.1; dir")

    with pytest.raises(ValueError, match="Malformed or unsafe characters"):
        validate_network_target("192.168.1.1 --script=vuln")

    with pytest.raises(ValueError, match="Malformed or unsafe characters"):
        validate_network_target("192.168.1.1 | calc")

    with pytest.raises(ValueError, match="Invalid IP network target"):
        validate_network_target("not.an.ip.address")


def test_parse_nmap_xml_extraction() -> None:
    """Verify XML parsing maps correctly to domain contracts."""
    endpoints = parse_nmap_xml(SAMPLE_NMAP_XML)

    # Down host is ignored; 2 up hosts extracted
    assert len(endpoints) == 2

    # First host checks
    router = endpoints[0]
    assert str(router.observed_ip) == "192.168.1.1"
    assert router.observed_mac == "00:11:22:33:44:55"
    assert router.vendor == "Netgear"
    assert router.hostname == "router.home"
    assert not router.is_randomized_mac
    assert router.latency_ms == 1.2
    assert len(router.services) == 2
    assert router.services[0].port == 80
    assert router.services[0].service_name == "http"
    assert router.services[0].service_version == "lighttpd 1.4.55"

    # Second host (iPhone with randomized MAC)
    iphone = endpoints[1]
    assert str(iphone.observed_ip) == "192.168.1.42"
    assert iphone.observed_mac == "da:a1:19:00:11:22"
    assert iphone.is_randomized_mac is True
    assert iphone.latency_ms == 45.0


def test_resolve_nmap_executable() -> None:
    """Verify installed nmap is discovered on the host."""
    path = resolve_nmap_executable()
    assert path.is_file()
    assert path.name.lower() == "nmap.exe"
