import subprocess

import pytest


SAMPLE_NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="portal.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service
          name="http"
          product="nginx"
          version="1.26"
          method="probed"
          conf="10"
        />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service
          name="http"
          product="nginx"
          version="1.26"
          tunnel="ssl"
          method="probed"
          conf="10"
        />
      </port>
    </ports>
  </host>
</nmaprun>
"""


NO_HOSTNAME_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="203.0.113.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _completed_process(
    stdout=SAMPLE_NMAP_XML,
    *,
    returncode=0,
    stderr=b"",
):
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_v2_parser_produces_service_inventory():
    from app.assessment.handoff import ServiceInventory
    from app.scanners.nmap import (
        parse_nmap_service_inventory,
    )

    scanner_version, inventory = (
        parse_nmap_service_inventory(
            SAMPLE_NMAP_XML,
            requested_hostname="portal.example.com",
        )
    )

    assert scanner_version == "7.95"
    assert isinstance(inventory, ServiceInventory)

    assert len(inventory.services) == 2

    http = inventory.services[0]

    assert http.host == "portal.example.com"
    assert http.ip == "203.0.113.10"
    assert http.port == 80
    assert http.transport == "tcp"
    assert http.service == "http"
    assert http.product == "nginx"
    assert http.version == "1.26"
    assert http.state == "open"
    assert http.tls_hint is False

    https = inventory.services[1]

    assert https.port == 443
    assert https.tls_hint is True


def test_v2_parser_ignores_closed_ports():
    from app.scanners.nmap import (
        parse_nmap_service_inventory,
    )

    _, inventory = parse_nmap_service_inventory(
        SAMPLE_NMAP_XML,
        requested_hostname="portal.example.com",
    )

    assert {
        service.port
        for service in inventory.services
    } == {
        80,
        443,
    }


def test_v2_parser_falls_back_to_requested_hostname():
    from app.scanners.nmap import (
        parse_nmap_service_inventory,
    )

    _, inventory = parse_nmap_service_inventory(
        NO_HOSTNAME_XML,
        requested_hostname="fallback.example.com",
    )

    assert len(inventory.services) == 1
    assert inventory.services[0].host == (
        "fallback.example.com"
    )
    assert inventory.services[0].ip == "203.0.113.20"


def test_v2_parser_rejects_invalid_xml():
    from app.scanners.nmap import (
        NmapScannerError,
        parse_nmap_service_inventory,
    )

    with pytest.raises(
        NmapScannerError,
        match="invalid XML",
    ):
        parse_nmap_service_inventory(
            b"<definitely-not-valid",
            requested_hostname="portal.example.com",
        )


def test_normal_discovery_uses_only_explicit_ports(
    monkeypatch,
):
    from app.scanners.nmap import run_nmap_discovery

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return _completed_process()

    monkeypatch.setattr(
        "app.scanners.nmap.subprocess.run",
        fake_run,
    )

    result = run_nmap_discovery(
        target="portal.example.com",
        ports=(443, 80, 8443, 443),
        full_tcp=False,
        timeout_seconds=321,
    )

    command = captured["command"]

    port_index = command.index("-p")

    assert command[port_index + 1] == "80,443,8443"
    assert "1-65535" not in command

    assert command[-2:] == [
        "--",
        "portal.example.com",
    ]

    assert captured["kwargs"]["timeout"] == 321

    assert result.scanner_version == "7.95"
    assert result.raw_xml == SAMPLE_NMAP_XML
    assert len(
        result.service_inventory.services
    ) == 2


def test_normal_discovery_requires_explicit_ports():
    from app.scanners.nmap import (
        NmapScannerError,
        run_nmap_discovery,
    )

    with pytest.raises(
        NmapScannerError,
        match="explicit ports",
    ):
        run_nmap_discovery(
            target="portal.example.com",
            ports=(),
            full_tcp=False,
            timeout_seconds=120,
        )


def test_normal_discovery_rejects_invalid_port():
    from app.scanners.nmap import (
        NmapScannerError,
        run_nmap_discovery,
    )

    with pytest.raises(
        NmapScannerError,
        match="valid range",
    ):
        run_nmap_discovery(
            target="portal.example.com",
            ports=(80, 65536),
            full_tcp=False,
            timeout_seconds=120,
        )


def test_normal_discovery_cannot_smuggle_full_tcp_as_port_list(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.nmap import (
        NmapScannerError,
        run_nmap_discovery,
    )

    monkeypatch.setattr(
        settings,
        "nmap_max_explicit_ports",
        4,
        raising=False,
    )

    with pytest.raises(
        NmapScannerError,
        match="too many explicit ports",
    ):
        run_nmap_discovery(
            target="portal.example.com",
            ports=(80, 443, 8000, 8080, 8443),
            full_tcp=False,
            timeout_seconds=120,
        )


def test_full_tcp_rejects_hostname_target():
    from app.scanners.nmap import (
        NmapScannerError,
        run_nmap_discovery,
    )

    with pytest.raises(
        NmapScannerError,
        match="literal IP address or CIDR",
    ):
        run_nmap_discovery(
            target="portal.example.com",
            ports=(),
            full_tcp=True,
            timeout_seconds=1800,
        )


def test_full_tcp_rejects_explicit_port_mix():
    from app.scanners.nmap import (
        NmapScannerError,
        run_nmap_discovery,
    )

    with pytest.raises(
        NmapScannerError,
        match="must not include explicit ports",
    ):
        run_nmap_discovery(
            target="203.0.113.10",
            ports=(443,),
            full_tcp=True,
            timeout_seconds=1800,
        )


def test_full_tcp_literal_ip_uses_complete_tcp_range(
    monkeypatch,
):
    from app.scanners.nmap import run_nmap_discovery

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return _completed_process()

    monkeypatch.setattr(
        "app.scanners.nmap.subprocess.run",
        fake_run,
    )

    run_nmap_discovery(
        target="203.0.113.10",
        ports=(),
        full_tcp=True,
        timeout_seconds=1800,
    )

    command = captured["command"]

    port_index = command.index("-p")

    assert command[port_index + 1] == "1-65535"
    assert command[-2:] == [
        "--",
        "203.0.113.10",
    ]

    assert captured["kwargs"]["timeout"] == 1800


def test_full_tcp_literal_cidr_uses_complete_tcp_range(
    monkeypatch,
):
    from app.scanners.nmap import run_nmap_discovery

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return _completed_process()

    monkeypatch.setattr(
        "app.scanners.nmap.subprocess.run",
        fake_run,
    )

    run_nmap_discovery(
        target="203.0.113.0/28",
        ports=(),
        full_tcp=True,
        timeout_seconds=1800,
    )

    command = captured["command"]

    port_index = command.index("-p")

    assert command[port_index + 1] == "1-65535"
    assert command[-2:] == [
        "--",
        "203.0.113.0/28",
    ]


def test_legacy_web_discovery_still_uses_legacy_settings(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.nmap import (
        run_nmap_web_discovery,
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return _completed_process()

    monkeypatch.setattr(
        "app.scanners.nmap.subprocess.run",
        fake_run,
    )

    monkeypatch.setattr(
        settings,
        "nmap_allowed_ports",
        "80,443",
    )
    monkeypatch.setattr(
        settings,
        "nmap_timeout_seconds",
        120,
    )

    result = run_nmap_web_discovery(
        "portal.example.com"
    )

    command = captured["command"]
    port_index = command.index("-p")

    assert command[port_index + 1] == "80,443"
    assert captured["kwargs"]["timeout"] == 120

    assert result.scanner_version == "7.95"
    assert [
        item.port
        for item in result.open_ports
    ] == [
        80,
        443,
    ]
