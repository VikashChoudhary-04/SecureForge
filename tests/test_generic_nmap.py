"""Tests for the generic Nmap integration."""

from __future__ import annotations

from secureforge.core.config import (
ScanConfiguration,
TargetConfiguration,
)
from secureforge.core.normalization import RawEvidence
from secureforge.integrations.nmap import (
GenericNmapIntegration,
)

def make_configuration(
*,
network_target: str | None = "127.0.0.1",
) -> ScanConfiguration:
"""Create an Nmap scan configuration."""
return ScanConfiguration(
application="SecureCommerce",
target=TargetConfiguration(
name="securecommerce-network",
network_target=network_target,
),
)

def make_evidence(
raw_data: dict,
*,
target: str = "127.0.0.1",
) -> RawEvidence:
"""Create Nmap evidence."""
return RawEvidence(
source="nmap",
target=target,
raw_data=raw_data,
metadata={
"application": "SecureCommerce",
},
)

def test_build_command_uses_service_detection() -> None:
integration = GenericNmapIntegration(
executable="nmap"
)


command = integration.build_command(
    make_configuration()
)

assert command == [
    "nmap",
    "-sV",
    "-oX",
    "-",
    "127.0.0.1",
]


def test_build_command_supports_custom_template() -> None:
integration = GenericNmapIntegration(
command=[
"nmap",
"-sV",
"-oX",
"-",
"{target}",
]
)


command = integration.build_command(
    make_configuration(
        network_target="192.168.1.10"
    )
)

assert command == [
    "nmap",
    "-sV",
    "-oX",
    "-",
    "192.168.1.10",
]


def test_build_command_requires_network_target() -> None:
integration = GenericNmapIntegration()


configuration = make_configuration(
    network_target=None
)

try:
    integration.build_command(
        configuration
    )
except Exception as exc:
    assert "network_target" in str(exc)
else:
    raise AssertionError(
        "Expected network target validation to fail."
    )


def test_normalize_nmap_xml() -> None:
integration = GenericNmapIntegration()


xml_output = """\


<?xml version="1.0"?>

<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="securecommerce.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service
          name="http"
          product="Node.js"
          version="20.0.0"
        />
      </port>
    </ports>
  </host>
</nmaprun>
"""


evidence = make_evidence(
    {
        "xml": xml_output
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1

finding = result.findings[0]

assert finding["source_finding_id"] == (
    "nmap-1-tcp-3000"
)
assert finding["title"] == (
    "Open TCP service: http"
)
assert finding["severity"] == "info"
assert finding["confidence"] == "confirmed"
assert finding["endpoint"] == "127.0.0.1:3000"
assert finding["asset"] == "127.0.0.1"

assert finding["metadata"]["host"] == "127.0.0.1"
assert finding["metadata"]["hostname"] == (
    "securecommerce.local"
)
assert finding["metadata"]["port"] == "3000"
assert finding["metadata"]["protocol"] == "tcp"
assert finding["metadata"]["service"] == "http"
assert finding["metadata"]["product"] == "Node.js"
assert finding["metadata"]["version"] == "20.0.0"


def test_closed_ports_are_not_normalized_as_findings() -> None:
integration = GenericNmapIntegration()


xml_output = """\


<?xml version="1.0"?>

<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


evidence = make_evidence(
    {
        "xml": xml_output
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1
assert result.findings[0]["endpoint"] == (
    "127.0.0.1:80"
)


def test_multiple_open_services_are_normalized() -> None:
integration = GenericNmapIntegration()


xml_output = """\


<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Python" version="3.12"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


result = integration.normalize(
    make_evidence(
        {
            "stdout": xml_output
        },
        target="10.0.0.5",
    )
)

assert result.success is True
assert len(result.findings) == 3

assert [
    finding["endpoint"]
    for finding in result.findings
] == [
    "10.0.0.5:22",
    "10.0.0.5:443",
    "10.0.0.5:8080",
]


def test_structured_json_output_is_supported() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "services": [
            {
                "id": "nmap-001",
                "host": "10.0.0.10",
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.0",
            }
        ]
    },
    target="10.0.0.10",
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert len(result.findings) == 1

finding = result.findings[0]

assert finding["source_finding_id"] == "nmap-001"
assert finding["endpoint"] == "10.0.0.10:22"
assert finding["metadata"]["service"] == "ssh"
assert finding["metadata"]["product"] == "OpenSSH"
assert finding["metadata"]["version"] == "9.0"


def test_json_closed_service_is_skipped() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "results": [
            {
                "id": "nmap-002",
                "host": "10.0.0.20",
                "port": 25,
                "protocol": "tcp",
                "state": "closed",
                "service": "smtp",
            }
        ]
    },
    target="10.0.0.20",
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings == []


def test_open_service_is_not_marked_as_vulnerability() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "nmap-003",
                "host": "10.0.0.30",
                "port": 8080,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
            }
        ]
    },
    target="10.0.0.30",
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["severity"] == "info"
assert finding["cwe"] is None
assert finding["owasp"] is None
assert finding["security_requirement"] is None
assert "not treated as a vulnerability" in (
    finding["impact"].lower()
)


def test_unknown_service_is_supported() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "findings": [
            {
                "id": "nmap-004",
                "host": "10.0.0.40",
                "port": 9999,
                "state": "open",
            }
        ]
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True

finding = result.findings[0]

assert finding["title"] == (
    "Open TCP service: unknown service"
)


def test_invalid_nmap_xml_returns_failure() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "xml": "<nmaprun><host>"
    }
)

result = integration.normalize(
    evidence
)

assert result.success is False
assert result.errors
assert "could not be parsed" in result.errors[0]


def test_unsupported_output_returns_failure() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "stdout": "Nmap scan output that is not XML or JSON"
    }
)

result = integration.normalize(
    evidence
)

assert result.success is False
assert result.errors
assert "supported XML or JSON" in result.errors[0]


def test_xml_with_no_hosts_generates_warning() -> None:
integration = GenericNmapIntegration()


evidence = make_evidence(
    {
        "xml": "<nmaprun></nmaprun>"
    }
)

result = integration.normalize(
    evidence
)

assert result.success is True
assert result.findings == []
assert any(
    "no hosts" in warning.lower()
    for warning in result.warnings
)


def test_integration_metadata() -> None:
integration = GenericNmapIntegration(
version="7.97"
)


metadata = integration.integration_metadata()

assert metadata["integration"] == "nmap"
assert metadata["display_name"] == (
    "Nmap Network Discovery"
)
assert metadata["version"] == "7.97"

