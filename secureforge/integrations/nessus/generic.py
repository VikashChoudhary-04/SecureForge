"""Generic Nessus vulnerability-assessment integration for SecureForge."""

from **future** import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from secureforge.integrations.base import (
IntegrationConfigurationError,
IntegrationParseError,
SecurityIntegration,
)
from secureforge.core.normalization import RawEvidence

class GenericNessusIntegration(SecurityIntegration):
"""Normalize Nessus-style vulnerability assessment results."""

```
integration_name = "nessus"
display_name = "Nessus"
description = (
    "Ingest Nessus vulnerability assessment evidence and normalize "
    "confirmed scanner findings into SecureForge."
)

default_command = (
    "nessus-scanner --target {target} --format json"
)

def build_command(self, target: dict[str, Any]) -> list[str]:
    """Build the Nessus command for a target configuration."""
    custom_command = target.get("nessus_command")

    if custom_command:
        if isinstance(custom_command, str):
            command = custom_command.format(
                target=target.get("network_target")
                or target.get("host")
                or target.get("url")
                or "",
            )
            return command.split()

        if isinstance(custom_command, list):
            return [
                str(part).format(
                    target=target.get("network_target")
                    or target.get("host")
                    or target.get("url")
                    or "",
                )
                for part in custom_command
            ]

        raise IntegrationConfigurationError(
            "nessus_command must be a string or list."
        )

    target_value = (
        target.get("network_target")
        or target.get("host")
        or target.get("url")
    )

    if not target_value:
        raise IntegrationConfigurationError(
            "Nessus integration requires "
            "'network_target', 'host', or 'url'."
        )

    return [
        "nessus-scanner",
        "--target",
        str(target_value),
        "--format",
        "json",
    ]

def validate_config(self, target: dict[str, Any]) -> None:
    """Validate the target configuration."""
    if not isinstance(target, dict):
        raise IntegrationConfigurationError(
            "Nessus target configuration must be a mapping."
        )

    if not (
        target.get("network_target")
        or target.get("host")
        or target.get("url")
    ):
        raise IntegrationConfigurationError(
            "Nessus integration requires "
            "'network_target', 'host', or 'url'."
        )

def supports_target(self, target: dict[str, Any]) -> bool:
    """Return whether the integration can assess the target."""
    if not isinstance(target, dict):
        return False

    return bool(
        target.get("network_target")
        or target.get("host")
        or target.get("url")
    )

def normalize(
    self,
    raw_output: str,
    *,
    target: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Parse Nessus JSON or XML output into normalized findings."""
    if not raw_output or not raw_output.strip():
        raise IntegrationParseError(
            "Nessus returned empty output."
        )

    text = raw_output.strip()

    if text.startswith("<"):
        return self._parse_xml(text, target=target or {})

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntegrationParseError(
            "Nessus output is neither valid JSON nor XML."
        ) from exc

    return self._parse_json(payload, target=target or {})

def create_evidence(
    self,
    *,
    source_reference: str | None,
    target: str | None,
    raw_data: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> RawEvidence:
    """Create raw evidence from Nessus output."""
    combined_metadata = dict(metadata or {})

    combined_metadata.setdefault(
        "integration",
        self.integration_name,
    )

    return RawEvidence(
        source=self.integration_name,
        source_version=combined_metadata.get("source_version"),
        source_reference=source_reference,
        target=target,
        raw_data=raw_data,
        metadata=combined_metadata,
    )

def _parse_json(
    self,
    payload: Any,
    *,
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    """Parse common Nessus JSON structures."""
    if isinstance(payload, list):
        raw_findings = payload
    elif isinstance(payload, dict):
        raw_findings = (
            payload.get("findings")
            or payload.get("vulnerabilities")
            or payload.get("results")
            or payload.get("plugins")
            or payload.get("items")
        )

        if raw_findings is None:
            raw_findings = self._extract_nested_findings(payload)

        if raw_findings is None:
            raise IntegrationParseError(
                "Nessus JSON does not contain a supported "
                "finding collection."
            )
    else:
        raise IntegrationParseError(
            "Nessus JSON root must be an object or list."
        )

    if not isinstance(raw_findings, list):
        raise IntegrationParseError(
            "Nessus finding collection must be a list."
        )

    findings: list[dict[str, Any]] = []

    for index, raw_finding in enumerate(raw_findings, start=1):
        if not isinstance(raw_finding, dict):
            continue

        normalized = self._normalize_finding(
            raw_finding,
            index=index,
            target=target,
        )

        if normalized is not None:
            findings.append(normalized)

    if not findings and raw_findings:
        raise IntegrationParseError(
            "Nessus output contained findings, but none could "
            "be normalized."
        )

    return findings

def _extract_nested_findings(
    self,
    payload: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Extract findings from common nested Nessus containers."""
    for key in ("report", "scan", "data"):
        value = payload.get(key)

        if not isinstance(value, dict):
            continue

        for finding_key in (
            "findings",
            "vulnerabilities",
            "results",
            "plugins",
            "items",
        ):
            findings = value.get(finding_key)

            if isinstance(findings, list):
                return findings

    return None

def _normalize_finding(
    self,
    raw: dict[str, Any],
    *,
    index: int,
    target: dict[str, Any],
) -> dict[str, Any] | None:
    """Normalize one Nessus vulnerability."""
    title = self._first_string(
        raw,
        "title",
        "plugin_name",
        "name",
        "finding",
    )

    if not title:
        title = f"Nessus finding {index}"

    severity = self._normalize_severity(
        raw.get("severity")
        or raw.get("risk")
        or raw.get("risk_factor")
    )

    confidence = self._normalize_confidence(
        raw.get("confidence")
    )

    plugin_id = self._first_string(
        raw,
        "plugin_id",
        "pluginID",
        "plugin",
    )

    cve = self._extract_cve(raw)

    cwe = self._normalize_identifier(
        raw.get("cwe")
        or raw.get("cwe_id")
    )

    cvss = self._extract_cvss(raw)

    host = self._first_string(
        raw,
        "host",
        "hostname",
        "ip",
        "address",
    )

    port = self._first_string(
        raw,
        "port",
        "service_port",
    )

    protocol = self._first_string(
        raw,
        "protocol",
        "transport",
    )

    endpoint = self._build_endpoint(
        host=host,
        port=port,
        protocol=protocol,
        fallback=(
            target.get("url")
            or target.get("network_target")
            or target.get("host")
        ),
    )

    description = self._first_string(
        raw,
        "description",
        "synopsis",
        "details",
        "summary",
    ) or title

    impact = self._first_string(
        raw,
        "impact",
        "risk_description",
        "risk",
    ) or self._default_impact(
        severity=severity,
        title=title,
    )

    remediation = self._first_string(
        raw,
        "solution",
        "remediation",
        "fix",
        "recommendation",
    ) or self._default_remediation(
        title=title,
        cve=cve,
    )

    evidence = self._first_string(
        raw,
        "evidence",
        "plugin_output",
        "output",
        "proof",
    )

    finding_id = (
        f"nessus-{plugin_id}"
        if plugin_id
        else f"nessus-{index}"
    )

    metadata: dict[str, Any] = {
        "plugin_id": plugin_id,
        "cve": cve,
        "cvss": cvss,
        "host": host,
        "port": port,
        "protocol": protocol,
        "integration": self.integration_name,
    }

    for key in (
        "family",
        "plugin_family",
        "service",
        "product",
        "version",
        "solution",
        "see_also",
        "vpr",
        "exploit_available",
        "exploitability",
    ):
        if key in raw:
            metadata[key] = raw[key]

    return {
        "source_finding_id": plugin_id or f"nessus-{index}",
        "title": title,
        "finding_id": finding_id,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": self._extract_owasp(raw),
        "security_requirement": self._map_requirement(
            title=title,
            raw=raw,
        ),
        "asset": host or self._target_asset(target),
        "endpoint": endpoint,
        "parameter": self._first_string(
            raw,
            "parameter",
            "param",
        ),
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "evidence": evidence,
        "metadata": metadata,
    }

def _parse_xml(
    self,
    raw_output: str,
    *,
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    """Parse a simplified Nessus XML report."""
    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError as exc:
        raise IntegrationParseError(
            "Nessus XML output could not be parsed."
        ) from exc

    findings: list[dict[str, Any]] = []

    for index, item in enumerate(
        root.iter("ReportItem"),
        start=1,
    ):
        raw: dict[str, Any] = {
            "plugin_id": item.attrib.get("pluginID"),
            "plugin_name": item.attrib.get("pluginName"),
            "severity": item.attrib.get("severity"),
            "port": item.attrib.get("port"),
            "protocol": item.attrib.get("protocol"),
            "service": item.attrib.get("svc_name"),
        }

        for child in item:
            key = self._xml_tag(child.tag)
            value = (child.text or "").strip()

            if not value:
                continue

            if key in raw and raw[key]:
                continue

            raw[key] = value

        host = self._find_xml_host(item)

        if host:
            raw["host"] = host

        normalized = self._normalize_finding(
            raw,
            index=index,
            target=target,
        )

        if normalized is not None:
            findings.append(normalized)

    if not findings:
        raise IntegrationParseError(
            "Nessus XML report contains no supported ReportItem findings."
        )

    return findings

@staticmethod
def _find_xml_host(item: ET.Element) -> str | None:
    """Find the host associated with a Nessus XML report item."""
    report = item

    for parent in item.iter():
        for host in parent.findall(".//Host"):
            address = host.attrib.get("name")

            if address:
                return address

    for attribute in ("host", "hostname", "ip"):
        value = report.attrib.get(attribute)

        if value:
            return value

    return None

@staticmethod
def _xml_tag(tag: str) -> str:
    """Normalize an XML tag name."""
    return tag.rsplit("}", 1)[-1].lower()

@staticmethod
def _first_string(
    data: dict[str, Any],
    *keys: str,
) -> str | None:
    """Return the first non-empty string-like value."""
    for key in keys:
        value = data.get(key)

        if value is None:
            continue

        if isinstance(value, str):
            value = value.strip()

            if value:
                return value

        elif isinstance(value, (int, float)):
            return str(value)

    return None

@staticmethod
def _normalize_identifier(
    value: Any,
) -> str | None:
    """Normalize CWE-like identifiers."""
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    if text.upper().startswith("CWE-"):
        return text.upper()

    match = re.search(r"\b(\d{1,5})\b", text)

    if match:
        return f"CWE-{match.group(1)}"

    return text

@staticmethod
def _extract_cve(
    raw: dict[str, Any],
) -> str | None:
    """Extract the first CVE identifier."""
    candidates = [
        raw.get("cve"),
        raw.get("cves"),
        raw.get("cve_id"),
        raw.get("cve_ids"),
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        values = (
            candidate
            if isinstance(candidate, list)
            else [candidate]
        )

        for value in values:
            match = re.search(
                r"CVE-\d{4}-\d{4,7}",
                str(value),
                flags=re.IGNORECASE,
            )

            if match:
                return match.group(0).upper()

    text = " ".join(
        str(value)
        for value in raw.values()
        if isinstance(value, str)
    )

    match = re.search(
        r"CVE-\d{4}-\d{4,7}",
        text,
        flags=re.IGNORECASE,
    )

    return match.group(0).upper() if match else None

@staticmethod
def _extract_cvss(
    raw: dict[str, Any],
) -> float | None:
    """Extract a numeric CVSS score."""
    for key in (
        "cvss",
        "cvss_score",
        "cvss_v2",
        "cvss_v3",
        "cvss_v31",
        "cvss_base_score",
    ):
        value = raw.get(key)

        if value is None:
            continue

        if isinstance(value, dict):
            for nested_key in (
                "base_score",
                "score",
                "base",
            ):
                nested = value.get(nested_key)

                if nested is not None:
                    value = nested
                    break

        try:
            return float(value)
        except (TypeError, ValueError):
            continue

    return None

@staticmethod
def _normalize_severity(
    value: Any,
) -> str:
    """Normalize Nessus severity values."""
    if value is None:
        return "info"

    text = str(value).strip().lower()

    mapping = {
        "4": "critical",
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info",
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "none": "info",
    }

    return mapping.get(text, "info")

@staticmethod
def _normalize_confidence(
    value: Any,
) -> str:
    """Normalize confidence values."""
    if value is None:
        return "high"

    text = str(value).strip().lower()

    mapping = {
        "confirmed": "confirmed",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "unknown": "unknown",
    }

    return mapping.get(text, "high")

@staticmethod
def _extract_owasp(
    raw: dict[str, Any],
) -> str | None:
    """Extract an OWASP mapping when supplied by the scanner."""
    value = (
        raw.get("owasp")
        or raw.get("owasp_category")
        or raw.get("owasp_top_10")
    )

    if value is None:
        return None

    if isinstance(value, list):
        return ", ".join(str(item) for item in value)

    return str(value)

@staticmethod
def _map_requirement(
    *,
    title: str,
    raw: dict[str, Any],
) -> str | None:
    """Map common Nessus findings to SecureForge requirements."""
    text = " ".join(
        [
            title,
            str(raw.get("description") or ""),
            str(raw.get("plugin_name") or ""),
            str(raw.get("family") or ""),
        ]
    ).lower()

    if any(
        keyword in text
        for keyword in (
            "ssl",
            "tls",
            "certificate",
            "cleartext",
            "unencrypted",
        )
    ):
        return "SF-TRANSPORT-001"

    if any(
        keyword in text
        for keyword in (
            "credential",
            "password",
            "authentication",
            "account",
        )
    ):
        return "SF-AUTH-001"

    if any(
        keyword in text
        for keyword in (
            "sql injection",
            "cross-site scripting",
            "xss",
            "injection",
        )
    ):
        return "SF-INPUT-001"

    if any(
        keyword in text
        for keyword in (
            "authorization",
            "access control",
            "privilege escalation",
        )
    ):
        return "SF-AUTHZ-001"

    return None

@staticmethod
def _build_endpoint(
    *,
    host: str | None,
    port: str | None,
    protocol: str | None,
    fallback: Any,
) -> str | None:
    """Build a useful endpoint representation."""
    if not host:
        return str(fallback) if fallback else None

    if port:
        if protocol:
            return f"{protocol}://{host}:{port}"

        return f"{host}:{port}"

    return host

@staticmethod
def _target_asset(
    target: dict[str, Any],
) -> str:
    """Return the best available target asset."""
    return str(
        target.get("network_target")
        or target.get("host")
        or target.get("url")
        or "unknown"
    )

@staticmethod
def _default_impact(
    *,
    severity: str,
    title: str,
) -> str:
    """Build a conservative default impact statement."""
    if severity == "critical":
        return (
            f"{title} may expose the target to severe security impact "
            "and should be investigated before release."
        )

    if severity == "high":
        return (
            f"{title} may expose the target to significant security "
            "impact and should be remediated."
        )

    if severity == "medium":
        return (
            f"{title} may create a meaningful security weakness "
            "depending on exposure and application context."
        )

    if severity == "low":
        return (
            f"{title} represents a lower-severity security weakness "
            "that should be addressed according to risk."
        )

    return (
        f"{title} is recorded as security assessment evidence "
        "without a direct severity claim."
    )

@staticmethod
def _default_remediation(
    *,
    title: str,
    cve: str | None,
) -> str:
    """Build conservative remediation guidance."""
    if cve:
        return (
            f"Review {cve}, apply the vendor-recommended fix or "
            "upgrade, and retest the affected asset."
        )

    return (
        f"Investigate {title}, apply the vendor or configuration "
        "remediation, and retest the affected asset."
    )
```
