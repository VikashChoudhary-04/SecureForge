"""Generic Nmap integration for SecureForge."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
    NormalizationResult,
    RawEvidence,
)
from secureforge.integrations.base import SecurityIntegration


class IntegrationConfigurationError(ValueError):
    """Raised when an integration configuration is invalid."""


class GenericNmapIntegration(SecurityIntegration):
    """Adapt Nmap host and service discovery to SecureForge evidence."""

    integration_name = "nmap"
    name = "nmap"
    display_name = "Nmap Network Discovery"

    DEFAULT_EXECUTABLE = "nmap"

    def __init__(
        self,
        *,
        executable: str | None = None,
        command: list[str] | None = None,
        version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.executable = (
            executable
            or self.DEFAULT_EXECUTABLE
        )
        self.command = list(
            command or []
        )
        self.version = version
        self.metadata = dict(
            metadata or {}
        )

    def integration_metadata(self) -> dict[str, Any]:
        """Return metadata describing the integration."""
        return {
            "integration": self.integration_name,
            "display_name": self.display_name,
            "version": self.version,
            **self.metadata,
        }

    def build_command(
        self,
        configuration: ScanConfiguration,
    ) -> list[str]:
        """Build an Nmap service-discovery command."""
        self.validate_configuration(
            configuration
        )

        target = configuration.target.network_target

        if self.command:
            return self._render_command(
                self.command,
                target,
            )

        return [
            self.executable,
            "-sV",
            "-oX",
            "-",
            target,
        ]

    def validate_configuration(
        self,
        configuration: ScanConfiguration,
    ) -> None:
        """Validate the network target."""
        if not configuration.target.network_target:
            raise IntegrationConfigurationError(
                "Nmap scanning requires "
                "target.network_target."
            )

    def supports_target(
        self,
        configuration: ScanConfiguration,
    ) -> bool:
        """Return whether a network target is configured."""
        return bool(
            configuration.target.network_target
        )

    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Normalize Nmap output into attack-surface findings."""
        raw_data = evidence.raw_data

        if not isinstance(
            raw_data,
            dict,
        ):
            return NormalizationResult(
                source=self.integration_name,
                success=False,
                errors=[
                    "Nmap evidence must contain "
                    "structured output."
                ],
            )

        xml_output = self._extract_xml(
            raw_data
        )

        if xml_output:
            return self._normalize_xml(
                xml_output,
                evidence,
            )

        parsed_data = self._extract_json(
            raw_data
        )

        if parsed_data is None:
            return NormalizationResult(
                source=self.integration_name,
                success=False,
                errors=[
                    "Nmap evidence does not contain "
                    "supported XML or JSON output."
                ],
            )

        records = self._extract_records(
            parsed_data
        )

        findings: list[dict[str, Any]] = []
        warnings: list[str] = []

        for index, record in enumerate(
            records,
            start=1,
        ):
            if not isinstance(
                record,
                dict,
            ):
                warnings.append(
                    f"Nmap record #{index} is not "
                    "an object and was skipped."
                )
                continue

            finding = self._normalize_record(
                record,
                evidence,
                index,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return NormalizationResult(
            source=self.integration_name,
            findings=findings,
            warnings=warnings,
            success=True,
        )

    def _normalize_xml(
        self,
        xml_output: str,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Normalize Nmap XML output."""
        try:
            root = ET.fromstring(
                xml_output
            )
        except ET.ParseError as exc:
            return NormalizationResult(
                source=self.integration_name,
                success=False,
                errors=[
                    f"Nmap XML could not be parsed: {exc}"
                ],
            )

        findings: list[dict[str, Any]] = []
        warnings: list[str] = []

        host_count = 0

        for host_index, host in enumerate(
            root.findall(".//host"),
            start=1,
        ):
            host_count += 1

            address_element = host.find(
                "address"
            )

            host_address = (
                address_element.get(
                    "addr"
                )
                if address_element is not None
                else None
            )

            host_name_element = host.find(
                "./hostnames/hostname"
            )

            hostname = (
                host_name_element.get(
                    "name"
                )
                if host_name_element is not None
                else None
            )

            ports = host.findall(
                "./ports/port"
            )

            for port in ports:
                state_element = port.find(
                    "state"
                )

                state = (
                    state_element.get(
                        "state"
                    )
                    if state_element is not None
                    else None
                )

                if state != "open":
                    continue

                service = port.find(
                    "service"
                )

                service_name = (
                    service.get(
                        "name"
                    )
                    if service is not None
                    else None
                )

                product = (
                    service.get(
                        "product"
                    )
                    if service is not None
                    else None
                )

                version = (
                    service.get(
                        "version"
                    )
                    if service is not None
                    else None
                )

                protocol = port.get(
                    "protocol",
                    "tcp",
                )

                port_number = port.get(
                    "portid"
                )

                source_id = (
                    f"nmap-{host_index}-"
                    f"{protocol}-{port_number}"
                )

                endpoint = self._endpoint(
                    host_address,
                    port_number,
                )

                service_display = (
                    service_name
                    or "unknown service"
                )

                title = (
                    f"Open {protocol.upper()} "
                    f"service: {service_display}"
                )

                description = (
                    f"Nmap identified an open "
                    f"{protocol.upper()} port "
                    f"{port_number} on "
                    f"{host_address or 'the target'}."
                )

                if hostname:
                    description += (
                        f" The host is identified as "
                        f"{hostname}."
                    )

                if product:
                    description += (
                        f" Detected product: "
                        f"{product}."
                    )

                if version:
                    description += (
                        f" Detected version: "
                        f"{version}."
                    )

                findings.append(
                    self._build_finding(
                        source_id=source_id,
                        title=title,
                        endpoint=endpoint,
                        asset=(
                            host_address
                            or evidence.target
                            or "network-target"
                        ),
                        application=(
                            evidence.metadata.get(
                                "application"
                            )
                            or "unknown-application"
                        ),
                        description=description,
                        metadata={
                            "host": host_address,
                            "hostname": hostname,
                            "port": port_number,
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "state": state,
                        },
                    )
                )

        if host_count == 0:
            warnings.append(
                "Nmap XML contained no hosts."
            )

        return NormalizationResult(
            source=self.integration_name,
            findings=findings,
            warnings=warnings,
            success=True,
        )

    def _normalize_record(
        self,
        record: dict[str, Any],
        evidence: RawEvidence,
        index: int,
    ) -> dict[str, Any] | None:
        """Normalize one structured Nmap record."""
        host = self._first_value(
            record,
            "host",
            "address",
            "ip",
            "target",
        )

        port = self._first_value(
            record,
            "port",
            "port_number",
        )

        state = self._first_value(
            record,
            "state",
            default="open",
        )

        if str(
            state
        ).lower() != "open":
            return None

        protocol = self._first_value(
            record,
            "protocol",
            default="tcp",
        )

        service = self._first_value(
            record,
            "service",
            "service_name",
            default="unknown service",
        )

        product = self._first_value(
            record,
            "product",
        )

        version = self._first_value(
            record,
            "version",
        )

        endpoint = self._endpoint(
            host,
            port,
        )

        title = (
            f"Open {str(protocol).upper()} "
            f"service: {service}"
        )

        description = (
            f"Nmap identified an open "
            f"{str(protocol).upper()} port "
            f"{port} on "
            f"{host or 'the target'}."
        )

        if product:
            description += (
                f" Detected product: {product}."
            )

        if version:
            description += (
                f" Detected version: {version}."
            )

        source_id = self._first_value(
            record,
            "id",
            "finding_id",
            "fingerprint",
            default=f"nmap-{index}",
        )

        return self._build_finding(
            source_id=str(
                source_id
            ),
            title=title,
            endpoint=endpoint,
            asset=(
                host
                or evidence.target
                or "network-target"
            ),
            application=(
                evidence.metadata.get(
                    "application"
                )
                or "unknown-application"
            ),
            description=description,
            metadata={
                "host": host,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "state": state,
            },
        )

    @staticmethod
    def _build_finding(
        *,
        source_id: str,
        title: str,
        endpoint: str | None,
        asset: str,
        application: str,
        description: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a normalized attack-surface finding."""
        return {
            "source_finding_id": source_id,
            "title": title,
            "severity": "info",
            "confidence": "confirmed",
            "endpoint": endpoint,
            "parameter": None,
            "cwe": None,
            "owasp": None,
            "security_requirement": None,
            "description": description,
            "impact": (
                "An exposed service expands the reachable "
                "attack surface. Exposure is recorded as "
                "security evidence and is not treated as a "
                "vulnerability by itself."
            ),
            "remediation": (
                "Verify that the service is intentionally "
                "exposed, restrict network access where "
                "possible, and remove unnecessary services."
            ),
            "asset": asset,
            "application": application,
            "metadata": metadata,
        }

    @staticmethod
    def _endpoint(
        host: Any,
        port: Any,
    ) -> str | None:
        """Build a host:port endpoint."""
        if host is None or port is None:
            return None

        return f"{host}:{port}"

    @staticmethod
    def _extract_xml(
        raw_data: dict[str, Any],
    ) -> str | None:
        """Extract Nmap XML from evidence."""
        for key in (
            "xml",
            "stdout",
            "output",
        ):
            value = raw_data.get(
                key
            )

            if (
                isinstance(
                    value,
                    str,
                )
                and "<nmaprun" in value
            ):
                return value

        return None

    @staticmethod
    def _extract_json(
        raw_data: dict[str, Any],
    ) -> Any:
        """Extract structured JSON Nmap output."""
        for key in (
            "findings",
            "results",
            "hosts",
            "services",
        ):
            value = raw_data.get(
                key
            )

            if isinstance(
                value,
                (list, dict),
            ):
                return value

            if isinstance(
                value,
                str,
            ):
                try:
                    return json.loads(
                        value
                    )
                except json.JSONDecodeError:
                    continue

        stdout = raw_data.get(
            "stdout"
        )

        if (
            isinstance(
                stdout,
                str,
            )
            and stdout.strip()
        ):
            try:
                return json.loads(
                    stdout
                )
            except json.JSONDecodeError:
                return None

        return None

    @staticmethod
    def _extract_records(
        raw_data: Any,
    ) -> list[Any]:
        """Extract service records from structured output."""
        if isinstance(
            raw_data,
            list,
        ):
            return raw_data

        if isinstance(
            raw_data,
            dict,
        ):
            for key in (
                "findings",
                "results",
                "hosts",
                "services",
            ):
                value = raw_data.get(
                    key
                )

                if isinstance(
                    value,
                    list,
                ):
                    return value

                if isinstance(
                    value,
                    dict,
                ):
                    return [
                        value
                    ]

            return [
                raw_data
            ]

        return []

    @staticmethod
    def _first_value(
        record: dict[str, Any],
        *keys: str,
        default: Any = None,
    ) -> Any:
        """Return the first non-empty record value."""
        for key in keys:
            value = record.get(
                key
            )

            if (
                value is not None
                and value != ""
            ):
                return value

        return default

    @staticmethod
    def _render_command(
        command: list[str],
        target: str,
    ) -> list[str]:
        """Render a configured Nmap command template."""
        return [
            token.replace(
                "{target}",
                target,
            )
            for token in command
        ]
