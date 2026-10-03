from __future__ import annotations

import json
from typing import Any

from secureforge.core.normalization import RawEvidence
from secureforge.integrations.base import (
    IntegrationConfigurationError,
    IntegrationParseError,
    SecurityIntegration,
)






class ManualEvidenceIntegration(SecurityIntegration):
    """Convert manually validated security evidence into findings."""

    name = "manual"
    integration_name = "manual"
    display_name = "Manual Validation"
    description = (
        "Ingest manually validated evidence from penetration testing "
        "and security assessment workflows."
    )

    default_command = (
        "manual-evidence --input {evidence_path}"
    )

    SUPPORTED_SOURCES = {
        "burp",
        "burp_suite",
        "wireshark",
        "metasploit",
        "manual",
        "other",
    }

    def __init__(
        self,
        *,
        version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.version = version
        self.metadata = dict(
            metadata or {}
        )

    def run(
        self,
        context: Any,
    ) -> Any:
        """Execute manual evidence processing."""
        raise NotImplementedError(
            "Manual evidence is supplied as pre-collected evidence."
        )

    def integration_metadata(self) -> dict[str, Any]:
        """Return integration metadata."""
        return {
            "integration": self.integration_name,
            "display_name": self.display_name,
            "version": self.version,
            "metadata": dict(self.metadata),
        }

    def build_command(
        self,
        target: dict[str, Any],
    ) -> list[str]:
        """Build a command for loading a manual evidence file."""
        evidence_path = target.get(
            "evidence_path"
        )

        if not evidence_path:
            raise IntegrationConfigurationError(
                "Manual evidence integration requires "
                "'evidence_path'."
            )

        custom_command = target.get(
            "manual_command"
        )

        if custom_command:
            if isinstance(
                custom_command,
                str,
            ):
                return custom_command.format(
                    evidence_path=str(
                        evidence_path
                    ),
                ).split()

            if isinstance(
                custom_command,
                list,
            ):
                return [
                    str(part).format(
                        evidence_path=str(
                            evidence_path
                        ),
                    )
                    for part in custom_command
                ]

            raise IntegrationConfigurationError(
                "manual_command must be a string or list."
            )

        return [
            "manual-evidence",
            "--input",
            str(evidence_path),
        ]

    def validate_config(
        self,
        target: dict[str, Any],
    ) -> None:
        """Validate manual evidence configuration."""
        if not isinstance(
            target,
            dict,
        ):
            raise IntegrationConfigurationError(
                "Manual evidence configuration must be a mapping."
            )

        if not target.get(
            "evidence_path"
        ):
            raise IntegrationConfigurationError(
                "Manual evidence integration requires "
                "'evidence_path'."
            )

    def supports_target(
        self,
        target: dict[str, Any],
    ) -> bool:
        """Return whether the target contains manual evidence."""
        return (
            isinstance(
                target,
                dict,
            )
            and bool(
                target.get(
                    "evidence_path"
                )
            )
        )

    def normalize(
        self,
        raw_output: str,
        *,
        target: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Normalize manually supplied security findings."""
        if not raw_output or not raw_output.strip():
            raise IntegrationParseError(
                "Manual evidence output is empty."
            )

        try:
            payload = json.loads(
                raw_output
            )
        except json.JSONDecodeError as exc:
            raise IntegrationParseError(
                "Manual evidence must be valid JSON."
            ) from exc

        return self._normalize_payload(
            payload,
            target=target or {},
        )

    def create_evidence(
        self,
        *,
        source_reference: str | None,
        target: str | None,
        raw_data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> RawEvidence:
        """Create preserved raw evidence for manual validation."""
        combined_metadata = dict(
            metadata or {}
        )

        combined_metadata.setdefault(
            "integration",
            self.integration_name,
        )

        if self.version is not None:
            combined_metadata.setdefault(
                "source_version",
                self.version,
            )

        return RawEvidence(
            source=self.integration_name,
            source_version=combined_metadata.get(
                "source_version"
            ),
            source_reference=source_reference,
            target=target,
            raw_data=raw_data,
            metadata=combined_metadata,
        )

    def _normalize_payload(
        self,
        payload: Any,
        *,
        target: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Normalize a supported manual evidence document."""
        if isinstance(
            payload,
            list,
        ):
            raw_findings = payload

        elif isinstance(
            payload,
            dict,
        ):
            collection_keys = (
                "findings",
                "validated_findings",
                "evidence",
                "results",
            )
            raw_findings = None
            for key in collection_keys:
                if key in payload:
                    raw_findings = payload[key]
                    break

            if raw_findings is None:
                raw_findings = [payload]

        else:
            raise IntegrationParseError(
                "Manual evidence JSON must contain "
                "an object or list."
            )

        if not isinstance(
            raw_findings,
            list,
        ):
            raise IntegrationParseError(
                "Manual evidence findings must be a list."
            )

        findings: list[dict[str, Any]] = []

        for index, raw_finding in enumerate(
            raw_findings,
            start=1,
        ):
            if not isinstance(
                raw_finding,
                dict,
            ):
                continue

            normalized = self._normalize_finding(
                raw_finding,
                index=index,
                target=target,
            )

            findings.append(
                normalized
            )

        if not findings:
            raise IntegrationParseError(
                "Manual evidence did not contain "
                "any usable findings."
            )

        return findings

    def _normalize_finding(
        self,
        raw: dict[str, Any],
        *,
        index: int,
        target: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize one manually validated finding."""
        source = self._normalize_source(
            raw.get("source")
            or raw.get("tool")
            or raw.get("validated_with")
        )

        title = self._first_string(
            raw,
            "title",
            "name",
            "finding",
        ) or f"Manual finding {index}"

        finding_id = self._first_string(
            raw,
            "finding_id",
            "id",
        ) or f"manual-{index}"

        severity = self._normalize_severity(
            raw.get("severity")
        )

        confidence = self._normalize_confidence(
            raw.get("confidence")
        )

        description = self._first_string(
            raw,
            "description",
            "details",
            "summary",
        ) or title

        impact = self._first_string(
            raw,
            "impact",
            "business_impact",
        ) or (
            "The manually validated weakness may affect the "
            "security of the assessed application or asset."
        )

        remediation = self._first_string(
            raw,
            "remediation",
            "solution",
            "fix",
        ) or (
            "Remediate the validated weakness and repeat the "
            "same validation procedure."
        )

        endpoint = self._first_string(
            raw,
            "endpoint",
            "url",
            "location",
        )

        parameter = self._first_string(
            raw,
            "parameter",
            "param",
        )

        asset = self._first_string(
            raw,
            "asset",
            "host",
            "target",
        ) or self._target_asset(
            target
        )

        evidence = self._extract_evidence(
            raw
        )

        metadata = dict(
            raw.get("metadata")
            if isinstance(
                raw.get("metadata"),
                dict,
            )
            else {}
        )

        metadata.update(
            {
                "validation_source": source,
                "manual_validation": True,
            }
        )

        if "request" in raw:
            metadata["request"] = raw[
                "request"
            ]

        if "response" in raw:
            metadata["response"] = raw[
                "response"
            ]

        if "command" in raw:
            metadata["command"] = raw[
                "command"
            ]

        if "packet_reference" in raw:
            metadata["packet_reference"] = raw[
                "packet_reference"
            ]

        if "module" in raw:
            metadata["module"] = raw[
                "module"
            ]

        return {
            "finding_id": finding_id,
            "source_finding_id": self._first_string(
                raw,
                "source_finding_id",
                "plugin_id",
                "alert_id",
            ),
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "cwe": self._first_string(
                raw,
                "cwe",
                "cwe_id",
            ),
            "owasp": self._first_string(
                raw,
                "owasp",
                "owasp_category",
            ),
            "security_requirement": self._map_requirement(
                title=title,
                raw=raw,
            ),
            "asset": asset,
            "endpoint": endpoint,
            "parameter": parameter,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
            "metadata": metadata,
        }

    def _normalize_source(
        self,
        value: Any,
    ) -> str:
        """Normalize the manual validation source."""
        if value is None:
            return "manual"

        text = str(
            value
        ).strip().lower()

        aliases = {
            "burp suite": "burp_suite",
            "burp": "burp",
            "wireshark": "wireshark",
            "metasploit": "metasploit",
            "msf": "metasploit",
            "manual": "manual",
        }

        normalized = aliases.get(
            text,
            text,
        )

        if normalized not in self.SUPPORTED_SOURCES:
            return "other"

        return normalized

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """Normalize manually supplied severity."""
        if value is None:
            return "medium"

        text = str(
            value
        ).strip().lower()

        mapping = {
            "critical": "critical",
            "crit": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "med": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
        }

        return mapping.get(
            text,
            "medium",
        )

    @staticmethod
    def _normalize_confidence(
        value: Any,
    ) -> str:
        """Normalize manually supplied confidence."""
        if value is None:
            return "confirmed"

        text = str(
            value
        ).strip().lower()

        mapping = {
            "confirmed": "confirmed",
            "high": "high",
            "medium": "medium",
            "med": "medium",
            "low": "low",
            "unknown": "unknown",
        }

        return mapping.get(
            text,
            "confirmed",
        )

    @staticmethod
    def _first_string(
        data: dict[str, Any],
        *keys: str,
    ) -> str | None:
        """Return the first non-empty string-like field."""
        for key in keys:
            value = data.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):
                value = value.strip()

                if value:
                    return value

            elif isinstance(
                value,
                (int, float),
            ):
                return str(
                    value
                )

        return None

    @staticmethod
    def _extract_evidence(
        raw: dict[str, Any],
    ) -> str:
        """Build a concise evidence representation."""
        evidence = raw.get(
            "evidence"
        )

        if (
            isinstance(
                evidence,
                str,
            )
            and evidence.strip()
        ):
            return evidence.strip()

        if isinstance(
            evidence,
            list,
        ):
            return "\n".join(
                str(item)
                for item in evidence
                if str(item).strip()
            )

        for key in (
            "proof",
            "proof_of_concept",
            "validation_result",
            "output",
        ):
            value = raw.get(
                key
            )

            if (
                isinstance(
                    value,
                    str,
                )
                and value.strip()
            ):
                return value.strip()

        return (
            "Manual validation was recorded without a dedicated "
            "evidence text field."
        )

    @staticmethod
    def _map_requirement(
        *,
        title: str,
        raw: dict[str, Any],
    ) -> str | None:
        """Map common manually validated issues to requirements."""
        text = " ".join(
            [
                title,
                str(
                    raw.get(
                        "description"
                    )
                    or ""
                ),
                str(
                    raw.get(
                        "category"
                    )
                    or ""
                ),
            ]
        ).lower()

        if any(
            keyword in text
            for keyword in (
                "bola",
                "idor",
                "authorization",
                "access control",
                "privilege",
            )
        ):
            return "SF-AUTHZ-001"

        if any(
            keyword in text
            for keyword in (
                "authentication",
                "session",
                "login",
                "credential",
            )
        ):
            return "SF-AUTH-001"

        if any(
            keyword in text
            for keyword in (
                "sql injection",
                "xss",
                "cross-site scripting",
                "injection",
            )
        ):
            return "SF-INPUT-001"

        if any(
            keyword in text
            for keyword in (
                "secret",
                "api key",
                "token",
                "password exposed",
            )
        ):
            return "SF-SECRET-001"

        if any(
            keyword in text
            for keyword in (
                "tls",
                "ssl",
                "cleartext",
                "unencrypted",
            )
        ):
            return "SF-TRANSPORT-001"

        return None

    @staticmethod
    def _target_asset(
        target: dict[str, Any],
    ) -> str:
        """Return the best available target identifier."""
        return str(
            target.get("asset")
            or target.get("host")
            or target.get("url")
            or target.get("network_target")
            or "unknown"
        )

"""Contextual risk evaluation engine for SecureForge."""

