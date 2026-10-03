from __future__ import annotations

import json
from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
    NormalizationResult,
    RawEvidence,
)
from secureforge.integrations.base import (
    IntegrationConfigurationError,
    SecurityIntegration,
)




class GenericDASTIntegration(SecurityIntegration):
    """Adapt generic JSON DAST output to SecureForge."""

    integration_name = "dast"
    name = "dast"
    display_name = "Generic Dynamic Application Security Testing"

    DEFAULT_EXECUTABLE = "dast-scanner"

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
        """Build the DAST scanner command."""
        self.validate_configuration(
            configuration
        )

        target = configuration.target.base_url

        if self.command:
            return self._render_command(
                self.command,
                target,
            )

        return [
            self.executable,
            "--target",
            target,
            "--format",
            "json",
        ]

    def validate_configuration(
        self,
        configuration: ScanConfiguration,
    ) -> None:
        """Validate the target required for DAST."""
        if not configuration.target.base_url:
            raise IntegrationConfigurationError(
                "DAST scanning requires target.base_url."
            )

    def supports_target(
        self,
        configuration: ScanConfiguration,
    ) -> bool:
        """Return whether the target can be dynamically scanned."""
        return bool(
            configuration.target.base_url
        )

    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Normalize generic DAST scanner output."""
        try:
            raw_data = self._load_json(
                evidence.raw_data
            )
        except ValueError as exc:
            return NormalizationResult(
                source=self.integration_name,
                success=False,
                errors=[str(exc)],
            )

        records = self._extract_records(
            raw_data
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
                    f"DAST finding #{index} is not "
                    "an object and was skipped."
                )
                continue

            try:
                findings.append(
                    self._normalize_record(
                        record,
                        evidence,
                        index,
                    )
                )
            except (
                ValueError,
                TypeError,
            ) as exc:
                warnings.append(
                    f"DAST finding #{index} could not "
                    f"be normalized: {exc}"
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
    ) -> dict[str, Any]:
        """Convert one DAST result into normalized finding data."""
        title = self._first_value(
            record,
            "title",
            "name",
            "alert",
            "finding",
            "issue",
            default="DAST Security Finding",
        )

        finding_type = self._first_value(
            record,
            "type",
            "category",
            "alert_type",
            "vulnerability_type",
            default=title,
        )

        source_id = self._first_value(
            record,
            "id",
            "finding_id",
            "alert_id",
            "plugin_id",
            "rule_id",
            "fingerprint",
            default=f"dast-{index}",
        )

        url = self._first_value(
            record,
            "url",
            "uri",
            "endpoint",
            "target",
        )

        method = self._first_value(
            record,
            "method",
            "http_method",
        )

        parameter = self._first_value(
            record,
            "parameter",
            "param",
            "parameter_name",
        )

        endpoint = self._format_endpoint(
            method,
            url,
        )

        description = self._first_value(
            record,
            "description",
            "details",
            "message",
            default=(
                f"The dynamic security scanner identified "
                f"{finding_type}."
            ),
        )

        impact = self._first_value(
            record,
            "impact",
            default=(
                "The runtime weakness may be exploitable "
                "against the deployed application and could "
                "affect confidentiality, integrity, or availability."
            ),
        )

        remediation = self._first_value(
            record,
            "remediation",
            "recommendation",
            "solution",
            "fix",
            default=(
                "Remediate the identified application weakness, "
                "verify the fix through a repeatable security test, "
                "and add a regression test where practical."
            ),
        )

        security_requirement = (
            record.get(
                "security_requirement"
            )
            or self._requirement_for_type(
                finding_type
            )
        )

        metadata: dict[str, Any] = {
            "finding_type": finding_type,
            "url": url,
            "method": method,
            "parameter": parameter,
            "target": evidence.target,
        }

        for key in (
            "request",
            "response",
            "evidence",
            "proof",
            "payload",
            "status_code",
            "cwe",
            "owasp",
            "tags",
            "confidence",
        ):
            if key in record:
                metadata[key] = record[key]

        return {
            "source_finding_id": str(
                source_id
            ),
            "title": str(
                title
            ),
            "severity": self._normalize_severity(
                record.get("severity")
                or record.get("risk")
                or record.get("risk_level")
            ),
            "confidence": self._normalize_confidence(
                record.get("confidence")
            ),
            "endpoint": endpoint,
            "parameter": (
                str(parameter)
                if parameter is not None
                else None
            ),
            "cwe": self._normalize_cwe(
                record.get("cwe")
            ),
            "owasp": self._normalize_owasp(
                record.get("owasp")
            ),
            "security_requirement": security_requirement,
            "description": str(
                description
            ),
            "impact": str(
                impact
            ),
            "remediation": str(
                remediation
            ),
            "asset": (
                evidence.target
                or "web-application"
            ),
            "application": (
                evidence.metadata.get(
                    "application"
                )
                or "unknown-application"
            ),
            "metadata": metadata,
        }

    @staticmethod
    def _load_json(
        raw_data: Any,
    ) -> Any:
        """Load DAST JSON from raw evidence."""
        if isinstance(
            raw_data,
            str,
        ):
            try:
                return json.loads(
                    raw_data
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "DAST scanner stdout is not valid JSON."
                ) from exc

        if not isinstance(
            raw_data,
            dict,
        ):
            return raw_data

        for key in (
            "findings",
            "results",
            "alerts",
            "issues",
            "vulnerabilities",
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

        if isinstance(
            stdout,
            str,
        ) and stdout.strip():
            try:
                return json.loads(
                    stdout
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "DAST scanner stdout is not valid JSON."
                ) from exc

        return []

    @staticmethod
    def _extract_records(
        raw_data: Any,
    ) -> list[Any]:
        """Extract DAST records from supported JSON structures."""
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
                "alerts",
                "issues",
                "vulnerabilities",
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
                    return [value]

            return [raw_data]

        return []

    @staticmethod
    def _first_value(
        record: dict[str, Any],
        *keys: str,
        default: Any = None,
    ) -> Any:
        """Return the first non-empty value."""
        for key in keys:
            value = record.get(
                key
            )

            if value is not None and value != "":
                return value

        return default

    @staticmethod
    def _format_endpoint(
        method: Any,
        url: Any,
    ) -> str | None:
        """Format an HTTP method and URL."""
        if url is None:
            return None

        url_text = str(
            url
        ).strip()

        if not url_text:
            return None

        if method:
            return (
                f"{str(method).upper()} "
                f"{url_text}"
            )

        return url_text

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """Normalize DAST severity or risk values."""
        if value is None:
            return "medium"

        normalized = str(
            value
        ).strip().lower()

        mapping = {
            "critical": "critical",
            "crit": "critical",
            "blocker": "critical",
            "high": "high",
            "error": "high",
            "major": "high",
            "medium": "medium",
            "moderate": "medium",
            "warning": "medium",
            "medium-risk": "medium",
            "low": "low",
            "minor": "low",
            "info": "info",
            "informational": "info",
        }

        return mapping.get(
            normalized,
            "medium",
        )

    @staticmethod
    def _normalize_confidence(
        value: Any,
    ) -> str:
        """Normalize DAST confidence values."""
        if value is None:
            return "unknown"

        normalized = str(
            value
        ).strip().lower()

        mapping = {
            "confirmed": "confirmed",
            "certain": "confirmed",
            "high": "high",
            "high-confidence": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "unknown": "unknown",
        }

        return mapping.get(
            normalized,
            "unknown",
        )

    @staticmethod
    def _normalize_cwe(
        value: Any,
    ) -> str | None:
        """Normalize a CWE identifier."""
        if value is None:
            return None

        normalized = str(
            value
        ).strip()

        if not normalized:
            return None

        if normalized.upper().startswith(
            "CWE-"
        ):
            return normalized.upper()

        if normalized.isdigit():
            return f"CWE-{normalized}"

        return normalized

    @staticmethod
    def _normalize_owasp(
        value: Any,
    ) -> str | None:
        """Normalize an OWASP mapping."""
        if value is None:
            return None

        normalized = str(
            value
        ).strip()

        return normalized or None

    @staticmethod
    def _requirement_for_type(
        finding_type: Any,
    ) -> str:
        """Map common DAST weaknesses to SecureForge requirements."""
        normalized = str(
            finding_type
        ).strip().lower()

        if any(
            term in normalized
            for term in (
                "sql injection",
                "sqli",
                "command injection",
                "injection",
            )
        ):
            return "SF-INPUT-001"

        if any(
            term in normalized
            for term in (
                "xss",
                "cross-site scripting",
                "cross site scripting",
            )
        ):
            return "SF-INPUT-001"

        if any(
            term in normalized
            for term in (
                "authentication",
                "auth bypass",
                "session",
                "cookie",
            )
        ):
            return "SF-AUTH-001"

        if any(
            term in normalized
            for term in (
                "authorization",
                "idor",
                "bola",
                "access control",
            )
        ):
            return "SF-AUTHZ-001"

        if any(
            term in normalized
            for term in (
                "tls",
                "ssl",
                "transport",
                "cleartext",
            )
        ):
            return "SF-TRANSPORT-001"

        return "SF-API-001"

    @staticmethod
    def _render_command(
        command: list[str],
        target: str,
    ) -> list[str]:
        """Render a configured DAST command template."""
        return [
            token.replace(
                "{target}",
                target,
            )
            for token in command
        ]

