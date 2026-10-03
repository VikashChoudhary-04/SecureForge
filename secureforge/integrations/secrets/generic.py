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




class GenericSecretsIntegration(SecurityIntegration):
    """Adapt generic JSON secret-scanner output to SecureForge."""

    integration_name = "secrets"
    name = "secrets"
    display_name = "Generic Secret Detection"

    DEFAULT_EXECUTABLE = "secret-scanner"

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
        """Build the secret scanner command."""
        self.validate_configuration(
            configuration
        )

        source_path = configuration.target.source_path

        if self.command:
            return self._render_command(
                self.command,
                source_path,
            )

        return [
            self.executable,
            "--source",
            source_path,
            "--format",
            "json",
        ]

    def validate_configuration(
        self,
        configuration: ScanConfiguration,
    ) -> None:
        """Validate configuration required for secret scanning."""
        if not configuration.target.source_path:
            raise IntegrationConfigurationError(
                "Secret scanning requires target.source_path."
            )

    def supports_target(
        self,
        configuration: ScanConfiguration,
    ) -> bool:
        """Return whether the target can be scanned."""
        return bool(
            configuration.target.source_path
        )

    def normalize(
        self,
        evidence: RawEvidence,
    ) -> NormalizationResult:
        """Normalize generic secret-scanner output."""
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
                    f"Secret finding #{index} is not "
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
                    f"Secret finding #{index} could not "
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
        """Convert one secret finding into normalized data."""
        secret_type = self._first_value(
            record,
            "secret_type",
            "rule",
            "rule_id",
            "detector",
            "type",
            default="exposed secret",
        )

        source_id = self._first_value(
            record,
            "id",
            "finding_id",
            "fingerprint",
            "rule_id",
            default=f"secret-{index}",
        )

        file_path = self._extract_location_value(
            record,
            "file",
            "filename",
            "path",
        )

        line = self._extract_location_value(
            record,
            "line",
            "line_number",
        )

        commit = self._first_value(
            record,
            "commit",
            "commit_sha",
            "commit_id",
        )

        author = self._first_value(
            record,
            "author",
            "author_name",
        )

        redacted_value = self._redact_secret(
            record
        )

        location = self._build_location(
            file_path=file_path,
            line=line,
        )

        title = (
            f"Potential exposed secret: "
            f"{secret_type}"
        )

        description = (
            f"A secret-detection source identified "
            f"a potential {secret_type} in "
            f"{location or 'the scanned source'}."
        )

        impact = (
            "Exposed credentials, API keys, tokens, or "
            "other authentication material may allow "
            "unauthorized access to applications, "
            "infrastructure, or third-party services. "
            "The actual secret value is intentionally "
            "not retained by SecureForge."
        )

        remediation = (
            "Remove the secret from source control, "
            "revoke or rotate the exposed credential, "
            "identify affected systems, replace it with "
            "a managed secret mechanism, and verify "
            "that the credential is no longer present "
            "in repository history where applicable."
        )

        metadata: dict[str, Any] = {
            "secret_type": secret_type,
            "file": file_path,
            "line": line,
            "commit": commit,
            "author": author,
            "secret_value": redacted_value,
            "secret_values_redacted": True,
        }

        for key in (
            "tags",
            "fingerprint",
        ):
            if key in record:
                metadata[key] = record[key]

        return {
            "source_finding_id": str(
                source_id
            ),
            "title": title,
            "severity": self._normalize_severity(
                record.get("severity")
            ),
            "confidence": self._normalize_confidence(
                record.get("confidence")
            ),
            "endpoint": None,
            "parameter": None,
            "cwe": self._normalize_cwe(
                record.get("cwe")
            ),
            "owasp": self._normalize_owasp(
                record.get("owasp")
            ),
            "security_requirement": (
                record.get(
                    "security_requirement"
                )
                or "SF-SECRET-001"
            ),
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "asset": (
                evidence.target
                or "source-code"
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
        """Load secret-scanner JSON from raw evidence."""
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
                    "Secret scanner stdout is not valid JSON."
                ) from exc

        if not isinstance(
            raw_data,
            dict,
        ):
            return raw_data

        for key in (
            "findings",
            "results",
            "secrets",
            "issues",
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
                    "Secret scanner stdout is not valid JSON."
                ) from exc

        return []

    @staticmethod
    def _extract_records(
        raw_data: Any,
    ) -> list[Any]:
        """Extract finding records from supported structures."""
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
                "secrets",
                "issues",
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
        """Return the first non-empty value."""
        for key in keys:
            value = record.get(
                key
            )

            if value is not None and value != "":
                return value

        return default

    @staticmethod
    def _extract_location_value(
        record: dict[str, Any],
        *keys: str,
    ) -> Any:
        """Extract a location field from flat or nested output."""
        for key in keys:
            value = record.get(
                key
            )

            if value is not None and value != "":
                return value

        location = record.get(
            "location"
        )

        if isinstance(
            location,
            dict,
        ):
            for key in keys:
                value = location.get(
                    key
                )

                if value is not None and value != "":
                    return value

        return None

    @staticmethod
    def _build_location(
        *,
        file_path: Any,
        line: Any,
    ) -> str | None:
        """Build a human-readable source location."""
        if not file_path:
            return None

        if line:
            return f"{file_path}:{line}"

        return str(
            file_path
        )

    @staticmethod
    def _redact_secret(
        record: dict[str, Any],
    ) -> str:
        """Return a safe representation of secret material."""
        if record.get(
            "redacted_value"
        ):
            return str(
                record["redacted_value"]
            )

        if record.get(
            "masked_value"
        ):
            return str(
                record["masked_value"]
            )

        if (
            record.get("secret")
            or record.get("secret_value")
            or record.get("match")
        ):
            return "[REDACTED]"

        return "[REDACTED]"

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """Normalize scanner severity values."""
        if value is None:
            return "high"

        normalized = str(
            value
        ).strip().lower()

        mapping = {
            "critical": "critical",
            "blocker": "critical",
            "high": "high",
            "error": "high",
            "medium": "medium",
            "moderate": "medium",
            "warning": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
        }

        return mapping.get(
            normalized,
            "high",
        )

    @staticmethod
    def _normalize_confidence(
        value: Any,
    ) -> str:
        """Normalize scanner confidence values."""
        if value is None:
            return "confirmed"

        normalized = str(
            value
        ).strip().lower()

        mapping = {
            "confirmed": "confirmed",
            "certain": "confirmed",
            "high": "high",
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
    def _render_command(
        command: list[str],
        source_path: str,
    ) -> list[str]:
        """Render a configured command template."""
        return [
            token.replace(
                "{source}",
                source_path,
            )
            for token in command
        ]
