"""Generic JSON SAST integration for SecureForge."""

from __future__ import annotations

from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
NormalizationResult,
RawEvidence,
)

from ..base import (
IntegrationConfigurationError,
IntegrationParseError,
SecurityIntegration,
)

class GenericSASTIntegration(SecurityIntegration):
"""Normalize findings from a generic JSON SAST scanner."""


integration_name = "sast"
display_name = "Generic Static Application Security Testing"

SEVERITY_MAP = {
    "critical": "critical",
    "blocker": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Build a generic SAST command placeholder."""
    self.validate_configuration(
        configuration
    )

    tool = self._tool_configuration(
        configuration
    )

    if tool is not None:
        if tool.command:
            return [
                *tool.command,
                *tool.arguments,
            ]

        if tool.executable:
            return [
                tool.executable,
                *tool.arguments,
            ]

    return [
        "sast-scanner",
        "--source",
        configuration.target.source_path
        or ".",
        "--format",
        "json",
    ]

def validate_configuration(
    self,
    configuration: ScanConfiguration,
) -> None:
    """Validate configuration for SAST execution."""
    super().validate_configuration(
        configuration
    )

    source_path = configuration.target.source_path

    if not source_path:
        raise IntegrationConfigurationError(
            "SAST requires target.source_path."
        )

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize generic SAST JSON output."""
    raw_data = self._extract_raw_data(
        evidence
    )

    findings_data = self._extract_findings(
        raw_data
    )

    normalized_findings: list[dict[str, Any]] = []
    warnings: list[str] = []

    for index, item in enumerate(
        findings_data
    ):
        try:
            normalized_findings.append(
                self._normalize_finding(
                    item,
                    index=index,
                    evidence=evidence,
                )
            )
        except IntegrationParseError as exc:
            warnings.append(
                str(exc)
            )

    return NormalizationResult(
        source=self.integration_name,
        findings=normalized_findings,
        evidence=[
            evidence
        ],
        warnings=warnings,
        success=True,
    )

def _normalize_finding(
    self,
    item: dict[str, Any],
    *,
    index: int,
    evidence: RawEvidence,
) -> dict[str, Any]:
    """Convert one SAST finding into SecureForge format."""
    title = self._required_string(
        item,
        ("title", "name", "message"),
        index,
        "title",
    )

    severity = self._normalize_severity(
        item.get(
            "severity",
            "info",
        ),
        index,
    )

    description = self._string(
        item.get(
            "description"
        )
        or item.get(
            "message"
        )
        or title
    )

    asset = (
        self._string(
            item.get(
                "asset"
            )
        )
        or evidence.target
        or "unknown"
    )

    location = self._extract_location(
        item
    )

    cwe = self._normalize_cwe(
        item.get(
            "cwe"
        )
    )

    owasp = self._normalize_owasp(
        item.get(
            "owasp"
        )
    )

    remediation = (
        self._string(
            item.get(
                "remediation"
            )
        )
        or self._string(
            item.get(
                "recommendation"
            )
        )
        or "Review the SAST finding and remediate the vulnerable code."
    )

    impact = (
        self._string(
            item.get(
                "impact"
            )
        )
        or "The identified code weakness may introduce security risk."
    )

    finding: dict[str, Any] = {
        "title": title,
        "source": self.integration_name,
        "source_finding_id": self._source_id(
            item,
            index,
        ),
        "application": (
            evidence.metadata.get(
                "application"
            )
            or "unknown"
        ),
        "asset": asset,
        "endpoint": location.get(
            "endpoint"
        ),
        "parameter": location.get(
            "parameter"
        ),
        "cwe": cwe,
        "owasp": owasp,
        "security_requirement": (
            self._security_requirement(
                item
            )
        ),
        "severity": severity,
        "confidence": self._normalize_confidence(
            item.get(
                "confidence"
            )
        ),
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "metadata": {
            "source_location": location,
            "scanner_metadata": item.get(
                "metadata",
                {},
            ),
        },
    }

    return finding

@staticmethod
def _extract_raw_data(
    evidence: RawEvidence,
) -> Any:
    """Extract scanner data from raw evidence."""
    raw_data = evidence.raw_data

    if isinstance(
        raw_data,
        dict,
    ):
        if "findings" in raw_data:
            return raw_data

        stdout = raw_data.get(
            "stdout"
        )

        if stdout:
            return stdout

    return raw_data

@classmethod
def _extract_findings(
    cls,
    raw_data: Any,
) -> list[dict[str, Any]]:
    """Extract finding records from common JSON layouts."""
    if isinstance(
        raw_data,
        dict,
    ):
        findings = raw_data.get(
            "findings"
        )

        if findings is None:
            findings = raw_data.get(
                "results"
            )

        if findings is None:
            findings = raw_data.get(
                "issues"
            )

        if findings is None:
            return []

        if not isinstance(
            findings,
            list,
        ):
            raise IntegrationParseError(
                "SAST findings field must be a list."
            )

        return cls._validate_finding_items(
            findings
        )

    if isinstance(
        raw_data,
        list,
    ):
        return cls._validate_finding_items(
            raw_data
        )

    if isinstance(
        raw_data,
        str,
    ):
        import json

        try:
            parsed = json.loads(
                raw_data
            )
        except json.JSONDecodeError as exc:
            raise IntegrationParseError(
                "SAST output is not valid JSON."
            ) from exc

        return cls._extract_findings(
            parsed
        )

    raise IntegrationParseError(
        "Unsupported SAST output format."
    )

@staticmethod
def _validate_finding_items(
    findings: list[Any],
) -> list[dict[str, Any]]:
    """Validate extracted finding records."""
    validated: list[dict[str, Any]] = []

    for index, finding in enumerate(
        findings
    ):
        if not isinstance(
            finding,
            dict,
        ):
            raise IntegrationParseError(
                f"SAST finding at index {index} "
                "must be an object."
            )

        validated.append(
            finding
        )

    return validated

@classmethod
def _normalize_severity(
    cls,
    value: Any,
    index: int,
) -> str:
    """Normalize scanner severity to SecureForge severity."""
    normalized = cls._string(
        value
    ).lower()

    if normalized in cls.SEVERITY_MAP:
        return cls.SEVERITY_MAP[
            normalized
        ]

    raise IntegrationParseError(
        f"Unsupported SAST severity "
        f"'{value}' at index {index}."
    )

@staticmethod
def _normalize_confidence(
    value: Any,
) -> str:
    """Normalize optional scanner confidence."""
    if value is None:
        return "unknown"

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

    if isinstance(
        value,
        list,
    ):
        if not value:
            return None

        value = value[0]

    normalized = str(
        value
    ).strip().upper()

    if not normalized:
        return None

    if normalized.startswith(
        "CWE-"
    ):
        return normalized

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

    if isinstance(
        value,
        list,
    ):
        if not value:
            return None

        value = value[0]

    normalized = str(
        value
    ).strip()

    return normalized or None

@staticmethod
def _source_id(
    item: dict[str, Any],
    index: int,
) -> str:
    """Return a stable source finding identifier."""
    value = (
        item.get(
            "id"
        )
        or item.get(
            "rule_id"
        )
        or item.get(
            "fingerprint"
        )
    )

    if value is None:
        return f"sast-{index + 1}"

    return str(
        value
    ).strip()

@staticmethod
def _required_string(
    item: dict[str, Any],
    keys: tuple[str, ...],
    index: int,
    field_name: str,
) -> str:
    """Return the first non-empty string from candidate fields."""
    for key in keys:
        value = item.get(
            key
        )

        if value is not None:
            normalized = str(
                value
            ).strip()

            if normalized:
                return normalized

    raise IntegrationParseError(
        f"SAST finding at index {index} "
        f"is missing required field '{field_name}'."
    )

@staticmethod
def _string(
    value: Any,
) -> str:
    """Convert a value into a normalized string."""
    if value is None:
        return ""

    return str(
        value
    ).strip()

@classmethod
def _extract_location(
    cls,
    item: dict[str, Any],
) -> dict[str, str | None]:
    """Extract source location and endpoint information."""
    location = item.get(
        "location"
    )

    if not isinstance(
        location,
        dict,
    ):
        location = {}

    endpoint = (
        cls._string(
            item.get(
                "endpoint"
            )
        )
        or cls._string(
            location.get(
                "endpoint"
            )
        )
        or cls._string(
            item.get(
                "path"
            )
        )
        or cls._string(
            location.get(
                "path"
            )
        )
    )

    parameter = (
        cls._string(
            item.get(
                "parameter"
            )
        )
        or cls._string(
            location.get(
                "parameter"
            )
        )
    )

    return {
        "endpoint": endpoint or None,
        "parameter": parameter or None,
        "file": (
            cls._string(
                item.get(
                    "file"
                )
            )
            or cls._string(
                location.get(
                    "file"
                )
            )
            or None
        ),
        "line": (
            cls._string(
                item.get(
                    "line"
                )
            )
            or cls._string(
                location.get(
                    "line"
                )
            )
            or None
        ),
        "column": (
            cls._string(
                item.get(
                    "column"
                )
            )
            or cls._string(
                location.get(
                    "column"
                )
            )
            or None
        ),
    }

@staticmethod
def _security_requirement(
    item: dict[str, Any],
) -> str | None:
    """Extract a SecureForge security requirement mapping."""
    value = (
        item.get(
            "security_requirement"
        )
        or item.get(
            "requirement"
        )
    )

    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    return normalized or None

@staticmethod
def _tool_configuration(
    configuration: ScanConfiguration,
):
    """Find the SAST tool configuration if one exists."""
    for tool in configuration.tools:
        if tool.name.strip().lower() == "sast":
            return tool

    return None

