"""Generic JSON SCA integration for SecureForge."""

from **future** import annotations

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

class GenericSCAIntegration(SecurityIntegration):
"""Normalize findings from a generic JSON SCA scanner."""

```
integration_name = "sca"
display_name = "Generic Software Composition Analysis"

SEVERITY_MAP = {
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

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Build a generic SCA command."""
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
        "sca-scanner",
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
    """Validate configuration for SCA execution."""
    super().validate_configuration(
        configuration
    )

    if not configuration.target.source_path:
        raise IntegrationConfigurationError(
            "SCA requires target.source_path."
        )

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize generic SCA JSON output."""
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
    """Convert one dependency vulnerability into a finding."""
    package_name = (
        self._string(
            item.get(
                "package"
            )
        )
        or self._string(
            item.get(
                "package_name"
            )
        )
        or self._string(
            item.get(
                "dependency"
            )
        )
    )

    if not package_name:
        raise IntegrationParseError(
            f"SCA finding at index {index} "
            "is missing a package name."
        )

    installed_version = (
        self._string(
            item.get(
                "installed_version"
            )
        )
        or self._string(
            item.get(
                "version"
            )
        )
        or self._string(
            item.get(
                "current_version"
            )
        )
    )

    fixed_version = (
        self._string(
            item.get(
                "fixed_version"
            )
        )
        or self._string(
            item.get(
                "patched_version"
            )
        )
        or self._string(
            item.get(
                "fixed_in"
            )
        )
    )

    vulnerability_id = self._vulnerability_id(
        item,
        index,
    )

    severity = self._normalize_severity(
        item.get(
            "severity",
            self._severity_from_cvss(
                item.get(
                    "cvss"
                )
                or item.get(
                    "cvss_score"
                )
            ),
        ),
        index,
    )

    title = (
        self._string(
            item.get(
                "title"
            )
        )
        or self._string(
            item.get(
                "summary"
            )
        )
        or f"Vulnerable dependency: {package_name}"
    )

    description = (
        self._string(
            item.get(
                "description"
            )
        )
        or self._string(
            item.get(
                "details"
            )
        )
        or (
            f"Dependency '{package_name}' "
            f"has known vulnerability "
            f"{vulnerability_id}."
        )
    )

    remediation = self._build_remediation(
        package_name,
        installed_version,
        fixed_version,
        item,
    )

    impact = (
        self._string(
            item.get(
                "impact"
            )
        )
        or (
            f"The vulnerable dependency '{package_name}' "
            "may expose the application to known security issues."
        )
    )

    cwe = self._normalize_cwe(
        item.get(
            "cwe"
        )
    )

    owasp = self._string(
        item.get(
            "owasp"
        )
    ) or None

    asset = (
        self._string(
            item.get(
                "asset"
            )
        )
        or evidence.target
        or "application-dependencies"
    )

    finding: dict[str, Any] = {
        "title": title,
        "source": self.integration_name,
        "source_finding_id": vulnerability_id,
        "application": (
            evidence.metadata.get(
                "application"
            )
            or "unknown"
        ),
        "asset": asset,
        "endpoint": None,
        "parameter": None,
        "cwe": cwe,
        "owasp": owasp,
        "security_requirement": (
            self._string(
                item.get(
                    "security_requirement"
                )
            )
            or "SF-DEP-001"
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
            "package": package_name,
            "installed_version": installed_version or None,
            "fixed_version": fixed_version or None,
            "vulnerability_id": vulnerability_id,
            "cvss": self._cvss_value(
                item.get(
                    "cvss"
                )
                or item.get(
                    "cvss_score"
                )
            ),
            "dependency_type": (
                self._string(
                    item.get(
                        "dependency_type"
                    )
                )
                or None
            ),
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
        if any(
            key in raw_data
            for key in (
                "findings",
                "vulnerabilities",
                "results",
                "dependencies",
            )
        ):
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
    """Extract vulnerability records from common SCA formats."""
    if isinstance(
        raw_data,
        dict,
    ):
        findings = (
            raw_data.get(
                "findings"
            )
            or raw_data.get(
                "vulnerabilities"
            )
            or raw_data.get(
                "results"
            )
        )

        if findings is None:
            dependencies = raw_data.get(
                "dependencies"
            )

            if dependencies is None:
                return []

            findings = dependencies

        if not isinstance(
            findings,
            list,
        ):
            raise IntegrationParseError(
                "SCA findings field must be a list."
            )

        return cls._validate_items(
            findings
        )

    if isinstance(
        raw_data,
        list,
    ):
        return cls._validate_items(
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
                "SCA output is not valid JSON."
            ) from exc

        return cls._extract_findings(
            parsed
        )

    raise IntegrationParseError(
        "Unsupported SCA output format."
    )

@staticmethod
def _validate_items(
    findings: list[Any],
) -> list[dict[str, Any]]:
    """Validate extracted SCA records."""
    validated: list[dict[str, Any]] = []

    for index, finding in enumerate(
        findings
    ):
        if not isinstance(
            finding,
            dict,
        ):
            raise IntegrationParseError(
                f"SCA finding at index {index} "
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
    """Normalize scanner severity."""
    normalized = cls._string(
        value
    ).lower()

    if normalized in cls.SEVERITY_MAP:
        return cls.SEVERITY_MAP[
            normalized
        ]

    raise IntegrationParseError(
        f"Unsupported SCA severity "
        f"'{value}' at index {index}."
    )

@classmethod
def _severity_from_cvss(
    cls,
    value: Any,
) -> str:
    """Infer severity from a numeric CVSS score."""
    score = cls._cvss_value(
        value
    )

    if score is None:
        return "medium"

    if score >= 9.0:
        return "critical"

    if score >= 7.0:
        return "high"

    if score >= 4.0:
        return "medium"

    if score > 0:
        return "low"

    return "info"

@staticmethod
def _cvss_value(
    value: Any,
) -> float | None:
    """Normalize a CVSS score."""
    if value is None:
        return None

    if isinstance(
        value,
        dict,
    ):
        value = (
            value.get(
                "score"
            )
            or value.get(
                "base_score"
            )
        )

    try:
        score = float(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if score < 0 or score > 10:
        return None

    return score

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
def _vulnerability_id(
    item: dict[str, Any],
    index: int,
) -> str:
    """Extract or generate a vulnerability identifier."""
    value = (
        item.get(
            "id"
        )
        or item.get(
            "vulnerability_id"
        )
        or item.get(
            "cve"
        )
        or item.get(
            "ghsa"
        )
        or item.get(
            "advisory"
        )
    )

    if value is None:
        return f"sca-{index + 1}"

    return str(
        value
    ).strip()

@classmethod
def _build_remediation(
    cls,
    package_name: str,
    installed_version: str,
    fixed_version: str,
    item: dict[str, Any],
) -> str:
    """Build actionable dependency remediation guidance."""
    explicit = (
        cls._string(
            item.get(
                "remediation"
            )
        )
        or cls._string(
            item.get(
                "recommendation"
            )
        )
    )

    if explicit:
        return explicit

    if fixed_version:
        if installed_version:
            return (
                f"Upgrade '{package_name}' from "
                f"{installed_version} to "
                f"{fixed_version} or a later secure version."
            )

        return (
            f"Upgrade '{package_name}' to "
            f"{fixed_version} or a later secure version."
        )

    return (
        f"Upgrade '{package_name}' to a supported "
        "version that is not affected by the vulnerability."
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

@staticmethod
def _tool_configuration(
    configuration: ScanConfiguration,
):
    """Find the SCA tool configuration if one exists."""
    for tool in configuration.tools:
        if tool.name.strip().lower() == "sca":
            return tool

    return None
```
