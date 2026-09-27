"""Generic Infrastructure-as-Code security integration for SecureForge."""

from **future** import annotations

import json
from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import (
NormalizationError,
NormalizationFindingFactory,
NormalizationResult,
RawEvidence,
)

from secureforge.integrations.base import (
IntegrationConfigurationError,
SecurityIntegration,
)

class GenericIACIntegration(SecurityIntegration):
"""Adapt generic IaC scanner output to SecureForge."""

```
integration_name = "iac"
display_name = "Generic Infrastructure-as-Code Security"

DEFAULT_EXECUTABLE = "iac-scanner"

def __init__(
    self,
    *,
    executable: str | None = None,
    command: list[str] | None = None,
    version: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    super().__init__(
        version=version,
        metadata=metadata,
    )

    self.executable = (
        executable
        or self.DEFAULT_EXECUTABLE
    )
    self.command = list(
        command or []
    )

def build_command(
    self,
    configuration: ScanConfiguration,
) -> list[str]:
    """Build the IaC scanner command."""
    self.validate_configuration(
        configuration
    )

    source_path = configuration.target.iac_path

    if self.command:
        return self._render_command(
            self.command,
            source_path,
        )

    return [
        self.executable,
        "--path",
        source_path,
        "--format",
        "json",
    ]

def validate_configuration(
    self,
    configuration: ScanConfiguration,
) -> None:
    """Validate the IaC source path."""
    super().validate_configuration(
        configuration
    )

    if not configuration.target.iac_path:
        raise IntegrationConfigurationError(
            "IaC scanning requires target.iac_path."
        )

def supports_target(
    self,
    configuration: ScanConfiguration,
) -> bool:
    """Return whether the target contains IaC."""
    return bool(
        configuration.target.iac_path
    )

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize generic IaC scanner output."""
    try:
        raw_data = self._load_json(
            evidence.raw_data
        )
    except ValueError as exc:
        return NormalizationResult.failure(
            source=self.integration_name,
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
                f"IaC finding #{index} is not "
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
        except NormalizationError as exc:
            warnings.append(
                f"IaC finding #{index} could not "
                f"be normalized: {exc}"
            )

    return NormalizationResult.success_result(
        source=self.integration_name,
        findings=findings,
        warnings=warnings,
        metadata={
            "integration": self.integration_name,
            "source_version": self.version,
            "iac_security": True,
        },
    )

def create_finding_factory(
    self,
) -> NormalizationFindingFactory:
    """Return the canonical finding factory."""
    return NormalizationFindingFactory()

def _normalize_record(
    self,
    record: dict[str, Any],
    evidence: RawEvidence,
    index: int,
) -> dict[str, Any]:
    """Convert one IaC scanner result into finding data."""
    title = self._first_value(
        record,
        "title",
        "name",
        "finding",
        "issue",
        "check_name",
        default="IaC Security Finding",
    )

    finding_type = self._first_value(
        record,
        "type",
        "category",
        "issue_type",
        "check_type",
        default=title,
    )

    source_id = self._first_value(
        record,
        "id",
        "finding_id",
        "check_id",
        "rule_id",
        "policy_id",
        "fingerprint",
        default=f"iac-{index}",
    )

    resource = self._first_value(
        record,
        "resource",
        "resource_name",
        "resource_address",
        "address",
    )

    file_path = self._first_value(
        record,
        "file",
        "filename",
        "path",
    )

    line = self._first_value(
        record,
        "line",
        "line_number",
    )

    cloud_provider = self._first_value(
        record,
        "provider",
        "cloud_provider",
    )

    service = self._first_value(
        record,
        "service",
        "resource_type",
    )

    description = self._first_value(
        record,
        "description",
        "details",
        "message",
        default=(
            f"The IaC security scanner identified "
            f"{finding_type}."
        ),
    )

    impact = self._first_value(
        record,
        "impact",
        default=self._default_impact(
            finding_type
        ),
    )

    remediation = self._first_value(
        record,
        "remediation",
        "recommendation",
        "solution",
        "fix",
        default=self._default_remediation(
            finding_type
        ),
    )

    location = self._format_location(
        file_path=file_path,
        line=line,
    )

    metadata: dict[str, Any] = {
        "finding_type": finding_type,
        "resource": resource,
        "file": file_path,
        "line": line,
        "cloud_provider": cloud_provider,
        "service": service,
    }

    for key in (
        "policy_id",
        "rule_id",
        "terraform_resource",
        "resource_type",
        "region",
        "account",
        "project",
        "subscription",
        "severity",
        "framework",
        "references",
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
        ),
        "confidence": self._normalize_confidence(
            record.get("confidence")
        ),
        "endpoint": location,
        "parameter": (
            str(resource)
            if resource is not None
            else None
        ),
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
            or "SF-IAC-001"
        ),
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
            resource
            or evidence.target
            or "infrastructure-code"
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
    raw_data: dict[str, Any],
) -> Any:
    """Load IaC scanner JSON."""
    for key in (
        "findings",
        "results",
        "issues",
        "misconfigurations",
        "checks",
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
                pass

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
                "IaC scanner stdout is not valid JSON."
            ) from exc

    return []

@staticmethod
def _extract_records(
    raw_data: Any,
) -> list[Any]:
    """Extract IaC findings from supported structures."""
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
            "issues",
            "misconfigurations",
            "checks",
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
def _format_location(
    *,
    file_path: Any,
    line: Any,
) -> str | None:
    """Format an IaC source location."""
    if not file_path:
        return None

    if line:
        return (
            f"{file_path}:{line}"
        )

    return str(
        file_path
    )

@staticmethod
def _normalize_severity(
    value: Any,
) -> str:
    """Normalize IaC severity."""
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
        "low": "low",
        "minor": "low",
        "negligible": "low",
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
    """Normalize IaC confidence."""
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
def _default_impact(
    finding_type: Any,
) -> str:
    """Return contextual impact for common IaC issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "public",
            "internet",
            "exposed",
            "open",
        )
    ):
        return (
            "An overly exposed infrastructure resource may "
            "be reachable by unauthorized external users, "
            "increasing the application's attack surface."
        )

    if any(
        term in normalized
        for term in (
            "permission",
            "privilege",
            "iam",
            "role",
            "access",
        )
    ):
        return (
            "Excessive permissions can allow a compromised "
            "identity or workload to access resources beyond "
            "its intended security boundary."
        )

    if any(
        term in normalized
        for term in (
            "storage",
            "bucket",
            "database",
            "encryption",
        )
    ):
        return (
            "An insecure infrastructure configuration may "
            "expose sensitive data or weaken protection "
            "against unauthorized access."
        )

    return (
        "The identified infrastructure configuration may "
        "introduce a security weakness into the deployed "
        "environment."
    )

@staticmethod
def _default_remediation(
    finding_type: Any,
) -> str:
    """Return remediation guidance for common IaC issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "public",
            "internet",
            "exposed",
        )
    ):
        return (
            "Restrict the resource to the minimum required "
            "network exposure, remove unnecessary public access, "
            "and verify the resulting infrastructure policy."
        )

    if any(
        term in normalized
        for term in (
            "permission",
            "privilege",
            "iam",
            "role",
        )
    ):
        return (
            "Apply least-privilege permissions, remove "
            "unnecessary actions or resources, and verify "
            "the effective permissions after deployment."
        )

    if any(
        term in normalized
        for term in (
            "storage",
            "bucket",
            "database",
            "encryption",
        )
    ):
        return (
            "Enable the required security controls, restrict "
            "access to authorized principals, and verify "
            "encryption and data-protection settings."
        )

    return (
        "Apply the scanner's recommended secure IaC "
        "configuration and verify the deployed resource "
        "against the intended security requirement."
    )

@staticmethod
def _render_command(
    command: list[str],
    source_path: str,
) -> list[str]:
    """Render a configured IaC scanner command."""
    return [
        token.replace(
            "{path}",
            source_path,
        ).replace(
            "{source}",
            source_path,
        ).replace(
            "{target}",
            source_path,
        )
        for token in command
    ]
```
