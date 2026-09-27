"""Generic container security integration for SecureForge."""

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

class GenericContainerIntegration(SecurityIntegration):
"""Adapt generic JSON container-scanner output to SecureForge."""

```
integration_name = "container"
display_name = "Generic Container Security"

DEFAULT_EXECUTABLE = "container-scanner"

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
    """Build the container scanner command."""
    self.validate_configuration(
        configuration
    )

    target = (
        configuration.target.container_image
        or configuration.target.container_path
    )

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
    """Validate the container target."""
    super().validate_configuration(
        configuration
    )

    target = configuration.target

    if not (
        target.container_image
        or target.container_path
    ):
        raise IntegrationConfigurationError(
            "Container scanning requires "
            "target.container_image or "
            "target.container_path."
        )

def supports_target(
    self,
    configuration: ScanConfiguration,
) -> bool:
    """Return whether the target has container data."""
    target = configuration.target

    return bool(
        target.container_image
        or target.container_path
    )

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize generic container scanner output."""
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
                f"Container finding #{index} is not "
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
                f"Container finding #{index} could not "
                f"be normalized: {exc}"
            )

    return NormalizationResult.success_result(
        source=self.integration_name,
        findings=findings,
        warnings=warnings,
        metadata={
            "integration": self.integration_name,
            "source_version": self.version,
            "container_security": True,
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
    """Convert one container result into finding data."""
    title = self._first_value(
        record,
        "title",
        "name",
        "finding",
        "issue",
        "vulnerability",
        default="Container Security Finding",
    )

    finding_type = self._first_value(
        record,
        "type",
        "category",
        "issue_type",
        "vulnerability_type",
        default=title,
    )

    source_id = self._first_value(
        record,
        "id",
        "finding_id",
        "vulnerability_id",
        "rule_id",
        "fingerprint",
        "cve",
        default=f"container-{index}",
    )

    package = self._first_value(
        record,
        "package",
        "package_name",
        "dependency",
        "library",
    )

    installed_version = self._first_value(
        record,
        "installed_version",
        "version",
        "current_version",
    )

    fixed_version = self._first_value(
        record,
        "fixed_version",
        "patched_version",
        "fixed_in",
    )

    image = self._first_value(
        record,
        "image",
        "image_name",
        "container_image",
    )

    endpoint = self._first_value(
        record,
        "path",
        "file",
        "dockerfile",
        "location",
    )

    description = self._first_value(
        record,
        "description",
        "details",
        "message",
        default=(
            f"The container security scanner identified "
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
    )

    if not remediation:
        remediation = self._default_remediation(
            finding_type,
            package,
            installed_version,
            fixed_version,
        )

    metadata: dict[str, Any] = {
        "finding_type": finding_type,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "image": image,
    }

    for key in (
        "cvss",
        "cvss_score",
        "cve",
        "vendor",
        "component",
        "layer",
        "user",
        "ports",
        "privileged",
        "running_as_root",
        "severity",
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
        "endpoint": (
            str(endpoint)
            if endpoint is not None
            else None
        ),
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
            or "SF-CONTAINER-001"
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
            image
            or evidence.target
            or "container"
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
    """Load container scanner JSON."""
    for key in (
        "findings",
        "results",
        "vulnerabilities",
        "issues",
        "misconfigurations",
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
                "Container scanner stdout "
                "is not valid JSON."
            ) from exc

    return []

@staticmethod
def _extract_records(
    raw_data: Any,
) -> list[Any]:
    """Extract container findings from supported structures."""
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
            "vulnerabilities",
            "issues",
            "misconfigurations",
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
def _normalize_severity(
    value: Any,
) -> str:
    """Normalize container severity."""
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
        "important": "high",
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
    """Normalize container confidence."""
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
    """Return contextual impact for common container issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "root",
            "privileged",
            "privilege",
        )
    ):
        return (
            "Running a container with excessive privileges "
            "can increase the impact of a compromise and "
            "may weaken isolation from the host system."
        )

    if any(
        term in normalized
        for term in (
            "cve",
            "vulnerability",
            "package",
            "dependency",
        )
    ):
        return (
            "A vulnerable package in the container image "
            "may expose the deployed application to known "
            "exploitation techniques."
        )

    if any(
        term in normalized
        for term in (
            "port",
            "exposed",
            "network",
        )
    ):
        return (
            "Unnecessary network exposure can increase the "
            "reachable attack surface of the containerized "
            "application."
        )

    return (
        "The container configuration or image may introduce "
        "security weaknesses into the deployed workload."
    )

@staticmethod
def _default_remediation(
    finding_type: Any,
    package: Any,
    installed_version: Any,
    fixed_version: Any,
) -> str:
    """Return remediation guidance for container issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if fixed_version:
        package_name = (
            str(package)
            if package
            else "the affected package"
        )

        return (
            f"Upgrade {package_name} from "
            f"{installed_version or 'the installed version'} "
            f"to {fixed_version} or a later supported version, "
            "rebuild the image, and retest the resulting image."
        )

    if any(
        term in normalized
        for term in (
            "root",
            "running as root",
        )
    ):
        return (
            "Create and run the container with a dedicated "
            "non-root user, verify file permissions, rebuild "
            "the image, and retest the deployed container."
        )

    if any(
        term in normalized
        for term in (
            "privileged",
            "privilege",
        )
    ):
        return (
            "Remove unnecessary privileged capabilities and "
            "grant only the minimum permissions required by "
            "the application."
        )

    if any(
        term in normalized
        for term in (
            "port",
            "exposed",
            "network",
        )
    ):
        return (
            "Remove unnecessary exposed ports and restrict "
            "network access to the minimum required services."
        )

    if package:
        return (
            f"Review and update package {package}, rebuild "
            "the container image, and verify that the issue "
            "is no longer present."
        )

    return (
        "Apply the scanner's recommended secure configuration, "
        "rebuild the container image, and verify the result "
        "with a repeatable security check."
    )

@staticmethod
def _render_command(
    command: list[str],
    target: str,
) -> list[str]:
    """Render a configured container scanner command."""
    return [
        token.replace(
            "{target}",
            target,
        ).replace(
            "{image}",
            target,
        ).replace(
            "{path}",
            target,
        )
        for token in command
    ]
```
