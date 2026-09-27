"""Generic API security integration for SecureForge."""

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

class GenericAPIIntegration(SecurityIntegration):
"""Adapt generic API-security scanner output to SecureForge."""

```
integration_name = "api"
display_name = "Generic API Security"

DEFAULT_EXECUTABLE = "api-security-scanner"

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
    """Build the API-security scanner command."""
    self.validate_configuration(
        configuration
    )

    target = configuration.target

    if self.command:
        return self._render_command(
            self.command,
            target.openapi_url,
            target.api_base_url,
            target.base_url,
        )

    if target.openapi_url:
        return [
            self.executable,
            "--openapi",
            target.openapi_url,
            "--format",
            "json",
        ]

    return [
        self.executable,
        "--target",
        (
            target.api_base_url
            or target.base_url
        ),
        "--format",
        "json",
    ]

def validate_configuration(
    self,
    configuration: ScanConfiguration,
) -> None:
    """Validate the target required for API security testing."""
    super().validate_configuration(
        configuration
    )

    target = configuration.target

    if not (
        target.openapi_url
        or target.api_base_url
        or target.base_url
    ):
        raise IntegrationConfigurationError(
            "API security scanning requires "
            "target.openapi_url, target.api_base_url, "
            "or target.base_url."
        )

def supports_target(
    self,
    configuration: ScanConfiguration,
) -> bool:
    """Return whether the target exposes an API security surface."""
    target = configuration.target

    return bool(
        target.openapi_url
        or target.api_base_url
        or target.base_url
    )

def normalize(
    self,
    evidence: RawEvidence,
) -> NormalizationResult:
    """Normalize generic API-security scanner output."""
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
                f"API finding #{index} is not "
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
                f"API finding #{index} could not "
                f"be normalized: {exc}"
            )

    return NormalizationResult.success_result(
        source=self.integration_name,
        findings=findings,
        warnings=warnings,
        metadata={
            "integration": self.integration_name,
            "source_version": self.version,
            "api_security": True,
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
    """Convert one API-security result into finding data."""
    title = self._first_value(
        record,
        "title",
        "name",
        "finding",
        "issue",
        default="API Security Finding",
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
        "rule_id",
        "fingerprint",
        default=f"api-{index}",
    )

    endpoint = self._first_value(
        record,
        "endpoint",
        "url",
        "path",
        "route",
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

    endpoint_display = self._format_endpoint(
        method,
        endpoint,
    )

    description = self._first_value(
        record,
        "description",
        "details",
        "message",
        default=(
            f"The API security scanner identified "
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
        "fix",
        default=self._default_remediation(
            finding_type
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

    metadata = {
        "finding_type": finding_type,
        "method": method,
        "endpoint": endpoint,
        "parameter": parameter,
        "api_base_url": (
            evidence.target
        ),
    }

    for key in (
        "request",
        "response",
        "status_code",
        "authentication",
        "authorization",
        "operation_id",
        "schema",
        "tags",
    ):
        if key in record:
            metadata[key] = record[key]

    return {
        "source_finding_id": str(
            source_id
        ),
        "title": str(title),
        "severity": self._normalize_severity(
            record.get("severity")
        ),
        "confidence": self._normalize_confidence(
            record.get("confidence")
        ),
        "endpoint": endpoint_display,
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
            or record.get(
                "owasp_api"
            )
        ),
        "security_requirement": (
            security_requirement
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
            evidence.target
            or "api"
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
    """Load API scanner JSON from raw evidence."""
    for key in (
        "findings",
        "results",
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
                "API security scanner stdout "
                "is not valid JSON."
            ) from exc

    return []

@staticmethod
def _extract_records(
    raw_data: Any,
) -> list[Any]:
    """Extract API findings from supported structures."""
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

        if value is not None and value != "":
            return value

    return default

@staticmethod
def _format_endpoint(
    method: Any,
    endpoint: Any,
) -> str | None:
    """Format an HTTP method and endpoint."""
    if endpoint is None:
        return None

    endpoint_text = str(
        endpoint
    ).strip()

    if not endpoint_text:
        return None

    if method:
        return (
            f"{str(method).upper()} "
            f"{endpoint_text}"
        )

    return endpoint_text

@staticmethod
def _normalize_severity(
    value: Any,
) -> str:
    """Normalize API scanner severity."""
    if value is None:
        return "medium"

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
        "medium",
    )

@staticmethod
def _normalize_confidence(
    value: Any,
) -> str:
    """Normalize API scanner confidence."""
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
def _requirement_for_type(
    finding_type: Any,
) -> str:
    """Map common API security issues to SecureForge requirements."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "bola",
            "idor",
            "object level authorization",
            "object-level authorization",
        )
    ):
        return "SF-AUTHZ-001"

    if any(
        term in normalized
        for term in (
            "function level authorization",
            "function-level authorization",
            "broken function",
            "bfla",
        )
    ):
        return "SF-AUTHZ-002"

    if any(
        term in normalized
        for term in (
            "authentication",
            "unauthenticated",
            "auth bypass",
        )
    ):
        return "SF-AUTH-001"

    if any(
        term in normalized
        for term in (
            "input validation",
            "injection",
            "sql injection",
            "xss",
        )
    ):
        return "SF-INPUT-001"

    return "SF-API-001"

@staticmethod
def _default_impact(
    finding_type: Any,
) -> str:
    """Return contextual impact for common API issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "bola",
            "idor",
            "object level authorization",
        )
    ):
        return (
            "An authorization weakness may allow an attacker "
            "to access or modify another user's resources."
        )

    if any(
        term in normalized
        for term in (
            "function level authorization",
            "broken function",
            "bfla",
        )
    ):
        return (
            "An authorization weakness may allow a lower-privileged "
            "user to invoke functionality intended for a higher "
            "privilege level."
        )

    if any(
        term in normalized
        for term in (
            "excessive data",
            "data exposure",
            "sensitive data",
        )
    ):
        return (
            "The API may expose more information than required, "
            "potentially disclosing sensitive application data."
        )

    if any(
        term in normalized
        for term in (
            "authentication",
            "unauthenticated",
            "auth bypass",
        )
    ):
        return (
            "Weak or missing authentication may allow unauthorized "
            "users to access protected API functionality."
        )

    return (
        "The identified API weakness may affect confidentiality, "
        "integrity, availability, or authorization boundaries."
    )

@staticmethod
def _default_remediation(
    finding_type: Any,
) -> str:
    """Return remediation guidance for common API issues."""
    normalized = str(
        finding_type
    ).strip().lower()

    if any(
        term in normalized
        for term in (
            "bola",
            "idor",
            "object level authorization",
        )
    ):
        return (
            "Enforce server-side object-level authorization "
            "for every resource access and verify that the "
            "authenticated principal owns or is explicitly "
            "authorized to access the requested object."
        )

    if any(
        term in normalized
        for term in (
            "function level authorization",
            "broken function",
            "bfla",
        )
    ):
        return (
            "Enforce server-side function-level authorization "
            "for every privileged operation and deny access "
            "unless the caller has the required role or permission."
        )

    if any(
        term in normalized
        for term in (
            "authentication",
            "unauthenticated",
            "auth bypass",
        )
    ):
        return (
            "Require strong authentication for protected API "
            "operations and verify authentication state on the "
            "server before processing sensitive requests."
        )

    return (
        "Validate the API behavior against the application's "
        "security requirements, enforce server-side controls, "
        "and add a regression test for the confirmed weakness."
    )

@staticmethod
def _render_command(
    command: list[str],
    openapi_url: str | None,
    api_base_url: str | None,
    base_url: str | None,
) -> list[str]:
    """Render a configured API scanner command template."""
    target = (
        api_base_url
        or base_url
        or ""
    )

    rendered: list[str] = []

    for token in command:
        rendered.append(
            token.replace(
                "{openapi}",
                openapi_url or "",
            ).replace(
                "{api_base}",
                target,
            ).replace(
                "{target}",
                target,
            )
        )

    return rendered
```
