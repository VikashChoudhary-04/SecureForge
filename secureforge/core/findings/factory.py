"""Factory helpers for constructing SecureForge findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValidationStatus,
)


def build_finding(
    *,
    finding_id: str,
    title: str,
    source: str,
    asset: str,
    application: str = "SecureCommerce",
    endpoint: str | None = None,
    parameter: str | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    security_requirement: str | None = None,
    severity: Severity = Severity.INFO,
    confidence: Confidence = Confidence.MEDIUM,
    evidence: list[dict[str, Any]] | None = None,
    description: str = "",
    impact: str = "",
    remediation: str = "",
    status: FindingStatus = FindingStatus.OPEN,
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED,
    metadata: Mapping[str, Any] | None = None,
) -> Finding:
    """Build a normalized finding from integration or test data."""
    finding = Finding(
        finding_id=finding_id,
        title=title,
        source=source,
        asset=asset,
        application=application,
        endpoint=endpoint,
        parameter=parameter,
        cwe=cwe,
        owasp=owasp,
        security_requirement=security_requirement,
        severity=severity,
        confidence=confidence,
        description=description,
        impact=impact,
        remediation=remediation,
        status=status,
        validation_status=validation_status,
        metadata=dict(metadata or {}),
    )

    for item in evidence or []:
        finding.add_evidence(item)

    return finding
