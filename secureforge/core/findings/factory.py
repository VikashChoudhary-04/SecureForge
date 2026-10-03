"""Factory helpers for constructing SecureForge findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValidationStatus,
)


class FindingFactory:
    """Create normalized Finding objects from scanner data."""

    REQUIRED_FIELDS = (
        "title",
        "source",
        "asset",
        "description",
    )

    def create(
        self,
        data: Mapping[str, Any],
    ) -> Finding:
        """Create a Finding from normalized dictionary data."""
        if not isinstance(data, Mapping):
            raise TypeError(
                "FindingFactory input must be a dictionary"
            )

        values = dict(data)

        missing = [
            field
            for field in self.REQUIRED_FIELDS
            if not str(values.get(field, "")).strip()
        ]

        if missing:
            raise ValueError(
                "Missing required finding fields: "
                + ", ".join(missing)
            )

        values["finding_id"] = self._finding_id(values)
        values["severity"] = self._severity(
            values.get("severity", Severity.INFO)
        )
        values["confidence"] = self._confidence(
            values.get("confidence", Confidence.MEDIUM)
        )
        values["status"] = self._status(
            values.get("status", FindingStatus.OPEN)
        )
        values["validation_status"] = self._validation_status(
            values.get(
                "validation_status",
                ValidationStatus.NOT_VALIDATED,
            )
        )

        return Finding(**values)

    def create_many(
        self,
        items: Sequence[Mapping[str, Any]],
    ) -> list[Finding]:
        """Create multiple Finding objects."""
        return [
            self.create(item)
            for item in items
        ]

    def _severity(
        self,
        value: Severity | str,
    ) -> Severity:
        """Normalize a severity value."""
        if isinstance(value, Severity):
            return value

        normalized = str(value).strip().lower()

        try:
            return Severity(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid finding severity: {value}"
            ) from exc

    def _confidence(
        self,
        value: Confidence | str,
    ) -> Confidence:
        """Normalize a confidence value."""
        if isinstance(value, Confidence):
            return value

        normalized = str(value).strip().lower()

        try:
            return Confidence(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid finding confidence: {value}"
            ) from exc

    def _status(
        self,
        value: FindingStatus | str,
    ) -> FindingStatus:
        """Normalize a finding lifecycle status."""
        if isinstance(value, FindingStatus):
            return value

        normalized = str(value).strip().lower()

        try:
            return FindingStatus(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid finding status: {value}"
            ) from exc

    def _validation_status(
        self,
        value: ValidationStatus | str,
    ) -> ValidationStatus:
        """Normalize a validation status."""
        if isinstance(value, ValidationStatus):
            return value

        normalized = str(value).strip().lower()

        try:
            return ValidationStatus(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid validation status: {value}"
            ) from exc

    def _finding_id(
        self,
        data: Mapping[str, Any],
    ) -> str:
        """Return an explicit or deterministic finding identifier."""
        explicit = data.get("finding_id")

        if explicit:
            return str(explicit)

        import hashlib
        import json

        identity = {
            "source": data.get("source"),
            "title": data.get("title"),
            "asset": data.get("asset"),
            "application": data.get(
                "application",
                "SecureCommerce",
            ),
            "endpoint": data.get("endpoint"),
            "parameter": data.get("parameter"),
            "cwe": data.get("cwe"),
            "owasp": data.get("owasp"),
        }

        serialized = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest().upper()[:12]

        return f"SF-{digest}"
        

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
    validation_status: ValidationStatus = (
        ValidationStatus.NOT_VALIDATED
    ),
    metadata: Mapping[str, Any] | None = None,
) -> Finding:
    """Build a normalized finding from explicit fields."""
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
