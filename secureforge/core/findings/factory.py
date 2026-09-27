"""Factory for creating SecureForge findings from normalized data."""

from **future** import annotations

from typing import Any

from pydantic import ValidationError

from .identifiers import FindingIdentifier
from .models import (
Confidence,
Finding,
FindingStatus,
Severity,
ValidationStatus,
)

class FindingFactory:
"""Create canonical Finding objects from normalized finding data."""

```
REQUIRED_FIELDS = (
    "title",
    "source",
    "application",
    "asset",
    "severity",
    "description",
    "impact",
    "remediation",
)

def create(
    self,
    data: dict[str, Any],
) -> Finding:
    """Create a Finding from normalized dictionary data."""
    if not isinstance(data, dict):
        raise TypeError(
            "Finding data must be a dictionary."
        )

    self._validate_required_fields(data)

    finding_data = dict(data)

    finding_data["finding_id"] = (
        finding_data.get("finding_id")
        or FindingIdentifier.from_finding_data(
            finding_data
        )
    )

    finding_data["severity"] = self._normalize_severity(
        finding_data["severity"]
    )

    if "confidence" in finding_data:
        finding_data["confidence"] = (
            self._normalize_confidence(
                finding_data["confidence"]
            )
        )

    if "status" in finding_data:
        finding_data["status"] = (
            self._normalize_status(
                finding_data["status"]
            )
        )

    if "validation_status" in finding_data:
        finding_data["validation_status"] = (
            self._normalize_validation_status(
                finding_data["validation_status"]
            )
        )

    try:
        return Finding.model_validate(
            finding_data
        )
    except ValidationError as exc:
        raise ValueError(
            f"Invalid normalized finding data: {exc}"
        ) from exc

def create_many(
    self,
    findings: list[dict[str, Any]],
) -> list[Finding]:
    """Create multiple canonical findings."""
    return [
        self.create(finding)
        for finding in findings
    ]

def _validate_required_fields(
    self,
    data: dict[str, Any],
) -> None:
    """Validate fields required to construct a finding."""
    missing_fields = [
        field
        for field in self.REQUIRED_FIELDS
        if field not in data
        or data[field] is None
        or (
            isinstance(data[field], str)
            and not data[field].strip()
        )
    ]

    if missing_fields:
        raise ValueError(
            "Missing required finding fields: "
            + ", ".join(missing_fields)
            + "."
        )

@staticmethod
def _normalize_severity(
    value: Any,
) -> Severity:
    """Normalize severity values into the Severity enum."""
    if isinstance(value, Severity):
        return value

    try:
        return Severity(
            str(value).strip().lower()
        )
    except ValueError as exc:
        supported = ", ".join(
            severity.value
            for severity in Severity
        )

        raise ValueError(
            f"Invalid finding severity '{value}'. "
            f"Choose from: {supported}."
        ) from exc

@staticmethod
def _normalize_confidence(
    value: Any,
) -> Confidence:
    """Normalize confidence values."""
    if isinstance(value, Confidence):
        return value

    try:
        return Confidence(
            str(value).strip().lower()
        )
    except ValueError as exc:
        supported = ", ".join(
            confidence.value
            for confidence in Confidence
        )

        raise ValueError(
            f"Invalid finding confidence '{value}'. "
            f"Choose from: {supported}."
        ) from exc

@staticmethod
def _normalize_status(
    value: Any,
) -> FindingStatus:
    """Normalize finding lifecycle status."""
    if isinstance(value, FindingStatus):
        return value

    try:
        return FindingStatus(
            str(value).strip().lower()
        )
    except ValueError as exc:
        supported = ", ".join(
            status.value
            for status in FindingStatus
        )

        raise ValueError(
            f"Invalid finding status '{value}'. "
            f"Choose from: {supported}."
        ) from exc

@staticmethod
def _normalize_validation_status(
    value: Any,
) -> ValidationStatus:
    """Normalize finding validation status."""
    if isinstance(value, ValidationStatus):
        return value

    try:
        return ValidationStatus(
            str(value).strip().lower()
        )
    except ValueError as exc:
        supported = ", ".join(
            status.value
            for status in ValidationStatus
        )

        raise ValueError(
            f"Invalid validation status '{value}'. "
            f"Choose from: {supported}."
        ) from exc
```
