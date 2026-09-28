"""Finding identifier helpers for SecureForge."""

from __future__ import annotations

import hashlib
import re


class FindingIdentifierError(ValueError):
    """Raised when a finding identifier cannot be generated."""


def build_finding_id(
    *,
    source: str,
    title: str,
    asset: str,
    endpoint: str | None = None,
    parameter: str | None = None,
) -> str:
    """Generate a stable SecureForge finding identifier."""
    values = [
        source,
        title,
        asset,
        endpoint or "",
        parameter or "",
    ]

    normalized = "|".join(
        _normalize_identifier_component(value)
        for value in values
    )

    digest = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()[:12]

    source_prefix = _normalize_identifier_component(
        source
    ).upper()

    if not source_prefix:
        source_prefix = "UNKNOWN"

    return f"{source_prefix}-{digest}"


def _normalize_identifier_component(
    value: str,
) -> str:
    """Normalize a value before identifier generation."""
    normalized = value.strip().lower()

    if not normalized:
        return ""

    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    return normalized
