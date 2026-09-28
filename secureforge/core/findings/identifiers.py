"""Deterministic finding identifier generation for SecureForge."""

from __future__ import annotations

import hashlib
import re

class FindingIdentifier:
"""Generate stable SecureForge finding identifiers."""

```
PREFIX = "SF"

@classmethod
def generate(
    cls,
    *,
    source: str,
    title: str,
    asset: str,
    endpoint: str | None = None,
    parameter: str | None = None,
    cwe: str | None = None,
) -> str:
    """Generate a deterministic identifier from finding attributes."""
    canonical_parts = [
        cls._normalize(source),
        cls._normalize(title),
        cls._normalize(asset),
        cls._normalize(endpoint),
        cls._normalize(parameter),
        cls._normalize(cwe),
    ]

    canonical_value = "|".join(canonical_parts)

    digest = hashlib.sha256(
        canonical_value.encode("utf-8")
    ).hexdigest()[:12].upper()

    return f"{cls.PREFIX}-{digest}"

@classmethod
def from_finding_data(
    cls,
    finding_data: dict[str, object],
) -> str:
    """Generate an ID from normalized finding data."""
    return cls.generate(
        source=str(
            finding_data.get(
                "source",
                "",
            )
        ),
        title=str(
            finding_data.get(
                "title",
                "",
            )
        ),
        asset=str(
            finding_data.get(
                "asset",
                "",
            )
        ),
        endpoint=cls._optional_string(
            finding_data.get("endpoint")
        ),
        parameter=cls._optional_string(
            finding_data.get("parameter")
        ),
        cwe=cls._optional_string(
            finding_data.get("cwe")
        ),
    )

@staticmethod
def _optional_string(
    value: object,
) -> str | None:
    """Convert an optional value into a string."""
    if value is None:
        return None

    return str(value)

@staticmethod
def _normalize(
    value: str | None,
) -> str:
    """Normalize an identifier input for deterministic hashing."""
    if value is None:
        return ""

    normalized = value.strip().lower()

    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    return normalized
```
