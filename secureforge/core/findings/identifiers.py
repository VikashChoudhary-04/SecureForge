"""Finding identifier helpers for SecureForge."""

from __future__ import annotations

import hashlib
import re
from typing import Any


class FindingIdentifierError(ValueError):
    """Raised when a finding identifier cannot be generated."""


class FindingIdentifier:
    """Generate stable identifiers for normalized findings."""

    PREFIX = "SF-"
    DIGEST_LENGTH = 12

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
        """Generate a deterministic SecureForge finding identifier."""
        values = [
            source,
            title,
            asset,
            endpoint or "",
            parameter or "",
            cwe or "",
        ]

        normalized = "|".join(
            cls._normalize_component(
                value
            )
            for value in values
        )

        digest = hashlib.sha256(
            normalized.encode(
                "utf-8"
            )
        ).hexdigest()[: cls.DIGEST_LENGTH].upper()

        return f"{cls.PREFIX}{digest}"

    @classmethod
    def from_finding_data(
        cls,
        finding: dict[str, Any],
    ) -> str:
        """Generate an identifier from normalized finding data."""
        return cls.generate(
            source=cls._string(
                finding.get(
                    "source"
                )
            ),
            title=cls._string(
                finding.get(
                    "title"
                )
            ),
            asset=cls._string(
                finding.get(
                    "asset"
                )
            ),
            endpoint=cls._optional_string(
                finding.get(
                    "endpoint"
                )
            ),
            parameter=cls._optional_string(
                finding.get(
                    "parameter"
                )
            ),
            cwe=cls._optional_string(
                finding.get(
                    "cwe"
                )
            ),
        )

    @classmethod
    def _normalize_component(
        cls,
        value: Any,
    ) -> str:
        """Normalize a value before hashing."""
        normalized = cls._string(
            value
        ).lower()

        if not normalized:
            return ""

        normalized = re.sub(
            r"\s+",
            " ",
            normalized,
        )

        return normalized

    @staticmethod
    def _string(
        value: Any,
    ) -> str:
        """Convert a value to a normalized string."""
        if value is None:
            return ""

        return str(
            value
        ).strip()

    @staticmethod
    def _optional_string(
        value: Any,
    ) -> str | None:
        """Convert an optional value to a normalized string."""
        if value is None:
            return None

        normalized = str(
            value
        ).strip()

        return normalized or None


def build_finding_id(
    *,
    source: str,
    title: str,
    asset: str,
    endpoint: str | None = None,
    parameter: str | None = None,
    cwe: str | None = None,
) -> str:
    """Generate a stable SecureForge finding identifier."""
    return FindingIdentifier.generate(
        source=source,
        title=title,
        asset=asset,
        endpoint=endpoint,
        parameter=parameter,
        cwe=cwe,
    )


__all__ = [
    "FindingIdentifier",
    "FindingIdentifierError",
    "build_finding_id",
]
