"""Finding persistence helpers for SecureForge."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class FindingStoreError(RuntimeError):
    """Raised when finding persistence fails."""


class FindingStore:
    """Persist normalized findings as JSON."""

    filename = "findings.json"

    def save(
        self,
        findings: list[Finding],
        directory: Path,
    ) -> Path:
        """Save findings to a JSON file."""
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = directory / self.filename

        try:
            payload = [
                finding.model_dump(
                    mode="json"
                )
                for finding in findings
            ]

            path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError) as exc:
            raise FindingStoreError(
                f"Unable to save findings: {exc}"
            ) from exc

        return path

    def load(
        self,
        path: Path,
    ) -> list[Finding]:
        """Load findings from a JSON file."""
        if not path.exists():
            raise FindingStoreError(
                f"Finding file does not exist: {path}"
            )

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise FindingStoreError(
                f"Unable to read findings: {exc}"
            ) from exc

        if not isinstance(payload, list):
            raise FindingStoreError(
                "Finding store must contain a JSON list."
            )

        try:
            return [
                Finding.model_validate(item)
                for item in payload
            ]
        except (TypeError, ValueError) as exc:
            raise FindingStoreError(
                f"Invalid finding data: {exc}"
            ) from exc
