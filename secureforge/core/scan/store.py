```python id="f1k7qp"
"""Persistent storage for SecureForge scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secureforge.core.scan.orchestrator import (
    SecurityScanResult,
)


class ScanResultStoreError(Exception):
    """Raised when a scan result cannot be stored or loaded."""


class ScanResultStore:
    """Persist completed SecureForge scan results as JSON."""

    def __init__(
        self,
        directory: Path = Path("reports/scans"),
    ) -> None:
        self.directory = directory

    def save(
        self,
        result: SecurityScanResult,
        *,
        scan_id: str | None = None,
    ) -> Path:
        """Save a complete scan result and return its file path."""
        identifier = (
            scan_id
            if scan_id is not None
            else result.execution.scan_id
        )

        self._validate_identifier(
            identifier
        )

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = self.path_for(
            identifier
        )

        try:
            payload = self._serialize(
                result
            )

            path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                    default=str,
                ),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ScanResultStoreError(
                f"Unable to save scan result: {exc}"
            ) from exc

        return path

    def load(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Load a persisted scan result."""
        self._validate_identifier(
            scan_id
        )

        path = self.path_for(
            scan_id
        )

        if not path.exists():
            raise ScanResultStoreError(
                f"Scan result not found: {path}"
            )

        if not path.is_file():
            raise ScanResultStoreError(
                f"Scan result path is not a file: {path}"
            )

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except OSError as exc:
            raise ScanResultStoreError(
                f"Unable to read scan result: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ScanResultStoreError(
                f"Scan result contains invalid JSON: {exc}"
            ) from exc

        if not isinstance(
            payload,
            dict,
        ):
            raise ScanResultStoreError(
                "Stored scan result must contain a JSON object."
            )

        self._validate_payload(
            payload
        )

        return payload

    def exists(
        self,
        scan_id: str,
    ) -> bool:
        """Return whether a stored scan result exists."""
        self._validate_identifier(
            scan_id
        )

        return self.path_for(
            scan_id
        ).is_file()

    def path_for(
        self,
        scan_id: str,
    ) -> Path:
        """Return the storage path for a scan identifier."""
        self._validate_identifier(
            scan_id
        )

        return (
            self.directory
            / f"{scan_id}.json"
        )

    @staticmethod
    def _serialize(
        result: SecurityScanResult,
    ) -> dict[str, Any]:
        """Serialize a complete scan result."""
        return result.to_dict()

    @staticmethod
    def _validate_identifier(
        identifier: str,
    ) -> None:
        """Validate a scan-result identifier."""
        if not isinstance(
            identifier,
            str,
        ):
            raise ScanResultStoreError(
                "Scan result identifier must be a string."
            )

        if not identifier.strip():
            raise ScanResultStoreError(
                "Scan result identifier must not be empty."
            )

        if (
            "/" in identifier
            or "\\" in identifier
            or identifier in {".", ".."}
        ):
            raise ScanResultStoreError(
                "Scan result identifier contains an invalid path component."
            )

    @staticmethod
    def _validate_payload(
        payload: dict[str, Any],
    ) -> None:
        """Validate the minimum persisted scan-result structure."""
        required_sections = {
            "scan",
            "findings",
            "pipeline",
        }

        missing = (
            required_sections
            - payload.keys()
        )

        if missing:
            missing_values = ", ".join(
                sorted(missing)
            )

            raise ScanResultStoreError(
                "Stored scan result is missing required "
                f"sections: {missing_values}"
            )

        if not isinstance(
            payload["scan"],
            dict,
        ):
            raise ScanResultStoreError(
                "Stored scan result 'scan' section must be an object."
            )

        if not isinstance(
            payload["findings"],
            list,
        ):
            raise ScanResultStoreError(
                "Stored scan result 'findings' section must be a list."
            )

        if not isinstance(
            payload["pipeline"],
            dict,
        ):
            raise ScanResultStoreError(
                "Stored scan result 'pipeline' section must be an object."
            )
```
