"""Persistence helpers for SecureForge scan results."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any

from .models import SecurityScanResult


class ScanResultStoreError(Exception):
    """Base exception for scan result store failures."""


class ScanResultStore:
    """Persist SecureForge scan results as JSON artifacts."""

    def __init__(
        self,
        directory: str | Path,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._lock = RLock()

    def path_for(
        self,
        scan_id: str,
    ) -> Path:
        """Return the deterministic artifact path for a scan."""
        self._validate_scan_id(scan_id)
        return self.directory / f"{scan_id}.json"

    def save(
        self,
        result: SecurityScanResult,
        scan_id: str | None = None,
    ) -> Path:
        """Persist a complete scan result and return its artifact path."""
        resolved_scan_id = scan_id or self._scan_id(result)
        self._validate_scan_id(resolved_scan_id)

        payload = self._serialize_result(
            result,
            resolved_scan_id,
        )

        path = self.path_for(
            resolved_scan_id
        )

        with self._lock:
            path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        return path

    def load(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Load and validate a persisted scan result."""
        path = self.path_for(scan_id)

        if not path.is_file():
            raise ScanResultStoreError(
                f"Scan result not found: '{scan_id}'."
            )

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            if isinstance(exc, json.JSONDecodeError):
                raise ScanResultStoreError(
                    f"Scan result '{scan_id}' contains invalid JSON."
                ) from exc

            raise ScanResultStoreError(
                f"Unable to read scan result '{scan_id}'."
            ) from exc

        if not isinstance(payload, dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' must contain a JSON object."
            )

        self._validate_payload(
            payload,
            scan_id,
        )

        return deepcopy(payload)

    def exists(
        self,
        scan_id: str,
    ) -> bool:
        """Return whether a persisted scan result exists."""
        path = self.path_for(scan_id)
        return path.is_file()

    @staticmethod
    def _scan_id(
        result: SecurityScanResult,
    ) -> str:
        """Extract the canonical scan ID from a result."""
        if result.scan_id:
            return result.scan_id

        if result.execution.scan_id:
            return result.execution.scan_id

        raise ScanResultStoreError(
            "SecurityScanResult must contain a scan ID."
        )

    @staticmethod
    def _validate_scan_id(
        scan_id: str,
    ) -> None:
        """Reject unsafe or empty scan identifiers."""
        if not scan_id:
            raise ScanResultStoreError(
                "Scan ID must not be empty."
            )

        if "/" in scan_id or "\\" in scan_id:
            raise ScanResultStoreError(
                "Scan ID contains an invalid path component."
            )

        if scan_id in {".", ".."}:
            raise ScanResultStoreError(
                "Scan ID contains an invalid path component."
            )

    @classmethod
    def _serialize_result(
        cls,
        result: SecurityScanResult,
        scan_id: str,
    ) -> dict[str, Any]:
        """Convert a scan result into the stable persisted structure."""
        payload = cls._to_jsonable(result)

        if not isinstance(payload, dict):
            raise ScanResultStoreError(
                "SecurityScanResult must serialize to a JSON object."
            )

        execution = payload.get("execution", {})
        if not isinstance(execution, dict):
            execution = {}

        execution.setdefault(
            "scan_id",
            scan_id,
        )

        pipeline = payload.get("pipeline")
        if not isinstance(pipeline, dict):
            pipeline = {}

        pipeline.setdefault(
            "risk",
            {},
        )
        pipeline.setdefault(
            "policy",
            {},
        )
        pipeline.setdefault(
            "release_gate",
            {},
        )

        payload["execution"] = execution
        payload["scan"] = execution
        payload["findings"] = payload.get(
            "findings",
            [],
        )
        payload["pipeline"] = pipeline

        return payload

    @staticmethod
    def _to_jsonable(
        value: Any,
    ) -> Any:
        """Convert Pydantic models and nested values into JSON-safe data."""
        if hasattr(value, "model_dump"):
            return value.model_dump(
                mode="json"
            )

        if isinstance(value, dict):
            return {
                str(key): ScanResultStore._to_jsonable(
                    item
                )
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple)):
            return [
                ScanResultStore._to_jsonable(
                    item
                )
                for item in value
            ]

        if isinstance(value, set):
            return [
                ScanResultStore._to_jsonable(
                    item
                )
                for item in value
            ]

        return value

    @staticmethod
    def _validate_payload(
        payload: dict[str, Any],
        scan_id: str,
    ) -> None:
        """Validate the required persisted result structure."""
        required_sections = {
            "scan",
            "findings",
            "pipeline",
        }

        if not required_sections.issubset(
            payload
        ):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        scan = payload["scan"]
        findings = payload["findings"]
        pipeline = payload["pipeline"]

        if not isinstance(scan, dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if not isinstance(findings, list):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if not isinstance(pipeline, dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        pipeline_sections = {
            "risk",
            "policy",
            "release_gate",
        }

        if not pipeline_sections.issubset(
            pipeline
        ):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if any(
            not isinstance(
                pipeline[section],
                dict,
            )
            for section in pipeline_sections
        ):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if not any(
            pipeline[section]
            for section in pipeline_sections
        ):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )


__all__ = [
    "ScanResultStore",
    "ScanResultStoreError",
]
