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
    def __init__(self, directory: str | Path = ".secureforge/scans") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def _validate_scan_id(self, scan_id: str) -> None:
        if not isinstance(scan_id, str) or not scan_id:
            raise ScanResultStoreError("Scan identifier must not be empty.")
        if "/" in scan_id or "\\" in scan_id:
            raise ScanResultStoreError(
                "Scan identifier contains an invalid path component."
            )
        if scan_id in {".", ".."}:
            raise ScanResultStoreError(
                "Scan identifier contains an invalid path component."
            )

    def path_for(self, scan_id: str) -> Path:
        self._validate_scan_id(scan_id)
        return self.directory / f"{scan_id}.json"

    def save(
        self,
        result: SecurityScanResult,
        scan_id: str | None = None,
    ) -> Path:
        if scan_id is not None:
            self._validate_scan_id(scan_id)
            resolved_scan_id = scan_id
        else:
            resolved_scan_id = self._scan_id(result)
            self._validate_scan_id(resolved_scan_id)

        payload = self._serialize_result(result, resolved_scan_id)
        path = self.path_for(resolved_scan_id)

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

    def load(self, scan_id: str) -> dict[str, Any]:
        path = self.path_for(scan_id)
        if not path.is_file():
            raise ScanResultStoreError(
                f"Scan result not found: '{scan_id}'."
            )

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' contains invalid JSON."
            ) from exc
        except OSError as exc:
            raise ScanResultStoreError(
                f"Unable to read scan result '{scan_id}'."
            ) from exc

        if not isinstance(payload, dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' must contain a JSON object."
            )

        self._validate_payload(payload, scan_id)
        return deepcopy(payload)

    def exists(self, scan_id: str) -> bool:
        return self.path_for(scan_id).is_file()

    @staticmethod
    def _scan_id(result: SecurityScanResult) -> str:
        if getattr(result, "scan_id", None):
            return result.scan_id
        if result.execution.scan_id:
            return result.execution.scan_id
        raise ScanResultStoreError("SecurityScanResult must contain a scan ID.")

    @classmethod
    def _serialize_result(
        cls,
        result: SecurityScanResult,
        scan_id: str,
    ):
        payload = (
            result.model_dump(mode="json")
            if hasattr(result, "model_dump")
            else cls._to_jsonable(result)
        )
        if not isinstance(payload, dict):
            raise ScanResultStoreError(
                "SecurityScanResult must serialize to a JSON object."
            )

        execution = payload.get("execution", {})
        if not isinstance(execution, dict):
            execution = {}

        execution["scan_id"] = scan_id

        pipeline_obj = getattr(result, "pipeline", None)
        if pipeline_obj is not None and hasattr(pipeline_obj, "to_dict"):
            pipeline = cls._to_jsonable(pipeline_obj.to_dict())
        else:
            pipeline = payload.get("pipeline", {})

        if not isinstance(pipeline, dict):
            pipeline = {}

        payload["execution"] = execution
        payload["scan"] = execution
        payload["findings"] = payload.get("findings", [])
        payload["pipeline"] = pipeline
        return payload

    @staticmethod
    def _to_jsonable(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dataclass_fields__"):
            from dataclasses import asdict

            return asdict(value)
        if isinstance(value, dict):
            return {
                str(key): ScanResultStore._to_jsonable(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [ScanResultStore._to_jsonable(item) for item in value]
        return value

    @staticmethod
    def _validate_payload(
        payload: dict[str, Any],
        scan_id: str,
    ) -> None:
        required_sections = {"scan", "findings", "pipeline"}
        if not required_sections.issubset(payload):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if not isinstance(payload["scan"], dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )
        if not isinstance(payload["findings"], list):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )
        if not isinstance(payload["pipeline"], dict):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        pipeline = payload["pipeline"]
        required_pipeline = {"risk", "policy", "release_gate"}
        if not required_pipeline.issubset(pipeline):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )

        if not all(
            isinstance(pipeline[key], dict) and bool(pipeline[key])
            for key in required_pipeline
        ):
            raise ScanResultStoreError(
                f"Scan result '{scan_id}' is missing required sections."
            )


__all__ = ["ScanResultStore", "ScanResultStoreError"]

