"""Persistent storage for SecureForge scan results."""

from **future** import annotations

import json
from pathlib import Path
from typing import Any

from secureforge.core.findings.models import Finding
from secureforge.core.scan.orchestrator import (
SecurityScanResult,
)
from secureforge.core.scan.security_pipeline import (
SecurityPipelineResult,
)

class ScanResultStoreError(Exception):
"""Raised when a scan result cannot be stored or loaded."""

class ScanResultStore:
"""Persist completed SecureForge scan results as JSON."""

```
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
    """Save a scan result and return its file path."""
    identifier = (
        scan_id
        if scan_id is not None
        else result.execution.scan_id
    )

    if not identifier.strip():
        raise ScanResultStoreError(
            "Scan result identifier must not be empty."
        )

    self.directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        self.directory
        / f"{identifier}.json"
    )

    try:
        payload = result.to_dict()

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
    if not scan_id.strip():
        raise ScanResultStoreError(
            "Scan result identifier must not be empty."
        )

    path = (
        self.directory
        / f"{scan_id}.json"
    )

    if not path.exists():
        raise ScanResultStoreError(
            f"Scan result not found: {path}"
        )

    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanResultStoreError(
            f"Unable to load scan result: {exc}"
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise ScanResultStoreError(
            "Stored scan result must contain a JSON object."
        )

    return payload

def exists(
    self,
    scan_id: str,
) -> bool:
    """Return whether a stored scan result exists."""
    return (
        self.directory
        / f"{scan_id}.json"
    ).exists()

def path_for(
    self,
    scan_id: str,
) -> Path:
    """Return the storage path for a scan identifier."""
    return (
        self.directory
        / f"{scan_id}.json"
    )
```
