"""Tests for SecureForge scan-result storage."""

import json
from pathlib import Path

import pytest

from secureforge.core.scan.store import (
ScanResultStore,
ScanResultStoreError,
)

def test_scan_result_store_saves_scan_result(
sample_scan_result,
tmp_path: Path,
) -> None:
"""Persist a complete scan result as JSON."""
store = ScanResultStore(
directory=tmp_path
)

```
path = store.save(
    sample_scan_result
)

assert path == (
    tmp_path
    / f"{sample_scan_result.execution.scan_id}.json"
)
assert path.exists()

payload = json.loads(
    path.read_text(
        encoding="utf-8"
    )
)

assert isinstance(
    payload,
    dict,
)
assert "scan" in payload
assert "findings" in payload
assert "pipeline" in payload
```

def test_scan_result_store_loads_saved_result(
sample_scan_result,
tmp_path: Path,
) -> None:
"""Load a previously stored scan result."""
store = ScanResultStore(
directory=tmp_path
)

```
store.save(
    sample_scan_result
)

loaded = store.load(
    sample_scan_result.execution.scan_id
)

assert isinstance(
    loaded,
    dict,
)
assert loaded["scan"]["scan_id"] == (
    sample_scan_result.execution.scan_id
)
```

def test_scan_result_store_exists(
sample_scan_result,
tmp_path: Path,
) -> None:
"""Check whether a scan result exists."""
store = ScanResultStore(
directory=tmp_path
)

```
scan_id = (
    sample_scan_result.execution.scan_id
)

assert store.exists(
    scan_id
) is False

store.save(
    sample_scan_result
)

assert store.exists(
    scan_id
) is True
```

def test_scan_result_store_path_for(
tmp_path: Path,
) -> None:
"""Return the expected path for a scan identifier."""
store = ScanResultStore(
directory=tmp_path
)

```
assert store.path_for(
    "scan-001"
) == (
    tmp_path
    / "scan-001.json"
)
```

def test_scan_result_store_rejects_empty_identifier(
sample_scan_result,
tmp_path: Path,
) -> None:
"""Reject an empty scan identifier."""
store = ScanResultStore(
directory=tmp_path
)

```
with pytest.raises(
    ScanResultStoreError,
    match="identifier must not be empty",
):
    store.save(
        sample_scan_result,
        scan_id="   ",
    )
```

def test_scan_result_store_rejects_empty_load_identifier(
tmp_path: Path,
) -> None:
"""Reject an empty identifier when loading."""
store = ScanResultStore(
directory=tmp_path
)

```
with pytest.raises(
    ScanResultStoreError,
    match="identifier must not be empty",
):
    store.load(
        "   "
    )
```

def test_scan_result_store_raises_for_missing_result(
tmp_path: Path,
) -> None:
"""Raise an explicit error when a result does not exist."""
store = ScanResultStore(
directory=tmp_path
)

```
with pytest.raises(
    ScanResultStoreError,
    match="Scan result not found",
):
    store.load(
        "missing-scan"
    )
```

def test_scan_result_store_rejects_non_object_json(
tmp_path: Path,
) -> None:
"""Reject stored JSON that is not an object."""
store = ScanResultStore(
directory=tmp_path
)

```
path = (
    tmp_path
    / "invalid.json"
)

tmp_path.mkdir(
    parents=True,
    exist_ok=True,
)

path.write_text(
    json.dumps(
        ["invalid"]
    ),
    encoding="utf-8",
)

with pytest.raises(
    ScanResultStoreError,
    match="must contain a JSON object",
):
    store.load(
        "invalid"
    )
```

def test_scan_result_store_rejects_malformed_json(
tmp_path: Path,
) -> None:
"""Reject malformed persisted JSON."""
store = ScanResultStore(
directory=tmp_path
)

```
path = (
    tmp_path
    / "broken.json"
)

path.write_text(
    "{broken",
    encoding="utf-8",
)

with pytest.raises(
    ScanResultStoreError,
    match="Unable to load scan result",
):
    store.load(
        "broken"
    )
```
