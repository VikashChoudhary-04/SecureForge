```python id="r3m8wk"
"""Tests for SecureForge scan-result persistence."""

from pathlib import Path

import pytest

from secureforge.core.scan import (
    ScanResultStore,
    ScanResultStoreError,
)


def test_scan_result_store_saves_complete_result(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Persist a complete scan result."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = store.save(
        sample_scan_result
    )

    assert path == (
        tmp_path
        / f"{sample_scan_result.execution.scan_id}.json"
    )
    assert path.exists()

    payload = store.load(
        sample_scan_result.execution.scan_id
    )

    assert "scan" in payload
    assert "findings" in payload
    assert "pipeline" in payload

    assert (
        payload["scan"]["scan_id"]
        == sample_scan_result.execution.scan_id
    )

    assert isinstance(
        payload["findings"],
        list,
    )

    assert isinstance(
        payload["pipeline"],
        dict,
    )


def test_scan_result_store_supports_custom_scan_id(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Persist a result under an explicitly supplied identifier."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = store.save(
        sample_scan_result,
        scan_id="custom-scan",
    )

    assert path == (
        tmp_path
        / "custom-scan.json"
    )

    assert store.exists(
        "custom-scan"
    )


def test_scan_result_store_exists_returns_false(
    tmp_path: Path,
) -> None:
    """Return false when a scan result is absent."""
    store = ScanResultStore(
        directory=tmp_path
    )

    assert not store.exists(
        "missing-scan"
    )


def test_scan_result_store_path_for(
    tmp_path: Path,
) -> None:
    """Return the expected persistence path."""
    store = ScanResultStore(
        directory=tmp_path
    )

    assert store.path_for(
        "scan-001"
    ) == (
        tmp_path
        / "scan-001.json"
    )


def test_scan_result_store_rejects_empty_identifier(
    tmp_path: Path,
) -> None:
    """Reject empty scan identifiers."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="must not be empty",
    ):
        store.exists(" ")


def test_scan_result_store_rejects_path_traversal_identifier(
    tmp_path: Path,
) -> None:
    """Reject identifiers that could escape the storage directory."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="invalid path component",
    ):
        store.path_for(
            "../outside"
        )


def test_scan_result_store_rejects_missing_result(
    tmp_path: Path,
) -> None:
    """Raise an error when a scan result does not exist."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="not found",
    ):
        store.load(
            "missing-scan"
        )


def test_scan_result_store_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """Reject malformed persisted JSON."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "broken.json"
    )

    path.write_text(
        "{invalid",
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="invalid JSON",
    ):
        store.load(
            "broken"
        )


def test_scan_result_store_rejects_non_object_json(
    tmp_path: Path,
) -> None:
    """Reject valid JSON that is not an object."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "list.json"
    )

    path.write_text(
        "[]",
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="JSON object",
    ):
        store.load(
            "list"
        )


def test_scan_result_store_rejects_incomplete_payload(
    tmp_path: Path,
) -> None:
    """Reject persisted data missing required scan sections."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "incomplete.json"
    )

    path.write_text(
        '{"scan": {}}',
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="missing required sections",
    ):
        store.load(
            "incomplete"
        )


def test_scan_result_store_rejects_invalid_section_types(
    tmp_path: Path,
) -> None:
    """Reject persisted data with invalid section types."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "invalid-sections.json"
    )

    path.write_text(
        """
        {
          "scan": [],
          "findings": {},
          "pipeline": "invalid"
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="scan.*object",
    ):
        store.load(
            "invalid-sections"
        )
```
