"""Tests for persistent SecureForge scan-result storage."""

import json
from pathlib import Path

import pytest

from secureforge.core.scan import (
    ScanResultStore,
    ScanResultStoreError,
)


def test_scan_store_saves_complete_result(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Persist a complete security scan result."""
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

    assert path.is_file()

    payload = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    assert "scan" in payload
    assert "findings" in payload
    assert "pipeline" in payload

    assert "risk" in payload["pipeline"]
    assert "policy" in payload["pipeline"]
    assert "release_gate" in payload["pipeline"]


def test_scan_store_loads_saved_result(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Load a previously persisted scan result."""
    store = ScanResultStore(
        directory=tmp_path
    )

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

    assert len(
        loaded["findings"]
    ) == len(
        sample_scan_result.findings
    )

    assert loaded["pipeline"]["risk"]["score"] == (
        sample_scan_result.pipeline.risk.score
    )


def test_scan_store_exists(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Check whether a persisted scan exists."""
    store = ScanResultStore(
        directory=tmp_path
    )

    scan_id = (
        sample_scan_result.execution.scan_id
    )

    assert store.exists(scan_id) is False

    store.save(
        sample_scan_result
    )

    assert store.exists(scan_id) is True


def test_scan_store_path_for(
    tmp_path: Path,
) -> None:
    """Return the deterministic path for a scan identifier."""
    store = ScanResultStore(
        directory=tmp_path
    )

    assert store.path_for(
        "scan-001"
    ) == (
        tmp_path
        / "scan-001.json"
    )


def test_scan_store_supports_explicit_scan_id(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Allow callers to override the stored scan identifier."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = store.save(
        sample_scan_result,
        scan_id="custom-scan-001",
    )

    assert path == (
        tmp_path
        / "custom-scan-001.json"
    )

    assert store.exists(
        "custom-scan-001"
    )


def test_scan_store_rejects_empty_identifier(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject an empty scan identifier."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="must not be empty",
    ):
        store.save(
            sample_scan_result,
            scan_id="",
        )


def test_scan_store_rejects_path_separator(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject path traversal through scan identifiers."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="invalid path component",
    ):
        store.save(
            sample_scan_result,
            scan_id="../escape",
        )


def test_scan_store_rejects_backslash(
    sample_scan_result,
    tmp_path: Path,
) -> None:
    """Reject Windows-style path traversal."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="invalid path component",
    ):
        store.save(
            sample_scan_result,
            scan_id=r"..\escape",
        )


def test_scan_store_rejects_missing_result(
    tmp_path: Path,
) -> None:
    """Raise an explicit error for an unknown scan."""
    store = ScanResultStore(
        directory=tmp_path
    )

    with pytest.raises(
        ScanResultStoreError,
        match="Scan result not found",
    ):
        store.load(
            "missing-scan"
        )


def test_scan_store_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """Reject a corrupted persisted scan result."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "scan-001.json"
    )

    path.write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="contains invalid JSON",
    ):
        store.load(
            "scan-001"
        )


def test_scan_store_rejects_non_object_json(
    tmp_path: Path,
) -> None:
    """Reject a persisted JSON array."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "scan-001.json"
    )

    path.write_text(
        json.dumps(
            ["not", "an", "object"]
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="must contain a JSON object",
    ):
        store.load(
            "scan-001"
        )


def test_scan_store_rejects_missing_required_section(
    tmp_path: Path,
) -> None:
    """Reject persisted results missing required sections."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "scan-001.json"
    )

    path.write_text(
        json.dumps(
            {
                "scan": {},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="missing required sections",
    ):
        store.load(
            "scan-001"
        )


def test_scan_store_rejects_invalid_pipeline(
    tmp_path: Path,
) -> None:
    """Reject persisted results with an invalid pipeline."""
    store = ScanResultStore(
        directory=tmp_path
    )

    path = (
        tmp_path
        / "scan-001.json"
    )

    path.write_text(
        json.dumps(
            {
                "scan": {},
                "findings": [],
                "pipeline": {
                    "risk": {},
                    "policy": {},
                    "release_gate": {},
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ScanResultStoreError,
        match="missing required sections",
    ):
        store.load(
            "scan-001"
        )
