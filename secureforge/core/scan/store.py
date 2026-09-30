"""Persistence helpers for SecureForge scan results."""

from __future__ import annotations

from copy import deepcopy
from threading import RLock

from .models import SecurityScanResult


class ScanResultStoreError(Exception):
    """Base exception for scan result store failures."""


class ScanResultStore:
    """In-memory store for scan results.

    The store provides a small persistence abstraction for the current
    SecureForge implementation. It can later be replaced by a database
    or artifact-backed implementation without changing CLI consumers.
    """

    def __init__(self) -> None:
        self._results: dict[str, SecurityScanResult] = {}
        self._lock = RLock()

    def save(
        self,
        result: SecurityScanResult,
    ) -> SecurityScanResult:
        """Save a scan result and return the stored result."""
        scan_id = self._scan_id(result)

        with self._lock:
            stored = deepcopy(result)
            self._results[scan_id] = stored
            return deepcopy(stored)

    def get(
        self,
        scan_id: str,
    ) -> SecurityScanResult | None:
        """Return a scan result by scan ID."""
        with self._lock:
            result = self._results.get(scan_id)

            if result is None:
                return None

            return deepcopy(result)

    def require(
        self,
        scan_id: str,
    ) -> SecurityScanResult:
        """Return a scan result or raise KeyError."""
        result = self.get(scan_id)

        if result is None:
            raise KeyError(
                f"Scan result '{scan_id}' was not found."
            )

        return result

    def delete(
        self,
        scan_id: str,
    ) -> bool:
        """Delete a stored scan result."""
        with self._lock:
            return self._results.pop(
                scan_id,
                None,
            ) is not None

    def list(
        self,
    ) -> list[SecurityScanResult]:
        """Return all stored scan results."""
        with self._lock:
            return [
                deepcopy(result)
                for result in self._results.values()
            ]

    def clear(self) -> None:
        """Remove all stored scan results."""
        with self._lock:
            self._results.clear()

    def exists(
        self,
        scan_id: str,
    ) -> bool:
        """Return whether a scan result exists."""
        with self._lock:
            return scan_id in self._results

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


__all__ = [
    "ScanResultStore",
    "ScanResultStoreError",
]
