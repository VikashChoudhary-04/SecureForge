"""Factory helpers for SecureForge scan runs."""

from __future__ import annotations

from datetime import datetime, timezone

from secureforge.core.config import ScanConfiguration

from .models import ScanRun


class ScanRunFactory:
    """Create initialized ScanRun objects from SecureForge configuration."""

    def create(
        self,
        configuration: ScanConfiguration,
        *,
        commit_sha: str | None = None,
    ) -> ScanRun:
        """Create a scan run from the supplied configuration."""
        started_at = datetime.now(timezone.utc)

        return ScanRun(
            scan_id=configuration.scan_id,
            profile=configuration.profile,
            application=configuration.application,
            version=configuration.version,
            target=configuration.target,
            environment=configuration.environment,
            commit_sha=commit_sha,
            started_at=started_at,
        )
