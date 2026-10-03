"""Factory helpers for SecureForge scan runs."""

from __future__ import annotations

from secureforge.core.config import ScanConfiguration

from .identifiers import ScanIdentifier
from .models import ScanRun


class ScanRunFactory:
    """Create initialized ScanRun objects from SecureForge configuration."""

    @staticmethod
    def validate_configuration(
        configuration: ScanConfiguration,
    ) -> None:
        """Validate the configuration required to create a scan run."""
        if not configuration.application.strip():
            raise ValueError(
                "Scan application cannot be empty"
            )

        if not configuration.version.strip():
            raise ValueError(
                "Scan version cannot be empty"
            )

        if (
            configuration.target is None
            and configuration.profile != "ci"
        ):
            raise ValueError(
                "Scan target is required for this scan profile"
            )

        if (
            configuration.target is not None
            and not configuration.target.name.strip()
        ):
            raise ValueError(
                "Scan target name cannot be empty"
            )

    def create(
        self,
        configuration: ScanConfiguration,
        *,
        commit_sha: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ScanRun:
        """Create a validated scan run from SecureForge configuration."""
        self.validate_configuration(
            configuration
        )

        scan_metadata = dict(
            configuration.metadata
        )

        target_metadata = {}
        if configuration.target is not None:
            target_metadata = {
                "target_name": configuration.target.name,
                "target_type": configuration.target.target_type.value,
            }

        for key, value in target_metadata.items():
            scan_metadata.setdefault(
                key,
                value,
            )

        if metadata:
            for key, value in metadata.items():
                scan_metadata[key] = value

        scan_id = ScanIdentifier.from_configuration(
            configuration,
            commit_sha=commit_sha,
        )

        return ScanRun(
            scan_id=scan_id,
            profile=configuration.profile,
            application=configuration.application,
            version=configuration.version,
            environment=configuration.environment,
            commit_sha=commit_sha,
            metadata=scan_metadata,
        )


__all__ = [
    "ScanRunFactory",
]
