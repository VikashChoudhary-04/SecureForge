"""Deterministic scan identifier generation for SecureForge."""

from __future__ import annotations

import hashlib
import re

from secureforge.core.config import ScanProfile

class ScanIdentifier:
"""Generate stable identifiers for SecureForge scan runs."""

    PREFIX = "SCAN"
    
    @classmethod
    def generate(
        cls,
        *,
        application: str,
        version: str,
        profile: ScanProfile | str,
        commit_sha: str | None = None,
        environment: str | None = None,
    ) -> str:
        """Generate a deterministic scan identifier."""
        normalized_application = cls._normalize_required(
            application,
            "application",
        )
        normalized_version = cls._normalize_required(
            version,
            "version",
        )
        normalized_profile = cls._normalize_profile(
            profile
        )
    
        canonical_parts = [
            normalized_application,
            normalized_version,
            normalized_profile,
            cls._normalize(commit_sha),
            cls._normalize(environment),
        ]
    
        canonical_value = "|".join(
            canonical_parts
        )
    
        digest = hashlib.sha256(
            canonical_value.encode("utf-8")
        ).hexdigest()[:12].upper()
    
        return f"{cls.PREFIX}-{digest}"
    
    @classmethod
    def from_configuration(
        cls,
        configuration,
        *,
        commit_sha: str | None = None,
    ) -> str:
        """Generate a scan ID from SecureForge configuration."""
        return cls.generate(
            application=configuration.application,
            version=configuration.version,
            profile=configuration.profile,
            commit_sha=commit_sha,
            environment=configuration.environment,
        )
    
    @staticmethod
    def _normalize_required(
        value: str,
        field_name: str,
    ) -> str:
        """Normalize and validate a required identifier component."""
        normalized = ScanIdentifier._normalize(value)
    
        if not normalized:
            raise ValueError(
                f"{field_name} cannot be empty."
            )
    
        return normalized
    
    @staticmethod
    def _normalize(value: str | None) -> str:
        """Normalize an optional identifier component."""
        if value is None:
            return ""
    
        normalized = str(value).strip().lower()
    
        return re.sub(
            r"\s+",
            " ",
            normalized,
        )
    
    @staticmethod
    def _normalize_profile(
        profile: ScanProfile | str,
    ) -> str:
        """Normalize and validate a scan profile."""
        if isinstance(profile, ScanProfile):
            return profile.value
    
        normalized = str(profile).strip().lower()
    
        try:
            return ScanProfile(normalized).value
        except ValueError as exc:
            supported = ", ".join(
                item.value
                for item in ScanProfile
            )
    
            raise ValueError(
                f"Unsupported scan profile '{profile}'. "
                f"Choose from: {supported}."
            ) from exc
