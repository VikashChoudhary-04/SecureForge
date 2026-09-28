"""SecureForge scan profile definitions."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ScanProfile

@dataclass(frozen=True)
class ProfileDefinition:
        """Definition of a SecureForge verification profile."""
        
        profile: ScanProfile
        
        description: str
        
        integrations: tuple[str, ...]
        
        validation_enabled: bool = False
        
        regression_enabled: bool = False
        
        reporting_enabled: bool = True
        
        
        QUICK_PROFILE = ProfileDefinition(
                profile=ScanProfile.QUICK,
                description=(
                "Fast application security verification using "
                "static analysis, dependency analysis, and secret detection."
                ),
                integrations=(
                "sast",
                "sca",
                "secrets",
                ),
        )
        
        STANDARD_PROFILE = ProfileDefinition(
                profile=ScanProfile.STANDARD,
                description=(
                "Balanced security verification covering application, "
                "API, dynamic, and container security."
                ),
                integrations=(
                "sast",
                "sca",
                "secrets",
                "api",
                "dast",
                "container",
                ),
                validation_enabled=True,
                regression_enabled=True,
        )
        
        FULL_PROFILE = ProfileDefinition(
                profile=ScanProfile.FULL,
                description=(
                "Comprehensive verification including application, "
                "API, infrastructure, container, network, and "
                "additional security assessment integrations."
                ),
                integrations=(
                "sast",
                "sca",
                "secrets",
                "api",
                "dast",
                "container",
                "iac",
                "nessus",
                "nmap",
                "manual",
                ),
                validation_enabled=True,
                regression_enabled=True,
        )
        
        _PROFILE_MAP: dict[ScanProfile, ProfileDefinition] = {
                ScanProfile.QUICK: QUICK_PROFILE,
                ScanProfile.STANDARD: STANDARD_PROFILE,
                ScanProfile.FULL: FULL_PROFILE,
        }
        
        def get_profile(profile: ScanProfile | str) -> ProfileDefinition:
                """Return the definition for a SecureForge scan profile."""
                if isinstance(profile, str):
                        try:
                                profile = ScanProfile(profile.lower())
                        except ValueError as exc:
                                supported = ", ".join(
                                item.value
                                for item in ScanProfile
                                )
        
        
                        raise ValueError(
                            f"Unsupported scan profile '{profile}'. "
                            f"Choose from: {supported}."
                        ) from exc
        
                return _PROFILE_MAP[profile]
        
        
        def list_profiles() -> list[ProfileDefinition]:
                """Return all supported SecureForge scan profiles."""
                return list(_PROFILE_MAP.values())
