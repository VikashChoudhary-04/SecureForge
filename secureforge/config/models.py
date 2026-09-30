"""Configuration models for SecureForge runtime configuration."""

from __future__ import annotations

from enum import Enum


class ScanProfile(str, Enum):
    """Supported SecureForge verification profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"


__all__ = [
    "ScanProfile",
]
