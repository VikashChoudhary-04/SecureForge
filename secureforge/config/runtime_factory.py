"""Factories for loading SecureForge runtime scan configuration."""

from __future__ import annotations

from pathlib import Path

from .models import ScanConfiguration
from .runtime import load_runtime_configuration
from .runtime_builder import build_scan_configuration

def load_scan_configuration(
path: str | Path,
) -> ScanConfiguration:
"""Load a YAML configuration and build ScanConfiguration."""
runtime = load_runtime_configuration(path)

return build_scan_configuration(runtime)
