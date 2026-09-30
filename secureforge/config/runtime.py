"""Runtime configuration loading and runtime construction for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secureforge.core.scan import (
    ScanOrchestrator,
    ScanResultStore,
    ScanRunner,
    SecurityPipeline,
)


class RuntimeConfigurationError(Exception):
    """Raised when SecureForge runtime configuration is invalid."""


class RuntimeConfiguration:
    """Loaded and validated SecureForge runtime configuration."""

    def __init__(
        self,
        *,
        path: Path,
        data: dict[str, Any],
    ) -> None:
        self.path = path
        self._data = data

    @property
    def project(self) -> dict[str, Any]:
        """Return the project configuration section."""
        return self._section("project")

    @property
    def scan(self) -> dict[str, Any]:
        """Return the scan configuration section."""
        return self._section("scan")

    @property
    def target(self) -> dict[str, Any]:
        """Return the target configuration section."""
        return self._section("target")

    @property
    def integrations(self) -> dict[str, Any]:
        """Return the integrations configuration section."""
        return self._section("integrations")

    @property
    def policy(self) -> dict[str, Any]:
        """Return the policy configuration section."""
        return self._section("policy")

    @property
    def requirements(self) -> dict[str, Any]:
        """Return the requirements configuration section."""
        return self._section("requirements")

    @property
    def output(self) -> dict[str, Any]:
        """Return the output configuration section."""
        return self._section("output")

    @property
    def logging(self) -> dict[str, Any]:
        """Return the logging configuration section."""
        return self._section("logging")

    @property
    def profile(self) -> str:
        """Return the normalized scan profile."""
        profile = self.scan.get("profile")

        if profile is None:
            raise RuntimeConfigurationError(
                "scan.profile is required"
            )

        return str(profile).strip().lower()

    def integration(
        self,
        name: str,
    ) -> dict[str, Any]:
        """Return configuration for one integration."""
        value = self.integrations.get(name)

        if value is None:
            return {}

        if not isinstance(value, dict):
            raise RuntimeConfigurationError(
                f"Integration '{name}' configuration must be a mapping"
            )

        return value

    def enabled_integrations(self) -> list[str]:
        """Return integrations explicitly enabled."""
        enabled: list[str] = []

        for name, configuration in self.integrations.items():
            if not isinstance(configuration, dict):
                raise RuntimeConfigurationError(
                    f"Integration '{name}' configuration must be a mapping"
                )

            if configuration.get("enabled") is True:
                enabled.append(name)

        return enabled

    def _section(
        self,
        name: str,
    ) -> dict[str, Any]:
        """Return a configuration section as a mapping."""
        value = self._data.get(name)

        if value is None:
            return {}

        if not isinstance(value, dict):
            raise RuntimeConfigurationError(
                f"Configuration section '{name}' must be a mapping"
            )

        return value


@dataclass
class SecureForgeRuntime:
    """Runtime services used to execute SecureForge scans."""

    orchestrator: ScanOrchestrator
    store: ScanResultStore
    pipeline: SecurityPipeline
    runner: ScanRunner


def build_runtime(
    *,
    profile: str = "quick",
    source_path: str | Path | None = None,
    target: str | None = None,
) -> SecureForgeRuntime:
    """Build the core SecureForge runtime services."""
    normalized_profile = str(
        profile
    ).strip().lower()

    if normalized_profile not in {
        "quick",
        "standard",
        "full",
        "ci",
    }:
        raise RuntimeConfigurationError(
            f"Unsupported scan profile '{profile}'"
        )

    runner = ScanRunner()
    pipeline = SecurityPipeline()
    store = ScanResultStore()

    orchestrator = ScanOrchestrator(
        runner=runner,
        pipeline=pipeline,
    )

    return SecureForgeRuntime(
        orchestrator=orchestrator,
        store=store,
        pipeline=pipeline,
        runner=runner,
    )


def load_runtime_configuration(
    path: Path | str,
) -> RuntimeConfiguration:
    """Load and validate a SecureForge runtime configuration."""
    configuration_path = Path(path)

    if not configuration_path.exists():
        raise RuntimeConfigurationError(
            f"Configuration file does not exist: {configuration_path}"
        )

    try:
        with configuration_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise RuntimeConfigurationError(
            f"Invalid YAML configuration: {exc}"
        ) from exc
    except OSError as exc:
        raise RuntimeConfigurationError(
            f"Unable to read configuration file: {configuration_path}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeConfigurationError(
            "root configuration value must be a mapping"
        )

    project = data.get("project")

    if not isinstance(project, dict):
        project = {}

    if not project.get("name"):
        raise RuntimeConfigurationError(
            "project.name is required"
        )

    if not project.get("application"):
        raise RuntimeConfigurationError(
            "project.application is required"
        )

    scan = data.get("scan")

    if not isinstance(scan, dict):
        scan = {}

    if not scan.get("profile"):
        raise RuntimeConfigurationError(
            "scan.profile is required"
        )

    integrations = data.get("integrations")

    if not isinstance(integrations, dict):
        raise RuntimeConfigurationError(
            "At least one integration must be configured"
        )

    if not integrations:
        raise RuntimeConfigurationError(
            "At least one integration must be configured"
        )

    for name, configuration in integrations.items():
        if not isinstance(configuration, dict):
            raise RuntimeConfigurationError(
                f"Integration '{name}' configuration must be a mapping"
            )

    normalized_data = dict(data)
    normalized_scan = dict(scan)
    normalized_scan["profile"] = (
        str(scan["profile"]).strip().lower()
    )
    normalized_data["scan"] = normalized_scan

    return RuntimeConfiguration(
        path=configuration_path,
        data=normalized_data,
    )


__all__ = [
    "RuntimeConfiguration",
    "RuntimeConfigurationError",
    "SecureForgeRuntime",
    "build_runtime",
    "load_runtime_configuration",
]
