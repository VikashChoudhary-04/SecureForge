"""Regression suite runner for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .engine import RegressionEngine
from .executors import SecureCommerceRegressionExecutor
from .loader import RegressionLoader
from .models import RegressionSuiteResult


@dataclass(frozen=True)
class RegressionRunConfiguration:
    """Configuration required to execute a regression suite."""

    suite_path: Path
    base_url: str = "http://127.0.0.1:5000"
    timeout: float = 5.0
    source_root: Path | None = None
    infrastructure_root: Path | None = None


class RegressionRunner:
    """Load and execute a configured regression suite."""

    def __init__(
        self,
        *,
        loader: RegressionLoader | None = None,
        engine: RegressionEngine | None = None,
    ) -> None:
        self.loader = (
            loader
            if loader is not None
            else RegressionLoader()
        )

        self.engine = (
            engine
            if engine is not None
            else RegressionEngine()
        )

    def run(
        self,
        configuration: RegressionRunConfiguration,
    ) -> RegressionSuiteResult:
        """Load the configured suite and execute it."""
        suite = self.loader.load(
            configuration.suite_path
        )

        executor = SecureCommerceRegressionExecutor(
            base_url=configuration.base_url,
            timeout=configuration.timeout,
            source_root=configuration.source_root,
            infrastructure_root=(
                configuration.infrastructure_root
            ),
        )

        return self.engine.run_suite(
            suite,
            executor.execute,
        )


def build_regression_runner() -> RegressionRunner:
    """Build the default regression runner."""
    return RegressionRunner()


__all__ = [
    "RegressionRunConfiguration",
    "RegressionRunner",
    "build_regression_runner",
]
