"""Runtime construction for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.config.loader import ConfigLoader
from secureforge.core.correlation.engine import CorrelationEngine
from secureforge.core.policy.engine import PolicyEngine
from secureforge.core.release_gate.engine import ReleaseGateEngine
from secureforge.core.risk.engine import RiskEngine
from secureforge.core.scan.orchestrator import ScanOrchestrator
from secureforge.core.scan.planner import ScanPlanner
from secureforge.core.scan.runner import ScanRunner
from secureforge.core.scan.security_pipeline import SecurityPipeline
from secureforge.core.scan.store import ScanResultStore
from secureforge.integrations.registry_factory import (
    build_default_registry,
)
from secureforge.regression.engine import RegressionEngine
from secureforge.validation.factory import build_validation_engine
from secureforge.validation.planner import ValidationPlanner


@dataclass(frozen=True)
class SecureForgeRuntime:
    """Fully constructed SecureForge runtime."""

    orchestrator: ScanOrchestrator
    store: ScanResultStore
    pipeline: SecurityPipeline


def build_runtime(
    *,
    profile: str = "standard",
    target: str | None = None,
    source_path: Path | None = None,
    config_path: Path | None = None,
) -> SecureForgeRuntime:
    """Build all services required for a SecureForge scan."""
    config_loader = ConfigLoader()

    configuration = config_loader.load(
        profile=profile,
        config_path=config_path,
    )

    integration_registry = build_default_registry(
        configuration=configuration,
    )

    planner = ScanPlanner(
        configuration=configuration,
        registry=integration_registry,
    )

    runner = ScanRunner(
        planner=planner,
        registry=integration_registry,
    )

    correlation_engine = CorrelationEngine()
    risk_engine = RiskEngine()

    policy_engine = PolicyEngine(
        configuration.policy
    )

    release_gate_engine = ReleaseGateEngine()

    regression_engine = RegressionEngine(
        configuration.regression
    )

    validation_engine = build_validation_engine()

    validation_planner = ValidationPlanner(
        validator="secureforge",
    )

    pipeline = SecurityPipeline(
        correlation_engine=correlation_engine,
        risk_engine=risk_engine,
        policy_engine=policy_engine,
        release_gate_engine=release_gate_engine,
        regression_engine=regression_engine,
        validation_engine=validation_engine,
    )

    orchestrator = ScanOrchestrator(
        runner=runner,
        pipeline=pipeline,
        validation_planner=validation_planner,
    )

    store = ScanResultStore()

    return SecureForgeRuntime(
        orchestrator=orchestrator,
        store=store,
        pipeline=pipeline,
    )


__all__ = [
    "SecureForgeRuntime",
    "build_runtime",
]
