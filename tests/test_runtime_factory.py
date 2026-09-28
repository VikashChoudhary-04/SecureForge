# SecureForge runtime factory tests

from secureforge.config.runtime import (
    SecureForgeRuntime,
    build_runtime,
)


def test_build_runtime_returns_secureforge_runtime() -> None:
    runtime = build_runtime(
        profile="quick",
        source_path=None,
        target=None,
    )

    assert isinstance(
        runtime,
        SecureForgeRuntime,
    )


def test_build_runtime_creates_orchestrator() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.orchestrator is not None


def test_build_runtime_creates_scan_store() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.store is not None


def test_build_runtime_creates_pipeline() -> None:
    runtime = build_runtime(
        profile="quick",
    )

    assert runtime.pipeline is not None


def test_build_runtime_supports_standard_profile() -> None:
    runtime = build_runtime(
        profile="standard",
    )

    assert runtime.orchestrator is not None
    assert runtime.pipeline is not None


def test_build_runtime_supports_full_profile() -> None:
    runtime = build_runtime(
        profile="full",
    )

    assert runtime.orchestrator is not None
    assert runtime.pipeline is not None
