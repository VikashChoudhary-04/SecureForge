"""Tests for SecureForge validation factories."""

from secureforge.validation import (
    APIValidator,
    CommandValidator,
    HTTPValidator,
    ManualValidator,
    ScriptValidator,
    ValidationEngine,
    build_validation_engine,
    build_validation_registry,
)


def test_build_validation_registry_registers_default_validators() -> None:
    registry = build_validation_registry()

    assert registry.names() == [
        "http",
        "api",
        "command",
        "script",
        "manual",
    ]


def test_build_validation_registry_creates_expected_validator_types() -> None:
    registry = build_validation_registry()

    assert isinstance(registry.get("http"), HTTPValidator)
    assert isinstance(registry.get("api"), APIValidator)
    assert isinstance(registry.get("command"), CommandValidator)
    assert isinstance(registry.get("script"), ScriptValidator)
    assert isinstance(registry.get("manual"), ManualValidator)


def test_build_validation_engine_returns_engine() -> None:
    engine = build_validation_engine()

    assert isinstance(engine, ValidationEngine)
    assert len(engine.registry) == 5


def test_build_validation_engine_accepts_command_allowlist() -> None:
    engine = build_validation_engine(
        command_allowlist={"curl"},
    )

    command_validator = engine.registry.get("command")

    assert isinstance(command_validator, CommandValidator)
    assert command_validator.allowed_commands == {"curl"}


def test_build_validation_engine_accepts_custom_timeouts() -> None:
    engine = build_validation_engine(
        command_timeout=5.0,
        http_timeout=6.0,
        script_timeout=7.0,
        api_timeout=8.0,
    )

    assert engine.registry.get("command").timeout == 5.0
    assert engine.registry.get("http").timeout == 6.0
    assert engine.registry.get("script").timeout == 7.0
    assert engine.registry.get("api").timeout == 8.0
