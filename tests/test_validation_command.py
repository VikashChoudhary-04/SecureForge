"""Tests for the SecureForge command validator."""

import pytest

from secureforge.validation.command import CommandValidator
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)
from secureforge.validation.base import ValidationError


def build_request(
    command: str,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="CMD-001",
        target="http://localhost:5000",
        method=ValidationMethod.COMMAND,
        metadata={
            "command": command,
        },
    )


def test_command_validator_supports_command_method() -> None:
    validator = CommandValidator(
        allowed_commands={"python"},
    )

    request = build_request("python -c \"print('ok')\"")

    assert validator.supports(request) is True


def test_command_validator_rejects_other_methods() -> None:
    validator = CommandValidator()

    request = ValidationRequest(
        finding_id="CMD-001",
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert validator.supports(request) is False


def test_command_validator_rejects_missing_command() -> None:
    validator = CommandValidator()

    request = ValidationRequest(
        finding_id="CMD-001",
        target="http://localhost:5000",
        method=ValidationMethod.COMMAND,
    )

    with pytest.raises(
        ValidationError,
        match="requires a command",
    ):
        validator.validate(request)


def test_command_validator_rejects_empty_command() -> None:
    validator = CommandValidator()

    request = build_request("   ")

    with pytest.raises(
        ValidationError,
        match="must not be empty",
    ):
        validator.validate(request)


def test_command_validator_rejects_unallowed_command() -> None:
    validator = CommandValidator(
        allowed_commands={"curl"},
    )

    request = build_request("python --version")

    with pytest.raises(
        ValidationError,
        match="Command is not allowed",
    ):
        validator.validate(request)


def test_command_validator_rejects_shell_syntax() -> None:
    validator = CommandValidator(
        allowed_commands={"curl"},
    )

    request = build_request(
        "curl http://localhost:5000 && whoami"
    )

    with pytest.raises(
        ValidationError,
        match="Shell syntax is not allowed",
    ):
        validator.validate(request)


def test_command_validator_rejects_pipeline_syntax() -> None:
    validator = CommandValidator(
        allowed_commands={"curl"},
    )

    request = build_request(
        "curl http://localhost:5000 | whoami"
    )

    with pytest.raises(
        ValidationError,
        match="Shell syntax is not allowed",
    ):
        validator.validate(request)


def test_command_validator_executes_allowed_command() -> None:
    validator = CommandValidator(
        allowed_commands={"python"},
    )

    request = build_request(
        'python -c "print(\'secureforge-test\')"'
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "command"
    assert result.finding_id == "CMD-001"
    assert "secureforge-test" in result.evidence[0].output


def test_command_validator_reports_nonzero_exit() -> None:
    validator = CommandValidator(
        allowed_commands={"python"},
    )

    request = build_request(
        'python -c "raise SystemExit(2)"'
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.REJECTED
    assert "exit code 2" in result.message
    assert result.evidence[0].observed == "Exit code 2."


def test_command_validator_rejects_invalid_command_syntax() -> None:
    validator = CommandValidator(
        allowed_commands={"python"},
    )

    request = build_request(
        'python -c "print(\'unterminated)"'
    )

    with pytest.raises(
        ValidationError,
        match="Invalid command syntax",
    ):
        validator.validate(request)
