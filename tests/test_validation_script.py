```python id="3g5r8p"
"""Tests for the SecureForge script validator."""

from secureforge.validation.base import ValidationError
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)
from secureforge.validation.script import ScriptValidator


def build_request(
    command: str,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="SCRIPT-001",
        target="http://localhost:5000",
        method=ValidationMethod.SCRIPT,
        metadata={
            "command": command,
        },
    )


def test_script_validator_supports_script_method() -> None:
    validator = ScriptValidator()

    request = build_request(
        "python -c \"print('ok')\""
    )

    assert validator.supports(request) is True


def test_script_validator_rejects_other_methods() -> None:
    validator = ScriptValidator()

    request = ValidationRequest(
        finding_id="SCRIPT-001",
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert validator.supports(request) is False


def test_script_validator_requires_command() -> None:
    validator = ScriptValidator()

    request = ValidationRequest(
        finding_id="SCRIPT-001",
        target="http://localhost:5000",
        method=ValidationMethod.SCRIPT,
    )

    try:
        validator.validate(request)
    except ValidationError as exc:
        assert "requires a command" in str(exc)
    else:
        raise AssertionError(
            "Expected ValidationError for missing command."
        )


def test_script_validator_rejects_empty_command() -> None:
    validator = ScriptValidator()

    request = build_request("   ")

    try:
        validator.validate(request)
    except ValidationError as exc:
        assert "must not be empty" in str(exc)
    else:
        raise AssertionError(
            "Expected ValidationError for empty command."
        )


def test_script_validator_executes_successful_command() -> None:
    validator = ScriptValidator()

    request = build_request(
        'python -c "print(\'secureforge-script-test\')"'
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "script"
    assert result.finding_id == "SCRIPT-001"
    assert result.evidence
    assert "secureforge-script-test" in (
        result.evidence[0].output or ""
    )


def test_script_validator_reports_nonzero_exit() -> None:
    validator = ScriptValidator()

    request = build_request(
        'python -c "raise SystemExit(3)"'
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.REJECTED
    assert "exit code 3" in result.message
    assert result.evidence[0].observed == "Exit code 3."


def test_script_validator_handles_missing_executable() -> None:
    validator = ScriptValidator()

    request = build_request(
        "secureforge-command-that-does-not-exist-12345"
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.ERROR
    assert result.validator == "script"
    assert result.evidence[0].observed is not None


def test_script_validator_uses_configured_timeout() -> None:
    validator = ScriptValidator(timeout=0.01)

    request = build_request(
        'python -c "import time; time.sleep(1)"'
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.ERROR
    assert "timed out" in result.message.lower()
```
