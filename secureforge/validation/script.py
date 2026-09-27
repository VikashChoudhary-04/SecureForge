```python
"""Controlled script-based security validation for SecureForge."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from .base import (
    BaseValidator,
    ValidationError,
)
from .models import (
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class ScriptValidator(BaseValidator):
    """Execute explicitly configured validation scripts."""

    name = "script"

    def __init__(
        self,
        *,
        timeout: float = 10.0,
    ) -> None:
        self.timeout = timeout

    def supports(
        self,
        request: ValidationRequest,
    ) -> bool:
        """Return whether this validator supports script validation."""
        return (
            request.method
            == ValidationMethod.SCRIPT
        )

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Execute a controlled validation command."""
        command = request.metadata.get(
            "command"
        )

        if not command:
            raise ValidationError(
                "Script validation requires a command "
                "in request metadata."
            )

        if not command.strip():
            raise ValidationError(
                "Script validation command must not be empty."
            )

        validated_at = datetime.now(
            timezone.utc
        ).isoformat()

        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            output = (
                exc.stdout
                if isinstance(
                    exc.stdout,
                    str,
                )
                else ""
            )

            return ValidationResult(
                finding_id=request.finding_id,
                outcome=ValidationOutcome.ERROR,
                message=(
                    "Validation script timed out."
                ),
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.SCRIPT,
                        description=(
                            "Controlled validation script execution."
                        ),
                        command=command,
                        output=output,
                        observed="Command timed out.",
                    )
                ],
                validator=self.name,
                validated_at=validated_at,
            )

        except OSError as exc:
            return ValidationResult(
                finding_id=request.finding_id,
                outcome=ValidationOutcome.ERROR,
                message=(
                    "Validation script could not be executed: "
                    f"{exc}"
                ),
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.SCRIPT,
                        description=(
                            "Controlled validation script execution."
                        ),
                        command=command,
                        observed=str(exc),
                    )
                ],
                validator=self.name,
                validated_at=validated_at,
            )

        output = (
            completed.stdout
            or completed.stderr
        ).strip()

        if completed.returncode == 0:
            outcome = ValidationOutcome.CONFIRMED
            message = (
                "Validation script completed successfully."
            )
        else:
            outcome = ValidationOutcome.REJECTED
            message = (
                "Validation script completed with "
                f"exit code {completed.returncode}."
            )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[
                ValidationEvidence(
                    method=ValidationMethod.SCRIPT,
                    description=(
                        "Controlled validation script execution."
                    ),
                    command=command,
                    output=output,
                    expected="Exit code 0.",
                    observed=(
                        f"Exit code {completed.returncode}."
                    ),
                )
            ],
            validator=self.name,
            validated_at=validated_at,
        )
```
