"""Controlled command-based security validation for SecureForge."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from datetime import datetime, timezone

from .base import BaseValidator, ValidationError
from .models import (
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class CommandValidator(BaseValidator):
    """Execute explicitly allowed validation commands without a shell."""

    name = "command"

    def __init__(
        self,
        *,
        allowed_commands: set[str] | None = None,
        allowlist: set[str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        if (
            allowed_commands is not None
            and allowlist is not None
            and allowed_commands != allowlist
        ):
            raise ValueError(
                "allowed_commands and allowlist must contain the same commands when both are provided."
            )

        self.allowed_commands = (
            allowed_commands
            if allowed_commands is not None
            else allowlist
        ) or {"curl", "nmap"}
        self.timeout = timeout

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.COMMAND

    def validate(self, request: ValidationRequest) -> ValidationResult:
        command_text = request.metadata.get("command")

        if not command_text:
            raise ValidationError(
                "Command validation requires a command."
            )

        if not command_text.strip():
            raise ValidationError(
                "Command must not be empty."
            )

        if any(
            token in command_text
            for token in (
                "&&",
                "||",
                "|",
                ";",
                ">",
                "<",
                "`",
                "$(",
            )
        ):
            raise ValidationError(
                "Shell syntax is not allowed."
            )

        try:
            argv = shlex.split(
                command_text,
                posix=True,
            )
        except ValueError as exc:
            raise ValidationError(
                "Invalid command syntax: "
                f"{exc}"
            ) from exc

        if not argv:
            raise ValidationError(
                "Command must not be empty."
            )

        executable = argv[0]
        if executable in {"python", "python3"} and "-c" in argv:
            index = argv.index("-c")
            if index + 1 < len(argv):
                try:
                    compile(argv[index + 1], "<secureforge-command>", "exec")
                except SyntaxError as exc:
                    raise ValidationError(
                        "Invalid command syntax: " + str(exc)
                    ) from exc
        if executable not in self.allowed_commands:
            raise ValidationError(
                f"Command is not allowed: {executable}"
            )

        resolved = shutil.which(executable)
        if resolved is None:
            raise ValidationError(
                f"Command executable was not found: {executable}"
            )

        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ) as exc:
            return self._result(
                request=request,
                outcome=ValidationOutcome.ERROR,
                message=f"Command execution failed: {exc}",
            )

        if completed.returncode == 0:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="Allowed command completed successfully.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.COMMAND,
                    description="Controlled command validation.",
                    command=command_text,
                    output=completed.stdout,
                    observed=f"Exit code {completed.returncode}.",
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message=(
                f"Command exited with exit code {completed.returncode}."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.COMMAND,
                description="Controlled command validation.",
                command=command_text,
                output=completed.stdout,
                observed=f"Exit code {completed.returncode}.",
            ),
        )

    @staticmethod
    def _result(
        *,
        request: ValidationRequest,
        outcome: ValidationOutcome,
        message: str,
        evidence: ValidationEvidence | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=(
                [evidence]
                if evidence is not None
                else []
            ),
            validator="command",
            validated_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )


__all__ = ["CommandValidator"]
