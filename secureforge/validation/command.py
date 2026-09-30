"""Controlled command-based security validation for SecureForge."""

from __future__ import annotations

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
        """Configure the command validator.

        ``allowlist`` is accepted as a compatibility alias for
        ``allowed_commands`` because the validation factory exposes the
        configuration using that name.
        """
        if allowed_commands is not None and allowlist is not None:
            if allowed_commands != allowlist:
                raise ValueError(
                    "allowed_commands and allowlist must contain the same "
                    "commands when both are provided."
                )

        configured_commands = (
            allowed_commands
            if allowed_commands is not None
            else allowlist
        )

        self.allowed_commands = configured_commands or {
            "curl",
            "nmap",
        }
        self.timeout = timeout

    def supports(self, request: ValidationRequest) -> bool:
        """Return whether this validator supports command validation."""
        return request.method == ValidationMethod.COMMAND

    def validate(self, request: ValidationRequest) -> ValidationResult:
        """Execute a controlled command and interpret its exit status."""
        command_text = request.metadata.get("command")

        if not command_text:
            raise ValidationError(
                "Command validation requires a command in request metadata."
            )

        command = self._parse_command(command_text)
        executable = command[0]

        if executable not in self.allowed_commands:
            raise ValidationError(
                f"Command is not allowed for validation: {executable}"
            )

        executable_path = shutil.which(executable)

        if executable_path is None:
            raise ValidationError(
                f"Validation command is not installed: {executable}"
            )

        command[0] = executable_path
        validated_at = datetime.now(timezone.utc).isoformat()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            output = self._timeout_output(exc)

            return ValidationResult(
                finding_id=request.finding_id,
                outcome=ValidationOutcome.ERROR,
                message="Validation command timed out.",
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.COMMAND,
                        description=(
                            "Controlled command validation without "
                            "shell interpretation."
                        ),
                        command=command_text,
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
                message=f"Validation command failed to execute: {exc}",
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.COMMAND,
                        description=(
                            "Controlled command validation without "
                            "shell interpretation."
                        ),
                        command=command_text,
                        observed=str(exc),
                    )
                ],
                validator=self.name,
                validated_at=validated_at,
            )

        output = self._command_output(completed)

        if completed.returncode == 0:
            outcome = ValidationOutcome.CONFIRMED
            message = "Validation command completed successfully."
        else:
            outcome = ValidationOutcome.REJECTED
            message = (
                "Validation command completed with "
                f"exit code {completed.returncode}."
            )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[
                ValidationEvidence(
                    method=ValidationMethod.COMMAND,
                    description=(
                        "Controlled command validation without "
                        "shell interpretation."
                    ),
                    command=command_text,
                    output=output,
                    expected="Exit code 0.",
                    observed=f"Exit code {completed.returncode}.",
                )
            ],
            validator=self.name,
            validated_at=validated_at,
        )

    def _parse_command(self, command_text: str) -> list[str]:
        """Parse a command without enabling shell syntax."""
        command = command_text.strip()

        if not command:
            raise ValidationError(
                "Command validation command must not be empty."
            )

        forbidden_tokens = (
            ";",
            "&&",
            "||",
            "|",
            ">",
            "<",
            "`",
            "$(",
            "\n",
            "\r",
        )

        for token in forbidden_tokens:
            if token in command:
                raise ValidationError(
                    "Shell syntax is not allowed in command validation."
                )

        try:
            import shlex

            parsed = shlex.split(command)
        except ValueError as exc:
            raise ValidationError(
                f"Invalid command syntax: {exc}"
            ) from exc

        if not parsed:
            raise ValidationError(
                "Command validation command must not be empty."
            )

        return parsed

    @staticmethod
    def _command_output(
        completed: subprocess.CompletedProcess[str],
    ) -> str:
        """Return stdout when available, otherwise stderr."""
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        if stdout and stderr:
            return f"stdout:\n{stdout}\nstderr:\n{stderr}"

        return stdout or stderr

    @staticmethod
    def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
        """Extract available output from a timed-out process."""
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        stdout = stdout.strip()
        stderr = stderr.strip()

        if stdout and stderr:
            return f"stdout:\n{stdout}\nstderr:\n{stderr}"

        return stdout or stderr
