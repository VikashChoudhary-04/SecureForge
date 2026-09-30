"""Security tool subprocess execution for SecureForge."""

from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime, timezone

from secureforge.core.config import ToolConfiguration

from .models import (
    ToolExecutionResult,
    ToolExecutionStatus,
)


class ScanExecutionError(Exception):
    """Base exception for scan tool execution failures."""


class ToolExecutor:
    """Execute configured security tools as controlled subprocesses."""

    def execute(
        self,
        tool: ToolConfiguration,
    ) -> ToolExecutionResult:
        """Execute one configured security tool."""
        command = self._build_command(tool)
        started_at = self._utc_now()
        start_time = time.monotonic()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=tool.timeout_seconds,
                check=False,
                env=self._build_environment(tool),
            )

            duration = time.monotonic() - start_time
            completed_at = self._utc_now()

            status = (
                ToolExecutionStatus.SUCCESS
                if completed.returncode == 0
                else ToolExecutionStatus.FAILED
            )

            error = None

            if status == ToolExecutionStatus.FAILED:
                error = (
                    f"Tool '{tool.name}' exited with "
                    f"code {completed.returncode}."
                )

            return ToolExecutionResult(
                tool_name=tool.name,
                integration=tool.name,
                status=status,
                command=command,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                duration_seconds=duration,
                error=error,
                started_at=started_at,
                completed_at=completed_at,
                metadata=tool.metadata,
            )

        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start_time
            completed_at = self._utc_now()

            stdout = self._decode_output(
                exc.stdout
            )
            stderr = self._decode_output(
                exc.stderr
            )

            return ToolExecutionResult(
                tool_name=tool.name,
                integration=tool.name,
                status=ToolExecutionStatus.TIMEOUT,
                command=command,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                error=(
                    f"Tool '{tool.name}' exceeded the "
                    f"{tool.timeout_seconds}-second timeout."
                ),
                started_at=started_at,
                completed_at=completed_at,
                metadata=tool.metadata,
            )

        except FileNotFoundError:
            duration = time.monotonic() - start_time
            completed_at = self._utc_now()

            return ToolExecutionResult(
                tool_name=tool.name,
                integration=tool.name,
                status=ToolExecutionStatus.FAILED,
                command=command,
                duration_seconds=duration,
                error=(
                    f"Executable for tool '{tool.name}' "
                    "was not found."
                ),
                started_at=started_at,
                completed_at=completed_at,
                metadata=tool.metadata,
            )

        except OSError as exc:
            duration = time.monotonic() - start_time
            completed_at = self._utc_now()

            return ToolExecutionResult(
                tool_name=tool.name,
                integration=tool.name,
                status=ToolExecutionStatus.FAILED,
                command=command,
                duration_seconds=duration,
                error=(
                    f"Failed to execute tool "
                    f"'{tool.name}': {exc}"
                ),
                started_at=started_at,
                completed_at=completed_at,
                metadata=tool.metadata,
            )

    def execute_many(
        self,
        tools: list[ToolConfiguration],
    ) -> list[ToolExecutionResult]:
        """Execute multiple configured tools sequentially."""
        return [
            self.execute(tool)
            for tool in tools
        ]

    @staticmethod
    def _build_command(
        tool: ToolConfiguration,
    ) -> list[str]:
        """Build the final subprocess command."""
        if tool.command:
            return [
                *tool.command,
                *tool.arguments,
            ]

        if tool.executable:
            return [
                tool.executable,
                *tool.arguments,
            ]

        raise ValueError(
            f"Tool '{tool.name}' does not define "
            "a command or executable."
        )

    @staticmethod
    def _build_environment(
        tool: ToolConfiguration,
    ) -> dict[str, str] | None:
        """Build the process environment when configured."""
        if not tool.environment:
            return None

        environment = os.environ.copy()
        environment.update(tool.environment)

        return environment

    @staticmethod
    def _decode_output(
        output: str | bytes | None,
    ) -> str:
        """Normalize subprocess timeout output to text."""
        if output is None:
            return ""

        if isinstance(output, bytes):
            return output.decode(
                "utf-8",
                errors="replace",
            )

        return output

    @staticmethod
    def _utc_now() -> datetime:
        """Return the current UTC timestamp."""
        return datetime.now(timezone.utc)


class ScanExecutor(ToolExecutor):
    """Compatibility executor exposed by the scan package API."""


def build_scan_executor() -> ScanExecutor:
    """Build and return a SecureForge scan executor."""
    return ScanExecutor()


__all__ = [
    "ScanExecutionError",
    "ScanExecutor",
    "ToolExecutor",
    "build_scan_executor",
]
