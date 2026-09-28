"""Load persisted SecureForge security reports."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from .models import SecurityReport


class SecurityReportLoadError(Exception):
    """Raised when a security report cannot be loaded."""


class SecurityReportLoader:
    """Load validated security reports from JSON files."""

    def load(
        self,
        path: Path,
    ) -> SecurityReport:
        """Load and validate a security report from JSON."""
        if not path.exists():
            raise SecurityReportLoadError(
                f"Security report not found: {path}"
            )

        if not path.is_file():
            raise SecurityReportLoadError(
                f"Security report path is not a file: {path}"
            )

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except OSError as exc:
            raise SecurityReportLoadError(
                f"Unable to read security report: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise SecurityReportLoadError(
                f"Security report contains invalid JSON: {exc}"
            ) from exc

        if not isinstance(
            payload,
            dict,
        ):
            raise SecurityReportLoadError(
                "Security report must contain a JSON object."
            )

        try:
            return SecurityReport.model_validate(
                payload
            )
        except ValidationError as exc:
            raise SecurityReportLoadError(
                "Security report failed schema validation."
            ) from exc


def load_security_report(
    path: Path,
) -> SecurityReport:
    """Load a validated security report from a JSON file."""
    loader = SecurityReportLoader()
    return loader.load(path)
