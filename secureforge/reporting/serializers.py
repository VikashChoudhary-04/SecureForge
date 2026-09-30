"""Serialization helpers for SecureForge security reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import SecurityReport


class SecurityReportSerializer:
    """Serialize SecureForge reports into portable formats."""

    def to_dict(
        self,
        report: SecurityReport,
    ) -> dict[str, Any]:
        """Convert a report into a JSON-compatible dictionary."""
        return report.model_dump(
            mode="json"
        )

    def to_json(
        self,
        report: SecurityReport,
        *,
        indent: int = 2,
    ) -> str:
        """Serialize a report to formatted JSON."""
        return json.dumps(
            self.to_dict(report),
            indent=indent,
            sort_keys=False,
        )

    def write_json(
        self,
        report: SecurityReport,
        path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        """Write a security report to a JSON file."""
        output_path = Path(path)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            self.to_json(
                report,
                indent=indent,
            ),
            encoding="utf-8",
        )

        return output_path


__all__ = [
    "SecurityReportSerializer",
]
