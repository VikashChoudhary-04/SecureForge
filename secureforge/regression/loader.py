"""Load SecureForge regression tests from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import re

import yaml

from .models import RegressionSuite, RegressionTest


class RegressionConfigurationError(Exception):
    """Raised when regression configuration is invalid."""


class RegressionLoader:
    """Load regression suites from YAML files."""

    def load(self, path: str | Path) -> RegressionSuite:
        configuration_path = Path(path)
        if not configuration_path.is_file():
            raise RegressionConfigurationError(
                f"Regression configuration not found: {configuration_path}"
            )
        raw_text = configuration_path.read_text(
            encoding="utf-8"
        )

        if re.search(
            r"(?im)^\s*enabled\s*:\s*(?:yes|no|on|off)\s*$",
            raw_text,
        ):
            raise RegressionConfigurationError(
                "Regression test 'enabled' must be boolean."
            )

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            raise RegressionConfigurationError(
                "Invalid YAML in regression configuration."
            ) from exc
        if not isinstance(data, dict):
            raise RegressionConfigurationError(
                "Regression configuration must be a YAML mapping."
            )
        return self._build_suite(data)

    def _build_suite(self, data: dict[str, Any]) -> RegressionSuite:
        suite_data = data.get("suite")
        if not isinstance(suite_data, dict):
            raise RegressionConfigurationError(
                "Regression configuration requires a 'suite' mapping."
            )

        suite_id = suite_data.get("id")
        name = suite_data.get("name")
        raw_tests = data.get("tests", suite_data.get("tests"))

        if not isinstance(suite_id, str) or not suite_id.strip():
            raise RegressionConfigurationError(
                "Regression suite requires a non-empty 'id'."
            )
        if not isinstance(name, str) or not name.strip():
            raise RegressionConfigurationError(
                "Regression suite requires a non-empty 'name'."
            )
        if not isinstance(raw_tests, list):
            raise RegressionConfigurationError(
                "Regression suite requires a 'tests' list."
            )

        tests = [
            self._build_test(item, index=index)
            for index, item in enumerate(raw_tests, start=1)
        ]

        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise RegressionConfigurationError(
                "Regression metadata must be a mapping."
            )

        return RegressionSuite(
            suite_id=suite_id.strip(),
            name=name.strip(),
            tests=tests,
            metadata=metadata,
        )

    def _build_test(self, data: Any, *, index: int) -> RegressionTest:
        if not isinstance(data, dict):
            raise RegressionConfigurationError(
                f"Regression test #{index} must be a mapping."
            )

        required_fields = (
            "id", "name", "security_requirement", "description",
            "objective", "target", "expected_result", "failure_condition",
        )
        for field in required_fields:
            value = data.get(field)
            if not isinstance(value, str) or not value.strip():
                raise RegressionConfigurationError(
                    f"Regression test #{index} requires a non-empty '{field}'."
                )

        method = data.get("method", "GET")
        if not isinstance(method, str):
            raise RegressionConfigurationError(
                f"Regression test #{index} 'method' must be a string."
            )

        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RegressionConfigurationError(
                f"Regression test #{index} 'enabled' must be boolean."
            )

        tags = data.get("tags", [])
        if not isinstance(tags, list):
            raise RegressionConfigurationError(
                f"Regression test #{index} 'tags' must be a list."
            )
        if not all(isinstance(tag, str) for tag in tags):
            raise RegressionConfigurationError(
                f"Regression test #{index} tags must contain only strings."
            )

        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise RegressionConfigurationError(
                f"Regression test #{index} 'metadata' must be a mapping."
            )

        return RegressionTest(
            test_id=data["id"].strip(),
            name=data["name"].strip(),
            security_requirement=data["security_requirement"].strip(),
            description=data["description"].strip(),
            objective=data["objective"].strip(),
            target=data["target"].strip(),
            method=method.strip().upper(),
            expected_result=data["expected_result"].strip(),
            failure_condition=data["failure_condition"].strip(),
            enabled=enabled,
            tags=[tag.strip() for tag in tags],
            metadata=metadata,
        )


__all__ = ["RegressionConfigurationError", "RegressionLoader"]
