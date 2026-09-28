"""YAML loading utilities for SecureForge security requirements."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import SecurityRequirement
from .registry import RequirementRegistry


class RequirementLoader:
    """Load security requirements from YAML files."""

    def load_file(
        self,
        path: str | Path,
    ) -> list[SecurityRequirement]:
        """Load security requirements from a YAML file."""
        requirements_path = Path(path)

        if not requirements_path.exists():
            raise FileNotFoundError(
                f"Requirements file '{requirements_path}' was not found."
            )

        if not requirements_path.is_file():
            raise ValueError(
                f"Requirements path '{requirements_path}' is not a file."
            )

        try:
            with requirements_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise ValueError(
                f"Invalid YAML requirements file "
                f"'{requirements_path}': {exc}"
            ) from exc

        return self.load_data(data)

    def load_data(
        self,
        data: Any,
    ) -> list[SecurityRequirement]:
        """Validate raw YAML data into security requirements."""
        if data is None:
            raise ValueError(
                "Requirements file is empty."
            )

        if isinstance(data, dict):
            data = data.get("requirements")

        if not isinstance(data, list):
            raise ValueError(
                "Security requirements must be a YAML list "
                "or a mapping containing 'requirements'."
            )

        requirements: list[SecurityRequirement] = []

        for index, item in enumerate(data):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Requirement at index {index} must be a YAML mapping."
                )

            try:
                requirement = SecurityRequirement.model_validate(
                    item
                )
            except Exception as exc:
                raise ValueError(
                    f"Invalid security requirement at index "
                    f"{index}: {exc}"
                ) from exc

            requirements.append(requirement)

        return requirements

    def load_registry(
        self,
        path: str | Path,
    ) -> RequirementRegistry:
        """Load requirements directly into a registry."""
        requirements = self.load_file(path)

        return RequirementRegistry(
            requirements
        )

    @staticmethod
    def dump_data(
        requirements: list[SecurityRequirement],
    ) -> list[dict[str, Any]]:
        """Convert requirement models into serializable dictionaries."""
        return [
            requirement.model_dump(
                mode="json"
            )
            for requirement in requirements
        ]

    def save_file(
        self,
        requirements: list[SecurityRequirement],
        path: str | Path,
    ) -> None:
        """Save security requirements to a YAML file."""
        requirements_path = Path(path)

        requirements_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = {
            "requirements": self.dump_data(
                requirements
            )
        }

        with requirements_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            yaml.safe_dump(
                data,
                file,
                sort_keys=False,
                default_flow_style=False,
            )


__all__ = [
    "RequirementLoader",
]
