"""YAML loading utilities for SecureForge security policies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import PolicyConfig

class PolicyLoader:
"""Load and save SecureForge policy configurations."""

```
def load_file(
    self,
    path: str | Path,
) -> PolicyConfig:
    """Load and validate a policy from a YAML file."""
    policy_path = Path(path)

    if not policy_path.exists():
        raise FileNotFoundError(
            f"Policy file '{policy_path}' was not found."
        )

    if not policy_path.is_file():
        raise ValueError(
            f"Policy path '{policy_path}' is not a file."
        )

    try:
        with policy_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid YAML policy file "
            f"'{policy_path}': {exc}"
        ) from exc

    return self.load_data(data)

def load_data(
    self,
    data: Any,
) -> PolicyConfig:
    """Validate raw policy data."""
    if data is None:
        raise ValueError(
            "Policy file is empty."
        )

    if not isinstance(data, dict):
        raise ValueError(
            "SecureForge policy must contain a YAML mapping."
        )

    try:
        return PolicyConfig.model_validate(
            data
        )
    except Exception as exc:
        raise ValueError(
            f"Invalid SecureForge policy: {exc}"
        ) from exc

@staticmethod
def dump_data(
    policy: PolicyConfig,
) -> dict[str, Any]:
    """Convert a policy model into serializable data."""
    return policy.model_dump(
        mode="json"
    )

def save_file(
    self,
    policy: PolicyConfig,
    path: str | Path,
) -> None:
    """Save a validated policy as YAML."""
    policy_path = Path(path)

    policy_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = self.dump_data(
        policy
    )

    with policy_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            data,
            file,
            sort_keys=False,
            default_flow_style=False,
        )
```
