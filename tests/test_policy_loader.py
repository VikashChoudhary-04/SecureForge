"""Tests for the SecureForge policy loader."""

from pathlib import Path

import pytest

from secureforge.core.policy import (
PolicyAction,
PolicyConfig,
PolicyDecision,
PolicyException,
PolicyLoader,
PolicyRule,
)

def build_policy() -> PolicyConfig:
"""Create a representative SecureForge policy."""
return PolicyConfig(
policy_id="default-release-gate",
version="1.0",
rules=[
PolicyRule(
rule_id="BLOCK-CRITICAL",
name="Block critical findings",
description=(
"Critical findings must block the release."
),
severity="critical",
action=PolicyAction.BLOCK,
),
PolicyRule(
rule_id="BLOCK-HIGH",
name="Block high findings",
description=(
"High findings must block the release."
),
severity="high",
action=PolicyAction.BLOCK,
),
PolicyRule(
rule_id="REVIEW-MEDIUM",
name="Review medium findings",
description=(
"Medium findings require security review."
),
severity="medium",
action=PolicyAction.REVIEW,
),
],
exceptions=[
PolicyException(
exception_id="EXC-001",
finding_id="SF-TEST-001",
reason="Temporary accepted risk.",
approved_by="security-team",
expires_at="2026-12-31T23:59:59Z",
compensating_control=(
"Additional monitoring is enabled."
),
)
],
fail_on_tool_error=True,
fail_on_regression_failure=True,
)

def write_yaml(
path: Path,
content: str,
) -> Path:
"""Write YAML content to a temporary file."""
path.write_text(
content,
encoding="utf-8",
)


return path


def test_loader_loads_policy_from_yaml(
tmp_path: Path,
) -> None:
"""Verify a policy can be loaded from YAML."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: default-release-gate
version: "1.0"

rules:

* rule_id: BLOCK-CRITICAL
  name: Block critical findings
  description: Critical findings must block the release.
  severity: critical
  action: block

* rule_id: REVIEW-MEDIUM
  name: Review medium findings
  description: Medium findings require security review.
  severity: medium
  action: review

fail_on_tool_error: true
fail_on_regression_failure: true
""",
)


policy = PolicyLoader().load_file(
    path
)

assert isinstance(
    policy,
    PolicyConfig,
)
assert policy.policy_id == "default-release-gate"
assert policy.version == "1.0"
assert len(policy.rules) == 2
assert policy.rules[0].action == PolicyAction.BLOCK
assert policy.rules[1].action == PolicyAction.REVIEW
assert policy.fail_on_tool_error is True
assert policy.fail_on_regression_failure is True


def test_loader_loads_exceptions(
tmp_path: Path,
) -> None:
"""Verify policy exceptions are loaded correctly."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: exception-policy
version: "1.0"

rules:

* rule_id: BLOCK-HIGH
  name: Block high findings
  description: High findings block release.
  severity: high
  action: block

exceptions:

* exception_id: EXC-001
  finding_id: SF-001
  reason: Temporary accepted risk.
  approved_by: security-team
  expires_at: "2026-12-31T23:59:59Z"
  compensating_control: Additional monitoring.
  enabled: true
  """,
  )

  policy = PolicyLoader().load_file(
  path
  )

  assert len(policy.exceptions) == 1
  assert policy.exceptions[0].exception_id == "EXC-001"
  assert policy.exceptions[0].finding_id == "SF-001"
  assert policy.exceptions[0].approved_by == "security-team"

def test_loader_load_data() -> None:
"""Verify raw dictionaries can be converted into policies."""
data = {
"policy_id": "test-policy",
"version": "1.0",
"rules": [
{
"rule_id": "PASS-LOW",
"name": "Pass low findings",
"description": "Low findings pass.",
"severity": "low",
"action": "pass",
}
],
}


policy = PolicyLoader().load_data(
    data
)

assert policy.policy_id == "test-policy"
assert len(policy.rules) == 1
assert policy.rules[0].action == PolicyAction.PASS


def test_loader_rejects_missing_file(
tmp_path: Path,
) -> None:
"""Verify missing policy files are rejected."""
path = tmp_path / "missing.yaml"


with pytest.raises(
    FileNotFoundError,
    match="was not found",
):
    PolicyLoader().load_file(path)


def test_loader_rejects_directory(
tmp_path: Path,
) -> None:
"""Verify a directory cannot be loaded as a policy."""
path = tmp_path / "policy"


path.mkdir()

with pytest.raises(
    ValueError,
    match="is not a file",
):
    PolicyLoader().load_file(path)


def test_loader_rejects_invalid_yaml(
tmp_path: Path,
) -> None:
"""Verify malformed YAML is rejected."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: test-policy
rules:

* rule_id: BLOCK
  name: Broken
  description: [invalid
  """,
  )

  with pytest.raises(
  ValueError,
  match="Invalid YAML policy file",
  ):
  PolicyLoader().load_file(path)

def test_loader_rejects_empty_file(
tmp_path: Path,
) -> None:
"""Verify empty policy files are rejected."""
path = write_yaml(
tmp_path / "policy.yaml",
"",
)


with pytest.raises(
    ValueError,
    match="Policy file is empty",
):
    PolicyLoader().load_file(path)


def test_loader_rejects_non_mapping_data(
tmp_path: Path,
) -> None:
"""Verify a policy must be represented as a mapping."""
path = write_yaml(
tmp_path / "policy.yaml",
"""

* policy_id: invalid
  """,
  )

  with pytest.raises(
  ValueError,
  match="must contain a YAML mapping",
  ):
  PolicyLoader().load_file(path)

def test_loader_rejects_invalid_policy_field(
tmp_path: Path,
) -> None:
"""Verify invalid policy values are rejected."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: test-policy
version: "1.0"

rules:

* rule_id: INVALID
  name: Invalid action
  description: Invalid action should fail.
  severity: high
  action: destroy
  """,
  )

  with pytest.raises(
  ValueError,
  match="Invalid SecureForge policy",
  ):
  PolicyLoader().load_file(path)

def test_loader_dump_data() -> None:
"""Verify policy models can be serialized."""
policy = build_policy()


data = PolicyLoader.dump_data(
    policy
)

assert data["policy_id"] == "default-release-gate"
assert data["version"] == "1.0"
assert len(data["rules"]) == 3
assert len(data["exceptions"]) == 1
assert data["rules"][0]["action"] == "block"


def test_loader_save_file(
tmp_path: Path,
) -> None:
"""Verify policies can be written to YAML."""
path = tmp_path / "policy.yaml"


policy = build_policy()

PolicyLoader().save_file(
    policy,
    path,
)

assert path.exists()

loaded = PolicyLoader().load_file(
    path
)

assert loaded == policy


def test_loader_round_trip_preserves_policy(
tmp_path: Path,
) -> None:
"""Verify saving and loading preserves the complete policy."""
path = tmp_path / "policy.yaml"


original = build_policy()

loader = PolicyLoader()

loader.save_file(
    original,
    path,
)

loaded = loader.load_file(
    path
)

assert loaded == original


def test_loader_accepts_string_path(
tmp_path: Path,
) -> None:
"""Verify string paths are supported."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: string-path-policy
version: "1.0"
rules: []
""",
)


policy = PolicyLoader().load_file(
    str(path)
)

assert policy.policy_id == "string-path-policy"


def test_loader_preserves_metadata(
tmp_path: Path,
) -> None:
"""Verify policy metadata survives YAML loading."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: metadata-policy
version: "1.0"

metadata:
owner: security
environment: production

rules: []
""",
)


policy = PolicyLoader().load_file(
    path
)

assert policy.metadata == {
    "owner": "security",
    "environment": "production",
}


def test_loader_preserves_disabled_rules(
tmp_path: Path,
) -> None:
"""Verify disabled policy rules are loaded without modification."""
path = write_yaml(
tmp_path / "policy.yaml",
"""
policy_id: disabled-rule-policy
version: "1.0"

rules:

* rule_id: BLOCK-HIGH
  name: Disabled high rule
  description: This rule is currently disabled.
  severity: high
  action: block
  enabled: false
  """,
  )

  policy = PolicyLoader().load_file(
  path
  )

  assert len(policy.rules) == 1
  assert policy.rules[0].enabled is False
