"""Tests for the SecureForge regression YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from secureforge.regression import (
RegressionConfigurationError,
RegressionLoader,
)

def write_config(
tmp_path: Path,
content: str,
) -> Path:
"""Write a regression configuration fixture."""
path = (
tmp_path
/ "regression.yaml"
)


path.write_text(
    content,
    encoding="utf-8",
)

return path


def test_loader_builds_regression_suite(tmp_path):
"""Loader should build a typed regression suite."""
path = write_config(
tmp_path,
"""
suite:
id: securecommerce-regression
name: SecureCommerce Security Regression Suite

tests:
- id: BOLA-001
name: BOLA Authorization Regression
security_requirement: SF-AUTHZ-001
description: Verify object-level authorization.
objective: Prevent unauthorized order access.
target: /api/orders/2
method: GET
expected_result: HTTP 403
failure_condition: HTTP 200 exposes another user's order.
enabled: true
tags:
- authorization
- bola
- api


- id: SQLI-001
  name: SQL Injection Regression
  security_requirement: SF-INPUT-001
  description: Verify SQL injection is blocked.
  objective: Prevent SQL query manipulation.
  target: /vulnerable/search-user
  method: GET
  expected_result: Input is safely handled.
  failure_condition: SQL syntax is manipulated by user input.
  enabled: false
  tags:
    - injection
    - sqli


metadata:
application: SecureCommerce
environment: lab
""",
)


suite = RegressionLoader().load(path)

assert suite.suite_id == (
    "securecommerce-regression"
)
assert suite.name == (
    "SecureCommerce Security Regression Suite"
)

assert len(suite.tests) == 2

assert suite.tests[0].test_id == "BOLA-001"
assert suite.tests[0].security_requirement == (
    "SF-AUTHZ-001"
)
assert suite.tests[0].method == "GET"
assert suite.tests[0].enabled is True

assert suite.tests[1].test_id == "SQLI-001"
assert suite.tests[1].enabled is False

assert suite.metadata == {
    "application": "SecureCommerce",
    "environment": "lab",
}


def test_loader_defaults_method_to_get(tmp_path):
"""Missing method should default to GET."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite

tests:
- id: TEST-001
name: Test
security_requirement: SF-API-001
description: Test description.
objective: Test objective.
target: /health
expected_result: HTTP 200
failure_condition: HTTP 500.
""",
)


suite = RegressionLoader().load(path)

assert suite.tests[0].method == "GET"


def test_loader_defaults_enabled_to_true(tmp_path):
"""Missing enabled field should default to true."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite

tests:
- id: TEST-001
name: Test
security_requirement: SF-API-001
description: Test description.
objective: Test objective.
target: /health
expected_result: HTTP 200
failure_condition: HTTP 500.
""",
)


suite = RegressionLoader().load(path)

assert suite.tests[0].enabled is True


def test_loader_rejects_missing_file(tmp_path):
"""Missing configuration files should raise a clear error."""
path = (
tmp_path
/ "missing.yaml"
)


with pytest.raises(
    RegressionConfigurationError,
    match="not found",
):
    RegressionLoader().load(path)


def test_loader_rejects_invalid_yaml(tmp_path):
"""Invalid YAML should produce a configuration error."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: [invalid
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="Invalid YAML",
):
    RegressionLoader().load(path)


def test_loader_rejects_non_mapping_root(tmp_path):
"""The root YAML document must be a mapping."""
path = write_config(
tmp_path,
"""

* invalid
* root
  """,
  )

  with pytest.raises(
  RegressionConfigurationError,
  match="must be a YAML mapping",
  ):
  RegressionLoader().load(path)

def test_loader_rejects_missing_suite(tmp_path):
"""The suite mapping is mandatory."""
path = write_config(
tmp_path,
"""
metadata:
application: SecureCommerce
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="requires a 'suite' mapping",
):
    RegressionLoader().load(path)


def test_loader_rejects_missing_suite_id(tmp_path):
"""A suite must have an ID."""
path = write_config(
tmp_path,
"""
suite:
name: Test Suite
tests: []
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="non-empty 'id'",
):
    RegressionLoader().load(path)


def test_loader_rejects_missing_tests_list(tmp_path):
"""A suite must contain a tests list."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="requires a 'tests' list",
):
    RegressionLoader().load(path)


def test_loader_rejects_incomplete_test_definition(
tmp_path,
):
"""Regression tests must contain required security fields."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite

tests:
- id: TEST-001
name: Incomplete Test
security_requirement: SF-API-001
description: Missing objective and expected behavior.
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="requires a non-empty",
):
    RegressionLoader().load(path)


def test_loader_rejects_invalid_enabled_type(
tmp_path,
):
"""Enabled must be a boolean."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite

tests:
- id: TEST-001
name: Test
security_requirement: SF-API-001
description: Test description.
objective: Test objective.
target: /health
expected_result: HTTP 200
failure_condition: HTTP 500.
enabled: yes
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="must be boolean",
):
    RegressionLoader().load(path)


def test_loader_rejects_invalid_tags(tmp_path):
"""Tags must be represented as a list of strings."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite

tests:
- id: TEST-001
name: Test
security_requirement: SF-API-001
description: Test description.
objective: Test objective.
target: /health
expected_result: HTTP 200
failure_condition: HTTP 500.
tags:
- valid
- 123
""",
)


with pytest.raises(
    RegressionConfigurationError,
    match="tags must contain only strings",
):
    RegressionLoader().load(path)


def test_loader_rejects_invalid_metadata(tmp_path):
"""Suite metadata must be a mapping."""
path = write_config(
tmp_path,
"""
suite:
id: test-suite
name: Test Suite
tests: []

metadata:

* invalid
  """,
  )

  with pytest.raises(
  RegressionConfigurationError,
  match="metadata must be a mapping",
  ):
  RegressionLoader().load(path)
