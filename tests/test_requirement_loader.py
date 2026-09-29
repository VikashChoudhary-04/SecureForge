"""Tests for the SecureForge security requirement loader."""

from pathlib import Path

import pytest

from secureforge.core.requirements import (
RequirementCategory,
RequirementLoader,
RequirementRegistry,
RequirementStatus,
SecurityRequirement,
)

def build_requirement(
requirement_id: str = "SF-AUTHZ-001",
) -> SecurityRequirement:
"""Create a representative security requirement."""
return SecurityRequirement(
requirement_id=requirement_id,
title="Object-level authorization",
description=(
"Users must only access objects they are authorized to access."
),
category=RequirementCategory.AUTHORIZATION,
status=RequirementStatus.ACTIVE,
owasp="API1:2023",
cwe=["CWE-639"],
verification_methods=[
"DAST",
"manual",
"regression",
],
mandatory=True,
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

def test_loader_loads_requirement_list_from_yaml(
tmp_path: Path,
) -> None:
"""Verify requirements can be loaded from a YAML list."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""

* requirement_id: SF-AUTHZ-001
  title: Object-level authorization
  description: Users must only access authorized objects.
  category: authorization
  status: active
  owasp: API1:2023
  cwe:

  * CWE-639
    verification_methods:
  * DAST
  * manual
    mandatory: true
    """,
    )

  requirements = RequirementLoader().load_file(
  path
  )

  assert len(requirements) == 1
  assert requirements[0].requirement_id == "SF-AUTHZ-001"
  assert requirements[0].category == (
  RequirementCategory.AUTHORIZATION
  )
  assert requirements[0].mandatory is True

def test_loader_loads_wrapped_requirements_mapping(
tmp_path: Path,
) -> None:
"""Verify requirements can be loaded from a wrapped YAML mapping."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTH-001
  title: Strong authentication
  description: Authentication must be enforced.
  category: authentication
  status: active
  mandatory: true
  """,
  )

  requirements = RequirementLoader().load_file(
  path
  )

  assert len(requirements) == 1
  assert requirements[0].requirement_id == "SF-AUTH-001"
  assert requirements[0].category == (
  RequirementCategory.AUTHENTICATION
  )

def test_loader_loads_multiple_requirements(
tmp_path: Path,
) -> None:
"""Verify multiple requirements are loaded."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTH-001
  title: Authentication
  description: Authentication must be enforced.
  category: authentication

* requirement_id: SF-SECRET-001
  title: Secret protection
  description: Secrets must not be exposed.
  category: secret

* requirement_id: SF-DEP-001
  title: Dependency security
  description: Dependencies must be assessed.
  category: dependency
  """,
  )

  requirements = RequirementLoader().load_file(
  path
  )

  assert len(requirements) == 3
  assert [
  requirement.requirement_id
  for requirement in requirements
  ] == [
  "SF-AUTH-001",
  "SF-SECRET-001",
  "SF-DEP-001",
  ]

def test_loader_load_registry(
tmp_path: Path,
) -> None:
"""Verify YAML requirements can be loaded into a registry."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTHZ-001
  title: Authorization
  description: Authorization must be enforced.
  category: authorization

* requirement_id: SF-API-001
  title: API authentication
  description: APIs must enforce authentication.
  category: api
  """,
  )

  registry = RequirementLoader().load_registry(
  path
  )

  assert isinstance(
  registry,
  RequirementRegistry,
  )
  assert len(registry) == 2
  assert registry.contains("SF-AUTHZ-001")
  assert registry.contains("SF-API-001")

def test_loader_rejects_missing_file(
tmp_path: Path,
) -> None:
"""Verify a missing requirements file raises an error."""
path = tmp_path / "missing.yaml"

with pytest.raises(
    FileNotFoundError,
    match="was not found",
):
    RequirementLoader().load_file(path)

def test_loader_rejects_directory(
tmp_path: Path,
) -> None:
"""Verify a directory cannot be loaded as a requirements file."""
path = tmp_path / "requirements"

path.mkdir()

with pytest.raises(
    ValueError,
    match="is not a file",
):
    RequirementLoader().load_file(path)

def test_loader_rejects_invalid_yaml(
tmp_path: Path,
) -> None:
"""Verify malformed YAML is rejected."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTH-001
  title: Authentication
  description: [invalid
  """,
  )

  with pytest.raises(
  ValueError,
  match="Invalid YAML requirements file",
  ):
  RequirementLoader().load_file(path)

def test_loader_rejects_empty_file(
tmp_path: Path,
) -> None:
"""Verify an empty requirements file is rejected."""
path = write_yaml(
tmp_path / "requirements.yaml",
"",
)

with pytest.raises(
    ValueError,
    match="Requirements file is empty",
):
    RequirementLoader().load_file(path)

def test_loader_rejects_non_list_data(
tmp_path: Path,
) -> None:
"""Verify unsupported YAML structures are rejected."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
name: invalid
value: true
""",
)

with pytest.raises(
    ValueError,
    match="must be a YAML list",
):
    RequirementLoader().load_file(path)

def test_loader_rejects_non_mapping_requirement(
tmp_path: Path,
) -> None:
"""Verify each requirement must be a YAML mapping."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* SF-AUTH-001
  """,
  )

  with pytest.raises(
  ValueError,
  match="must be a YAML mapping",
  ):
  RequirementLoader().load_file(path)

def test_loader_rejects_invalid_requirement(
tmp_path: Path,
) -> None:
"""Verify invalid requirement fields are rejected."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTH-001
  title: Authentication
  description: Authentication must be enforced.
  category: invalid-category
  """,
  )

  with pytest.raises(
  ValueError,
  match="Invalid security requirement",
  ):
  RequirementLoader().load_file(path)

def test_loader_dump_data_serializes_requirements() -> None:
"""Verify requirement models can be serialized."""
requirement = build_requirement()

data = RequirementLoader.dump_data(
    [requirement]
)

assert data == [
    {
        "requirement_id": "SF-AUTHZ-001",
        "title": "Object-level authorization",
        "description": (
            "Users must only access objects they are authorized to access."
        ),
        "category": "authorization",
        "status": "active",
        "owasp": "API1:2023",
        "cwe": ["CWE-639"],
        "verification_methods": [
            "DAST",
            "manual",
            "regression",
        ],
        "mandatory": True,
        "metadata": {},
    }
]

def test_loader_save_file_writes_yaml(
tmp_path: Path,
) -> None:
"""Verify requirements can be written to YAML."""
path = tmp_path / "requirements.yaml"

requirements = [
    build_requirement("SF-AUTHZ-001"),
    build_requirement("SF-AUTHZ-002"),
]

RequirementLoader().save_file(
    requirements,
    path,
)

assert path.exists()

loaded = RequirementLoader().load_file(
    path
)

assert len(loaded) == 2
assert loaded[0].requirement_id == "SF-AUTHZ-001"
assert loaded[1].requirement_id == "SF-AUTHZ-002"

def test_loader_round_trip_preserves_requirement(
tmp_path: Path,
) -> None:
"""Verify save/load preserves the requirement model."""
path = tmp_path / "requirements.yaml"

original = build_requirement()

loader = RequirementLoader()

loader.save_file(
    [original],
    path,
)

loaded = loader.load_file(
    path
)

assert loaded == [original]

def test_loader_accepts_path_string(
tmp_path: Path,
) -> None:
"""Verify string paths are supported."""
path = write_yaml(
tmp_path / "requirements.yaml",
"""
requirements:

* requirement_id: SF-AUTH-001
  title: Authentication
  description: Authentication must be enforced.
  category: authentication
  """,
  )

  requirements = RequirementLoader().load_file(
  str(path)
  )

  assert len(requirements) == 1
