"""Tests for the SecureForge scan-run factory."""

import pytest

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
)
from secureforge.core.scan import ScanStatus
from secureforge.core.scan.factory import ScanRunFactory
from secureforge.core.scan.identifiers import ScanIdentifier

def build_configuration() -> ScanConfiguration:
"""Create a representative SecureForge configuration."""
return ScanConfiguration(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
environment="lab",
target=TargetConfiguration(
name="securecommerce-local",
target_type=TargetType.WEB_AND_API,
base_url="http://localhost:5000",
api_base_url="http://localhost:5000/api",
openapi_url="http://localhost:5000/openapi.json",
),
)

def test_factory_creates_scan_run() -> None:
"""Verify the factory creates a valid scan run."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration
)

assert scan.application == "SecureCommerce"
assert scan.version == "1.0.0"
assert scan.profile == ScanProfile.STANDARD
assert scan.environment == "lab"
assert scan.status == ScanStatus.CREATED

def test_factory_generates_deterministic_scan_id() -> None:
"""Verify factory-generated IDs are deterministic."""
configuration = build_configuration()
factory = ScanRunFactory()

first = factory.create(
    configuration,
    commit_sha="abc123",
)

second = factory.create(
    configuration,
    commit_sha="abc123",
)

assert first.scan_id == second.scan_id

def test_factory_uses_scan_identifier_generator() -> None:
"""Verify the factory uses ScanIdentifier."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration,
    commit_sha="abc123",
)

expected = ScanIdentifier.from_configuration(
    configuration,
    commit_sha="abc123",
)

assert scan.scan_id == expected

def test_factory_preserves_commit_sha() -> None:
"""Verify commit SHA is preserved in the scan."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration,
    commit_sha="abc123",
)

assert scan.commit_sha == "abc123"

def test_factory_supports_missing_commit_sha() -> None:
"""Verify scan creation works without a commit SHA."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration
)

assert scan.commit_sha is None
assert scan.scan_id.startswith("SCAN-")

def test_factory_adds_target_name_metadata() -> None:
"""Verify target name is stored in scan metadata."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration
)

assert (
    scan.metadata["target_name"]
    == "securecommerce-local"
)

def test_factory_adds_target_type_metadata() -> None:
"""Verify target type is stored in scan metadata."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration
)

assert (
    scan.metadata["target_type"]
    == "web_and_api"
)

def test_factory_preserves_custom_metadata() -> None:
"""Verify caller-provided metadata is preserved."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration,
    metadata={
        "trigger": "pull_request",
        "branch": "main",
    },
)

assert scan.metadata["trigger"] == "pull_request"
assert scan.metadata["branch"] == "main"

def test_factory_does_not_overwrite_custom_target_metadata() -> None:
"""Verify explicitly supplied target metadata is preserved."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration,
    metadata={
        "target_name": "custom-target",
        "target_type": "custom-type",
    },
)

assert scan.metadata["target_name"] == "custom-target"
assert scan.metadata["target_type"] == "custom-type"

def test_factory_creates_distinct_scans_for_different_commits() -> None:
"""Verify different commits produce distinct scan IDs."""
configuration = build_configuration()
factory = ScanRunFactory()

first = factory.create(
    configuration,
    commit_sha="abc123",
)

second = factory.create(
    configuration,
    commit_sha="def456",
)

assert first.scan_id != second.scan_id

def test_factory_creates_distinct_scans_for_different_profiles() -> None:
"""Verify different profiles produce distinct scan IDs."""
factory = ScanRunFactory()

quick_configuration = build_configuration()
quick_configuration.profile = ScanProfile.QUICK

full_configuration = build_configuration()
full_configuration.profile = ScanProfile.FULL

quick_scan = factory.create(
    quick_configuration
)

full_scan = factory.create(
    full_configuration
)

assert quick_scan.scan_id != full_scan.scan_id

def test_factory_validation_accepts_valid_configuration() -> None:
"""Verify valid configuration passes factory validation."""
configuration = build_configuration()

ScanRunFactory.validate_configuration(
    configuration
)

def test_factory_rejects_empty_application() -> None:
"""Verify empty application names are rejected."""
configuration = build_configuration()
configuration.application = "   "

with pytest.raises(
    ValueError,
    match="Scan application cannot be empty",
):
    ScanRunFactory.validate_configuration(
        configuration
    )

def test_factory_rejects_empty_version() -> None:
"""Verify empty versions are rejected."""
configuration = build_configuration()
configuration.version = "   "

with pytest.raises(
    ValueError,
    match="Scan version cannot be empty",
):
    ScanRunFactory.validate_configuration(
        configuration
    )

def test_factory_rejects_empty_target_name() -> None:
"""Verify empty target names are rejected."""
configuration = build_configuration()
configuration.target.name = "   "

with pytest.raises(
    ValueError,
    match="Scan target name cannot be empty",
):
    ScanRunFactory.validate_configuration(
        configuration
    )

def test_factory_create_validates_configuration() -> None:
"""Verify create performs configuration validation."""
configuration = build_configuration()
configuration.application = "   "

with pytest.raises(
    ValueError,
    match="Scan application cannot be empty",
):
    ScanRunFactory().create(
        configuration
    )

def test_factory_accepts_web_target() -> None:
"""Verify web-only targets can create scan runs."""
configuration = build_configuration()
configuration.target.target_type = TargetType.WEB

scan = ScanRunFactory().create(
    configuration
)

assert scan.metadata["target_type"] == "web"

def test_factory_accepts_api_target() -> None:
"""Verify API-only targets can create scan runs."""
configuration = build_configuration()
configuration.target.target_type = TargetType.API

scan = ScanRunFactory().create(
    configuration
)

assert scan.metadata["target_type"] == "api"

def test_factory_returns_created_scan() -> None:
"""Verify newly created scans have not started execution."""
configuration = build_configuration()

scan = ScanRunFactory().create(
    configuration
)

assert scan.status == ScanStatus.CREATED
assert scan.completed_at is None
