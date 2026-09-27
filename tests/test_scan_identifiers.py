"""Tests for SecureForge scan identifier generation."""

import pytest

from secureforge.core.config import (
ScanConfiguration,
ScanProfile,
TargetConfiguration,
TargetType,
)
from secureforge.core.scan.identifiers import ScanIdentifier

def build_configuration() -> ScanConfiguration:
"""Create a representative scan configuration."""
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
),
)

def test_scan_identifier_is_deterministic() -> None:
"""Verify identical inputs produce the same identifier."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.STANDARD,
commit_sha="abc123",
environment="lab",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile=ScanProfile.STANDARD,
    commit_sha="abc123",
    environment="lab",
)

assert first == second
```

def test_scan_identifier_has_expected_prefix() -> None:
"""Verify generated IDs use the SCAN prefix."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.QUICK,
)

```
assert identifier.startswith("SCAN-")
```

def test_scan_identifier_has_expected_length() -> None:
"""Verify generated identifiers have the expected format."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.QUICK,
)

```
assert len(identifier) == 17
```

def test_scan_identifier_changes_with_application() -> None:
"""Verify application changes produce different identifiers."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="OtherApplication",
    version="1.0.0",
    profile="quick",
)

assert first != second
```

def test_scan_identifier_changes_with_version() -> None:
"""Verify version changes produce different identifiers."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="2.0.0",
    profile="quick",
)

assert first != second
```

def test_scan_identifier_changes_with_profile() -> None:
"""Verify profile changes produce different identifiers."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile="full",
)

assert first != second
```

def test_scan_identifier_changes_with_commit() -> None:
"""Verify commit changes produce different identifiers."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="standard",
commit_sha="abc123",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile="standard",
    commit_sha="def456",
)

assert first != second
```

def test_scan_identifier_changes_with_environment() -> None:
"""Verify environment changes produce different identifiers."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="standard",
environment="lab",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile="standard",
    environment="staging",
)

assert first != second
```

def test_scan_identifier_normalizes_application_case() -> None:
"""Verify application casing does not affect the identifier."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="securecommerce",
    version="1.0.0",
    profile="quick",
)

assert first == second
```

def test_scan_identifier_normalizes_whitespace() -> None:
"""Verify repeated whitespace is normalized."""
first = ScanIdentifier.generate(
application="Secure  Commerce",
version="1.0.0",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="Secure Commerce",
    version="1.0.0",
    profile="quick",
)

assert first == second
```

def test_scan_identifier_normalizes_version_case() -> None:
"""Verify version normalization is deterministic."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version=" RELEASE-1 ",
profile="quick",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="release-1",
    profile="quick",
)

assert first == second
```

def test_scan_identifier_normalizes_commit_case() -> None:
"""Verify commit normalization is deterministic."""
first = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
commit_sha="ABC123",
)

```
second = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile="quick",
    commit_sha="abc123",
)

assert first == second
```

def test_scan_identifier_accepts_string_profile() -> None:
"""Verify string scan profiles are supported."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="standard",
)

```
assert identifier.startswith("SCAN-")
```

def test_scan_identifier_accepts_enum_profile() -> None:
"""Verify ScanProfile values are supported."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile=ScanProfile.FULL,
)

```
assert identifier.startswith("SCAN-")
```

def test_scan_identifier_handles_missing_optional_values() -> None:
"""Verify optional components can be omitted."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
)

```
assert identifier.startswith("SCAN-")
assert len(identifier) == 17
```

def test_scan_identifier_handles_none_commit() -> None:
"""Verify an explicitly missing commit is supported."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
commit_sha=None,
)

```
assert identifier.startswith("SCAN-")
```

def test_scan_identifier_handles_none_environment() -> None:
"""Verify an explicitly missing environment is supported."""
identifier = ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="quick",
environment=None,
)

```
assert identifier.startswith("SCAN-")
```

def test_scan_identifier_rejects_empty_application() -> None:
"""Verify empty application names are rejected."""
with pytest.raises(
ValueError,
match="application cannot be empty",
):
ScanIdentifier.generate(
application="",
version="1.0.0",
profile="quick",
)

def test_scan_identifier_rejects_whitespace_application() -> None:
"""Verify whitespace-only application names are rejected."""
with pytest.raises(
ValueError,
match="application cannot be empty",
):
ScanIdentifier.generate(
application="   ",
version="1.0.0",
profile="quick",
)

def test_scan_identifier_rejects_empty_version() -> None:
"""Verify empty versions are rejected."""
with pytest.raises(
ValueError,
match="version cannot be empty",
):
ScanIdentifier.generate(
application="SecureCommerce",
version="",
profile="quick",
)

def test_scan_identifier_rejects_whitespace_version() -> None:
"""Verify whitespace-only versions are rejected."""
with pytest.raises(
ValueError,
match="version cannot be empty",
):
ScanIdentifier.generate(
application="SecureCommerce",
version="   ",
profile="quick",
)

def test_scan_identifier_rejects_invalid_profile() -> None:
"""Verify unsupported profiles are rejected."""
with pytest.raises(
ValueError,
match="Unsupported scan profile",
):
ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile="invalid",
)

def test_scan_identifier_from_configuration() -> None:
"""Verify configuration-based identifier generation."""
configuration = build_configuration()

```
identifier = ScanIdentifier.from_configuration(
    configuration,
    commit_sha="abc123",
)

expected = ScanIdentifier.generate(
    application="SecureCommerce",
    version="1.0.0",
    profile=ScanProfile.STANDARD,
    commit_sha="abc123",
    environment="lab",
)

assert identifier == expected
```

def test_configuration_identifier_changes_with_commit() -> None:
"""Verify configuration-based IDs reflect the commit."""
configuration = build_configuration()

```
first = ScanIdentifier.from_configuration(
    configuration,
    commit_sha="abc123",
)

second = ScanIdentifier.from_configuration(
    configuration,
    commit_sha="def456",
)

assert first != second
```

def test_configuration_identifier_uses_configuration_profile() -> None:
"""Verify configuration profile affects the generated ID."""
configuration = build_configuration()

```
standard_id = ScanIdentifier.from_configuration(
    configuration
)

configuration.profile = ScanProfile.FULL

full_id = ScanIdentifier.from_configuration(
    configuration
)

assert standard_id != full_id
```

def test_configuration_identifier_uses_configuration_environment() -> None:
"""Verify configuration environment affects the generated ID."""
configuration = build_configuration()

```
lab_id = ScanIdentifier.from_configuration(
    configuration
)

configuration.environment = "staging"

staging_id = ScanIdentifier.from_configuration(
    configuration
)

assert lab_id != staging_id
```

def test_different_profiles_have_distinct_identifiers() -> None:
"""Verify all supported profiles produce distinct IDs."""
identifiers = {
ScanIdentifier.generate(
application="SecureCommerce",
version="1.0.0",
profile=profile,
environment="lab",
)
for profile in ScanProfile
}

```
assert len(identifiers) == len(
    list(ScanProfile)
)
```

def test_same_inputs_with_optional_values_are_reproducible() -> None:
"""Verify reproducibility when optional values are supplied."""
parameters = {
"application": "SecureCommerce",
"version": "1.0.0",
"profile": ScanProfile.FULL,
"commit_sha": "ABC123",
"environment": "LAB",
}

```
identifiers = [
    ScanIdentifier.generate(**parameters)
    for _ in range(5)
]

assert len(set(identifiers)) == 1
```
