"""Tests for SecureForge scan identifier generation."""

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
