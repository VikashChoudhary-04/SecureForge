"""Tests for SecureCommerce report input evidence."""

from **future** import annotations

import json
from pathlib import Path

EVIDENCE_PATH = (
Path(**file**).resolve().parents[1]
/ "evidence"
/ "sample-report-input.json"
)

def load_report_input() -> dict:
"""Load the report input fixture."""
assert EVIDENCE_PATH.is_file()

```
return json.loads(
    EVIDENCE_PATH.read_text(
        encoding="utf-8"
    )
)
```

def test_report_input_contains_release_metadata():
"""Report input should identify the release being evaluated."""
data = load_report_input()

```
release = data["release"]

assert release["release_id"] == (
    "release-securecommerce-001"
)
assert release["application"] == "SecureCommerce"
assert release["version"] == "0.1.0"
assert release["environment"] == "lab"
assert release["profile"] == "standard"
assert release["commit_sha"]
```

def test_report_input_contains_scan_metadata():
"""Report input should contain scan execution metadata."""
data = load_report_input()

```
scan = data["scan"]

assert scan["scan_id"] == "SF-SCAN-0001"
assert scan["status"] == "completed"
assert scan["started_at"]
assert scan["completed_at"]

assert scan["integrations"] == [
    "sast",
    "sca",
    "secrets",
    "api",
    "dast",
    "container",
]
```

def test_report_input_contains_findings():
"""Report input should contain normalized security findings."""
data = load_report_input()

```
findings = data["findings"]

assert len(findings) == 3

finding_ids = {
    finding["finding_id"]
    for finding in findings
}

assert finding_ids == {
    "SF-BOLA-001",
    "SF-SQLI-001",
    "SF-SECRET-001",
}
```

def test_findings_contain_security_mappings():
"""Findings should retain security-standard mappings."""
data = load_report_input()

```
for finding in data["findings"]:
    assert finding["severity"]
    assert finding["confidence"]
    assert finding["cwe"]
    assert finding["security_requirement"]
    assert finding["description"]
    assert finding["impact"]
    assert finding["remediation"]
```

def test_correlated_finding_preserves_source_ids():
"""Correlated findings should retain their original source findings."""
data = load_report_input()

```
bola = next(
    finding
    for finding in data["findings"]
    if finding["finding_id"] == "SF-BOLA-001"
)

assert bola["source"] == "correlation"

assert set(
    bola["source_finding_ids"]
) == {
    "API-BOLA-001",
    "DAST-BOLA-001",
    "BURP-BOLA-001",
}

assert bola["evidence_count"] == 3
```

def test_report_input_contains_risk_evaluation():
"""Report input should contain risk evaluation data."""
data = load_report_input()

```
risk = data["risk"]

assert risk["overall_score"] == 9.4
assert risk["highest_severity"] == "critical"
assert risk["confirmed_critical"] == 1
assert risk["confirmed_high"] == 2

assert risk["risk_factors"]["internet_exposure"] is True
assert risk["risk_factors"]["sensitive_data"] is True
assert risk["risk_factors"]["exploit_evidence"] is True
```

def test_report_input_contains_policy_evaluation():
"""Report input should contain release policy information."""
data = load_report_input()

```
policy = data["policy"]

assert policy["policy_name"] == "default"
assert policy["critical_action"] == "block"
assert policy["high_action"] == "block"
assert policy["medium_action"] == "review"
assert policy["low_action"] == "pass"
assert policy["tool_errors"] == []
assert policy["regression_failures"] == []
```

def test_report_input_contains_remediation_state():
"""Report input should describe the remediation lifecycle state."""
data = load_report_input()

```
remediation = data["remediation"]

assert remediation["open_findings"] == 3
assert remediation["remediated_findings"] == 0
assert remediation["verified_findings"] == 0
assert remediation["pending_retests"] == 3
```

def test_report_input_contains_regression_results():
"""Report input should contain regression test results."""
data = load_report_input()

```
regression = data["regression"]

assert regression["tests_total"] == 6
assert regression["tests_passed"] == 0
assert regression["tests_failed"] == 6

test_ids = {
    test["test_id"]
    for test in regression["tests"]
}

assert test_ids == {
    "BOLA-001",
    "SQLI-001",
    "XSS-001",
    "SECRET-001",
    "AUTHZ-001",
    "MISCONFIG-001",
}
```

def test_report_input_contains_block_decision():
"""The vulnerable release should be blocked."""
data = load_report_input()

```
decision = data["decision"]

assert decision["status"] == "block"
assert decision["release_allowed"] is False
assert decision["reason"]
```
