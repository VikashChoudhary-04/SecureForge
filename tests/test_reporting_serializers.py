"""Tests for SecureForge security report serialization."""

from __future__ import annotations

import json

from secureforge.core.findings import (
Confidence,
Finding,
Severity,
)
from secureforge.core.policy import PolicyDecision
from secureforge.core.release_gate import (
ReleaseGateDecision,
ReleaseGateStatus,
)
from secureforge.core.risk import RiskAssessment
from secureforge.reporting import (
SecurityReportBuilder,
SecurityReportSerializer,
)

def build_report():
"""Build a representative report for serializer tests."""
finding = Finding(
finding_id="SF-SQLI-001",
title="SQL Injection",
source="sast",
source_finding_id="SAST-SQLI-001",
application="SecureCommerce",
asset="SecureCommerce Web Application",
endpoint="/vulnerable/search-user",
parameter="user_id",
cwe="CWE-89",
owasp="A05:2025-Injection",
security_requirement="SF-INPUT-001",
severity=Severity.CRITICAL,
confidence=Confidence.CONFIRMED,
description="Unsafe SQL query construction.",
impact="Database queries may be manipulated.",
remediation="Use parameterized queries.",
)

risk = RiskAssessment(
    score=9.5,
    highest_severity="critical",
    confirmed_critical=1,
    confirmed_high=0,
    factors={
        "internet_exposure": True,
        "sensitive_data": True,
    },
)

policy = PolicyDecision(
    policy_name="default",
    actions={
        "critical": "block",
        "high": "block",
        "medium": "review",
        "low": "pass",
        "info": "pass",
    },
    tool_errors=[],
    regression_failures=[],
    exceptions=[],
)

release_gate = ReleaseGateDecision(
    status=ReleaseGateStatus.BLOCK,
    reason="Critical SQL injection finding.",
    release_allowed=False,
)

return SecurityReportBuilder().build(
    release_id="release-serializer-001",
    application="SecureCommerce",
    version="0.1.0",
    environment="lab",
    profile="standard",
    scan_id="SF-SCAN-SERIALIZER-001",
    scan_status="completed",
    integrations=["sast"],
    findings=[finding],
    risk=risk,
    policy=policy,
    release_gate=release_gate,
)

def test_serializer_converts_report_to_dictionary():
"""Serializer should produce a JSON-compatible dictionary."""
report = build_report()
serializer = SecurityReportSerializer()

data = serializer.to_dict(report)

assert isinstance(data, dict)
assert data["release"]["application"] == (
    "SecureCommerce"
)
assert data["scan"]["scan_id"] == (
    "SF-SCAN-SERIALIZER-001"
)
assert data["findings"][0]["finding_id"] == (
    "SF-SQLI-001"
)
assert data["decision"]["status"] == "block"

def test_serializer_produces_valid_json():
"""Serialized report should be valid JSON."""
report = build_report()
serializer = SecurityReportSerializer()

output = serializer.to_json(report)

parsed = json.loads(output)

assert parsed["release"]["release_id"] == (
    "release-serializer-001"
)
assert parsed["findings"][0]["severity"] == (
    "critical"
)
assert parsed["decision"]["release_allowed"] is False

def test_serializer_writes_json_file(tmp_path):
"""Serializer should write the report to disk."""
report = build_report()
serializer = SecurityReportSerializer()

output_path = (
    tmp_path
    / "reports"
    / "security-report.json"
)

result = serializer.write_json(
    report,
    output_path,
)

assert result == output_path
assert output_path.is_file()

content = output_path.read_text(
    encoding="utf-8"
)

parsed = json.loads(content)

assert parsed["release"]["application"] == (
    "SecureCommerce"
)
assert parsed["risk"]["highest_severity"] == (
    "critical"
)
assert parsed["decision"]["status"] == "block"

def test_serializer_preserves_nested_report_data():
"""Nested risk, policy, and regression data should survive serialization."""
report = build_report()

report.regression.tests_total = 1
report.regression.tests_failed = 1

report.policy.tool_errors.append(
    "Synthetic tool failure."
)

serializer = SecurityReportSerializer()

data = serializer.to_dict(report)

assert data["regression"]["tests_total"] == 1
assert data["regression"]["tests_failed"] == 1
assert data["policy"]["tool_errors"] == [
    "Synthetic tool failure."
]
