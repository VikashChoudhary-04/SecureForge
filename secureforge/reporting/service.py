"""Service layer for SecureForge security reporting."""

from **future** import annotations

from dataclasses import dataclass
from pathlib import Path

from secureforge.core.findings.models import Finding
from secureforge.core.policy.models import PolicyDecision
from secureforge.core.release_gate.models import ReleaseGateDecision
from secureforge.core.risk.models import RiskAssessment
from secureforge.core.scan.orchestrator import SecurityScanResult
from secureforge.regression import (
RegressionGateDecision,
RegressionSuiteResult,
)

from .builder import SecurityReportBuilder
from .html import SecurityHTMLReportRenderer
from .models import (
ReleaseMetadata,
RemediationReport,
ScanMetadata,
SecurityReport,
)
from .scan import build_scan_report
from .serializers import SecurityReportSerializer

@dataclass(frozen=True)
class ReportPaths:
"""Output paths for generated security reports."""

```
json_path: Path
html_path: Path
```

class SecurityReportService:
"""Generate complete JSON and HTML security reports."""

```
def __init__(
    self,
    *,
    builder: SecurityReportBuilder | None = None,
    serializer: SecurityReportSerializer | None = None,
    renderer: SecurityHTMLReportRenderer | None = None,
) -> None:
    self.builder = (
        builder
        if builder is not None
        else SecurityReportBuilder()
    )

    self.serializer = (
        serializer
        if serializer is not None
        else SecurityReportSerializer()
    )

    self.renderer = (
        renderer
        if renderer is not None
        else SecurityHTMLReportRenderer()
    )

def build_report(
    self,
    *,
    release: ReleaseMetadata,
    scan: ScanMetadata,
    findings: list[Finding],
    risk: RiskAssessment,
    policy: PolicyDecision,
    decision: ReleaseGateDecision,
    remediation: RemediationReport | None = None,
    regression: RegressionSuiteResult | None = None,
    regression_gate: RegressionGateDecision | None = None,
    generated_at: str | None = None,
) -> SecurityReport:
    """Build a security report from domain results."""
    return self.builder.build(
        release=release,
        scan=scan,
        findings=findings,
        risk=risk,
        policy=policy,
        decision=decision,
        remediation=remediation,
        regression=regression,
        regression_gate=regression_gate,
        generated_at=generated_at,
    )

def build_from_scan_result(
    self,
    *,
    result: SecurityScanResult,
    release: ReleaseMetadata,
    scan: ScanMetadata,
    generated_at: str | None = None,
) -> SecurityReport:
    """Build a report directly from a completed scan result."""
    return build_scan_report(
        result,
        release=release,
        scan=scan,
        generated_at=generated_at,
    )

def generate(
    self,
    report: SecurityReport,
    paths: ReportPaths,
) -> ReportPaths:
    """Write both JSON and HTML report files."""
    self.serializer.write_json(
        report,
        paths.json_path,
    )

    self.renderer.write_html(
        report,
        paths.html_path,
    )

    return paths

def generate_from_results(
    self,
    *,
    release: ReleaseMetadata,
    scan: ScanMetadata,
    findings: list[Finding],
    risk: RiskAssessment,
    policy: PolicyDecision,
    decision: ReleaseGateDecision,
    paths: ReportPaths,
    remediation: RemediationReport | None = None,
    regression: RegressionSuiteResult | None = None,
    regression_gate: RegressionGateDecision | None = None,
    generated_at: str | None = None,
) -> ReportPaths:
    """Build and write a complete security report."""
    report = self.build_report(
        release=release,
        scan=scan,
        findings=findings,
        risk=risk,
        policy=policy,
        decision=decision,
        remediation=remediation,
        regression=regression,
        regression_gate=regression_gate,
        generated_at=generated_at,
    )

    return self.generate(
        report,
        paths,
    )

def generate_from_scan_result(
    self,
    *,
    result: SecurityScanResult,
    release: ReleaseMetadata,
    scan: ScanMetadata,
    paths: ReportPaths,
    generated_at: str | None = None,
) -> ReportPaths:
    """Build and write reports directly from a scan result."""
    report = self.build_from_scan_result(
        result=result,
        release=release,
        scan=scan,
        generated_at=generated_at,
    )

    return self.generate(
        report,
        paths,
    )
```
