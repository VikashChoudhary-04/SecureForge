"""Tests for SecureForge security metrics."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from secureforge.core.findings import (
    FindingStatus,
    ValidationStatus,
)
from secureforge.core.metrics import (
    FindingMetrics,
    RegressionMetrics,
    ReleaseMetrics,
    RemediationMetrics,
    RequirementMetrics,
    SecurityMetrics,
    SecurityMetricsCalculator,
)


def make_finding(
    *,
    severity: str = "medium",
    status: FindingStatus = FindingStatus.OPEN,
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED,
    security_requirement: str | None = None,
) -> SimpleNamespace:
    """Create the minimum finding shape required by the calculator."""
    return SimpleNamespace(
        severity=SimpleNamespace(value=severity),
        status=status,
        validation_status=validation_status,
        security_requirement=security_requirement,
    )


def make_release_decision(
    *,
    status: str,
    blocking_findings: list[str] | None = None,
    review_findings: list[str] | None = None,
) -> SimpleNamespace:
    """Create the minimum release-decision shape required by the calculator."""
    return SimpleNamespace(
        status=status,
        blocking_findings=blocking_findings or [],
        review_findings=review_findings or [],
    )


def make_validation_result(
    outcome: str,
) -> SimpleNamespace:
    """Create the minimum validation-result shape required by the calculator."""
    return SimpleNamespace(
        outcome=SimpleNamespace(value=outcome),
    )


class TestSecurityMetricsModels:
    """Test security metrics model defaults and derived values."""

    def test_security_metrics_use_empty_defaults(self) -> None:
        metrics = SecurityMetrics()

        assert metrics.findings == FindingMetrics()
        assert metrics.releases == ReleaseMetrics()
        assert metrics.regression == RegressionMetrics()
        assert metrics.requirements == RequirementMetrics()
        assert metrics.remediation == RemediationMetrics()

    def test_release_rates_are_none_without_evaluated_releases(self) -> None:
        metrics = ReleaseMetrics()

        assert metrics.pass_rate is None
        assert metrics.review_rate is None
        assert metrics.block_rate is None

    def test_release_rates_are_calculated(self) -> None:
        metrics = ReleaseMetrics(
            evaluated=4,
            passed=2,
            reviewed=1,
            blocked=1,
        )

        assert metrics.pass_rate == pytest.approx(0.5)
        assert metrics.review_rate == pytest.approx(0.25)
        assert metrics.block_rate == pytest.approx(0.25)

    def test_requirement_satisfaction_rate_is_none_without_requirements(
        self,
    ) -> None:
        metrics = RequirementMetrics()

        assert metrics.satisfaction_rate is None

    def test_requirement_satisfaction_rate_is_calculated(self) -> None:
        metrics = RequirementMetrics(
            evaluated=4,
            violated=1,
            satisfied=3,
        )

        assert metrics.satisfaction_rate == pytest.approx(0.75)


class TestSecurityMetricsCalculator:
    """Test SecurityMetricsCalculator behavior."""

    def test_empty_calculation_returns_zeroed_metrics(self) -> None:
        calculator = SecurityMetricsCalculator()

        metrics = calculator.calculate()

        assert metrics.findings.total == 0
        assert metrics.releases.evaluated == 0
        assert metrics.regression.total_failures == 0
        assert metrics.requirements.evaluated == 0
        assert metrics.remediation.remediated == 0

    def test_calculates_finding_severity_counts(self) -> None:
        findings = [
            make_finding(severity="critical"),
            make_finding(severity="high"),
            make_finding(severity="high"),
            make_finding(severity="medium"),
            make_finding(severity="low"),
            make_finding(severity="info"),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.findings.total == 6
        assert metrics.findings.critical == 1
        assert metrics.findings.high == 2
        assert metrics.findings.medium == 1
        assert metrics.findings.low == 1
        assert metrics.findings.informational == 1

    def test_calculates_informational_severity_alias(self) -> None:
        findings = [
            make_finding(severity="informational"),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.findings.informational == 1

    def test_calculates_finding_lifecycle_counts(self) -> None:
        findings = [
            make_finding(status=FindingStatus.OPEN),
            make_finding(status=FindingStatus.IN_PROGRESS),
            make_finding(status=FindingStatus.VALIDATED),
            make_finding(status=FindingStatus.REJECTED),
            make_finding(status=FindingStatus.REMEDIATED),
            make_finding(status=FindingStatus.VERIFIED),
            make_finding(status=FindingStatus.ACCEPTED),
            make_finding(status=FindingStatus.REOPENED),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.findings.total == 8
        assert metrics.findings.open == 1
        assert metrics.findings.in_progress == 1
        assert metrics.findings.validated == 1
        assert metrics.findings.rejected == 1
        assert metrics.findings.remediated == 1
        assert metrics.findings.verified == 1
        assert metrics.findings.accepted == 1
        assert metrics.findings.reopened == 1

    def test_calculates_confirmed_and_unconfirmed_findings(self) -> None:
        findings = [
            make_finding(
                validation_status=ValidationStatus.CONFIRMED,
            ),
            make_finding(
                validation_status=ValidationStatus.VALIDATED,
            ),
            make_finding(
                validation_status=ValidationStatus.VERIFIED,
            ),
            make_finding(
                validation_status=ValidationStatus.INCONCLUSIVE,
            ),
            make_finding(
                validation_status=ValidationStatus.NOT_VALIDATED,
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.findings.confirmed == 3
        assert metrics.findings.unconfirmed == 2

    def test_calculates_false_positive_rate_from_validation_results(
        self,
    ) -> None:
        validation_results = [
            make_validation_result("confirmed"),
            make_validation_result("rejected"),
            make_validation_result("rejected"),
            make_validation_result("inconclusive"),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            validation_results=validation_results,
        )

        assert metrics.findings.false_positive_rate == pytest.approx(0.5)

    def test_false_positive_rate_is_none_without_completed_results(
        self,
    ) -> None:
        validation_results = [
            make_validation_result("error"),
            make_validation_result("unknown"),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            validation_results=validation_results,
        )

        assert metrics.findings.false_positive_rate is None

    def test_counts_requirement_mappings_on_findings(self) -> None:
        findings = [
            make_finding(
                security_requirement="SF-AUTH-001",
            ),
            make_finding(
                security_requirement="SF-AUTHZ-001",
            ),
            make_finding(
                security_requirement=None,
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.findings.requirements_violated == 2

    def test_calculates_release_outcomes(self) -> None:
        decisions = [
            make_release_decision(status="passed"),
            make_release_decision(status="pass"),
            make_release_decision(status="review"),
            make_release_decision(status="blocked"),
            make_release_decision(status="block"),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            release_decisions=decisions,
        )

        assert metrics.releases.evaluated == 5
        assert metrics.releases.passed == 2
        assert metrics.releases.reviewed == 1
        assert metrics.releases.blocked == 2

    def test_counts_release_blocking_and_review_conditions(self) -> None:
        decisions = [
            make_release_decision(
                status="blocked",
                blocking_findings=["FINDING-001"],
            ),
            make_release_decision(
                status="review",
                review_findings=["FINDING-002"],
            ),
            make_release_decision(
                status="passed",
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            release_decisions=decisions,
        )

        assert metrics.releases.blocking_conditions == 1
        assert metrics.releases.review_conditions == 1

    def test_deduplicates_regression_failures(self) -> None:
        failures = [
            "BOLA-001",
            "SQLI-001",
            "BOLA-001",
            "",
            "XSS-001",
            "SQLI-001",
        ]

        metrics = SecurityMetricsCalculator().calculate(
            regression_failures=failures,
        )

        assert metrics.regression.total_failures == 3
        assert metrics.regression.failed_tests == (
            "BOLA-001",
            "SQLI-001",
            "XSS-001",
        )

    def test_calculates_requirement_coverage(self) -> None:
        findings = [
            make_finding(
                security_requirement="SF-AUTH-001",
            ),
            make_finding(
                security_requirement="sf-api-001",
            ),
        ]

        requirement_ids = [
            "SF-AUTH-001",
            "SF-AUTHZ-001",
            "SF-API-001",
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
            requirement_ids=requirement_ids,
        )

        assert metrics.requirements.evaluated == 3
        assert metrics.requirements.violated == 2
        assert metrics.requirements.satisfied == 1
        assert metrics.requirements.satisfaction_rate == pytest.approx(
            1 / 3
        )

    def test_requirement_ids_are_normalized(self) -> None:
        findings = [
            make_finding(
                security_requirement=" sf-auth-001 ",
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
            requirement_ids=[
                "SF-AUTH-001",
            ],
        )

        assert metrics.requirements.evaluated == 1
        assert metrics.requirements.violated == 1
        assert metrics.requirements.satisfied == 0

    def test_requirement_metrics_without_configured_requirements(
        self,
    ) -> None:
        findings = [
            make_finding(
                security_requirement="SF-AUTH-001",
            ),
            make_finding(
                security_requirement="SF-AUTH-001",
            ),
            make_finding(
                security_requirement="SF-AUTHZ-001",
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.requirements.evaluated == 0
        assert metrics.requirements.violated == 2
        assert metrics.requirements.satisfied == 0
        assert metrics.requirements.satisfaction_rate is None

    def test_calculates_remediation_and_verified_counts(self) -> None:
        findings = [
            make_finding(
                status=FindingStatus.REMEDIATED,
            ),
            make_finding(
                status=FindingStatus.REMEDIATED,
            ),
            make_finding(
                validation_status=ValidationStatus.VERIFIED,
            ),
            make_finding(
                validation_status=ValidationStatus.VERIFIED,
            ),
            make_finding(),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.remediation.remediated == 2
        assert metrics.remediation.verified == 2

    def test_mttr_is_unavailable_without_remediation_timestamps(
        self,
    ) -> None:
        findings = [
            make_finding(
                status=FindingStatus.REMEDIATED,
            ),
        ]

        metrics = SecurityMetricsCalculator().calculate(
            findings=findings,
        )

        assert metrics.remediation.mttr_seconds is None
        assert metrics.remediation.mttr_available is False

    def test_calculator_returns_complete_security_metrics(self) -> None:
        metrics = SecurityMetricsCalculator().calculate()

        assert isinstance(metrics, SecurityMetrics)
        assert isinstance(metrics.findings, FindingMetrics)
        assert isinstance(metrics.releases, ReleaseMetrics)
        assert isinstance(metrics.regression, RegressionMetrics)
        assert isinstance(metrics.requirements, RequirementMetrics)
        assert isinstance(metrics.remediation, RemediationMetrics)


class TestMetricsPackageExports:
    """Test the public metrics package API."""

    def test_metrics_package_exports_public_types(self) -> None:
        from secureforge import core
        from secureforge.core import metrics

        assert hasattr(core, "metrics")

        assert hasattr(metrics, "FindingMetrics")
        assert hasattr(metrics, "ReleaseMetrics")
        assert hasattr(metrics, "RegressionMetrics")
        assert hasattr(metrics, "RequirementMetrics")
        assert hasattr(metrics, "RemediationMetrics")
        assert hasattr(metrics, "SecurityMetrics")
        assert hasattr(metrics, "SecurityMetricsCalculator")

    def test_metrics_package_defines_public_api(self) -> None:
        from secureforge.core import metrics

        expected_exports = {
            "FindingMetrics",
            "ReleaseMetrics",
            "RegressionMetrics",
            "RequirementMetrics",
            "RemediationMetrics",
            "SecurityMetrics",
            "SecurityMetricsCalculator",
        }

        assert expected_exports.issubset(
            set(metrics.__all__)
        )
