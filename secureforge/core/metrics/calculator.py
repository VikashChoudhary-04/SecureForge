"""Calculate security metrics from existing SecureForge domain models."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from secureforge.core.findings import (
    Finding,
    FindingStatus,
    Severity,
    ValidationStatus,
)

from .models import (
    FindingMetrics,
    RegressionMetrics,
    ReleaseMetrics,
    RemediationMetrics,
    RequirementMetrics,
    SecurityMetrics,
)


class SecurityMetricsCalculator:
    """Calculate measurable security metrics without owning domain logic."""

    def calculate(
        self,
        *,
        findings: Iterable[Finding] | None = None,
        release_decisions: Sequence[Any] | None = None,
        regression_failures: Iterable[str] | None = None,
        requirement_ids: Iterable[str] | None = None,
        validation_results: Sequence[Any] | None = None,
    ) -> SecurityMetrics:
        """Build a security metrics snapshot from supplied evidence."""
        finding_list = list(findings or [])

        return SecurityMetrics(
            findings=self._calculate_finding_metrics(
                finding_list,
                validation_results=validation_results,
            ),
            releases=self._calculate_release_metrics(
                release_decisions or [],
            ),
            regression=self._calculate_regression_metrics(
                regression_failures or [],
            ),
            requirements=self._calculate_requirement_metrics(
                finding_list,
                requirement_ids=requirement_ids,
            ),
            remediation=self._calculate_remediation_metrics(
                finding_list,
            ),
        )

    @staticmethod
    def _calculate_finding_metrics(
        findings: list[Finding],
        *,
        validation_results: Sequence[Any] | None = None,
    ) -> FindingMetrics:
        """Calculate severity and lifecycle metrics for findings."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        status_counts = {
            FindingStatus.OPEN: 0,
            FindingStatus.IN_PROGRESS: 0,
            FindingStatus.VALIDATED: 0,
            FindingStatus.REJECTED: 0,
            FindingStatus.REMEDIATED: 0,
            FindingStatus.VERIFIED: 0,
            FindingStatus.ACCEPTED: 0,
            FindingStatus.REOPENED: 0,
        }

        confirmed = 0
        unconfirmed = 0
        requirements_violated = 0

        for finding in findings:
            severity = finding.severity.value

            if severity in {"info", "informational"}:
                severity_counts["informational"] += 1
            elif severity in severity_counts:
                severity_counts[severity] += 1

            if finding.status in status_counts:
                status_counts[finding.status] += 1

            if finding.validation_status in {
                ValidationStatus.CONFIRMED,
                ValidationStatus.VALIDATED,
                ValidationStatus.VERIFIED,
            }:
                confirmed += 1
            else:
                unconfirmed += 1

            if finding.security_requirement:
                requirements_violated += 1

        false_positive_rate = (
            SecurityMetricsCalculator._false_positive_rate(
                validation_results
            )
        )

        return FindingMetrics(
            total=len(findings),
            critical=severity_counts["critical"],
            high=severity_counts["high"],
            medium=severity_counts["medium"],
            low=severity_counts["low"],
            informational=severity_counts["informational"],
            open=status_counts[FindingStatus.OPEN],
            in_progress=status_counts[FindingStatus.IN_PROGRESS],
            validated=status_counts[FindingStatus.VALIDATED],
            rejected=status_counts[FindingStatus.REJECTED],
            remediated=status_counts[FindingStatus.REMEDIATED],
            verified=status_counts[FindingStatus.VERIFIED],
            accepted=status_counts[FindingStatus.ACCEPTED],
            reopened=status_counts[FindingStatus.REOPENED],
            confirmed=confirmed,
            unconfirmed=unconfirmed,
            false_positive_rate=false_positive_rate,
            requirements_violated=requirements_violated,
        )

    @staticmethod
    def _calculate_release_metrics(
        release_decisions: Sequence[Any],
    ) -> ReleaseMetrics:
        """Calculate release outcome metrics."""
        passed = 0
        reviewed = 0
        blocked = 0
        blocking_conditions = 0
        review_conditions = 0

        for decision in release_decisions:
            status = getattr(decision, "status", None)
            status = getattr(status, "value", status)

            if status in {"passed", "pass"}:
                passed += 1
            elif status == "review":
                reviewed += 1
            elif status in {"blocked", "block"}:
                blocked += 1

            if getattr(decision, "blocking_findings", None):
                blocking_conditions += 1

            if getattr(decision, "review_findings", None):
                review_conditions += 1

        return ReleaseMetrics(
            evaluated=len(release_decisions),
            passed=passed,
            reviewed=reviewed,
            blocked=blocked,
            blocking_conditions=blocking_conditions,
            review_conditions=review_conditions,
        )

    @staticmethod
    def _calculate_regression_metrics(
        regression_failures: Iterable[str],
    ) -> RegressionMetrics:
        """Calculate regression failure metrics."""
        failures = tuple(
            dict.fromkeys(
                failure
                for failure in regression_failures
                if failure
            )
        )

        return RegressionMetrics(
            total_failures=len(failures),
            failed_tests=failures,
        )

    @staticmethod
    def _calculate_requirement_metrics(
        findings: list[Finding],
        *,
        requirement_ids: Iterable[str] | None = None,
    ) -> RequirementMetrics:
        """Calculate requirement violation metrics.

        Requirement satisfaction is only calculated when an explicit
        requirement set is supplied. A finding mapped to a requirement
        represents a violation of that requirement for this metric
        snapshot.
        """
        configured_requirements = {
            requirement_id.strip().upper()
            for requirement_id in (requirement_ids or [])
            if requirement_id and requirement_id.strip()
        }

        violated_requirements = {
            finding.security_requirement.strip().upper()
            for finding in findings
            if finding.security_requirement
            and (
                not configured_requirements
                or finding.security_requirement.strip().upper()
                in configured_requirements
            )
        }

        if not configured_requirements:
            return RequirementMetrics(
                evaluated=0,
                violated=len(violated_requirements),
                satisfied=0,
            )

        violated = len(
            violated_requirements.intersection(
                configured_requirements
            )
        )
        evaluated = len(configured_requirements)

        return RequirementMetrics(
            evaluated=evaluated,
            violated=violated,
            satisfied=evaluated - violated,
        )

    @staticmethod
    def _calculate_remediation_metrics(
        findings: list[Finding],
    ) -> RemediationMetrics:
        """Calculate remediation counts.

        MTTR remains unavailable until SecureForge has explicit
        remediation timestamps. Finding last_seen is not treated as a
        remediation timestamp.
        """
        remediated = sum(
            finding.status == FindingStatus.REMEDIATED
            for finding in findings
        )

        verified = sum(
            finding.validation_status == ValidationStatus.VERIFIED
            for finding in findings
        )

        return RemediationMetrics(
            remediated=remediated,
            verified=verified,
            mttr_seconds=None,
            mttr_available=False,
        )

    @staticmethod
    def _false_positive_rate(
        validation_results: Sequence[Any] | None,
    ) -> float | None:
        """Calculate rejected-validation percentage."""
        if not validation_results:
            return None

        completed = 0
        rejected = 0

        for result in validation_results:
            outcome = getattr(result, "outcome", None)
            outcome = getattr(outcome, "value", outcome)

            if outcome in {
                "confirmed",
                "rejected",
                "inconclusive",
            }:
                completed += 1

            if outcome == "rejected":
                rejected += 1

        if completed == 0:
            return None

        return rejected / completed


__all__ = [
    "SecurityMetricsCalculator",
]
