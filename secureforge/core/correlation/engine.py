"""Correlation engine for combining related SecureForge findings."""

from __future__ import annotations

from collections.abc import Iterable

from secureforge.core.findings import Finding

from .matcher import FindingMatcher
from .models import (
    CorrelatedFinding,
    CorrelationConfidence,
    CorrelationLink,
)


class CorrelationEngine:
    """Identify relationships between normalized security findings."""

    def __init__(
        self,
        minimum_signals: int = 2,
        matcher: FindingMatcher | None = None,
    ) -> None:
        if minimum_signals < 1:
            raise ValueError(
                "minimum_signals must be at least 1."
            )

        self.minimum_signals = minimum_signals
        self.matcher = matcher or FindingMatcher()

    def correlate(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelatedFinding]:
        """Correlate findings using explainable matching signals."""
        finding_list = list(findings)

        if len(finding_list) < 2:
            return []

        groups: dict[str, CorrelatedFinding] = {}

        for index, source in enumerate(finding_list):
            for target in finding_list[index + 1:]:
                link = self._build_link(
                    source,
                    target,
                )

                if link is None:
                    continue

                group_key = self._group_key(
                    source,
                    target,
                )

                correlated = groups.setdefault(
                    group_key,
                    CorrelatedFinding(
                        finding_id=self._build_correlated_id(
                            source,
                            target,
                        )
                    ),
                )

                correlated.add_source_finding(
                    source.finding_id
                )
                correlated.add_source_finding(
                    target.finding_id
                )

                for evidence in source.evidence:
                    correlated.add_evidence(
                        evidence.evidence_id
                    )

                for evidence in target.evidence:
                    correlated.add_evidence(
                        evidence.evidence_id
                    )

                correlated.add_link(link)

                if (
                    link.confidence
                    == CorrelationConfidence.HIGH
                ):
                    correlated.confidence = (
                        CorrelationConfidence.HIGH
                    )

        return list(groups.values())

    def _build_link(
        self,
        source: Finding,
        target: Finding,
    ) -> CorrelationLink | None:
        """Build a correlation link when enough signals agree."""
        signals = self.matcher.match(
            source,
            target,
        )

        if len(signals) < self.minimum_signals:
            return None

        correlation_types = (
            self.matcher.correlation_types(
                signals
            )
        )

        primary_type = (
            self.matcher.primary_correlation_type(
                signals
            )
        )

        confidence = self._confidence_for_signals(
            signals
        )

        return CorrelationLink(
            source_finding_id=source.finding_id,
            target_finding_id=target.finding_id,
            correlation_type=primary_type,
            confidence=confidence,
            reason=self._build_reason(
                signals
            ),
            signals=signals,
            metadata={
                "correlation_types": [
                    correlation_type.value
                    for correlation_type in correlation_types
                ]
            },
        )

    @staticmethod
    def _confidence_for_signals(
        signals: list[str],
    ) -> CorrelationConfidence:
        """Determine correlation confidence from matching signals."""
        strong_signals = {
            "same_cwe",
            "same_asset",
            "same_endpoint",
        }

        strong_count = len(
            strong_signals.intersection(
                signals
            )
        )

        if strong_count >= 2:
            return CorrelationConfidence.HIGH

        if len(signals) >= 3:
            return CorrelationConfidence.HIGH

        return CorrelationConfidence.MEDIUM

    @staticmethod
    def _build_reason(
        signals: list[str],
    ) -> str:
        """Create a human-readable explanation for correlation."""
        formatted = ", ".join(signals)

        return (
            "Findings correlated using matching signals: "
            f"{formatted}."
        )

    @staticmethod
    def _group_key(
        source: Finding,
        target: Finding,
    ) -> str:
        """Create a deterministic key for a finding pair."""
        return "::".join(
            sorted(
                [
                    source.finding_id,
                    target.finding_id,
                ]
            )
        )

    @staticmethod
    def _build_correlated_id(
        source: Finding,
        target: Finding,
    ) -> str:
        """Build a stable identifier for a correlated finding."""
        first, second = sorted(
            [
                source.finding_id,
                target.finding_id,
            ]
        )

        return f"CORR-{first}-{second}"
