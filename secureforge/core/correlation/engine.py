"""Correlation engine for combining related SecureForge findings."""

from **future** import annotations

from collections import defaultdict
from typing import Iterable

from secureforge.core.findings import Finding

from .models import (
CorrelatedFinding,
CorrelationConfidence,
CorrelationLink,
CorrelationType,
)

class CorrelationEngine:
"""Identify relationships between normalized security findings."""

```
def __init__(self, minimum_signals: int = 2) -> None:
    if minimum_signals < 1:
        raise ValueError("minimum_signals must be at least 1.")

    self.minimum_signals = minimum_signals

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
        for target in finding_list[index + 1 :]:
            link = self._build_link(source, target)

            if link is None:
                continue

            group_key = self._group_key(source, target)

            correlated = groups.setdefault(
                group_key,
                CorrelatedFinding(
                    finding_id=self._build_correlated_id(
                        source,
                        target,
                    )
                ),
            )

            correlated.add_source_finding(source.finding_id)
            correlated.add_source_finding(target.finding_id)

            for evidence in source.evidence:
                correlated.add_evidence(evidence.evidence_id)

            for evidence in target.evidence:
                correlated.add_evidence(evidence.evidence_id)

            correlated.add_link(link)

            if link.confidence == CorrelationConfidence.HIGH:
                correlated.confidence = CorrelationConfidence.HIGH

    return list(groups.values())

def _build_link(
    self,
    source: Finding,
    target: Finding,
) -> CorrelationLink | None:
    """Build a correlation link when enough signals agree."""
    signals: list[str] = []
    correlation_types: list[CorrelationType] = []

    if source.cwe and target.cwe and source.cwe == target.cwe:
        signals.append("same_cwe")
        correlation_types.append(CorrelationType.SAME_VULNERABILITY)

    if source.asset == target.asset:
        signals.append("same_asset")
        correlation_types.append(CorrelationType.SAME_ASSET)

    if source.endpoint and target.endpoint:
        if self._normalize_endpoint(source.endpoint) == self._normalize_endpoint(
            target.endpoint
        ):
            signals.append("same_endpoint")
            correlation_types.append(CorrelationType.SAME_ENDPOINT)

    if source.parameter and target.parameter:
        if source.parameter.lower() == target.parameter.lower():
            signals.append("same_parameter")
            correlation_types.append(CorrelationType.SAME_PARAMETER)

    if self._title_similarity(source.title, target.title):
        signals.append("similar_title")
        correlation_types.append(CorrelationType.RELATED)

    if len(signals) < self.minimum_signals:
        return None

    confidence = self._confidence_for_signals(signals)

    primary_type = self._select_primary_type(correlation_types)

    return CorrelationLink(
        source_finding_id=source.finding_id,
        target_finding_id=target.finding_id,
        correlation_type=primary_type,
        confidence=confidence,
        reason=self._build_reason(signals),
        signals=signals,
    )

@staticmethod
def _normalize_endpoint(endpoint: str) -> str:
    """Normalize an endpoint for basic comparison."""
    endpoint = endpoint.strip().lower()

    if "?" in endpoint:
        endpoint = endpoint.split("?", 1)[0]

    return endpoint.rstrip("/")

@staticmethod
def _title_similarity(first: str, second: str) -> bool:
    """Perform a simple explainable title comparison."""
    first_words = {
        word.strip(".,:;()[]{}").lower()
        for word in first.split()
        if len(word.strip(".,:;()[]{}")) >= 4
    }

    second_words = {
        word.strip(".,:;()[]{}").lower()
        for word in second.split()
        if len(word.strip(".,:;()[]{}")) >= 4
    }

    if not first_words or not second_words:
        return False

    overlap = first_words.intersection(second_words)

    return len(overlap) >= 2

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

    strong_count = len(strong_signals.intersection(signals))

    if strong_count >= 2:
        return CorrelationConfidence.HIGH

    if len(signals) >= 3:
        return CorrelationConfidence.HIGH

    return CorrelationConfidence.MEDIUM

@staticmethod
def _select_primary_type(
    correlation_types: list[CorrelationType],
) -> CorrelationType:
    """Select the most meaningful correlation relationship."""
    priority = [
        CorrelationType.SAME_VULNERABILITY,
        CorrelationType.SAME_ENDPOINT,
        CorrelationType.SAME_PARAMETER,
        CorrelationType.SAME_ASSET,
        CorrelationType.SUPPORTING_EVIDENCE,
        CorrelationType.RELATED,
    ]

    for correlation_type in priority:
        if correlation_type in correlation_types:
            return correlation_type

    return CorrelationType.RELATED

@staticmethod
def _build_reason(signals: list[str]) -> str:
    """Create a human-readable explanation for correlation."""
    formatted = ", ".join(signals)

    return f"Findings correlated using matching signals: {formatted}."

@staticmethod
def _group_key(source: Finding, target: Finding) -> str:
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
```
