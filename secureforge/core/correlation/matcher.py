"""Explainable finding matching logic for SecureForge correlation."""

from **future** import annotations

from secureforge.core.findings import Finding

from .models import CorrelationType

class FindingMatcher:
"""Compare findings using deterministic correlation signals."""

```
def match(
    self,
    source: Finding,
    target: Finding,
) -> list[str]:
    """Return matching correlation signals."""
    if source.finding_id == target.finding_id:
        return []

    signals: list[str] = []

    if self.same_cwe(source, target):
        signals.append("same_cwe")

    if self.same_asset(source, target):
        signals.append("same_asset")

    if self.same_endpoint(source, target):
        signals.append("same_endpoint")

    if self.same_parameter(source, target):
        signals.append("same_parameter")

    if self.similar_title(source, target):
        signals.append("similar_title")

    return signals

def correlation_types(
    self,
    signals: list[str],
) -> list[CorrelationType]:
    """Convert matching signals into correlation types."""
    mapping = {
        "same_cwe": CorrelationType.SAME_VULNERABILITY,
        "same_asset": CorrelationType.SAME_ASSET,
        "same_endpoint": CorrelationType.SAME_ENDPOINT,
        "same_parameter": CorrelationType.SAME_PARAMETER,
        "similar_title": CorrelationType.RELATED,
    }

    return [
        mapping[signal]
        for signal in signals
        if signal in mapping
    ]

@staticmethod
def same_cwe(
    source: Finding,
    target: Finding,
) -> bool:
    """Return whether both findings reference the same CWE."""
    return bool(
        source.cwe
        and target.cwe
        and source.cwe.strip().lower()
        == target.cwe.strip().lower()
    )

@staticmethod
def same_asset(
    source: Finding,
    target: Finding,
) -> bool:
    """Return whether both findings affect the same asset."""
    return (
        source.asset.strip().lower()
        == target.asset.strip().lower()
    )

@classmethod
def same_endpoint(
    cls,
    source: Finding,
    target: Finding,
) -> bool:
    """Return whether both findings affect the same endpoint."""
    if not source.endpoint or not target.endpoint:
        return False

    return (
        cls.normalize_endpoint(source.endpoint)
        == cls.normalize_endpoint(target.endpoint)
    )

@staticmethod
def same_parameter(
    source: Finding,
    target: Finding,
) -> bool:
    """Return whether both findings reference the same parameter."""
    if not source.parameter or not target.parameter:
        return False

    return (
        source.parameter.strip().lower()
        == target.parameter.strip().lower()
    )

@staticmethod
def similar_title(
    source: Finding,
    target: Finding,
) -> bool:
    """Return whether finding titles share meaningful words."""
    first_words = FindingMatcher._title_words(
        source.title
    )

    second_words = FindingMatcher._title_words(
        target.title
    )

    if not first_words or not second_words:
        return False

    overlap = first_words.intersection(
        second_words
    )

    return len(overlap) >= 2

@staticmethod
def normalize_endpoint(
    endpoint: str,
) -> str:
    """Normalize an endpoint for correlation comparison."""
    normalized = endpoint.strip().lower()

    if "?" in normalized:
        normalized = normalized.split(
            "?",
            1,
        )[0]

    return normalized.rstrip("/")

@staticmethod
def _title_words(
    title: str,
) -> set[str]:
    """Extract meaningful words from a finding title."""
    punctuation = ".,:;()[]{}"

    return {
        word.strip(punctuation).lower()
        for word in title.split()
        if len(word.strip(punctuation)) >= 4
    }

def primary_correlation_type(
    self,
    signals: list[str],
) -> CorrelationType:
    """Select the strongest correlation type for matching signals."""
    correlation_types = self.correlation_types(
        signals
    )

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
```
