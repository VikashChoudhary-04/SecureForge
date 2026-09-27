"""Finding storage and lookup operations for SecureForge."""

from **future** import annotations

from collections.abc import Iterable, Iterator

from .models import Finding, FindingStatus

class FindingStore:
"""In-memory repository for normalized SecureForge findings."""

```
def __init__(self) -> None:
    self._findings: dict[str, Finding] = {}

def add(self, finding: Finding) -> Finding:
    """Add a finding to the store.

    Raises:
        ValueError: If the finding ID already exists.
    """
    if finding.finding_id in self._findings:
        raise ValueError(
            f"Finding '{finding.finding_id}' already exists."
        )

    self._findings[finding.finding_id] = finding

    return finding

def upsert(self, finding: Finding) -> Finding:
    """Insert a finding or replace an existing finding."""
    self._findings[finding.finding_id] = finding

    return finding

def get(self, finding_id: str) -> Finding | None:
    """Return a finding by its SecureForge ID."""
    return self._findings.get(finding_id)

def require(self, finding_id: str) -> Finding:
    """Return a finding or raise a clear lookup error."""
    finding = self.get(finding_id)

    if finding is None:
        raise KeyError(
            f"Finding '{finding_id}' was not found."
        )

    return finding

def remove(self, finding_id: str) -> Finding:
    """Remove and return a finding."""
    try:
        return self._findings.pop(finding_id)
    except KeyError as exc:
        raise KeyError(
            f"Finding '{finding_id}' was not found."
        ) from exc

def all(self) -> list[Finding]:
    """Return all stored findings in insertion order."""
    return list(self._findings.values())

def __iter__(self) -> Iterator[Finding]:
    """Iterate over stored findings."""
    return iter(self._findings.values())

def __len__(self) -> int:
    """Return the number of stored findings."""
    return len(self._findings)

def clear(self) -> None:
    """Remove all findings from the store."""
    self._findings.clear()

def contains(self, finding_id: str) -> bool:
    """Return whether a finding ID exists."""
    return finding_id in self._findings

def by_status(
    self,
    status: FindingStatus,
) -> list[Finding]:
    """Return findings matching a lifecycle status."""
    return [
        finding
        for finding in self._findings.values()
        if finding.status == status
    ]

def by_source(self, source: str) -> list[Finding]:
    """Return findings produced by a specific source."""
    normalized_source = source.strip().lower()

    return [
        finding
        for finding in self._findings.values()
        if finding.source.strip().lower() == normalized_source
    ]

def by_asset(self, asset: str) -> list[Finding]:
    """Return findings affecting a specific asset."""
    normalized_asset = asset.strip().lower()

    return [
        finding
        for finding in self._findings.values()
        if finding.asset.strip().lower() == normalized_asset
    ]

def by_requirement(
    self,
    requirement_id: str,
) -> list[Finding]:
    """Return findings mapped to a security requirement."""
    return [
        finding
        for finding in self._findings.values()
        if finding.security_requirement == requirement_id
    ]

def open_findings(self) -> list[Finding]:
    """Return findings that remain unresolved."""
    resolved_statuses = {
        FindingStatus.REMEDIATED,
        FindingStatus.VERIFIED,
        FindingStatus.ACCEPTED,
    }

    return [
        finding
        for finding in self._findings.values()
        if finding.status not in resolved_statuses
    ]

def update_status(
    self,
    finding_id: str,
    status: FindingStatus,
) -> Finding:
    """Update the lifecycle status of a stored finding."""
    finding = self.require(finding_id)

    finding.status = status

    return finding

def add_many(
    self,
    findings: Iterable[Finding],
) -> int:
    """Add multiple findings and return the number inserted."""
    inserted = 0

    for finding in findings:
        self.add(finding)
        inserted += 1

    return inserted
```
