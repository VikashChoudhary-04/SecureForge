# Validation planning for SecureForge findings

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secureforge.core.findings.models import Finding

from .models import ValidationMethod, ValidationRequest


@dataclass(frozen=True)
class ValidationPlan:
    """Plan describing findings selected for validation."""

    requests: tuple[ValidationRequest, ...]
    skipped_findings: tuple[str, ...]


class ValidationPlanner:
    """Create controlled validation requests from findings."""

    def __init__(
        self,
        *,
        validator: str = "secureforge",
    ) -> None:
        self.validator = validator

    def plan(
        self,
        findings: list[Finding],
        *,
        target: str,
        method: ValidationMethod = ValidationMethod.HTTP,
    ) -> ValidationPlan:
        """Build validation requests for eligible findings."""
        requests: list[ValidationRequest] = []
        skipped: list[str] = []

        for finding in findings:
            request = self._build_request(
                finding=finding,
                target=target,
                method=method,
            )

            if request is None:
                skipped.append(
                    finding.finding_id
                )
                continue

            requests.append(request)

        return ValidationPlan(
            requests=tuple(requests),
            skipped_findings=tuple(skipped),
        )

    def plan_finding(
        self,
        finding: Finding,
        *,
        target: str,
        method: ValidationMethod = ValidationMethod.HTTP,
    ) -> ValidationRequest | None:
        """Build a validation request for one finding."""
        return self._build_request(
            finding=finding,
            target=target,
            method=method,
        )

    def _build_request(
        self,
        *,
        finding: Finding,
        target: str,
        method: ValidationMethod,
    ) -> ValidationRequest | None:
        """Build a request when sufficient context exists."""
        if not finding.finding_id.strip():
            return None

        if not target.strip():
            return None

        endpoint = finding.endpoint
        parameter = finding.parameter

        if method in {
            ValidationMethod.HTTP,
            ValidationMethod.API,
        }:
            if not endpoint and not self._has_default_endpoint(
                finding.finding_id
            ):
                return None

        payload = self._extract_explicit_payload(
            finding
        )

        metadata = self._build_metadata(
            finding=finding,
            method=method,
        )

        return ValidationRequest(
            finding_id=finding.finding_id,
            target=target,
            method=method,
            endpoint=endpoint,
            parameter=parameter,
            payload=payload,
            validator=self.validator,
            metadata=metadata,
        )

    @staticmethod
    def _has_default_endpoint(
        finding_id: str,
    ) -> bool:
        """Return whether the SecureCommerce validator has a default."""
        return finding_id.upper() in {
            "BOLA-001",
            "SQLI-001",
            "XSS-001",
            "AUTHZ-001",
            "SECRET-001",
            "MISCONFIG-001",
            "SSRF-001",
            "UPLOAD-001",
            "PATH-TRAVERSAL-001",
        }

    @staticmethod
    def _extract_explicit_payload(
        finding: Finding,
    ) -> str | None:
        """Extract only an explicitly marked validation payload.

        Generic evidence such as an HTTP request or scanner output
        must not automatically become a validation payload because
        it may contain an entire request rather than the intended
        test value.
        """
        for evidence in finding.evidence:
            metadata: Any = getattr(
                evidence,
                "metadata",
                None,
            )

            if metadata is None and isinstance(
                evidence,
                dict,
            ):
                metadata = evidence.get(
                    "metadata"
                )

                if metadata is None:
                    data = evidence.get(
                        "data"
                    )
                    if isinstance(data, dict):
                        metadata = data.get(
                            "metadata"
                        )

            if metadata is None:
                data = getattr(
                    evidence,
                    "data",
                    None,
                )
                if isinstance(data, dict):
                    metadata = data.get(
                        "metadata"
                    )

            if isinstance(
                metadata,
                dict,
            ):
                payload = metadata.get(
                    "validation_payload"
                )

                if payload is not None:
                    return str(payload)

        return None

    @staticmethod
    def _build_metadata(
        *,
        finding: Finding,
        method: ValidationMethod,
    ) -> dict[str, str]:
        """Build validation context metadata."""
        metadata: dict[str, str] = {
            "finding_source": finding.source,
            "validation_method": method.value,
        }

        if finding.cwe:
            metadata["cwe"] = finding.cwe

        if finding.owasp_mapping:
            metadata["owasp_mapping"] = (
                finding.owasp_mapping
            )

        if finding.security_requirement:
            metadata["security_requirement"] = (
                finding.security_requirement
            )

        return metadata


__all__ = [
    "ValidationPlan",
    "ValidationPlanner",
]
