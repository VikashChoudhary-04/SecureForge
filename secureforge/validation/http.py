"""HTTP-based security validation for SecureForge."""

from __future__ import annotations

import urllib.error
import urllib.request
from datetime import UTC, datetime

from .base import BaseValidator, ValidationError
from .models import (
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class HTTPValidator(BaseValidator):
    """Validate security findings against controlled HTTP endpoints."""

    name = "http"

    def __init__(self, *, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def supports(self, request: ValidationRequest) -> bool:
        """Return whether this validator supports HTTP validation."""
        return request.method == ValidationMethod.HTTP

    def validate(self, request: ValidationRequest) -> ValidationResult:
        """Send a controlled HTTP request and record the response."""
        if not request.endpoint:
            raise ValidationError(
                "HTTP validation requires an endpoint."
            )

        url = self._build_url(
            request.target,
            request.endpoint,
        )

        method = request.metadata.get(
            "http_method",
            "GET",
        ).upper()

        headers = self._build_headers(request)
        body = (
            request.payload.encode("utf-8")
            if request.payload is not None
            else None
        )

        validated_at = datetime.now(UTC).isoformat()

        http_request = urllib.request.Request(
            url=url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(
                http_request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read().decode(
                    "utf-8",
                    errors="replace",
                )
                status_code = response.status
                response_headers = dict(response.headers.items())

        except urllib.error.HTTPError as exc:
            response_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )
            status_code = exc.code
            response_headers = dict(exc.headers.items())

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            return ValidationResult(
                finding_id=request.finding_id,
                outcome=ValidationOutcome.ERROR,
                message=f"HTTP validation failed: {exc}",
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.HTTP,
                        description=(
                            "Controlled HTTP security validation."
                        ),
                        request=f"{method} {url}",
                        observed=str(exc),
                    )
                ],
                validator=self.name,
                validated_at=validated_at,
            )

        expected_status = request.metadata.get(
            "expected_status"
        )

        expected_text = request.metadata.get(
            "expected_text"
        )

        observed_status = str(status_code)

        status_matches = True

        if expected_status is not None:
            status_matches = self._status_matches(
                expected_status,
                status_code,
            )

        text_matches = True

        if expected_text is not None:
            text_matches = expected_text in response_body

        if (
            expected_status is not None
            or expected_text is not None
        ):
            confirmed = status_matches and text_matches

            outcome = (
                ValidationOutcome.CONFIRMED
                if confirmed
                else ValidationOutcome.REJECTED
            )

            message = (
                "HTTP validation matched the expected security behavior."
                if confirmed
                else "HTTP validation did not match the expected behavior."
            )
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            message = (
                "HTTP request completed; finding-specific interpretation "
                "is required."
            )

        observed = (
            f"HTTP status {observed_status}; "
            f"response headers: {len(response_headers)}"
        )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[
                ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled HTTP security validation."
                    ),
                    request=f"{method} {url}",
                    response=response_body,
                    expected=self._build_expected_description(
                        expected_status,
                        expected_text,
                    ),
                    observed=observed,
                )
            ],
            validator=self.name,
            validated_at=validated_at,
        )

    @staticmethod
    def _build_url(
        target: str,
        endpoint: str,
    ) -> str:
        """Build an HTTP URL from the target and endpoint."""
        base = target.rstrip("/")
        path = endpoint.strip()

        if not path:
            raise ValidationError(
                "HTTP endpoint must not be empty."
            )

        if not path.startswith("/"):
            path = f"/{path}"

        return f"{base}{path}"

    @staticmethod
    def _build_headers(
        request: ValidationRequest,
    ) -> dict[str, str]:
        """Build request headers from validation metadata."""
        headers = {
            "User-Agent": "SecureForge-Validator/0.1",
            "Accept": "*/*",
        }

        content_type = request.metadata.get(
            "content_type"
        )

        if content_type:
            headers["Content-Type"] = content_type

        return headers

    @staticmethod
    def _status_matches(
        expected: str,
        observed: int,
    ) -> bool:
        """Compare an expected HTTP status with the observed status."""
        expected = expected.strip()

        if "-" in expected:
            parts = expected.split(
                "-",
                maxsplit=1,
            )

            try:
                lower = int(parts[0])
                upper = int(parts[1])
            except ValueError:
                return False

            return lower <= observed <= upper

        try:
            return observed == int(expected)
        except ValueError:
            return False

    @staticmethod
    def _build_expected_description(
        expected_status: str | None,
        expected_text: str | None,
    ) -> str | None:
        """Build a concise description of expected behavior."""
        expectations: list[str] = []

        if expected_status is not None:
            expectations.append(
                f"HTTP status {expected_status}"
            )

        if expected_text is not None:
            expectations.append(
                f"response containing {expected_text!r}"
            )

        if not expectations:
            return None

        return " and ".join(expectations)


__all__ = [
    "HTTPValidator",
]
