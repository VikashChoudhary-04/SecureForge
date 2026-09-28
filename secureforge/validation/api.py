"""API-based security validation for SecureForge."""

from __future__ import annotations

import json
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


class APIValidator(BaseValidator):
    """Validate API security findings against controlled lab endpoints."""

    name = "api"

    def __init__(self, *, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def supports(self, request: ValidationRequest) -> bool:
        """Return whether this validator supports API validation."""
        return request.method == ValidationMethod.API

    def validate(self, request: ValidationRequest) -> ValidationResult:
        """Send a controlled API request and record the response."""
        if not request.endpoint:
            raise ValidationError(
                "API validation requires an endpoint."
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
        body = self._build_body(request)
        validated_at = datetime.now(UTC).isoformat()

        api_request = urllib.request.Request(
            url=url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(
                api_request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read().decode(
                    "utf-8",
                    errors="replace",
                )
                status_code = response.status

        except urllib.error.HTTPError as exc:
            response_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )
            status_code = exc.code

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            return ValidationResult(
                finding_id=request.finding_id,
                outcome=ValidationOutcome.ERROR,
                message=f"API validation failed: {exc}",
                evidence=[
                    ValidationEvidence(
                        method=ValidationMethod.API,
                        description=(
                            "Controlled API security validation."
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
        observed_status = str(status_code)

        if expected_status is not None:
            confirmed = self._status_matches(
                expected_status,
                status_code,
            )

            outcome = (
                ValidationOutcome.CONFIRMED
                if confirmed
                else ValidationOutcome.REJECTED
            )

            message = (
                "API validation matched the expected security behavior."
                if confirmed
                else "API validation did not match the expected behavior."
            )
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            message = (
                "API request completed; finding-specific interpretation "
                "is required."
            )

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[
                ValidationEvidence(
                    method=ValidationMethod.API,
                    description=(
                        "Controlled API security validation."
                    ),
                    request=f"{method} {url}",
                    response=response_body,
                    expected=(
                        f"HTTP status {expected_status}"
                        if expected_status is not None
                        else None
                    ),
                    observed=f"HTTP status {observed_status}",
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
        """Build an API URL from the target and endpoint."""
        base = target.rstrip("/")
        path = endpoint.strip()

        if not path:
            raise ValidationError(
                "API endpoint must not be empty."
            )

        if not path.startswith("/"):
            path = f"/{path}"

        return f"{base}{path}"

    @staticmethod
    def _build_headers(
        request: ValidationRequest,
    ) -> dict[str, str]:
        """Build request headers from validation metadata."""
        headers: dict[str, str] = {
            "User-Agent": "SecureForge-Validator/0.1",
            "Accept": "application/json",
        }

        raw_headers = request.metadata.get("headers")

        if raw_headers:
            try:
                parsed = json.loads(raw_headers)
            except json.JSONDecodeError as exc:
                raise ValidationError(
                    f"Invalid API headers JSON: {exc}"
                ) from exc

            if not isinstance(parsed, dict):
                raise ValidationError(
                    "API headers must be a JSON object."
                )

            for key, value in parsed.items():
                if (
                    not isinstance(key, str)
                    or not isinstance(value, str)
                ):
                    raise ValidationError(
                        "API header names and values must be strings."
                    )

                headers[key] = value

        return headers

    @staticmethod
    def _build_body(
        request: ValidationRequest,
    ) -> bytes | None:
        """Build an optional JSON request body."""
        if request.payload is None:
            return None

        content_type = request.metadata.get(
            "content_type",
            "application/json",
        )

        if content_type == "application/json":
            try:
                parsed = json.loads(request.payload)
            except json.JSONDecodeError as exc:
                raise ValidationError(
                    f"Invalid API JSON payload: {exc}"
                ) from exc

            return json.dumps(parsed).encode("utf-8")

        return request.payload.encode("utf-8")

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


__all__ = [
    "APIValidator",
]
