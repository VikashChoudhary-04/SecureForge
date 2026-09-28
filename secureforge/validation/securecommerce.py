```python
"""SecureCommerce-specific security validators for SecureForge."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .base import BaseValidator, ValidationError
from .models import (
    ValidationEvidence,
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
    ValidationResult,
)


class SecureCommerceValidator(BaseValidator):
    """Validate controlled SecureCommerce security findings."""

    name = "securecommerce"

    SUPPORTED_FINDINGS = {
        "BOLA-001",
        "SQLI-001",
        "XSS-001",
        "AUTHZ-001",
        "SECRET-001",
        "MISCONFIG-001",
    }

    def supports(
        self,
        request: ValidationRequest,
    ) -> bool:
        """Return whether the finding is supported."""
        return (
            request.finding_id.upper()
            in self.SUPPORTED_FINDINGS
        )

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate a supported SecureCommerce finding."""
        finding_id = request.finding_id.upper()

        if finding_id == "BOLA-001":
            return self._validate_bola(request)

        if finding_id == "SQLI-001":
            return self._validate_sqli(request)

        if finding_id == "XSS-001":
            return self._validate_xss(request)

        if finding_id == "AUTHZ-001":
            return self._validate_authorization(request)

        if finding_id == "SECRET-001":
            return self._validate_secret(request)

        if finding_id == "MISCONFIG-001":
            return self._validate_misconfiguration(request)

        raise ValidationError(
            f"Unsupported SecureCommerce finding: {finding_id}"
        )

    def _validate_bola(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate unauthorized object access."""
        endpoint = request.endpoint or "/api/users/2"

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )

        if response.status == 200:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The supplied object endpoint returned "
                    "HTTP 200 during unauthorized-object validation."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.API,
                    description=(
                        "Controlled BOLA validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="Authorization failure for unauthorized object.",
                    observed=f"HTTP {response.status}",
                ),
            )

        if response.status in {401, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The application rejected unauthorized object access."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.API,
                    description=(
                        "Controlled BOLA validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=(
                "The response did not provide sufficient evidence "
                "to confirm or reject BOLA."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.API,
                description=(
                    "Controlled BOLA validation request."
                ),
                request=response.request,
                response=response.body,
                observed=f"HTTP {response.status}",
            ),
        )

    def _validate_sqli(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate the controlled SQL injection endpoint."""
        endpoint = request.endpoint or "/vulnerable/search"

        payload = (
            request.payload
            if request.payload
            else "' OR '1'='1"
        )

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
            parameter=request.parameter or "q",
            payload=payload,
        )

        body_lower = response.body.lower()

        sql_error_markers = (
            "sqlite error",
            "sql syntax",
            "operationalerror",
            "near \"",
            "database error",
        )

        if any(
            marker in body_lower
            for marker in sql_error_markers
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The controlled SQL injection payload "
                    "produced database error evidence."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled SQL injection validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="No database error or injectable behavior.",
                    observed=(
                        "Database error marker detected."
                    ),
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=(
                "The response did not expose sufficient "
                "SQL injection evidence."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description=(
                    "Controlled SQL injection validation request."
                ),
                request=response.request,
                response=response.body,
                expected="No SQL injection evidence.",
                observed=(
                    f"HTTP {response.status}"
                ),
            ),
        )

    def _validate_xss(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate controlled reflected-XSS behavior."""
        endpoint = request.endpoint or "/vulnerable/search"

        payload = (
            request.payload
            if request.payload
            else "<SecureForge-XSS-Test>"
        )

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
            parameter=request.parameter or "q",
            payload=payload,
        )

        if payload in response.body:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The controlled XSS marker was reflected "
                    "in the HTTP response."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled reflected-XSS validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="User-controlled marker should be encoded.",
                    observed="Marker reflected in response.",
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message=(
                "The controlled XSS marker was not reflected "
                "in the response."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description=(
                    "Controlled reflected-XSS validation request."
                ),
                request=response.request,
                response=response.body,
                expected="Marker reflected without encoding.",
                observed="Marker not reflected.",
            ),
        )

    def _validate_authorization(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate a protected administrative action."""
        endpoint = request.endpoint or "/vulnerable/admin-action"

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )

        if response.status == 200:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The protected administrative endpoint "
                    "returned HTTP 200 without the expected "
                    "authorization control."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled function-level authorization test."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
                    observed="HTTP 200.",
                ),
            )

        if response.status in {401, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The protected administrative endpoint "
                    "enforced authorization."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled function-level authorization test."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=(
                "The authorization response was inconclusive."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description=(
                    "Controlled function-level authorization test."
                ),
                request=response.request,
                response=response.body,
                observed=f"HTTP {response.status}",
            ),
        )

    def _validate_secret(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate that a known synthetic secret is not exposed."""
        marker = (
            request.payload
            if request.payload
            else "SECURECOMMERCE_FAKE_SECRET"
        )

        endpoint = request.endpoint or "/"

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )

        if marker in response.body:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The synthetic lab secret was exposed "
                    "in the application response."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled synthetic-secret exposure test."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="Synthetic secret must not be exposed.",
                    observed="Synthetic secret detected.",
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message=(
                "The synthetic lab secret was not exposed "
                "in the tested response."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description=(
                    "Controlled synthetic-secret exposure test."
                ),
                request=response.request,
                response=response.body,
                expected="Synthetic secret must not be exposed.",
                observed="Synthetic secret not detected.",
            ),
        )

    def _validate_misconfiguration(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate a known insecure application configuration."""
        endpoint = request.endpoint or "/"

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )

        server_header = response.headers.get(
            "Server",
            "",
        )

        if "Werkzeug" in server_header:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The application exposed its development "
                    "server identification."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled security-configuration validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "Production deployment should not expose "
                        "development-server identification."
                    ),
                    observed=server_header,
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=(
                "The tested response did not expose the "
                "expected misconfiguration marker."
            ),
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description=(
                    "Controlled security-configuration validation."
                ),
                request=response.request,
                response=response.body,
                observed=server_header or "No Server header.",
            ),
        )

    def _request(
        self,
        *,
        request: ValidationRequest,
        endpoint: str,
        method: str,
        parameter: str | None = None,
        payload: str | None = None,
    ) -> "_HTTPResponse":
        """Perform one controlled HTTP request."""
        url = self._build_url(
            target=request.target,
            endpoint=endpoint,
        )

        if parameter and payload is not None:
            separator = "&" if "?" in url else "?"
            url = (
                f"{url}{separator}"
                f"{parameter}={self._encode(payload)}"
            )

        http_request = Request(
            url,
            method=method,
            headers={
                "User-Agent": "SecureForge-Validator/0.1",
            },
        )

        try:
            with urlopen(
                http_request,
                timeout=5,
            ) as response:
                body = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                return _HTTPResponse(
                    status=response.status,
                    body=body,
                    headers=dict(response.headers.items()),
                    request=f"{method} {url}",
                )

        except HTTPError as exc:
            body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            return _HTTPResponse(
                status=exc.code,
                body=body,
                headers=dict(exc.headers.items()),
                request=f"{method} {url}",
            )

        except (URLError, TimeoutError, OSError) as exc:
            raise ValidationError(
                f"SecureCommerce request failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    @staticmethod
    def _build_url(
        *,
        target: str,
        endpoint: str,
    ) -> str:
        """Build a target URL safely."""
        base = target.rstrip("/")
        path = endpoint.lstrip("/")

        return f"{base}/{path}"

    @staticmethod
    def _encode(
        value: str,
    ) -> str:
        """URL-encode a controlled validation value."""
        from urllib.parse import quote

        return quote(
            value,
            safe="",
        )

    @staticmethod
    def _result(
        *,
        request: ValidationRequest,
        outcome: ValidationOutcome,
        message: str,
        evidence: ValidationEvidence,
    ) -> ValidationResult:
        """Construct a validation result."""
        from datetime import datetime, timezone

        return ValidationResult(
            finding_id=request.finding_id,
            outcome=outcome,
            message=message,
            evidence=[evidence],
            validator="securecommerce",
            validated_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )


class _HTTPResponse:
    """Internal representation of a controlled HTTP response."""

    def __init__(
        self,
        *,
        status: int,
        body: str,
        headers: dict[str, str],
        request: str,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers
        self.request = request


__all__ = [
    "SecureCommerceValidator",
]
```
