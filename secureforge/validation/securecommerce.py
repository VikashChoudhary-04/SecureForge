```python id="7q3m8k"
"""SecureCommerce-specific security validators for SecureForge."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
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
        """Return whether this validator supports the finding."""
        return (
            request.finding_id.upper()
            in self.SUPPORTED_FINDINGS
        )

    def validate(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate one supported SecureCommerce finding."""
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
        """Validate unauthorized object-level access."""
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
                    "The object endpoint returned HTTP 200 "
                    "without evidence of authorization enforcement."
                ),
                evidence=ValidationEvidence(
                    method=(
                        ValidationMethod.API
                        if request.method == ValidationMethod.API
                        else ValidationMethod.HTTP
                    ),
                    description=(
                        "Controlled BOLA validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403 for unauthorized access.",
                    observed=f"HTTP {response.status}",
                ),
            )

        if response.status in {401, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The application rejected unauthorized "
                    "object access."
                ),
                evidence=ValidationEvidence(
                    method=(
                        ValidationMethod.API
                        if request.method == ValidationMethod.API
                        else ValidationMethod.HTTP
                    ),
                    description=(
                        "Controlled BOLA validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._inconclusive(
            request=request,
            message=(
                "The response did not provide sufficient "
                "evidence to confirm or reject BOLA."
            ),
            response=response,
        )

    def _validate_sqli(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate controlled SQL injection behavior."""
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
            "database error",
            "unrecognized token",
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
                        "Controlled SQL injection validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "The application should handle the "
                        "input without database errors."
                    ),
                    observed=(
                        "Database error marker detected."
                    ),
                ),
            )

        return self._inconclusive(
            request=request,
            message=(
                "No definitive SQL injection evidence was "
                "identified from the controlled response."
            ),
            response=response,
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
                    "without output encoding."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled reflected-XSS validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "User-controlled HTML should be "
                        "encoded before reflection."
                    ),
                    observed=(
                        "The exact controlled marker was reflected."
                    ),
                ),
            )

        if (
            quote(payload, safe="")
            in response.body
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The XSS marker was present only in "
                    "URL-encoded form."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled reflected-XSS validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "Unencoded marker must not be reflected."
                    ),
                    observed=(
                        "Only encoded marker was observed."
                    ),
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
                    "Controlled reflected-XSS validation."
                ),
                request=response.request,
                response=response.body,
                expected=(
                    "Unencoded marker should not be reflected."
                ),
                observed="Marker not reflected.",
            ),
        )

    def _validate_authorization(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate protected administrative functionality."""
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

        return self._inconclusive(
            request=request,
            message=(
                "The authorization response was inconclusive."
            ),
            response=response,
        )

    def _validate_secret(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate exposure of a synthetic lab secret."""
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
                    "in the tested response."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled synthetic-secret exposure test."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "The synthetic lab secret must not "
                        "appear in the response."
                    ),
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
                expected=(
                    "The synthetic lab secret must not "
                    "appear in the response."
                ),
                observed="Synthetic secret not detected.",
            ),
        )

    def _validate_misconfiguration(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate the controlled development-server exposure."""
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
                    "The application exposed development-server "
                    "identification."
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

        return self._inconclusive(
            request=request,
            message=(
                "The tested response did not expose the "
                "expected misconfiguration marker."
            ),
            response=response,
            observed=(
                server_header
                if server_header
                else "No Server header."
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
        if request.method not in {
            ValidationMethod.HTTP,
            ValidationMethod.API,
        }:
            raise ValidationError(
                "SecureCommerce HTTP validation requires "
                "HTTP or API validation mode."
            )

        url = self._build_url(
            target=request.target,
            endpoint=endpoint,
        )

        if parameter and payload is not None:
            separator = "&" if "?" in url else "?"

            url = (
                f"{url}{separator}"
                f"{quote(parameter, safe='')}="
                f"{quote(payload, safe='')}"
            )

        headers = {
            "User-Agent": "SecureForge-Validator/0.1",
        }

        http_request = Request(
            url,
            method=method,
            headers=headers,
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
                    headers=dict(
                        response.headers.items()
                    ),
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
                headers=dict(
                    exc.headers.items()
                ),
                request=f"{method} {url}",
            )

        except (
            URLError,
            TimeoutError,
            OSError,
        ) as exc:
            raise ValidationError(
                "SecureCommerce request failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    @staticmethod
    def _build_url(
        *,
        target: str,
        endpoint: str,
    ) -> str:
        """Build a target URL."""
        return (
            f"{target.rstrip('/')}/"
            f"{endpoint.lstrip('/')}"
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

    def _inconclusive(
        self,
        *,
        request: ValidationRequest,
        message: str,
        response: "_HTTPResponse",
        observed: str | None = None,
    ) -> ValidationResult:
        """Construct an inconclusive validation result."""
        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=message,
            evidence=ValidationEvidence(
                method=(
                    ValidationMethod.API
                    if request.method == ValidationMethod.API
                    else ValidationMethod.HTTP
                ),
                description=(
                    "Controlled SecureCommerce validation."
                ),
                request=response.request,
                response=response.body,
                observed=(
                    observed
                    if observed is not None
                    else f"HTTP {response.status}"
                ),
            ),
        )


@dataclass(frozen=True)
class _HTTPResponse:
    """Internal representation of a controlled HTTP response."""

    status: int
    body: str
    headers: dict[str, str]
    request: str


__all__ = [
    "SecureCommerceValidator",
]
```
