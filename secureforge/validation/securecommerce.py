# SecureCommerce-specific security validators

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
        "SSRF-001",
        "UPLOAD-001",
        "PATH-TRAVERSAL-001",
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

        validators = {
            "BOLA-001": self._validate_bola,
            "SQLI-001": self._validate_sqli,
            "XSS-001": self._validate_xss,
            "AUTHZ-001": self._validate_authorization,
            "SECRET-001": self._validate_secret,
            "MISCONFIG-001": self._validate_misconfiguration,
            "SSRF-001": self._validate_ssrf,
            "UPLOAD-001": self._validate_upload,
            "PATH-TRAVERSAL-001": self._validate_path_traversal,
        }

        validator = validators.get(
            finding_id
        )

        if validator is None:
            raise ValidationError(
                "Unsupported SecureCommerce finding: "
                f"{finding_id}"
            )

        return validator(request)

    def _validate_bola(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate unauthorized object-level access."""
        endpoint = (
            request.endpoint
            or "/api/users/2"
        )

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
                    method=self._validation_method(request),
                    description=(
                        "Controlled BOLA validation request."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
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
                    method=self._validation_method(request),
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
        endpoint = (
            request.endpoint
            or "/vulnerable/search"
        )

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
                        "The application should process input "
                        "without exposing database errors."
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
        endpoint = (
            request.endpoint
            or "/vulnerable/search"
        )

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
                        "User-controlled HTML should be encoded."
                    ),
                    observed=(
                        "The exact controlled marker was reflected."
                    ),
                ),
            )

        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message=(
                "The controlled XSS marker was not reflected "
                "as unencoded HTML."
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
                observed="Marker not reflected as raw HTML.",
            ),
        )

    def _validate_authorization(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate protected administrative functionality."""
        endpoint = (
            request.endpoint
            or "/vulnerable/admin-action"
        )

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

        response = self._request(
            request=request,
            endpoint=request.endpoint or "/",
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
                "The synthetic lab secret was not exposed."
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
        """Validate controlled development-server exposure."""
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/",
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

    def _validate_ssrf(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate the controlled SSRF endpoint."""
        endpoint = (
            request.endpoint
            or "/external/fetch"
        )

        internal_target = (
            request.payload
            or request.metadata.get(
                "ssrf_target",
                "http://127.0.0.1:5000/",
            )
        )

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
            parameter=request.parameter or "url",
            payload=internal_target,
        )

        body_lower = response.body.lower()

        indicators = (
            '"status":"fetched"',
            '"status": "fetched"',
            "securecommerce",
        )

        if response.status == 200 and any(
            indicator in body_lower
            for indicator in indicators
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The application fetched a controlled "
                    "internal resource through a user-supplied URL."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled SSRF validation against the "
                        "SecureCommerce lab application."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "User-controlled URLs should not allow "
                        "access to internal resources."
                    ),
                    observed=(
                        "The internal target was fetched."
                    ),
                ),
            )

        if response.status in {400, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The application rejected the controlled "
                    "internal-resource request."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled SSRF validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 400 or 403.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._inconclusive(
            request=request,
            message=(
                "The SSRF response did not provide sufficient "
                "evidence to confirm or reject the finding."
            ),
            response=response,
        )

    def _validate_upload(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate insecure file-upload handling."""
        endpoint = (
            request.endpoint
            or "/upload/"
        )

        filename = (
            request.payload
            or "secureforge-test.txt"
        )

        boundary = "----SecureForgeBoundary"

        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; '
            f'name="file"; filename="{filename}"\r\n'
            "Content-Type: text/plain\r\n"
            "\r\n"
            "SecureForge controlled upload\r\n"
            f"--{boundary}--\r\n"
        ).encode()

        response = self._request_raw(
            request=request,
            endpoint=endpoint,
            method="POST",
            body=body,
            headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary}"
                )
            },
        )

        if response.status == 201:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "The application accepted the controlled "
                    "file upload without the expected security "
                    "validation controls."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled file-upload validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "Untrusted file uploads should be "
                        "subject to security validation."
                    ),
                    observed=f"HTTP {response.status}",
                ),
            )

        if response.status in {400, 403, 415}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The application rejected the controlled "
                    "file upload."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled file-upload validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="HTTP 400, 403, or 415.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._inconclusive(
            request=request,
            message=(
                "The file-upload response was inconclusive."
            ),
            response=response,
        )

    def _validate_path_traversal(
        self,
        request: ValidationRequest,
    ) -> ValidationResult:
        """Validate controlled path-traversal behavior."""
        endpoint = (
            request.endpoint
            or "/upload/download/.."
        )

        traversal_path = (
            request.payload
            or "../securecommerce/app.py"
        )

        if request.payload is None:
            endpoint = (
                "/upload/download/"
                + traversal_path
            )

        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )

        traversal_markers = (
            "from flask import",
            "create_app",
            "securecommerce",
        )

        if response.status == 200 and any(
            marker.lower() in response.body.lower()
            for marker in traversal_markers
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message=(
                    "Controlled path traversal exposed "
                    "application source content."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled path-traversal validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected=(
                        "File paths must remain confined "
                        "to the intended upload directory."
                    ),
                    observed=(
                        "Application source content was returned."
                    ),
                ),
            )

        if response.status in {400, 403, 404}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message=(
                    "The controlled traversal request did not "
                    "return the targeted application file."
                ),
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description=(
                        "Controlled path-traversal validation."
                    ),
                    request=response.request,
                    response=response.body,
                    expected="No traversal-controlled file access.",
                    observed=f"HTTP {response.status}",
                ),
            )

        return self._inconclusive(
            request=request,
            message=(
                "The path-traversal response was inconclusive."
            ),
            response=response,
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
        """Perform a controlled HTTP request."""
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
            separator = (
                "&"
                if "?" in url
                else "?"
            )

            url = (
                f"{url}{separator}"
                f"{quote(parameter, safe='')}="
                f"{quote(payload, safe='')}"
            )

        return self._request_raw(
            request=request,
            endpoint=url,
            method=method,
            absolute_url=True,
        )

    def _request_raw(
        self,
        *,
        request: ValidationRequest,
        endpoint: str,
        method: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        absolute_url: bool = False,
    ) -> "_HTTPResponse":
        """Perform one controlled raw HTTP request."""
        if absolute_url:
            url = endpoint
        else:
            url = self._build_url(
                target=request.target,
                endpoint=endpoint,
            )

        request_headers = {
            "User-Agent": "SecureForge-Validator/0.1",
        }

        if headers:
            request_headers.update(
                headers
            )

        http_request = Request(
            url,
            data=body,
            method=method,
            headers=request_headers,
        )

        try:
            with urlopen(
                http_request,
                timeout=5,
            ) as response:
                response_body = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                return _HTTPResponse(
                    status=response.status,
                    body=response_body,
                    headers=dict(
                        response.headers.items()
                    ),
                    request=f"{method} {url}",
                )

        except HTTPError as exc:
            response_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            return _HTTPResponse(
                status=exc.code,
                body=response_body,
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
    def _validation_method(
        request: ValidationRequest,
    ) -> ValidationMethod:
        """Return the evidence method for an HTTP request."""
        if request.method == ValidationMethod.API:
            return ValidationMethod.API

        return ValidationMethod.HTTP

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
                method=self._validation_method(request),
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

