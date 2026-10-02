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

    def supports(self, request: ValidationRequest) -> bool:
        return request.finding_id.upper() in self.SUPPORTED_FINDINGS

    def validate(self, request: ValidationRequest) -> ValidationResult:
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

        validator = validators.get(finding_id)
        if validator is None:
            raise ValidationError(
                f"Unsupported SecureCommerce finding: {finding_id}"
            )

        try:
            return validator(request)
        except ValidationError as exc:
            return self._result(
                request=request,
                outcome=ValidationOutcome.ERROR,
                message=str(exc),
                evidence=ValidationEvidence(
                    method=self._validation_method(request),
                    description="SecureCommerce validation error.",
                    observed=str(exc),
                ),
            )

    def _validate_bola(self, request):
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/api/users/2",
            method="GET",
        )
        if response.status == 200:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The object endpoint returned HTTP 200 without evidence of authorization enforcement.",
                evidence=ValidationEvidence(
                    method=self._validation_method(request),
                    description="Controlled BOLA validation request.",
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
                message="The application rejected unauthorized object access.",
                evidence=ValidationEvidence(
                    method=self._validation_method(request),
                    description="Controlled BOLA validation request.",
                    request=response.request,
                    response=response.body,
                    expected="HTTP 401 or 403.",
                    observed=f"HTTP {response.status}",
                ),
            )
        return self._inconclusive(
            request=request,
            message="The response did not provide sufficient evidence to confirm or reject BOLA.",
            response=response,
        )

    def _validate_sqli(self, request):
        payload = request.payload or "' OR '1'='1"
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/vulnerable/search",
            method="GET",
            parameter=request.parameter or "q",
            payload=payload,
        )
        body = response.body.lower()
        if any(marker in body for marker in (
            "sqlite error",
            "sql syntax",
            "operationalerror",
            "database error",
            "unrecognized token",
        )):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The controlled SQL injection payload produced database error evidence.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled SQL injection validation.",
                    request=response.request,
                    response=response.body,
                    observed="Database error marker detected.",
                ),
            )
        return self._inconclusive(
            request=request,
            message="No definitive SQL injection evidence was identified from the controlled response.",
            response=response,
        )

    def _validate_xss(self, request):
        payload = request.payload or "<SecureForge-XSS-Test>"
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/vulnerable/search",
            method="GET",
            parameter=request.parameter or "q",
            payload=payload,
        )
        if payload in response.body:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The controlled XSS marker was reflected without output encoding.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled reflected-XSS validation.",
                    request=response.request,
                    response=response.body,
                    observed="The exact controlled marker was reflected.",
                ),
            )
        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message="The controlled XSS marker was not reflected as unencoded HTML.",
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description="Controlled reflected-XSS validation.",
                request=response.request,
                response=response.body,
                observed="Marker not reflected as raw HTML.",
            ),
        )

    def _validate_authorization(self, request):
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/vulnerable/admin-action",
            method="GET",
        )
        if response.status == 200:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The protected administrative endpoint returned HTTP 200 without the expected authorization control.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled function-level authorization test.",
                    request=response.request,
                    response=response.body,
                    observed="HTTP 200.",
                ),
            )
        if response.status in {401, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message="The protected administrative endpoint enforced authorization.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled function-level authorization test.",
                    request=response.request,
                    response=response.body,
                    observed=f"HTTP {response.status}",
                ),
            )
        return self._inconclusive(
            request=request,
            message="The authorization response was inconclusive.",
            response=response,
        )

    def _validate_secret(self, request):
        marker = request.payload or "SECURECOMMERCE_FAKE_SECRET"
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/",
            method="GET",
        )
        if marker in response.body:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The synthetic lab secret was exposed in the tested response.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled synthetic-secret exposure test.",
                    request=response.request,
                    response=response.body,
                    observed="Synthetic secret detected.",
                ),
            )
        return self._result(
            request=request,
            outcome=ValidationOutcome.REJECTED,
            message="The synthetic lab secret was not exposed.",
            evidence=ValidationEvidence(
                method=ValidationMethod.HTTP,
                description="Controlled synthetic-secret exposure test.",
                request=response.request,
                response=response.body,
                observed="Synthetic secret not detected.",
            ),
        )

    def _validate_misconfiguration(self, request):
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/",
            method="GET",
        )
        server = response.headers.get("Server", "")
        if "Werkzeug" in server:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The application exposed development-server identification.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled security-configuration validation.",
                    request=response.request,
                    response=response.body,
                    observed=server,
                ),
            )
        return self._inconclusive(
            request=request,
            message="The tested response did not expose the expected misconfiguration marker.",
            response=response,
            observed=server or "No Server header.",
        )

    def _validate_ssrf(self, request):
        target = request.payload or request.metadata.get(
            "ssrf_target",
            "http://127.0.0.1:5000/",
        )
        response = self._request(
            request=request,
            endpoint=request.endpoint or "/external/fetch",
            method="GET",
            parameter=request.parameter or "url",
            payload=target,
        )
        body = response.body.lower()
        if response.status == 200 and any(
            marker in body
            for marker in (
                '"status":"fetched"',
                '"status": "fetched"',
                "securecommerce",
            )
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The application fetched a controlled internal resource through a user-supplied URL.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled SSRF validation.",
                    request=response.request,
                    response=response.body,
                    observed="The internal target was fetched.",
                ),
            )
        if response.status in {400, 403}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message="The application rejected the controlled internal-resource request.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled SSRF validation.",
                    request=response.request,
                    response=response.body,
                    observed=f"HTTP {response.status}",
                ),
            )
        return self._inconclusive(
            request=request,
            message="The SSRF response did not provide sufficient evidence to confirm or reject the finding.",
            response=response,
        )

    def _validate_upload(self, request):
        endpoint = request.endpoint or "/upload/"
        filename = request.payload or "secureforge-test.txt"
        boundary = "----SecureForgeBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "SecureForge controlled upload\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        response = self._request_raw(
            request=request,
            endpoint=endpoint,
            method="POST",
            body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}"
            },
        )
        if response.status == 201:
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="The application accepted the controlled file upload without the expected security validation controls.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled file-upload validation.",
                    request=response.request,
                    response=response.body,
                    observed=f"HTTP {response.status}",
                ),
            )
        if response.status in {400, 403, 415}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message="The application rejected the controlled file upload.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled file-upload validation.",
                    request=response.request,
                    response=response.body,
                    observed=f"HTTP {response.status}",
                ),
            )
        return self._inconclusive(
            request=request,
            message="The file-upload response was inconclusive.",
            response=response,
        )

    def _validate_path_traversal(self, request):
        traversal_path = request.payload or "../securecommerce/app.py"
        endpoint = request.endpoint or (
            "/upload/download/" + traversal_path
        )
        response = self._request(
            request=request,
            endpoint=endpoint,
            method="GET",
        )
        markers = (
            "from flask import",
            "create_app",
            "securecommerce",
        )
        if response.status == 200 and any(
            marker.lower() in response.body.lower()
            for marker in markers
        ):
            return self._result(
                request=request,
                outcome=ValidationOutcome.CONFIRMED,
                message="Controlled path traversal exposed application source content.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled path-traversal validation.",
                    request=response.request,
                    response=response.body,
                    observed="Application source content was returned.",
                ),
            )
        if response.status in {400, 403, 404}:
            return self._result(
                request=request,
                outcome=ValidationOutcome.REJECTED,
                message="The controlled traversal request did not return the targeted application file.",
                evidence=ValidationEvidence(
                    method=ValidationMethod.HTTP,
                    description="Controlled path-traversal validation.",
                    request=response.request,
                    response=response.body,
                    observed=f"HTTP {response.status}",
                ),
            )
        return self._inconclusive(
            request=request,
            message="The path-traversal response was inconclusive.",
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
    ):
        if request.method not in {
            ValidationMethod.HTTP,
            ValidationMethod.API,
        }:
            raise ValidationError(
                "SecureCommerce HTTP validation requires HTTP or API validation mode."
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
    ):
        url = endpoint if absolute_url else self._build_url(
            target=request.target,
            endpoint=endpoint,
        )

        request_headers = {
            "User-Agent": "SecureForge-Validator/0.1"
        }
        if headers:
            request_headers.update(headers)

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
                return _HTTPResponse(
                    status=response.status,
                    body=response.read().decode(
                        "utf-8",
                        errors="replace",
                    ),
                    headers=dict(response.headers.items()),
                    request=f"{method} {url}",
                )
        except HTTPError as exc:
            return _HTTPResponse(
                status=exc.code,
                body=exc.read().decode(
                    "utf-8",
                    errors="replace",
                ),
                headers=dict(exc.headers.items()),
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
    def _build_url(*, target: str, endpoint: str) -> str:
        return f"{target.rstrip('/')}/{endpoint.lstrip('/')}"

    @staticmethod
    def _validation_method(request):
        return (
            ValidationMethod.API
            if request.method == ValidationMethod.API
            else ValidationMethod.HTTP
        )

    @staticmethod
    def _result(
        *,
        request,
        outcome,
        message,
        evidence,
    ):
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
        request,
        message,
        response,
        observed=None,
    ):
        return self._result(
            request=request,
            outcome=ValidationOutcome.INCONCLUSIVE,
            message=message,
            evidence=ValidationEvidence(
                method=self._validation_method(request),
                description="Controlled SecureCommerce validation.",
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


__all__ = ["SecureCommerceValidator"]
