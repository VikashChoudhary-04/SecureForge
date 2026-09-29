"""Tests for the SecureForge HTTP validator."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from secureforge.validation.base import ValidationError
from secureforge.validation.http import HTTPValidator
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)


class TestHandler(BaseHTTPRequestHandler):
    """Small local HTTP server used for validator tests."""

    def do_GET(self) -> None:
        if self.path == "/ok":
            body = b"SecureForge test response."
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/search"):
            body = b"search-result"
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        return


@pytest.fixture()
def http_server() -> tuple[str, HTTPServer]:
    server = HTTPServer(
        ("127.0.0.1", 0),
        TestHandler,
    )

    thread = Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    host, port = server.server_address
    target = f"http://{host}:{port}"

    try:
        yield target, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def build_request(
    target: str,
    *,
    endpoint: str | None = None,
    parameter: str | None = None,
    payload: str | None = None,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="HTTP-001",
        target=target,
        method=ValidationMethod.HTTP,
        endpoint=endpoint,
        parameter=parameter,
        payload=payload,
    )


def test_http_validator_supports_http_method() -> None:
    validator = HTTPValidator()

    request = build_request(
        "http://localhost:5000",
        endpoint="/ok",
    )

    assert validator.supports(request) is True


def test_http_validator_rejects_other_methods() -> None:
    validator = HTTPValidator()

    request = ValidationRequest(
        finding_id="HTTP-001",
        target="http://localhost:5000",
        method=ValidationMethod.API,
    )

    assert validator.supports(request) is False


def test_http_validator_requires_endpoint() -> None:
    validator = HTTPValidator()

    request = build_request(
        "http://localhost:5000",
    )

    with pytest.raises(
        ValidationError,
        match="requires an endpoint",
    ):
        validator.validate(request)


def test_http_validator_requires_target() -> None:
    validator = HTTPValidator()

    request = build_request(
        "",
        endpoint="/ok",
    )

    with pytest.raises(
        ValidationError,
        match="Target must not be empty",
    ):
        validator.validate(request)


def test_http_validator_records_successful_response(
    http_server: tuple[str, HTTPServer],
) -> None:
    target, _ = http_server
    validator = HTTPValidator()

    request = build_request(
        target,
        endpoint="/ok",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.validator == "http"
    assert result.finding_id == "HTTP-001"
    assert result.evidence
    assert result.evidence[0].response is not None
    assert "SecureForge test response." in result.evidence[0].response


def test_http_validator_builds_query_parameter(
    http_server: tuple[str, HTTPServer],
) -> None:
    target, _ = http_server
    validator = HTTPValidator()

    request = build_request(
        target,
        endpoint="/search",
        parameter="q",
        payload="test value",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.evidence[0].request is not None
    assert "q=test+value" in result.evidence[0].request


def test_http_validator_handles_http_error(
    http_server: tuple[str, HTTPServer],
) -> None:
    target, _ = http_server
    validator = HTTPValidator()

    request = build_request(
        target,
        endpoint="/missing",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.evidence[0].observed == "HTTP 404"


def test_http_validator_handles_unreachable_target() -> None:
    validator = HTTPValidator(timeout=0.2)

    request = build_request(
        "http://127.0.0.1:1",
        endpoint="/ok",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.ERROR
    assert result.validator == "http"
    assert result.evidence[0].observed is not None
