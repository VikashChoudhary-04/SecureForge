```python
"""Tests for the SecureForge API validator."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from secureforge.validation.api import APIValidator
from secureforge.validation.base import ValidationError
from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)


class APIHandler(BaseHTTPRequestHandler):
    """Small local API server used for validator tests."""

    def do_GET(self) -> None:
        if self.path == "/api/users":
            self._send_json(
                200,
                {"users": ["alice", "bob"]},
            )
            return

        self._send_json(
            404,
            {"error": "not found"},
        )

    def do_POST(self) -> None:
        if self.path != "/api/users":
            self._send_json(
                404,
                {"error": "not found"},
            )
            return

        length = int(
            self.headers.get("Content-Length", "0")
        )
        body = self.rfile.read(length).decode(
            "utf-8",
            errors="replace",
        )

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(
                400,
                {"error": "invalid json"},
            )
            return

        self._send_json(
            201,
            {
                "created": True,
                "payload": payload,
            },
        )

    def _send_json(
        self,
        status: int,
        payload: dict,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        return


@pytest.fixture()
def api_server() -> tuple[str, HTTPServer]:
    server = HTTPServer(
        ("127.0.0.1", 0),
        APIHandler,
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
    endpoint: str = "/api/users",
    payload: str | None = None,
    metadata: dict[str, str] | None = None,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id="API-001",
        target=target,
        method=ValidationMethod.API,
        endpoint=endpoint,
        payload=payload,
        metadata=metadata or {},
    )


def test_api_validator_supports_api_method() -> None:
    validator = APIValidator()

    request = build_request(
        "http://localhost:5000",
    )

    assert validator.supports(request) is True


def test_api_validator_rejects_other_methods() -> None:
    validator = APIValidator()

    request = ValidationRequest(
        finding_id="API-001",
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
    )

    assert validator.supports(request) is False


def test_api_validator_requires_endpoint() -> None:
    validator = APIValidator()

    request = ValidationRequest(
        finding_id="API-001",
        target="http://localhost:5000",
        method=ValidationMethod.API,
    )

    with pytest.raises(
        ValidationError,
        match="requires an endpoint",
    ):
        validator.validate(request)


def test_api_validator_records_successful_get(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        metadata={
            "expected_status": "200",
        },
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.validator == "api"
    assert result.evidence[0].request == (
        f"GET {target}/api/users"
    )
    assert result.evidence[0].response is not None
    assert "alice" in result.evidence[0].response
    assert result.evidence[0].observed == "HTTP status 200"


def test_api_validator_rejects_unexpected_status(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        metadata={
            "expected_status": "403",
        },
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.REJECTED
    assert result.evidence[0].expected == "HTTP status 403"
    assert result.evidence[0].observed == "HTTP status 200"


def test_api_validator_supports_status_ranges(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        metadata={
            "expected_status": "200-299",
        },
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED


def test_api_validator_sends_json_post(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        payload='{"username": "alice"}',
        metadata={
            "http_method": "POST",
            "expected_status": "201",
        },
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.evidence[0].observed == "HTTP status 201"


def test_api_validator_accepts_custom_headers(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        metadata={
            "headers": json.dumps(
                {
                    "Authorization": "Bearer test-token",
                    "X-Test": "SecureForge",
                }
            ),
            "expected_status": "200",
        },
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.CONFIRMED


def test_api_validator_rejects_invalid_headers_json() -> None:
    validator = APIValidator()

    request = build_request(
        "http://localhost:5000",
        metadata={
            "headers": "{invalid-json",
        },
    )

    with pytest.raises(
        ValidationError,
        match="Invalid API headers JSON",
    ):
        validator.validate(request)


def test_api_validator_rejects_non_object_headers() -> None:
    validator = APIValidator()

    request = build_request(
        "http://localhost:5000",
        metadata={
            "headers": '["Authorization"]',
        },
    )

    with pytest.raises(
        ValidationError,
        match="headers must be a JSON object",
    ):
        validator.validate(request)


def test_api_validator_rejects_invalid_json_payload() -> None:
    validator = APIValidator()

    request = build_request(
        "http://localhost:5000",
        payload="{invalid-json",
        metadata={
            "http_method": "POST",
        },
    )

    with pytest.raises(
        ValidationError,
        match="Invalid API JSON payload",
    ):
        validator.validate(request)


def test_api_validator_handles_http_error(
    api_server: tuple[str, HTTPServer],
) -> None:
    target, _ = api_server
    validator = APIValidator()

    request = build_request(
        target,
        endpoint="/missing",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.evidence[0].observed == "HTTP status 404"


def test_api_validator_handles_unreachable_target() -> None:
    validator = APIValidator(timeout=0.2)

    request = build_request(
        "http://127.0.0.1:1",
    )

    result = validator.validate(request)

    assert result.outcome == ValidationOutcome.ERROR
    assert result.validator == "api"
    assert result.evidence[0].observed is not None


def test_api_validator_builds_endpoint_without_leading_slash() -> None:
    url = APIValidator._build_url(
        "http://localhost:5000/",
        "api/users",
    )

    assert url == "http://localhost:5000/api/users"


def test_api_validator_rejects_empty_endpoint() -> None:
    with pytest.raises(
        ValidationError,
        match="endpoint must not be empty",
    ):
        APIValidator._build_url(
            "http://localhost:5000",
            "   ",
        )
```
