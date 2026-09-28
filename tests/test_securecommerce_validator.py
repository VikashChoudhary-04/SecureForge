```python
# SecureCommerce validation tests

from __future__ import annotations

from unittest.mock import patch

from secureforge.validation.models import (
    ValidationMethod,
    ValidationOutcome,
    ValidationRequest,
)
from secureforge.validation.securecommerce import (
    SecureCommerceValidator,
    _HTTPResponse,
)


def make_request(
    finding_id: str,
    *,
    endpoint: str | None = None,
    parameter: str | None = None,
    payload: str | None = None,
) -> ValidationRequest:
    return ValidationRequest(
        finding_id=finding_id,
        target="http://localhost:5000",
        method=ValidationMethod.HTTP,
        endpoint=endpoint,
        parameter=parameter,
        payload=payload,
    )


def test_supports_known_securecommerce_findings():
    validator = SecureCommerceValidator()

    for finding_id in {
        "BOLA-001",
        "SQLI-001",
        "XSS-001",
        "AUTHZ-001",
        "SECRET-001",
        "MISCONFIG-001",
    }:
        request = make_request(finding_id)

        assert validator.supports(request) is True


def test_rejects_unknown_finding():
    validator = SecureCommerceValidator()

    request = make_request("UNKNOWN-001")

    assert validator.supports(request) is False


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_bola_confirms_unauthorized_object_access(
    mock_request,
):
    mock_request.return_value = _HTTPResponse(
        status=200,
        body='{"id": 2, "username": "alice"}',
        headers={},
        request="GET http://localhost:5000/api/users/2",
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "BOLA-001",
            endpoint="/api/users/2",
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.finding_id == "BOLA-001"


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_bola_rejects_when_access_is_forbidden(
    mock_request,
):
    mock_request.return_value = _HTTPResponse(
        status=403,
        body="Forbidden",
        headers={},
        request="GET http://localhost:5000/api/users/2",
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "BOLA-001",
            endpoint="/api/users/2",
        )
    )

    assert result.outcome == ValidationOutcome.REJECTED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_sqli_confirms_database_error(
    mock_request,
):
    mock_request.return_value = _HTTPResponse(
        status=500,
        body="sqlite error: near \"OR\": syntax error",
        headers={},
        request=(
            "GET http://localhost:5000/"
            "vulnerable/search?q=%27%20OR%20%271%27%3D%271"
        ),
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "SQLI-001",
            endpoint="/vulnerable/search",
            parameter="q",
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_xss_confirms_unencoded_marker(
    mock_request,
):
    marker = "<SecureForge-XSS-Test>"

    mock_request.return_value = _HTTPResponse(
        status=200,
        body=(
            f"<html><body>{marker}</body></html>"
        ),
        headers={},
        request=(
            "GET http://localhost:5000/"
            "vulnerable/search?q=%3CSecureForge-XSS-Test%3E"
        ),
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "XSS-001",
            endpoint="/vulnerable/search",
            parameter="q",
            payload=marker,
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_xss_rejects_when_marker_is_not_reflected(
    mock_request,
):
    marker = "<SecureForge-XSS-Test>"

    mock_request.return_value = _HTTPResponse(
        status=200,
        body="<html><body>No user input reflected.</body></html>",
        headers={},
        request="GET http://localhost:5000/vulnerable/search",
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "XSS-001",
            endpoint="/vulnerable/search",
            parameter="q",
            payload=marker,
        )
    )

    assert result.outcome == ValidationOutcome.REJECTED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_authorization_confirms_unprotected_admin_endpoint(
    mock_request,
):
    mock_request.return_value = _HTTPResponse(
        status=200,
        body="Admin action executed.",
        headers={},
        request=(
            "GET http://localhost:5000/"
            "vulnerable/admin-action"
        ),
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "AUTHZ-001",
            endpoint="/vulnerable/admin-action",
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_secret_confirms_synthetic_secret_exposure(
    mock_request,
):
    marker = "SECURECOMMERCE_FAKE_SECRET"

    mock_request.return_value = _HTTPResponse(
        status=200,
        body=f"configuration={marker}",
        headers={},
        request="GET http://localhost:5000/",
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "SECRET-001",
            endpoint="/",
            payload=marker,
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_misconfiguration_confirms_werkzeug_header(
    mock_request,
):
    mock_request.return_value = _HTTPResponse(
        status=200,
        body="SecureCommerce",
        headers={
            "Server": "Werkzeug/3.1.0 Python/3.12",
        },
        request="GET http://localhost:5000/",
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request(
            "MISCONFIG-001",
            endpoint="/",
        )
    )

    assert result.outcome == ValidationOutcome.CONFIRMED


@patch.object(
    SecureCommerceValidator,
    "_request",
)
def test_network_failure_is_returned_as_validation_error(
    mock_request,
):
    from secureforge.validation.base import ValidationError

    mock_request.side_effect = ValidationError(
        "connection refused"
    )

    validator = SecureCommerceValidator()

    result = validator.validate(
        make_request("BOLA-001")
    )

    assert result.outcome == ValidationOutcome.ERROR
    assert result.finding_id == "BOLA-001"
```
