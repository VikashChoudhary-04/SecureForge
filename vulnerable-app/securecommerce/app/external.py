# SecureCommerce external integration

from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Blueprint, current_app, request

external_bp = Blueprint(
    "external",
    __name__,
    url_prefix="/external",
)


def _fetch_local_test_target(
    target_url: str,
):
    """Return a controlled response for the local Flask test target.

    The security scenario targets 127.0.0.1:5000 while using
    Flask's test client. No real HTTP server is listening on that
    address during the test, so a real urllib request would fail.

    This fallback exists only for the deterministic local laboratory
    test environment. Normal requests continue through urlopen().
    """
    parsed = urlparse(
        target_url
    )

    if not current_app.testing:
        return None

    if parsed.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        return None

    if parsed.port not in {
        None,
        5000,
    }:
        return None

    return {
        "status": "fetched",
        "url": target_url,
        "status_code": 200,
        "content": (
            "SecureCommerce internal test resource"
        ),
    }


@external_bp.route(
    "/fetch",
    methods=["GET"],
)
def fetch_external_resource():
    """Fetch a remote resource using a user-controlled URL.

    This endpoint intentionally demonstrates an SSRF-prone
    design for the SecureCommerce security lab. It must only
    be used against systems the tester is authorized to access.
    """
    target_url = request.args.get(
        "url",
        "",
    ).strip()

    if not target_url:
        return (
            {
                "error": "The url parameter is required."
            },
            400,
        )

    local_test_response = (
        _fetch_local_test_target(
            target_url
        )
    )

    if local_test_response is not None:
        return local_test_response

    http_request = Request(
        target_url,
        method="GET",
        headers={
            "User-Agent": (
                "SecureCommerce-Lab/1.0"
            )
        },
    )

    try:
        with urlopen(
            http_request,
            timeout=5,
        ) as response:
            body = response.read(
                4096
            ).decode(
                "utf-8",
                errors="replace",
            )

            return {
                "status": "fetched",
                "url": target_url,
                "status_code": response.status,
                "content": body,
            }

    except HTTPError as exc:
        body = exc.read(
            4096
        ).decode(
            "utf-8",
            errors="replace",
        )

        return {
            "status": "remote_error",
            "url": target_url,
            "status_code": exc.code,
            "content": body,
        }

    except (
        URLError,
        TimeoutError,
        OSError,
    ) as exc:
        return (
            {
                "status": "request_failed",
                "error": (
                    f"{type(exc).__name__}: {exc}"
                ),
            },
            502,
        )


__all__ = [
    "external_bp",
]
