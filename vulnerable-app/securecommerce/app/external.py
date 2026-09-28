```python
# SecureCommerce external integration

from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Blueprint, request

external_bp = Blueprint(
    "external",
    __name__,
    url_prefix="/external",
)


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
```
