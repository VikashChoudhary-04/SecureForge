"""Deliberately vulnerable routes for the SecureCommerce lab."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .security import current_user
from .vulnerabilities import (
    vulnerable_admin_action,
    vulnerable_fetch_url,
    vulnerable_file_path,
    vulnerable_profile_lookup,
    vulnerable_user_lookup,
)

vulnerable_bp = Blueprint(
    "vulnerable",
    __name__,
    url_prefix="/vulnerable",
)


@vulnerable_bp.get("/search-user")
def search_user():
    """Intentionally vulnerable SQL query endpoint."""
    user_id = request.args.get("user_id")

    if user_id is None:
        return (
            jsonify(
                {
                    "error": "user_id is required"
                }
            ),
            400,
        )

    try:
        result = vulnerable_user_lookup(
            user_id
        )
    except Exception as exc:
        return (
            jsonify(
                {
                    "error": "database query failed",
                    "detail": str(exc),
                }
            ),
            500,
        )

    if result is None:
        return (
            jsonify(
                {
                    "error": "user not found"
                }
            ),
            404,
        )

    return jsonify(result)


@vulnerable_bp.get("/search")
def search():
    """Intentionally vulnerable reflected-XSS endpoint."""
    query = request.args.get(
        "q",
        request.args.get(
            "query",
            "",
        ),
    )

    return (
        "<!doctype html>"
        "<html>"
        "<head><title>SecureCommerce Search</title></head>"
        "<body>"
        "<h1>Product Search</h1>"
        "<p>Search backend: SQLite database</p>"
        f"<p>Search results for: {query}</p>"
        "</body>"
        "</html>"
    )


@vulnerable_bp.get("/profile/<int:user_id>")
def vulnerable_profile(user_id: int):
    """Intentionally vulnerable object-level authorization endpoint."""
    result = vulnerable_profile_lookup(
        user_id
    )

    if result is None:
        return (
            jsonify(
                {
                    "error": "user not found"
                }
            ),
            404,
        )

    return jsonify(
        {
            "warning": (
                "This endpoint intentionally omits "
                "object-level authorization."
            ),
            "profile": result,
        }
    )


@vulnerable_bp.route(
    "/admin-action",
    methods=["GET", "POST"],
)
def vulnerable_admin():
    """Intentionally vulnerable function-level authorization endpoint."""
    data = request.get_json(
        silent=True
    ) or {}

    if request.method == "GET":
        action = request.args.get(
            "action",
            "list_users",
        )
    else:
        action = data.get("action")

    if not isinstance(action, str) or not action.strip():
        return (
            jsonify(
                {
                    "error": "action is required"
                }
            ),
            400,
        )

    result = vulnerable_admin_action(
        action.strip()
    )

    user = current_user()

    return jsonify(
        {
            "warning": (
                "This endpoint intentionally does "
                "not enforce administrative authorization."
            ),
            "request_identity": {
                "authenticated": user is not None,
                "user_id": user.id if user else None,
                "username": (
                    user.username
                    if user
                    else None
                ),
                "email": (
                    user.email
                    if user
                    else None
                ),
                "role": (
                    user.role
                    if user
                    else None
                ),
            },
            "result": result,
        }
    )


@vulnerable_bp.get("/download")
def vulnerable_download():
    """Intentionally vulnerable file path endpoint."""
    filename = request.args.get("filename")

    if filename is None:
        return (
            jsonify(
                {
                    "error": "filename is required"
                }
            ),
            400,
        )

    path = vulnerable_file_path(
        filename
    )

    return jsonify(
        {
            "warning": (
                "This endpoint intentionally "
                "does not validate the file path."
            ),
            "requested_filename": filename,
            "resolved_path": str(
                path.resolve()
            ),
        }
    )


@vulnerable_bp.get("/fetch")
def vulnerable_fetch():
    """Intentionally vulnerable SSRF endpoint."""
    url = request.args.get("url")

    if url is None:
        return (
            jsonify(
                {
                    "error": "url is required"
                }
            ),
            400,
        )

    result = vulnerable_fetch_url(
        url
    )

    status_code = (
        200
        if result.get("status") == "success"
        else 502
    )

    return (
        jsonify(
            {
                "warning": (
                    "This endpoint intentionally "
                    "does not restrict destination hosts."
                ),
                "result": result,
            }
        ),
        status_code,
    )


__all__ = [
    "vulnerable_bp",
]
