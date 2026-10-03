"""Authentication routes for SecureCommerce."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .security import (
    authenticate_user,
    clear_session,
    establish_session,
    get_request_identity,
)

auth_bp = Blueprint(
    "auth",
    __name__,
)


@auth_bp.post("/login")
def login():
    """Authenticate a SecureCommerce user."""
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return (
            jsonify(
                {
                    "error": "username is required"
                }
            ),
            400,
        )

    if not isinstance(password, str) or not password:
        return (
            jsonify(
                {
                    "error": "password is required"
                }
            ),
            400,
        )

    user = authenticate_user(
        username.strip(),
        password,
    )

    if user is None:
        return (
            jsonify(
                {
                    "error": "invalid credentials"
                }
            ),
            401,
        )

    establish_session(user)

    return jsonify(
        {
            "message": "login successful",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
            },
        }
    )


@auth_bp.post("/logout")
def logout():
    """Terminate the current authentication session."""
    clear_session()

    return jsonify(
        {
            "message": "logout successful"
        }
    )


@auth_bp.get("/me")
def me():
    """Return the current authentication identity."""
    return jsonify(
        get_request_identity()
    )

