"""Authentication tests for SecureCommerce."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database


class TestConfig(Config):
    """Isolated configuration for authentication tests."""

    TESTING = True

    SECRET_KEY = "auth-test-secret"

    DATABASE_PATH = Path(
        "/tmp/securecommerce-auth-test.db"
    )

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///:memory:"
    )

    UPLOAD_FOLDER = Path(
        "/tmp/securecommerce-auth-test-uploads"
    )

    LAB_MODE = True


@pytest.fixture()
def app():
    """Create an isolated authentication test application."""
    application = create_app(TestConfig)

    with application.app_context():
        db.drop_all()
        db.create_all()
        seed_database()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


def test_login_success(client):
    """Valid credentials should create an authenticated session."""
    response = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "AlicePass123!",
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["message"] == "login successful"
    assert data["user"]["username"] == "alice"
    assert data["user"]["role"] == "user"


def test_login_invalid_password(client):
    """Invalid credentials should be rejected."""
    response = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401

    data = response.get_json()

    assert data["error"] == "invalid credentials"


def test_login_unknown_user(client):
    """Unknown users should be rejected."""
    response = client.post(
        "/login",
        json={
            "username": "does-not-exist",
            "password": "Password123!",
        },
    )

    assert response.status_code == 401

    data = response.get_json()

    assert data["error"] == "invalid credentials"


def test_login_requires_username(client):
    """Login should require a username."""
    response = client.post(
        "/login",
        json={
            "password": "Password123!",
        },
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["error"] == "username is required"


def test_login_requires_password(client):
    """Login should require a password."""
    response = client.post(
        "/login",
        json={
            "username": "alice",
        },
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["error"] == "password is required"


def test_me_requires_authentication(client):
    """Identity endpoint should report an unauthenticated request."""
    response = client.get("/me")

    assert response.status_code == 200

    data = response.get_json()

    assert data["authenticated"] is False
    assert data["user_id"] is None
    assert data["username"] is None
    assert data["role"] is None


def test_me_returns_authenticated_identity(client):
    """Identity endpoint should expose the current session identity."""
    login_response = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "AlicePass123!",
        },
    )

    assert login_response.status_code == 200

    response = client.get("/me")

    assert response.status_code == 200

    data = response.get_json()

    assert data["authenticated"] is True
    assert data["user_id"] == 2
    assert data["username"] == "alice"
    assert data["role"] == "user"
    assert data["session_present"] is True


def test_logout_clears_session(client):
    """Logout should terminate the current session."""
    login_response = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "AlicePass123!",
        },
    )

    assert login_response.status_code == 200

    logout_response = client.post(
        "/logout"
    )

    assert logout_response.status_code == 200

    data = logout_response.get_json()

    assert data["message"] == "logout successful"

    identity_response = client.get("/me")

    assert identity_response.status_code == 200

    identity = identity_response.get_json()

    assert identity["authenticated"] is False
    assert identity["user_id"] is None


def test_admin_login_preserves_role(client):
    """Admin authentication should preserve the admin role."""
    response = client.post(
        "/login",
        json={
            "username": "admin",
            "password": "AdminPass123!",
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"

