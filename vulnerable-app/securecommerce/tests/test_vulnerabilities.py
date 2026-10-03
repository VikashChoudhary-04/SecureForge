"""Tests for intentionally vulnerable SecureCommerce behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database


class TestConfig(Config):
    """Isolated configuration for vulnerability tests."""

    TESTING = True
    SECRET_KEY = "vulnerability-test-secret"
    DATABASE_PATH = Path(
        "/tmp/securecommerce-vulnerability-test.db"
    )
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    UPLOAD_FOLDER = Path(
        "/tmp/securecommerce-vulnerability-test-uploads"
    )
    LAB_MODE = True


@pytest.fixture()
def app():
    """Create an isolated vulnerability-test application."""
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


def test_vulnerable_sql_lookup_returns_user(client):
    """The vulnerable lookup should expose a user record."""
    response = client.get(
        "/vulnerable/search-user?user_id=2"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == 2
    assert data["username"] == "alice"


def test_vulnerable_profile_allows_cross_user_access(client):
    """The vulnerable profile endpoint should expose another user."""
    response = client.get(
        "/vulnerable/profile/3"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["profile"]["username"] == "bob"


def test_vulnerable_admin_action_allows_normal_user(client):
    """The vulnerable admin endpoint should omit role validation."""
    login_response = client.post(
        "/login",
        json={
            "username": "alice",
            "password": "AlicePass123!",
        },
    )

    assert login_response.status_code == 200

    response = client.post(
        "/vulnerable/admin-action",
        json={
            "action": "list_users",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["request_identity"]["username"] == "alice"
    assert data["request_identity"]["role"] == "user"
    assert data["result"]["status"] == "success"


def test_vulnerable_file_endpoint_exposes_resolved_path(client):
    """The vulnerable file endpoint should resolve an unsafe path."""
    response = client.get(
        "/vulnerable/download"
        "?filename=../instance/securecommerce.db"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["requested_filename"] == (
        "../instance/securecommerce.db"
    )
    assert "securecommerce.db" in data["resolved_path"]


def test_vulnerable_fetch_rejects_unsupported_scheme(client):
    """The SSRF endpoint should reject non-HTTP schemes."""
    response = client.get(
        "/vulnerable/fetch"
        "?url=file:///etc/passwd"
    )

    assert response.status_code == 502
    data = response.get_json()
    assert data["result"]["status"] == "error"
    assert data["result"]["message"] == (
        "unsupported URL scheme"
    )


def test_vulnerable_endpoints_are_lab_scoped(client):
    """All intentionally vulnerable endpoints use the lab prefix."""
    routes = [
        "/vulnerable/search-user?user_id=2",
        "/vulnerable/profile/2",
        "/vulnerable/download?filename=test.txt",
        "/vulnerable/fetch?url=http://localhost:5000/health",
    ]

    for route in routes:
        response = client.get(route)
        assert response.status_code in {200, 404, 502}

    response = client.post(
        "/vulnerable/admin-action",
        json={
            "action": "list_users",
        },
    )

    assert response.status_code == 200

