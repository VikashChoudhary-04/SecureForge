"""Tests for SecureCommerce vulnerable route surfaces."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database


class TestConfig(Config):
    """Isolated configuration for vulnerable-route tests."""

    TESTING = True
    SECRET_KEY = "vulnerable-route-test-secret"
    DATABASE_PATH = Path(
        "/tmp/securecommerce-vulnerable-route-test.db"
    )
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    UPLOAD_FOLDER = Path(
        "/tmp/securecommerce-vulnerable-route-test-uploads"
    )
    LAB_MODE = True


@pytest.fixture()
def app():
    """Create an isolated vulnerable-route test application."""
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


def test_reflected_xss_endpoint_reflects_input(client):
    """The laboratory XSS endpoint should reflect supplied input."""
    payload = "<script>alert(1)</script>"

    response = client.get(
        "/vulnerable/search",
        query_string={
            "query": payload,
        },
    )

    assert response.status_code == 200
    assert payload in response.get_data(as_text=True)


def test_sql_injection_endpoint_exists(client):
    """The SQL injection laboratory endpoint should be reachable."""
    response = client.get(
        "/vulnerable/search-user",
        query_string={
            "user_id": "2",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["username"] == "alice"


def test_bola_endpoint_exists(client):
    """The BOLA laboratory endpoint should be reachable."""
    response = client.get(
        "/vulnerable/profile/3"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["profile"]["username"] == "bob"


def test_broken_function_authorization_endpoint_exists(client):
    """The broken authorization endpoint should be reachable."""
    response = client.post(
        "/vulnerable/admin-action",
        json={
            "action": "list_users",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["result"]["status"] == "success"


def test_path_traversal_endpoint_exists(client):
    """The path traversal laboratory endpoint should be reachable."""
    response = client.get(
        "/vulnerable/download",
        query_string={
            "filename": "../instance/securecommerce.db",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert "../instance/securecommerce.db" == (
        data["requested_filename"]
    )


def test_ssrf_endpoint_rejects_non_http_scheme(client):
    """The SSRF endpoint should reject unsupported schemes."""
    response = client.get(
        "/vulnerable/fetch",
        query_string={
            "url": "file:///etc/passwd",
        },
    )

    assert response.status_code == 502
    data = response.get_json()
    assert data["result"]["status"] == "error"
    assert data["result"]["message"] == (
        "unsupported URL scheme"
    )

