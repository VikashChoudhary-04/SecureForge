"""Application-level tests for SecureCommerce."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database


class TestConfig(Config):
    """Isolated configuration for application tests."""

    TESTING = True

    SECRET_KEY = "test-secret"

    DATABASE_PATH = Path("/tmp/securecommerce-test.db")

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///:memory:"
    )

    UPLOAD_FOLDER = Path(
        "/tmp/securecommerce-test-uploads"
    )

    LAB_MODE = True


@pytest.fixture()
def app():
    """Create an isolated SecureCommerce application."""
    application = create_app(TestConfig)

    with application.app_context():
        db.drop_all()
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


def test_health_endpoint(client):
    """Health endpoint should report the application status."""
    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "ok"
    assert data["application"] == "SecureCommerce"


def test_api_health_endpoint(client):
    """API health endpoint should be available."""
    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "ok"
    assert data["service"] == "securecommerce-api"


def test_openapi_endpoint(client):
    """OpenAPI specification should be available."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.get_json()

    assert data["openapi"] == "3.0.3"
    assert data["info"]["title"] == "SecureCommerce API"
    assert "/api/orders/{order_id}" in data["paths"]


def test_seed_database(client, app):
    """Seed data should create deterministic laboratory records."""
    with app.app_context():
        seed_database()

        from app.models import Order, Product, User

        assert User.query.count() == 3
        assert Product.query.count() == 4
        assert Order.query.count() == 2


def test_register_user(client):
    """A new user should be registered successfully."""
    response = client.post(
        "/register",
        json={
            "username": "charlie",
            "email": "charlie@securecommerce.local",
            "password": "CharliePass123!",
        },
    )

    assert response.status_code == 201

    data = response.get_json()

    assert data["message"] == "user registered"
    assert data["username"] == "charlie"


def test_login_user(client, app):
    """A seeded user should be able to authenticate."""
    with app.app_context():
        seed_database()

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


def test_products_endpoint(client, app):
    """Product catalog should return seeded products."""
    with app.app_context():
        seed_database()

    response = client.get("/products")

    assert response.status_code == 200

    data = response.get_json()

    assert len(data["products"]) == 4


def test_orders_endpoint(client, app):
    """Order endpoint should return seeded orders."""
    with app.app_context():
        seed_database()

    response = client.get(
        "/orders?user_id=2"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert len(data["orders"]) == 1

