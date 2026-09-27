"""Administrative route tests for SecureCommerce."""

from **future** import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database

class TestConfig(Config):
"""Isolated configuration for administrative tests."""

```
TESTING = True

SECRET_KEY = "admin-test-secret"

DATABASE_PATH = Path(
    "/tmp/securecommerce-admin-test.db"
)

SQLALCHEMY_DATABASE_URI = (
    "sqlite:///:memory:"
)

UPLOAD_FOLDER = Path(
    "/tmp/securecommerce-admin-test-uploads"
)

LAB_MODE = True
```

@pytest.fixture()
def app():
"""Create an isolated administrative test application."""
application = create_app(TestConfig)

```
with application.app_context():
    db.drop_all()
    db.create_all()
    seed_database()

yield application

with application.app_context():
    db.session.remove()
    db.drop_all()

db.engine.dispose()
```

@pytest.fixture()
def client(app):
"""Return a Flask test client."""
return app.test_client()

def login(
client,
username: str,
password: str,
):
"""Authenticate a test user."""
return client.post(
"/login",
json={
"username": username,
"password": password,
},
)

def test_admin_users_requires_authentication(client):
"""Administrative users endpoint should require authentication."""
response = client.get(
"/admin/users"
)

```
assert response.status_code == 401

data = response.get_json()

assert data["error"] == "authentication required"
```

def test_admin_users_rejects_normal_user(client):
"""Normal users should not access administrative data."""
response = login(
client,
"alice",
"AlicePass123!",
)

```
assert response.status_code == 200

response = client.get(
    "/admin/users"
)

assert response.status_code == 403

data = response.get_json()

assert data["error"] == "insufficient privileges"
```

def test_admin_users_allows_admin(client):
"""Administrators should access administrative user data."""
response = login(
client,
"admin",
"AdminPass123!",
)

```
assert response.status_code == 200

response = client.get(
    "/admin/users"
)

assert response.status_code == 200

data = response.get_json()

assert len(data["users"]) == 3
```

def test_create_product_requires_admin(client):
"""Product creation should require administrator privileges."""
response = login(
client,
"alice",
"AlicePass123!",
)

```
assert response.status_code == 200

response = client.post(
    "/admin/products",
    json={
        "name": "Unauthorized Product",
        "description": "Should not be created.",
        "price": 10.0,
        "stock": 5,
    },
)

assert response.status_code == 403
```

def test_admin_can_create_product(client):
"""Administrator should be able to create a product."""
response = login(
client,
"admin",
"AdminPass123!",
)

```
assert response.status_code == 200

response = client.post(
    "/admin/products",
    json={
        "name": "Security Lab Mouse",
        "description": (
            "Product created for the security lab."
        ),
        "price": 49.99,
        "stock": 20,
    },
)

assert response.status_code == 201

data = response.get_json()

assert data["message"] == "product created"
assert data["product"]["name"] == "Security Lab Mouse"
assert data["product"]["price"] == 49.99
```

def test_admin_can_delete_product(client):
"""Administrator should be able to delete a product."""
response = login(
client,
"admin",
"AdminPass123!",
)

```
assert response.status_code == 200

response = client.delete(
    "/admin/products/1"
)

assert response.status_code == 200

data = response.get_json()

assert data["message"] == "product deleted"
assert data["product_id"] == 1
```
