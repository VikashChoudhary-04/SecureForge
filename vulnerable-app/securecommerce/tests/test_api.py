"""REST API tests for SecureCommerce."""

from **future** import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import Config
from app.database import db
from app.seed import seed_database

class TestConfig(Config):
"""Isolated configuration for API tests."""

```
TESTING = True

SECRET_KEY = "api-test-secret"

DATABASE_PATH = Path(
    "/tmp/securecommerce-api-test.db"
)

SQLALCHEMY_DATABASE_URI = (
    "sqlite:///:memory:"
)

UPLOAD_FOLDER = Path(
    "/tmp/securecommerce-api-test-uploads"
)

LAB_MODE = True
```

@pytest.fixture()
def app():
"""Create an isolated API test application."""
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
"""Return a Flask API test client."""
return app.test_client()

def test_list_users(client):
"""Users endpoint should return seeded users."""
response = client.get("/api/users")

```
assert response.status_code == 200

data = response.get_json()

assert len(data["users"]) == 3
assert data["users"][0]["username"] == "admin"
```

def test_get_user(client):
"""User endpoint should return the requested user."""
response = client.get("/api/users/2")

```
assert response.status_code == 200

data = response.get_json()

assert data["username"] == "alice"
assert data["role"] == "user"
```

def test_missing_user_returns_404(client):
"""Unknown users should return a 404 response."""
response = client.get("/api/users/9999")

```
assert response.status_code == 404

data = response.get_json()

assert data["error"] == "user not found"
```

def test_list_products(client):
"""Products endpoint should return seeded products."""
response = client.get("/api/products")

```
assert response.status_code == 200

data = response.get_json()

assert len(data["products"]) == 4
```

def test_get_product(client):
"""Product endpoint should return a product."""
response = client.get("/api/products/1")

```
assert response.status_code == 200

data = response.get_json()

assert data["name"] == "Secure Laptop"
assert data["price"] == 899.99
```

def test_list_orders(client):
"""Orders endpoint should return orders for a user."""
response = client.get(
"/api/orders?user_id=2"
)

```
assert response.status_code == 200

data = response.get_json()

assert len(data["orders"]) == 1
assert data["orders"][0]["user_id"] == 2
```

def test_get_order(client):
"""Order endpoint should return order details."""
response = client.get("/api/orders/1")

```
assert response.status_code == 200

data = response.get_json()

assert data["id"] == 1
assert data["user_id"] == 2
assert len(data["items"]) == 2
```

def test_create_order(client):
"""A valid order should be created."""
response = client.post(
"/api/orders",
json={
"user_id": 2,
"shipping_address": (
"New SecureCommerce Lab Address"
),
"items": [
{
"product_id": 2,
"quantity": 1,
},
{
"product_id": 4,
"quantity": 2,
},
],
},
)

```
assert response.status_code == 201

data = response.get_json()

assert data["message"] == "order created"
assert data["order_id"] > 0
assert data["total"] == 289.97
```

def test_create_order_rejects_missing_items(client):
"""Orders without items should be rejected."""
response = client.post(
"/api/orders",
json={
"user_id": 2,
"shipping_address": "Test Address",
},
)

```
assert response.status_code == 400

data = response.get_json()

assert "items" in data["error"]
```

def test_create_order_rejects_unknown_product(client):
"""Orders containing an unknown product should fail."""
response = client.post(
"/api/orders",
json={
"user_id": 2,
"shipping_address": "Test Address",
"items": [
{
"product_id": 9999,
"quantity": 1,
}
],
},
)

```
assert response.status_code == 404

data = response.get_json()

assert "not found" in data["error"]
```

def test_admin_users_endpoint(client):
"""Administrative user endpoint should be reachable."""
response = client.get(
"/api/admin/users"
)

```
assert response.status_code == 200

data = response.get_json()

assert len(data["users"]) == 3
```
