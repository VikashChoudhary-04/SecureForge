"""Browser-facing routes for SecureCommerce."""

from **future** import annotations

from flask import Blueprint, jsonify, request

from .database import db
from .models import Order, Product, User

web_bp = Blueprint(
"web",
**name**,
)

@web_bp.get("/")
def index():
"""Return the SecureCommerce application overview."""
return jsonify(
{
"application": "SecureCommerce",
"description": (
"Deliberately vulnerable e-commerce "
"application for security testing."
),
"endpoints": {
"register": "/register",
"login": "/login",
"products": "/products",
"profile": "/profile",
"orders": "/orders",
},
}
)

@web_bp.post("/register")
def register():
"""Register a new SecureCommerce user."""
data = request.get_json(silent=True) or {}

```
username = data.get("username")
email = data.get("email")
password = data.get("password")

if not all(
    isinstance(value, str) and value.strip()
    for value in (username, email, password)
):
    return (
        jsonify(
            {
                "error": (
                    "username, email, and password "
                    "are required"
                )
            }
        ),
        400,
    )

if User.query.filter_by(username=username).first():
    return (
        jsonify(
            {
                "error": "username already exists"
            }
        ),
        409,
    )

if User.query.filter_by(email=email).first():
    return (
        jsonify(
            {
                "error": "email already exists"
            }
        ),
        409,
    )

user = User(
    username=username,
    email=email,
    role="user",
)

user.set_password(password)

db.session.add(user)
db.session.commit()

return (
    jsonify(
        {
            "message": "user registered",
            "user_id": user.id,
            "username": user.username,
        }
    ),
    201,
)
```

@web_bp.post("/login")
def login():
"""Authenticate a SecureCommerce user."""
data = request.get_json(silent=True) or {}

```
username = data.get("username")
password = data.get("password")

if not username or not password:
    return (
        jsonify(
            {
                "error": (
                    "username and password are required"
                )
            }
        ),
        400,
    )

user = User.query.filter_by(
    username=username
).first()

if user is None:
    return (
        jsonify(
            {
                "error": "invalid credentials"
            }
        ),
        401,
    )

from werkzeug.security import check_password_hash

if not check_password_hash(
    user.password_hash,
    password,
):
    return (
        jsonify(
            {
                "error": "invalid credentials"
            }
        ),
        401,
    )

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
```

@web_bp.get("/products")
def products():
"""Return the product catalog."""
product_list = Product.query.order_by(
Product.id
).all()

```
return jsonify(
    {
        "products": [
            {
                "id": product.id,
                "name": product.name,
                "description": product.description,
                "price": product.price,
                "stock": product.stock,
            }
            for product in product_list
        ]
    }
)
```

@web_bp.get("/profile")
def profile():
"""Return a user profile."""
user_id = request.args.get("user_id", type=int)

```
if user_id is None:
    return (
        jsonify(
            {
                "error": "user_id is required"
            }
        ),
        400,
    )

user = db.session.get(
    User,
    user_id,
)

if user is None:
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
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": (
            user.created_at.isoformat()
            if user.created_at
            else None
        ),
    }
)
```

@web_bp.get("/orders")
def orders():
"""Return orders belonging to a user."""
user_id = request.args.get("user_id", type=int)

```
if user_id is None:
    return (
        jsonify(
            {
                "error": "user_id is required"
            }
        ),
        400,
    )

order_list = Order.query.filter_by(
    user_id=user_id
).order_by(
    Order.id.desc()
).all()

return jsonify(
    {
        "orders": [
            {
                "id": order.id,
                "user_id": order.user_id,
                "status": order.status,
                "total": order.total,
                "shipping_address": (
                    order.shipping_address
                ),
            }
            for order in order_list
        ]
    }
)
```
