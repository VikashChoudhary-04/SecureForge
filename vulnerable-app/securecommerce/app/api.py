"""REST API routes for SecureCommerce."""

from **future** import annotations

from flask import Blueprint, jsonify, request

from .database import db
from .models import Order, OrderItem, Product, User

api_bp = Blueprint(
"api",
**name**,
url_prefix="/api",
)

@api_bp.get("/health")
def api_health():
"""Return API health information."""
return jsonify(
{
"status": "ok",
"service": "securecommerce-api",
}
)

@api_bp.get("/users")
def list_users():
"""Return application users."""
users = User.query.order_by(
User.id
).all()

```
return jsonify(
    {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
            }
            for user in users
        ]
    }
)
```

@api_bp.get("/users/[int:user_id](int:user_id)")
def get_user(user_id: int):
"""Return one user."""
user = db.session.get(
User,
user_id,
)

```
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

@api_bp.get("/products")
def api_products():
"""Return products through the REST API."""
products = Product.query.order_by(
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
            for product in products
        ]
    }
)
```

@api_bp.get("/products/[int:product_id](int:product_id)")
def get_product(product_id: int):
"""Return one product."""
product = db.session.get(
Product,
product_id,
)

```
if product is None:
    return (
        jsonify(
            {
                "error": "product not found"
            }
        ),
        404,
    )

return jsonify(
    {
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "stock": product.stock,
    }
)
```

@api_bp.post("/orders")
def create_order():
"""Create an order."""
data = request.get_json(silent=True) or {}

```
user_id = data.get("user_id")
shipping_address = data.get(
    "shipping_address"
)
items = data.get("items", [])

if not isinstance(user_id, int):
    return (
        jsonify(
            {
                "error": "user_id must be an integer"
            }
        ),
        400,
    )

if not isinstance(
    shipping_address,
    str,
) or not shipping_address.strip():
    return (
        jsonify(
            {
                "error": (
                    "shipping_address is required"
                )
            }
        ),
        400,
    )

if not isinstance(items, list) or not items:
    return (
        jsonify(
            {
                "error": "items must be a non-empty list"
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

order = Order(
    user_id=user.id,
    shipping_address=shipping_address,
    status="pending",
    total=0.0,
)

db.session.add(order)

total = 0.0

for item in items:
    product_id = item.get("product_id")
    quantity = item.get("quantity", 1)

    if not isinstance(product_id, int):
        return (
            jsonify(
                {
                    "error": (
                        "product_id must be an integer"
                    )
                }
            ),
            400,
        )

    if not isinstance(quantity, int) or quantity < 1:
        return (
            jsonify(
                {
                    "error": (
                        "quantity must be a "
                        "positive integer"
                    )
                }
            ),
            400,
        )

    product = db.session.get(
        Product,
        product_id,
    )

    if product is None:
        return (
            jsonify(
                {
                    "error": (
                        f"product {product_id} not found"
                    )
                }
            ),
            404,
        )

    order_item = OrderItem(
        order=order,
        product=product,
        quantity=quantity,
        unit_price=product.price,
    )

    db.session.add(order_item)

    total += product.price * quantity

order.total = total

db.session.commit()

return (
    jsonify(
        {
            "message": "order created",
            "order_id": order.id,
            "total": order.total,
        }
    ),
    201,
)
```

@api_bp.get("/orders")
def list_orders():
"""Return orders for a supplied user."""
user_id = request.args.get(
"user_id",
type=int,
)

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

orders = Order.query.filter_by(
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
            for order in orders
        ]
    }
)
```

@api_bp.get("/orders/[int:order_id](int:order_id)")
def get_order(order_id: int):
"""Return one order."""
order = db.session.get(
Order,
order_id,
)

```
if order is None:
    return (
        jsonify(
            {
                "error": "order not found"
            }
        ),
        404,
    )

return jsonify(
    {
        "id": order.id,
        "user_id": order.user_id,
        "status": order.status,
        "total": order.total,
        "shipping_address": order.shipping_address,
        "items": [
            {
                "id": item.id,
                "product_id": item.product_id,
                "quantity": item.quantity,
                "unit_price": item.unit_price,
            }
            for item in order.items
        ],
    }
)
```

@api_bp.get("/admin/users")
def admin_users():
"""Return administrative user information."""
users = User.query.order_by(
User.id
).all()

```
return jsonify(
    {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
            }
            for user in users
        ]
    }
)
```
