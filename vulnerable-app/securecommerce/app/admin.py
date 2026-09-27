"""Administrative routes for SecureCommerce."""

from **future** import annotations

from flask import Blueprint, jsonify, request

from .database import db
from .models import Product, User
from .security import role_required

admin_bp = Blueprint(
"admin",
**name**,
url_prefix="/admin",
)

@admin_bp.get("/users")
@role_required("admin")
def users():
"""Return all users to an administrator."""
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

@admin_bp.post("/products")
@role_required("admin")
def create_product():
"""Create a product as an administrator."""
data = request.get_json(silent=True) or {}

```
name = data.get("name")
description = data.get("description")
price = data.get("price")
stock = data.get("stock")

if not isinstance(name, str) or not name.strip():
    return (
        jsonify(
            {
                "error": "name is required"
            }
        ),
        400,
    )

if not isinstance(
    description,
    str,
) or not description.strip():
    return (
        jsonify(
            {
                "error": "description is required"
            }
        ),
        400,
    )

if not isinstance(
    price,
    (int, float),
) or price < 0:
    return (
        jsonify(
            {
                "error": "price must be non-negative"
            }
        ),
        400,
    )

if not isinstance(stock, int) or stock < 0:
    return (
        jsonify(
            {
                "error": "stock must be non-negative"
            }
        ),
        400,
    )

product = Product(
    name=name.strip(),
    description=description.strip(),
    price=float(price),
    stock=stock,
)

db.session.add(product)
db.session.commit()

return (
    jsonify(
        {
            "message": "product created",
            "product": {
                "id": product.id,
                "name": product.name,
                "price": product.price,
                "stock": product.stock,
            },
        }
    ),
    201,
)
```

@admin_bp.delete("/products/[int:product_id](int:product_id)")
@role_required("admin")
def delete_product(product_id: int):
"""Delete a product as an administrator."""
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

db.session.delete(product)
db.session.commit()

return jsonify(
    {
        "message": "product deleted",
        "product_id": product_id,
    }
)
```
