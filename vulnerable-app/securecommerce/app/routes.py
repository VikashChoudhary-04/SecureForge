"""Application routes for SecureCommerce."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from .database import db
from .models import Order, Product, User

routes_bp = Blueprint(
    "routes",
    __name__,
)


@routes_bp.get("/health")
def health():
    """Return the SecureCommerce application health status."""
    return jsonify(
        {
            "status": "ok",
            "application": "SecureCommerce",
        }
    )


@routes_bp.get("/profile")
def profile():
    """Return a user profile."""
    user_id = request.args.get("user_id", type=int)

    if user_id is None:
        return (
            jsonify({"error": "user_id is required"}),
            400,
        )

    user = db.session.get(User, user_id)

    if user is None:
        return (
            jsonify({"error": "user not found"}),
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


@routes_bp.get("/orders")
def orders():
    """Return orders belonging to a user."""
    user_id = request.args.get("user_id", type=int)

    if user_id is None:
        return (
            jsonify({"error": "user_id is required"}),
            400,
        )

    order_list = (
        Order.query.filter_by(user_id=user_id)
        .order_by(Order.id.desc())
        .all()
    )

    return jsonify(
        {
            "orders": [
                {
                    "id": order.id,
                    "user_id": order.user_id,
                    "status": order.status,
                    "total": order.total,
                    "shipping_address": order.shipping_address,
                }
                for order in order_list
            ]
        }
    )

