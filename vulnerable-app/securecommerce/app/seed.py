"""Seed deterministic laboratory data for SecureCommerce."""

from __future__ import annotations

from .database import db
from .models import Order, OrderItem, Product, User


def seed_database() -> None:
    """Populate the database with deterministic lab data."""
    _seed_users()
    _seed_products()
    _seed_orders()

    db.session.commit()


def _seed_users() -> None:
    """Create laboratory users."""
    if User.query.count() > 0:
        return

    admin = User(
        username="admin",
        email="admin@securecommerce.local",
        role="admin",
    )
    admin.set_password("AdminPass123!")

    alice = User(
        username="alice",
        email="alice@securecommerce.local",
        role="user",
    )
    alice.set_password("AlicePass123!")

    bob = User(
        username="bob",
        email="bob@securecommerce.local",
        role="user",
    )
    bob.set_password("BobPass123!")

    db.session.add_all(
        [
            admin,
            alice,
            bob,
        ]
    )


def _seed_products() -> None:
    """Create laboratory products."""
    if Product.query.count() > 0:
        return

    products = [
        Product(
            name="Secure Laptop",
            description="Laboratory laptop product.",
            price=899.99,
            stock=25,
        ),
        Product(
            name="Developer Keyboard",
            description="Mechanical keyboard for developers.",
            price=129.99,
            stock=50,
        ),
        Product(
            name="Security Monitor",
            description="27-inch security testing monitor.",
            price=349.99,
            stock=15,
        ),
        Product(
            name="USB Security Toolkit",
            description="Laboratory USB security toolkit.",
            price=79.99,
            stock=100,
        ),
    ]

    db.session.add_all(products)


def _seed_orders() -> None:
    """Create reproducible orders for multiple users."""
    if Order.query.count() > 0:
        return

    alice = User.query.filter_by(
        username="alice"
    ).first()

    bob = User.query.filter_by(
        username="bob"
    ).first()

    laptop = Product.query.filter_by(
        name="Secure Laptop"
    ).first()

    keyboard = Product.query.filter_by(
        name="Developer Keyboard"
    ).first()

    monitor = Product.query.filter_by(
        name="Security Monitor"
    ).first()

    if not all(
        [
            alice,
            bob,
            laptop,
            keyboard,
            monitor,
        ]
    ):
        raise RuntimeError(
            "Required seed records were not created."
        )

    alice_order = Order(
        user_id=alice.id,
        status="processing",
        shipping_address=(
            "Alice Lab Address, SecureCommerce City"
        ),
    )

    alice_laptop = OrderItem(
        order=alice_order,
        product=laptop,
        quantity=1,
        unit_price=laptop.price,
    )

    alice_keyboard = OrderItem(
        order=alice_order,
        product=keyboard,
        quantity=2,
        unit_price=keyboard.price,
    )

    alice_order.total = (
        alice_laptop.unit_price * alice_laptop.quantity
        + alice_keyboard.unit_price
        * alice_keyboard.quantity
    )

    bob_order = Order(
        user_id=bob.id,
        status="shipped",
        shipping_address=(
            "Bob Lab Address, SecureCommerce City"
        ),
    )

    bob_monitor = OrderItem(
        order=bob_order,
        product=monitor,
        quantity=1,
        unit_price=monitor.price,
    )

    bob_order.total = (
        bob_monitor.unit_price
        * bob_monitor.quantity
    )

    db.session.add_all(
        [
            alice_order,
            bob_order,
        ]
    )

