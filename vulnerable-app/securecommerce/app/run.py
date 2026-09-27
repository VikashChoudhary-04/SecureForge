"""Local entry point for SecureCommerce."""

from **future** import annotations

import os

from app import create_app
from app.seed import seed_database

app = create_app()

def initialize_lab() -> None:
"""Initialize deterministic laboratory data."""
with app.app_context():
seed_database()

if **name** == "**main**":
initialize_lab()

```
app.run(
    host=os.getenv(
        "SECURECOMMERCE_HOST",
        "127.0.0.1",
    ),
    port=int(
        os.getenv(
            "SECURECOMMERCE_PORT",
            "5000",
        )
    ),
    debug=os.getenv(
        "SECURECOMMERCE_DEBUG",
        "false",
    ).lower() == "true",
)
```
