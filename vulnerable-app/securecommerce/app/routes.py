"""Web routes for SecureCommerce."""

from **future** import annotations

from flask import Flask, jsonify

def register_routes(app: Flask) -> None:
"""Register all SecureCommerce web and API routes."""
from .web import web_bp
from .api import api_bp

```
app.register_blueprint(web_bp)
app.register_blueprint(api_bp)

@app.get("/health")
def health() -> tuple[dict[str, str], int]:
    """Return application health status."""
    return (
        jsonify(
            {
                "status": "ok",
                "application": "SecureCommerce",
                "environment": "lab",
            }
        ).json,
        200,
    )
```
