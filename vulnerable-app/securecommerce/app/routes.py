"""Web routes for SecureCommerce."""

from **future** import annotations

from flask import Flask, jsonify

from .api import api_bp
from .openapi import openapi_bp
from .web import web_bp

def register_routes(app: Flask) -> None:
"""Register all SecureCommerce web and API routes."""
app.register_blueprint(web_bp)
app.register_blueprint(api_bp)
app.register_blueprint(openapi_bp)

```
@app.get("/health")
def health():
    """Return application health status."""
    return jsonify(
        {
            "status": "ok",
            "application": "SecureCommerce",
            "environment": "lab",
        }
    )
```
