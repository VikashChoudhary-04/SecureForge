```python id="06blfc"
# SecureCommerce application factory

from __future__ import annotations

from flask import Flask

from .api import api_bp
from .auth import auth_bp
from .external import external_bp
from .routes import routes_bp
from .upload import upload_bp
from .vulnerable_routes import vulnerable_bp


def create_app(
    config_object=None,
) -> Flask:
    """Create and configure the SecureCommerce lab application."""
    app = Flask(__name__)

    if config_object is not None:
        app.config.from_object(config_object)

    app.register_blueprint(routes_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(vulnerable_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(external_bp)

    return app


__all__ = [
    "create_app",
]
```
