# SecureCommerce application factory

from __future__ import annotations

from pathlib import Path

from flask import Flask

from .admin import admin_bp
from .api import api_bp
from .auth import auth_bp
from .config import Config
from .database import db
from .external import external_bp
from .openapi import openapi_bp
from .routes import routes_bp
from .seed import seed_database
from .upload import upload_bp
from .vulnerable_routes import vulnerable_bp
from .web import web_bp


def create_app(
    config_object=None,
) -> Flask:
    """Create and configure the SecureCommerce lab application."""
    app = Flask(__name__)

    if config_object is None:
        config_object = Config

    app.config.from_object(config_object)

    database_uri = app.config.get(
        "SQLALCHEMY_DATABASE_URI"
    )

    if isinstance(database_uri, str):
        prefix = "sqlite:///"
        if database_uri.startswith(prefix):
            database_path = Path(
                database_uri[len(prefix):]
            )
            database_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

    upload_folder = app.config.get(
        "UPLOAD_FOLDER"
    )

    if upload_folder:
        Path(upload_folder).mkdir(
            parents=True,
            exist_ok=True,
        )

    db.init_app(app)

    app.register_blueprint(routes_bp)
    app.register_blueprint(web_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(vulnerable_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(external_bp)
    app.register_blueprint(openapi_bp)

    with app.app_context():
        db.create_all()
        seed_database()

    return app


__all__ = [
    "create_app",
]
