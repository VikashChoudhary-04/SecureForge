"""SecureCommerce Flask application factory."""

from **future** import annotations

from pathlib import Path

from flask import Flask

from .config import Config
from .database import db

def create_app(
config_class: type[Config] = Config,
) -> Flask:
"""Create and configure a SecureCommerce application."""
app = Flask(**name**)

```
app.config.from_object(config_class)

_ensure_directories(app)

db.init_app(app)

with app.app_context():
    db.create_all()

_register_routes(app)

return app
```

def _ensure_directories(app: Flask) -> None:
"""Create application directories required at runtime."""
database_path = Path(
app.config["DATABASE_PATH"]
)

```
database_path.parent.mkdir(
    parents=True,
    exist_ok=True,
)

upload_directory = Path(
    app.config["UPLOAD_FOLDER"]
)

upload_directory.mkdir(
    parents=True,
    exist_ok=True,
)
```

def _register_routes(app: Flask) -> None:
"""Register application route modules."""
from .routes import register_routes

```
register_routes(app)
```
