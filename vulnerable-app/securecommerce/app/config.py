"""SecureCommerce application configuration."""

from __future__ import annotations

import os
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent
INSTANCE_ROOT = APP_ROOT / "instance"
UPLOAD_ROOT = APP_ROOT / "uploads"


class Config:
    """Base configuration for SecureCommerce."""

    SECRET_KEY = os.getenv(
        "SECURECOMMERCE_SECRET_KEY",
        "securecommerce-development-secret",
    )
    DATABASE_PATH = Path(
        os.getenv(
            "SECURECOMMERCE_DATABASE",
            str(INSTANCE_ROOT / "securecommerce.db"),
        )
    )
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = Path(
        os.getenv(
            "SECURECOMMERCE_UPLOAD_FOLDER",
            str(UPLOAD_ROOT),
        )
    )
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    JSON_SORT_KEYS = False
    LAB_MODE = os.getenv(
        "SECURECOMMERCE_LAB_MODE", "true"
    ).lower() == "true"
    EXTERNAL_SERVICE_URL = os.getenv(
        "SECURECOMMERCE_EXTERNAL_SERVICE_URL",
        "http://localhost:5001",
    )
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"

