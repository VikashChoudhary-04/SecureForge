"""SecureForge command-line interface."""

from __future__ import annotations

__all__ = ["app"]


def __getattr__(name: str):
    """Lazily expose the Typer application.

    Keeping this import lazy prevents ``python -m secureforge.cli.main``
    from importing ``secureforge.cli.main`` before runpy executes it.
    """
    if name == "app":
        from .main import app

        return app

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )
