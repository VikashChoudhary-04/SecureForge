"""Authentication and security helpers for SecureCommerce."""

from **future** import annotations

from functools import wraps
from typing import Any, Callable

from flask import g, jsonify, request, session

from .database import db
from .models import User

def authenticate_user(
username: str,
password: str,
) -> User | None:
"""Authenticate a user by username and password."""
from werkzeug.security import check_password_hash

```
user = User.query.filter_by(
    username=username
).first()

if user is None:
    return None

if not check_password_hash(
    user.password_hash,
    password,
):
    return None

return user
```

def establish_session(
user: User,
) -> None:
"""Store the authenticated user in the Flask session."""
session["user_id"] = user.id
session["username"] = user.username
session["role"] = user.role

def clear_session() -> None:
"""Clear the current authentication session."""
session.clear()

def current_user() -> User | None:
"""Return the currently authenticated user."""
user_id = session.get("user_id")

```
if user_id is None:
    return None

user = db.session.get(
    User,
    user_id,
)

if user is not None:
    g.current_user = user

return user
```

def login_required(
view: Callable[..., Any],
) -> Callable[..., Any]:
"""Require an authenticated user for a route."""

```
@wraps(view)
def wrapped(*args: Any, **kwargs: Any):
    user = current_user()

    if user is None:
        return (
            jsonify(
                {
                    "error": "authentication required"
                }
            ),
            401,
        )

    return view(*args, **kwargs)

return wrapped
```

def role_required(
role: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
"""Require an authenticated user with a specific role."""

```
def decorator(
    view: Callable[..., Any],
) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(
        *args: Any,
        **kwargs: Any,
    ):
        user = current_user()

        if user is None:
            return (
                jsonify(
                    {
                        "error": (
                            "authentication required"
                        )
                    }
                ),
                401,
            )

        if user.role != role:
            return (
                jsonify(
                    {
                        "error": "insufficient privileges"
                    }
                ),
                403,
            )

        return view(
            *args,
            **kwargs,
        )

    return wrapped

return decorator
```

def get_request_identity() -> dict[str, Any]:
"""Return authentication information useful for lab evidence."""
user = current_user()

```
return {
    "authenticated": user is not None,
    "user_id": user.id if user else None,
    "username": user.username if user else None,
    "role": user.role if user else None,
    "session_present": bool(session),
    "remote_address": request.remote_addr,
}
```
