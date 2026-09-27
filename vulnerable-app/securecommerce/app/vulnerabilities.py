"""Deliberately vulnerable behaviors for the SecureCommerce lab.

* These functions are intentionally insecure.
* They exist only for controlled local security testing.
* Do not reuse these patterns in production applications.
  """

from **future** import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from .config import Config
from .database import db
from .models import User

def vulnerable_user_lookup(
user_id: str,
) -> dict[str, Any] | None:
"""Perform an intentionally unsafe SQL query.

```
- The query concatenates user-controlled input directly into SQL.
- This function exists to provide a reproducible SQL injection
  target for the SecureForge lab.
"""
database_path = Path(
    Config.DATABASE_PATH
)

connection = sqlite3.connect(
    database_path
)
connection.row_factory = sqlite3.Row

try:
    query = (
        "SELECT id, username, email, role "
        "FROM users "
        f"WHERE id = {user_id}"
    )

    row = connection.execute(
        query
    ).fetchone()

    if row is None:
        return None

    return dict(row)
finally:
    connection.close()
```

def vulnerable_profile_lookup(
user_id: int,
) -> dict[str, Any] | None:
"""Return another user's profile without authorization.

```
- The caller-controlled object identifier is trusted.
- No ownership check is performed.
- This intentionally models a BOLA/IDOR condition.
"""
user = db.session.get(
    User,
    user_id,
)

if user is None:
    return None

return {
    "id": user.id,
    "username": user.username,
    "email": user.email,
    "role": user.role,
}
```

def vulnerable_admin_action(
action: str,
) -> dict[str, str]:
"""Perform an administrative action without role validation.

```
- Authentication is intentionally not checked here.
- Authorization must be enforced by the caller in secure code.
- This function exists to model a broken function-level
  authorization scenario.
"""
allowed_actions = {
    "list_users": "Administrative user listing requested.",
    "export_users": "Administrative user export requested.",
    "reset_password": "Administrative password reset requested.",
}

message = allowed_actions.get(
    action
)

if message is None:
    return {
        "status": "error",
        "message": "unknown administrative action",
    }

return {
    "status": "success",
    "message": message,
}
```

def vulnerable_file_path(
filename: str,
) -> Path:
"""Build an upload path without safe path validation.

```
- The supplied filename is joined directly with the upload
  directory.
- This intentionally provides a path traversal testing target.
"""
return Path(
    Config.UPLOAD_FOLDER
) / filename
```

def vulnerable_fetch_url(
url: str,
) -> dict[str, Any]:
"""Fetch a caller-supplied URL without SSRF restrictions.

```
- No destination allowlist is enforced.
- No private-network restriction is applied.
- The request is intentionally simple so the behavior is
  reproducible in an isolated laboratory environment.
"""
parsed = urlparse(url)

if parsed.scheme not in {
    "http",
    "https",
}:
    return {
        "status": "error",
        "message": "unsupported URL scheme",
    }

try:
    response = requests.get(
        url,
        timeout=5,
    )

    return {
        "status": "success",
        "url": url,
        "status_code": response.status_code,
        "content_type": response.headers.get(
            "Content-Type"
        ),
        "body_preview": response.text[:500],
    }
except requests.RequestException as exc:
    return {
        "status": "error",
        "url": url,
        "message": str(exc),
    }
```
