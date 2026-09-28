```python
# SecureCommerce OpenAPI definition

from __future__ import annotations

from flask import Blueprint, jsonify

openapi_bp = Blueprint(
    "openapi",
    __name__,
)


OPENAPI_DOCUMENT = {
    "openapi": "3.0.3",
    "info": {
        "title": "SecureCommerce API",
        "version": "1.0.0",
        "description": (
            "Intentionally vulnerable API specification "
            "for the SecureForge security verification lab."
        ),
    },
    "servers": [
        {
            "url": "http://localhost:5000",
        }
    ],
    "paths": {
        "/api/users/{user_id}": {
            "get": {
                "summary": "Retrieve a user",
                "description": (
                    "Intentionally vulnerable object-level "
                    "authorization endpoint."
                ),
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "integer",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "User returned.",
                    },
                    "401": {
                        "description": "Authentication required.",
                    },
                    "403": {
                        "description": "Access denied.",
                    },
                },
            }
        },
        "/vulnerable/search": {
            "get": {
                "summary": "Search users",
                "description": (
                    "Intentionally vulnerable search endpoint "
                    "used for SQL injection and reflected XSS "
                    "validation."
                ),
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Search response.",
                    },
                    "500": {
                        "description": (
                            "Database error caused by the "
                            "intentionally vulnerable implementation."
                        ),
                    },
                },
            }
        },
        "/vulnerable/admin-action": {
            "get": {
                "summary": "Administrative action",
                "description": (
                    "Intentionally vulnerable function-level "
                    "authorization endpoint."
                ),
                "responses": {
                    "200": {
                        "description": "Administrative action executed.",
                    },
                    "401": {
                        "description": "Authentication required.",
                    },
                    "403": {
                        "description": "Access denied.",
                    },
                },
            }
        },
        "/external/fetch": {
            "get": {
                "summary": "Fetch external resource",
                "description": (
                    "Intentionally SSRF-prone endpoint. The URL "
                    "is controlled by the request parameter."
                ),
                "parameters": [
                    {
                        "name": "url",
                        "in": "query",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "format": "uri",
                        },
                        "description": (
                            "Remote URL to fetch. This parameter "
                            "is intentionally unsafe in the lab."
                        ),
                    }
                ],
                "responses": {
                    "200": {
                        "description": (
                            "Remote resource fetched."
                        )
                    },
                    "400": {
                        "description": "URL missing.",
                    },
                    "502": {
                        "description": (
                            "Remote request failed."
                        ),
                    },
                },
            }
        },
        "/upload/": {
            "post": {
                "summary": "Upload a file",
                "description": (
                    "Intentionally insecure file-upload endpoint "
                    "used for SecureForge validation."
                ),
                "requestBody": {
                    "required": True,
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "required": [
                                    "file"
                                ],
                                "properties": {
                                    "file": {
                                        "type": "string",
                                        "format": "binary",
                                    }
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "File uploaded.",
                    },
                    "400": {
                        "description": "Invalid upload request.",
                    },
                },
            }
        },
        "/upload/download/{filename}": {
            "get": {
                "summary": "Download uploaded file",
                "description": (
                    "Intentionally insufficiently protected "
                    "file path used for controlled path-traversal "
                    "testing."
                ),
                "parameters": [
                    {
                        "name": "filename",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "File returned.",
                    },
                    "400": {
                        "description": "Invalid file request.",
                    },
                    "404": {
                        "description": "File not found.",
                    },
                },
            }
        },
    },
}


@openapi_bp.route(
    "/openapi.json",
    methods=["GET"],
)
def openapi_document():
    """Return the SecureCommerce OpenAPI document."""
    return jsonify(
        OPENAPI_DOCUMENT
    )


__all__ = [
    "OPENAPI_DOCUMENT",
    "openapi_bp",
]
```
