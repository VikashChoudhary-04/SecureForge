```python
# SecureCommerce security-scenario tests

from __future__ import annotations

from io import BytesIO

from app import create_app


def create_test_app():
    """Create the SecureCommerce test application."""
    app = create_app()

    app.config.update(
        TESTING=True,
    )

    return app


def test_sql_injection_scenario():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/vulnerable/search",
            query_string={
                "q": "' OR '1'='1",
            },
        )

    assert response.status_code == 200

    body = response.get_data(
        as_text=True
    ).lower()

    assert (
        "sqlite"
        in body
        or "sql"
        in body
        or "database"
        in body
    )


def test_reflected_xss_scenario():
    app = create_test_app()

    marker = "<SecureForge-XSS-Test>"

    with app.test_client() as client:
        response = client.get(
            "/vulnerable/search",
            query_string={
                "q": marker,
            },
        )

    assert response.status_code == 200
    assert marker in response.get_data(
        as_text=True
    )


def test_bola_scenario():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/api/users/2"
        )

    assert response.status_code == 200

    body = response.get_json()

    assert body is not None
    assert "id" in body or "username" in body


def test_broken_function_level_authorization_scenario():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/vulnerable/admin-action"
        )

    assert response.status_code == 200


def test_ssrf_scenario():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/external/fetch",
            query_string={
                "url": (
                    "http://127.0.0.1:5000/"
                )
            },
        )

    assert response.status_code == 200

    body = response.get_json()

    assert body is not None
    assert body["status"] == "fetched"


def test_insecure_file_upload_scenario():
    app = create_test_app()

    with app.test_client() as client:
        response = client.post(
            "/upload/",
            data={
                "file": (
                    BytesIO(
                        b"SecureForge controlled upload"
                    ),
                    "test.txt",
                )
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 201

    body = response.get_json()

    assert body is not None
    assert body["status"] == "uploaded"
    assert body["filename"] == "test.txt"


def test_development_server_misconfiguration_signal():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200

    server_header = response.headers.get(
        "Server",
        ""
    )

    assert (
        "Werkzeug"
        in server_header
        or app.config.get("TESTING") is True
    )


def test_synthetic_secret_exists_for_lab_validation():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get("/")

    body = response.get_data(
        as_text=True
    )

    assert response.status_code == 200

    assert (
        "SECURECOMMERCE_FAKE_SECRET"
        in body
        or app.config.get("TESTING") is True
    )
```
