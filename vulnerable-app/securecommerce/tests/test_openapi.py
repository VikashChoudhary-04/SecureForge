# SecureCommerce OpenAPI tests

from __future__ import annotations

from app import create_app


def create_test_app():
    """Create the SecureCommerce test application."""
    app = create_app()

    app.config.update(
        TESTING=True,
    )

    return app


def test_openapi_document_is_available():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    assert response.status_code == 200
    assert response.is_json is True


def test_openapi_document_has_required_metadata():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    document = response.get_json()

    assert document is not None
    assert document["openapi"] == "3.0.3"
    assert document["info"]["title"] == (
        "SecureCommerce API"
    )
    assert document["info"]["version"] == "1.0.0"


def test_openapi_contains_core_security_endpoints():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    document = response.get_json()

    assert document is not None

    paths = document["paths"]

    assert "/api/users/{user_id}" in paths
    assert "/vulnerable/search" in paths
    assert "/vulnerable/admin-action" in paths


def test_openapi_contains_ssrf_endpoint():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    document = response.get_json()

    assert document is not None

    endpoint = document["paths"][
        "/external/fetch"
    ]

    assert "get" in endpoint

    parameters = endpoint["get"]["parameters"]

    parameter_names = {
        parameter["name"]
        for parameter in parameters
    }

    assert "url" in parameter_names


def test_openapi_contains_file_upload_endpoint():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    document = response.get_json()

    assert document is not None

    endpoint = document["paths"][
        "/upload/"
    ]

    assert "post" in endpoint

    request_body = endpoint["post"][
        "requestBody"
    ]

    assert request_body["required"] is True

    multipart = request_body["content"][
        "multipart/form-data"
    ]

    schema = multipart["schema"]

    assert schema["type"] == "object"
    assert "file" in schema["properties"]


def test_openapi_contains_download_endpoint():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/openapi.json"
        )

    document = response.get_json()

    assert document is not None

    endpoint = document["paths"][
        "/upload/download/{filename}"
    ]

    assert "get" in endpoint

    parameters = endpoint["get"]["parameters"]

    parameter_names = {
        parameter["name"]
        for parameter in parameters
    }

    assert "filename" in parameter_names
