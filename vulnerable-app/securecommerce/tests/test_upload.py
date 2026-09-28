```python
# SecureCommerce file-upload tests

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


def test_upload_page_is_available():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get("/upload/")

    assert response.status_code == 200
    assert b"SecureCommerce File Upload" in response.data


def test_file_upload_accepts_lab_file():
    app = create_test_app()

    with app.test_client() as client:
        response = client.post(
            "/upload/",
            data={
                "file": (
                    BytesIO(b"SecureForge lab file"),
                    "lab.txt",
                )
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 201

    body = response.get_json()

    assert body is not None
    assert body["status"] == "uploaded"
    assert body["filename"] == "lab.txt"


def test_upload_requires_file():
    app = create_test_app()

    with app.test_client() as client:
        response = client.post(
            "/upload/",
            data={},
            content_type="multipart/form-data",
        )

    assert response.status_code == 400
    assert b"No file was supplied." in response.data


def test_upload_requires_filename():
    app = create_test_app()

    with app.test_client() as client:
        response = client.post(
            "/upload/",
            data={
                "file": (
                    BytesIO(b"SecureForge lab file"),
                    "",
                )
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 400
    assert b"Filename is required." in response.data


def test_missing_downloaded_file_returns_404():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/upload/download/nonexistent.txt"
        )

    assert response.status_code == 404
    assert b"File not found." in response.data


def test_download_returns_uploaded_file():
    app = create_test_app()

    with app.test_client() as client:
        upload_response = client.post(
            "/upload/",
            data={
                "file": (
                    BytesIO(b"SecureForge download test"),
                    "download-test.txt",
                )
            },
            content_type="multipart/form-data",
        )

        assert upload_response.status_code == 201

        response = client.get(
            "/upload/download/download-test.txt"
        )

    assert response.status_code == 200
    assert response.data == (
        b"SecureForge download test"
    )
    assert response.headers["Content-Type"].startswith(
        "application/octet-stream"
    )


def test_download_rejects_directory_request():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/upload/download/."
        )

    assert response.status_code in {
        400,
        404,
    }
```
