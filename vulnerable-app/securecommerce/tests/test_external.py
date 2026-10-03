# SecureCommerce external integration tests

from __future__ import annotations

from unittest.mock import patch

from app import create_app


def create_test_app():
    """Create the SecureCommerce test application."""
    app = create_app()
    app.config.update(
        TESTING=True,
    )
    return app


def test_external_endpoint_requires_url():
    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/external/fetch"
        )

    assert response.status_code == 400

    body = response.get_json()

    assert body is not None
    assert body["error"] == (
        "The url parameter is required."
    )


@patch(
    "app.external.urlopen"
)
def test_external_endpoint_fetches_controlled_resource(
    mock_urlopen,
):
    class FakeResponse:
        status = 200

        def read(
            self,
            size=-1,
        ):
            return b"SecureCommerce test response"

        def __enter__(self):
            return self

        def __exit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            return False

    mock_urlopen.return_value = FakeResponse()

    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/external/fetch",
            query_string={
                "url": "http://127.0.0.1:5001/health"
            },
        )

    assert response.status_code == 200

    body = response.get_json()

    assert body is not None
    assert body["status"] == "fetched"
    assert body["status_code"] == 200
    assert body["content"] == (
        "SecureCommerce test response"
    )

    mock_urlopen.assert_called_once()


@patch(
    "app.external.urlopen"
)
def test_external_endpoint_returns_remote_error(
    mock_urlopen,
):
    from urllib.error import HTTPError

    class FakeResponse:
        def read(
            self,
            size=-1,
        ):
            return b"not found"

    mock_urlopen.side_effect = HTTPError(
        url="http://127.0.0.1:5001/missing",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=FakeResponse(),
    )

    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/external/fetch",
            query_string={
                "url": "http://127.0.0.1:5001/missing"
            },
        )

    assert response.status_code == 200

    body = response.get_json()

    assert body is not None
    assert body["status"] == "remote_error"
    assert body["status_code"] == 404
    assert body["content"] == "not found"


@patch(
    "app.external.urlopen"
)
def test_external_endpoint_handles_request_failure(
    mock_urlopen,
):
    from urllib.error import URLError

    mock_urlopen.side_effect = URLError(
        "connection refused"
    )

    app = create_test_app()

    with app.test_client() as client:
        response = client.get(
            "/external/fetch",
            query_string={
                "url": "http://127.0.0.1:5001/health"
            },
        )

    assert response.status_code == 502

    body = response.get_json()

    assert body is not None
    assert body["status"] == "request_failed"
    assert "URLError" in body["error"]
