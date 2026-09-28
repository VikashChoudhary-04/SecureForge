```python
# SecureCommerce vulnerable file-upload functionality

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, request

upload_bp = Blueprint(
    "upload",
    __name__,
    url_prefix="/upload",
)

UPLOAD_DIRECTORY = Path("uploads")


@upload_bp.route(
    "/",
    methods=["GET", "POST"],
)
def upload_file():
    """Demonstrate intentionally insecure file handling.

    This endpoint exists only inside the SecureCommerce lab.
    It intentionally omits production controls such as strict
    extension validation, content validation, malware scanning,
    size enforcement, and safe filename handling.
    """
    if request.method == "GET":
        return """
        <!doctype html>
        <html>
        <head>
            <title>SecureCommerce File Upload</title>
        </head>
        <body>
            <h1>SecureCommerce File Upload</h1>

            <form
                method="post"
                enctype="multipart/form-data"
            >
                <label for="file">
                    Select a file:
                </label>

                <input
                    id="file"
                    name="file"
                    type="file"
                >

                <button type="submit">
                    Upload
                </button>
            </form>
        </body>
        </html>
        """

    uploaded_file = request.files.get(
        "file"
    )

    if uploaded_file is None:
        return (
            "No file was supplied.",
            400,
        )

    if not uploaded_file.filename:
        return (
            "Filename is required.",
            400,
        )

    UPLOAD_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = (
        UPLOAD_DIRECTORY
        / uploaded_file.filename
    )

    uploaded_file.save(
        destination
    )

    return {
        "status": "uploaded",
        "filename": uploaded_file.filename,
        "path": str(destination),
    }, 201


@upload_bp.route(
    "/download/<path:filename>",
    methods=["GET"],
)
def download_file(
    filename: str,
):
    """Download a file from the controlled lab upload directory.

    The endpoint intentionally performs insufficient path
    validation so path traversal can be demonstrated during
    authorized SecureCommerce testing.
    """
    requested_path = (
        UPLOAD_DIRECTORY
        / filename
    )

    if not requested_path.exists():
        return (
            "File not found.",
            404,
        )

    if not requested_path.is_file():
        return (
            "Requested path is not a file.",
            400,
        )

    try:
        content = requested_path.read_bytes()
    except OSError as exc:
        return (
            f"Unable to read file: {exc}",
            500,
        )

    return (
        content,
        200,
        {
            "Content-Type": (
                "application/octet-stream"
            ),
            "Content-Disposition": (
                'attachment; '
                f'filename="{Path(filename).name}"'
            ),
        },
    )


__all__ = [
    "UPLOAD_DIRECTORY",
    "upload_bp",
]
```
