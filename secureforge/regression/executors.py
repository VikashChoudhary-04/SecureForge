"""Practical executors for SecureForge regression tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .models import RegressionTest

class RegressionExecutorError(Exception):
"""Raised when a regression executor cannot run safely."""

class SecureCommerceRegressionExecutor:
"""Execute SecureCommerce laboratory regression tests."""

```
def __init__(
    self,
    *,
    base_url: str = "http://127.0.0.1:5000",
    timeout: float = 5.0,
    source_root: str | Path | None = None,
    infrastructure_root: str | Path | None = None,
) -> None:
    self.base_url = base_url.rstrip("/")
    self.timeout = timeout

    self.source_root = (
        Path(source_root)
        if source_root is not None
        else None
    )

    self.infrastructure_root = (
        Path(infrastructure_root)
        if infrastructure_root is not None
        else None
    )

def execute(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Execute a regression test based on its test ID."""
    executors = {
        "BOLA-001": self._execute_bola,
        "SQLI-001": self._execute_sqli,
        "XSS-001": self._execute_xss,
        "SECRET-001": self._execute_secret_scan,
        "AUTHZ-001": self._execute_authz,
        "MISCONFIG-001": self._execute_iac,
    }

    executor = executors.get(
        test.test_id
    )

    if executor is None:
        raise RegressionExecutorError(
            f"No SecureCommerce regression executor "
            f"is registered for '{test.test_id}'."
        )

    return executor(test)

def _execute_bola(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Verify that cross-user order access is denied."""
    response = requests.get(
        urljoin(
            self.base_url,
            test.target,
        ),
        timeout=self.timeout,
    )

    passed = response.status_code == 403

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            f"HTTP {response.status_code}"
        ),
        "message": (
            "Cross-user order access was denied."
            if passed
            else "Cross-user order access was not denied."
        ),
        "evidence": {
            "status_code": response.status_code,
            "expected_status_code": 403,
        },
    }

def _execute_sqli(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Check that SQL injection input is not executed."""
    target = urljoin(
        self.base_url,
        "/vulnerable/search-user",
    )

    payload = (
        "2' OR '1'='1"
    )

    response = requests.get(
        target,
        params={
            "user_id": payload,
        },
        timeout=self.timeout,
    )

    body = response.text.lower()

    database_error_patterns = (
        "sql syntax",
        "sqlite error",
        "operationalerror",
        "near \"or\"",
        "unterminated",
    )

    database_error = any(
        pattern in body
        for pattern in database_error_patterns
    )

    passed = (
        response.status_code >= 400
        and not database_error
    )

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            f"HTTP {response.status_code}"
        ),
        "message": (
            "SQL injection input was safely rejected."
            if passed
            else "SQL injection behavior remains observable."
        ),
        "evidence": {
            "status_code": response.status_code,
            "database_error_detected": database_error,
            "response_length": len(
                response.text
            ),
        },
    }

def _execute_xss(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Check that reflected XSS input is encoded."""
    payload = (
        "<script>"
        "secureforge_xss_test"
        "</script>"
    )

    target = urljoin(
        self.base_url,
        "/vulnerable/search",
    )

    response = requests.get(
        target,
        params={
            "query": payload,
        },
        timeout=self.timeout,
    )

    executable_payload_present = (
        payload in response.text
    )

    encoded_payload_present = (
        "&lt;script&gt;"
        in response.text
    )

    passed = (
        response.status_code == 200
        and not executable_payload_present
        and encoded_payload_present
    )

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            "encoded"
            if encoded_payload_present
            and not executable_payload_present
            else "executable"
            if executable_payload_present
            else (
                f"HTTP {response.status_code}"
            )
        ),
        "message": (
            "XSS input was safely encoded."
            if passed
            else "Reflected XSS behavior remains observable."
        ),
        "evidence": {
            "status_code": response.status_code,
            "executable_payload_present": (
                executable_payload_present
            ),
            "encoded_payload_present": (
                encoded_payload_present
            ),
        },
    }

def _execute_secret_scan(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Check application source for hardcoded active secrets."""
    if self.source_root is None:
        raise RegressionExecutorError(
            "source_root is required for SECRET-001."
        )

    if not self.source_root.is_dir():
        raise RegressionExecutorError(
            f"Source directory does not exist: "
            f"{self.source_root}"
        )

    secret_patterns = (
        re.compile(
            r"(?i)(api[_-]?key|secret|token)"
            r"\s*=\s*['\"][^'\"]{12,}['\"]"
        ),
        re.compile(
            r"(?i)sk-[a-z0-9_-]{16,}"
        ),
    )

    matches: list[dict[str, Any]] = []

    for path in self.source_root.rglob("*.py"):
        if not path.is_file():
            continue

        try:
            lines = path.read_text(
                encoding="utf-8"
            ).splitlines()
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            if any(
                pattern.search(line)
                for pattern in secret_patterns
            ):
                matches.append(
                    {
                        "file": str(path),
                        "line": line_number,
                        "value": "[REDACTED]",
                    }
                )

    passed = not matches

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            "No active hardcoded secret detected."
            if passed
            else f"{len(matches)} potential secret(s) detected."
        ),
        "message": (
            "Source secret regression passed."
            if passed
            else "Hardcoded secret regression failed."
        ),
        "evidence": {
            "matches": matches,
            "values_redacted": True,
        },
    }

def _execute_authz(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Verify that non-admin users cannot invoke admin actions."""
    target = urljoin(
        self.base_url,
        test.target,
    )

    response = requests.post(
        target,
        json={
            "action": "list_users",
        },
        headers={
            "X-User-Id": "2",
        },
        timeout=self.timeout,
    )

    passed = response.status_code == 403

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            f"HTTP {response.status_code}"
        ),
        "message": (
            "Non-admin administrative access was denied."
            if passed
            else "Non-admin administrative access remains possible."
        ),
        "evidence": {
            "status_code": response.status_code,
            "expected_status_code": 403,
        },
    }

def _execute_iac(
    self,
    test: RegressionTest,
) -> dict[str, Any]:
    """Check remediated infrastructure configuration."""
    if self.infrastructure_root is None:
        raise RegressionExecutorError(
            "infrastructure_root is required "
            "for MISCONFIG-001."
        )

    secure_file = (
        self.infrastructure_root
        / "secure.tf"
    )

    if not secure_file.is_file():
        raise RegressionExecutorError(
            f"Secure infrastructure file does not exist: "
            f"{secure_file}"
        )

    content = secure_file.read_text(
        encoding="utf-8"
    )

    checks = {
        "localhost_binding": (
            "host        = \"127.0.0.1\""
            in content
        ),
        "encryption_enabled": (
            'encryption = "enabled"'
            in content
        ),
        "private_storage": (
            'access     = "private"'
            in content
        ),
        "least_privilege": (
            "read-write-required-resources-only"
            in content
        ),
        "wildcard_permissions_absent": (
            'permissions = "*"'
            not in content
        ),
    }

    passed = all(
        checks.values()
    )

    return {
        "status": (
            "passed"
            if passed
            else "failed"
        ),
        "actual_result": (
            "Secure infrastructure checks passed."
            if passed
            else "One or more infrastructure checks failed."
        ),
        "message": (
            "Infrastructure security regression passed."
            if passed
            else "Infrastructure misconfiguration remains."
        ),
        "evidence": {
            "checks": checks,
            "secure_file": str(
                secure_file
            ),
        },
    }
```

def build_securecommerce_executor(
*,
base_url: str = "http://127.0.0.1:5000",
timeout: float = 5.0,
source_root: str | Path | None = None,
infrastructure_root: str | Path | None = None,
) -> SecureCommerceRegressionExecutor:
"""Build the default SecureCommerce regression executor."""
return SecureCommerceRegressionExecutor(
base_url=base_url,
timeout=timeout,
source_root=source_root,
infrastructure_root=infrastructure_root,
)
