"""Tests for the SecureForge validator registry."""

import pytest

from secureforge.validation.base import BaseValidator
from secureforge.validation.models import (
    ValidationMethod,
    ValidationRequest,
    ValidationResult,
)
from secureforge.validation.registry import (
    ValidatorRegistry,
    ValidatorRegistryError,
)


class HTTPTestValidator(BaseValidator):
    """Test HTTP validator."""

    name = "http-test"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.HTTP

    def validate(self, request: ValidationRequest) -> ValidationResult:
        raise NotImplementedError


class APITestValidator(BaseValidator):
    """Test API validator."""

    name = "api-test"

    def supports(self, request: ValidationRequest) -> bool:
        return request.method == ValidationMethod.API

    def validate(self, request: ValidationRequest) -> ValidationResult:
        raise NotImplementedError


class EmptyNameValidator(BaseValidator):
    """Test validator with an invalid name."""

    name = "   "

    def supports(self, request: ValidationRequest) -> bool:
        return True

    def validate(self, request: ValidationRequest) -> ValidationResult:
        raise NotImplementedError


def test_registry_starts_empty() -> None:
    registry = ValidatorRegistry()

    assert len(registry) == 0
    assert registry.names() == []
    assert registry.list() == []


def test_registry_registers_validator() -> None:
    registry = ValidatorRegistry()
    validator = HTTPTestValidator()

    registry.register(validator)

    assert len(registry) == 1
    assert registry.get("http-test") is validator
    assert registry.names() == ["http-test"]


def test_registry_accepts_initial_validators() -> None:
    http_validator = HTTPTestValidator()
    api_validator = APITestValidator()

    registry = ValidatorRegistry(
        validators=[
            http_validator,
            api_validator,
        ]
    )

    assert registry.names() == [
        "http-test",
        "api-test",
    ]


def test_registry_rejects_empty_validator_name() -> None:
    registry = ValidatorRegistry()

    with pytest.raises(
        ValidatorRegistryError,
        match="Validator name must not be empty",
    ):
        registry.register(EmptyNameValidator())


def test_registry_rejects_duplicate_validator() -> None:
    registry = ValidatorRegistry()
    registry.register(HTTPTestValidator())

    with pytest.raises(
        ValidatorRegistryError,
        match="Validator already registered",
    ):
        registry.register(HTTPTestValidator())


def test_registry_get_rejects_unknown_validator() -> None:
    registry = ValidatorRegistry()

    with pytest.raises(
        ValidatorRegistryError,
        match="Validator not registered",
    ):
        registry.get("missing")


def test_registry_unregisters_validator() -> None:
    registry = ValidatorRegistry()
    validator = HTTPTestValidator()
    registry.register(validator)

    removed = registry.unregister("http-test")

    assert removed is validator
    assert len(registry) == 0


def test_registry_unregister_rejects_unknown_validator() -> None:
    registry = ValidatorRegistry()

    with pytest.raises(
        ValidatorRegistryError,
        match="Validator not registered",
    ):
        registry.unregister("missing")


def test_registry_finds_validator_by_request() -> None:
    registry = ValidatorRegistry()
    http_validator = HTTPTestValidator()
    api_validator = APITestValidator()

    registry.register(http_validator)
    registry.register(api_validator)

    request = ValidationRequest(
        finding_id="TEST-001",
        target="http://localhost:5000",
        method=ValidationMethod.API,
    )

    assert registry.find(request) is api_validator


def test_registry_rejects_request_without_supported_validator() -> None:
    registry = ValidatorRegistry()
    registry.register(HTTPTestValidator())

    request = ValidationRequest(
        finding_id="TEST-001",
        target="http://localhost:5000",
        method=ValidationMethod.COMMAND,
    )

    with pytest.raises(
        ValidatorRegistryError,
        match="No validator supports",
    ):
        registry.find(request)
