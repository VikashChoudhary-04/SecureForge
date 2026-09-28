"""Registry for SecureForge security requirements."""

from __future__ import annotations

from collections.abc import Iterable

from .models import RequirementStatus, SecurityRequirement


class RequirementRegistry:
    """Store and retrieve security requirements by requirement ID."""

    def __init__(
        self,
        requirements: Iterable[SecurityRequirement] | None = None,
    ) -> None:
        self._requirements: dict[str, SecurityRequirement] = {}

        if requirements:
            self.register_many(requirements)

    def register(
        self,
        requirement: SecurityRequirement,
        *,
        replace: bool = False,
    ) -> None:
        """Register a security requirement."""
        requirement_id = self._normalize_id(
            requirement.requirement_id
        )

        if not requirement_id:
            raise ValueError(
                "Security requirement ID cannot be empty."
            )

        if (
            requirement_id in self._requirements
            and not replace
        ):
            raise ValueError(
                f"Security requirement '{requirement_id}' "
                "is already registered."
            )

        self._requirements[requirement_id] = requirement

    def register_many(
        self,
        requirements: Iterable[SecurityRequirement],
        *,
        replace: bool = False,
    ) -> int:
        """Register multiple security requirements."""
        requirements_list = list(requirements)

        for requirement in requirements_list:
            self.register(
                requirement,
                replace=replace,
            )

        return len(requirements_list)

    def get(
        self,
        requirement_id: str,
    ) -> SecurityRequirement | None:
        """Return a requirement by ID."""
        normalized_id = self._normalize_id(
            requirement_id
        )

        return self._requirements.get(normalized_id)

    def require(
        self,
        requirement_id: str,
    ) -> SecurityRequirement:
        """Return a requirement or raise a clear lookup error."""
        requirement = self.get(requirement_id)

        if requirement is None:
            normalized_id = self._normalize_id(
                requirement_id
            )

            raise KeyError(
                f"Security requirement '{normalized_id}' "
                "was not found."
            )

        return requirement

    def contains(
        self,
        requirement_id: str,
    ) -> bool:
        """Return whether a requirement is registered."""
        return self.get(requirement_id) is not None

    def remove(
        self,
        requirement_id: str,
    ) -> SecurityRequirement:
        """Remove and return a requirement."""
        normalized_id = self._normalize_id(
            requirement_id
        )

        try:
            return self._requirements.pop(
                normalized_id
            )
        except KeyError as exc:
            raise KeyError(
                f"Security requirement '{normalized_id}' "
                "was not found."
            ) from exc

    def all(self) -> list[SecurityRequirement]:
        """Return all registered requirements."""
        return list(self._requirements.values())

    def active(self) -> list[SecurityRequirement]:
        """Return only active requirements."""
        return [
            requirement
            for requirement in self._requirements.values()
            if requirement.status == RequirementStatus.ACTIVE
        ]

    def mandatory(self) -> list[SecurityRequirement]:
        """Return active mandatory requirements."""
        return [
            requirement
            for requirement in self._requirements.values()
            if requirement.is_mandatory()
        ]

    def clear(self) -> None:
        """Remove all registered requirements."""
        self._requirements.clear()

    def __len__(self) -> int:
        """Return the number of registered requirements."""
        return len(self._requirements)

    def __contains__(
        self,
        requirement_id: str,
    ) -> bool:
        """Support membership checks using requirement IDs."""
        return self.contains(requirement_id)

    @staticmethod
    def _normalize_id(
        requirement_id: str,
    ) -> str:
        """Normalize a requirement identifier."""
        return requirement_id.strip().upper()


__all__ = [
    "RequirementRegistry",
]
