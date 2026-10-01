"""Risk models used by the SecureForge risk engine."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secureforge.core.findings.models import Severity


class RiskLevel(str, Enum):
    """Normalized contextual risk level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetImportance(str, Enum):
    """Business or security importance of an affected asset."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Environment(str, Enum):
    """Environment in which the finding was observed."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"
    LAB = "lab"
    UNKNOWN = "unknown"


class RiskContext(BaseModel):
    """Contextual information used during risk evaluation."""

    model_config = ConfigDict(extra="allow")

    asset_importance: AssetImportance = AssetImportance.MEDIUM
    internet_exposed: bool = False
    authentication_required: bool = True
    sensitive_data: bool = False
    exploit_evidence: bool = False
    environment: Environment = Environment.UNKNOWN
    security_requirement: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Result of contextual risk evaluation."""

    model_config = ConfigDict(extra="allow")

    finding_id: str | None = None
    base_severity: RiskLevel = RiskLevel.INFO
    contextual_risk: RiskLevel = RiskLevel.INFO
    context: RiskContext = Field(default_factory=RiskContext)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    factors: list[Any] | dict[str, Any] = Field(default_factory=list)
    explanation: str = ""
    evaluated_at: str = ""

    score: float | None = None
    highest_severity: Severity | RiskLevel | str | None = None
    finding_count: int | None = None
    confirmed_critical: int = 0
    confirmed_high: int = 0

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, value: Any) -> Any:
        """Normalize legacy aggregate risk-assessment construction."""
        if not isinstance(value, dict):
            return value

        normalized = dict(value)

        if "risk_score" not in normalized and "score" in normalized:
            normalized["risk_score"] = normalized["score"]

        highest = normalized.get("highest_severity")
        if "base_severity" not in normalized and highest is not None:
            normalized["base_severity"] = cls._normalize_risk_level(highest)

        if "contextual_risk" not in normalized and highest is not None:
            normalized["contextual_risk"] = cls._normalize_risk_level(highest)

        return normalized

    @staticmethod
    def _normalize_risk_level(value: Any) -> RiskLevel:
        raw = getattr(value, "value", value)
        try:
            return RiskLevel(str(raw).lower())
        except ValueError:
            return RiskLevel.INFO

    @property
    def overall_score(self) -> float:
        """Return the effective numeric score."""
        return self.score if self.score is not None else self.risk_score

    @property
    def overall_severity(self) -> str:
        """Return the effective highest severity."""
        value = self.highest_severity or self.contextual_risk
        return getattr(value, "value", str(value))

    def model_post_init(self, __context: Any) -> None:
        """Populate legacy aggregate aliases from modern fields."""
        if self.score is None:
            self.score = self.risk_score
        if self.highest_severity is None:
            self.highest_severity = self.contextual_risk
        if self.finding_count is None and self.finding_id is not None:
            self.finding_count = 1
