"""Risk models used by SecureForge."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secureforge.core.findings.models import Severity


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetImportance(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"
    LAB = "lab"
    UNKNOWN = "unknown"


class RiskContext(BaseModel):
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
    level: str | RiskLevel | None = None
    blocked: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def legacy(cls, value):
        if not isinstance(value, dict):
            return value

        data = dict(value)

        if "risk_score" not in data and "score" in data:
            data["risk_score"] = data["score"]

        source = data.get(
            "highest_severity",
            data.get("level"),
        )
        if "base_severity" not in data and source is not None:
            data["base_severity"] = cls.level_of(source)
        if "contextual_risk" not in data and source is not None:
            data["contextual_risk"] = cls.level_of(source)

        return data

    @staticmethod
    def level_of(value):
        raw = getattr(value, "value", value)
        try:
            return RiskLevel(str(raw).lower())
        except ValueError:
            return RiskLevel.INFO

    def model_post_init(self, __context):
        if self.score is None:
            self.score = self.risk_score
        if self.highest_severity is None:
            self.highest_severity = self.contextual_risk
        if self.finding_count is None:
            self.finding_count = 1 if self.finding_id else 0
        if self.level is None:
            self.level = self.contextual_risk
        if self.blocked is None:
            self.blocked = self.risk_score >= 90.0

    @property
    def overall_score(self):
        return self.score if self.score is not None else self.risk_score

    @property
    def overall_severity(self):
        value = self.highest_severity or self.contextual_risk
        return getattr(value, "value", str(value))
