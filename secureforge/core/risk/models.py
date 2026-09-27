"""Risk models used by the SecureForge risk engine."""

from **future** import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class RiskLevel(str, Enum):
"""Normalized contextual risk level."""

```
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"
```

class AssetImportance(str, Enum):
"""Business or security importance of an affected asset."""

```
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
```

class Environment(str, Enum):
"""Environment in which the finding was observed."""

```
DEVELOPMENT = "development"
TEST = "test"
STAGING = "staging"
PRODUCTION = "production"
LAB = "lab"
UNKNOWN = "unknown"
```

class RiskContext(BaseModel):
"""Contextual information used during risk evaluation."""

```
model_config = ConfigDict(extra="allow")

asset_importance: AssetImportance = AssetImportance.MEDIUM

internet_exposed: bool = False
authentication_required: bool = True
sensitive_data: bool = False
exploit_evidence: bool = False

environment: Environment = Environment.UNKNOWN

security_requirement: str | None = None

metadata: dict[str, Any] = Field(default_factory=dict)
```

class RiskAssessment(BaseModel):
"""Result of contextual risk evaluation."""

```
model_config = ConfigDict(extra="allow")

finding_id: str

base_severity: RiskLevel
contextual_risk: RiskLevel

context: RiskContext

risk_score: float = Field(ge=0.0, le=100.0)

factors: list[str] = Field(default_factory=list)

explanation: str

evaluated_at: str

metadata: dict[str, Any] = Field(default_factory=dict)
```
