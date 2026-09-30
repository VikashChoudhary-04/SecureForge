"""Configuration models used by SecureForge."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class ScanProfile(str, Enum):
"""Supported SecureForge verification profiles."""


QUICK = "quick"
STANDARD = "standard"
FULL = "full"
CI = "ci"


class TargetType(str, Enum):
"""Types of application targets supported by SecureForge."""


WEB = "web"
API = "api"
WEB_AND_API = "web_and_api"


class ToolConfiguration(BaseModel):
"""Configuration for an external security tool."""


model_config = ConfigDict(extra="allow")

name: str

enabled: bool = True

executable: str | None = None

command: list[str] = Field(
    default_factory=list
)

timeout_seconds: int = Field(
    default=300,
    ge=1,
)

arguments: list[str] = Field(
    default_factory=list
)

environment: dict[str, str] = Field(
    default_factory=dict
)

metadata: dict[str, Any] = Field(
    default_factory=dict
)


class TargetConfiguration(BaseModel):
"""Security verification target configuration."""


model_config = ConfigDict(extra="allow")

name: str

target_type: TargetType

base_url: str | None = None

api_base_url: str | None = None

openapi_url: str | None = None

source_path: str | None = None

container_image: str | None = None

container_path: str | None = None

iac_path: str | None = None

network_target: str | None = None

evidence_path: str | None = None

docker_image: str | None = None

metadata: dict[str, Any] = Field(
    default_factory=dict
)


class ScanConfiguration(BaseModel):
"""Configuration for one SecureForge verification run."""


model_config = ConfigDict(extra="allow")

application: str

version: str

profile: ScanProfile = ScanProfile.QUICK

environment: str = "lab"

target: TargetConfiguration

tools: list[ToolConfiguration] = Field(
    default_factory=list
)

output_directory: str = "reports"

fail_on_tool_error: bool = False

metadata: dict[str, Any] = Field(
    default_factory=dict
)

@property
def enabled_tools(self) -> list[ToolConfiguration]:
    """Return only enabled tool configurations."""
    return [
        tool
        for tool in self.tools
        if tool.enabled
    ]

def has_web_target(self) -> bool:
    """Return whether the target includes a web application."""
    return self.target.target_type in {
        TargetType.WEB,
        TargetType.WEB_AND_API,
    }

def has_api_target(self) -> bool:
    """Return whether the target includes an API."""
    return self.target.target_type in {
        TargetType.API,
        TargetType.WEB_AND_API,
    }


__all__ = [
"ScanConfiguration",
"ScanProfile",
"TargetConfiguration",
"TargetType",
"ToolConfiguration",
]
