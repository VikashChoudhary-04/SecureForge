"""Deterministic mock security integration for SecureForge tests and CI."""

from __future__ import annotations

import copy
import json
from typing import Any

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization.models import NormalizationResult
from secureforge.core.scan.models import RawEvidence, ToolExecutionResult, ToolExecutionStatus

from .base import SecurityIntegration


class MockSecurityIntegration(SecurityIntegration):
    """Produce deterministic security evidence without external tools."""

    integration_name = "mock"
    display_name = "Mock Security Scanner"

    def __init__(
        self,
        *,
        name: str = "mock",
        version: str = "1.0",
        metadata: dict[str, Any] | None = None,
        findings: list[dict[str, object]] | None = None,
    ) -> None:
        self.name = name
        self.integration_name = name
        self.version = version
        self.metadata = dict(metadata or {})
        self._findings = [copy.deepcopy(item) for item in (findings or [])]

    @property
    def findings(self) -> list[dict[str, object]]:
        return [copy.deepcopy(item) for item in self._findings]

    def add_finding(self, finding: dict[str, object]) -> None:
        if not isinstance(finding, dict):
            raise TypeError("Mock finding must be a dictionary.")
        self._findings.append(copy.deepcopy(finding))

    def clear_findings(self) -> None:
        self._findings.clear()

    def build_command(self, configuration: ScanConfiguration) -> list[str]:
        target_name = getattr(getattr(configuration, "target", None), "name", None)
        return [
            "secureforge-mock",
            "--application",
            str(configuration.application),
            "--target",
            str(target_name or getattr(configuration, "target", None) or ""),
            "--format",
            "json",
        ]

    def execute(self, configuration: ScanConfiguration) -> ToolExecutionResult:
        command = self.build_command(configuration)
        payload = json.dumps({"findings": self.findings, "metadata": self.integration_metadata()})
        return ToolExecutionResult(
            tool_name=self.integration_name,
            integration=self.integration_name,
            status=ToolExecutionStatus.SUCCESS,
            command=command,
            exit_code=0,
            stdout=payload,
            stderr="",
            error=None,
            metadata=self.integration_metadata(),
        )

    def create_evidence_from_execution(
        self,
        result: ToolExecutionResult,
        configuration: ScanConfiguration,
    ) -> RawEvidence:
        target = getattr(getattr(configuration, "target", None), "base_url", None)
        raw_data = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "command": result.command,
        }
        return RawEvidence(
            source=self.integration_name,
            source_version=self.version,
            target=target,
            raw_data=raw_data,
            metadata={
                "integration": self.integration_name,
                **self.metadata,
            },
        )

    def integration_metadata(self) -> dict[str, Any]:
        return {
            "integration": self.integration_name,
            "display_name": self.display_name,
            "version": self.version,
            **self.metadata,
        }

    def normalize(self, evidence: RawEvidence) -> NormalizationResult:
        if evidence.source != self.integration_name:
            raise ValueError(
                f"Expected evidence source '{self.integration_name}', got '{evidence.source}'."
            )

        payload = evidence.raw_data
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        if isinstance(payload, dict) and "stdout" in payload:
            stdout = payload.get("stdout", "")
            try:
                payload = json.loads(stdout) if isinstance(stdout, str) else stdout
            except json.JSONDecodeError:
                payload = {}
        if not isinstance(payload, dict):
            payload = {}

        findings = payload.get("findings", self.findings)
        if not isinstance(findings, list):
            findings = []

        return NormalizationResult(
            source=self.integration_name,
            findings=copy.deepcopy(findings),
            evidence=[evidence],
            metadata={"source": self.integration_name, "deterministic": True},
        )

    def create_evidence(self, configuration: ScanConfiguration) -> RawEvidence:
        result = self.execute(configuration)
        return self.create_evidence_from_execution(result, configuration)

    def supports_target(self, configuration: ScanConfiguration) -> bool:
        del configuration
        return True

    def run(self, context: Any) -> Any:
        raise NotImplementedError("Use execute() with a ScanConfiguration for the mock integration.")


__all__ = ["MockSecurityIntegration"]
