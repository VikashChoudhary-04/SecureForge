"""End-to-end scan execution pipeline for SecureForge."""

from __future__ import annotations

from secureforge.core.config import ScanConfiguration
from secureforge.core.normalization import NormalizationPipeline

from .executor import ToolExecutor
from .factory import ScanRunFactory
from .models import ScanRun, ToolExecutionStatus
from .normalizer import ScanResultNormalizer
from .planner import ScanPlanner

class ScanRunner:
"""Execute configured tools and normalize their security evidence."""

    def __init__(
        self,
        *,
        planner: ScanPlanner | None = None,
        executor: ToolExecutor | None = None,
        factory: ScanRunFactory | None = None,
        normalizer: ScanResultNormalizer | None = None,
    ) -> None:
        self.planner = planner or ScanPlanner()
        self.executor = executor or ToolExecutor()
        self.factory = factory or ScanRunFactory()
        self.normalizer = normalizer
    
    def run(
        self,
        configuration: ScanConfiguration,
        *,
        commit_sha: str | None = None,
    ) -> ScanRun:
        """Execute a complete tool-and-normalization scan."""
        scan = self.factory.create(
            configuration,
            commit_sha=commit_sha,
        )
    
        scan.start()
    
        try:
            planned_tools = self.planner.plan(
                configuration
            )
    
            self._record_plan_warnings(
                scan,
                configuration,
            )
    
            if not planned_tools:
                scan.add_warning(
                    "No enabled security tools were available "
                    "for the selected scan profile."
                )
    
            for planned_tool in planned_tools:
                result = self.executor.execute(
                    planned_tool.configuration
                )
    
                result.metadata.setdefault(
                    "integration",
                    planned_tool.integration,
                )
    
                scan.add_tool_result(
                    result
                )
    
                if result.status in {
                    ToolExecutionStatus.FAILED,
                    ToolExecutionStatus.TIMEOUT,
                }:
                    scan.add_error(
                        result.error
                        or (
                            f"Integration "
                            f"'{planned_tool.integration}' failed."
                        )
                    )
    
            if self.normalizer is not None:
                self._normalize_results(
                    scan,
                    configuration,
                )
    
            scan.complete()
    
        except Exception as exc:
            scan.fail(
                f"Scan execution failed unexpectedly: {exc}"
            )
    
        return scan
    
    def _normalize_results(
        self,
        scan: ScanRun,
        configuration: ScanConfiguration,
    ) -> None:
        """Normalize successful tool results into findings."""
        results = [
            result
            for result in scan.tool_results
            if result.succeeded
        ]
    
        if not results:
            return
    
        normalization_results, findings = (
            self.normalizer.findings_from_results(
                results,
                target=self._target_reference(
                    configuration
                ),
                application=configuration.application,
            )
        )
    
        scan.add_findings(
            findings
        )
    
        for result in normalization_results:
            if not result.success:
                scan.add_warning(
                    f"Normalization failed for "
                    f"integration '{result.source}'."
                )
    
            for warning in result.warnings:
                scan.add_warning(
                    warning
                )
    
            for error in result.errors:
                scan.add_error(
                    error
                )
    
    def _record_plan_warnings(
        self,
        scan: ScanRun,
        configuration: ScanConfiguration,
    ) -> None:
        """Record missing and disabled integration warnings."""
        for integration in self.planner.missing_integrations(
            configuration
        ):
            scan.add_warning(
                f"Integration '{integration}' is required "
                f"by profile '{configuration.profile.value}' "
                "but no tool is configured."
            )
    
        for integration in self.planner.disabled_integrations(
            configuration
        ):
            scan.add_warning(
                f"Integration '{integration}' is disabled "
                "and will be skipped."
            )
    
    @staticmethod
    def _target_reference(
        configuration: ScanConfiguration,
    ) -> str | None:
        """Return the most useful target reference."""
        target = configuration.target
    
        return (
            target.base_url
            or target.api_base_url
            or target.openapi_url
            or target.source_path
            or target.name
        )
