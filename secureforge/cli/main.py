"""Command-line interface for SecureForge."""

from __future__ import annotations

from pathlib import Path

import typer

from secureforge import __version__
from secureforge.cli.report import (
    ReportCommandConfiguration,
    build_report_command_service,
)
from secureforge.cli.scan import (
    ScanCommandConfiguration,
    build_scan_command_service,
)
from secureforge.config.runtime import RuntimeConfigurationError
from secureforge.core.config.models import ScanProfile
from secureforge.regression.cli import app as regression_app


app = typer.Typer(
    name="secureforge",
    help=(
        "Continuous security verification and release gate "
        "for web/API applications."
    ),
)


def _version_callback(value: bool | None) -> None:
    if value:
        typer.echo(f"SecureForge {__version__}")
        raise typer.Exit()


@app.callback()
def _main_callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        is_eager=True,
        callback=_version_callback,
    ),
) -> None:
    pass


@app.command()
def scan(
    profile: str = typer.Option("standard"),
    target: str | None = typer.Option(None),
    source_path: Path | None = typer.Option(
        None,
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    scan_id: str = typer.Option("local-scan"),
    application: str = typer.Option("SecureCommerce"),
    version_label: str = typer.Option("dev"),
    commit_sha: str | None = typer.Option(None),
    environment: str = typer.Option("lab"),
    output: Path = typer.Option(Path("reports")),
    scan_storage: Path = typer.Option(
        Path(".secureforge/scans"),
    ),
    regression: bool = typer.Option(
        False,
        "--regression",
        help="Run the configured regression security suite.",
    ),
    regression_suite: Path = typer.Option(
        Path("requirements/regression-tests.yaml"),
        "--regression-suite",
        help="Path to the regression test suite configuration.",
    ),
    regression_base_url: str | None = typer.Option(
        None,
        "--regression-base-url",
        help=(
            "Base URL for regression tests. "
            "Defaults to --target."
        ),
    ),
    regression_timeout: float = typer.Option(
        5.0,
        "--regression-timeout",
        help="Timeout in seconds for each regression test request.",
    ),
    regression_source_root: Path | None = typer.Option(
        None,
        "--regression-source-root",
        help=(
            "Source root used by source-based regression checks. "
            "Defaults to --source-path."
        ),
    ),
    regression_infrastructure_root: Path | None = typer.Option(
        None,
        "--regression-infrastructure-root",
        help="Infrastructure root used by regression checks.",
    ),
) -> None:
    try:
        scan_profile = ScanProfile(profile)
    except ValueError as exc:
        typer.echo("unsupported profile")
        raise typer.Exit(code=2) from exc

    _validate_scan_options(
        profile=profile,
        environment=environment,
        target=target,
        source_path=source_path,
        validate=False,
        validation_finding=[],
        validation_endpoint=[],
        validation_payload=[],
        regression=regression,
    )

    config = ScanCommandConfiguration(
        scan_id=scan_id,
        profile=scan_profile,
        target=target,
        source_path=source_path,
        application=application,
        version=version_label,
        commit_sha=commit_sha,
        environment=environment,
        output_directory=output,
        scan_storage_directory=scan_storage,
        run_regression=regression,
        regression_suite_path=regression_suite,
        regression_base_url=regression_base_url,
        regression_timeout=regression_timeout,
        regression_source_root=regression_source_root,
        regression_infrastructure_root=(
            regression_infrastructure_root
        ),
    )

    try:
        result = build_scan_command_service().run(config)
    except RuntimeConfigurationError as exc:
        # A targetless invocation is also used by the CLI as a lightweight
        # profile-selection command. Only the scan-service validation error
        # for a missing target is treated as that mode; other configuration
        # errors must remain real failures.
        if (
            target is None
            and source_path is None
            and str(exc).strip().lower()
            == "scan target must not be empty."
        ):
            typer.echo(
                f"Selected profile: {scan_profile.value}"
            )
            typer.echo(
                f"Profile: {scan_profile.value}"
            )
            return

        typer.echo(
            f"Configuration error: {exc}"
        )
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        typer.echo(
            f"Scan failed: {exc}"
        )
        raise typer.Exit(code=2) from exc

    _print_scan_result(result)


@app.command()
def report(
    format: str = typer.Option(
        "html",
        "--format",
    ),
    input: Path | None = typer.Option(
        None,
        "--input",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
    ),
    json_format: bool = typer.Option(
        False,
        "--json",
    ),
    html_format: bool = typer.Option(
        False,
        "--html",
    ),
) -> None:
    if json_format:
        format = "json"
    elif html_format:
        format = "html"

    normalized = format.strip().lower()

    if normalized not in {"json", "html"}:
        typer.echo("unsupported report format")
        raise typer.Exit(code=2)

    if input is None:
        typer.echo("Report generation command")
        typer.echo(
            f"Report format: {normalized}"
        )
        return

    output_path = (
        output
        or input.with_suffix(".html")
    )

    try:
        build_report_command_service().run(
            ReportCommandConfiguration(
                input_path=input,
                output_path=output_path,
            )
        )
    except Exception as exc:
        typer.echo(
            f"Report failed: {exc}"
        )
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"Report written: {output_path}"
    )


@app.command()
def policy() -> None:
    typer.echo(
        "SecureForge Policy Evaluation"
    )


app.add_typer(
    regression_app,
    name="regression",
)


@app.command()
def validate(
    finding: str | None = typer.Option(
        None,
        "--finding",
    ),
) -> None:
    if not finding:
        typer.echo(
            "A finding identifier is required"
        )
        raise typer.Exit(code=2)

    typer.echo(
        f"Finding: {finding}"
    )


def _validate_scan_options(
    *,
    profile: str,
    environment: str = "lab",
    target: str | None,
    source_path: Path | None,
    validate: bool,
    validation_finding: list[str],
    validation_endpoint: list[str],
    validation_payload: list[str],
    regression: bool = False,
) -> None:
    if profile not in {
        "quick",
        "standard",
        "full",
        "ci",
    }:
        raise typer.BadParameter(
            "unsupported profile"
        )

    if profile == "ci":
        if environment not in {
            "ci",
            "test",
        }:
            raise typer.BadParameter(
                "CI profile only supports ci or test environments."
            )

        if validate:
            raise typer.BadParameter(
                "CI profile does not support active validation."
            )

        if regression:
            raise typer.BadParameter(
                "CI profile does not support regression execution."
            )

    if len(validation_endpoint) > len(
        validation_finding
    ):
        raise typer.BadParameter(
            "Number of --validation-endpoint values cannot exceed "
            "the number of --validation-finding values."
        )

    if len(validation_payload) > len(
        validation_finding
    ):
        raise typer.BadParameter(
            "Number of --validation-payload values cannot exceed "
            "the number of --validation-finding values."
        )


def _print_scan_result(result) -> None:
    """Print the current scan execution result."""

    execution = getattr(
        result,
        "execution",
        None,
    )

    pipeline = getattr(
        result,
        "pipeline",
        None,
    )

    risk = (
        getattr(
            pipeline,
            "risk",
            None,
        )
        if pipeline
        else None
    )

    gate = (
        getattr(
            pipeline,
            "release_gate",
            None,
        )
        if pipeline
        else None
    )

    scan_id = getattr(
        execution,
        "scan_id",
        "unknown",
    )

    typer.echo(
        f"Scan ID: {scan_id}"
    )

    typer.echo(
        "Status: "
        f"{getattr(execution, 'status', 'completed')}"
    )

    typer.echo(
        "Findings: "
        f"{len(getattr(pipeline, 'findings', []) or [])}"
    )

    typer.echo(
        "Risk Score: "
        f"{getattr(risk, 'risk_score', 0)}"
    )

    typer.echo(
        "Highest Severity: "
        f"{getattr(risk, 'highest_severity', 'unknown')}"
    )

    typer.echo(
        "Release Decision: "
        f"{getattr(gate, 'status', 'unknown')}"
    )

    typer.echo(
        "Release Allowed: "
        f"{getattr(gate, 'release_allowed', False)}"
    )

    typer.echo(
        f"Security Report: reports/{scan_id}.json"
    )

    typer.echo(
        f"HTML Report: reports/{scan_id}.html"
    )

    typer.echo(
        "Persisted Scan: .secureforge/scans"
    )


def _print_scan_summary(result) -> None:
    """Print a concise release-gate summary.

    This helper provides the summary representation used by the
    CLI summary tests and by callers that need a focused release
    decision view.
    """

    pipeline = result.pipeline
    decision = pipeline.release_gate

    status = decision.status.lower()

    if status == "passed":
        display_status = "PASS"
    elif status == "review":
        display_status = "REVIEW"
    elif status == "blocked":
        display_status = "BLOCK"
    else:
        display_status = status.upper()

    typer.echo("")
    typer.echo("SecureForge Scan Complete")
    typer.echo("-------------------------")

    typer.echo(
        f"Findings: {len(pipeline.findings)}"
    )

    typer.echo(
        f"Release: {display_status}"
    )

    if pipeline.validation is not None:
        typer.echo(
            "Validation: "
            f"{pipeline.validation.confirmed} confirmed, "
            f"{pipeline.validation.rejected} rejected, "
            f"{pipeline.validation.inconclusive} inconclusive, "
            f"{pipeline.validation.errors} errors"
        )

    if pipeline.validation_gate is not None:
        typer.echo(
            "Validation Gate: "
            f"{pipeline.validation_gate.status}"
        )

    if pipeline.regression_gate is not None:
        typer.echo(
            "Regression Gate: "
            f"{pipeline.regression_gate.status}"
        )

    typer.echo(
        f"Decision: {decision.status}"
    )

    typer.echo(
        f"Reason: {decision.reason}"
    )


if __name__ == "__main__":
    app()
