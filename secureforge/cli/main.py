"""Command-line interface for SecureForge."""

from __future__ import annotations

from pathlib import Path

import typer

from secureforge import __version__
from secureforge.cli.scan import ScanCommandConfig, ScanCommandService
from secureforge.config.factory import create_runtime
from secureforge.validation.models import (
    ValidationMethod,
    ValidationRequest,
)

app = typer.Typer(
    name="secureforge",
    help=(
        "Continuous security verification and release gate "
        "for web/API applications."
    ),
)

VALID_PROFILES = {
    "quick",
    "standard",
    "full",
    "ci",
}


@app.command()
def scan(
    profile: str = typer.Option(
        "standard",
        help=(
            "Security scan profile: quick, standard, "
            "full, or ci."
        ),
    ),
    target: str | None = typer.Option(
        None,
        help="Target URL or host.",
    ),
    source_path: Path | None = typer.Option(
        None,
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Application source directory.",
    ),
    scan_id: str = typer.Option(
        "local-scan",
        help="Unique scan identifier.",
    ),
    application: str = typer.Option(
        "SecureCommerce",
        help="Application name.",
    ),
    version_label: str = typer.Option(
        "dev",
        help="Application version.",
    ),
    commit_sha: str | None = typer.Option(
        None,
        help="Git commit SHA.",
    ),
    environment: str = typer.Option(
        "lab",
        help="Execution environment.",
    ),
    output: Path = typer.Option(
        Path("reports"),
        help="Directory for generated reports.",
    ),
    scan_storage: Path = typer.Option(
        Path(".secureforge/scans"),
        help="Directory for stored scan results.",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help=(
            "Automatically validate findings supported by "
            "the configured validation planners."
        ),
    ),
    validation_finding: list[str] = typer.Option(
        [],
        "--validation-finding",
        help=(
            "Finding ID to validate manually. "
            "May be supplied multiple times."
        ),
    ),
    validation_endpoint: list[str] = typer.Option(
        [],
        "--validation-endpoint",
        help=(
            "Endpoint corresponding to a manual validation finding."
        ),
    ),
    validation_payload: list[str] = typer.Option(
        [],
        "--validation-payload",
        help=(
            "Payload corresponding to a manual validation finding."
        ),
    ),
    validation_method: str = typer.Option(
        "http",
        help=(
            "Validation method: http, api, command, "
            "script, or manual."
        ),
    ),
    regression: bool = typer.Option(
        False,
        "--regression",
        help="Run regression tests as part of the security pipeline.",
    ),
) -> None:
    """Run a SecureForge security verification scan."""
    _validate_scan_options(
        profile=profile,
        target=target,
        source_path=source_path,
        validate=validate,
        validation_finding=validation_finding,
        validation_endpoint=validation_endpoint,
        validation_payload=validation_payload,
        regression=regression,
    )

    try:
        method = ValidationMethod(validation_method)
    except ValueError as exc:
        raise typer.BadParameter(
            "Invalid validation method. "
            "Use: http, api, command, script, or manual."
        ) from exc

    validation_requests = _build_validation_requests(
        finding_ids=validation_finding,
        endpoints=validation_endpoint,
        payloads=validation_payload,
        method=method,
        target=target,
    )

    try:
        runtime = create_runtime(
            profile=profile,
            target=target,
            source_path=source_path,
        )

        service = ScanCommandService(
            orchestrator=runtime.orchestrator,
            store=runtime.store,
        )

        config = ScanCommandConfig(
            scan_id=scan_id,
            profile=profile,
            target=target,
            source_path=source_path,
            application=application,
            version=version_label,
            commit_sha=commit_sha,
            environment=environment,
            output_directory=output,
            scan_storage_directory=scan_storage,
            validation_requests=tuple(
                validation_requests
            ),
            validate_findings=validate,
            validation_method=method,
            run_regression=regression,
        )

        result = service.run(config)

    except Exception as exc:
        typer.echo(
            f"SecureForge scan failed: "
            f"{type(exc).__name__}: {exc}",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    _print_scan_summary(result)


@app.command()
def version() -> None:
    """Display the SecureForge version."""
    typer.echo(f"SecureForge {__version__}")


def _validate_scan_options(
    *,
    profile: str,
    target: str | None,
    source_path: Path | None,
    validate: bool,
    validation_finding: list[str],
    validation_endpoint: list[str],
    validation_payload: list[str],
    regression: bool,
) -> None:
    """Validate scan command options."""
    if not target and not source_path:
        raise typer.BadParameter(
            "Provide at least one of --target or --source-path."
        )

    if profile not in VALID_PROFILES:
        available = ", ".join(
            sorted(VALID_PROFILES)
        )
        raise typer.BadParameter(
            f"Profile must be one of: {available}."
        )

    if profile == "ci" and environment_is_not_ci():
        raise typer.BadParameter(
            "The ci profile requires the execution environment "
            "to be 'ci' or 'test'."
        )

    if validate and not target:
        raise typer.BadParameter(
            "--validate requires --target because active "
            "finding validation targets an application."
        )

    if profile == "ci" and validate:
        raise typer.BadParameter(
            "The ci profile is deterministic and does not "
            "perform active finding validation."
        )

    if profile == "ci" and regression:
        raise typer.BadParameter(
            "The ci profile does not run application regression "
            "tests."
        )

    if len(validation_endpoint) > len(
        validation_finding
    ):
        raise typer.BadParameter(
            "Number of --validation-endpoint values "
            "cannot exceed the number of "
            "--validation-finding values."
        )

    if len(validation_payload) > len(
        validation_finding
    ):
        raise typer.BadParameter(
            "Number of --validation-payload values "
            "cannot exceed the number of "
            "--validation-finding values."
        )


def environment_is_not_ci() -> bool:
    """Return whether the default CLI environment is non-CI."""
    return False


def _build_validation_requests(
    *,
    finding_ids: list[str],
    endpoints: list[str],
    payloads: list[str],
    method: ValidationMethod,
    target: str | None,
) -> list[ValidationRequest]:
    """Build manually supplied validation requests."""
    if not finding_ids:
        return []

    if target is None:
        raise typer.BadParameter(
            "A --target is required when manual validation "
            "requests are supplied."
        )

    requests: list[ValidationRequest] = []

    for index, finding_id in enumerate(
        finding_ids
    ):
        endpoint = (
            endpoints[index]
            if index < len(endpoints)
            else None
        )

        payload = (
            payloads[index]
            if index < len(payloads)
            else None
        )

        requests.append(
            ValidationRequest(
                finding_id=finding_id,
                target=target,
                method=method,
                endpoint=endpoint,
                payload=payload,
            )
        )

    return requests


def _print_scan_summary(result) -> None:
    """Print a concise scan summary."""
    pipeline = result.pipeline

    typer.echo("")
    typer.echo("SecureForge Scan Complete")
    typer.echo("-------------------------")
    typer.echo(
        f"Findings: {len(pipeline.findings)}"
    )

    status = pipeline.release_gate.status.upper()

    typer.echo(
        f"Release: {status}"
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
        f"Decision: {pipeline.release_gate.status}"
    )

    typer.echo(
        f"Reason: {pipeline.release_gate.reason}"
    )


if __name__ == "__main__":
    app()
