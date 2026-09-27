```python id="q7m4tz"
"""SecureForge command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from secureforge import __version__
from secureforge.cli.report import (
    ReportCommandService,
    build_report_command_service,
)
from secureforge.cli.scan import (
    ScanCommandConfiguration,
    build_scan_command_service,
)
from secureforge.config.runtime_builder import (
    RuntimeConfigurationError,
)
from secureforge.core.config.models import (
    ScanProfile,
)
from secureforge.regression.cli import app as regression_app


app = typer.Typer(
    name="secureforge",
    help=(
        "Continuous security verification and "
        "release gate for web and API applications."
    ),
    no_args_is_help=True,
)

app.add_typer(
    regression_app,
    name="regression",
    help="Run security regression tests.",
)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        help="Show the SecureForge version.",
        is_eager=True,
    ),
) -> None:
    """SecureForge command-line interface."""
    if version:
        typer.echo(
            f"SecureForge {__version__}"
        )
        raise typer.Exit()


@app.command()
def scan(
    profile: ScanProfile = typer.Option(
        ScanProfile.STANDARD,
        "--profile",
        help="Security verification profile.",
        case_sensitive=False,
    ),
    target: str = typer.Option(
        "http://127.0.0.1:5000",
        "--target",
        help="Application or API target to assess.",
    ),
    source_path: Optional[Path] = typer.Option(
        None,
        "--source-path",
        help="Source directory used by source-based integrations.",
        exists=False,
        file_okay=False,
        dir_okay=True,
    ),
    scan_id: str = typer.Option(
        "cli-scan",
        "--scan-id",
        help="Identifier assigned to this scan.",
    ),
) -> None:
    """Run a SecureForge security verification scan."""
    try:
        selected_profile = ScanProfile(
            profile
        )

        configuration = (
            ScanCommandConfiguration(
                scan_id=scan_id,
                profile=selected_profile,
                target=target,
                source_path=source_path,
            )
        )

        service = (
            build_scan_command_service()
        )

        result = service.run(
            configuration
        )

    except RuntimeConfigurationError as exc:
        typer.echo(
            f"Configuration error: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=2
        ) from exc

    except ValueError as exc:
        raise typer.BadParameter(
            "Profile must be quick, standard, or full."
        ) from exc

    except Exception as exc:
        typer.echo(
            f"Scan failed: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=2
        ) from exc

    typer.echo(
        f"Scan ID: {result.execution.scan_id}"
    )
    typer.echo(
        f"Status: {result.execution.status.value}"
    )
    typer.echo(
        f"Findings: {len(result.findings)}"
    )
    typer.echo(
        f"Risk Score: {result.pipeline.risk.score}"
    )
    typer.echo(
        "Highest Severity: "
        f"{result.pipeline.risk.highest_severity.value}"
    )
    typer.echo(
        "Release Decision: "
        f"{result.release_status}"
    )
    typer.echo(
        "Release Allowed: "
        f"{result.release_allowed}"
    )

    if result.execution.warnings:
        typer.echo("Warnings:")
        for warning in result.execution.warnings:
            typer.echo(
                f"- {warning}"
            )

    if result.execution.errors:
        typer.echo("Errors:")
        for error in result.execution.errors:
            typer.echo(
                f"- {error}"
            )

    if result.pipeline.regression_gate is not None:
        typer.echo(
            "Regression Gate: "
            f"{result.pipeline.regression_gate.status}"
        )

    if result.release_blocked:
        raise typer.Exit(
            code=1
        )


@app.command()
def report(
    json_path: Path = typer.Option(
        Path("reports/security-report.json"),
        "--json",
        help="Path to an existing SecureForge JSON report.",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    html_path: Optional[Path] = typer.Option(
        None,
        "--html",
        help="Output path for the regenerated HTML report.",
        file_okay=True,
        dir_okay=False,
    ),
) -> None:
    """Load a JSON report and generate its HTML representation."""
    service = build_report_command_service()

    try:
        output_path = service.regenerate_html(
            json_path=json_path,
            html_path=html_path,
        )
    except Exception as exc:
        typer.echo(
            f"Report generation failed: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=2
        ) from exc

    typer.echo(
        f"JSON Report: {json_path}"
    )
    typer.echo(
        f"HTML Report: {output_path}"
    )


if __name__ == "__main__":
    app()
```
