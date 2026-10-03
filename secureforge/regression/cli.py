"""Command-line interface for SecureForge regression testing."""

from __future__ import annotations

from pathlib import Path

import typer

from .runner import RegressionRunConfiguration, RegressionRunner


app = typer.Typer(
    name="regression",
    help="Run SecureForge security regression tests.",
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def regression_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo("SecureForge Security Regression")


@app.command("run")
def run_regression(
    suite: str = typer.Option(
        "requirements/regression-tests.yaml",
        "--suite",
    ),
    base_url: str = typer.Option(
        "http://127.0.0.1:5000",
        "--base-url",
    ),
    source_root: str | None = typer.Option(
        None,
        "--source-root",
    ),
    infrastructure_root: str | None = typer.Option(
        None,
        "--infrastructure-root",
    ),
    timeout: float = typer.Option(
        5.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    config = RegressionRunConfiguration(
        suite_path=Path(suite),
        base_url=base_url,
        timeout=timeout,
        source_root=(
            Path(source_root)
            if source_root
            else None
        ),
        infrastructure_root=(
            Path(infrastructure_root)
            if infrastructure_root
            else None
        ),
    )

    try:
        result = RegressionRunner().run(config)
    except Exception as exc:
        typer.echo(
            f"Regression execution error: {exc}"
        )
        raise typer.Exit(code=1) from exc

    typer.echo(f"Suite: {result.name}")
    typer.echo(
        f"Status: {result.status.value.upper()}"
    )
    typer.echo(f"Total: {result.total}")
    typer.echo(f"Passed: {result.passed}")
    typer.echo(f"Failed: {result.failed}")
    typer.echo(f"Errors: {result.errors}")
    typer.echo(f"Skipped: {result.skipped}")

    for item in result.results:
        typer.echo(
            f" - {item.test_id}: "
            f"{item.status.value.upper()}"
        )

    if result.status.value == "error":
        typer.echo(
            "Regression execution error: "
            "one or more regression tests "
            "could not be executed."
        )

    raise typer.Exit(
        code=0
        if result.status.value == "passed"
        else 1
    )


__all__ = [
    "app",
    "run_regression",
]


if __name__ == "__main__":
    app()

