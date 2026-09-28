"""Command-line interface for SecureForge regression testing."""

from __future__ import annotations

from pathlib import Path

import typer

from .runner import (
RegressionRunConfiguration,
RegressionRunner,
)

app = typer.Typer(
name="regression",
help=(
"Run SecureForge security regression tests "
"against the SecureCommerce laboratory."
),
no_args_is_help=True,
)

@app.command("run")
def run_regression(
suite: Path = typer.Option(
Path("requirements/regression-tests.yaml"),
"--suite",
help="Path to the regression suite YAML file.",
exists=True,
readable=True,
dir_okay=False,
),
base_url: str = typer.Option(
"http://127.0.0.1:5000",
"--base-url",
help="Base URL of the SecureCommerce application.",
),
source_root: Path | None = typer.Option(
None,
"--source-root",
help="SecureCommerce source directory for source regressions.",
exists=True,
file_okay=False,
dir_okay=True,
),
infrastructure_root: Path | None = typer.Option(
None,
"--infrastructure-root",
help="Infrastructure directory for IaC regressions.",
exists=True,
file_okay=False,
dir_okay=True,
),
timeout: float = typer.Option(
5.0,
"--timeout",
min=0.1,
help="HTTP request timeout in seconds.",
),
) -> None:
"""Run the configured SecureCommerce regression suite."""
configuration = RegressionRunConfiguration(
suite_path=suite,
base_url=base_url,
timeout=timeout,
source_root=source_root,
infrastructure_root=infrastructure_root,
)

```
runner = RegressionRunner()

try:
    result = runner.run(
        configuration
    )
except Exception as exc:
    typer.echo(
        f"Regression execution error: {exc}",
        err=True,
    )
    raise typer.Exit(
        code=2
    ) from exc

typer.echo(
    f"Suite: {result.name}"
)
typer.echo(
    f"Status: {result.status.value.upper()}"
)
typer.echo(
    f"Total: {result.total}"
)
typer.echo(
    f"Passed: {result.passed}"
)
typer.echo(
    f"Failed: {result.failed}"
)
typer.echo(
    f"Errors: {result.errors}"
)
typer.echo(
    f"Skipped: {result.skipped}"
)

for regression_result in result.results:
    typer.echo(
        " - "
        f"{regression_result.test_id}: "
        f"{regression_result.status.value.upper()}"
    )

if result.status.value == "passed":
    raise typer.Exit(
        code=0
    )

raise typer.Exit(
    code=1
)
```
