"""SecureForge command-line interface."""

from **future** import annotations

from typing import Optional

import typer

from secureforge import **version**
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
f"SecureForge {**version**}"
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
) -> None:
"""Run a SecureForge security verification scan."""
try:
selected_profile = ScanProfile(
profile
)
except ValueError as exc:
raise typer.BadParameter(
"Profile must be quick, standard, or full."
) from exc

```
typer.echo(
    f"Selected profile: "
    f"{selected_profile.value}"
)
typer.echo(
    "Scan engine implementation is being assembled."
)
```

@app.command()
def report() -> None:
"""Generate a SecureForge security report."""
typer.echo(
"Report generation command is being assembled."
)

if **name** == "**main**":
app()
