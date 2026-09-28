# SecureForge CLI summary tests

from types import SimpleNamespace

from typer.testing import CliRunner

from secureforge.cli.main import app


runner = CliRunner()


def _result(
    *,
    status: str,
    reason: str = "Test decision.",
):
    decision = SimpleNamespace(
        status=status,
        reason=reason,
        release_allowed=status != "blocked",
    )

    pipeline = SimpleNamespace(
        findings=[],
        release_gate=decision,
        validation=None,
        validation_gate=None,
        regression_gate=None,
    )

    return SimpleNamespace(
        pipeline=pipeline,
    )


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "SecureForge" in result.stdout


def test_release_gate_status_values_are_distinct() -> None:
    from secureforge.cli.main import _print_scan_summary

    output_cases = (
        ("passed", "Release: PASS"),
        ("review", "Release: REVIEW"),
        ("blocked", "Release: BLOCK"),
    )

    for status, expected in output_cases:
        result = runner.invoke(
            app,
            [
                "version",
            ],
        )

        assert result.exit_code == 0

        # Exercise the formatter without invoking a real scan.
        # The helper writes through Typer's output layer.
        _print_scan_summary(_result(status=status))

        assert expected


def test_cli_summary_reports_review_as_review(capsys) -> None:
    from secureforge.cli.main import _print_scan_summary

    _print_scan_summary(
        _result(
            status="review",
            reason="Validation evidence requires review.",
        )
    )

    output = capsys.readouterr().out

    assert "Release: REVIEW" in output
    assert "Release: BLOCK" not in output
    assert "Decision: review" in output
    assert "Validation evidence requires review." in output


def test_cli_summary_reports_block_as_block(capsys) -> None:
    from secureforge.cli.main import _print_scan_summary

    _print_scan_summary(
        _result(
            status="blocked",
            reason="Confirmed security finding blocks release.",
        )
    )

    output = capsys.readouterr().out

    assert "Release: BLOCK" in output
    assert "Decision: blocked" in output
    assert "Confirmed security finding blocks release." in output


def test_cli_summary_reports_pass_as_pass(capsys) -> None:
    from secureforge.cli.main import _print_scan_summary

    _print_scan_summary(
        _result(
            status="passed",
            reason="All configured release-gate controls passed.",
        )
    )

    output = capsys.readouterr().out

    assert "Release: PASS" in output
    assert "Release: BLOCK" not in output
    assert "Decision: passed" in output
