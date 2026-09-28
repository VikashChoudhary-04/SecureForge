# SecureForge CLI summary tests

from types import SimpleNamespace

from secureforge.cli.main import _print_scan_summary


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


def test_cli_summary_reports_review_as_review(capsys) -> None:
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
    assert "All configured release-gate controls passed." in output
