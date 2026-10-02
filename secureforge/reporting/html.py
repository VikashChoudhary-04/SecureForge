"""HTML report rendering for SecureForge."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from .models import SecurityReport


class SecurityHTMLReportRenderer:
    """Render SecureForge security reports as HTML."""

    def write_html(self, report: SecurityReport, output_path: str | Path):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return path

    def render(self, report: SecurityReport) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureForge Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 0; padding: 24px; background: #f5f7fa; color: #1f2937; }}
section {{ background: white; margin-bottom: 20px; padding: 20px; border-radius: 8px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; }}
.badge {{ display: inline-block; padding: 4px 7px; margin: 2px; background: #e5e7eb; }}
</style>
</head>
<body>
<header>
<h1>SecureForge Security Report</h1>
<p>{escape(report.release.application)} &mdash; {escape(report.release.version)}</p>
</header>
<main>
{self._render_decision(report)}
{self._render_release(report)}
{self._render_scan(report)}
{self._render_risk(report)}
{self._render_policy(report)}
{self._render_validation(report)}
{self._render_validation_results(report)}
{self._render_findings(report)}
{self._render_remediation(report)}
{self._render_regression(report)}
{self._render_metadata(report)}
</main>
</body>
</html>"""

    def _render_decision(self, report):
        return f"""<section>
<h2>Release Decision</h2>
<p><strong>Status:</strong> {escape(report.decision.status)}</p>
<p><strong>Release allowed:</strong> {report.decision.release_allowed}</p>
<p><strong>Reason:</strong> {escape(report.decision.reason)}</p>
</section>"""

    def _render_release(self, report):
        return f"""<section>
<h2>Release</h2>
<p>{escape(report.release.application)} / {escape(report.release.version)}</p>
<p>Environment: {escape(report.release.environment)}</p>
</section>"""

    def _render_scan(self, report):
        return f"""<section>
<h2>Scan</h2>
<p>Profile: {escape(report.scan.profile)}</p>
<p>Target: {escape(report.scan.target)}</p>
<p>Started: {escape(report.scan.started_at)}</p>
<p>Completed: {escape(report.scan.completed_at)}</p>
</section>"""

    def _render_risk(self, report):
        factors = report.risk.factors
        if isinstance(factors, dict):
            rows = "".join(
                f"<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>"
                for k, v in factors.items()
            )
        else:
            rows = "".join(
                f"<tr><td colspan='2'>{escape(str(item))}</td></tr>"
                for item in factors
            )
        return f"""<section>
<h2>Risk Assessment</h2>
<p><strong>Score:</strong> {report.risk.score}</p>
<p><strong>Severity:</strong> {escape(report.risk.highest_severity)}</p>
<p><strong>Blocked:</strong> {report.risk.blocked}</p>
<table>{rows}</table>
</section>"""

    def _render_policy(self, report):
        actions = report.policy.actions
        action_text = escape(str(actions))
        return f"""<section>
<h2>Policy Evaluation</h2>
<p><strong>Action:</strong> {escape(report.policy.action)}</p>
<p><strong>Reason:</strong> {escape(report.policy.reason)}</p>
<p><strong>Actions:</strong> {action_text}</p>
<p><strong>Exceptions:</strong> {escape(str(report.policy.exceptions))}</p>
</section>"""

    def _render_validation(self, report):
        if report.validation is None:
            return "<section><h2>Security Validation</h2><p>Validation was not executed.</p></section>"
        gate = ""
        if report.validation_gate is not None:
            gate = f"""
<h3>Validation Gate</h3>
<p><strong>Allowed:</strong> {report.validation_gate.allowed}</p>
<p><strong>Blocked:</strong> {report.validation_gate.blocked}</p>
<p><strong>Status:</strong> {escape(report.validation_gate.status)}</p>
<p><strong>Reason:</strong> {escape(report.validation_gate.reason)}</p>"""
        return f"""<section>
<h2>Security Validation</h2>
<p>Total: {report.validation.total}</p>
<p>Confirmed: {report.validation.confirmed}</p>
<p>Rejected: {report.validation.rejected}</p>
<p>Inconclusive: {report.validation.inconclusive}</p>
<p>Errors: {report.validation.errors}</p>
{gate}
</section>"""

    def _render_validation_results(self, report):
        if not report.validation_results:
            return ""
        rows = "".join(
            f"<tr><td>{escape(r.finding_id)}</td><td>{escape(r.outcome)}</td><td>{escape(r.message)}</td></tr>"
            for r in report.validation_results
        )
        return f"<section><h2>Validation Results</h2><table><tr><th>Finding</th><th>Outcome</th><th>Message</th></tr>{rows}</table></section>"

    def _render_findings(self, report):
        if not report.findings:
            return "<section><h2>Findings</h2><p>No findings were produced.</p></section>"
        content = []
        for finding in report.findings:
            content.append(
                f"""<div>
<h3>{escape(finding.finding_id)} &mdash; {escape(finding.title)}</h3>
<p><span class="badge">Severity: {escape(finding.severity)}</span>
<span class="badge">Status: {escape(finding.status)}</span></p>
<p>Source: {escape(finding.source)}</p>
<p>Asset: {escape(finding.asset)}</p>
<p>Description: {escape(finding.description)}</p>
<p>Impact: {escape(finding.impact)}</p>
<p>Remediation: {escape(finding.remediation)}</p>
</div>"""
            )
        return f"<section><h2>Findings</h2>{''.join(content)}</section>"

    def _render_remediation(self, report):
        items = report.remediation.findings
        rows = "".join(
            f"<li><strong>{escape(item.finding_id)}</strong> &mdash; "
            f"{escape(item.status)} &mdash; {escape(item.remediation)}</li>"
            for item in items
        )
        return f"""<section>
<h2>Remediation</h2>
<p>Total: {report.remediation.total}</p>
<p>Open: {report.remediation.open_count}</p>
<p>Remediated: {report.remediation.remediated_count}</p>
<ul>{rows or "<li>None</li>"}</ul>
</section>"""

    def _render_regression(self, report):
        if report.regression is None:
            return "<section><h2>Regression Testing</h2><p>Regression testing was not executed.</p></section>"

        gate_html = ""
        if report.regression_gate is not None:
            gate = report.regression_gate
            failed = "".join(f"<li>{escape(str(x))}</li>" for x in gate.failed_tests) or "<li>None</li>"
            errored = "".join(f"<li>{escape(str(x))}</li>" for x in gate.errored_tests) or "<li>None</li>"
            skipped = "".join(f"<li>{escape(str(x))}</li>" for x in gate.skipped_tests) or "<li>None</li>"
            gate_html = f"""
<h3>Regression Gate</h3>
<p><strong>Allowed:</strong> {gate.allowed}</p>
<p><strong>Blocked:</strong> {gate.blocked}</p>
<p><strong>Status:</strong> {escape(str(gate.status))}</p>
<p><strong>Reason:</strong> {escape(gate.reason)}</p>
<p><strong>Failed tests:</strong></p><ul>{failed}</ul>
<p><strong>Errored tests:</strong></p><ul>{errored}</ul>
<p><strong>Skipped tests:</strong></p><ul>{skipped}</ul>"""

        rows = "".join(
            f"<tr><td>{escape(t.test_id)}</td><td>{escape(t.status)}</td><td>{escape(t.message)}</td></tr>"
            for t in report.regression.tests
        )
        return f"""<section>
<h2>Regression Testing</h2>
<p>Suite: {escape(report.regression.suite_id)}</p>
<p>Status: {escape(report.regression.status)}</p>
<p>Total: {report.regression.total}</p>
<p>Passed: {report.regression.passed}</p>
<p>Failed: {report.regression.failed}</p>
<p>Errored: {report.regression.errors}</p>
{gate_html}
<table><tr><th>Test ID</th><th>Status</th><th>Message</th></tr>{rows}</table>
</section>"""

    def _render_metadata(self, report):
        return f"<section><h2>Report Metadata</h2><p><strong>Generated:</strong> {escape(report.generated_at)}</p></section>"


HTMLReportRenderer = SecurityHTMLReportRenderer

__all__ = ["HTMLReportRenderer", "SecurityHTMLReportRenderer"]
