# SecureForge Security Reporting Methodology

## Purpose

- SecureForge produces security reports that explain what was tested, what was discovered, what was validated, and why a release decision was reached.
- Reports are designed for:
	- Developers
	- Security engineers
	- Application owners
	- Reviewers
	- CI/CD pipelines
	- Security leadership
- A report should be understandable without requiring direct access to scanner consoles.

## Reporting Objectives

- A SecureForge report should answer:
	- What application was tested?
	- Which version was tested?
	- Which environment was tested?
	- Which security profile was used?
	- Which tools contributed evidence?
	- What findings were identified?
	- Which findings were correlated?
	- Which findings were validated?
	- What remediation is required?
	- Which regressions were detected?
	- What policy was applied?
	- What is the final release decision?
	- Why was that decision produced?

## Report Formats

- SecureForge supports two primary report formats:
	- JSON
	- HTML

### JSON

- JSON is intended for:
	- CI/CD processing
	- Automation
	- API consumers
	- Archival
	- Machine-readable analysis
- JSON should preserve structured security information.

### HTML

- HTML is intended for:
	- Human review
	- Security assessments
	- Developer remediation
	- Release approval
	- Audit discussions
- HTML should present the most important security information clearly.

## Report Structure

- A security report contains:
	- Release metadata
	- Scan metadata
	- Findings
	- Risk
	- Policy
	- Validation
	- Validation results
	- Validation gate
	- Remediation
	- Regression
	- Regression gate
	- Final decision
	- Generation metadata

## Release Metadata

- Release metadata identifies the software being evaluated.
- Recommended fields include:
	- Application
	- Version
	- Commit SHA
	- Environment
	- Release identifier

## Scan Metadata

- Scan metadata identifies how verification was performed.
- Recommended fields include:
	- Scan ID
	- Profile
	- Target
	- Source path
	- Started timestamp
	- Completed timestamp
	- Tool list

## Findings

- Each finding should contain:
	- Finding ID
	- Title
	- Source
	- Asset
	- Application
	- Endpoint
	- Parameter
	- CWE
	- OWASP mapping
	- Security requirement
	- Severity
	- Confidence
	- Description
	- Impact
	- Remediation
	- Status
	- Validation status
	- Evidence

## Finding Identity

- Finding IDs provide stable references across the security lifecycle.
- Examples include:
	- `BOLA-001`
	- `SQLI-001`
	- `XSS-001`
	- `AUTHZ-001`
	- `SECRET-001`
- A stable finding identity helps connect:
	- Detection
	- Validation
	- Remediation
	- Retesting
	- Regression testing

## Finding Status

- Reports should distinguish finding lifecycle states.
- Examples include:
	- Open
	- Validated
	- Remediated
	- Verified
	- Reopened

## Severity

- Severity should be presented explicitly.
- SecureForge uses:
	- Critical
	- High
	- Medium
	- Low
	- Informational

## Confidence

- Confidence communicates how strongly the available evidence supports the finding.
- A report should not imply that every scanner finding is confirmed.
- Validation results provide additional evidence for confidence.

## Evidence

- Reports should provide enough evidence to understand the security condition.
- Evidence can include:
	- Request
	- Response
	- Command
	- Output
	- Expected behavior
	- Observed behavior
- Sensitive values should be redacted before reporting.

## Correlation Reporting

- When multiple tools identify the same condition, the report should show that the finding contains multiple evidence sources.
- Example:
	- SAST
	- DAST
	- Burp validation
- Correlation prevents duplicated findings from obscuring the underlying security condition.

## Risk Section

- The risk section should explain the contextual risk assessment.
- Relevant factors can include:
	- Severity
	- Confidence
	- Asset importance
	- Exposure
	- Authentication requirement
	- Sensitive data
	- Exploit evidence
	- Environment

## Policy Section

- The policy section should identify the rules applied to the scan.
- Example:
	- Critical → block
	- High → block
	- Medium → review
	- Low → pass

## Validation Section

- The validation section should summarize:
	- Total validations
	- Confirmed findings
	- Rejected findings
	- Inconclusive findings
	- Validation errors
	- Remediation verification

## Validation Results

- Individual validation results should identify:
	- Finding ID
	- Outcome
	- Message
	- Validator
	- Timestamp
	- Evidence
	- Remediation verification state

## Validation Gate

- The validation gate should explain whether validation produced:
	- Passed
	- Review
	- Blocked
	- Error
- The report should preserve the distinction between a confirmed vulnerability and an inconclusive validation.

## Remediation

- Remediation reporting should identify:
	- Finding
	- Recommended action
	- Current status
	- Verification state
- Remediation should be actionable rather than generic.

## Retesting

- Retesting information should show:
	- Previous outcome
	- Current outcome
	- Remediation verification
	- Validation evidence
- A verified remediation should remain connected to the original finding.

## Regression

- Regression reporting should include:
	- Regression test ID
	- Finding or requirement
	- Status
	- Expected behavior
	- Observed behavior
	- Evidence

## Regression Gate

- The regression gate should clearly indicate:
	- Passed
	- Review
	- Blocked
	- Error
- Failed required regression tests should be visible in the final decision explanation.

## Final Decision

- The final decision should be highly visible.
- SecureForge uses:
	- `PASS`
	- `REVIEW`
	- `BLOCK`

### PASS

- The configured security controls passed.
- The report should still show all relevant findings and coverage limitations.

### REVIEW

- The report should identify the unresolved uncertainty.
- Examples include:
	- Inconclusive validation
	- Validation errors
	- Regression uncertainty
	- Explicit review conditions

### BLOCK

- The report should identify the exact blocking condition.
- Examples include:
	- Policy-blocking finding
	- Confirmed vulnerability
	- Failed regression
	- Explicit security control failure

## Decision Reason

- Every final decision should have a human-readable reason.
- Example:
	- `Release blocked because SQLI-001 is confirmed and high severity findings are configured to block release.`
- Reasons should describe observed security controls rather than speculate about developer intent.

## Report Traceability

- Reports should connect:
	- Release
	- Commit
	- Scan
	- Finding
	- Evidence
	- Validation
	- Remediation
	- Regression
	- Policy
	- Final decision

## Report Generation

- SecureForge generates:
	- `security-report.json`
	- `security-report.html`
- Both reports should represent the same security decision.
- JSON is the structured source for automation.
- HTML is the human-readable representation.

## Report Consistency

- JSON and HTML should agree on:
	- Finding count
	- Severity
	- Validation results
	- Regression results
	- Policy decision
	- Final release status
- Report generation should not independently recalculate security decisions.

## Report Security

- Reports may contain sensitive security information.
- Reports should:
	- Redact credentials
	- Avoid unnecessary secrets
	- Avoid unnecessary application data
	- Use controlled storage
	- Follow organizational access requirements

## CI Artifacts

- CI workflows should preserve reports as build artifacts when appropriate.
- Recommended artifacts include:
	- Security JSON report
	- Security HTML report
	- Scan result
- Artifact visibility should be restricted when the report contains sensitive information.

## Report Retention

- Security reports should be retained according to:
	- Security policy
	- Compliance requirements
	- Incident-response requirements
	- Development needs
- Retention should balance auditability with sensitive-data exposure.

## Reporting Errors

- Report-generation failures should be treated separately from security findings.
- Examples include:
	- Invalid report model
	- Serialization failure
	- Invalid output path
	- HTML rendering failure
- A report-generation error should not be represented as a clean security scan.

## Reporting and CI

- CI should expose the final decision clearly.
- Example:
	- `PASS` → security gate passed
	- `REVIEW` → human review required
	- `BLOCK` → security gate failed
- The detailed report provides the evidence behind the status.

## Practical Report Example

- A report may contain:
	- Application → SecureCommerce
	- Version → `0.1.0`
	- Environment → `lab`
	- Profile → `standard`
	- Findings → 4
	- Confirmed → 2
	- Inconclusive → 1
	- Regression failures → 0
	- Policy → High severity blocks
	- Final decision → `BLOCK`
- The report should then identify which confirmed finding caused the block.

## Coverage Transparency

- A report should make missing coverage visible.
- Examples include:
	- Tool unavailable
	- Integration skipped
	- Authentication not configured
	- Target unavailable
	- Validation not performed
	- Regression test skipped
- Missing coverage must not be represented as a successful security check.

## Practical Principle

- A SecureForge report is not simply a list of vulnerabilities.
- It is the evidence trail connecting:
	- What was tested
	- What was found
	- What was validated
	- What was remediated
	- What was retested
	- What regressed
	- What policy was applied
	- Why the release received its final decision
