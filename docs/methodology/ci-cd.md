# SecureForge CI/CD Security Methodology

## Purpose

- SecureForge is designed to operate as a security verification layer inside a software delivery pipeline.
- The CI/CD workflow should make security verification repeatable for every relevant code change.
- The objective is to detect, validate, prioritize, and gate security conditions before release.

## CI/CD Lifecycle

- A typical SecureForge workflow is:
	- Developer creates a branch
	- Pull request is opened
	- CI starts
	- SecureForge is installed
	- Security tests execute
	- Security evidence is collected
	- Findings are normalized
	- Findings are correlated
	- Risk is evaluated
	- Policy is evaluated
	- Validation runs when configured
	- Regression tests run when configured
	- Release gate evaluates the result
	- Reports are generated
	- CI succeeds, requires review, or fails

## Pipeline Triggers

- SecureForge can run on:
	- Pull requests
	- Pushes to protected branches
	- Release workflows
	- Scheduled security verification
	- Manual workflow dispatch

## Pull Request Verification

- Pull requests provide an early security feedback point.
- The pipeline should run security checks before code is merged.
- Typical checks include:
	- SAST
	- SCA
	- Secret detection
	- API security testing
	- DAST where a test deployment is available
	- Container security
	- IaC security
	- SecureForge policy evaluation

## Branch Protection

- Organizations can require the SecureForge security job to pass before merging.
- A protected branch can therefore enforce:
	- Security tests completed
	- No policy-blocking findings
	- Required regression tests passed
	- Required validation completed

## Security Profiles

### Quick Profile

- Intended for fast pull-request verification.
- Includes:
	- SAST
	- SCA
	- Secret detection
- The quick profile provides rapid feedback but does not represent complete application security coverage.

### Standard Profile

- Intended for normal application verification.
- Includes:
	- SAST
	- SCA
	- Secret detection
	- API security
	- DAST
	- Container security

### Full Profile

- Intended for deeper controlled verification.
- Includes:
	- Standard security checks
	- IaC security
	- Nessus
	- Nmap
	- Manual security evidence

## Source and Target Context

- CI scans may require:
	- Source path
	- Target URL
	- OpenAPI specification
	- Container image
	- Infrastructure code
	- Scan configuration
- SecureForge should fail clearly when required context is missing rather than silently skipping a required control.

## Environment Separation

- CI should use controlled environments.
- Recommended environments include:
	- Development
	- Test
	- Staging
	- Dedicated security lab
- Production testing should only occur when explicitly authorized and when the configured validation methods are safe for production.

## SecureCommerce CI

- SecureCommerce provides a deliberately vulnerable application for SecureForge development.
- A controlled CI workflow can:
	- Start SecureCommerce
	- Wait for application readiness
	- Expose its OpenAPI definition
	- Run SecureForge against the application
	- Validate selected findings
	- Run regression tests
	- Generate security reports

## Tool Integration

- SecureForge should orchestrate established security tools rather than attempting to replace them.
- Example integrations include:
	- SAST scanner
	- SCA scanner
	- Secret scanner
	- API security scanner
	- DAST scanner
	- Container scanner
	- IaC scanner
	- Nmap
	- Nessus
	- Burp Suite
	- Wireshark
	- Metasploit

## Evidence Collection

- Each integration should produce structured evidence.
- SecureForge normalizes that evidence into the common finding model.
- Tool-specific details should remain available as evidence without forcing the core engine to understand every scanner's native format.

## Correlation

- Multiple tools can report the same security condition.
- SecureForge correlates compatible findings before release evaluation.
- Example:
	- SAST identifies possible SQL injection.
	- DAST identifies the same endpoint.
	- Manual Burp validation confirms the issue.
- The final security report should represent the correlated security condition with its supporting evidence.

## Validation in CI

- Validation should only run when:
	- The target is available.
	- The target is authorized.
	- The validation method is safe.
	- Required context is available.
- Validation should use controlled payloads.
- Real credentials and production secrets must not be embedded in CI configuration.

## Validation States

- CI should preserve the distinction between:
	- Confirmed
	- Rejected
	- Inconclusive
	- Error
- A validation error should not be silently converted into a successful validation.

## Regression Testing

- Regression tests protect previously remediated security controls.
- CI should execute required regression tests for relevant releases.
- Example regression scenarios include:
	- BOLA
	- SQL injection
	- XSS
	- Secret exposure
	- Authorization
	- Security misconfiguration

## Release-Gate Behavior

- SecureForge produces:
	- `PASS`
	- `REVIEW`
	- `BLOCK`

### PASS

- The configured release controls passed.
- The CI job can continue.

### REVIEW

- Security evidence requires human assessment.
- Examples include:
	- Inconclusive validation
	- Validation errors
	- Regression uncertainty
- Organizations can configure their CI workflow to require approval before release.

### BLOCK

- A configured release condition failed.
- Examples include:
	- Blocking severity finding
	- Confirmed vulnerability violating policy
	- Failed regression test
	- Explicit security policy violation
- The CI security job should fail when enforcement is enabled.

## Exit Codes

- CLI behavior should provide meaningful process status.
- A practical mapping is:
	- `0` → verification passed
	- Non-zero → verification did not satisfy CI enforcement requirements
- The exact mapping should remain consistent with the configured release-gate semantics.

## Report Artifacts

- CI should preserve generated security reports.
- Recommended artifacts include:
	- `security-report.json`
	- `security-report.html`
	- Stored scan result
	- Tool evidence when appropriate
- Reports should be retained according to organizational security-retention requirements.

## Report Reproducibility

- Each report should identify:
	- Application
	- Version
	- Commit SHA
	- Scan ID
	- Environment
	- Profile
	- Tools used
	- Findings
	- Validation results
	- Regression results
	- Policy decision
	- Final release decision
	- Timestamp

## Secrets in CI

- CI credentials must be stored in the CI platform's secret-management system.
- Credentials should never be committed to:
	- YAML files
	- Source code
	- Reports
	- Test fixtures
	- Documentation
- SecureCommerce uses synthetic secrets specifically for controlled testing.

## Least Privilege

- The SecureForge workflow should request only the permissions it needs.
- Example GitHub Actions permission:
	- Repository contents → read
- Additional permissions should be enabled only when the workflow genuinely requires them.

## Failure Handling

- CI should distinguish:
	- Security failure
	- Validation uncertainty
	- Tool execution failure
	- Configuration failure
	- Infrastructure failure
- Error messages should identify the failed stage.
- Security reports should still be uploaded when possible.

## Tool Availability

- External scanners may not be installed on every CI runner.
- SecureForge should fail clearly when a required integration is unavailable.
- Optional integrations can be excluded through the selected profile.

## Fast Feedback

- Pull-request workflows should favor fast controls.
- Recommended order:
	- SAST
	- Secret detection
	- SCA
	- Policy evaluation
- Deeper dynamic or infrastructure testing can run in separate workflows when execution time requires it.

## Deeper Verification

- Full security verification may run:
	- Before release
	- On staging deployments
	- On scheduled intervals
	- Before production deployment
- The full profile can include infrastructure and network verification.

## Manual Security Testing

- Some security evidence remains intentionally manual.
- Burp Suite, Wireshark, and Metasploit can contribute controlled evidence to SecureForge.
- Manual evidence should be normalized into the same finding model as automated evidence.

## Security Boundaries

- CI security testing must remain within authorized scope.
- Do not configure automated CI jobs to attack:
	- Third-party services
	- Uncontrolled infrastructure
	- External production systems
	- Assets without explicit authorization
- Dynamic validation should use dedicated test environments whenever practical.

## Example Workflow

- A practical SecureForge workflow can be:
	- Checkout source
	- Install Python dependencies
	- Install SecureForge
	- Run unit tests
	- Run SecureForge quick profile
	- Start SecureCommerce when application validation is required
	- Run standard/full verification
	- Generate JSON and HTML reports
	- Upload reports as CI artifacts
	- Evaluate release gate
	- Fail the workflow when the configured gate returns `BLOCK`

## Developer Feedback

- CI output should provide concise feedback:
	- Number of findings
	- Validation summary
	- Regression summary
	- Final release status
	- Reason for the decision
- Developers should use the detailed security report for remediation context.

## Practical Principle

- SecureForge should make security verification part of the delivery workflow rather than a separate manual activity.
- The intended model is:
	- Detect early
	- Validate when needed
	- Explain the evidence
	- Enforce policy
	- Prevent regressions
	- Preserve the report
	- Make the release decision explicit
