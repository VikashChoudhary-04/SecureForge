# SecureForge Evidence Handling Methodology

## Purpose

- Security decisions are only as trustworthy as the evidence supporting them.
- SecureForge preserves security evidence throughout the verification lifecycle.
- Evidence is used to:
	- Explain findings
	- Support validation
	- Correlate scanner results
	- Calculate contextual risk
	- Support remediation
	- Verify retesting
	- Detect regressions
	- Justify release decisions

## Evidence Lifecycle

- SecureForge follows this evidence lifecycle:
	- Collect
	- Parse
	- Normalize
	- Sanitize
	- Store
	- Correlate
	- Validate
	- Report
	- Retain according to policy

## Evidence Sources

- Evidence can originate from:
	- SAST
	- SCA
	- Secret detection
	- API security testing
	- DAST
	- Container scanning
	- IaC scanning
	- Nmap
	- Nessus
	- Burp Suite
	- Wireshark
	- Metasploit
	- SecureCommerce validation
	- Manual security testing
	- Regression tests

## Evidence Structure

- A finding can contain evidence describing:
	- Source
	- Description
	- Request
	- Response
	- Command
	- Output
	- Expected behavior
	- Observed behavior
- Evidence should be directly connected to the finding it supports.

## Evidence Quality

- Evidence should be:
	- Relevant
	- Reproducible
	- Specific
	- Traceable
	- Sufficient for the claimed conclusion
- SecureForge should avoid treating weak observations as confirmed vulnerabilities.

## Detection Evidence

- Detection evidence indicates that a security tool observed a potentially problematic condition.
- Examples include:
	- SAST rule match
	- DAST alert
	- Dependency vulnerability
	- Secret pattern match
- Detection evidence does not necessarily prove exploitability.

## Validation Evidence

- Validation evidence demonstrates whether a reported condition can be reproduced.
- Examples include:
	- Controlled HTTP request
	- Controlled API request
	- Expected and observed response
	- Safe command execution
	- Manual tester observation
- Validation evidence should identify the validation method used.

## Retest Evidence

- Retest evidence compares the original security condition with the post-remediation state.
- It should preserve:
	- Finding ID
	- Previous outcome
	- Current outcome
	- Validation method
	- Evidence
	- Timestamp
	- Remediation verification state

## Regression Evidence

- Regression evidence demonstrates whether a previously protected security condition remains protected.
- A regression result should identify:
	- Regression test ID
	- Finding or requirement
	- Expected behavior
	- Observed behavior
	- Result
	- Evidence
	- Execution timestamp

## Sensitive Information

- Security evidence can contain sensitive information.
- Examples include:
	- Session tokens
	- Authorization headers
	- API keys
	- Passwords
	- Cookies
	- Source code
	- Internal hostnames
	- Network addresses
	- Database information
	- Packet contents

## Secret Handling

- Secrets should never be intentionally stored in plaintext evidence.
- When a secret is detected:
	- Preserve the finding context.
	- Redact the secret value.
	- Preserve enough information to identify the issue.
- Example:
	- Secret type → API key
	- Location → `config/settings.py:42`
	- Value → `[REDACTED]`

## Request Sanitization

- HTTP requests may contain sensitive headers.
- Evidence should redact:
	- `Authorization`
	- `Cookie`
	- `Set-Cookie`
	- API-key headers
	- Bearer tokens
- Sanitization should occur before evidence is written to persistent reports.

## Response Sanitization

- Responses may contain:
	- Session data
	- User information
	- Database records
	- Internal configuration
	- Secrets
- SecureForge should avoid storing unnecessary response content.
- When full responses are not required, preserve only the relevant security observation.

## Command Evidence

- Command execution evidence should contain:
	- Executable
	- Sanitized arguments
	- Exit status
	- Relevant output
- Sensitive command-line arguments should be redacted before persistence.

## Network Evidence

- Network evidence may contain sensitive packet information.
- Wireshark captures should be treated as potentially sensitive security artifacts.
- Reports should reference captures rather than embedding unnecessary packet contents.

## Evidence Minimization

- SecureForge should follow data minimization.
- Store enough evidence to support:
	- Finding interpretation
	- Validation
	- Retesting
	- Auditability
- Avoid storing unrelated application data.

## Evidence Provenance

- Every evidence item should identify its source when possible.
- Provenance can include:
	- Tool
	- Integration
	- Scanner version
	- Scan ID
	- Timestamp
	- Target
	- Application version
	- Commit SHA

## Tool Output Preservation

- Native tool output can be preserved when required for troubleshooting or auditability.
- The normalized SecureForge finding remains the primary internal representation.
- Raw output should be stored separately when its size or sensitivity makes direct inclusion inappropriate.

## Normalized Evidence

- Normalized evidence should allow the core engine to operate independently of individual scanner formats.
- The normalization layer should map tool-specific fields into the SecureForge evidence model.

## Evidence Correlation

- Evidence from multiple sources can support the same finding.
- Example:
	- SAST identifies a vulnerable SQL query.
	- DAST identifies suspicious behavior on the endpoint.
	- Burp confirms controlled SQL injection.
- SecureForge should preserve all relevant supporting evidence while maintaining one correlated finding.

## Evidence Confidence

- Evidence should contribute to confidence assessment.
- Stronger evidence may include:
	- Reproducible validation
	- Direct response behavior
	- Multiple independent sources
	- Confirmed security impact
- Weaker evidence may include:
	- Pattern-only detection
	- Incomplete scanner output
	- Configuration assumptions
	- Unverified manual observations

## Evidence and Risk

- Evidence contributes context to risk assessment.
- SecureForge should distinguish:
	- Severity
	- Confidence
	- Exploit evidence
	- Asset context
	- Exposure
- A severe scanner finding without sufficient evidence should not be silently treated as confirmed exploitation.

## Evidence and Policy

- Policy decisions should reference normalized security findings rather than raw scanner output.
- The evidence remains available to explain why a finding reached a particular policy state.

## Evidence and Validation

- Validation can strengthen or weaken the confidence of a finding.
- Example:
	- Initial detection → possible SQL injection
	- Controlled validation → confirmed
	- Finding confidence increases
- A rejected validation should be recorded without deleting the original detection evidence.

## Evidence and Remediation

- Remediation evidence can include:
	- Changed source code
	- Configuration change
	- Dependency upgrade
	- Security-control implementation
	- Deployment version
- Remediation evidence should explain what changed without unnecessarily exposing sensitive source material.

## Evidence and Retesting

- Retesting should preserve both:
	- Original evidence
	- New validation evidence
- This allows SecureForge to demonstrate the transition from:
	- Detected
	- Confirmed
	- Remediated
	- Verified

## Evidence and Regression

- Regression evidence should remain linked to the original finding or security requirement.
- If the same vulnerability returns:
	- Existing identity should be reused when appropriate.
	- New evidence should be attached.
	- The finding lifecycle should record the reopening.

## Evidence Storage

- SecureForge stores scan results and reports in structured formats.
- Recommended formats include:
	- JSON for machine processing
	- HTML for human review
- Evidence storage locations should be controlled and access-restricted.

## Evidence Integrity

- Stored evidence should be associated with:
	- Scan ID
	- Release identifier
	- Commit SHA
	- Timestamp
- Organizations requiring stronger auditability can additionally use:
	- Artifact hashes
	- Signed reports
	- Immutable storage

## Evidence Retention

- Retention should follow organizational security requirements.
- Retention decisions should consider:
	- Compliance
	- Incident-response requirements
	- Debugging needs
	- Sensitive-data exposure
	- Storage cost
- Sensitive evidence should not be retained indefinitely without a justified purpose.

## Evidence Access

- Security evidence should be accessible only to authorized users and systems.
- Access should follow least privilege.
- CI artifacts containing security findings should not automatically be made publicly accessible.

## Evidence in Git

- Raw security evidence should not normally be committed to source control.
- Avoid committing:
	- Credentials
	- Session tokens
	- Production traffic
	- Sensitive packet captures
	- Private vulnerability reports
- Synthetic lab fixtures are acceptable when they contain no real secrets.

## Test Fixtures

- SecureForge uses controlled evidence fixtures for integration tests.
- Fixtures should:
	- Be synthetic
	- Be reproducible
	- Represent realistic scanner structures
	- Avoid real credentials
	- Clearly identify their test purpose

## Mock Evidence

- Mock evidence may be used to test:
	- Normalization
	- Correlation
	- Risk
	- Policy
	- Reporting
	- Release-gate behavior
- Mock evidence must be clearly distinguishable from real scanner evidence.

## Evidence Failure

- If evidence cannot be parsed:
	- Preserve the integration error.
	- Identify the affected tool.
	- Avoid treating malformed output as a clean scan.
- If evidence is incomplete:
	- Preserve the uncertainty.
	- Do not manufacture missing fields.

## Evidence Reporting

- Security reports should provide enough evidence to explain:
	- What was detected
	- Where it was detected
	- Which tool detected it
	- Whether it was validated
	- What the impact is
	- What remediation is recommended
	- Whether remediation was verified
	- Whether regression coverage exists
	- How the release decision was reached

## Practical Principle

- SecureForge treats evidence as a first-class security artifact.
- The objective is not to collect the maximum amount of data.
- The objective is to preserve the minimum sufficient evidence needed to make the security decision:
	- Traceable
	- Reproducible
	- Explainable
	- Safe to handle
	- Useful for remediation
	- Useful for future regression testing
