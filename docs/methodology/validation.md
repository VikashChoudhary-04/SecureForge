# SecureForge Validation Methodology

## Purpose

- SecureForge separates automated detection from security validation.
- A scanner finding represents evidence that a security condition may exist.
- Validation attempts to reproduce the security condition against an authorized target.
- Retesting determines whether a previously confirmed finding was actually remediated.
- Validation evidence is preserved so the final release decision remains explainable.

## Validation Lifecycle

- SecureForge follows this lifecycle:
	- Detection
	- Normalization
	- Correlation
	- Validation
	- Risk evaluation
	- Policy evaluation
	- Release decision
	- Remediation
	- Retesting
	- Regression prevention

## Detection Versus Validation

### Detection

- Detection may come from:
	- SAST
	- SCA
	- Secret scanning
	- API security testing
	- DAST
	- Container scanning
	- IaC scanning
	- Nmap
	- Nessus
	- Burp Suite
	- Wireshark
	- Metasploit
	- Manual security testing

### Validation

- Validation asks whether the reported security condition can be demonstrated against the authorized target.
- Validation may use:
	- HTTP requests
	- API requests
	- Controlled commands
	- Controlled scripts
	- Manual evidence
	- SecureCommerce-specific validation logic

### Important Distinction

- A scanner finding must not automatically be treated as a confirmed vulnerability.
- A validation result may be:
	- `confirmed`
	- `rejected`
	- `inconclusive`
	- `error`

## Validation Outcomes

### Confirmed

- The controlled validation reproduced evidence consistent with the reported security condition.
- A confirmed finding remains actionable.
- The release gate may block the release when the confirmed finding violates configured security controls.

### Rejected

- The controlled validation did not reproduce the reported condition.
- Rejection does not necessarily prove that the application is completely secure.
- It means the specific validation attempt did not confirm the finding.

### Inconclusive

- Available evidence was insufficient to determine whether the finding is valid.
- Examples include:
	- Unexpected application behavior
	- Insufficient response evidence
	- Environment differences
	- Missing authentication context
	- Missing test prerequisites

### Error

- The validation process itself failed.
- Examples include:
	- Target unreachable
	- Connection failure
	- Validator failure
	- Invalid validation configuration
	- Execution timeout

## Validation Methods

### HTTP

- Used for controlled web application validation.
- SecureForge can construct requests using:
	- Target
	- Endpoint
	- Parameter
	- Controlled payload
- HTTP errors are retained as validation evidence instead of being silently discarded.

### API

- Used for REST and API-specific validation.
- API validation can include:
	- HTTP method
	- Endpoint
	- JSON payload
	- Expected status code
	- Controlled headers

### Command

- Used for tightly controlled command-based validation.
- SecureForge applies an executable allowlist.
- Shell operators are rejected by the command validator.
- Commands execute without a shell where possible.
- Only authorized lab or assessment environments should be used.

### Script

- Used when validation requires a dedicated validation script.
- Script execution must be treated as trusted execution.
- Scripts should be reviewed before being enabled in CI or production assessment workflows.

### Manual

- Used when human security testing produces evidence that cannot be safely or reliably automated.
- Manual validation records:
	- Finding ID
	- Outcome
	- Description
	- Evidence
	- Remediation verification state

## SecureCommerce Validation

- SecureCommerce provides controlled validation scenarios for SecureForge development and testing.
- Supported scenarios include:
	- `BOLA-001`
	- `SQLI-001`
	- `XSS-001`
	- `AUTHZ-001`
	- `SECRET-001`
	- `MISCONFIG-001`
	- `SSRF-001`
	- `UPLOAD-001`
	- `PATH-TRAVERSAL-001`

### BOLA Validation

- SecureForge requests a controlled user object.
- The validator evaluates whether the application improperly returns the object without appropriate authorization.
- HTTP `200` may provide confirmation in the intentionally vulnerable lab.
- HTTP `401` or `403` provides evidence that access was rejected.

### SQL Injection Validation

- SecureForge sends a controlled SQL injection test value.
- The validator looks for controlled database-error evidence.
- Database errors are treated as evidence rather than as a universal proof of exploitability.
- A lack of recognizable evidence results in `inconclusive`.

### Reflected XSS Validation

- SecureForge sends a unique controlled marker.
- The validator checks whether the marker is reflected without the expected encoding.
- The controlled marker is used instead of destructive JavaScript.

### Authorization Validation

- SecureForge tests a protected administrative endpoint.
- Successful unauthorized access can confirm the controlled authorization finding.
- Access denial provides evidence that the authorization control is being enforced.

### Synthetic Secret Validation

- SecureCommerce contains a synthetic lab secret.
- SecureForge searches the controlled response for that marker.
- Real credentials must never be used for this scenario.

### SSRF Validation

- SecureForge supplies a controlled internal target to the SSRF-prone lab endpoint.
- The validation target must remain inside the authorized laboratory environment.
- Successful retrieval of the controlled internal resource provides evidence of the SSRF condition.

### File Upload Validation

- SecureForge submits a controlled test file.
- The validator evaluates whether the application accepts the upload without the expected security controls.
- The test file must contain only harmless laboratory content.

### Path Traversal Validation

- SecureForge submits a controlled traversal request against the intentionally vulnerable download functionality.
- Validation looks for evidence that a file outside the intended upload location was returned.
- Only synthetic lab files or source files inside the controlled SecureCommerce environment should be targeted.

## Validation Evidence

- Every validation result should preserve relevant evidence.
- Evidence may include:
	- Validation method
	- Request
	- Response
	- Command
	- Command output
	- Expected behavior
	- Observed behavior
	- Validator name
	- Timestamp

## Authentication Context

- Some vulnerabilities cannot be reliably validated without authentication.
- Examples include:
	- BOLA
	- Broken function-level authorization
	- Privilege-related authorization issues
- SecureForge should not assume that an unauthenticated request proves authorization failure.
- Future validators should support controlled synthetic test identities where authentication is required.

## Retesting

- Retesting occurs after remediation.
- A retest compares the previous validation outcome with the current validation outcome.

### Remediation Verified

- A previously confirmed finding is considered remediation-verified when:
	- The previous outcome was `confirmed`.
	- The current validation outcome is `rejected`.
	- The rejection corresponds to the intended security control.

### Still Confirmed

- If the retest remains `confirmed`, the finding remains unresolved.
- The release gate may block the release according to configured policy.

### Retest Inconclusive

- An inconclusive retest does not prove that remediation succeeded.
- It should be surfaced for security review.

### Retest Error

- A failed retest should not be silently interpreted as remediation.
- The error must remain visible in the security report.

## Regression Prevention

- Confirmed vulnerabilities may become regression tests.
- Regression tests prevent a previously remediated vulnerability from silently returning.
- SecureForge currently defines controlled regression scenarios for:
	- BOLA
	- SQL injection
	- XSS
	- Secret exposure
	- Authorization
	- Security misconfiguration

## Release-Gate Interaction

- Validation is one input into the final release decision.
- The validation gate distinguishes:
	- `passed`
	- `review`
	- `blocked`
	- `error`
- A confirmed validation finding can block the release.
- An inconclusive result requires review rather than being treated as proof of safety.
- A validation error indicates that the verification process did not complete successfully.
- Risk, policy, regression, and validation controls are evaluated together by the release gate.

## Evidence Quality Rules

- Validation must be:
	- Controlled
	- Reproducible
	- Authorized
	- Non-destructive
	- Explainable
	- Relevant to the finding
- SecureForge should prefer a narrowly scoped validation test over a broad exploit.
- Validation should use synthetic credentials, synthetic secrets, and controlled payloads.
- Destructive actions are outside the intended SecureForge validation scope.

## Security Boundaries

- SecureForge must only validate systems for which the operator has explicit authorization.
- The SecureCommerce application is intentionally vulnerable and exists only as a controlled laboratory target.
- Real credentials, production secrets, third-party systems, and unauthorized infrastructure must not be used for SecureForge validation examples.

## Practical Principle

- SecureForge does not attempt to replace specialized security-testing tools.
- Its purpose is to turn security evidence into a defensible verification workflow:
	- Detect
	- Normalize
	- Correlate
	- Validate
	- Prioritize
	- Remediate
	- Retest
	- Gate
	- Prevent recurrence
