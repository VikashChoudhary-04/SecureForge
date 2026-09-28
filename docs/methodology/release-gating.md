# SecureForge Release-Gating Methodology

## Purpose

- SecureForge converts security verification evidence into an explicit release decision.
- The release gate answers:
	- Can this application release under the configured security policy?
- The decision is based on evidence produced during the security verification pipeline.
- SecureForge does not replace organizational risk acceptance or security governance.
- The configured gate provides a repeatable technical control that can be enforced locally or in CI/CD.

## Release Decisions

- SecureForge uses three primary release states:
	- `PASS`
	- `REVIEW`
	- `BLOCK`

### PASS

- `PASS` means the configured release controls completed without a condition that requires blocking or review.
- A pass does not mean the application is universally secure.
- It means the application satisfied the configured SecureForge release criteria for that verification run.

### REVIEW

- `REVIEW` means available evidence is insufficient for an automatic pass or block.
- Review conditions may include:
	- Inconclusive validation
	- Validation errors
	- Regression-test uncertainty
	- Configured security exceptions requiring review
	- Other explicitly configured verification conditions
- A review requires a human security decision before release.

### BLOCK

- `BLOCK` means a configured security control has identified a condition that prevents automatic release.
- Examples include:
	- Confirmed high-severity security finding
	- Confirmed critical security finding
	- Failed required regression test
	- Explicit policy violation
	- Confirmed validation finding that violates the release policy

## Release-Gate Inputs

- The final release decision considers:
	- Security findings
	- Correlated evidence
	- Risk assessment
	- Security policy
	- Validation results
	- Validation gate
	- Regression results
	- Regression gate
	- Configured exceptions
	- Release metadata

## Pipeline

- SecureForge follows this decision flow:
	- Scan
	- Normalize
	- Correlate
	- Assess risk
	- Evaluate policy
	- Validate selected findings
	- Run regression tests
	- Evaluate release controls
	- Produce final decision
	- Generate evidence report

## Findings

- Findings are normalized into the SecureForge finding model.
- A finding may include:
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
	- Evidence
	- Remediation
	- Validation status
	- Regression test

## Evidence Correlation

- Multiple tools may identify the same underlying issue.
- SecureForge correlates related evidence before evaluating the final security state.
- Example:
	- SAST reports possible SQL injection.
	- DAST reports possible SQL injection.
	- Burp validation confirms SQL injection.
- The evidence should be represented as one correlated security condition with multiple supporting sources rather than unrelated duplicate findings.

## Risk Evaluation

- Risk evaluation provides contextual prioritization.
- Inputs may include:
	- Severity
	- Confidence
	- Asset importance
	- Internet exposure
	- Authentication requirements
	- Sensitive-data exposure
	- Exploit evidence
	- Security requirement
	- Environment

## Risk Versus Policy

- Risk and policy are separate concepts.
- Risk answers:
	- How significant is the security condition in its current context?
- Policy answers:
	- What conditions does the organization require before release?
- A policy can require blocking a finding even when its calculated risk is below another threshold.
- A risk engine should not silently override an explicit release policy.

## Validation Gate

- Validation determines whether selected findings can be reproduced.
- Validation produces:
	- `confirmed`
	- `rejected`
	- `inconclusive`
	- `error`

### Confirmed Validation

- A confirmed validation finding can produce a `BLOCK`.
- The final release gate still evaluates the configured release policy.
- Confirmation should preserve the supporting request and response evidence.

### Rejected Validation

- A rejected validation result indicates that the specific controlled validation did not reproduce the condition.
- It does not automatically prove that the application has no related vulnerability.

### Inconclusive Validation

- An inconclusive result produces `REVIEW`.
- SecureForge should not silently convert uncertainty into `PASS`.

### Validation Error

- A validation error produces `REVIEW` unless another configured control independently requires a block.
- The error must remain visible in the report.

## Regression Gate

- Regression testing verifies that previously remediated security conditions do not return.
- A failed regression test can produce `BLOCK`.
- A skipped or inconclusive regression test can produce `REVIEW` when the configured control requires human verification.

## Policy Gate

- The policy engine evaluates findings against configured release rules.
- Example policy:
	- Critical → block
	- High → block
	- Medium → review
	- Low → pass

## Exceptions

- Exceptions must be explicit.
- An exception should record:
	- Finding ID
	- Reason
	- Owner
	- Approval context
	- Expiration
	- Scope
- Exceptions should never silently remove the underlying security evidence.

## Decision Precedence

- SecureForge should evaluate blocking conditions before passing a release.
- A practical precedence model is:
	- Confirmed blocking security condition → `BLOCK`
	- Required regression failure → `BLOCK`
	- Explicit policy violation → `BLOCK`
	- Unresolved verification uncertainty → `REVIEW`
	- Validation or regression error → `REVIEW`
	- No blocking or review condition → `PASS`

## Final Decision

- The release decision should contain:
	- Final status
	- Release allowed state
	- Reason
	- Relevant control
	- Release metadata
	- Scan identifier
	- Application version
	- Commit SHA when available
	- Environment
	- Timestamp

## CI/CD Behavior

- SecureForge can be executed from GitHub Actions or another CI environment.
- A typical workflow is:
	- Pull request created
	- SecureForge starts
	- Security evidence collected
	- Findings normalized
	- Risk calculated
	- Policy evaluated
	- Validation performed
	- Regression tests executed
	- Release gate evaluated
	- Reports generated
	- CI job succeeds or fails according to the configured release result

## CI Enforcement

- `PASS` can allow the pipeline to continue.
- `BLOCK` should cause the security job to fail when release enforcement is enabled.
- `REVIEW` should require an explicit human review workflow when the organization treats review as a release dependency.

## Report Requirements

- Every release decision should be reproducible from its report.
- The security report should contain:
	- Release metadata
	- Scan metadata
	- Findings
	- Risk
	- Policy
	- Validation
	- Validation results
	- Validation gate
	- Remediation
	- Regression results
	- Regression gate
	- Final decision
	- Generation timestamp

## Example Decision

- Example:
	- Finding: `BOLA-001`
	- Severity: High
	- Validation: Confirmed
	- Policy: High severity blocks
	- Regression: Not applicable
	- Final decision: `BLOCK`
- The report should contain enough evidence to explain why the decision was produced.

## Another Example

- Example:
	- Finding: `SQLI-001`
	- Scanner evidence: Possible SQL injection
	- Validation: Inconclusive
	- Policy: No independent blocking condition
	- Final decision: `REVIEW`
- The correct result is review rather than treating the inconclusive validation as either proof of vulnerability or proof of safety.

## Clean Release Example

- Example:
	- Findings: No policy-blocking findings
	- Validation: Passed
	- Regression: Passed
	- Policy: Passed
	- Risk: Within configured threshold
	- Final decision: `PASS`

## Security Boundary

- A SecureForge `PASS` is not a universal security certification.
- It is a decision against the configured:
	- Scope
	- Tools
	- Profiles
	- Security requirements
	- Policies
	- Validation coverage
	- Regression coverage
	- Environment
- Missing coverage must remain visible.

## Practical Principle

- SecureForge turns security testing into a controlled release decision:
	- Evidence
	- Correlation
	- Context
	- Validation
	- Risk
	- Policy
	- Regression
	- Decision
	- Evidence report
- The goal is not to claim that an application is perfectly secure.
- The goal is to make the security decision repeatable, explainable, and enforceable.
