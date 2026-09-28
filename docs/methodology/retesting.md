# SecureForge Retesting Methodology

## Purpose

- Retesting determines whether a previously identified security finding remains present after remediation.
- Retesting is different from running the original scan again.
- A retest uses the original finding context and a controlled validation method to determine whether the security condition still exists.
- The objective is to produce evidence for one of three practical outcomes:
	- Remediation verified
	- Finding still present
	- Verification inconclusive

## Retesting Lifecycle

- SecureForge follows this workflow:
	- Finding identified
	- Finding validated
	- Remediation implemented
	- Retest requested
	- Validation executed again
	- Previous and current outcomes compared
	- Remediation status determined
	- Regression coverage evaluated
	- Release decision updated

## Previous State

- A retest requires a known previous validation outcome.
- The previous outcome provides the baseline for comparison.
- The most important baseline is a previously `confirmed` finding.
- A finding that was never confirmed should not automatically be treated as remediated merely because a later scan produces no evidence.

## Retest Request

- A retest uses the original validation context where possible.
- Relevant information includes:
	- Finding ID
	- Target
	- Validation method
	- Endpoint
	- Parameter
	- Controlled payload
	- Validator
	- Required metadata

## Retest Outcomes

### Remediated

- A previously confirmed finding is considered remediated when the new validation rejects the security condition.
- The remediation result must be supported by validation evidence.
- SecureForge marks the finding as verified after remediation is confirmed.

### Still Confirmed

- The current validation still confirms the finding.
- The finding remains unresolved.
- The finding may continue to block the release according to configured policy.

### Inconclusive

- The retest did not provide enough evidence to determine whether remediation succeeded.
- Examples include:
	- Target unavailable
	- Application behavior changed unexpectedly
	- Required authentication unavailable
	- Validation evidence insufficient

### Error

- The retest process itself failed.
- An error must not be interpreted as successful remediation.

## Remediation Verification

- SecureForge uses the following controlled rule:
	- Previous outcome = `confirmed`
	- Current outcome = `rejected`
	- Result = remediation verified
- The verification state is recorded separately from the raw validation outcome.
- This distinction prevents the system from confusing "the test rejected the finding" with "the original finding was definitely fixed."

## Example

- Initial validation:
	- Finding: `SQLI-001`
	- Outcome: `confirmed`
	- Evidence: controlled SQL injection behavior
- Remediation:
	- Parameterized database query implemented
- Retest:
	- Finding: `SQLI-001`
	- Outcome: `rejected`
- Result:
	- Remediation verified
	- Finding no longer confirmed
	- Regression coverage should be retained

## Retest Evidence

- Each retest should preserve:
	- Finding ID
	- Previous outcome
	- Current outcome
	- Validation request
	- Validation evidence
	- Validator
	- Timestamp
	- Remediation verification state

## Finding Lifecycle

- A SecureForge finding can move through these states:
	- Open
	- Validated
	- Remediated
	- Verified
	- Reopened

### Open

- The finding has been detected but has not necessarily been validated.

### Validated

- Controlled validation has confirmed the reported security condition.

### Remediated

- The application has been changed in response to the confirmed finding.

### Verified

- Retesting has provided evidence that the original security condition is no longer present.

### Reopened

- A previously verified finding becomes confirmed again.
- Reopening is important for detecting security regressions.

## Retesting Versus Rescanning

### Retesting

- Focuses on a specific previously identified finding.
- Reuses the finding's validation context.
- Answers:
	- "Did this remediation remove the reported security condition?"

### Rescanning

- Runs the broader security verification pipeline again.
- May discover:
	- The original finding
	- New findings
	- Related findings
	- Regression findings
- Answers:
	- "What is the security state of this release now?"

## Regression Testing

- A remediated finding should become a regression candidate when the vulnerability can be expressed as a repeatable security test.
- Regression testing protects against reintroduction of the same defect.

## Regression Candidate Criteria

- A finding is a good regression candidate when:
	- The validation is deterministic.
	- The test is reproducible.
	- The test is safe.
	- The expected secure behavior is clear.
	- The test does not require destructive actions.
- Examples include:
	- BOLA authorization check
	- SQL injection rejection
	- XSS output encoding
	- Secret exposure detection
	- Authorization enforcement
	- Security configuration checks

## Regression Failure

- A regression test fails when a previously protected security condition becomes vulnerable again.
- A regression failure should:
	- Identify the regression test.
	- Preserve the evidence.
	- Associate the failure with the relevant security requirement.
	- Feed into the release-gate decision.

## Release-Gate Interaction

- Retesting produces evidence.
- The release gate evaluates that evidence together with:
	- Risk
	- Security policy
	- Regression results
	- Other configured verification controls
- A still-confirmed security finding can block release.
- An inconclusive retest requires review.
- A retest error must remain visible and must not be interpreted as remediation.

## Reopening

- A verified finding can be reopened if later validation confirms the vulnerability again.
- Reopening preserves the historical lifecycle instead of creating an unrelated duplicate finding.
- The finding should retain:
	- Original identity
	- Previous validation history
	- Remediation history
	- Retest history
	- Regression history

## Practical Retesting Workflow

- For each confirmed finding:
	- Record the remediation.
	- Reuse the controlled validation method.
	- Execute the retest.
	- Compare previous and current outcomes.
	- Mark remediation verified when supported by evidence.
	- Create or retain regression coverage.
	- Include the result in the security report.
	- Re-evaluate the release gate.

## Security Principles

- Retesting must be:
	- Authorized
	- Controlled
	- Reproducible
	- Non-destructive
	- Evidence-driven
- A failed validation attempt is not proof that a vulnerability was fixed.
- Absence of evidence is not automatically evidence of absence.
- SecureForge should preserve uncertainty instead of converting it into a false pass.

## Practical Principle

- The SecureForge remediation lifecycle is:
	- Detect
	- Validate
	- Remediate
	- Retest
	- Verify
	- Regression-test
	- Gate
	- Monitor for recurrence
