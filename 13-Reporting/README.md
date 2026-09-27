# 📊 SecureForge Reporting

* This directory defines how SecureForge converts security evidence and release-gate results into reproducible, traceable, and actionable security reports.
* Reporting is the final evidence layer connecting security analysis to developers, security engineers, reviewers, and CI/CD systems.
* A report should explain not only **what was found**, but also **why the release received its decision**.

## Purpose

* SecureForge reporting should answer:

  * What application was evaluated?
  * What version or commit was evaluated?
  * Which security checks ran?
  * What evidence was collected?
  * Which findings were identified?
  * Which findings were validated?
  * How were findings correlated?
  * How was risk evaluated?
  * Which policy was applied?
  * Were there exceptions?
  * Which regression tests ran?
  * What remediation remains?
  * Why was the final release decision made?

## Reporting Philosophy

* Reports should be:

  * Evidence-based
  * Reproducible
  * Traceable
  * Human-readable
  * Machine-readable
  * Actionable
  * Deterministic
  * Security-focused

* Reporting should not:

  * Invent security results.
  * Hide failed tools.
  * Hide unresolved findings.
  * Present missing evidence as successful evidence.
  * Claim complete security assurance.
  * Replace the underlying security evidence.

## Reporting Flow

```text id="k7r3wp"
Security Evidence
       ↓
Normalized Findings
       ↓
Correlation
       ↓
Risk Evaluation
       ↓
Policy Evaluation
       ↓
Remediation Status
       ↓
Regression Results
       ↓
Release Decision
       ↓
Security Report
```

## Report Types

* SecureForge should initially support:

  * JSON report
  * HTML report
  * CI/CD summary
  * Console summary

* JSON should be the canonical machine-readable representation.

* HTML should provide a human-readable security report.

* CI/CD output should provide concise release-gate information.

* Console output should provide immediate feedback during local execution.

## Report Identity

* Every report should have a unique report identifier.

* Example:

```text id="z4v8km"
Report ID:
SF-REPORT-2026-0007

Application:
SecureCommerce

Release:
v1.4.0

Commit:
a91f3e2
```

* The identifier allows a report to be referenced independently from the execution that generated it.

## Report Metadata

* A report should contain metadata such as:

  * Report ID
  * Application name
  * Application version
  * Release identifier
  * Commit SHA
  * Branch
  * Environment
  * SecureForge version
  * Scan profile
  * Execution timestamp
  * Duration
  * Tool versions
  * Report schema version

## Example Metadata

```json
{
  "report_id": "SF-REPORT-2026-0007",
  "application": "SecureCommerce",
  "version": "1.4.0",
  "commit_sha": "a91f3e2",
  "environment": "staging",
  "profile": "standard",
  "secureforge_version": "0.1.0"
}
```

## Execution Summary

* The report should summarize what SecureForge actually executed.

* Example:

```text id="f3w8qk"
Profile:
standard

Checks:
SAST
SCA
Secret Detection
API Security
DAST
Container Security

Completed:
6

Failed:
0
```

* A skipped or failed integration should be explicitly identified.

## Tool Inventory

* Reports should identify the tools that contributed evidence.

* Example:

```text id="b6m2xs"
Tool
├── SAST
├── SCA
├── Secret Scanner
├── API Scanner
├── DAST
└── Container Scanner
```

* Tool versions should be included when available.

## Finding Summary

* The report should provide a concise finding summary.

* Example:

```text id="v5p9qt"
Critical: 0
High:     2
Medium:   3
Low:      4
Info:     2
```

* These counts should represent the findings actually included in the report.

## Finding Details

* Every important finding should include enough information to understand the issue.

* Suggested fields:

  * Finding ID
  * Title
  * Source
  * Asset
  * Endpoint
  * Parameter
  * Severity
  * Confidence
  * CWE
  * OWASP mapping
  * Security requirement
  * Description
  * Impact
  * Evidence
  * Remediation
  * Validation status
  * Regression test
  * First seen
  * Last seen
  * Current status

## Example Finding

```json
{
  "finding_id": "SF-0012",
  "title": "Broken Object Level Authorization",
  "severity": "high",
  "confidence": "confirmed",
  "cwe": "CWE-639",
  "owasp": "API1",
  "requirement": "SF-AUTHZ-001",
  "validation_status": "validated",
  "regression_test": "BOLA-001"
}
```

## Evidence Section

* Reports should preserve a traceable summary of the evidence supporting each important finding.

* Evidence may include:

  * Tool output
  * HTTP request
  * HTTP response
  * Source location
  * Scanner identifier
  * Manual validation notes
  * Test result
  * Packet-analysis observation
  * Infrastructure result

* Sensitive information should be redacted where appropriate.

## Evidence Traceability

* Every finding should be traceable back to its source.

```text id="m9q4yc"
Finding SF-0012
       ↓
Evidence E-0048
       ↓
Burp Validation
       ↓
Request / Response
       ↓
BOLA-001
```

* This provides an evidence chain for security decisions.

## Correlation Summary

* Reports should explain when multiple sources were correlated.

* Example:

```text id="s8k2rd"
SAST
  ↓
Possible SQLi
  \
   → Correlated Finding SF-0021
  /
DAST
  ↓
Possible SQLi
```

* The report should preserve the individual sources rather than hiding them behind the correlated finding.

## Risk Summary

* Reports should explain the contextual risk assigned to findings.

* Example:

```text id="n4j7vz"
Finding:
BOLA

Severity:
High

Confidence:
Confirmed

Internet Exposure:
Yes

Sensitive Data:
Yes

Contextual Risk:
High
```

* The report should provide enough information to understand the risk decision.

## Policy Summary

* Reports should identify the policy that produced the release decision.

* Example:

```yaml id="2w7hpn"
policy:
  critical:
    action: block
  high:
    action: block
  medium:
    action: review
  low:
    action: pass
```

* The report should include the relevant policy version or configuration identifier where available.

## Release Decision

* Every completed report should contain a final release decision.

* Supported decisions:

  * `PASS`
  * `REVIEW`
  * `BLOCK`

* Example:

```text id="x2f8ka"
Security Evaluation
        ↓
Policy Evaluation
        ↓
      BLOCK
```

## Decision Explanation

* The report should explain why the decision occurred.

* Example:

```text id="p6w4qn"
Decision:
BLOCK

Reason:
1 validated high-risk authorization finding
1 failed security regression test
```

* The explanation should be generated from actual evaluation results.

## PASS Report

* A `PASS` report should not claim that the application contains no vulnerabilities.

* It should state that the configured security gate requirements were satisfied for the evaluated scope.

* Example:

```text id="y3k8ms"
Decision:
PASS

Meaning:
No configured blocking conditions were triggered
for the evaluated scope and profile.
```

## REVIEW Report

* A `REVIEW` report should identify the conditions requiring human attention.

* Example:

```text id="r5q2vx"
Decision:
REVIEW

Reason:
Medium-risk finding requires security review.
```

## BLOCK Report

* A `BLOCK` report should clearly identify the conditions preventing release.

* Example:

```text id="c7n4jw"
Decision:
BLOCK

Blocking Conditions:
- Confirmed high-risk authorization finding
- Failed security regression test
```

## Remediation Summary

* Reports should show the current remediation state of important findings.

* Suggested statuses:

  * `open`
  * `in_progress`
  * `remediated`
  * `verified`
  * `reopened`
  * `accepted`

* Example:

```text id="u4m8zs"
SF-0012
Remediation:
verified

SF-0021
Remediation:
in_progress

SF-0031
Remediation:
open
```

## Retesting Summary

* Reports should identify which findings were retested.

* Example:

```text id="q6v2hp"
Finding:
SF-0012

Retest:
PASSED

Expected:
Unauthorized access denied

Actual:
403 Forbidden
```

## Regression Summary

* Reports should summarize security regression tests.

* Example:

```text id="a8j3lx"
Regression Tests:
12 total

Passed:
11

Failed:
1
```

* Failed regression tests should link back to the affected finding or requirement when possible.

## Security Requirement Coverage

* Reports should show which security requirements were evaluated.

* Example:

```text id="e5m7rc"
SF-AUTH-001
✓

SF-AUTHZ-001
✓

SF-API-001
✓

SF-SECRET-001
✓
```

* Coverage should represent evaluated requirements, not a claim of complete application security compliance.

## Exceptions

* If a policy exception exists, the report should record:

  * Exception ID
  * Affected finding
  * Reason
  * Scope
  * Approver where applicable
  * Expiration
  * Compensating control
  * Policy effect

* Example:

```yaml id="j7s3qd"
exception:
  id: EX-001
  finding: SF-0042
  expires: 2026-10-15
  reason: "Temporary remediation window"
```

* Expired exceptions should not silently remain effective.

## Environment Information

* Security results may depend on the evaluated environment.

* Reports should identify:

  * Development
  * Test
  * Staging
  * Production-like lab

* Environment context should be preserved because the same finding may have different exposure characteristics across environments.

## Reproducibility

* Reports should contain enough information to reproduce the evaluation where practical.

* Useful information includes:

  * Commit SHA
  * Application version
  * SecureForge version
  * Profile
  * Policy version
  * Tool versions
  * Target environment
  * Configuration identifier
  * Timestamp

## Report Schema Versioning

* Machine-readable reports should have a schema version.

* Example:

```json
{
  "schema_version": "1.0"
}
```

* Schema changes should be deliberate and documented.

## JSON Report Structure

* A conceptual report structure may look like:

```text
SecurityReport
├── metadata
├── execution
├── tools
├── requirements
├── findings
├── evidence
├── risk
├── policy
├── remediation
├── retesting
├── regression
├── exceptions
└── decision
```

## Example JSON Structure

```json
{
  "schema_version": "1.0",
  "metadata": {},
  "execution": {},
  "tools": [],
  "requirements": [],
  "findings": [],
  "evidence": [],
  "risk": {},
  "policy": {},
  "remediation": {},
  "retesting": {},
  "regression": {},
  "exceptions": [],
  "decision": {}
}
```

## HTML Report Structure

* The HTML report should prioritize human readability.

* Suggested sections:

  * Executive summary
  * Release decision
  * Finding summary
  * Blocking conditions
  * Findings
  * Evidence
  * Risk
  * Policy
  * Remediation
  * Retesting
  * Regression
  * Security requirements
  * Exceptions
  * Tool execution
  * Reproduction information

## Executive Summary

* The executive summary should answer:

  * What was tested?
  * What profile was used?
  * What was found?
  * What is the current release decision?
  * What requires attention?

* It should remain factual and concise.

## Developer-Focused Output

* Developers often need a shorter representation.

* Example:

```text id="v7c2km"
SecureForge Release Gate: BLOCK

Application:
SecureCommerce

Blocking Findings:
- SF-0012 — Broken Object Level Authorization
- SF-0021 — SQL Injection

Failed Regression Tests:
- BOLA-001

Next Action:
Review remediation details and rerun security verification.
```

## CI/CD Output

* CI/CD output should be concise and machine-readable where practical.

* Example:

```text id="s4h8qy"
SecureForge
Decision: BLOCK
Findings: 7
Blocking: 2
Regression failures: 1
Report: reports/security-report.json
```

* The CI job should use the release decision to determine its exit status.

## Report Exit Status

* The CLI may map decisions to process exit codes.

* Example:

```text id="x9k3fw"
PASS
  ↓
Exit 0

REVIEW
  ↓
Configured policy exit code

BLOCK
  ↓
Non-zero exit
```

* The exact mapping should be configurable and documented.

## Sensitive Data Handling

* Reports may contain sensitive security information.
* SecureForge should:

  * Redact secrets.
  * Avoid storing real credentials.
  * Sanitize authentication tokens.
  * Limit unnecessary request/response data.
  * Protect generated reports.
  * Clearly identify test credentials.

## Report Integrity

* Reports should not be modified silently after generation.

* Where practical, SecureForge may record:

  * Generation timestamp
  * Report hash
  * SecureForge version
  * Commit SHA

* These mechanisms improve confidence that the report corresponds to the evaluated execution.

## Report Storage

* Default generated reports should be stored under:

```text
reports/
├── security-report.json
└── security-report.html
```

* Historical storage can be added later if required.
* The initial implementation should remain simple and local-first.

## Reporting Errors

* Reporting failures should be distinguishable from security failures.

* Example:

```text id="n6v4zr"
Security Evaluation:
Completed

Release Decision:
BLOCK

Report Generation:
FAILED
```

* A failed report writer should not rewrite the underlying security result.

## Reporting Tests

* Reporting should be tested for:

  * Valid report generation
  * Empty findings
  * Multiple findings
  * Blocking findings
  * Review conditions
  * Passing evaluation
  * Regression failures
  * Exceptions
  * Sensitive-data redaction
  * JSON schema validity
  * HTML generation
  * Missing optional fields

## Deterministic Reports

* Identical inputs and configuration should produce logically equivalent reports.
* Dynamic fields such as timestamps should be handled explicitly.
* Ordering should be deterministic where practical.

## Reporting Metrics

* Useful reporting metrics include:

  * Reports generated
  * Reports by decision
  * Findings per report
  * Blocking findings
  * Review findings
  * Regression failures
  * Tool execution failures
  * Report generation failures

* These metrics describe SecureForge operation rather than application security as a whole.

## Suggested Implementation Structure

```text id="r2m7vx"
reporting/
├── __init__.py
├── models.py
├── json_report.py
├── html_report.py
├── summary.py
├── redaction.py
├── schema.py
└── tests/
    ├── test_json_report.py
    ├── test_html_report.py
    ├── test_redaction.py
    └── test_schema.py
```

* The exact structure may evolve during implementation.

## Reporting Contract

* The reporting layer should receive finalized evaluation data rather than independently recomputing security decisions.

```text id="c4w9ms"
Findings
   +
Evidence
   +
Risk
   +
Policy Result
   +
Remediation
   +
Regression
   ↓
Reporting
   ↓
JSON / HTML / CI Summary
```

## Design Principles

* SecureForge reporting should:

  * Explain the release decision.
  * Preserve evidence traceability.
  * Distinguish security failure from tool failure.
  * Preserve source information.
  * Avoid unsupported security claims.
  * Protect sensitive information.
  * Produce machine-readable output.
  * Produce human-readable output.
  * Support reproducibility.
  * Remain deterministic where practical.

## What Comes Next

* The next component is **CLI**.
* The CLI will provide the practical interface through which users execute SecureForge.
* It will connect the implemented core components into commands such as:

  * `secureforge scan`
  * `secureforge report`
  * `secureforge policy check`
  * `secureforge regression`
  * `secureforge validate`
* This begins the transition from SecureForge's architectural specification into an executable developer and security-engineering workflow.
