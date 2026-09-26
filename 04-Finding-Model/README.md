# 🧩 SecureForge Finding Model

## 🎯 Purpose

* The finding model defines how SecureForge represents security issues consistently across different security tools and validation methods.
* Security tools produce different formats, terminology, severity models, identifiers, and evidence.
* SecureForge needs a common representation so that findings can be:

  * Normalized.
  * Correlated.
  * Validated.
  * Prioritized.
  * Mapped to requirements.
  * Evaluated by policy.
  * Reported.
  * Converted into regression tests.

## 🧠 Finding Model Philosophy

* A finding is not simply a scanner message.

* A finding is a structured security record that connects evidence to a security interpretation.

* The model should preserve both:

  * What a security tool reported.
  * What SecureForge knows about the issue after normalization and validation.

* The model should avoid losing important source information during normalization.

* Original evidence should remain traceable to the normalized finding.

## 🔗 Finding Lifecycle

* A finding can move through several states:

```text id="7q1vfd"
Evidence
   ↓
Detected
   ↓
Normalized
   ↓
Correlated
   ↓
Validated
   ↓
Prioritized
   ↓
Policy Evaluated
   ↓
Remediation
   ↓
Retested
   ↓
Regression Protected
```

* Not every finding must pass through every state.
* For example:

  * A low-confidence informational finding may never require manual validation.
  * A critical authorization finding may require explicit validation before a release decision.

## 🆔 Finding Identity

* Every normalized finding should have a stable identifier.

* Example:

  * `SF-0012`

* The identifier should allow SecureForge to reference the finding across:

  * Reports.
  * Policy decisions.
  * Remediation.
  * Retesting.
  * Regression tests.
  * Historical releases.

* Finding identity should not depend only on a scanner-specific identifier.

## 📋 Core Finding Fields

### Finding ID

* Unique SecureForge identifier.
* Example:

  * `SF-0012`

### Title

* Short description of the security issue.
* Example:

  * `BOLA on GET /api/orders/{id}`

### Source

* Identifies where the evidence originated.
* Examples:

  * SAST
  * SCA
  * DAST
  * Secret Scanner
  * API Scanner
  * Nessus
  * Nmap
  * Burp Suite
  * Wireshark
  * Metasploit
  * Manual

### Asset

* Identifies the affected asset.
* Examples:

  * Web application.
  * API.
  * Container.
  * Database.
  * Host.
  * Infrastructure resource.

### Application

* Identifies the application associated with the finding.
* Example:

  * `SecureCommerce`

### Endpoint

* Identifies the affected application or API endpoint when applicable.
* Example:

  * `GET /api/orders/{id}`

### Parameter

* Identifies the affected input parameter when applicable.
* Example:

  * `id`

### CWE

* Identifies the relevant Common Weakness Enumeration classification.
* Example:

  * `CWE-639`

### OWASP Mapping

* Identifies the relevant OWASP category.
* Example:

  * `API1`

### Security Requirement

* Identifies the internal SecureForge security requirement affected by the finding.
* Example:

  * `SF-AUTHZ-001`

### Severity

* Represents the inherent seriousness of the issue.
* Example values:

  * `Critical`
  * `High`
  * `Medium`
  * `Low`
  * `Informational`

### Confidence

* Represents how strongly the available evidence supports the finding.
* Example values:

  * `Low`
  * `Medium`
  * `High`
  * `Confirmed`

### Evidence

* Contains the information supporting the finding.
* Evidence may include:

  * Scanner output.
  * HTTP request.
  * HTTP response.
  * Source-code location.
  * Dependency information.
  * Network observation.
  * Screenshot.
  * Manual validation result.
  * Tool output.

### Description

* Explains what the finding represents.
* The description should be understandable without requiring the reader to inspect the original scanner output.

### Impact

* Explains what could happen if the issue remains unresolved.
* Impact should be based on the actual affected asset and evidence.

### Remediation

* Provides actionable guidance for addressing the underlying security weakness.

### Status

* Represents the current lifecycle state of the finding.
* Example values:

  * `Open`
  * `In Progress`
  * `Remediated`
  * `Closed`
  * `Accepted`
  * `False Positive`

### Validation Status

* Represents whether the finding has been validated.
* Example values:

  * `Not Tested`
  * `Suspected`
  * `Confirmed`
  * `False Positive`
  * `Retested`

### First Seen

* Timestamp representing when the finding was first observed.

### Last Seen

* Timestamp representing the most recent observation of the finding.

### Regression Test

* Identifies the regression test associated with the finding.
* Example:

  * `BOLA-001`

## 🧾 Example Finding

```yaml
finding_id: SF-0012
title: BOLA on GET /api/orders/{id}
source:
  - DAST
  - Burp Suite
asset: SecureCommerce API
application: SecureCommerce
endpoint: GET /api/orders/{id}
parameter: id
cwe: CWE-639
owasp: API1
security_requirement: SF-AUTHZ-001
severity: High
confidence: Confirmed
status: Open
validation_status: Confirmed
first_seen: 2026-09-26T10:00:00Z
last_seen: 2026-09-26T10:15:00Z
regression_test: BOLA-001
```

## 🔍 Evidence Structure

* Evidence should be stored separately from the finding interpretation where practical.
* This allows SecureForge to preserve the original observation while maintaining a normalized security record.

### Example

```yaml
evidence:
  source: Burp Suite
  type: http_exchange
  request: |
    GET /api/orders/42 HTTP/1.1
    Authorization: Bearer <test-token>
  response: |
    HTTP/1.1 200 OK
  observation: User A accessed User B's order
```

* Sensitive values should be sanitized or redacted before being stored in reports.
* Real credentials should never be committed to the repository.

## 🔄 Source Preservation

* Normalization should not destroy source-specific information.

* SecureForge should preserve:

  * Original source.
  * Original finding identifier.
  * Original severity.
  * Original message.
  * Original evidence.
  * Tool version where available.
  * Scan timestamp where available.

* This allows a normalized finding to be traced back to its original source.

## 🧩 Source-Specific Identifiers

* Different tools may use their own identifiers.

* Examples:

  * CWE identifiers.
  * CVE identifiers.
  * Scanner plugin IDs.
  * Rule IDs.
  * Tool-specific finding IDs.

* SecureForge should preserve these identifiers without making them the primary SecureForge finding identity.

## 🔗 Correlation Identity

* Findings from different sources may represent the same vulnerability.

* SecureForge should use meaningful attributes when determining whether findings can be correlated.

* Possible correlation attributes include:

  * Application.
  * Asset.
  * Endpoint.
  * Parameter.
  * Vulnerability type.
  * CWE.
  * Affected component.
  * Evidence similarity.
  * Source-code location.

* Correlation should not rely on a single field when that could incorrectly merge unrelated vulnerabilities.

## ⚖️ Severity and Confidence

* Severity and confidence represent different concepts.

### Severity

* Answers:

  * **How serious is the vulnerability if it exists?**

### Confidence

* Answers:

  * **How strongly does the evidence support that the vulnerability exists?**

* Example:

  * A scanner may report a `Critical` SQL injection with `Low` confidence.
  * Manual validation may later change confidence to `Confirmed`.

* SecureForge should preserve this distinction.

## 🧠 Finding State vs. Validation State

* Finding lifecycle state and validation state should not be treated as the same thing.

### Finding State

* Describes what is happening with the issue.
* Examples:

  * `Open`
  * `In Progress`
  * `Remediated`
  * `Closed`

### Validation State

* Describes the evidence confidence regarding the vulnerability.

* Examples:

  * `Not Tested`
  * `Suspected`
  * `Confirmed`
  * `False Positive`
  * `Retested`

* This distinction allows SecureForge to represent situations such as:

  * `Open + Confirmed`
  * `Open + Suspected`
  * `Remediated + Confirmed`
  * `Closed + False Positive`

## 🛡️ Security Requirement Mapping

* A finding should map to a security requirement when the relationship is known.
* Example:

```text id="5g8f4k"
Finding
   ↓
BOLA
   ↓
CWE-639
   ↓
OWASP API1
   ↓
SF-AUTHZ-001
```

* This mapping allows SecureForge to determine not only that a vulnerability exists, but which expected security control has failed.

## 🧪 Validation Information

* A validated finding should contain enough information to explain how validation occurred.
* Validation data can include:

  * Validator.
  * Validation method.
  * Test accounts used.
  * Request.
  * Response.
  * Expected result.
  * Actual result.
  * Validation timestamp.
  * Validation conclusion.

### Example

```yaml
validation:
  status: confirmed
  method: controlled_cross_user_access
  expected: User A cannot access User B's order
  actual: User A received User B's order
  conclusion: BOLA confirmed
```

## 🔧 Remediation Information

* Remediation should describe how the underlying weakness should be fixed.
* Example:

  * Vulnerability:

    * BOLA.
  * Weakness:

    * Server trusts the object identifier without verifying ownership.
  * Remediation:

    * Perform server-side authorization checks against the authenticated user's permitted resources.
* Remediation should focus on the root cause rather than suppressing the security tool result.

## 🔁 Retest Information

* After remediation, SecureForge should record the retest result.
* Example:

```yaml
retest:
  status: passed
  tested_at: 2026-09-26T12:00:00Z
  result: Cross-user object access was denied
```

* A successful retest should be supported by evidence.

## 🔄 Regression Information

* Important findings can become regression tests.
* Example:

```yaml
regression:
  test_id: BOLA-001
  status: passed
  last_run: 2026-09-26T12:05:00Z
```

* If the regression test fails in a future release, SecureForge can create or reactivate the relevant finding.

## 📊 Finding Normalization

* Different tools may report the same issue differently.

* Example:

  * Tool A:

    * `Broken Access Control`
  * Tool B:

    * `IDOR`
  * Tool C:

    * `BOLA`
  * Tool D:

    * `CWE-639`

* SecureForge can normalize these into a consistent security representation where the underlying issue is the same.

## 🔗 Finding Correlation

* Correlation can combine multiple normalized findings into a single correlated issue.
* Example:

```text id="1w4h8n"
SAST
  ↓
Possible SQL Injection
  ↓
DAST
  ↓
Possible SQL Injection
  ↓
Burp Suite
  ↓
Confirmed SQL Injection
  ↓
Correlated SecureForge Finding
```

* The correlated finding should preserve all relevant evidence sources.

## 🚦 Finding and Policy

* Findings provide the information required by the policy engine.

* Policy can evaluate:

  * Severity.
  * Confidence.
  * Validation status.
  * Security requirement.
  * Asset context.
  * Environment.
  * Regression status.

* Example:

  * Confirmed critical vulnerability → `BLOCK`.
  * Confirmed high-risk authorization violation → `BLOCK`.
  * Medium unresolved finding → `REVIEW`.
  * Low informational observation → `PASS`.

## 📈 Finding History

* SecureForge should preserve finding history where practical.

* Historical information can help answer:

  * When was the finding first detected?
  * When was it validated?
  * When was it remediated?
  * Was the fix retested?
  * Did the finding return?
  * Which releases were affected?

* Historical data should support security reasoning rather than becoming unnecessary complexity.

## 🧪 Finding Quality Requirements

* A good finding should be:

  * Traceable.
  * Evidence-backed.
  * Understandable.
  * Actionable.
  * Correlatable.
  * Validatable.
  * Policy-aware.
  * Regression-aware.

* A finding should not depend entirely on:

  * A scanner's proprietary terminology.
  * An opaque severity score.
  * An unsupported assumption.
  * Missing evidence.

## 🧠 Design Principles

### Preserve Evidence

* Normalization should never unnecessarily discard the original evidence.

### Separate Observation From Interpretation

* Raw evidence and security conclusions should remain distinguishable.

### Separate Severity From Confidence

* A serious reported issue is not automatically a confirmed vulnerability.

### Maintain Traceability

* A finding should be traceable back to its evidence source.

### Support Correlation

* The model should allow multiple evidence sources to support one underlying issue.

### Support Validation

* The model should represent both unvalidated and confirmed findings.

### Support Remediation

* Findings should provide enough information to guide remediation.

### Support Retesting

* The model should record whether remediation was successfully verified.

### Support Regression

* Important findings should be linkable to repeatable regression tests.

### Keep Decisions Explainable

* A reviewer should be able to understand why a finding affected the release decision.

## ➡️ What Comes Next

* The next section focuses on evidence normalization.
* It explains how SecureForge receives different security-tool outputs and transforms them into the common finding model defined here.
