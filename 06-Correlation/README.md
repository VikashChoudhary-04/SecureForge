# 🔗 SecureForge Finding Correlation

## 🎯 Purpose

* Finding correlation connects multiple security observations that represent the same underlying security issue.

* Different security tools can independently report the same vulnerability.

* Without correlation, SecureForge could:

  * Count the same vulnerability multiple times.
  * Inflate security metrics.
  * Produce noisy reports.
  * Make risk appear higher than it actually is.
  * Create confusing remediation tasks.
  * Make release decisions harder to explain.

* Correlation transforms related normalized findings into a stronger, unified security representation while preserving the evidence contributed by each source.

## 🧠 Correlation Philosophy

* Correlation should answer:

  * Are these findings describing the same underlying security weakness?
  * Which attributes indicate that they are related?
  * Which evidence sources support the relationship?
  * Should they become one finding or remain separate?
  * Can the combined evidence increase confidence?
  * Can the correlated finding be mapped to one security requirement?

* Correlation must be conservative.

* Incorrectly merging two unrelated vulnerabilities can be more damaging than keeping two related findings separate.

## 🔄 Correlation Flow

```text
          Normalized Findings
                  ↓
          Candidate Matching
                  ↓
        Correlation Signals
                  ↓
          Similarity Analysis
                  ↓
        Correlation Decision
             ↙         ↘
        Correlated     Separate
          Finding      Findings
             ↓
       Evidence Group
             ↓
        Risk Evaluation
```

## 🧩 Correlation Signals

* SecureForge can use multiple attributes when determining whether findings are related.

### Application

* Findings affecting the same application are more likely to be related.
* Example:

  * `SecureCommerce`
  * `SecureCommerce`

### Asset

* Findings affecting the same asset can provide a strong correlation signal.
* Example:

  * `securecommerce-api`

### Endpoint

* Matching HTTP methods and routes can indicate that findings refer to the same functionality.
* Example:

  * `GET /api/orders/{id}`

### Parameter

* The same vulnerable parameter can strengthen correlation.
* Example:

  * `id`
  * `search`

### Vulnerability Type

* Findings describing the same vulnerability class can be related.
* Examples:

  * BOLA.
  * SQL injection.
  * XSS.
  * Secret exposure.

### CWE

* Matching CWE identifiers can provide an additional correlation signal.
* Example:

  * `CWE-639`

### Source Location

* Matching source-code locations can strongly suggest that multiple findings refer to the same weakness.
* Example:

  * `api/orders.py:84`

### Evidence

* Similar requests, responses, payloads, or observations can support correlation.

## 🧮 Correlation Confidence

* Correlation should have its own confidence rather than relying only on finding confidence.

* Example values:

  * `Low`
  * `Medium`
  * `High`
  * `Confirmed`

* A possible correlation does not automatically mean that two findings are the same vulnerability.

## 🧩 Example: SQL Injection

* Three security sources report related evidence.

### SAST

```text
Rule: SQL-001
Location: api/products.py:120
Severity: High
```

### DAST

```text
Endpoint: GET /api/products
Parameter: search
Severity: High
```

### Burp Suite

```text
Endpoint: GET /api/products
Parameter: search
Observation: SQL injection confirmed
```

* After normalization:

```text
SAST Finding
     ↓
Normalized Finding
     ↓
DAST Finding
     ↓
Normalized Finding
     ↓
Burp Finding
     ↓
Normalized Finding
```

* Correlation can determine that all three findings likely represent the same underlying SQL injection vulnerability.

## 🧾 Correlated Finding

```yaml
correlation:
  correlation_id: CORR-0007
  confidence: high
  findings:
    - SF-0021
    - SF-0022
    - SF-0023

finding:
  title: SQL Injection in product search
  endpoint: GET /api/products
  parameter: search
  cwe: CWE-89
  severity: High
  confidence: Confirmed
```

* The individual source findings should remain traceable.
* The correlated finding becomes the unified security representation.

## 🔗 Evidence Aggregation

* Correlation should combine supporting evidence without destroying source information.

```text
                  Correlated Finding
                         │
          ┌──────────────┼──────────────┐
          ↓              ↓              ↓
       SAST           DAST          Burp Suite
       Evidence       Evidence       Evidence
```

* This allows a reviewer to understand:

  * Which tools detected the issue.
  * Which tool confirmed it.
  * What each source observed.
  * Why the evidence was correlated.

## 🛡️ Correlation and Validation

* Correlation and validation are different operations.

* Correlation answers:

  * **Are these observations likely describing the same issue?**

* Validation answers:

  * **Is the underlying security issue actually real?**

* Example:

  * SAST and DAST both report possible SQL injection.
  * Correlation groups them.
  * Burp Suite validates the vulnerability.
  * The resulting finding becomes `Confirmed`.

## ⚖️ Correlation vs. Deduplication

* Deduplication removes duplicate records.

* Correlation creates a relationship between findings that may contain complementary evidence.

* Example:

  * Two identical scanner records may simply be duplicates.
  * A SAST result and a Burp result may contain different evidence for the same vulnerability.

* SecureForge should distinguish these situations.

## 🧩 Correlation vs. Merging

* Correlation does not necessarily mean permanently deleting the original findings.

* Original records should remain available for:

  * Traceability.
  * Auditing.
  * Debugging.
  * Source-specific analysis.
  * Reprocessing.

* The correlated finding acts as a unified representation.

## 🚫 Avoiding False Correlation

* SecureForge should avoid correlating findings solely because they share:

  * The same severity.
  * The same application.
  * The same CWE.
  * The same endpoint.
  * The same tool.

* Multiple signals should be considered when practical.

### Example

* Two SQL injection findings may affect:

  * Different endpoints.
  * Different parameters.
  * Different source locations.
* They should not automatically be merged into one vulnerability.

## 🧠 Correlation Rules

* Correlation rules should be explicit and testable.

### Strong Signals

* Same application.
* Same asset.
* Same endpoint.
* Same parameter.
* Same vulnerability class.
* Same source-code location.

### Supporting Signals

* Same CWE.
* Similar evidence.
* Similar descriptions.
* Related security requirement.
* Related affected component.

### Weak Signals

* Same severity.

* Same tool.

* Similar title only.

* Weak signals should not independently trigger a correlation decision.

## 📊 Correlation Decision

* A correlation engine can classify candidate relationships as:

```text
Same Vulnerability
Potentially Related
Unrelated
```

* Example:

```text
SAST + DAST + Burp
        ↓
Same endpoint
        ↓
Same parameter
        ↓
Same CWE
        ↓
Compatible evidence
        ↓
Same Vulnerability
```

## 🔍 Correlation Evidence

* Every correlation decision should be explainable.
* SecureForge should record why findings were correlated.

### Example

```yaml
correlation:
  correlation_id: CORR-0007
  decision: same_vulnerability
  confidence: high
  reasons:
    - same_application
    - same_endpoint
    - same_parameter
    - same_cwe
    - compatible_evidence
```

* This allows reviewers to understand the reasoning without inspecting internal implementation details.

## 🔄 Correlation Lifecycle

```text
New Findings
     ↓
Candidate Pairs
     ↓
Correlation Signals
     ↓
Similarity Evaluation
     ↓
Correlation Decision
     ↓
Evidence Group
     ↓
Unified Finding
     ↓
Risk Evaluation
```

## 🧪 Correlation Testing

* The correlation engine should be tested using controlled examples.

### Positive Correlation

* Two or more findings clearly represent the same vulnerability.
* Expected result:

  * Findings are correlated.

### Negative Correlation

* Findings look similar but represent different vulnerabilities.
* Expected result:

  * Findings remain separate.

### Partial Correlation

* Findings share some characteristics but lack enough evidence for a reliable relationship.
* Expected result:

  * Findings remain separate or receive a low-confidence relationship.

### Duplicate Evidence

* The same source reports the same issue multiple times.
* Expected result:

  * Duplicate records are handled without creating unnecessary vulnerabilities.

## 🧪 Example Test Cases

### BOLA Correlation

```text
DAST
GET /api/orders/42
       ↓
Possible BOLA

Burp Suite
GET /api/orders/42
       ↓
BOLA confirmed

        ↓

Correlated BOLA Finding
```

### SQL Injection Correlation

```text
SAST
api/products.py:120
       ↓
Possible SQL Injection

DAST
GET /api/products?search=...
       ↓
Possible SQL Injection

Burp Suite
GET /api/products?search=...
       ↓
SQL Injection confirmed

        ↓

Correlated SQL Injection Finding
```

## 📋 Correlation Data Model

* A correlation record can contain:

  * Correlation ID.
  * Related finding IDs.
  * Correlation confidence.
  * Correlation decision.
  * Matching signals.
  * Evidence references.
  * Created timestamp.
  * Updated timestamp.

### Example

```yaml
correlation_id: CORR-0007
decision: same_vulnerability
confidence: high
finding_ids:
  - SF-0021
  - SF-0022
  - SF-0023
signals:
  - same_application
  - same_endpoint
  - same_parameter
  - same_cwe
  - compatible_evidence
```

## 📈 Correlation Metrics

* SecureForge can track:

  * Total findings received.
  * Normalized findings.
  * Correlated findings.
  * Duplicate findings.
  * Uncorrelated findings.
  * Correlation confidence.
  * Findings per source.
  * Evidence sources per correlated finding.

* These metrics can help identify noisy security tools and improve evidence quality.

## 🚦 Correlation and Release Decisions

* Correlation should improve the accuracy of release decisions.

* It should prevent duplicate findings from artificially inflating risk.

* It should also strengthen confidence when multiple independent sources support the same issue.

* Example:

  * SAST reports a possible SQL injection.
  * DAST reports a possible SQL injection.
  * Burp Suite confirms the SQL injection.
  * SecureForge represents one confirmed vulnerability with three evidence sources.
  * Policy evaluates the resulting finding once rather than treating it as three separate vulnerabilities.

## 🧠 Correlation Principles

### Evidence Over Titles

* Correlation should rely on meaningful evidence rather than similar wording alone.

### Multiple Signals

* Strong correlation should be supported by multiple compatible attributes.

### Conservative Merging

* When uncertainty is high, keeping findings separate is safer than incorrectly merging unrelated issues.

### Preserve Source Findings

* Original evidence and source identifiers should remain traceable.

### Explain Decisions

* Every meaningful correlation should have understandable reasons.

### Separate Correlation From Validation

* Grouping related evidence does not prove that the underlying vulnerability exists.

### Support Reprocessing

* Correlation should be deterministic enough to allow findings to be reprocessed when correlation logic changes.

### Avoid Duplicate Risk

* The same underlying vulnerability should not artificially increase release risk because multiple tools detected it.

## 📁 Suggested Structure

```text
secureforge/
└── core/
    └── correlation/
        ├── engine.py
        ├── rules.py
        ├── models.py
        └── tests/
```

* The implementation should keep correlation logic separate from:

  * Tool adapters.
  * Reporting.
  * Policy evaluation.
  * CLI handling.

## ➡️ What Comes Next

* The next section focuses on contextual risk.
* It explains how SecureForge evaluates the practical importance of validated findings using severity, confidence, asset context, exposure, sensitive data, environment, and security requirements.
