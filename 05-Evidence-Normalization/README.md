# 🔄 SecureForge Evidence Normalization

## 🎯 Purpose

* Evidence normalization converts security-tool output into the common SecureForge finding model.

* Security tools produce different:

  * File formats.
  * Field names.
  * Severity values.
  * Finding identifiers.
  * Evidence structures.
  * Terminology.
  * Confidence representations.

* SecureForge must transform these different outputs without losing the information required for validation, correlation, risk evaluation, reporting, and release decisions.

## 🧠 Normalization Philosophy

* Normalization is a translation layer, not a replacement for the original security tool.

* SecureForge should:

  * Preserve original evidence.
  * Preserve source identity.
  * Convert tool-specific fields into common fields.
  * Map security classifications.
  * Normalize severity where possible.
  * Represent confidence explicitly.
  * Preserve unsupported information rather than silently discarding it.
  * Make normalized findings traceable to their original source.

* The normalized finding should answer:

  * What was reported?
  * Where was it reported?
  * Which tool reported it?
  * What evidence supports it?
  * How serious is it?
  * How confident are we?
  * Which security requirement may be affected?

## 🔗 Normalization Flow

```text
        Security Tool Output
                 ↓
           Input Adapter
                 ↓
          Parse Raw Data
                 ↓
        Validate Input Shape
                 ↓
         Map Common Fields
                 ↓
       Normalize Classifications
                 ↓
       Normalize Severity
                 ↓
       Normalize Confidence
                 ↓
       Preserve Source Evidence
                 ↓
        SecureForge Finding
```

## 🧩 Evidence Sources

* SecureForge can normalize evidence from multiple security sources.

### Application Security

* SAST.
* SCA.
* Secret scanners.
* DAST.
* API security tools.
* Manual application testing.

### Infrastructure Security

* Nessus.
* Nmap.
* Container scanners.
* IaC scanners.

### Expert Validation

* Burp Suite.
* Wireshark.
* Metasploit.
* Manual security evidence.

## 📦 Raw Evidence

* Raw evidence represents the original output before SecureForge modifies or interprets it.

* Examples:

  * JSON scanner output.
  * SARIF output.
  * XML output.
  * CSV output.
  * HTTP request and response.
  * Source-code location.
  * Tool-generated finding record.

* Raw evidence should remain available for traceability.

### Example Raw Finding

```json
{
  "rule_id": "AUTHZ-001",
  "message": "Possible insecure direct object reference",
  "severity": "error",
  "file": "api/orders.py",
  "line": 84
}
```

## 🧱 Input Adapters

* Each external source should have an adapter responsible for understanding that source's format.

* An adapter should:

  * Read the source format.
  * Validate required fields.
  * Extract relevant information.
  * Preserve original values.
  * Convert the result into an internal intermediate representation.

* Adapters should remain isolated from the core finding model where practical.

## 🗂️ Adapter Responsibilities

* An adapter should answer:

  * What tool produced this evidence?
  * What format is being processed?
  * Which records represent findings?
  * Which fields contain security classifications?
  * Where is the affected asset?
  * Where is the evidence?
  * Which source identifier should be preserved?

* An adapter should not independently decide whether a finding is confirmed.

* Validation belongs to the validation stage.

## 🧩 Common Internal Representation

* After parsing, evidence should be converted into a consistent internal representation.
* Example:

```yaml
source: sast
source_finding_id: AUTHZ-001
title: Possible insecure direct object reference
asset: SecureCommerce API
endpoint: GET /api/orders/{id}
parameter: id
severity: high
confidence: medium
cwe: CWE-639
evidence:
  file: api/orders.py
  line: 84
  message: Possible insecure direct object reference
```

* This intermediate representation can then be converted into the complete SecureForge finding.

## 🏷️ Field Mapping

* Different tools use different names for the same concept.
* Example:

| Tool Field | SecureForge Field   |
| ---------- | ------------------- |
| `rule_id`  | `source_finding_id` |
| `message`  | `description`       |
| `severity` | `severity`          |
| `file`     | `location`          |
| `line`     | `location.line`     |
| `cwe`      | `cwe`               |
| `endpoint` | `endpoint`          |
| `evidence` | `evidence`          |

* Field mapping should be explicit.
* Implicit or undocumented mappings make troubleshooting difficult.

## ⚖️ Severity Normalization

* Security tools may use different severity systems.

* Examples:

  * `critical`
  * `high`
  * `medium`
  * `low`
  * `warning`
  * `error`
  * Numeric scores.

* SecureForge should convert supported source values into a consistent severity vocabulary:

  * `Critical`
  * `High`
  * `Medium`
  * `Low`
  * `Informational`

* The original source severity should still be preserved.

### Example

```yaml
source_severity: error
severity: High
```

* Normalization should not pretend that unrelated severity systems are mathematically identical.
* When mapping is uncertain, the uncertainty should remain visible.

## 🎯 Confidence Normalization

* Confidence should be represented separately from severity.

* Possible normalized values:

  * `Low`
  * `Medium`
  * `High`
  * `Confirmed`

* Example:

```yaml
severity: Critical
confidence: Low
```

* This means the reported vulnerability could be serious, but the available evidence is not yet strong enough to treat it as confirmed.

## 🏷️ Classification Mapping

* Security tools may provide:

  * CWE.
  * CVE.
  * OWASP category.
  * Rule IDs.
  * Plugin IDs.
  * Proprietary vulnerability categories.

* SecureForge should preserve source classifications while mapping them into common classifications where reliable.

### Example

```yaml
source:
  rule_id: API-BOLA-001
cwe: CWE-639
owasp: API1
```

* Classification mapping should be documented and reviewable.

## 📍 Asset Normalization

* Different tools may identify the same asset differently.

* Examples:

  * `securecommerce-web`
  * `SecureCommerce`
  * `localhost:5000`
  * `securecommerce-api`

* SecureForge should normalize asset identity where possible.

* Example:

```yaml
asset:
  id: securecommerce-api
  name: SecureCommerce API
```

* Asset normalization is important for correlation and contextual risk.

## 🌐 Endpoint Normalization

* API and web tools may represent endpoints differently.

* Examples:

  * `/api/orders/42`
  * `GET https://localhost:5000/api/orders/42`
  * `GET /api/orders/{id}`

* SecureForge should distinguish:

  * HTTP method.
  * Route.
  * Concrete identifier.
  * Parameter.

* Example:

```yaml
endpoint:
  method: GET
  route: /api/orders/{id}
  parameter: id
```

* This makes correlation between tools more reliable.

## 🧾 Evidence Preservation

* Normalization must not destroy the evidence that supports a finding.

* Evidence should preserve relevant:

  * Requests.
  * Responses.
  * Source-code locations.
  * Tool output.
  * Dependency information.
  * Network observations.
  * Configuration.
  * Validation results.

* Sensitive information should be redacted where necessary.

## 🔐 Sensitive Data Handling

* Security evidence can contain sensitive information.

* Examples:

  * Passwords.
  * Tokens.
  * API keys.
  * Session cookies.
  * Internal IP addresses.
  * Personal information.

* SecureForge should:

  * Redact secrets.
  * Avoid storing real credentials.
  * Sanitize reports.
  * Protect sensitive evidence.
  * Use laboratory credentials for demonstrations.

### Example

```text
Authorization: Bearer <REDACTED>
```

## 🔗 Source Traceability

* Every normalized finding should remain traceable to its original source.
* Example:

```yaml
source:
  tool: burp
  version: "2026.x"
  finding_id: BURP-1234
  collected_at: 2026-09-26T12:00:00Z
```

* This allows reviewers to investigate the original evidence when necessary.

## 🔄 Normalization Example

* Consider three tools reporting the same potential SQL injection.

### SAST

```text
Rule: SQL-001
Severity: High
Location: api/products.py:120
```

### DAST

```text
URL: /api/products
Parameter: search
Severity: High
```

### Burp Suite

```text
Endpoint: GET /api/products
Parameter: search
Observation: SQL injection confirmed
```

* SecureForge can normalize these into:

```yaml
finding_id: SF-0020
title: SQL Injection in product search
asset: SecureCommerce API
endpoint: GET /api/products
parameter: search
cwe: CWE-89
severity: High
confidence: Confirmed
```

* The original evidence from all three sources remains attached to the finding.

## 🔗 Normalization and Correlation

* Normalization must happen before reliable correlation.

* Correlation becomes easier when findings use common:

  * Asset identifiers.
  * Endpoint representations.
  * Vulnerability classifications.
  * Parameters.
  * Severity values.
  * Security requirements.

* Example:

```text
SAST
  ↓
Normalized Finding
  ↓
DAST
  ↓
Normalized Finding
  ↓
Burp
  ↓
Normalized Finding
  ↓
Correlation
```

## 🧪 Normalization Validation

* Normalization itself must be tested.
* SecureForge should verify that:

  * Required fields are preserved.
  * Source identity remains available.
  * Severity mappings work correctly.
  * Classifications are not incorrectly changed.
  * Evidence is preserved.
  * Sensitive data is handled safely.
  * Invalid input is rejected or handled predictably.

## ❌ Invalid Evidence

* External tool output should not be blindly trusted.

* Invalid input can include:

  * Malformed JSON.
  * Missing required fields.
  * Invalid severity values.
  * Unexpected data types.
  * Corrupted files.
  * Unsupported schema versions.

* SecureForge should:

  * Detect malformed input.
  * Produce useful error messages.
  * Avoid silently dropping findings.
  * Log normalization failures.
  * Continue processing independent valid evidence where appropriate.

## 🧰 Adapter Error Handling

* Adapter failures should be distinguishable from security findings.

* Example:

  * A scanner reports a vulnerability.
  * SecureForge fails to parse the scanner output.

* This should not be represented as:

  * `No vulnerabilities found`.

* Instead, the system should report:

  * The evidence source could not be processed.
  * The verification result may be incomplete.

## 📊 Normalization Metrics

* SecureForge can track normalization metrics such as:

  * Number of source records processed.
  * Number of findings normalized.
  * Number of records rejected.
  * Number of unsupported records.
  * Number of normalization errors.
  * Number of findings missing required fields.

* These metrics help determine whether a security scan actually produced usable evidence.

## 🧠 Normalization Principles

### Preserve Original Evidence

* Never unnecessarily destroy the source record.

### Normalize Consistently

* Equivalent concepts should use consistent internal representations.

### Preserve Uncertainty

* Do not invent confidence or classifications that the evidence does not support.

### Keep Source Context

* A normalized finding should remain traceable to its originating tool.

### Separate Parsing From Validation

* Parsing determines what the source reported.
* Validation determines whether the reported security issue is actually valid.

### Fail Safely

* A parsing failure should not silently become a clean security result.

### Make Mappings Explicit

* Severity and classification mappings should be documented.

### Protect Sensitive Evidence

* Credentials and other sensitive values should be redacted or protected.

## 📁 Suggested Structure

```text
secureforge/
└── integrations/
    ├── sast/
    ├── sca/
    ├── secrets/
    ├── api/
    ├── dast/
    ├── container/
    ├── iac/
    ├── nessus/
    ├── nmap/
    └── manual/
```

* Each integration can contain:

  * Input parser.
  * Adapter.
  * Field mapping.
  * Validation.
  * Tests.

## ➡️ What Comes Next

* The next section focuses on finding correlation.
* It explains how SecureForge identifies multiple pieces of evidence that represent the same underlying security issue and combines them without losing their individual evidence.
