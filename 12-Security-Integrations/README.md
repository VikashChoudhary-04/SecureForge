# 🔌 SecureForge Security Integrations

* This directory defines how SecureForge receives security evidence from external security tools and controlled manual validation workflows.
* SecureForge is an orchestration, normalization, correlation, risk, policy, and release-gate layer.
* It is not intended to replace specialized security tools.

## Purpose

* External security tools produce valuable security evidence in different formats.
* SecureForge needs a consistent way to consume that evidence.
* The integration layer connects external tools to the SecureForge pipeline:

```text
     Security Tool
           ↓
      Tool Output
           ↓
       Adapter
           ↓
    Raw Evidence
           ↓
     Normalization
           ↓
      Correlation
           ↓
     Risk Evaluation
           ↓
      Policy Engine
           ↓
    Release Decision
```

## Integration Philosophy

* Each integration should have a clear responsibility.

* SecureForge should not unnecessarily duplicate mature security tooling.

* External tools should perform specialized security analysis.

* SecureForge should interpret and operationalize their results.

* The integration layer should prioritize:

  * Reliable evidence collection
  * Source traceability
  * Reproducibility
  * Error handling
  * Safe execution
  * Consistent normalization
  * Clear tool ownership
  * Minimal coupling

## Supported Integration Categories

* SecureForge is designed to support:

  * SAST
  * SCA
  * Secret Detection
  * API Security
  * DAST
  * Container Security
  * IaC Security
  * Nmap
  * Nessus
  * Burp Suite Professional
  * Wireshark
  * Metasploit
  * Manual validation

## Integration Lifecycle

```text
     Configure Tool
          ↓
      Execute Tool
          ↓
      Collect Output
          ↓
     Validate Output
          ↓
      Preserve Raw Data
          ↓
       Parse Result
          ↓
       Normalize
          ↓
      Add Evidence
          ↓
       Correlate
          ↓
     Risk Evaluation
          ↓
      Policy Engine
```

## Adapter Model

* Each external tool should have an adapter responsible for translating its output into SecureForge's internal representation.

* Conceptually:

```text
Tool Output
    ↓
Tool Adapter
    ↓
Normalized Finding
    ↓
Core SecureForge Model
```

* The adapter should not independently decide the final release decision.
* Risk and policy decisions belong to the corresponding SecureForge components.

## Adapter Responsibilities

* An adapter should:

  * Identify the source tool.
  * Read supported output formats.
  * Validate required fields.
  * Extract security findings.
  * Preserve source identifiers.
  * Preserve relevant evidence.
  * Map severity where possible.
  * Map CWE or equivalent classifications where available.
  * Normalize assets and endpoints.
  * Report parsing errors.
  * Return structured SecureForge evidence.

## Adapter Non-Responsibilities

* An adapter should not:

  * Invent evidence.
  * Automatically mark an unverified vulnerability as confirmed without justification.
  * Hide parsing failures.
  * Modify raw evidence unnecessarily.
  * Override policy decisions.
  * Replace the risk engine.
  * Replace the correlation engine.

## Source Traceability

* Every imported finding should preserve its origin.

* Example:

```text id="4qydx1"
Source:
Burp Suite

Source Finding ID:
BURP-1234

SecureForge Finding:
SF-0042
```

* This allows an analyst to trace a SecureForge finding back to the originating security tool.

## Raw Evidence Preservation

* SecureForge should preserve raw tool output whenever practical and safe.

* Raw evidence provides an audit trail for normalization decisions.

* Sensitive information should be handled according to the project's security requirements.

* Example:

```text id="y9v2t1"
Raw Tool Output
      ↓
Stored Evidence
      ↓
Adapter
      ↓
Normalized Finding
```

## SAST Integration

* SAST tools analyze source code for security weaknesses.

* SecureForge can consume findings such as:

  * Injection risks
  * Unsafe API usage
  * Authentication weaknesses
  * Authorization weaknesses
  * Hardcoded secrets
  * Dangerous functions

* Example workflow:

```text id="g5h1nd"
Source Code
    ↓
SAST
    ↓
Potential SQL Injection
    ↓
SecureForge Adapter
    ↓
Normalized Finding
```

* SAST findings may have lower confidence than dynamically validated findings depending on the tool and evidence available.

## SCA Integration

* SCA tools identify vulnerable or outdated dependencies.

* SecureForge can consume:

  * Package name
  * Package version
  * Vulnerability identifier
  * Severity
  * Fixed version
  * Dependency path
  * Advisory information

* Example:

```text id="5k9m6p"
requirements.txt
      ↓
SCA Scanner
      ↓
Vulnerable Dependency
      ↓
SecureForge
      ↓
SF-DEP-001
```

## Secret Detection Integration

* Secret detection tools identify credentials or sensitive tokens in source repositories and build artifacts.

* SecureForge can consume:

  * Secret type
  * Location
  * File
  * Line
  * Detection confidence
  * Secret fingerprint where supported

* Test credentials should be clearly identified and isolated from real secrets.

## API Security Integration

* API security tools can analyze OpenAPI specifications and API behavior.

* SecureForge can consume evidence related to:

  * Missing authentication
  * BOLA
  * Broken function-level authorization
  * Excessive data exposure
  * Input validation
  * Security misconfiguration
  * Rate/resource control issues

* API evidence should preserve:

  * HTTP method
  * Endpoint
  * Parameters
  * Authentication context
  * Response
  * Relevant request metadata

## DAST Integration

* DAST tools test running applications from an external perspective.

* SecureForge can consume:

  * URL
  * HTTP method
  * Parameter
  * Finding type
  * Severity
  * Evidence
  * Confidence
  * Scanner identifier

* DAST findings can provide useful runtime evidence for correlation and validation.

## Container Security Integration

* Container security tools can analyze:

  * Base images
  * Packages
  * Vulnerabilities
  * Configuration
  * User privileges
  * Exposed ports
  * Secrets
  * Runtime configuration

* Example:

```text id="w5j2l0"
Container Image
      ↓
Container Scanner
      ↓
Root User / Vulnerable Package
      ↓
SecureForge
      ↓
Container Security Finding
```

## IaC Security Integration

* IaC tools can analyze infrastructure configuration such as Terraform.

* SecureForge can consume findings related to:

  * Public exposure
  * Excessive permissions
  * Insecure storage
  * Weak network rules
  * Missing encryption
  * Unsafe configuration

* IaC findings should preserve the relevant configuration resource.

## Nmap Integration

* Nmap can provide network and service discovery evidence.

* SecureForge can consume:

  * Host
  * Port
  * Protocol
  * Service
  * Version
  * State
  * Script output where relevant

* Nmap should primarily provide attack-surface and service evidence.

* SecureForge should not treat every discovered service as automatically vulnerable.

## Nessus Integration

* Nessus can provide infrastructure vulnerability assessment evidence.

* SecureForge can consume:

  * Plugin identifier
  * Vulnerability title
  * Host
  * Port
  * Severity
  * CVE
  * CVSS information
  * Plugin output
  * Remediation guidance

* Nessus remains responsible for vulnerability assessment.

* SecureForge uses the resulting evidence in its broader security decision process.

## Burp Suite Professional Integration

* Burp Suite can provide application-security evidence through controlled testing.

* SecureForge may consume findings involving:

  * Authentication
  * Authorization
  * Injection
  * XSS
  * API security
  * Session handling
  * Security misconfiguration

* Burp remains the specialized application testing platform.

* SecureForge consumes and operationalizes relevant evidence.

## Wireshark Integration

* Wireshark is primarily a network-analysis and packet-inspection tool.

* SecureForge may use manually reviewed Wireshark evidence for cases such as:

  * Unexpected cleartext communication
  * Protocol behavior
  * Transport-security validation
  * Suspicious network behavior

* Wireshark findings may require manual validation before entering the release gate.

## Metasploit Integration

* Metasploit may be used for controlled validation of specific vulnerabilities in authorized lab environments.

* SecureForge should consume the resulting validation evidence rather than attempt to replace Metasploit.

* Example:

```text id="c5n0p4"
Known Vulnerability
       ↓
Controlled Validation
       ↓
Metasploit
       ↓
Validation Evidence
       ↓
SecureForge
```

* Exploitation must remain restricted to authorized and controlled environments.

## Manual Validation Integration

* Some findings require human verification.

* SecureForge should support manually supplied evidence.

* Manual validation may include:

  * Burp verification
  * Authorization testing
  * Packet analysis
  * Controlled exploitation
  * Business-logic validation

* Manual findings should contain:

  * Tester
  * Date
  * Target
  * Procedure
  * Evidence
  * Result
  * Confidence
  * Related requirement

## Tool Execution

* SecureForge should distinguish between:

  * Tool configuration
  * Tool execution
  * Output collection
  * Output parsing
  * Evidence normalization

* This separation makes integrations easier to test.

## Tool Availability

* External tools may not always be installed.

* SecureForge should detect missing dependencies before execution.

* Example:

```text id="l5h4p8"
Requested Integration
        ↓
Check Tool Availability
        ↓
Tool Available?
   ↙          ↘
 Yes           No
 ↓              ↓
Execute       Clear Error
```

* A missing optional tool should produce an actionable message rather than an unexplained failure.

## Command Safety

* External commands should be constructed safely.
* User-controlled values should not be concatenated into shell commands without appropriate handling.
* SecureForge should prefer structured subprocess execution over unsafe shell evaluation.
* Tool execution should be logged sufficiently for reproducibility without exposing secrets.

## Timeouts

* Security tools may run for long periods.

* Integrations should support configurable timeouts where appropriate.

* A timeout should be represented clearly in execution results.

* Example:

```text id="m0b8n4"
Tool Started
    ↓
Timeout Reached
    ↓
Execution Status:
TIMEOUT
    ↓
Evidence:
Partial / Unavailable
```

* A timeout should not automatically be interpreted as a clean security result.

## Exit Codes

* Tool exit codes should be preserved.

* SecureForge should distinguish between:

  * Successful execution
  * Findings detected
  * Tool execution failure
  * Invalid configuration
  * Timeout
  * Missing dependency

* A tool returning a non-zero code should not automatically mean that vulnerabilities were found.

## Output Formats

* Integrations should support stable machine-readable formats where possible.

* Preferred formats may include:

  * JSON
  * SARIF
  * XML
  * CSV where necessary
  * Tool-specific structured formats

* Human-readable output may be retained as supplementary evidence.

## Integration Configuration

* Integration settings should be separated from application logic.

* Example:

```yaml id="5m3r2w"
integrations:
  sast:
    enabled: true

  sca:
    enabled: true

  secrets:
    enabled: true

  dast:
    enabled: true

  nessus:
    enabled: false

  nmap:
    enabled: false
```

* Secrets such as API keys should not be stored directly in committed configuration files.

## Verification Profiles

* Integrations should support the SecureForge verification profiles.

* Quick:

```text id="n7y4r2"
SAST
SCA
Secret Detection
```

* Standard:

```text id="h1q8kc"
Quick
  +
API Security
DAST
Container Security
```

* Full:

```text id="u3p6mx"
Standard
   +
IaC Security
Nessus
Nmap
Manual Validation
```

* The exact execution behavior will be implemented later.

## Integration Failure Policy

* Tool failure should be distinguishable from a clean result.

* Example:

```text id="z8k3q1"
SAST
  ↓
Execution Failed
  ↓
No Reliable SAST Evidence
```

* Depending on policy, this may result in:

  * `REVIEW`
  * `BLOCK`
  * Explicit exception
  * Retry

* SecureForge should never silently convert missing evidence into `PASS`.

## Evidence Confidence

* Evidence quality should influence confidence.

* Example:

```text id="g1r6vz"
Static Analysis
      ↓
Potential SQLi
      ↓
Medium Confidence

Dynamic Validation
      ↓
Confirmed SQLi
      ↓
High Confidence
```

* Confidence should be determined by evidence rather than the name of the tool alone.

## Correlation Across Integrations

* Multiple tools may identify the same underlying weakness.

* Example:

```text id="a4x7kc"
SAST
 ↓
Possible SQLi
 ↓
     SecureForge
 ↓
DAST
 ↓
Possible SQLi
 ↓
Burp
 ↓
Confirmed SQLi
```

* Correlation should combine the evidence while preserving the individual sources.

## Integration Security

* Integrations may handle highly sensitive information.
* SecureForge should:

  * Avoid logging credentials.
  * Protect tokens.
  * Restrict file permissions where appropriate.
  * Sanitize sensitive evidence.
  * Avoid exposing secrets in reports.
  * Use test credentials in the lab.
  * Keep external tool credentials outside source control.

## Integration Testing

* Every integration should have tests for:

  * Valid output
  * Empty output
  * Malformed output
  * Missing fields
  * Unexpected fields
  * Duplicate findings
  * Severity mapping
  * Evidence preservation
  * Tool failure
  * Timeout
  * Missing executable

## Mocked Tool Execution

* Integration tests should not require every external security tool to be installed.

* Mock tool output can validate adapters independently.

* Example:

```text id="q2j5sw"
Mock Tool Output
      ↓
Adapter
      ↓
Normalized Evidence
      ↓
Expected SecureForge Object
```

* Real tool execution should be covered separately in controlled integration testing.

## Integration Logging

* Logs should make tool execution understandable.

* Useful information includes:

  * Integration name
  * Tool version
  * Execution start
  * Execution end
  * Exit status
  * Output location
  * Number of findings
  * Parsing status

* Logs must not expose credentials or sensitive secrets.

## Integration Metadata

* SecureForge should preserve useful metadata such as:

  * Tool name
  * Tool version
  * Adapter version
  * Scan timestamp
  * Target
  * Profile
  * Configuration identifier
  * Source file

* This improves reproducibility.

## Suggested Implementation Structure

```text id="q9z2vx"
integrations/
├── __init__.py
├── base.py
├── common/
│   ├── command.py
│   ├── execution.py
│   └── errors.py
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

* The exact structure may evolve during implementation.
* Each integration should remain independently testable.

## Integration Contract

* Each integration should expose a predictable contract.

* Conceptually:

```text
Integration
├── name
├── version
├── availability()
├── execute()
├── collect()
├── parse()
└── normalize()
```

* The final implementation may use Python interfaces or abstract base classes.

## Design Principles

* SecureForge integrations should:

  * Treat external tools as evidence sources.
  * Preserve source traceability.
  * Never fabricate findings.
  * Never silently discard parsing failures.
  * Separate tool execution from security decision-making.
  * Handle missing tools gracefully.
  * Protect credentials and sensitive evidence.
  * Support reproducible execution.
  * Remain independently testable.
  * Avoid rebuilding mature security tools.

## What Comes Next

* The next component is **Reporting**.
* It will define how SecureForge converts findings, evidence, risk, policy results, remediation state, and regression results into machine-readable and human-readable security reports.
* The reporting layer will provide the final evidence trail behind every `PASS`, `REVIEW`, or `BLOCK` release decision.
