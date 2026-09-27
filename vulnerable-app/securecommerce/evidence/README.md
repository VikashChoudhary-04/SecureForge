# SecureCommerce Security Evidence

* This directory stores controlled security evidence generated during SecureCommerce testing.
* Evidence is used by SecureForge to normalize findings, correlate duplicate observations, evaluate risk, and support release decisions.

## Evidence Sources

* Evidence may originate from:

  * SAST scanners.
  * SCA scanners.
  * Secret detection tools.
  * API security scanners.
  * DAST scanners.
  * Container security scanners.
  * IaC scanners.
  * Nmap.
  * Nessus.
  * Burp Suite Professional.
  * Wireshark.
  * Metasploit.
  * Manual security validation.

## Evidence Principles

* Evidence should be reproducible whenever practical.
* Evidence should contain enough context to explain what was detected.
* Evidence should never contain real production credentials or secrets.
* Deliberately fake laboratory secrets must remain clearly identified as test data.
* Sensitive values should be redacted before evidence is committed.
* Evidence should identify the originating tool or validation method.
* Evidence should preserve useful references such as:

  * Tool name.
  * Tool version.
  * Source finding identifier.
  * Target.
  * Endpoint.
  * Parameter.
  * Request or response reference.
  * File and line location.
  * Command or validation reference.
  * Collection timestamp.

## Supported Evidence Structure

* SecureForge integrations expect evidence in tool-specific formats.
* Generic JSON evidence should use a structure similar to:

```json
{
  "tool": "example-scanner",
  "version": "1.0.0",
  "target": "http://localhost:5000",
  "findings": [
    {
      "id": "EXAMPLE-001",
      "title": "Example Security Finding",
      "severity": "high",
      "confidence": "confirmed",
      "endpoint": "/api/example",
      "parameter": "id",
      "cwe": "CWE-639",
      "description": "Example controlled laboratory finding.",
      "evidence": {
        "request": "GET /api/example?id=2",
        "response_status": 200
      }
    }
  ]
}
```

## Manual Evidence

* Manual evidence may document validation performed with authorized security tools.
* Examples include:

  * Burp Suite request and response evidence.
  * Wireshark packet references.
  * Metasploit validation output.
  * Screenshots or references to controlled testing artifacts.
  * Reproduction steps.
  * Retest results.

## Evidence Lifecycle

```text
Tool / Manual Validation
          |
          v
     Raw Evidence
          |
          v
       SecureForge
          |
          v
     Normalized Finding
          |
          v
       Correlation
          |
          v
     Risk Evaluation
          |
          v
     Release Decision
```

## Repository Safety

* Do not commit:

  * Real passwords.
  * Real API keys.
  * Real access tokens.
  * Production session cookies.
  * Private certificates or private keys.
  * Personal data.
  * Production network captures.
  * Unredacted sensitive requests or responses.

* Use synthetic laboratory data for all committed evidence.

## Purpose Within the Project

* Evidence is not merely documentation.
* It is an input to the executable SecureForge verification pipeline.
* The final project should demonstrate that the same evidence can be:

  * Collected.
  * Parsed.
  * Normalized.
  * Correlated.
  * Risk-scored.
  * Evaluated against policy.
  * Included in a release report.
  * Used for validation and regression testing.
