# SecureCommerce Infrastructure Lab

* This directory contains the intentionally insecure Terraform configuration used by the SecureCommerce security-testing lab.
* The configuration exists to provide reproducible Infrastructure-as-Code evidence for SecureForge.

## Purpose

* The infrastructure configuration is deliberately insecure.
* It is designed to demonstrate how SecureForge can detect infrastructure security weaknesses before release.
* It must only be used in an authorized laboratory environment.

## Intentional Security Conditions

* The lab configuration contains several security conditions that should be detected by an IaC security scanner:

  * Application exposed on `0.0.0.0`.
  * Storage configured without encryption.
  * Storage configured for public access.
  * Excessive wildcard permissions.
  * Administrative-level permissions assigned to a broad laboratory role.

## SecureForge Mapping

* The intended SecureForge requirement is:

  * `SF-IAC-001` — Infrastructure Security.

* Example evidence can be normalized into findings such as:

  * Public application exposure.
  * Unencrypted storage.
  * Public storage access.
  * Excessive permissions.

## Laboratory Safety

* These Terraform files are intentionally insecure.
* Do not apply them to production infrastructure.
* Do not apply them to an account containing real production data.
* Use a disposable or isolated laboratory environment only.
* The primary purpose of these files is scanner testing and security verification.

## SecureForge Workflow

```text
Terraform Configuration
          |
          v
     IaC Scanner
          |
          v
      Raw Evidence
          |
          v
     Normalization
          |
          v
    Requirement Mapping
          |
          v
      Risk Engine
          |
          v
     Policy Engine
          |
          v
      Release Gate
```

## Validation Objective

* SecureForge should be able to:

  * Detect the intentionally insecure configuration.
  * Normalize scanner output.
  * Map findings to `SF-IAC-001`.
  * Preserve Terraform resource and configuration evidence.
  * Evaluate the findings according to the configured security policy.
  * Include the results in the final security report.

## Remediation Objective

* A later secure configuration should demonstrate:

  * Restricted network exposure.
  * Encryption enabled.
  * Private storage.
  * Least-privilege permissions.
  * Explicitly scoped roles.

* The vulnerable and remediated configurations should be testable independently so that SecureForge can demonstrate detection, remediation, retesting, and regression prevention.
