# SecureCommerce Vulnerable Application

* SecureCommerce is the deliberately vulnerable web and API application used as the primary target for SecureForge security verification.
* It is designed for controlled local security testing, validation, remediation, retesting, and regression testing.
* The application intentionally contains representative security weaknesses so that SecureForge can demonstrate a complete security verification lifecycle.

## Purpose

* SecureCommerce provides a realistic application target for demonstrating how SecureForge collects and evaluates security evidence.
* The application is intentionally insecure and must only be run in an authorized local or isolated laboratory environment.
* SecureCommerce is not intended for production deployment or exposure to the public internet.

## Application Scope

* SecureCommerce provides the following functional areas:

  * User registration and login.
  * User profile management.
  * Product browsing.
  * Shopping cart management.
  * Order creation and viewing.
  * Role-based administrative functionality.
  * REST API endpoints.
  * File upload functionality.
  * Database-backed application data.
  * External service integration.
  * Containerized deployment.
  * Infrastructure-as-Code configuration.

## Security Testing Coverage

* The application intentionally contains weaknesses covering multiple security areas:

  * Authentication weaknesses.
  * Session security weaknesses.
  * Object-level authorization failures.
  * Function-level authorization failures.
  * SQL injection.
  * Cross-site scripting.
  * API authentication and authorization weaknesses.
  * Excessive API data exposure.
  * Input validation weaknesses.
  * Server-side request forgery.
  * Insecure file handling.
  * Security misconfiguration.
  * Vulnerable dependencies.
  * Hardcoded or exposed secrets.
  * Container security weaknesses.
  * Infrastructure security weaknesses.
  * Transport security configuration issues.

## SecureForge Demonstration

* SecureCommerce is used to demonstrate the complete SecureForge lifecycle:

  * Discover security evidence.
  * Normalize scanner results.
  * Correlate duplicate findings.
  * Map findings to security requirements.
  * Evaluate contextual risk.
  * Apply release policies.
  * Produce a release decision.
  * Remediate vulnerabilities.
  * Retest security controls.
  * Execute regression tests.
  * Produce the final security report.

## Expected Release-Gate Flow

```text
SecureCommerce
      |
      v
Security Scanners
      |
      v
Evidence Collection
      |
      v
Normalization
      |
      v
Correlation
      |
      v
Risk Evaluation
      |
      v
Policy Evaluation
      |
      v
Release Gate
      |
      +-------------------+
      |                   |
      v                   v
   BLOCK/REVIEW          PASS
      |
      v
  Remediation
      |
      v
    Retest
      |
      v
 Regression Tests
      |
      v
    PASS
```

## Deliberate Vulnerability Model

* Vulnerabilities are intentionally introduced to create reproducible security-testing scenarios.
* Each vulnerability should have:

  * A predictable application location.
  * A clear security impact.
  * A corresponding SecureForge security requirement where applicable.
  * Evidence that can be collected by one or more integrations.
  * A remediation path.
  * A retesting method.
  * A regression test where appropriate.

## Example Security Scenarios

* A user accesses another user's order by modifying an object identifier.

  * Expected classification:

    * Vulnerability: Broken Object-Level Authorization.
    * Requirement: SF-AUTHZ-001.
    * API mapping: OWASP API1.
    * Expected outcome: high-risk finding requiring release review or blocking according to policy.

* An application endpoint constructs a database query from untrusted input.

  * Expected classification:

    * Vulnerability: SQL Injection.
    * Requirement: SF-INPUT-001.
    * Expected evidence sources:

      * SAST.
      * DAST.
      * Manual validation where required.

* A source file contains a deliberately fake API secret.

  * Expected classification:

    * Vulnerability: Exposed Secret.
    * Requirement: SF-SECRET-001.
    * Expected evidence source: secret detection integration.

* The container image runs the application as root.

  * Expected classification:

    * Vulnerability: Container security misconfiguration.
    * Requirement: SF-CONTAINER-001.
    * Expected evidence source: container security integration.

## Safety

* SecureCommerce contains intentional vulnerabilities.
* Run it only in an isolated development or security-testing environment.
* Do not use real passwords, API keys, tokens, personal information, or production data.
* Do not expose the application directly to the public internet.
* Do not use the application to test systems that you do not own or have explicit authorization to assess.

## Implementation

* The application will be implemented incrementally as part of the SecureForge project.
* The implementation will include:

  * Application source code.
  * Database models.
  * Web routes.
  * REST API routes.
  * Authentication and authorization logic.
  * Deliberately vulnerable code paths.
  * Secure remediation versions where useful.
  * Automated tests.
  * Container configuration.
  * Infrastructure-as-Code examples.

## Relationship With SecureForge

* SecureCommerce is the target.
* SecureForge is the verification and release-gate system.
* SecureCommerce provides the security conditions that SecureForge must detect and evaluate.
* SecureForge must not depend on undocumented behavior inside SecureCommerce.
* The target application should remain independently runnable so that security findings can be reproduced manually using authorized testing tools.

## Lab Objective

* The final lab should demonstrate a complete transition from an intentionally vulnerable release to a verified release:

  * Vulnerable application.
  * Security evidence collected.
  * Findings normalized.
  * Duplicate evidence correlated.
  * Risk evaluated.
  * Release blocked.
  * Vulnerabilities remediated.
  * Findings retested.
  * Regression tests executed.
  * Release verified.
  * Security report generated.
