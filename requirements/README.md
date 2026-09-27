# SecureForge Security Requirements

* This directory contains the machine-readable security requirements used by SecureForge to connect scanner evidence with explicit application-security expectations.

## Purpose

* Security requirements provide a stable internal vocabulary for SecureForge.
* Findings from different security tools can describe the same weakness in different ways.
* SecureForge maps those findings to internal requirements so that security decisions are based on consistent controls rather than scanner-specific terminology.

## Requirement Structure

* Each requirement contains:

  * A unique SecureForge identifier.
  * A human-readable title.
  * A description of the expected security control.
  * A security category.
  * Relevant OWASP mappings when applicable.
  * Relevant CWE mappings when applicable.

## Requirement Identifiers

* SecureForge uses identifiers such as:

  * `SF-AUTH-001` for authentication security.
  * `SF-AUTH-002` for session security.
  * `SF-AUTHZ-001` for object-level authorization.
  * `SF-AUTHZ-002` for function-level authorization.
  * `SF-API-001` for API security.
  * `SF-API-002` for API resource protection.
  * `SF-INPUT-001` for input validation.
  * `SF-SECRET-001` for secret protection.
  * `SF-DEP-001` for dependency security.
  * `SF-CONTAINER-001` for container security.
  * `SF-IAC-001` for infrastructure security.
  * `SF-TRANSPORT-001` for transport security.
  * `SF-REG-001` for security regression prevention.

## Finding Mapping

* Security integrations should map findings to a requirement whenever the evidence supports a meaningful mapping.
* Examples:

  * A confirmed BOLA finding maps to `SF-AUTHZ-001`.
  * A SQL injection finding maps to `SF-INPUT-001`.
  * A hard-coded API key maps to `SF-SECRET-001`.
  * A vulnerable dependency maps to `SF-DEP-001`.
  * A weak TLS configuration maps to `SF-TRANSPORT-001`.
* Integrations must not invent a requirement when the available evidence does not support one.

## OWASP and CWE

* OWASP mappings provide application-security context.
* CWE mappings identify the underlying weakness class.
* A requirement may contain multiple CWE mappings when appropriate.
* SecureForge does not claim that a finding is fully compliant or non-compliant with an entire OWASP standard solely because a mapping exists.

## Use in the Security Pipeline

* Requirements participate in the following workflow:

  * Scanner or manual evidence is collected.
  * Evidence is normalized into a common finding model.
  * The finding is mapped to a SecureForge requirement when possible.
  * Correlation combines evidence describing the same weakness.
  * Risk evaluation considers the resulting finding context.
  * The policy engine evaluates the security decision.
  * The release gate produces `PASS`, `REVIEW`, or `BLOCK`.
  * Confirmed findings can receive regression coverage.

## Source of Truth

* `requirements/security-requirements.yaml` is the machine-readable source of truth for the current SecureForge requirement catalog.
* Application code should reference requirement identifiers instead of duplicating requirement definitions.
* New requirements should receive a unique identifier and documented rationale before being used by integrations.

## Scope

* The requirement catalog intentionally covers the security controls required by the SecureForge demonstration application and verification workflow.
* It is not a complete implementation of OWASP ASVS or the OWASP API Security Top 10.
* Additional requirements may be added as the application and verification coverage expand.
