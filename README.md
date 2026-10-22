# 🛡️ SecureForge — Continuous Security Verification & Release Gate

<div align="center">

**Continuously verify application security. Correlate evidence. Enforce security policy. Prevent regressions.**

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Security](https://img.shields.io/badge/Domain-Application%20Security-red)
![DevSecOps](https://img.shields.io/badge/Focus-DevSecOps-orange)
![API Security](https://img.shields.io/badge/Focus-API%20Security-purple)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

SecureForge is a modular **application-security verification and release-gating framework** for web applications and APIs.

It brings security evidence, finding normalization, correlation, security requirements, contextual risk evaluation, policy enforcement, validation, regression testing, reporting, and release decisions into one workflow.

Instead of asking only:

> **"Did a security tool find something?"**

SecureForge asks:

> **"Based on the available security evidence, validation results, security requirements, risk, policy, and regression status — should this release PASS, require REVIEW, or be BLOCKED?"**

---

## 🎯 Why SecureForge?

Modern application security often produces fragmented results.

A development team may receive:

- SAST findings
- SCA findings
- Secret-scanning alerts
- API-security findings
- DAST findings
- Container findings
- IaC findings
- Manual penetration-testing evidence
- Regression results

The difficult part is not simply collecting those results.

The difficult part is turning them into a **consistent, explainable security decision**.

SecureForge is designed to provide that decision layer.

```text
Security Evidence
       ↓
Normalization
       ↓
Correlation
       ↓
Requirement Mapping
       ↓
Contextual Risk
       ↓
Policy Evaluation
       ↓
Validation / Regression
       ↓
Release Gate
       ↓
PASS / REVIEW / BLOCK
```

---

## 🧩 Core Capabilities

### Security Evidence Collection

SecureForge provides an integration architecture for security evidence from categories such as:

- SAST
- SCA
- Secret scanning
- API security
- DAST
- Container security
- IaC security
- Nmap
- Nessus
- Manual security validation

External security tools remain responsible for performing their specialized security testing.

SecureForge is responsible for processing their evidence and using it as part of the security-verification workflow.

### Finding Normalization

Different security tools produce different schemas, terminology, severity models, and evidence formats.

SecureForge converts supported results into a common finding representation.

A finding can contain information such as:

- Finding ID
- Title
- Source
- Asset
- Application
- Endpoint
- Parameter
- CWE
- OWASP mapping
- Security requirement
- Severity
- Confidence
- Evidence
- Description
- Impact
- Remediation
- Status
- Validation status
- First seen
- Last seen
- Regression test

### Finding Correlation

Multiple security tools can identify the same underlying weakness.

SecureForge can correlate related evidence so that one vulnerability is not incorrectly treated as multiple independent vulnerabilities.

```text
SAST
  ↓
Possible SQL Injection

DAST
  ↓
Possible SQL Injection

Manual Validation
  ↓
Confirmed SQL Injection

        ↓

Correlated Security Finding
```

Correlation can improve evidence quality, confidence, reporting, and release-decision accuracy.

### Security Requirements

Findings can be mapped to explicit security requirements.

Examples include:

- `SF-AUTH-001`
- `SF-AUTH-002`
- `SF-AUTHZ-001`
- `SF-AUTHZ-002`
- `SF-API-001`
- `SF-API-002`
- `SF-INPUT-001`
- `SF-SECRET-001`
- `SF-DEP-001`
- `SF-CONTAINER-001`
- `SF-IAC-001`
- `SF-TRANSPORT-001`
- `SF-REG-001`

This provides application-specific security meaning beyond a raw scanner finding.

### Contextual Risk Evaluation

SecureForge separates vulnerability severity from contextual security risk.

Risk evaluation can consider factors such as:

- Severity
- Confidence
- Asset importance
- Internet exposure
- Authentication requirements
- Sensitive-data exposure
- Exploit evidence
- Security requirements
- Environment

The objective is to make the reasoning behind a security decision understandable rather than relying on an opaque score.

### Policy Enforcement

The policy engine converts security conditions into explicit actions.

Policies can define:

- Blocking conditions
- Review conditions
- Passing conditions
- Exceptions
- Tool-execution requirements
- Regression requirements
- Security requirements

### Validation

Important findings can be validated before they influence the final security decision.

Validation can help establish:

- Whether a vulnerability is actually exploitable.
- Whether the affected component is reachable.
- Whether authentication or authorization controls work correctly.
- Whether the reported impact is accurate.
- Whether the evidence supports the finding.

### Security Regression Testing

Important security weaknesses can become repeatable regression tests.

The current SecureCommerce regression suite demonstrates:

- `BOLA-001`
- `SQLI-001`
- `XSS-001`
- `SECRET-001`
- `AUTHZ-001`
- `MISCONFIG-001`

This turns security fixes into repeatable verification rather than one-time testing.

### Release Gating

SecureForge produces a final release decision:

- `PASS`
- `REVIEW`
- `BLOCK`

The decision is based on the configured security policy and the available verification results.

---

## 🏗️ Architecture

SecureForge is organized as a verification pipeline rather than as a single scanner.

```text
┌─────────────────────────────────────────────────────┐
│                 Security Evidence                   │
│                                                     │
│ SAST │ SCA │ Secrets │ API │ DAST │ Container │ IaC │
│ Nmap │ Nessus │ Manual Validation │ Other Sources   │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                    Normalization                    │
│                                                     │
│        Tool Output → Common Finding Model           │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                     Correlation                     │
│                                                     │
│        Related Evidence → Unified Finding           │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│               Requirement Mapping                   │
│                                                     │
│       Finding → Security Requirement                │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                 Contextual Risk                     │
│                                                     │
│     Severity + Confidence + Application Context     │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                 Policy Evaluation                   │
│                                                     │
│          Evidence + Risk + Requirements             │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│          Validation / Regression Gates              │
└───────────────────────┬─────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│                   Release Gate                      │
│                                                     │
│             PASS / REVIEW / BLOCK                   │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 Target Independence

SecureForge is **not limited to SecureCommerce**.

The core framework is designed to work with different web and API applications through configuration, integrations, security requirements, and target-specific regression definitions.

### SecureCommerce

SecureCommerce is the project's deliberately vulnerable **reference and laboratory application**.

It exists to provide a controlled target for demonstrating and testing SecureForge.

### Other Targets

A different application can provide its own:

- Base URL
- API base URL
- OpenAPI specification
- Source path
- Container image
- Security integrations
- Security requirements
- Policy
- Regression suite

The important architectural distinction is:

> **SecureForge is the reusable verification framework. SecureCommerce is the reference target used to demonstrate it.**

The core security-verification pipeline is therefore not conceptually tied to a particular application.

Some regression tests are necessarily target-specific because they depend on application-specific endpoints, users, credentials, infrastructure, or expected behavior.

---

## 🧪 SecureCommerce

SecureCommerce is a deliberately vulnerable e-commerce application included as a controlled security-testing target.

It provides a realistic application environment for demonstrating the SecureForge lifecycle.

### Application Areas

The laboratory application includes functionality and scenarios involving:

- Registration
- Authentication
- Users and profiles
- Roles
- Products
- Orders
- REST APIs
- Database-backed functionality
- File handling
- External integrations
- Authentication and authorization controls

### Security Scenarios

The application provides controlled scenarios for security verification, including areas such as:

- Authentication
- Authorization
- BOLA / IDOR
- Function-level authorization
- SQL injection
- XSS
- API security
- SSRF
- File handling
- Secret exposure
- Dependency security
- Container security
- Infrastructure configuration

SecureCommerce is intentionally designed for authorized local laboratory testing.

---

## 🔐 Security Verification Lifecycle

SecureForge follows a repeatable security-verification lifecycle.

### Discover

Collect security evidence from configured sources.

### Normalize

Convert tool-specific results into the SecureForge finding model.

### Correlate

Identify related evidence that represents the same underlying security issue.

### Map

Associate findings with relevant security requirements and classifications.

### Validate

Determine whether important findings are supported by sufficient evidence.

### Prioritize

Evaluate security risk using severity, confidence, and application context.

### Remediate

Provide information necessary to address the underlying security issue.

### Retest

Verify that remediation actually addressed the vulnerability.

### Prevent Recurrence

Convert important security weaknesses into repeatable regression tests.

### Release Gate

Use the resulting evidence, risk, requirements, validation, and policy to produce:

```text
PASS
REVIEW
BLOCK
```

---

## 🚦 Release Decisions

### PASS

The configured security policy does not identify a blocking or review condition, and the required verification conditions have passed.

### REVIEW

The release requires human security review before it should proceed.

`REVIEW` is not equivalent to automatic security approval.

### BLOCK

A configured security condition requires the release to stop.

Examples can include:

- Confirmed critical vulnerabilities
- Confirmed high-impact authorization vulnerabilities
- Unsatisfied mandatory security requirements
- Failed security regression tests
- Required security integrations failing to execute
- Other explicitly configured blocking conditions

---

## 📋 Security Requirements

SecureForge uses a requirement registry to represent application-security expectations.

Current requirement identifiers include:

```text
SF-AUTH-001
SF-AUTH-002
SF-AUTHZ-001
SF-AUTHZ-002
SF-API-001
SF-API-002
SF-INPUT-001
SF-SECRET-001
SF-DEP-001
SF-CONTAINER-001
SF-IAC-001
SF-TRANSPORT-001
SF-REG-001
```

A security finding can therefore identify not only **what is wrong**, but also **which security requirement is affected**.

---

## 🧩 Finding Model

A normalized finding can contain:

- Finding ID
- Title
- Source
- Asset
- Application
- Endpoint
- Parameter
- CWE
- OWASP mapping
- Security requirement
- Severity
- Confidence
- Evidence
- Description
- Impact
- Remediation
- Status
- Validation status
- First seen
- Last seen
- Regression test

### Example

```text
Finding ID: SF-0012
Title: BOLA on GET /api/orders/{id}
CWE: CWE-639
OWASP: API1
Requirement: SF-AUTHZ-001
Severity: High
Confidence: Confirmed
Evidence: User A accessed User B's order
Regression Test: BOLA-001
```

---

## 🔄 Security Integrations

SecureForge uses an integration architecture for incorporating security evidence from different sources.

### Application Security

Integration categories include:

- SAST
- SCA
- Secret scanning
- API security
- DAST
- Container security
- IaC security

### Infrastructure Security

Integration categories include:

- Nmap
- Nessus
- Infrastructure configuration analysis
- Container security

### Manual Security Validation

External security tools can also support manually validated evidence.

Examples include:

- Burp Suite Professional
- Wireshark
- Metasploit
- Manual testing

External tools are evidence producers. SecureForge provides the processing, verification, policy, and release-decision layer.

Specific external tools must be installed and configured in the environment before they can execute successfully.

---

## 🕷️ Burp Suite

Burp Suite can be used for authorized manual web and API security testing.

Potential evidence includes:

- BOLA validation
- Authorization testing
- SQL injection validation
- XSS validation
- Session testing
- API security testing

SecureForge does not attempt to replace Burp Suite.

Instead, validated Burp evidence can participate in the SecureForge security-verification workflow.

---

## 🌐 Nmap and Nessus

### Nmap

Nmap can provide authorized attack-surface and service-discovery evidence such as:

- Open ports
- Services
- Service versions
- Unexpected exposed services

### Nessus

Nessus can provide vulnerability-assessment evidence for infrastructure and exposed services.

Relevant Nessus results can be incorporated into SecureForge when the integration is configured and the tool is available.

---

## 📡 Wireshark

Wireshark can provide manual network-level evidence for situations such as:

- Unexpected network communication
- Cleartext traffic
- Protocol behavior
- Security-control verification
- Network-level investigation of application behavior

SecureForge does not replace Wireshark.

---

## 💥 Metasploit

Metasploit can be used for controlled vulnerability validation in an authorized laboratory environment.

SecureForge does not replace Metasploit.

Where appropriate, validated Metasploit evidence can strengthen the evidence supporting a security finding.

---

## 📚 Security Standards

SecureForge can map security findings and requirements to recognized security classifications and standards where appropriate.

### OWASP Top 10

Application security findings can be mapped to relevant OWASP Top 10 categories.

### OWASP API Security Top 10

API-related findings can be mapped to relevant OWASP API Security Top 10 categories.

### OWASP ASVS

Security requirements can reference relevant ASVS controls.

SecureForge does **not** claim complete ASVS compliance. Only the requirements represented and implemented by the project are within its verification scope.

### CWE

Findings can be mapped to relevant Common Weakness Enumeration identifiers.

### CVSS

CVSS can be used where an appropriate vulnerability-severity representation is required.

CVSS severity and SecureForge contextual risk are treated as related but distinct concepts.

---

## 🧪 Regression Testing

SecureForge includes a regression framework for repeatable security verification.

### Current SecureCommerce Regression Suite

| Test | Area | Purpose |
|---|---|---|
| `BOLA-001` | Authorization | Verify object-level authorization |
| `SQLI-001` | Injection | Verify SQL injection behavior |
| `XSS-001` | Input / Output | Verify contextual output handling |
| `SECRET-001` | Secrets | Verify secret-detection behavior |
| `AUTHZ-001` | Authorization | Verify function-level authorization |
| `MISCONFIG-001` | IaC | Verify infrastructure security controls |

Regression results can influence the final release decision according to the configured policy.

---

## 🔄 CI/CD Security Gate

SecureForge can be integrated into CI/CD workflows.

A typical workflow is:

```text
Developer Push
      ↓
GitHub Actions
      ↓
SecureForge
      ↓
Security Evidence
      ↓
Normalization
      ↓
Correlation
      ↓
Risk Evaluation
      ↓
Policy Evaluation
      ↓
Regression / Validation
      ↓
PASS / REVIEW / BLOCK
```

A `BLOCK` result can be used as a CI/CD release gate.

---

## 📊 Reporting

SecureForge produces security-verification results that can be consumed by humans and automation.

Example report formats include:

- JSON
- HTML

Reports can contain:

- Scan information
- Application information
- Version
- Environment
- Findings
- Risk
- Policy evaluation
- Tool errors
- Validation results
- Regression results
- Release decision
- Timestamps

The reporting layer is intended to preserve the reasoning behind the final security decision.

---

## 🖥️ CLI

SecureForge provides a command-line interface for security verification.

### Scan

```bash
python -m secureforge.cli.main scan
```

### Scan With a Profile

```bash
python -m secureforge.cli.main scan --profile quick
python -m secureforge.cli.main scan --profile standard
python -m secureforge.cli.main scan --profile full
```

### Scan With Regression Testing

```bash
python -m secureforge.cli.main scan \
  --profile standard \
  --regression \
  --regression-suite requirements/regression-tests.yaml
```

Additional target, source, output, and regression configuration can be supplied through the available CLI options.

---

## ⚙️ Configuration

SecureForge separates framework behavior from target configuration.

A target configuration can define information such as:

```yaml
project:
  name: securecommerce
  application: SecureCommerce
  environment: lab
  version: "0.1.0"

scan:
  profile: standard

target:
  base_url: "http://localhost:5000"
  api_base_url: "http://localhost:5000/api"
  openapi_url: "http://localhost:5000/openapi.json"
  source_path: "./vulnerable-app/securecommerce"
  container_image: "securecommerce:latest"
```

Integrations, policies, requirements, reporting paths, and logging can also be configured.

This separation allows the same core framework to operate against different targets without embedding target-specific values throughout the application.

---

## 📁 Project Structure

```text
SecureForge/
├── README.md
├── secureforge/
│   ├── cli/
│   ├── core/
│   │   ├── findings/
│   │   ├── normalization/
│   │   ├── correlation/
│   │   ├── risk/
│   │   ├── policy/
│   │   └── requirements/
│   ├── integrations/
│   │   ├── sast/
│   │   ├── sca/
│   │   ├── secrets/
│   │   ├── api/
│   │   ├── dast/
│   │   ├── container/
│   │   ├── iac/
│   │   ├── nessus/
│   │   ├── nmap/
│   │   └── manual/
│   ├── validation/
│   ├── regression/
│   ├── reporting/
│   └── config/
├── tests/
├── policies/
├── requirements/
├── vulnerable-app/
│   └── securecommerce/
├── lab/
├── reports/
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   ├── methodology/
│   └── security-requirements/
└── .github/
    └── workflows/
```

---

## 🧰 Technology Stack

### Core

- Python
- Pydantic
- Typer
- Pytest
- YAML-based configuration

### Target Application

- Python
- Flask
- REST/OpenAPI
- Database-backed application

### Infrastructure

- Docker
- Terraform
- GitHub Actions
- Linux
- Git

### Security Tooling

SecureForge is designed to integrate with security tooling such as:

- Burp Suite Professional
- Nmap
- Nessus
- Wireshark
- Metasploit
- SAST tools
- SCA tools
- DAST tools
- Secret scanners
- Container security tools
- API security tools
- IaC security tools

The availability and execution state of external tools depends on the local environment.

---

## 🧪 Testing Strategy

SecureForge uses multiple levels of testing.

### Unit Testing

Individual components are tested independently, including areas such as:

- Finding models
- Normalization
- Policy evaluation
- Requirement loading
- Configuration
- Release-gate behavior

### Integration Testing

Integration tests verify interactions between components such as:

- Security integrations
- Evidence processing
- Normalization
- Runtime configuration
- Policy evaluation
- Reporting
- Regression execution

### End-to-End Testing

End-to-end verification tests the framework against SecureCommerce as a real local target.

This validates the interaction between the application, SecureForge runtime, regression framework, policy engine, reporting, and release gate.

### Regression Testing

Security regression tests verify that previously addressed security weaknesses remain addressed.

Regression failures can influence the release decision according to policy.

---

## ✅ Verified End-to-End Result

SecureForge has been exercised against the local SecureCommerce application using the standard verification profile and regression suite.

The verified regression result was:

```text
Regression Tests: 6
Passed:           6
Failed:           0
Errors:           0
Skipped:          0

Regression Gate:  PASS
```

The six regression tests all passed.

The overall release decision was nevertheless:

```text
Overall Decision: BLOCK
Release Allowed:  False
```

The reason was that several configured external security integrations were unavailable in the local environment.

The configured policy requires security integrations to execute successfully.

Therefore, SecureForge correctly distinguished:

```text
Regression Tests
      ↓
      PASS
      ↓
Policy Evaluation
      ↓
Required Tool Errors
      ↓
Overall Release
      ↓
     BLOCK
```

This is an important demonstration of the release-gating model:

> **A successful regression suite does not automatically mean that the release is allowed. The final decision considers the complete configured security-verification state.**

---

## 🧾 Evidence and Reproducibility

Security decisions should be supported by evidence.

SecureForge is designed to make the reasoning behind a release decision traceable.

A verification result should make it possible to understand:

- What was tested
- Which integrations were configured
- Which tools executed
- Which tools failed
- What findings were produced
- Which findings were validated
- Which requirements were affected
- How risk was evaluated
- Which policy was applied
- Which regression tests passed or failed
- Why the final release decision was produced

SecureForge is intentionally designed around evidence rather than fabricated or unsupported security conclusions.

---

## 📐 Design Principles

### Evidence Over Assumption

Security decisions should be based on available evidence rather than assumptions.

### Validation Over Blind Trust

Important findings should be validated before being treated as confirmed vulnerabilities.

### Correlate Before Prioritizing

Related evidence should be correlated before security risk is evaluated.

### Context Over Severity Alone

Severity matters, but practical risk also depends on application and environment context.

### Policies Must Be Explicit

Release decisions should be based on understandable and reviewable policy.

### Fixes Must Be Verified

A security fix should be verified rather than assumed to be effective.

### Security Fixes Should Become Regression Controls

Important vulnerabilities should be converted into repeatable regression tests where appropriate.

### Mature Tools Should Be Reused

SecureForge integrates established security tools instead of unnecessarily rebuilding their specialized capabilities.

### Security Decisions Should Be Explainable

A release decision should be traceable to evidence, requirements, risk, policy, validation, and regression results.

---

## 🚫 Scope Boundaries

SecureForge intentionally focuses on security verification and release gating for web and API applications.

It is not intended to become:

- A full enterprise vulnerability-management platform
- A SIEM
- A SOC platform
- A complete cloud-security platform
- A replacement for Burp Suite
- A replacement for Nessus
- A replacement for Nmap
- A replacement for Metasploit
- A replacement for mature SAST/SCA/DAST tooling
- A generic automated exploitation framework

This deliberate scope keeps SecureForge focused on its primary problem:

> **Turning security evidence into an explainable release decision.**

---

## 🔒 Authorized Use

SecureForge and SecureCommerce are intended for:

- Authorized security testing
- Controlled laboratory environments
- Defensive security research
- Legitimate application-security validation

Do not use SecureForge, SecureCommerce, or integrated security tools against systems or applications without explicit authorization.

---

## 📄 License

This project is licensed under the MIT License.
