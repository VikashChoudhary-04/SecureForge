# ⚖️ SecureForge Risk Engine

## 🎯 Purpose

* The SecureForge risk engine evaluates the practical security importance of a finding using both vulnerability characteristics and application context.
* It does not replace vulnerability severity.
* Instead, it adds context to help answer:

  * How important is this finding in this environment?
  * How confident are we that the vulnerability exists?
  * What assets are affected?
  * Is the affected service exposed?
  * Does sensitive data exist behind the vulnerable functionality?
  * Does the finding violate a mandatory security requirement?
  * Does the evidence demonstrate actual exploitability?

## 🧠 Risk Philosophy

* SecureForge separates:

  * **Severity**
  * **Confidence**
  * **Context**
  * **Risk**
  * **Policy**

* These concepts answer different questions.

### Severity

* How serious would the vulnerability be if it exists?

### Confidence

* How strongly does the available evidence support the vulnerability?

### Context

* Where does the vulnerability exist and what does it affect?

### Risk

* What is the practical security significance of the finding in this environment?

### Policy

* What action should be taken because of the resulting security condition?

## 🔄 Risk Evaluation Flow

```text id="h0h9wi"
          Normalized Finding
                  ↓
             Validation
                  ↓
          Severity Assessment
                  ↓
        Confidence Assessment
                  ↓
          Asset Context
                  ↓
        Exposure Assessment
                  ↓
       Sensitive Data Context
                  ↓
       Security Requirement
                  ↓
           Risk Evaluation
                  ↓
        Contextual Risk Result
                  ↓
            Policy Engine
```

## 🧩 Risk Inputs

* The risk engine can evaluate several explicit inputs.

### Severity

* Severity can be:

  * `Critical`
  * `High`
  * `Medium`
  * `Low`
  * `Informational`

* Severity should remain separate from contextual risk.

### Confidence

* Confidence represents the strength of the evidence.

* Example values:

  * `Low`
  * `Medium`
  * `High`
  * `Confirmed`

* A critical finding with low confidence should not automatically be treated the same as a confirmed critical vulnerability.

### Asset Importance

* Assets can have different importance levels.

* Example:

  * `Critical`
  * `High`
  * `Medium`
  * `Low`

* Example assets:

  * Authentication service.
  * Order API.
  * Administrative API.
  * Public product catalog.
  * Development-only endpoint.

### Internet Exposure

* Exposure can influence practical risk.

* Example values:

  * `Internet`
  * `Internal`
  * `Restricted`
  * `Local`

* A vulnerability exposed directly to the internet may require different treatment from the same weakness inside an isolated laboratory network.

### Authentication Requirement

* The risk engine can consider whether exploitation requires:

  * No authentication.
  * Normal user authentication.
  * Privileged authentication.
  * Administrative access.

### Sensitive Data

* The engine can consider whether the affected functionality handles sensitive information.
* Examples:

  * Credentials.
  * Personal information.
  * Orders.
  * Authentication tokens.
  * Secrets.
  * Financial information.

### Exploit Evidence

* Exploit evidence indicates how strongly the available evidence demonstrates actual exploitation.
* Example values:

  * `None`
  * `Suspected`
  * `Demonstrated`
  * `Confirmed`

### Security Requirement

* A finding that violates an important security requirement can receive additional risk significance.
* Example:

  * `SF-AUTHZ-001`

### Environment

* The same vulnerability can have different implications depending on the environment.
* Examples:

  * Development.
  * Testing.
  * Staging.
  * Production.

## ⚖️ Contextual Risk Model

* SecureForge should use a transparent and understandable model rather than an opaque formula.
* A conceptual model can be represented as:

```text id="o5qf0f"
             Severity
                +
            Confidence
                +
          Asset Context
                +
        Exposure Context
                +
       Data Sensitivity
                +
        Exploit Evidence
                +
     Requirement Importance
                ↓
         Contextual Risk
```

* The exact implementation can use explicit rules or a bounded scoring mechanism.
* The reasoning behind the result should remain visible.

## 🧮 Example Risk Representation

```yaml id="n5h7sc"
risk:
  severity: High
  confidence: Confirmed
  asset_importance: High
  exposure: Internet
  authentication_required: authenticated_user
  sensitive_data: true
  exploit_evidence: demonstrated
  security_requirement: SF-AUTHZ-001
  contextual_risk: High
```

* This is more informative than simply storing:

  * `risk_score: 9.2`

## 🛡️ Mandatory Requirements

* Security requirements can influence risk independently of raw severity.
* Example:

  * `SF-AUTHZ-001` is mandatory.
  * A confirmed BOLA violates the requirement.
  * The finding therefore represents a direct security-control failure.
* The policy engine can use this condition to determine whether the release must be blocked.

## 🔍 Risk and Validation

* Validation can significantly change the interpretation of a finding.

### Before Validation

```text id="u7g5v8"
Scanner Finding
     ↓
High Severity
     ↓
Medium Confidence
     ↓
Needs Validation
```

### After Validation

```text id="j8t7ap"
Manual Validation
       ↓
Confirmed Vulnerability
       ↓
High Severity
       ↓
High Confidence
       ↓
Higher Contextual Risk
```

* Validation should therefore be able to update the risk inputs.

## 🧪 Example: BOLA

* Finding:

  * BOLA on `GET /api/orders/{id}`.

* Severity:

  * High.

* Confidence:

  * Confirmed.

* Asset:

  * Production order API.

* Exposure:

  * Internet.

* Authentication:

  * Normal authenticated user.

* Sensitive data:

  * Order information.

* Requirement:

  * `SF-AUTHZ-001`.

* Exploit evidence:

  * Demonstrated.

* The combination of these factors can produce a high contextual-risk result.

## 🧪 Example: Development-Only Finding

* Finding:

  * Vulnerable dependency.

* Severity:

  * High.

* Confidence:

  * High.

* Asset:

  * Development-only service.

* Exposure:

  * Local.

* Sensitive data:

  * None.

* Environment:

  * Development.

* The contextual risk can differ from an equivalent vulnerability affecting an internet-facing production service.

## 🧪 Example: Low-Confidence Critical Finding

* Finding:

  * Potential remote code execution.

* Severity:

  * Critical.

* Confidence:

  * Low.

* Evidence:

  * Static scanner result only.

* Exploit evidence:

  * None.

* The vulnerability may require immediate investigation because the potential impact is severe.

* However, the low confidence should remain visible rather than pretending that exploitation has been confirmed.

## 🔗 Risk and Correlation

* Correlation should occur before final risk evaluation where practical.
* Multiple tool findings representing one vulnerability should not independently inflate the risk.

```text id="3e3k7k"
SAST Finding
      ↓
DAST Finding
      ↓
Burp Finding
      ↓
Correlation
      ↓
One Unified Finding
      ↓
Risk Evaluation
```

* Multiple evidence sources can increase confidence without creating multiple copies of the same risk.

## 📊 Risk Categories

* SecureForge can represent contextual risk using understandable categories:

  * `Critical`
  * `High`
  * `Medium`
  * `Low`
  * `Informational`

* The exact thresholds should be defined explicitly in configuration or policy.

## 🧩 Risk Factors

* Risk factors should be individually inspectable.

### Positive Risk Factors

* Internet exposure.
* High-value asset.
* Sensitive data.
* Demonstrated exploitation.
* Confirmed vulnerability.
* Mandatory security requirement violation.
* Privileged functionality exposure.

### Reducing Context

* Isolated development environment.

* Restricted network access.

* No sensitive data.

* Low asset importance.

* Unconfirmed finding.

* No demonstrated exploitability.

* These factors should influence the contextual interpretation without hiding the underlying severity.

## 🚦 Risk and Policy

* Risk does not directly equal the release decision.
* The policy engine uses risk and other conditions to determine the required action.

```text id="5g5i2x"
Finding
   ↓
Validation
   ↓
Contextual Risk
   ↓
Policy
   ↓
PASS / REVIEW / BLOCK
```

* This separation allows organizations to change release policy without rewriting the risk engine.

## 🧾 Risk Explanation

* Every risk result should be explainable.
* Example:

```yaml id="1xxf1p"
risk_explanation:
  result: High
  reasons:
    - confirmed_vulnerability
    - high_severity
    - internet_exposed
    - sensitive_data
    - demonstrated_exploit
    - mandatory_requirement_violation
```

* A reviewer should be able to understand why the risk was classified as high.

## 🧪 Risk Engine Testing

* The risk engine should be tested using controlled scenarios.

### High-Impact Confirmed Vulnerability

* Confirmed.
* High severity.
* Internet exposed.
* Sensitive data.
* Expected:

  * High contextual risk.

### Low-Confidence High Severity

* High severity.
* Low confidence.
* No exploit evidence.
* Expected:

  * Risk reflects the uncertainty.

### Isolated Development Vulnerability

* High severity.
* High confidence.
* Local development environment.
* No sensitive data.
* Expected:

  * Context affects the resulting risk.

### Mandatory Requirement Violation

* Confirmed vulnerability.
* Mandatory security requirement violated.
* Expected:

  * Risk representation identifies the requirement violation.

## 📈 Risk Metrics

* SecureForge can track:

  * Findings by severity.
  * Findings by contextual risk.
  * Confirmed findings.
  * High-risk findings.
  * Requirement violations.
  * Internet-exposed findings.
  * Sensitive-data findings.
  * Exploitation-confirmed findings.
  * Risk changes after remediation.

## 🔄 Risk History

* Risk should be traceable across releases where practical.

* Example:

  * Release A:

    * High contextual risk.
  * Release B:

    * Vulnerability remediated.
  * Release C:

    * Regression failure.
  * Release D:

    * Fix restored and verified.

* Historical risk information can help explain why release decisions changed over time.

## 🧠 Risk Principles

### Severity Is Not Risk

* Severity describes the seriousness of a vulnerability.
* Risk considers the vulnerability in context.

### Confidence Must Remain Visible

* A serious vulnerability with weak evidence should not be represented as confirmed without validation.

### Context Matters

* Asset importance, exposure, data sensitivity, and environment can change practical risk.

### Evidence Supports Risk

* Risk decisions should be traceable to evidence.

### Correlation Comes First

* Related evidence should be combined before duplicate findings influence risk.

### Requirements Matter

* Violations of important security requirements should be explicitly represented.

### Risk Must Be Explainable

* A reviewer should understand why a finding received its contextual risk classification.

### Policy Is Separate

* The risk engine evaluates risk.
* The policy engine determines what action the organization should take.

## 📁 Suggested Structure

```text id="2drk6g"
secureforge/
└── core/
    └── risk/
        ├── engine.py
        ├── factors.py
        ├── models.py
        ├── explanations.py
        └── tests/
```

* The risk engine should remain separate from:

  * Tool adapters.
  * Correlation.
  * Reporting.
  * CLI handling.
  * Policy execution.

## ➡️ What Comes Next

* The next section focuses on the SecureForge policy engine.
* It defines how explicit security policies convert findings, risk, requirement violations, regression failures, and exceptions into `PASS`, `REVIEW`, or `BLOCK`.
