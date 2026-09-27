# 🖥️ SecureForge CLI

* The SecureForge CLI is the primary command-line interface for running security verification workflows.
* It connects the core SecureForge components into a practical, repeatable workflow.
* The CLI is intentionally designed to be understandable during local development, CI/CD execution, and security testing.

## Purpose

* The CLI should allow a security engineer or developer to:

  * Run security verification.
  * Select a verification profile.
  * Validate findings.
  * Evaluate policies.
  * Run regression tests.
  * Generate reports.
  * Inspect results.
  * Understand why a release was allowed or blocked.

## CLI Philosophy

* The CLI should be:

  * Simple
  * Predictable
  * Scriptable
  * Explainable
  * Testable
  * CI/CD friendly
  * Safe by default

* The CLI should expose SecureForge functionality without forcing users to understand the internal Python architecture.

## Command Model

```text id="c3k7vx"
secureforge
    ↓
Command
    ↓
Core Workflow
    ↓
Security Evidence
    ↓
Evaluation
    ↓
Decision
    ↓
Report
```

## Primary Commands

* SecureForge should initially provide:

```text id="p8w2kn"
secureforge scan
secureforge report
secureforge policy check
secureforge regression
secureforge validate
```

* Additional commands may be added when implementation requires them.

## `secureforge scan`

* The `scan` command runs the configured security verification workflow.

* Example:

```bash
secureforge scan
```

* The command should:

  * Load configuration.
  * Identify the selected profile.
  * Execute enabled integrations.
  * Collect evidence.
  * Normalize findings.
  * Correlate findings.
  * Evaluate risk.
  * Evaluate policy.
  * Execute relevant regression tests.
  * Produce the release decision.
  * Generate reports.

## Scan Profiles

* The scan command should support verification profiles.

* Example:

```bash
secureforge scan --profile quick
```

```bash
secureforge scan --profile standard
```

```bash
secureforge scan --profile full
```

* Profiles should control which verification stages are executed.

## Quick Profile

```text id="q6s3md"
SAST
  +
SCA
  +
Secret Detection
```

* The quick profile is intended for fast developer feedback.

## Standard Profile

```text id="v2k8pr"
Quick
  +
API Security
  +
DAST
  +
Container Security
```

* The standard profile provides broader application and deployment verification.

## Full Profile

```text id="h5n7wx"
Standard
   +
IaC Security
   +
Nmap
   +
Nessus
   +
Manual Validation
```

* The full profile is intended for broader controlled security verification.

## Scan Options

* The CLI may support options such as:

```bash
secureforge scan \
  --profile standard \
  --config secureforge.yml \
  --target http://localhost:8000
```

* Options should remain focused on practical execution rather than exposing every internal implementation detail.

## Configuration

* SecureForge should support a configuration file.

* Example:

```yaml id="j4m8tz"
project:
  name: SecureCommerce

scan:
  profile: standard

target:
  base_url: http://localhost:8000

report:
  directory: reports/

policy:
  file: policies/default.yml
```

* Configuration should not contain real credentials.

## Configuration Precedence

* Where configuration can be supplied from multiple sources, precedence should be deterministic.

* A practical model is:

```text id="n7c2qp"
CLI Arguments
      ↓
Environment Variables
      ↓
Configuration File
      ↓
Default Values
```

* Explicit user input should override lower-priority configuration.

## `secureforge report`

* The `report` command generates or displays security reports from an evaluation result.

* Example:

```bash
secureforge report
```

* It may support:

```bash
secureforge report --format json
```

```bash
secureforge report --format html
```

* The report command should not silently fabricate a new security evaluation when only reporting is requested.

## `secureforge policy check`

* The `policy check` command evaluates findings and risk against the configured security policy.

* Example:

```bash
secureforge policy check
```

* The command should explain:

  * Policy loaded
  * Findings evaluated
  * Blocking conditions
  * Review conditions
  * Exceptions
  * Final policy decision

## Policy Example

```text id="k9m3vx"
Findings
   ↓
Risk Evaluation
   ↓
Policy
   ↓
BLOCK
```

* Example output:

```text
Policy Decision: BLOCK

Blocking Conditions:
- 1 confirmed high-risk finding
- 1 failed security regression test
```

## `secureforge regression`

* The `regression` command executes registered security regression tests.

* Example:

```bash
secureforge regression
```

* A specific test may be selected:

```bash
secureforge regression --test BOLA-001
```

* The command should report:

  * Tests executed
  * Tests passed
  * Tests failed
  * Tests blocked
  * Related findings
  * Evidence

## Regression Output

```text id="r4j8qs"
Regression Tests
────────────────
BOLA-001       PASS
SQLI-001       PASS
XSS-001        FAIL

Result:
FAIL
```

* A failed security regression should be available to the release-gate workflow.

## `secureforge validate`

* The `validate` command supports controlled validation of findings.

* Example:

```bash
secureforge validate --finding SF-0012
```

* Validation may use:

  * Automated checks
  * Existing evidence
  * Manual validation workflows
  * External security tools

* The command should preserve validation evidence.

## Validation Output

```text id="m2v7ck"
Finding:
SF-0012

Validation:
CONFIRMED

Evidence:
User A accessed User B's order

Requirement:
SF-AUTHZ-001
```

## Command Exit Codes

* Exit codes allow SecureForge to integrate with automation.

* The implementation should define stable exit semantics.

* Conceptually:

```text id="w6q4ns"
PASS
  ↓
Success Exit

REVIEW
  ↓
Configured Review Exit

BLOCK
  ↓
Non-zero Exit
```

* Tool execution failures should have distinguishable exit behavior where practical.

## Example CI Behavior

```text id="u8p5mr"
GitHub Actions
      ↓
secureforge scan --profile standard
      ↓
Release Decision
      ↓
PASS → Continue
BLOCK → Fail Job
```

* The exact exit-code mapping should be documented and tested.

## Human-Readable Output

* The default CLI output should be concise but useful.

* Example:

```text
SecureForge Security Verification

Application: SecureCommerce
Profile:     standard

Findings:
  Critical: 0
  High:     2
  Medium:   3
  Low:      1

Regression:
  Passed:  8
  Failed:  1

Decision:
  BLOCK

Reason:
  Confirmed high-risk authorization finding.
```

## Verbose Output

* A verbose option may provide additional execution details.

* Example:

```bash
secureforge scan --profile standard --verbose
```

* Verbose output may include:

  * Integration execution
  * Tool status
  * Adapter status
  * Parsing information
  * Finding correlation
  * Risk factors
  * Policy evaluation

## Quiet Output

* CI/CD systems may require minimal output.

* Example:

```bash
secureforge scan --quiet
```

* Quiet mode should still provide the final result and appropriate exit status.

## Output Formats

* The CLI should support structured output where practical.

* Example:

```bash
secureforge scan --output json
```

* Supported formats may include:

  * `text`
  * `json`

* HTML should primarily be generated by the reporting layer.

## Dry Run

* A dry-run mode may allow users to inspect the planned workflow without executing security tools.

* Example:

```bash
secureforge scan --profile full --dry-run
```

* Example output:

```text
Planned Verification

✓ SAST
✓ SCA
✓ Secret Detection
✓ API Security
✓ DAST
✓ Container Security
✓ IaC Security
✓ Nmap
✓ Nessus

No tools executed.
```

## Target Validation

* The CLI should validate target configuration before running active security checks.

* Example:

```text id="a7r3yx"
Target:
http://localhost:8000

Target Validation:
PASS
```

* Invalid or missing targets should produce actionable errors.

## Safe Defaults

* SecureForge should default to controlled and explicitly configured targets.
* The CLI should not silently scan arbitrary external systems.
* Active security integrations should require clear target configuration.
* Lab and development environments should be the primary implementation target.

## Error Handling

* CLI errors should explain:

  * What failed.
  * Which component failed.
  * Whether security evaluation completed.
  * What the user can do next.

* Poor example:

```text
Error
```

* Better example:

```text
SecureForge could not execute the DAST integration.

Reason:
Required scanner executable was not found.

Action:
Install the configured scanner or disable the integration
for this verification profile.
```

## Missing Integration

* Missing optional tools should not produce ambiguous results.

```text id="f3v7kx"
DAST
 ↓
Tool Not Installed
 ↓
Integration Status:
UNAVAILABLE
```

* The policy engine should determine whether unavailable evidence causes `REVIEW`, `BLOCK`, or another configured result.

## Logging

* CLI execution should provide useful logs without exposing secrets.

* Logs may contain:

  * Command
  * Integration
  * Start time
  * End time
  * Result
  * Finding count
  * Errors

* Credentials and tokens must not be logged.

## CLI Configuration Validation

* The CLI should validate configuration before starting a security workflow.

* Validation should detect:

  * Invalid profile
  * Missing configuration
  * Invalid target
  * Invalid policy
  * Unsupported integration
  * Invalid report path
  * Malformed configuration

## Help System

* Every command should provide help.

* Example:

```bash
secureforge --help
```

```bash
secureforge scan --help
```

```bash
secureforge regression --help
```

* Help should explain required arguments and practical examples.

## Version Command

* SecureForge should expose its version.

```bash
secureforge --version
```

* Example:

```text
SecureForge 0.1.0
```

* Version information should be consistent with the package metadata.

## Command Architecture

* The CLI should remain separate from the security-engine implementation.

```text id="c5v9pn"
CLI
 ↓
Command Handler
 ↓
Application Service
 ↓
Core SecureForge Components
 ↓
Result
```

* This prevents business logic from becoming tightly coupled to command-line parsing.

## Suggested Implementation Structure

```text id="z8m4qy"
secureforge/
└── cli/
    ├── __init__.py
    ├── main.py
    ├── commands/
    │   ├── scan.py
    │   ├── report.py
    │   ├── policy.py
    │   ├── regression.py
    │   └── validate.py
    ├── output.py
    └── errors.py
```

* The exact structure may evolve during implementation.

## CLI Testing

* The CLI should be tested for:

  * Command discovery
  * Argument parsing
  * Configuration loading
  * Invalid arguments
  * Profile selection
  * Exit codes
  * Output formatting
  * Error handling
  * Dry-run behavior
  * Missing integrations
  * Policy results

## Integration Testing

* CLI integration tests should verify that commands correctly invoke the underlying SecureForge workflows.

```text id="d3k8vx"
CLI Command
     ↓
Application Service
     ↓
Mock / Controlled Integration
     ↓
Evaluation
     ↓
Expected CLI Result
```

## End-to-End CLI Example

* A complete local workflow should eventually look similar to:

```bash
secureforge scan --profile standard
```

```text
SecureForge
    ↓
Load Configuration
    ↓
Run Security Integrations
    ↓
Collect Evidence
    ↓
Normalize
    ↓
Correlate
    ↓
Evaluate Risk
    ↓
Run Regression Tests
    ↓
Evaluate Policy
    ↓
Generate Reports
    ↓
PASS / REVIEW / BLOCK
```

## Example SecureCommerce Workflow

```bash
secureforge scan \
  --profile standard \
  --target http://localhost:8000
```

* Expected behavior in the deliberately vulnerable lab may include:

  * Security tools identify controlled weaknesses.
  * Findings are normalized.
  * Duplicate evidence is correlated.
  * Risk is calculated.
  * Policy evaluates the results.
  * Regression tests execute.
  * A report is generated.
  * The CLI displays the final decision.

* Actual results should always come from the executed lab rather than being hardcoded.

## CLI and Reporting

* The CLI should delegate report generation to the reporting layer.

```text id="n3y8kq"
CLI
 ↓
Evaluation Result
 ↓
Reporting Layer
 ↓
security-report.json
security-report.html
```

* The CLI should display the location of generated reports.

## CLI and CI/CD

* The CLI is intentionally designed to work in CI/CD environments.

```text id="g6p2rm"
GitHub Actions
      ↓
secureforge scan
      ↓
Exit Code
      ↓
Workflow Decision
```

* This makes the CLI the practical bridge between SecureForge and release automation.

## Design Principles

* SecureForge CLI should:

  * Keep commands simple.
  * Keep security logic outside command handlers.
  * Produce deterministic results where possible.
  * Support automation.
  * Provide useful human-readable output.
  * Provide machine-readable output.
  * Use meaningful exit codes.
  * Fail clearly.
  * Protect sensitive information.
  * Avoid unsafe target defaults.

## What Comes Next

* The next component is **CI/CD Integration**.
* It will define how SecureForge runs automatically inside GitHub Actions and how its release decision controls the pipeline.
* After the remaining architecture documentation is complete, implementation should begin with the actual Python package and runnable SecureForge CLI rather than continuing indefinitely with documentation.
