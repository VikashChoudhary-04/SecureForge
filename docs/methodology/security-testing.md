# SecureForge Security Testing Methodology

## Purpose

- SecureForge combines multiple security-testing techniques into one verification workflow.
- The objective is to evaluate the application from different security perspectives rather than depending on a single scanner.
- Each testing technique contributes evidence to the same security-verification pipeline.

## Testing Lifecycle

- SecureForge follows this practical lifecycle:
	- Define scope
	- Identify assets
	- Collect source and configuration evidence
	- Perform automated security checks
	- Analyze application behavior
	- Validate important findings
	- Assess contextual risk
	- Apply security policy
	- Retest remediation
	- Execute regression tests
	- Produce release decision

## Testing Scope

- Security testing should explicitly define:
	- Application
	- Version
	- Environment
	- Source path
	- Target URL
	- API specification
	- Network scope
	- Security tools
	- Validation methods
	- Release profile

## Application Security Testing

- Application security testing evaluates security controls implemented by the application.
- Areas include:
	- Authentication
	- Authorization
	- Session management
	- Input validation
	- Output encoding
	- File handling
	- API security
	- Error handling
	- Security configuration

## Authentication Testing

- Authentication testing verifies that users must correctly authenticate before accessing protected functionality.
- Tests may include:
	- Missing authentication
	- Weak authentication controls
	- Session handling
	- Authentication bypass
	- Credential handling
- SecureForge should record evidence rather than assuming that an authentication mechanism is secure because a login endpoint exists.

## Authorization Testing

- Authorization testing verifies whether authenticated users can perform only permitted actions.
- Important scenarios include:
	- Horizontal privilege escalation
	- Vertical privilege escalation
	- Broken object-level authorization
	- Broken function-level authorization
- SecureCommerce provides controlled examples for these scenarios.

## BOLA Testing

- BOLA testing verifies that access to an object is properly authorized for the requesting user.
- Example:
	- User A requests User B's object.
	- The application should deny unauthorized access.
- A confirmed unauthorized response should become validation evidence for the relevant finding.

## Input Validation Testing

- Input validation testing examines whether untrusted input is safely handled.
- Important classes include:
	- SQL injection
	- Cross-site scripting
	- Command injection
	- Path traversal
	- Server-side request forgery
- SecureForge should use controlled payloads in test environments.

## SQL Injection Testing

- SQL injection testing evaluates whether application input can alter database queries.
- SecureCommerce includes a deliberately vulnerable search scenario.
- Validation should:
	- Use controlled input
	- Avoid destructive database operations
	- Preserve request and response evidence
	- Detect controlled database-error behavior
- A scanner detection alone should not automatically be described as confirmed exploitation.

## XSS Testing

- XSS testing evaluates whether attacker-controlled input is returned or executed without appropriate output encoding.
- SecureCommerce contains a controlled reflected-XSS scenario.
- Validation should use harmless test payloads.
- Testing should confirm the security condition without delivering destructive browser actions.

## Path Traversal Testing

- Path traversal testing evaluates whether user-controlled file paths can access resources outside the intended directory.
- SecureCommerce contains a controlled download scenario.
- Validation should use a known lab marker.
- The test should not attempt to access arbitrary host files.

## File-Upload Testing

- File-upload testing evaluates:
	- Filename handling
	- File type validation
	- Storage location
	- Access control
	- Download behavior
	- Path traversal protection
- SecureForge should use harmless laboratory files.
- Uploaded test files should be stored in an isolated test directory.

## SSRF Testing

- SSRF testing evaluates whether the application can be manipulated into making unintended server-side requests.
- SecureCommerce provides a controlled external-fetch endpoint.
- Validation should target an explicitly controlled test service or local lab endpoint.
- Production SSRF testing requires explicit authorization and strict scope.

## API Security Testing

- API security testing evaluates REST endpoints independently from the browser interface.
- Areas include:
	- Authentication
	- Authorization
	- Object-level access
	- Function-level access
	- Input validation
	- Rate limiting
	- Error handling
	- Excessive data exposure
	- Security configuration

## OpenAPI Testing

- SecureForge can consume an OpenAPI definition to understand available API operations.
- OpenAPI evidence can support:
	- Endpoint discovery
	- Parameter discovery
	- Method identification
	- Authentication expectations
	- API security testing
- The OpenAPI document should not be treated as proof that the implementation matches the specification.

## Source-Code Testing

- Source-code testing identifies security weaknesses before runtime testing.
- SAST evidence can identify:
	- Dangerous functions
	- Injection patterns
	- Hardcoded secrets
	- Weak cryptography
	- Authorization weaknesses
	- Unsafe file operations

## Dependency Testing

- Dependency testing identifies known vulnerabilities in third-party components.
- Evidence should include:
	- Dependency
	- Installed version
	- Vulnerability identifier
	- Severity
	- Fixed version when available
- SecureForge should preserve the scanner's source and advisory information.

## Secret Detection

- Secret detection identifies credentials or sensitive tokens accidentally stored in source code or configuration.
- SecureForge should:
	- Detect the potential secret
	- Redact its value
	- Record the location
	- Recommend removal or rotation
- Synthetic secrets are used in the SecureCommerce lab.

## Container Security Testing

- Container testing evaluates:
	- Base image
	- Installed packages
	- Application dependencies
	- Container configuration
	- Exposed services
	- Privilege configuration
- Container findings should be correlated with application and dependency findings when they represent the same underlying risk.

## IaC Security Testing

- IaC testing evaluates infrastructure definitions before deployment.
- SecureCommerce includes intentionally insecure Terraform examples.
- Tests can identify:
	- Public exposure
	- Weak access controls
	- Insecure defaults
	- Missing encryption
	- Excessive permissions

## Network Testing

- Network testing provides attack-surface evidence.
- Nmap can identify:
	- Open ports
	- Services
	- Service versions
- An open port is an observation rather than automatically a vulnerability.
- Security interpretation depends on:
	- Expected service
	- Exposure
	- Asset importance
	- Configuration
	- Policy

## Vulnerability Assessment

- Nessus can provide infrastructure vulnerability evidence.
- SecureForge normalizes relevant Nessus findings into the common finding model.
- The Nessus result remains attributable to the Nessus integration.

## Manual Web Testing

- Manual web testing is useful when automated scanners cannot establish application-specific security context.
- Burp Suite can be used to:
	- Intercept requests
	- Modify parameters
	- Replay requests
	- Validate authorization
	- Confirm injection behavior
- Relevant evidence can then be supplied to SecureForge.

## Network Traffic Validation

- Wireshark can be used to inspect network behavior.
- Useful scenarios include:
	- Unexpected plaintext traffic
	- Protocol misuse
	- Unexpected connections
	- Authentication traffic
	- Application-to-service communication
- Packet evidence should be handled as potentially sensitive information.

## Controlled Exploitation

- Metasploit can be used for controlled validation of specific vulnerabilities.
- Exploitation should be limited to:
	- Authorized environments
	- Deliberately vulnerable systems
	- Defined security objectives
	- Non-destructive validation
- SecureForge records the result as evidence rather than attempting to become a full exploitation framework.

## Automated Versus Manual Testing

- Automated testing provides:
	- Repeatability
	- Speed
	- CI integration
	- Consistent output
- Manual testing provides:
	- Context
	- Business-logic understanding
	- Complex authorization validation
	- Tester judgment
- SecureForge combines both evidence types.

## Detection Versus Validation

- Detection asks:
	- Is there evidence suggesting a security problem?
- Validation asks:
	- Can the reported security condition be reproduced under controlled conditions?
- These are separate stages.
- This distinction reduces false confidence in scanner-only results.

## Severity Versus Confidence

- Severity describes potential security impact.
- Confidence describes confidence in the reported condition.
- A high-severity finding with low confidence may require validation before a final security decision.
- A confirmed high-severity finding provides substantially stronger evidence for release-gate evaluation.

## Testing Profiles

### Quick

- Focus:
	- Source security
	- Dependency security
	- Secret detection
- Objective:
	- Fast feedback during development and pull requests

### Standard

- Focus:
	- Quick checks
	- API security
	- Dynamic testing
	- Container security
- Objective:
	- Normal application verification

### Full

- Focus:
	- Standard checks
	- IaC
	- Infrastructure assessment
	- Network discovery
	- Manual evidence
- Objective:
	- Deeper controlled security verification

## Testing Sequence

- A practical sequence is:
	- Source analysis
	- Dependency analysis
	- Secret detection
	- API analysis
	- Dynamic testing
	- Container analysis
	- IaC analysis
	- Network assessment
	- Manual validation
	- Regression testing

## Finding Validation

- Findings selected for validation should have:
	- Clear security condition
	- Known target
	- Controlled validation method
	- Safe payload
	- Expected behavior
- Validation should produce structured evidence.

## Remediation Testing

- After remediation:
	- Re-run the relevant validation
	- Compare previous and current outcomes
	- Record remediation verification
	- Preserve the original finding identity
- A remediation should not be considered verified solely because a scanner no longer reports the issue.

## Regression Testing

- Confirmed security findings that can be expressed as repeatable tests should become regression tests.
- Regression testing protects against reintroduction of:
	- Authorization flaws
	- Injection
	- XSS
	- Secret exposure
	- Security misconfiguration

## Test Safety

- Security testing must be:
	- Authorized
	- Controlled
	- Non-destructive
	- Reproducible
	- Scope-limited
- Avoid:
	- Destructive database operations
	- Real credential attacks
	- Uncontrolled exploitation
	- Testing third-party systems without authorization

## Test Evidence

- Every meaningful test should preserve:
	- Test type
	- Target
	- Finding ID
	- Tool
	- Method
	- Input
	- Expected behavior
	- Observed behavior
	- Result
	- Timestamp

## Testing Limitations

- No single testing method provides complete application security coverage.
- Static analysis may miss runtime behavior.
- Dynamic analysis may miss unreachable code.
- API testing may miss browser-specific behavior.
- Network scanning may identify exposure without understanding business context.
- Manual testing depends on tester coverage.
- SecureForge therefore combines multiple evidence sources.

## Practical Principle

- SecureForge treats security testing as layered verification:
	- Source
	- Dependencies
	- Secrets
	- APIs
	- Runtime behavior
	- Containers
	- Infrastructure
	- Network
	- Manual validation
	- Regression
- The objective is not maximum scanner count.
- The objective is meaningful security evidence that can support an explainable release decision.
