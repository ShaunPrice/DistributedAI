# Security

This is an initial implementation. Injection screening is heuristic and cannot guarantee malicious instructions are detected. Treat all retrieved memory, messages and job text as untrusted data. Do not use the system as a substitute for the client tool's own permission controls.

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting if enabled, or contact the repository owner through an established private channel. Do not publish secrets, personal records, live tokens or exploit details in public issues. Public-release preparation should include dependency/container scanning, an independent security review, a threat-model review and a deployment-specific penetration test.

Never commit `.secrets`, `.env`, database dumps, Terraform state, private conversation exports or local client configurations. The repository's unit-test credentials are synthetic fixtures. This service does not execute queued commands, run shell actions, fetch user-supplied URLs or inherit an organisation's authority from project codes.

## Repository scanning

Dependabot alerts and automated security updates are enabled. The security workflow runs Bandit and pip-audit on pushes and pull requests, including while the repository is private. Its CodeQL job is configured to run when the repository is public; it deliberately skips private runs without an applicable paid entitlement. Public visibility alone does not validate deployment security or prove the absence of vulnerabilities.

AGPL/Apache licensing does not activate GitHub security products. Eligibility depends on repository visibility, account entitlement and settings. Review scanning configuration when changing visibility; container/native dependency scanning and independent penetration testing remain outstanding.

See [layered deployment](docs/LAYERS.md) and [security baseline and remaining gaps](docs/SECURITY_REVIEW.md) for the current separation and security controls.
