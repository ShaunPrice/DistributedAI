# Security

This is an initial implementation. Injection screening is heuristic and cannot guarantee malicious instructions are detected. Treat all retrieved memory, messages and job text as untrusted data. Do not use the system as a substitute for the client tool's own permission controls.

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting if enabled, or contact the repository owner through an established private channel. Do not publish secrets, personal records, live tokens or exploit details in public issues. Public-release preparation should include dependency/container scanning, an independent security review, a threat-model review and a deployment-specific penetration test.

Never commit `.secrets`, `.env`, database dumps, Terraform state, private conversation exports or local client configurations. The repository's unit-test credentials are synthetic fixtures. This service does not execute queued commands, run shell actions, fetch user-supplied URLs or inherit an organisation's authority from project codes.
