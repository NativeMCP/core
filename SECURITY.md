# Security Policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:

<https://github.com/NativeMCP/core/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Include the affected version or commit, the platform, a reproduction, and the
impact you believe it has. If you are unsure whether something is a
vulnerability, report it privately anyway. A false positive costs a reply, a
public disclosure of a real one costs considerably more.

Acknowledgement within 3 business days. Assessment and a remediation plan
within 10 business days.

## Scope

This project runs as a privileged local service and mediates model-driven
access to a user's machine. The following are always in scope:

- Escape from a configured root (INV-2)
- Any path that destroys user data (INV-1)
- Audit records that can be suppressed, forged or reordered (INV-3)
- Privilege escalation through the service account or installer
- Policy precedence inversion, a client request widening operator policy (INV-4)
- Secret material recoverable from disk, logs, memory dumps or audit records
- Prompt-injected tool invocation crossing a policy boundary

## Out of scope

- Findings that require an attacker to already hold administrator or root
- Denial of service through resource exhaustion by an already-authorized caller
- Vulnerabilities in a dependency already flagged by `cargo deny` in CI
- Social engineering of the operator

## Supported versions

Pre-1.0. Only `main` and the most recent tagged release receive fixes.
