# Security Policy

## Supported Versions

Security fixes are provided on a best-effort basis for the latest commit on the default branch.

## Reporting a Vulnerability

Please do not open public issues for potential vulnerabilities.

Preferred reporting paths:
- GitHub Security Advisories (private report)
- If unavailable, open a minimal public issue without exploit details and request private follow-up

Include:
- affected commit/version
- reproduction steps
- impact assessment
- any known mitigations

## Response Model

This is a community-maintained project with best-effort response and remediation.
No guaranteed SLA is provided.

## Security Considerations for This Project

This runtime handles local automation and local message/session metadata on macOS. Key risks include:
- Apple Events/Automation misuse
- local chat database access (`chat.db`)
- leaked session metadata in logs/state files

See `docs/security.md` for hardening guidance.
