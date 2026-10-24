# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for an exploitable vulnerability.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability** (private vulnerability reporting). Include:

- a description of the issue and its impact;
- steps to reproduce, ideally as a short script in the style of `scripts/attack_simulator.py`;
- the version or commit you tested.

## Disclosure

- Acknowledgement within 7 days.
- 90-day coordinated disclosure unless a fix ships sooner.
- Reporters are credited in the release notes unless they prefer to stay anonymous.

## Scope

In scope: the verification gate, token and signature handling, the audit log, the HTTP API and the
container configuration. Out of scope: the items listed under "Out of scope" in
[THREAT-MODEL.md](THREAT-MODEL.md), and findings that require possession of the signing key.
