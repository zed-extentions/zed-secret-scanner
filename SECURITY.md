# Security Policy

## Reporting a vulnerability

Please use GitHub's private **"Report a vulnerability"** flow (Security → Advisories) on
this repository. If that is not possible, contact the maintainers via the organization's
public contact listed on the org profile.

Do **not** open public issues or pull requests for security problems.

## Scope

This repository ships a Zed editor extension (`zed-secret-scanner`) and standalone native
language server / CLI (`secret-scanner-lsp`). Vulnerabilities in secret masking, diagnostic
handling, GitHub release download verification, or configuration parsing are in scope.
Vulnerabilities in Zed itself or third-party tools should be reported to their respective
projects.
