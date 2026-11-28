# RapidTriage Security Policy

## Supported Mode

RapidTriage is safest as a local-only forensic workstation tool. The default web bind address is `127.0.0.1`.

## Remote Access

Any non-localhost bind (`--remote`, `--host 0.0.0.0 --auth-token`, even `--allow-remote-without-auth`) refuses to start unless the server roots are set: `RAPIDTRIAGE_ANALYSIS_ROOTS` (evidence inputs) and `RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS` (run outputs), absolute local folders separated by the platform path separator. No output root may be, contain, or lie inside an evidence root. Use `--remote`, which also requires a token:

```bash
RAPIDTRIAGE_ANALYSIS_ROOTS=/srv/evidence \
RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS=/srv/rapidtriage-out \
RAPIDTRIAGE_TOKEN="replace-me" \
rapidtriage web --remote --host 0.0.0.0
```

Authentication tokens are header-only. Clients must send `X-RapidTriage-Token`; URL query-string tokens are rejected to avoid token leakage through logs, browser history, or referrers.

Do not expose the service directly to the public internet.

## Sensitive Data

RapidTriage may serve source previews, downloaded evidence files, report drafts, and hash manifests. Treat all output directories and browser sessions as sensitive evidence handling environments.

## Reporting Issues

For security-sensitive issues, include:

- RapidTriage version or commit hash.
- Operating system.
- Exact command or API route.
- Whether the web server was localhost-only or remotely bound.
- Redacted reproduction steps.

Do not include real evidence data in issue reports.
