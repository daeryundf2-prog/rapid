# RapidTriage Security Policy

## Supported Mode

RapidTriage is safest as a local-only forensic workstation tool. The default web bind address is `127.0.0.1`.

## Remote Access

If you bind to `0.0.0.0` or another non-localhost interface, configure an auth token:

```bash
rapidtriage web --host 0.0.0.0 --auth-token "replace-me"
```

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
