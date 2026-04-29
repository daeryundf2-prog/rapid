# RapidTriage Admin Deployment Guide

RapidTriage is local-first by default. Deploy it as a workstation tool unless a separately reviewed multi-user server is introduced.

## Deployment Checklist

- Install from a verified wheel, sdist, or portable ZIP.
- Verify `SHA256SUMS`, `release-manifest.json`, and `update-manifest.json`.
- Run the Windows or macOS/Linux smoke test before handing the build to analysts.
- Keep outputs outside evidence roots.
- Use `rapidtriage web --auth-token ...` for any non-localhost bind.
- Use `rapidtriage web --crash-log-dir ...` for local-only crash report storage.
- Back up Case DB files with `rapidtriage case-backup CASE.db --output-dir BACKUP`.
- Restore with `rapidtriage case-restore BACKUP/rapidtriage-case-backup-manifest.json --output CASE-restored.db`.

## Security Hardening

- Do not expose the web UI to the internet.
- Keep telemetry disabled; RapidTriage does not upload evidence or crash reports.
- Treat reviewer bundles as sensitive because they contain hashes, notes, selected evidence metadata, and reports.
- Run `scripts/check-dependencies.py` during release preparation.

