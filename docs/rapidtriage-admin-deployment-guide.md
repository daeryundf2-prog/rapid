# RapidTriage Admin Deployment Guide

RapidTriage is local-first by default. Deploy it as a workstation tool unless a separately reviewed multi-user server is introduced.

## Deployment Checklist

- Install from a verified wheel, sdist, or portable ZIP only after checking the release `SHA256SUMS`.
- Verify `release-manifest.json`, `admin-guide-coverage-manifest.json`, and `update-manifest.json`.
- On Windows, run `scripts\windows\smoke-test-rapidtriage.ps1`; on macOS/Linux, run `sh scripts/smoke-test-rapidtriage.sh` before handing the build to analysts.
- Keep case output, logs, crash exports, and report bundles outside evidence roots.
- Use `rapidtriage web --auth-token ...` for any non-localhost bind and record who received the token.
- Use `rapidtriage web --crash-log-dir ...` for local-only crash report storage.
- Back up Case DB files with `rapidtriage case-backup CASE.db --output-dir BACKUP`.
- Restore with `rapidtriage case-restore BACKUP/rapidtriage-case-backup-manifest.json --output CASE-restored.db`.
- Run `scripts/check-dependencies.py` and keep the dependency inventory/SBOM with the release evidence.
- Run `python scripts/crash-export-smoke.py --output-dir logs/crash-export-smoke --json` and keep `crash-export-smoke.json` plus the generated ZIP bundle with release evidence.
- Run `python scripts/crash-redaction-review.py logs/crash-export-smoke/crash-export-smoke.json --json` and keep `crash-redaction-review.json` with the same release evidence folder.
- Run `python scripts/parser-sandbox-smoke.py --output logs/parser-sandbox-smoke.json --json` and keep the subprocess isolation smoke result with security evidence.
- Run `python scripts/security-hardening-review.py --output logs/security-hardening-review.json --json` to capture the release host's local hardening baseline, document hashes, auth/no-upload boundaries, and preserved AppSec/sandbox blockers.
- Pass those JSON files and `scripts/check-dependencies.py --output logs/dependency-monitoring.json` output to `scripts/verify-release-evidence.py` with `--crash-smoke-json`, `--crash-redaction-review-json`, `--parser-sandbox-smoke-json`, `--dependency-monitoring-json`, and `--security-hardening-review-json` so release evidence fails if the ZIP hash, redaction review, parser-isolation smoke result, dependency CI/SBOM contract, release-blocking dependency policy, or hardening self-review is missing.

## Install And Update Runbook

1. Create a clean workstation folder such as `C:\RapidTriage` or `/opt/rapidtriage`.
2. Copy the release package, `SHA256SUMS`, `release-manifest.json`, and update manifest into the folder.
3. Verify checksums before execution with `python scripts/build-release.py --output-dir release --verify` or a platform hash tool.
4. Start through the platform launcher instead of ad-hoc Python commands when analysts are using the workstation.
5. For updates, preserve `cases/`, `logs/`, local crash exports, backup manifests, and reviewer bundles before replacing application files.
6. After every update, rerun the smoke test and attach the resulting summary to the deployment record.

## Authentication And Network Boundary

- Keep the web UI bound to `127.0.0.1` for single-user workstation review.
- If remote access is unavoidable, bind only on an approved internal interface, require `--auth-token`, and record the operator, host, port, token owner, and expiry.
- Do not expose RapidTriage directly to the internet.
- Raise the open-file limit before starting a LAN server (`ulimit -n 4096` in the terminal, or `LimitNOFILE=4096` for a systemd service). `rapidtriage web` raises the soft limit toward the hard limit itself (at most 8192) and prints the limit in effect; at 256, the macOS terminal default, about 245 idle connections from any LAN device stalled the server.
- `rapidtriage web` caps concurrent connections at `RAPIDTRIAGE_LIMIT_CONCURRENCY` (default 1000, at most half the open-file limit; further requests get 503), closes idle keep-alive connections after 5 seconds, and gives in-flight requests 10 seconds on SIGTERM/Ctrl-C (waiting `wait: true` run requests answer at once; queued runs are marked `interrupted`).
- Request bodies are capped at 8 MiB (`RAPIDTRIAGE_MAX_BODY_BYTES`; hash-set uploads 50 MB). For office use put a reverse proxy (Caddy, nginx) in front with TLS, the same body limit (nginx `client_max_body_size 51m` for hash-set uploads), header/body read timeouts (nginx `client_header_timeout 10s`, `client_body_timeout 30s`), and an allow list of examiner IPs in the firewall: uvicorn itself does not close a connection that never sends a complete request.
- With API auth on, the API schema and docs pages (`/openapi.json`, `/docs`, `/redoc`) also need the token.
- Treat browser sessions as evidence-adjacent because source previews, reviewer notes, and report drafts may be visible.

## Backup, Restore, And Logging

- Back up the Case DB before upgrades, parser experiments, bulk imports, or report submission.
- Verify restore output with the backup manifest hash before deleting the previous case database.
- Keep `logs/`, crash reports, smoke summaries, validation packages, dependency reports, and release manifests together.
- Do not store logs inside the original evidence mount or extracted evidence root.
- For failed deployments, preserve stdout/stderr, smoke summary JSON, crash report JSON, and the release manifest.

## Security Hardening

- Do not expose the web UI to the internet.
- Keep telemetry disabled; RapidTriage does not upload evidence or crash reports.
- Treat reviewer bundles as sensitive because they contain hashes, notes, selected evidence metadata, and reports.
- Run `scripts/check-dependencies.py` during release preparation.

## Evidence Handling And Handoff

- Preserve original evidence hashes outside RapidTriage and compare them with any source hash emitted by the tool.
- Keep generated reports, exhibit bundles, reviewer bundles, and case backups in a controlled output folder.
- Before handoff, include `release-manifest.json`, `SHA256SUMS`, dependency inventory/SBOM, smoke summaries, validation report, and known limitations.
- Mark any missing external evidence, such as Windows signing, macOS notarization, independent AppSec review, or fresh-machine deployment proof, as a release blocker rather than a completed commercial claim.
