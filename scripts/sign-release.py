#!/usr/bin/env python3
"""Create or verify a signed manifest of RapidTriage release artifacts.

Writes ``release-signature-manifest.json`` into the release directory. The
manifest lists every release file with its SHA-256 digest and size. When the
``RAPIDTRIAGE_SIGNING_KEY`` environment variable is set, the manifest also
carries an HMAC-SHA256 signature over the canonical file listing; without the
key the manifest is written unsigned with an explanatory note.

This is a symmetric, local-manifest signature: it provides tamper evidence for
release artifacts on operator-controlled hosts. It does not replace platform
signing (Authenticode, codesign/notarization, package signing) described in
docs/release-signing-runbook.md.
"""
from __future__ import annotations

# Force UTF-8 stdio so JSON output survives Windows consoles (cp1252).
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_NAME = "release-signature-manifest.json"
SIGNING_KEY_ENV = "RAPIDTRIAGE_SIGNING_KEY"
PROFILE_VERSION = "release-signature-manifest-v1"
UNSIGNED_NOTE = (
    "unsigned manifest-only mode; set RAPIDTRIAGE_SIGNING_KEY in the signing "
    "environment to attach an HMAC-SHA256 signature"
)
SIGNED_NOTE = (
    "manifest signed with the RAPIDTRIAGE_SIGNING_KEY secret (HMAC-SHA256, "
    "symmetric key; keep the key out of the release directory and VCS)"
)


def artifact_digests(release_dir: Path, manifest_path: Path) -> dict[str, dict[str, object]]:
    files: dict[str, dict[str, object]] = {}
    for path in sorted(release_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.resolve() == manifest_path.resolve():
            continue
        files[path.name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
    return files


def canonical_listing(files: dict[str, dict[str, object]]) -> bytes:
    return json.dumps({"files": files}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_listing(files: dict[str, dict[str, object]], key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_listing(files), hashlib.sha256).hexdigest()


def build_manifest(release_dir: Path, manifest_path: Path, key: str | None) -> dict[str, object]:
    files = artifact_digests(release_dir, manifest_path)
    signed = bool(key)
    manifest: dict[str, object] = {
        "profile_version": PROFILE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_dir": str(release_dir),
        "file_count": len(files),
        "files": files,
        "signed": signed,
        "signature": (
            {"algorithm": "hmac-sha256", "key_source": SIGNING_KEY_ENV, "value": sign_listing(files, key or "")}
            if signed
            else None
        ),
        "note": SIGNED_NOTE if signed else UNSIGNED_NOTE,
    }
    return manifest


def write_manifest(args: argparse.Namespace) -> int:
    release_dir = Path(args.release_dir).expanduser().resolve()
    if not release_dir.is_dir():
        print(f"release directory not found: {release_dir}", file=sys.stderr)
        return 1
    manifest_path = Path(args.output).expanduser().resolve() if args.output else release_dir / MANIFEST_NAME
    key = os.environ.get(SIGNING_KEY_ENV, "").strip() or None
    manifest = build_manifest(release_dir, manifest_path, key)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    else:
        print(f"Wrote release signature manifest: {manifest_path}")
        print(f"Files covered: {manifest['file_count']}  Signed: {manifest['signed']}")
        if not manifest["signed"]:
            print(f"Note: {UNSIGNED_NOTE}")
    return 0


def verify_manifest(args: argparse.Namespace) -> int:
    release_dir = Path(args.release_dir).expanduser().resolve()
    manifest_path = Path(args.output).expanduser().resolve() if args.output else release_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        print(f"Missing signature manifest: {manifest_path}", file=sys.stderr)
        return 1
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Signature manifest is not valid JSON: {exc}", file=sys.stderr)
        return 1
    files = manifest.get("files")
    if not isinstance(files, dict):
        print("Signature manifest is missing the files listing", file=sys.stderr)
        return 1

    failures: list[str] = []
    for name, entry in files.items():
        entry = entry if isinstance(entry, dict) else {}
        path = release_dir / name
        if not path.is_file():
            failures.append(f"Missing artifact: {name}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual.lower() != str(entry.get("sha256") or "").lower():
            failures.append(f"Checksum mismatch: {name}")

    signature = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else None
    signature_status = "unsigned"
    if signature:
        key = os.environ.get(SIGNING_KEY_ENV, "").strip()
        if not key:
            failures.append(f"Manifest is signed but {SIGNING_KEY_ENV} is not set; cannot verify signature")
            signature_status = "unverifiable"
        else:
            expected = sign_listing(files, key)
            if hmac.compare_digest(expected, str(signature.get("value") or "")):
                signature_status = "verified"
            else:
                failures.append("Manifest signature mismatch")
                signature_status = "invalid"
    elif args.require_signed:
        failures.append(f"Manifest is unsigned and --require-signed was given ({SIGNING_KEY_ENV} not set at sign time)")

    result = {
        "command": "sign-release.verify",
        "manifest": str(manifest_path),
        "file_count": len(files),
        "digest_failures": failures,
        "signature_status": signature_status,
        "ok": not failures,
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(f"Verified {len(files)} manifest digests; signature status: {signature_status}")
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify the RapidTriage release artifact manifest")
    parser.add_argument("--release-dir", default="release", help="Release artifact directory")
    parser.add_argument("--output", help=f"Signature manifest path (default: <release-dir>/{MANIFEST_NAME})")
    parser.add_argument("--verify", action="store_true", help="Verify an existing signature manifest and exit")
    parser.add_argument("--require-signed", action="store_true", help="Fail verification when the manifest is unsigned")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)
    if args.verify:
        return verify_manifest(args)
    return write_manifest(args)


if __name__ == "__main__":
    raise SystemExit(main())
