#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build RapidTriage release artifacts")
    parser.add_argument("--output-dir", default="release", help="Release artifact directory")
    parser.add_argument("--skip-build", action="store_true", help="Skip wheel/sdist build and only assemble portable zip")
    parser.add_argument("--verify", action="store_true", help="Verify SHA256SUMS in the output directory and exit")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    output_dir = (repo / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.verify:
        return verify_sha256s(output_dir)

    if not args.skip_build:
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--sdist"], cwd=repo, check=True)
        dist_dir = repo / "dist"
        for artifact in dist_dir.glob("*"):
            shutil.copy2(artifact, output_dir / artifact.name)

    portable_zip = output_dir / "rapidtriage-portable.zip"
    with zipfile.ZipFile(portable_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_if_exists(archive, repo / "README.md", "README.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-windows-quickstart.md", "docs/rapidtriage-windows-quickstart.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-macos-linux-quickstart.md", "docs/rapidtriage-macos-linux-quickstart.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-fresh-machine-smoke-test.md", "docs/rapidtriage-fresh-machine-smoke-test.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-e01-workflow.md", "docs/rapidtriage-e01-workflow.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-user-guide.md", "docs/rapidtriage-user-guide.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-known-limitations.md", "docs/rapidtriage-known-limitations.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-parser-coverage.md", "docs/rapidtriage-parser-coverage.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-security-policy.md", "docs/rapidtriage-security-policy.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-release-checklist.md", "docs/rapidtriage-release-checklist.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-release-notes-template.md", "docs/rapidtriage-release-notes-template.md")
        add_if_exists(archive, repo / "scripts" / "start-rapidtriage.sh", "scripts/start-rapidtriage.sh")
        add_if_exists(archive, repo / "scripts" / "smoke-test-rapidtriage.sh", "scripts/smoke-test-rapidtriage.sh")
        add_if_exists(archive, repo / "scripts" / "summarize-smoke.py", "scripts/summarize-smoke.py")
        add_if_exists(archive, repo / "scripts" / "verify-release-evidence.py", "scripts/verify-release-evidence.py")
        add_tree(archive, repo / "scripts" / "windows", "scripts/windows")
        archive.writestr("data/.gitkeep", "")
        archive.writestr("cases/.gitkeep", "")
        archive.writestr("logs/.gitkeep", "")
        archive.writestr("tools/.gitkeep", "")

    write_dependency_inventory(output_dir)
    write_release_manifest(output_dir, repo)
    write_sha256s(output_dir)

    print(f"Built portable zip: {portable_zip}")
    print(f"Wrote checksums: {output_dir / 'SHA256SUMS'}")
    print(f"Wrote release manifest: {output_dir / 'release-manifest.json'}")
    return 0


def add_if_exists(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    if path.is_file():
        archive.write(path, arcname)


def add_tree(archive: zipfile.ZipFile, root: Path, arcroot: str) -> None:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            archive.write(path, f"{arcroot}/{path.relative_to(root)}")


def write_dependency_inventory(output_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        text=True,
        capture_output=True,
        check=False,
    )
    inventory = output_dir / "dependency-inventory.txt"
    header = [
        "# RapidTriage dependency inventory",
        f"# Python executable: {sys.executable}",
        f"# pip freeze exit code: {result.returncode}",
        "",
    ]
    body = result.stdout if result.stdout.strip() else result.stderr
    inventory.write_text("\n".join(header) + body, encoding="utf-8")


def write_sha256s(output_dir: Path) -> None:
    checksum_path = output_dir / "SHA256SUMS"
    rows: list[str] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name == checksum_path.name:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.name}")
    checksum_path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")


def write_release_manifest(output_dir: Path, repo: Path) -> None:
    artifacts: list[dict[str, object]] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name in {"SHA256SUMS", "release-manifest.json"}:
            continue
        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )

    manifest = {
        "name": "rapidtriage-release",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_value(repo, ["rev-parse", "HEAD"]),
        "git_branch": git_value(repo, ["rev-parse", "--abbrev-ref", "HEAD"]),
        "python": {
            "executable": sys.executable,
            "version": platform.python_version(),
            "platform": platform.platform(),
        },
        "artifacts": artifacts,
        "required_followup_evidence": [
            "Windows smoke output folder",
            "macOS/Linux smoke output folder",
            "Windows Authenticode signature verification when distributing signed binaries",
            "macOS codesign/notarization/Gatekeeper verification when distributing app packages",
        ],
    }
    manifest_path = output_dir / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def verify_sha256s(output_dir: Path) -> int:
    checksum_path = output_dir / "SHA256SUMS"
    if not checksum_path.is_file():
        print(f"Missing checksum file: {checksum_path}", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked = 0
    for raw_line in checksum_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            expected, name = line.split(None, 1)
        except ValueError:
            failures.append(f"Malformed checksum row: {raw_line}")
            continue
        path = output_dir / name.strip()
        if not path.is_file():
            failures.append(f"Missing artifact: {name.strip()}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        checked += 1
        if actual.lower() != expected.lower():
            failures.append(f"Checksum mismatch: {name.strip()}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"Verified {checked} SHA256 checksums in {checksum_path}")
    return 0


def git_value(repo: Path, args: list[str]) -> str | None:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
