#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build RapidTriage release artifacts")
    parser.add_argument("--output-dir", default="release", help="Release artifact directory")
    parser.add_argument("--skip-build", action="store_true", help="Skip wheel/sdist build and only assemble portable zip")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    output_dir = (repo / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

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
        add_tree(archive, repo / "scripts" / "windows", "scripts/windows")
        archive.writestr("data/.gitkeep", "")
        archive.writestr("cases/.gitkeep", "")
        archive.writestr("logs/.gitkeep", "")
        archive.writestr("tools/.gitkeep", "")

    write_dependency_inventory(output_dir)
    write_sha256s(output_dir)

    print(f"Built portable zip: {portable_zip}")
    print(f"Wrote checksums: {output_dir / 'SHA256SUMS'}")
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


if __name__ == "__main__":
    raise SystemExit(main())
