#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify RapidTriage release evidence folders")
    parser.add_argument("--release-dir", default="release", help="Directory containing release artifacts")
    parser.add_argument("--validation-dir", default="release-validation", help="Directory containing validation package")
    parser.add_argument("--benchmark-dir", default="release-benchmark", help="Directory containing benchmark output")
    parser.add_argument("--smoke-dir", action="append", default=[], help="Smoke output directory; repeat per platform")
    parser.add_argument("--minimum-smoke-count", type=int, default=1, help="Minimum required passing smoke summaries")
    parser.add_argument(
        "--require-smoke-platform",
        action="append",
        default=[],
        help="Required passing smoke platform label; repeat for windows, macos-linux, or custom labels",
    )
    parser.add_argument("--output-dir", default="release-evidence", help="Directory for evidence verification report")
    args = parser.parse_args(argv)

    release_dir = Path(args.release_dir).expanduser().resolve()
    validation_dir = Path(args.validation_dir).expanduser().resolve()
    benchmark_dir = Path(args.benchmark_dir).expanduser().resolve()
    smoke_dirs = [Path(value).expanduser().resolve() for value in args.smoke_dir]
    required_smoke_platforms = [normalize_platform_label(value) for value in args.require_smoke_platform if value.strip()]
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    checks: list[dict[str, Any]] = []
    checks.extend(check_release_artifacts(release_dir))
    checks.extend(check_validation_package(validation_dir))
    checks.extend(check_benchmark_output(benchmark_dir))
    checks.extend(
        check_smoke_outputs(
            smoke_dirs,
            minimum_smoke_count=args.minimum_smoke_count,
            required_platforms=required_smoke_platforms,
        )
    )
    passed = all(item["status"] in {"pass", "skip"} for item in checks if item.get("required", True))

    payload = {
        "command": "verify-release-evidence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "release_gate": "pass" if passed else "fail",
        "inputs": {
            "release_dir": str(release_dir),
            "validation_dir": str(validation_dir),
            "benchmark_dir": str(benchmark_dir),
            "smoke_dirs": [str(path) for path in smoke_dirs],
            "minimum_smoke_count": args.minimum_smoke_count,
            "required_smoke_platforms": required_smoke_platforms,
        },
        "checks": checks,
        "summary": build_summary(checks),
        "next_actions": build_next_actions(checks),
    }

    json_path = output_dir / "release-evidence-report.json"
    markdown_path = output_dir / "release-evidence-report.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(payload), encoding="utf-8")

    print(f"Wrote release evidence JSON: {json_path}")
    print(f"Wrote release evidence Markdown: {markdown_path}")
    print(f"Release evidence result: {'PASS' if payload['passed'] else 'FAIL'}")
    return 0 if payload["passed"] else 1


def check_release_artifacts(release_dir: Path) -> list[dict[str, Any]]:
    checks = [
        check_path("release-dir", release_dir, is_dir=True),
        check_path("release-portable-zip", release_dir / "rapidtriage-portable.zip"),
        check_path("release-sha256s", release_dir / "SHA256SUMS"),
        check_path("release-manifest", release_dir / "release-manifest.json"),
        check_path("release-dependency-inventory", release_dir / "dependency-inventory.txt"),
        check_path("release-commercial-readiness-json", release_dir / "rapidtriage-commercial-readiness.json"),
        check_path("release-commercial-readiness-markdown", release_dir / "rapidtriage-commercial-readiness.md"),
    ]
    checks.append(check_sha256s(release_dir))
    checks.append(check_release_manifest(release_dir))
    checks.append(check_commercial_readiness_disclosure(release_dir))
    return checks


def check_validation_package(validation_dir: Path) -> list[dict[str, Any]]:
    json_path = validation_dir / "rapidtriage-validation-package.json"
    markdown_path = validation_dir / "rapidtriage-validation-report.md"
    checks = [
        check_path("validation-dir", validation_dir, is_dir=True),
        check_path("validation-json", json_path),
        check_path("validation-markdown", markdown_path),
    ]
    payload = read_json(json_path)
    status = payload.get("status") if isinstance(payload, dict) else None
    checks.append(
        make_check(
            "validation-status",
            status == "release-validation-package-ready",
            f"status={status or 'missing'}",
            path=json_path,
        )
    )
    return checks


def check_benchmark_output(benchmark_dir: Path) -> list[dict[str, Any]]:
    json_path = benchmark_dir / "rapidtriage-benchmark.json"
    markdown_path = benchmark_dir / "rapidtriage-benchmark.md"
    checks = [
        check_path("benchmark-dir", benchmark_dir, is_dir=True),
        check_path("benchmark-json", json_path),
        check_path("benchmark-markdown", markdown_path),
    ]
    payload = read_json(json_path)
    metrics = payload.get("metrics") if isinstance(payload, dict) else None
    ingest_seconds = metrics.get("ingest_seconds") if isinstance(metrics, dict) else None
    search_p50 = metrics.get("search_p50_seconds") if isinstance(metrics, dict) else None
    checks.append(
        make_check(
            "benchmark-metrics",
            isinstance(ingest_seconds, (int, float)) and ingest_seconds >= 0
            and isinstance(search_p50, (int, float))
            and search_p50 >= 0,
            f"ingest_seconds={ingest_seconds}, search_p50_seconds={search_p50}",
            path=json_path,
        )
    )
    return checks


def check_smoke_outputs(
    smoke_dirs: list[Path],
    *,
    minimum_smoke_count: int,
    required_platforms: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    passing = 0
    passing_platforms: set[str] = set()
    for index, smoke_dir in enumerate(smoke_dirs, start=1):
        label = smoke_dir.name or f"smoke-{index}"
        json_path = smoke_dir / "smoke-summary.json"
        markdown_path = smoke_dir / "smoke-summary.md"
        checks.append(check_path(f"smoke-{label}-dir", smoke_dir, is_dir=True))
        checks.append(check_path(f"smoke-{label}-json", json_path))
        checks.append(check_path(f"smoke-{label}-markdown", markdown_path))
        payload = read_json(json_path)
        passed = bool(payload.get("passed")) if isinstance(payload, dict) else False
        platform_label = infer_smoke_platform(smoke_dir, payload)
        if passed:
            passing += 1
            passing_platforms.add(platform_label)
        checks.append(
            make_check(
                f"smoke-{label}-status",
                passed,
                f"passed={passed}, platform={platform_label}",
                path=json_path,
            )
        )

    checks.append(
        make_check(
            "smoke-minimum-count",
            passing >= minimum_smoke_count,
            f"passing={passing}, required={minimum_smoke_count}",
        )
    )
    for platform_label in required_platforms:
        checks.append(
            make_check(
                f"smoke-platform-{platform_label}",
                platform_label in passing_platforms,
                f"passing_platforms={sorted(passing_platforms)}, required={platform_label}",
            )
        )
    return checks


def check_sha256s(release_dir: Path) -> dict[str, Any]:
    checksum_path = release_dir / "SHA256SUMS"
    if not checksum_path.is_file():
        return make_check("release-sha256-verification", False, "SHA256SUMS missing", path=checksum_path)

    failures: list[str] = []
    checked = 0
    for raw_line in checksum_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            expected, name = line.split(None, 1)
        except ValueError:
            failures.append(f"malformed row: {raw_line}")
            continue
        artifact_path = release_dir / name.strip()
        if not artifact_path.is_file():
            failures.append(f"missing artifact: {name.strip()}")
            continue
        actual = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        checked += 1
        if actual.lower() != expected.lower():
            failures.append(f"checksum mismatch: {name.strip()}")

    return make_check(
        "release-sha256-verification",
        not failures and checked > 0,
        f"checked={checked}" if not failures else "; ".join(failures),
        path=checksum_path,
    )


def check_release_manifest(release_dir: Path) -> dict[str, Any]:
    manifest_path = release_dir / "release-manifest.json"
    payload = read_json(manifest_path)
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    names = {str(item.get("name")) for item in artifacts if isinstance(item, dict)} if isinstance(artifacts, list) else set()
    required_names = {"rapidtriage-portable.zip", "dependency-inventory.txt"}
    missing = sorted(required_names - names)
    return make_check(
        "release-manifest-artifacts",
        isinstance(artifacts, list) and not missing,
        f"artifacts={len(artifacts) if isinstance(artifacts, list) else 0}, missing={missing}",
        path=manifest_path,
    )


def check_commercial_readiness_disclosure(release_dir: Path) -> dict[str, Any]:
    readiness_path = release_dir / "rapidtriage-commercial-readiness.json"
    payload = read_json(readiness_path)
    if not isinstance(payload, dict):
        return make_check(
            "release-commercial-readiness-disclosure",
            False,
            "commercial readiness report missing or invalid",
            path=readiness_path,
        )
    has_disclosure = (
        "commercial_claim_allowed" in payload
        and "non_commercial_count" in payload
        and "release_claim" in payload
        and isinstance(payload.get("non_commercial_items"), list)
    )
    detail = (
        f"claim_allowed={payload.get('commercial_claim_allowed')}, "
        f"non_commercial_count={payload.get('non_commercial_count')}, "
        f"status={payload.get('status')}"
    )
    return make_check("release-commercial-readiness-disclosure", has_disclosure, detail, path=readiness_path)


def check_path(check_id: str, path: Path, *, is_dir: bool = False) -> dict[str, Any]:
    exists = path.is_dir() if is_dir else path.is_file()
    kind = "directory" if is_dir else "file"
    return make_check(check_id, exists, f"{kind} {'present' if exists else 'missing'}", path=path)


def make_check(check_id: str, passed: bool, detail: str, *, path: Path | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "pass" if passed else "fail",
        "detail": detail,
        "path": str(path) if path is not None else "",
        "required": True,
        "remediation": "" if passed else remediation_for(check_id),
    }


def build_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"pass": 0, "fail": 0, "skip": 0}
    for item in checks:
        status = str(item.get("status", "fail"))
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_next_actions(checks: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for item in checks:
        if item.get("status") != "fail":
            continue
        remediation = str(item.get("remediation") or "").strip()
        if remediation and remediation not in seen:
            actions.append(remediation)
            seen.add(remediation)
    return actions


def remediation_for(check_id: str) -> str:
    if check_id.startswith("release-"):
        return "Rebuild release artifacts, then run build-release.py --verify before attaching SHA256SUMS."
    if check_id.startswith("validation-"):
        return "Run rapidtriage validation --output-dir release-validation --overwrite and attach JSON/Markdown output."
    if check_id.startswith("benchmark-"):
        return "Run rapidtriage benchmark --output-dir release-benchmark --overwrite and attach JSON/Markdown output."
    if check_id.startswith("smoke-platform-"):
        platform_label = check_id.removeprefix("smoke-platform-")
        return f"Run and summarize a passing smoke test for platform '{platform_label}', then pass it with --smoke-dir."
    if check_id.startswith("smoke-"):
        return "Run scripts/smoke-test-rapidtriage.sh or scripts/windows/smoke-test-rapidtriage.ps1 and attach smoke-summary.json/md."
    return "Review the failed release evidence check and attach the missing or corrected artifact."


def infer_smoke_platform(smoke_dir: Path, payload: Any) -> str:
    if isinstance(payload, dict):
        value = payload.get("platform")
        if isinstance(value, str) and value.strip():
            return normalize_platform_label(value)
    return normalize_platform_label(smoke_dir.name)


def normalize_platform_label(value: str) -> str:
    cleaned = value.strip().lower().replace("_", "-")
    if cleaned in {"win", "windows", "windows-latest"} or "windows" in cleaned:
        return "windows"
    if cleaned in {"mac", "macos", "macos-latest", "darwin"} or "macos" in cleaned or "darwin" in cleaned:
        return "macos-linux"
    if cleaned in {"linux", "ubuntu", "ubuntu-latest"} or "linux" in cleaned or "ubuntu" in cleaned:
        return "macos-linux"
    return cleaned or "unknown"


def read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def render_markdown(payload: dict[str, Any]) -> str:
    checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
    lines = [
        "# RapidTriage Release Evidence Report",
        "",
        f"- Result: {'PASS' if payload.get('passed') else 'FAIL'}",
        f"- Generated: `{payload.get('generated_at', '')}`",
        f"- Release dir: `{payload.get('inputs', {}).get('release_dir', '')}`",
        f"- Validation dir: `{payload.get('inputs', {}).get('validation_dir', '')}`",
        f"- Benchmark dir: `{payload.get('inputs', {}).get('benchmark_dir', '')}`",
        f"- Smoke dirs: `{', '.join(payload.get('inputs', {}).get('smoke_dirs', []))}`",
        f"- Required smoke platforms: `{', '.join(payload.get('inputs', {}).get('required_smoke_platforms', []))}`",
        f"- Release gate: `{payload.get('release_gate', '')}`",
        "",
        "| Check | Status | Detail | Path |",
        "| --- | --- | --- | --- |",
    ]
    for item in checks:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {item.get('id', '')} | {item.get('status', '')} | {item.get('detail', '')} | `{item.get('path', '')}` |"
        )
    next_actions = payload.get("next_actions") if isinstance(payload.get("next_actions"), list) else []
    if next_actions:
        lines.extend(["", "## Next Actions", ""])
        for action in next_actions:
            lines.append(f"- {action}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
