#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize RapidTriage smoke-test outputs")
    parser.add_argument("smoke_dir", help="Smoke output directory")
    parser.add_argument("--output", default="", help="JSON summary output path")
    parser.add_argument("--markdown", default="", help="Markdown summary output path")
    parser.add_argument("--platform", default="", help="Smoke platform label, for example windows or macos-linux")
    parser.add_argument("--allow-missing-web", action="store_true", help="Treat a missing web-index.html as skipped")
    args = parser.parse_args(argv)

    smoke_dir = Path(args.smoke_dir).resolve()
    summary = build_summary(smoke_dir, platform_label=args.platform, allow_missing_web=args.allow_missing_web)

    output_path = Path(args.output).resolve() if args.output else smoke_dir / "smoke-summary.json"
    markdown_path = Path(args.markdown).resolve() if args.markdown else smoke_dir / "smoke-summary.md"
    output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")

    print(f"Wrote smoke summary JSON: {output_path}")
    print(f"Wrote smoke summary Markdown: {markdown_path}")
    return 0 if summary["passed"] else 1


def build_summary(smoke_dir: Path, *, platform_label: str = "", allow_missing_web: bool = False) -> dict[str, Any]:
    checks = [
        check_doctor(smoke_dir),
        check_sample(smoke_dir),
        check_search(smoke_dir),
        check_benchmark(smoke_dir),
        check_validation(smoke_dir),
        check_evidence(smoke_dir),
        check_web(smoke_dir, allow_missing=allow_missing_web),
    ]
    return {
        "command": "smoke-summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "smoke_dir": str(smoke_dir),
        "platform": normalize_platform_label(platform_label) or infer_platform_label(smoke_dir),
        "python_platform": platform.platform(),
        "passed": all(item["status"] in {"pass", "skip"} for item in checks),
        "checks": checks,
    }


def check_doctor(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "doctor.json")
    status = payload.get("status") if isinstance(payload, dict) else None
    return check("doctor", status in {"ok", "warn"}, f"doctor status: {status or 'missing'}")


def check_sample(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "sample.json")
    run = payload.get("run") if isinstance(payload, dict) else None
    output_dir = run.get("output_dir") if isinstance(run, dict) else None
    return check("sample", bool(output_dir), f"sample run output: {output_dir or 'missing'}")


def check_search(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "sample-search.json")
    matches = payload.get("match_count") if isinstance(payload, dict) else None
    if matches is None and isinstance(payload, dict):
        matches = len(payload.get("matches", []))
    return check("search", isinstance(matches, int) and matches > 0, f"search matches: {matches}")


def check_benchmark(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "benchmark.json")
    metrics = payload.get("metrics") if isinstance(payload, dict) else None
    ingest = metrics.get("ingest_seconds") if isinstance(metrics, dict) else None
    return check("benchmark", isinstance(ingest, (int, float)) and ingest >= 0, f"ingest seconds: {ingest}")


def check_validation(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "validation.json")
    status = payload.get("status") if isinstance(payload, dict) else None
    return check("validation", status == "release-validation-package-ready", f"validation status: {status or 'missing'}")


def check_evidence(smoke_dir: Path) -> dict[str, Any]:
    payload = read_json(smoke_dir / "evidence-vhdx.json")
    adapter = payload.get("adapter") if isinstance(payload, dict) else None
    message = payload.get("message") if isinstance(payload, dict) else None
    return check("evidence-guidance", adapter == "virtual-disk", f"{adapter or 'missing'}: {message or ''}".strip())


def check_web(smoke_dir: Path, *, allow_missing: bool = False) -> dict[str, Any]:
    path = smoke_dir / "web-index.html"
    available = path.is_file() and path.stat().st_size > 0
    if not available and allow_missing:
        return {"name": "web", "status": "skip", "detail": "web-index.html skipped by smoke-test option"}
    return check("web", available, f"web-index.html {'present' if available else 'missing'}")


def check(name: str, passed: bool, detail: str) -> dict[str, str]:
    return {"name": name, "status": "pass" if passed else "fail", "detail": detail}


def infer_platform_label(smoke_dir: Path) -> str:
    lower_name = smoke_dir.name.lower()
    if "windows" in lower_name or lower_name.startswith("win"):
        return "windows"
    if "macos" in lower_name or "linux" in lower_name or "darwin" in lower_name:
        return "macos-linux"
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system in {"darwin", "linux"}:
        return "macos-linux"
    return system or "unknown"


def normalize_platform_label(value: str) -> str:
    cleaned = value.strip().lower().replace("_", "-")
    if cleaned in {"win", "windows-latest"}:
        return "windows"
    if cleaned in {"macos", "mac", "darwin", "linux", "ubuntu", "ubuntu-latest", "macos-latest"}:
        return "macos-linux"
    return cleaned


def read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# RapidTriage Smoke Summary",
        "",
        f"- Smoke directory: `{summary['smoke_dir']}`",
        f"- Platform: `{summary['platform']}`",
        f"- Result: {'PASS' if summary['passed'] else 'FAIL'}",
        f"- Generated: `{summary['generated_at']}`",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for item in summary["checks"]:
        lines.append(f"| {item['name']} | {item['status']} | {item['detail']} |")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
