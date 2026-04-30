#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run worker -> JSONL -> Case DB -> search smoke test")
    parser.add_argument("--output-dir", default="", help="Directory for smoke outputs; defaults to a temporary folder")
    parser.add_argument("--worker", default="", help="Path to rapid-worker binary")
    parser.add_argument("--skip-build", action="store_true", help="Do not build rapid-worker when the binary is missing")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="rapid-worker-case-db-smoke-"))
    output_dir.mkdir(parents=True, exist_ok=True)
    worker = locate_worker(repo, args.worker)
    if not worker.exists():
        if args.skip_build:
            raise SystemExit(f"rapid-worker not found: {worker}")
        run_checked(["cargo", "build", "--bin", "rapid-worker"], cwd=repo / "engines" / "rust")
    if not worker.exists():
        raise SystemExit(f"rapid-worker build did not produce expected binary: {worker}")

    evidence_root = output_dir / "evidence"
    logs_dir = evidence_root / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    evtx_path = logs_dir / "System.evtx"
    evtx_path.write_bytes(known_answer_evtx())

    jsonl_path = output_dir / "worker-artifacts.jsonl"
    db_path = output_dir / "case.db"
    env = {**os.environ, "RAPIDTRIAGE_RUST_WORKER": str(worker)}
    worker_payload = run_json(
        [
            sys.executable,
            "-m",
            "rapidtriage",
            "worker-parse",
            str(evidence_root),
            "--kind",
            "evtx-records",
            "--output",
            str(jsonl_path),
            "--case-id",
            "CASE-SMOKE",
            "--source-id",
            "SRC-SMOKE",
            "--json",
        ],
        cwd=repo,
        env=env,
    )
    import_payload = run_json(
        [
            sys.executable,
            "-m",
            "rapidtriage",
            "case-db",
            str(db_path),
            "--import-worker-jsonl",
            str(jsonl_path),
            "--case-id",
            "CASE-SMOKE",
            "--json",
        ],
        cwd=repo,
        env=env,
    )
    search_payload = run_json(
        [
            sys.executable,
            "-m",
            "rapidtriage",
            "case-search",
            str(db_path),
            "--case-id",
            "CASE-SMOKE",
            "-k",
            "PowerShell",
            "--source",
            "artifacts",
            "--json",
        ],
        cwd=repo,
        env=env,
    )
    status = "PASS" if int(search_payload.get("summary", {}).get("match_count", 0)) >= 1 else "FAIL"
    summary = {
        "command": "worker-case-db-smoke",
        "status": status,
        "output_dir": str(output_dir),
        "worker": str(worker),
        "evidence_root": str(evidence_root),
        "worker_jsonl": str(jsonl_path),
        "case_db": str(db_path),
        "worker_parse": worker_payload,
        "case_db_import": import_payload.get("imported_worker_jsonl"),
        "case_search_summary": search_payload.get("summary"),
    }
    (output_dir / "worker-case-db-smoke-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if status == "PASS" else 1


def locate_worker(repo: Path, explicit: str) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.environ.get("RAPIDTRIAGE_RUST_WORKER"):
        return Path(os.environ["RAPIDTRIAGE_RUST_WORKER"]).expanduser().resolve()
    suffix = ".exe" if os.name == "nt" else ""
    return repo / "engines" / "rust" / "target" / "debug" / f"rapid-worker{suffix}"


def run_checked(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    resolved = shutil.which(command[0]) or command[0]
    return subprocess.run(
        [resolved, *command[1:]],
        cwd=str(cwd),
        env=env,
        text=True,
        check=True,
    )


def run_json(command: list[str], *, cwd: Path, env: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise ValueError(f"command did not return a JSON object: {' '.join(command)}")
    return payload


def known_answer_evtx() -> bytes:
    blob = bytearray(4096 + 65536)
    blob[0:8] = b"ElfFile\0"
    chunk = 4096
    blob[chunk : chunk + 8] = b"ElfChnk\0"
    blob[chunk + 8 : chunk + 16] = (1).to_bytes(8, "little")
    blob[chunk + 16 : chunk + 24] = (1).to_bytes(8, "little")
    blob[chunk + 24 : chunk + 32] = (301).to_bytes(8, "little")
    blob[chunk + 32 : chunk + 40] = (301).to_bytes(8, "little")
    blob[chunk + 40 : chunk + 44] = (512).to_bytes(4, "little")
    blob[chunk + 44 : chunk + 48] = (700).to_bytes(4, "little")

    text = "PowerShell".encode("utf-16le")
    payload = bytearray([0x0F, 0x01, 0x01, 0x00, 0x05, 0x01])
    payload.extend(len(text).to_bytes(2, "little"))
    payload.extend(text)
    payload.append(0x00)

    record = chunk + 512
    record_size = 24 + len(payload) + 4
    blob[record : record + 4] = b"**\0\0"
    blob[record + 4 : record + 8] = record_size.to_bytes(4, "little")
    blob[record + 8 : record + 16] = (301).to_bytes(8, "little")
    blob[record + 16 : record + 24] = (132456789).to_bytes(8, "little")
    blob[record + 24 : record + 24 + len(payload)] = payload
    blob[record + record_size - 4 : record + record_size] = record_size.to_bytes(4, "little")
    return bytes(blob)


if __name__ == "__main__":
    raise SystemExit(main())
