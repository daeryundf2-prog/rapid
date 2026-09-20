#!/usr/bin/env python3
"""Finish the downstream stages of an interrupted ``rapidtriage run``.

When a ``run`` dies after writing its large stage outputs (manifest,
docs, files, artifacts) but before extract/timeline/indicators/summary,
re-running with ``--resume`` reloads every cached payload — which is not
safe for multi-GB outputs.  This driver completes the remaining stages
against the on-disk outputs using ``rapidtriage.core.json_stream`` so
only the members each stage needs are materialized:

- docs/files extract manifests are produced by ``run_extract`` with
  payloads assembled from streamed members.
- the timeline is produced by ``run_timeline`` with payload overrides
  (artifact ``artifacts`` arrays are fed as streaming generators).
- the indicator summary is produced by ``build_indicator_summary`` with
  in-memory payloads for small outputs and ``streamed_outputs`` for
  oversized ones.
- run summary/report/checkpoints/audit are written with the same
  builders the pipeline uses.

The audit record and ``completion`` notes in the summary disclose that
the tail stages were produced by this streamed completion path.

Usage:
    python scripts/complete-run.py --output-dir D:\\e01-full-extract \
        --source-image C:\\e01-raw\\bsh-image.raw --mode hacking
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.audit import write_audit_record
from rapidtriage.core.disk_image import DiskImageExtractionResult
from rapidtriage.core.docs import write_result
from rapidtriage.core.extract import run_extract
from rapidtriage.core.indicators import build_indicator_summary
from rapidtriage.core.input_root import InputRoot
from rapidtriage.core.json_stream import (
    LazyArray,
    LazyObject,
    Scalar,
    iter_array_items,
    open_json,
)
from rapidtriage.core.run import (
    RUN_PROFILES,
    build_markdown_report,
    build_preview_sandbox_run_policy_manifest,
    build_run_source_record,
    build_run_summary,
    build_sqlite_fts_run_optimization_manifest,
    record_run_checkpoint,
    write_run_checkpoints,
)
from rapidtriage.core.timeline import build_timeline_report, run_timeline

STREAM_THRESHOLD_BYTES = 1 << 30  # 1 GiB — stream outputs larger than this


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def stream_members(path: Path, names: set[str]) -> dict[str, object]:
    """Return materialized values for the named top-level members.

    Members not in ``names`` are fast-skipped, so this is safe on run
    outputs that embed multi-GB sections.
    """
    out: dict[str, object] = {}
    with open_json(path) as root:
        for key, node in root.members():
            if key in names:
                out[key] = node.materialize()
            if len(out) == len(names):
                break
    return out


def load_docs_payload(docs_path: Path) -> dict[str, object]:
    """Assemble the docs payload members downstream stages consume.

    ``docs.json`` embeds the whole manifest, so the file can be tens of
    GB even though the members needed below are small.
    """
    wanted = {"command", "root", "summary", "results", "candidates", "index", "scan_scope_root"}
    payload = stream_members(docs_path, wanted)
    missing = {"command", "summary", "results", "candidates"} - payload.keys()
    if missing:
        raise SystemExit(f"{docs_path} is missing required members: {sorted(missing)}")
    return payload


def reduce_manifest_providers(path: Path) -> dict[str, object]:
    """Build a manifest payload whose providers keep only name + types.

    ``build_run_summary`` uses providers for ``provider.name``,
    ``len(provider['artifacts'])`` and per-artifact ``artifact_type`` —
    this reducer preserves exactly that information.
    """
    providers: list[dict[str, object]] = []
    scalars: dict[str, object] = {}
    with open_json(path) as root:
        for key, node in root.members():
            if key == "providers" and isinstance(node, LazyArray):
                for provider in node.items(lazy=True):
                    providers.append(_reduce_provider(provider))
            elif isinstance(node, Scalar):
                scalars[key] = node.value
            elif key == "summary":
                scalars[key] = node.materialize()
    payload: dict[str, object] = dict(scalars)
    payload["providers"] = providers
    return payload


def _reduce_provider(node: object) -> dict[str, object]:
    name = None
    artifacts: list[dict[str, object]] = []
    if not isinstance(node, LazyObject):
        return {"name": name, "artifacts": artifacts}
    for key, child in node.members():
        if key == "name" and isinstance(child, Scalar):
            name = child.value
        elif key == "artifacts" and isinstance(child, LazyArray):
            for artifact in child.items(lazy=True):
                artifacts.append({"artifact_type": _artifact_type_of(artifact)})
    return {"name": name, "artifacts": artifacts}


def _artifact_type_of(node: object) -> object:
    if not isinstance(node, LazyObject):
        return None
    for key, child in node.members():
        if key == "artifact_type" and isinstance(child, Scalar):
            return child.value
    return None


def load_artifact_summaries(artifacts_dir: Path) -> dict[str, dict[str, object]]:
    """Return {kind: minimal-payload} for every artifact output file."""
    payloads: dict[str, dict[str, object]] = {}
    for path in sorted(artifacts_dir.glob("rapidtriage-artifacts-*.json")):
        kind = path.stem.replace("rapidtriage-artifacts-", "")
        members = stream_members(path, {"command", "kind", "summary"})
        payloads[kind] = {
            "command": "artifacts",
            "kind": members.get("kind", kind),
            "summary": members.get("summary", {}),
        }
        log(f"artifact summary loaded: {kind}")
    return payloads


def artifact_streaming_payload(path: Path, kind: str) -> dict[str, object]:
    """Timeline input payload whose ``artifacts`` member is a generator."""
    return {
        "command": "artifacts",
        "kind": kind,
        "artifacts": iter_array_items(path, "artifacts"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-image", type=Path, default=None)
    parser.add_argument("--mode", default="hacking")
    parser.add_argument("--stream-threshold-bytes", type=int, default=STREAM_THRESHOLD_BYTES)
    args = parser.parse_args()

    output_dir = args.output_dir.expanduser().resolve()
    profile = RUN_PROFILES[args.mode]

    manifest_path = output_dir / "rapidtriage-manifest.json"
    docs_path = output_dir / "rapidtriage-docs.json"
    docs_index_path = output_dir / "rapidtriage-docs-index.json"
    files_path = output_dir / "rapidtriage-files.json"
    artifacts_dir = output_dir / "artifacts"
    docs_extract_dir = output_dir / "docs-extract"
    files_extract_dir = output_dir / "files-extract"
    docs_extract_manifest = docs_extract_dir / "rapidtriage-extract-manifest.json"
    files_extract_manifest = files_extract_dir / "rapidtriage-extract-manifest.json"
    timeline_path = output_dir / "rapidtriage-timeline.json"
    timeline_report_path = output_dir / "rapidtriage-timeline-report.md"
    indicators_path = output_dir / "rapidtriage-indicators.json"
    summary_path = output_dir / "rapidtriage-run-summary.json"
    report_path = output_dir / "rapidtriage-run-report.md"
    disk_image_metadata_path = output_dir / "rapidtriage-disk-image.json"
    fingerprint_path = output_dir / "rapidtriage-run-fingerprint.json"
    checkpoint_path = output_dir / "rapidtriage-run-checkpoints.json"
    scheduler_path = output_dir / "rapidtriage-parser-scheduler.json"
    parser_crash_ledger_path = output_dir / "rapidtriage-parser-crash-isolation.json"
    memory_cap_ledger_path = output_dir / "rapidtriage-memory-cap-enforcement.json"
    preview_sandbox_policy_path = output_dir / "rapidtriage-preview-sandbox-policy.json"
    sqlite_fts_optimization_path = output_dir / "rapidtriage-sqlite-fts-optimization.json"

    for required in (manifest_path, docs_path, files_path, disk_image_metadata_path, fingerprint_path):
        if not required.is_file():
            raise SystemExit(f"required upstream output is missing: {required}")

    disk_image_meta = json.loads(disk_image_metadata_path.read_text(encoding="utf-8"))
    extract_dir = Path(disk_image_meta["extract_dir"])
    input_root = InputRoot(
        source_path=str(disk_image_meta.get("source_path") or args.source_image or ""),
        root_path=extract_dir,
        kind="disk-image-derived",
    )
    image_result = DiskImageExtractionResult(
        source_path=Path(str(disk_image_meta.get("source_path") or args.source_image or "")),
        stage_dir=Path(disk_image_meta["stage_dir"]),
        extract_dir=extract_dir,
        image_paths=tuple(Path(p) for p in disk_image_meta.get("image_paths", [])),
        partition_start_sector=disk_image_meta.get("partition_start_sector"),
        recovery_mode=str(disk_image_meta.get("recovery_mode") or ""),
        source_integrity=tuple(disk_image_meta.get("source_integrity", [])),
        tool_preflight=tuple(disk_image_meta.get("tool_preflight", [])),
        partition_table=tuple(disk_image_meta.get("partition_table", [])),
        split_part_warnings=tuple(disk_image_meta.get("split_part_warnings", [])),
        split_set_profile=dict(disk_image_meta.get("split_set_profile", {})),
        recovered_root_manifest=dict(disk_image_meta.get("recovered_root_manifest", {})),
        command_history=tuple(disk_image_meta.get("command_history", [])),
        warnings=tuple(disk_image_meta.get("warnings", [])),
        commercial_grade_ready=bool(disk_image_meta.get("commercial_grade_ready", False)),
    )
    fingerprint_payload = json.loads(fingerprint_path.read_text(encoding="utf-8"))
    artifact_paths = {p.stem.replace("rapidtriage-artifacts-", ""): p for p in sorted(artifacts_dir.glob("rapidtriage-artifacts-*.json"))}

    checkpoint_records: list[dict[str, object]] = []
    reused_outputs: set[str] = set()

    for stage, path in (
        ("disk-image", disk_image_metadata_path),
        ("manifest", manifest_path),
        ("docs", docs_path),
        ("docs-index", docs_index_path),
        ("files", files_path),
        ("parser-scheduler", scheduler_path),
        ("parser-crash-isolation", parser_crash_ledger_path),
    ):
        record_run_checkpoint(checkpoint_records, stage, path, reused=True)
        reused_outputs.add(stage)
    for kind, path in artifact_paths.items():
        record_run_checkpoint(checkpoint_records, f"artifacts-{kind}", path, reused=True)
        reused_outputs.add(f"artifacts-{kind}")

    log("loading docs payload members (streaming over embedded manifest)")
    docs_payload = load_docs_payload(docs_path)
    log("loading files payload")
    files_payload = json.loads(files_path.read_text(encoding="utf-8"))

    docs_extract_payload = run_extract(
        docs_path,
        docs_extract_dir,
        kinds=profile.docs_extract_kinds,
        payload=docs_payload,
    )
    write_result(docs_extract_payload, docs_extract_manifest)
    record_run_checkpoint(checkpoint_records, "docs-extract", docs_extract_manifest, reused=False)
    log(f"docs extract done: {docs_extract_payload['summary']}")

    files_extract_payload = run_extract(
        files_path,
        files_extract_dir,
        categories=profile.file_extract_categories,
        payload=files_payload,
    )
    write_result(files_extract_payload, files_extract_manifest)
    record_run_checkpoint(checkpoint_records, "files-extract", files_extract_manifest, reused=False)
    log(f"files extract done: {files_extract_payload['summary']}")

    log("building timeline (artifact arrays streamed from disk)")
    input_payloads: dict[str, dict[str, object]] = {
        str(files_path.expanduser().resolve()): files_payload,
        str(docs_path.expanduser().resolve()): docs_payload,
    }
    for kind, path in artifact_paths.items():
        input_payloads[str(path.expanduser().resolve())] = artifact_streaming_payload(path, kind)
    timeline_payload = run_timeline(
        root=input_root.root_path,
        input_kind=input_root.kind,
        files_inputs=[files_path],
        docs_inputs=[docs_path],
        artifacts_inputs=list(artifact_paths.values()),
        input_payloads=input_payloads,
    )
    write_result(timeline_payload, timeline_path)
    timeline_report_path.write_text(
        build_timeline_report(timeline_payload),
        encoding="utf-8",
    )
    record_run_checkpoint(checkpoint_records, "timeline", timeline_path, reused=False)
    log(f"timeline done: {timeline_payload['summary']}")

    artifact_outputs = {f"artifacts_{kind}": path for kind, path in artifact_paths.items()}
    provisional_outputs = {
        "manifest": manifest_path,
        "docs": docs_path,
        "docs_index": docs_index_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        "timeline": timeline_path,
        "timeline_report": timeline_report_path,
        **artifact_outputs,
    }
    output_payloads: dict[str, dict[str, object]] = {
        "files": files_payload,
        "timeline": timeline_payload,
    }
    streamed = set()
    for name, path in (
        [("docs", docs_path), *artifact_outputs.items()]
    ):
        if path.is_file() and path.stat().st_size > args.stream_threshold_bytes:
            streamed.add(name)
        else:
            output_payloads[name] = None  # load from disk via read_json_path
    output_payloads = {k: v for k, v in output_payloads.items() if v is not None}
    log(f"indicators: streaming outputs {sorted(streamed)}")
    indicators_payload = build_indicator_summary(
        {"outputs": {key: str(path) for key, path in provisional_outputs.items()}},
        output_payloads=output_payloads,
        streamed_outputs=streamed,
    )
    write_result(indicators_payload, indicators_path)
    record_run_checkpoint(checkpoint_records, "indicators", indicators_path, reused=False)
    log(f"indicators done: {indicators_payload['summary']}")

    log("reducing manifest providers (streaming)")
    manifest_payload = reduce_manifest_providers(manifest_path)
    artifact_payloads = load_artifact_summaries(artifacts_dir)
    parser_crash_ledger = (
        json.loads(parser_crash_ledger_path.read_text(encoding="utf-8"))
        if parser_crash_ledger_path.is_file()
        else {}
    )
    artifact_scheduler_manifest = (
        json.loads(scheduler_path.read_text(encoding="utf-8")) if scheduler_path.is_file() else {}
    )

    outputs = {
        "fingerprint": fingerprint_path,
        "checkpoints": checkpoint_path,
        "parser_scheduler": scheduler_path,
        "parser_crash_isolation": parser_crash_ledger_path,
        "memory_cap_enforcement": memory_cap_ledger_path,
        "preview_sandbox_policy": preview_sandbox_policy_path,
        "sqlite_fts_optimization": sqlite_fts_optimization_path,
        "manifest": manifest_path,
        "docs": docs_path,
        "docs_index": docs_index_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        "timeline": timeline_path,
        "timeline_report": timeline_report_path,
        "indicators": indicators_path,
        **artifact_outputs,
        "summary": summary_path,
        "report": report_path,
        "disk_image": disk_image_metadata_path,
    }
    preview_sandbox_policy = build_preview_sandbox_run_policy_manifest(outputs=outputs)
    write_result(preview_sandbox_policy, preview_sandbox_policy_path)
    sqlite_fts_optimization = build_sqlite_fts_run_optimization_manifest(outputs=outputs)
    write_result(sqlite_fts_optimization, sqlite_fts_optimization_path)

    write_run_checkpoints(
        checkpoint_path,
        output_dir=output_dir,
        input_fingerprint=fingerprint_payload,
        resume_requested=True,
        resume_effective=True,
        resume_disabled_reason="",
        checkpoints=checkpoint_records,
    )

    summary_payload = build_run_summary(
        root=input_root.root_path,
        output_dir=output_dir,
        profile=profile,
        manifest_payload=manifest_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        indicators_payload=indicators_payload,
        outputs=outputs,
        safety={
            "dry_run": False,
            "read_only": False,
            "max_extract_size_bytes": 0,
            "max_file_count": 0,
            "memory_cap_bytes": 0,
            "memory_cap_source": "unset",
            "overwrite": False,
            "resume": True,
            "resume_effective": True,
            "resume_disabled_reason": "",
            "known_good_hash_feeds": [],
            "hide_known_good": False,
            "known_good_max_hash_bytes": 0,
            "reused_outputs": sorted(reused_outputs),
            "delta_applied_outputs": [],
            "evidence_delta": {},
            "input_fingerprint": fingerprint_payload,
            "artifact_scheduler": {
                "strategy": "parallel-threaded-deterministic-output",
                "scheduled_count": len(profile.artifacts_kinds),
                "manifest": artifact_scheduler_manifest,
            },
            "parser_crash_isolation_ledger": parser_crash_ledger,
            "memory_cap_stage_checks": [],
            "preview_sandbox_policy": preview_sandbox_policy,
            "sqlite_fts_optimization": sqlite_fts_optimization,
            "completion": {
                "mode": "streamed-stage-completion",
                "note": "downstream stages were produced by scripts/complete-run.py "
                "because upstream outputs exceed safe json.load limits",
            },
        },
        source=build_run_source_record(input_root, image_result=image_result, outputs=outputs),
    )
    audit_output = output_dir / "rapidtriage-run-audit.json"
    summary_payload["audit"] = str(audit_output)
    memory_cap_manifest = summary_payload.get("processing", {}).get("memory_cap_enforcement", {}).get(
        "memory_cap_enforcement_manifest",
        {},
    )
    if isinstance(memory_cap_manifest, dict) and memory_cap_manifest:
        write_result(memory_cap_manifest, memory_cap_ledger_path)
    report_path.write_text(
        build_markdown_report(
            summary_payload,
            docs_payload=docs_payload,
            files_payload=files_payload,
            docs_extract_payload=docs_extract_payload,
            files_extract_payload=files_extract_payload,
            artifact_payloads=artifact_payloads,
            timeline_payload=timeline_payload,
            indicators_payload=indicators_payload,
        ),
        encoding="utf-8",
    )
    write_result(summary_payload, summary_path)
    write_audit_record(
        audit_output,
        command="run",
        options={
            "mode": args.mode,
            "output_dir": str(output_dir),
            "completion": "streamed-stage-completion",
            "image_source": str(image_result.source_path),
            "image_extracted_root": str(image_result.extract_dir),
        },
        input_root=input_root,
        input_files=[("image-source", image_result.source_path)],
        output_files=[(name, path) for name, path in outputs.items()],
        notes=[
            "Downstream stages completed via scripts/complete-run.py with streamed JSON readers.",
            "Upstream manifest/docs/files/artifacts outputs were reused from disk.",
        ],
    )
    log("completion finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
