#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/compare-runs.py --baseline <run dir> --candidate <run dir> \
#       [--allow-type TYPE ...] [--json] [--output <report.json>]
#
# Read-only comparison of two `rapidtriage run` output folders (R6 S1 lane A,
# docs/plans/r6-followups-2026-10-19.md section 1.3). Reads
# rapidtriage-run-summary.json, artifacts/rapidtriage-artifacts-<kind>.json
# (summary heads only; the multi-hundred-MB JSONL rows are streamed only for
# kinds whose artifact_type counts changed), rapidtriage-parser-scheduler.json
# and rapidtriage-run-progress.json.
#
# Verdict per existing artifact_type: unchanged | new-type | allowed (--allow-type)
# | move (kind total over non-allowed types unchanged) | regression. A kind is a
# regression when a type regressed, the kind disappeared with rows, its parser
# error count grew, or it did not complete. Kinds that exist only in the
# candidate are listed separately (rows, seconds, errors). Timing is reported
# with flags (> --slow-ratio x baseline) and only fails with --fail-on-slow.
# Reports carry counts, type names and at most 5 path tails per changed type
# (last 3 path components) - never row content.
#
# Exit codes: 0 pass, 1 regression, 2 input error. Engineering measurement only.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.artifact_profiles import (
    iter_artifact_output_rows,
    payload_record_count,
    read_artifact_output_head,
)

SCHEMA_VERSION = "rapidtriage-compare-runs-v1"
SUMMARY_NAME = "rapidtriage-run-summary.json"
SCHEDULER_NAME = "rapidtriage-parser-scheduler.json"
PROGRESS_NAME = "rapidtriage-run-progress.json"
ARTIFACT_FILE_RE = re.compile(r"^rapidtriage-artifacts-(?P<kind>.+)\.json$")
MAX_PATH_TAILS = 5
MAX_DISTINCT_PATHS = 200_000
PATH_TAIL_PARTS = 3
COMPLETED_STATUSES = {"completed", "reused", "delta-merged"}
EXIT_PASS, EXIT_REGRESSION, EXIT_INPUT_ERROR = 0, 1, 2


class InputError(Exception):
    pass


def _load_json(path: Path, *, required: bool) -> dict[str, object]:
    if not path.is_file():
        if required:
            raise InputError(f"missing {path.name} in {path.parent}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"unreadable {path.name}: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"{path.name} is not a JSON object")
    return payload


def _int(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def path_tail(path: object, parts: int = PATH_TAIL_PARTS) -> str:
    pieces = [piece for piece in re.split(r"[\\/]+", str(path or "")) if piece]
    return "/".join(pieces[-parts:])


# ---------------------------------------------------------------------------
# Run loading
# ---------------------------------------------------------------------------


def load_kind_heads(run_dir: Path) -> dict[str, dict[str, object]]:
    """kind -> {rows, type_counts, parser_error_count, collection_note_count, status, file}."""
    kinds: dict[str, dict[str, object]] = {}
    artifacts_dir = run_dir / "artifacts"
    if not artifacts_dir.is_dir():
        return kinds
    for path in sorted(artifacts_dir.iterdir()):
        match = ARTIFACT_FILE_RE.match(path.name)
        if not match or not path.is_file():
            continue
        try:
            head = read_artifact_output_head(path)
        except Exception as exc:  # report as an input error, do not crash
            raise InputError(f"unreadable {path.name}: {type(exc).__name__}") from exc
        summary = head.get("summary") if isinstance(head.get("summary"), Mapping) else {}
        type_counts = summary.get("artifact_type_counts") if isinstance(summary.get("artifact_type_counts"), Mapping) else {}
        notes = summary.get("collection_notes")
        parser_errors = head.get("parser_errors") if isinstance(head.get("parser_errors"), list) else []
        error_types = Counter(
            str(item.get("error_type") or "error") for item in parser_errors if isinstance(item, Mapping)
        )
        kinds[match.group("kind")] = {
            "rows": payload_record_count(head),
            "type_counts": {str(key): _int(value) for key, value in type_counts.items()},
            "parser_error_count": _int(summary.get("parser_error_count")),
            "parser_error_types": dict(sorted(error_types.items())),
            "collection_note_count": len(notes) if isinstance(notes, list) else 0,
            "status": str(summary.get("collection_status") or ""),
            "file": path,
        }
    return kinds


def provider_seconds(progress: Mapping[str, object], scheduler: Mapping[str, object]) -> dict[str, float]:
    seconds: dict[str, float] = {}
    events = scheduler.get("events") if isinstance(scheduler.get("events"), list) else []
    for event in events:
        if isinstance(event, Mapping) and event.get("kind"):
            seconds[str(event["kind"])] = round(_int(event.get("duration_ms")) / 1000.0, 3)
    providers = progress.get("providers") if isinstance(progress.get("providers"), Mapping) else {}
    for kind, entry in providers.items():
        if isinstance(entry, Mapping) and "duration_ms" in entry:
            seconds[str(kind)] = round(_int(entry.get("duration_ms")) / 1000.0, 3)
    return seconds


def scheduler_statuses(scheduler: Mapping[str, object]) -> dict[str, str]:
    events = scheduler.get("events") if isinstance(scheduler.get("events"), list) else []
    return {str(e["kind"]): str(e.get("status") or "") for e in events if isinstance(e, Mapping) and e.get("kind")}


def stage_durations(progress: Mapping[str, object]) -> tuple[list[dict[str, object]], float | None]:
    stages = progress.get("completed_stages") if isinstance(progress.get("completed_stages"), list) else []
    started = _parse_time(progress.get("started_at"))
    previous = started
    rows: list[dict[str, object]] = []
    for entry in stages:
        if not isinstance(entry, Mapping):
            continue
        done = _parse_time(entry.get("completed_at"))
        begin = _parse_time(entry.get("started_at")) or previous
        seconds = round((done - begin).total_seconds(), 3) if done and begin else None
        rows.append({"stage": str(entry.get("stage") or ""), "seconds": seconds})
        previous = done or previous
    finished = _parse_time(progress.get("completed_at")) or _parse_time(progress.get("updated_at"))
    total = round((finished - started).total_seconds(), 3) if finished and started else None
    return rows, total


def run_counts(summary: Mapping[str, object]) -> dict[str, int]:
    inner = summary.get("summary") if isinstance(summary.get("summary"), Mapping) else {}
    counts = inner.get("counts") if isinstance(inner.get("counts"), Mapping) else {}
    return {
        "artifacts": _int(counts.get("artifacts")),
        "timeline_events": _int(counts.get("timeline_events", inner.get("timeline_event_count"))),
        "file_candidates": _int(counts.get("files", inner.get("file_candidate_count"))),
        "indicators": _int(counts.get("indicators")),
    }


def load_run(run_dir: Path) -> dict[str, object]:
    if not run_dir.is_dir():
        raise InputError(f"not a directory: {run_dir}")
    summary = _load_json(run_dir / SUMMARY_NAME, required=True)
    scheduler = _load_json(run_dir / SCHEDULER_NAME, required=False)
    progress = _load_json(run_dir / PROGRESS_NAME, required=False)
    stages, total = stage_durations(progress)
    return {
        "dir": run_dir,
        "mode": str(summary.get("mode") or ""),
        "kinds": load_kind_heads(run_dir),
        "seconds": provider_seconds(progress, scheduler),
        "statuses": scheduler_statuses(scheduler),
        "stages": stages,
        "total_seconds": total,
        "counts": run_counts(summary),
    }


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def classify_types(
    base_types: Mapping[str, int], cand_types: Mapping[str, int], allow: set[str]
) -> list[dict[str, object]]:
    names = sorted(set(base_types) | set(cand_types))
    comparable_base = sum(count for name, count in base_types.items() if name not in allow)
    comparable_cand = sum(count for name, count in cand_types.items() if name not in allow)
    total_unchanged = comparable_base == comparable_cand
    rows: list[dict[str, object]] = []
    for name in names:
        base, cand = int(base_types.get(name, 0)), int(cand_types.get(name, 0))
        delta = cand - base
        if delta == 0:
            verdict = "unchanged"
        elif name in allow:
            verdict = "allowed"
        elif base == 0:
            verdict = "move" if total_unchanged else "new-type"
        elif total_unchanged:
            verdict = "move"
        else:
            verdict = "regression"
        rows.append({"artifact_type": name, "baseline": base, "candidate": cand, "delta": delta, "verdict": verdict})
    return rows


def _path_counters(path: Path, types: set[str]) -> dict[str, Counter[str]] | None:
    counters: dict[str, Counter[str]] = {name: Counter() for name in types}
    for row in iter_artifact_output_rows(path):
        name = str(row.get("artifact_type") or "")
        counter = counters.get(name)
        if counter is None:
            continue
        counter[str(row.get("path") or "")] += 1
        if len(counter) > MAX_DISTINCT_PATHS:
            return None
    return counters


def changed_path_tails(base_file: Path | None, cand_file: Path | None, types: set[str]) -> dict[str, list[str]]:
    """Up to MAX_PATH_TAILS path tails per type whose per-path row count differs."""
    if not types:
        return {}
    base = _path_counters(base_file, types) if base_file else {name: Counter() for name in types}
    cand = _path_counters(cand_file, types) if cand_file else {name: Counter() for name in types}
    tails: dict[str, list[str]] = {}
    for name in sorted(types):
        if base is None or cand is None:
            tails[name] = ["(too many distinct paths; not listed)"]
            continue
        b, c = base[name], cand[name]
        differing = sorted(p for p in set(b) | set(c) if b.get(p, 0) != c.get(p, 0))
        seen: list[str] = []
        for p in differing:
            tail = path_tail(p)
            if tail not in seen:
                seen.append(tail)
            if len(seen) >= MAX_PATH_TAILS:
                break
        tails[name] = seen
    return tails


def compare(
    baseline: Mapping[str, object],
    candidate: Mapping[str, object],
    *,
    allow: Iterable[str] = (),
    slow_ratio: float = 1.2,
    min_stage_seconds: float = 5.0,
    new_kind_budget_seconds: float = 60.0,
    path_tails: bool = True,
) -> dict[str, object]:
    allow_set = set(allow)
    base_kinds: Mapping[str, dict[str, object]] = baseline["kinds"]  # type: ignore[assignment]
    cand_kinds: Mapping[str, dict[str, object]] = candidate["kinds"]  # type: ignore[assignment]
    base_seconds: Mapping[str, float] = baseline["seconds"]  # type: ignore[assignment]
    cand_seconds: Mapping[str, float] = candidate["seconds"]  # type: ignore[assignment]
    cand_status: Mapping[str, str] = candidate["statuses"]  # type: ignore[assignment]

    kinds_out: list[dict[str, object]] = []
    for kind in sorted(base_kinds):
        base = base_kinds[kind]
        cand = cand_kinds.get(kind)
        reasons: list[str] = []
        if cand is None:
            type_rows = classify_types(base["type_counts"], {}, allow_set)  # type: ignore[arg-type]
            if _int(base["rows"]):
                reasons.append("kind-missing-in-candidate")
            cand_rows = 0
        else:
            type_rows = classify_types(base["type_counts"], cand["type_counts"], allow_set)  # type: ignore[arg-type]
            cand_rows = _int(cand["rows"])
            if _int(cand["parser_error_count"]) > _int(base["parser_error_count"]):
                reasons.append("parser-errors-increased")
            status = cand_status.get(kind)
            if status and status not in COMPLETED_STATUSES:
                reasons.append(f"scheduler-status-{status}")
        if any(row["verdict"] == "regression" for row in type_rows):
            reasons.append("artifact-type-count-changed")
        changed = {str(row["artifact_type"]) for row in type_rows if row["verdict"] != "unchanged"}
        tails = (
            changed_path_tails(base["file"], cand["file"] if cand else None, changed)  # type: ignore[arg-type]
            if path_tails and changed
            else {}
        )
        for row in type_rows:
            if row["artifact_type"] in tails:
                row["path_tails"] = tails[row["artifact_type"]]
        verdict = "regression" if reasons else ("move" if any(r["verdict"] == "move" for r in type_rows) else "pass")
        kinds_out.append(
            {
                "kind": kind,
                "baseline_rows": _int(base["rows"]),
                "candidate_rows": cand_rows,
                "delta": cand_rows - _int(base["rows"]),
                "baseline_parser_errors": _int(base["parser_error_count"]),
                "candidate_parser_errors": _int(cand["parser_error_count"]) if cand else 0,
                "baseline_collection_notes": _int(base["collection_note_count"]),
                "candidate_collection_notes": _int(cand["collection_note_count"]) if cand else 0,
                "baseline_seconds": base_seconds.get(kind),
                "candidate_seconds": cand_seconds.get(kind),
                "verdict": verdict,
                "reasons": reasons,
                "artifact_types": type_rows,
            }
        )

    new_kinds: list[dict[str, object]] = []
    for kind in sorted(set(cand_kinds) - set(base_kinds)):
        cand = cand_kinds[kind]
        new_kinds.append(
            {
                "kind": kind,
                "rows": _int(cand["rows"]),
                "seconds": cand_seconds.get(kind),
                "parser_errors": _int(cand["parser_error_count"]),
                "parser_error_types": cand["parser_error_types"],
                "collection_notes": _int(cand["collection_note_count"]),
                "status": cand_status.get(kind) or cand["status"],
                "artifact_type_counts": dict(sorted(cand["type_counts"].items())),  # type: ignore[union-attr]
            }
        )
    new_kind_seconds = round(sum(float(item["seconds"] or 0) for item in new_kinds), 3)

    timing_flags: list[str] = []
    base_stage = {str(s["stage"]): s["seconds"] for s in baseline["stages"]}  # type: ignore[union-attr]
    stages_out: list[dict[str, object]] = []
    for stage in candidate["stages"]:  # type: ignore[union-attr]
        name, cand_s = str(stage["stage"]), stage["seconds"]
        base_s = base_stage.get(name)
        ratio = round(cand_s / base_s, 3) if isinstance(cand_s, (int, float)) and base_s else None
        slow = bool(
            ratio is not None and ratio > slow_ratio and max(float(cand_s), float(base_s)) >= min_stage_seconds  # type: ignore[arg-type]
        )
        if slow:
            timing_flags.append(f"stage-slow:{name}")
        stages_out.append({"stage": name, "baseline_seconds": base_s, "candidate_seconds": cand_s, "ratio": ratio, "slow": slow})
    base_total, cand_total = baseline["total_seconds"], candidate["total_seconds"]
    total_ratio = round(cand_total / base_total, 3) if base_total and cand_total is not None else None  # type: ignore[operator]
    if total_ratio is not None and total_ratio > slow_ratio:
        timing_flags.append("total-slow")
    if new_kind_seconds > new_kind_budget_seconds:
        timing_flags.append("new-kinds-over-budget")

    counts_out = {
        key: {
            "baseline": baseline["counts"][key],  # type: ignore[index]
            "candidate": candidate["counts"][key],  # type: ignore[index]
            "delta": candidate["counts"][key] - baseline["counts"][key],  # type: ignore[index,operator]
        }
        for key in ("artifacts", "timeline_events", "file_candidates", "indicators")
    }
    regressions = [item["kind"] for item in kinds_out if item["verdict"] == "regression"]
    moves = [item["kind"] for item in kinds_out if item["verdict"] == "move"]
    return {
        "schema": SCHEMA_VERSION,
        "baseline": {"dir": str(baseline["dir"]), "mode": baseline["mode"]},
        "candidate": {"dir": str(candidate["dir"]), "mode": candidate["mode"]},
        "allowed_types": sorted(allow_set),
        "verdict": "regression" if regressions else "pass",
        "regression_kinds": regressions,
        "move_kinds": moves,
        "kinds": kinds_out,
        "new_kinds": new_kinds,
        "new_kinds_total_seconds": new_kind_seconds,
        "run_counts": counts_out,
        "stages": stages_out,
        "total_seconds": {"baseline": base_total, "candidate": cand_total, "ratio": total_ratio},
        "timing_flags": timing_flags,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _fmt(value: object) -> str:
    return "-" if value is None else str(value)


def render_text(report: Mapping[str, object]) -> str:
    lines = [f"compare-runs: {report['verdict'].upper()}"]  # type: ignore[union-attr]
    lines.append(f"{'kind':32} {'baseline':>10} {'candidate':>10} {'delta':>8} {'err b/c':>8}  verdict")
    for item in report["kinds"]:  # type: ignore[union-attr]
        err = f"{item['baseline_parser_errors']}/{item['candidate_parser_errors']}"
        lines.append(
            f"{item['kind']:32} {item['baseline_rows']:>10} {item['candidate_rows']:>10} {item['delta']:>8} {err:>8}  "
            f"{item['verdict']}{' (' + ', '.join(item['reasons']) + ')' if item['reasons'] else ''}"
        )
        for row in item["artifact_types"]:
            if row["verdict"] == "unchanged":
                continue
            lines.append(
                f"    {row['artifact_type']:40} {row['baseline']:>10} {row['candidate']:>10} {row['delta']:>8}  {row['verdict']}"
            )
            for tail in row.get("path_tails", []):
                lines.append(f"        ...{tail}")
    if report["new_kinds"]:
        lines.append("")
        lines.append(f"new kinds (total {report['new_kinds_total_seconds']} s)")
        lines.append(f"{'kind':32} {'rows':>10} {'seconds':>10} {'errors':>8}  status")
        for item in report["new_kinds"]:  # type: ignore[union-attr]
            lines.append(f"{item['kind']:32} {item['rows']:>10} {_fmt(item['seconds']):>10} {item['parser_errors']:>8}  {item['status']}")
    lines.append("")
    lines.append(f"{'count':32} {'baseline':>10} {'candidate':>10} {'delta':>8}")
    for key, value in report["run_counts"].items():  # type: ignore[union-attr]
        lines.append(f"{key:32} {value['baseline']:>10} {value['candidate']:>10} {value['delta']:>8}")
    lines.append("")
    lines.append(f"{'stage':32} {'baseline s':>10} {'candidate s':>11} {'ratio':>7}")
    for stage in report["stages"]:  # type: ignore[union-attr]
        flag = "  SLOW" if stage["slow"] else ""
        lines.append(f"{stage['stage']:32} {_fmt(stage['baseline_seconds']):>10} {_fmt(stage['candidate_seconds']):>11} {_fmt(stage['ratio']):>7}{flag}")
    total = report["total_seconds"]
    lines.append(f"{'total':32} {_fmt(total['baseline']):>10} {_fmt(total['candidate']):>11} {_fmt(total['ratio']):>7}")  # type: ignore[index]
    if report["timing_flags"]:
        lines.append("timing flags: " + ", ".join(report["timing_flags"]))  # type: ignore[arg-type]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare two rapidtriage run output folders (read-only).")
    parser.add_argument("--baseline", required=True, type=Path, help="baseline run output folder")
    parser.add_argument("--candidate", required=True, type=Path, help="candidate run output folder")
    parser.add_argument("--allow-type", action="append", default=[], metavar="TYPE", help="artifact_type whose count may change")
    parser.add_argument("--json", action="store_true", help="print the JSON report instead of tables")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this file")
    parser.add_argument("--slow-ratio", type=float, default=1.2, help="timing flag threshold (default 1.2)")
    parser.add_argument("--min-stage-seconds", type=float, default=5.0, help="ignore stage timing below this (default 5)")
    parser.add_argument("--new-kind-budget-seconds", type=float, default=60.0, help="new kinds total time budget (default 60)")
    parser.add_argument("--fail-on-slow", action="store_true", help="exit 1 when any timing flag is raised")
    parser.add_argument("--no-path-tails", action="store_true", help="skip streaming rows for path tails")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        baseline = load_run(args.baseline)
        candidate = load_run(args.candidate)
    except InputError as exc:
        print(f"compare-runs: input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    report = compare(
        baseline,
        candidate,
        allow=args.allow_type,
        slow_ratio=args.slow_ratio,
        min_stage_seconds=args.min_stage_seconds,
        new_kind_budget_seconds=args.new_kind_budget_seconds,
        path_tails=not args.no_path_tails,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text if args.json else render_text(report))
    if report["verdict"] == "regression":
        return EXIT_REGRESSION
    if args.fail_on_slow and report["timing_flags"]:
        return EXIT_REGRESSION
    return EXIT_PASS


if __name__ == "__main__":
    raise SystemExit(main())
