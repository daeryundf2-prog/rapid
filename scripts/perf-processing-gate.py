#!/usr/bin/env python3
"""Processing performance regression gate (T-214, QA-129).

    python scripts/perf-processing-gate.py --current <run>/rapidtriage-run-summary.json --corpus IMG-B \\
        [--output-dir-size <run output folder>] [--baseline <baseline.json>] \\
        [--allow-unmeasured output_bytes] [--tolerance 0.2] [--output <report.json>] [--json]

Compares per-step durations and the output size of one run against a committed baseline
(default ``docs/validation/perf-processing-baseline.json``, corpus ``IMG-B``). Lower is
better for every metric; a step whose current value is more than ``--tolerance`` (default
the baseline's, 20%) above its baseline is *worsened*.

``--current`` accepts:

* a run summary (``rapidtriage-run-summary.json``) or progress file carrying ``plan``, or
  the run plan itself (``rapidtriage-run-plan.json``, ``groups``). Read from the plan:
  ``prepare_s`` (group ``prepare`` ``duration_ms``), ``collection_s`` (first provider task
  ``started_at`` to last provider ``finished_at``), ``total_s`` (first group start to last
  group finish) and ``group.<id>_s`` for every timed group;
* a flat record ``{"metrics": {"prepare_s": ..., "output_bytes": ...}}`` (hand-entered
  or from another tool).

Run summaries do not record the output size: pass ``--output-dir-size <run folder>`` to
measure it (files only, links and junctions not followed), or put ``output_bytes`` in a
flat record. Metrics without a baseline are listed for information.

"비교 불충분" (verdict ``insufficient``, exit 3; R8 WB-13 review P1-3) when:

* a baseline metric the current run does not have (``unmeasured``) is not named in
  ``--allow-unmeasured a,b``;
* the plan is not comparable: its ``outcome`` is not ``complete`` (failed, partial, cancelled,
  interrupted or still running), a provider task did not finish (status other than
  ``completed`` / pre-run ``skipped``, or no ``finished_at``), or a task was reused or resumed
  from an earlier run (``reused`` / ``resumed_from_checkpoint``) -- each is listed in the report;
* the run's corpus identity (a flat record's ``corpus`` / ``evidence_bytes``) differs from the
  baseline corpus's ``identity``.

``--corpus`` is required and must name a baseline corpus: the gate does not guess which image
was processed. Non-finite numbers (NaN, Infinity), negative metrics and a tolerance outside
(0, 1] are input errors.

Exit 0 nothing worsened and everything compared, 1 at least one step worsened (the list is
printed), 2 input error, 3 비교 불충분. Engineering measurement only.
"""

from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import datetime as dt
import json
import math
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = REPO_ROOT / "docs" / "validation" / "perf-processing-baseline.json"
SCHEMA_VERSION = "perf-processing-gate-v1"
BASELINE_SCHEMA = "perf-processing-baseline-v1"
DEFAULT_TOLERANCE = 0.2
EXIT_OK, EXIT_WORSE, EXIT_INPUT, EXIT_INSUFFICIENT = 0, 1, 2, 3
OK, WORSENED, UNMEASURED, NO_BASELINE = "ok", "worsened", "unmeasured", "no_baseline"
INSUFFICIENT = "insufficient"
INSUFFICIENT_LABEL = "비교 불충분"
IDENTITY_KEYS = ("corpus", "evidence_bytes")
STEP_LABELS = {
    "prepare_s": "증거 준비(prepare) 시간",
    "collection_s": "수집 구간 시간",
    "total_s": "전체 처리 시간",
    "output_bytes": "출력 크기",
}


class GateInputError(Exception):
    """Input problem; the CLI exits 2 with a Korean message."""


def _read_json(path: Path, what: str) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise GateInputError(f"{what} 파일이 없습니다: {path}") from exc
    except (OSError, ValueError) as exc:
        raise GateInputError(f"{what} 파일을 읽지 못했습니다: {path} ({exc})") from exc
    if not isinstance(data, dict):
        raise GateInputError(f"{what} 파일의 최상위가 객체가 아닙니다: {path}")
    return data


def _numeric_metrics(raw: object, where: str) -> dict[str, float]:
    if not isinstance(raw, Mapping):
        raise GateInputError(f"{where}에 metrics 객체가 없습니다.")
    out: dict[str, float] = {}
    for name, value in raw.items():
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GateInputError(f"{where}의 {name} 값이 숫자가 아닙니다: {value!r}")
        if not math.isfinite(value) or value < 0:
            raise GateInputError(f"{where}의 {name} 값이 유한한 0 이상의 수가 아닙니다: {value!r}")
        out[str(name)] = float(value)
    return out


def check_tolerance(value: object, where: str) -> float:
    """A fraction in (0, 1]; ``True``, NaN, negative or > 1 is an input error (review P1-3)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 1:
        raise GateInputError(f"{where} 허용 폭은 0보다 크고 1 이하인 수여야 합니다: {value!r}")
    return float(value)


def load_baseline(path: Path, corpus: str | None) -> tuple[str, dict[str, float], float, dict[str, object]]:
    """``(corpus, metrics, tolerance, identity)`` from the baseline file; ``corpus`` must be named."""
    data = _read_json(path, "기준선")
    if data.get("schema_version") != BASELINE_SCHEMA:
        raise GateInputError(f"기준선 schema_version이 {BASELINE_SCHEMA}가 아닙니다: {path}")
    corpora = data.get("corpora")
    if not isinstance(corpora, Mapping) or not corpora:
        raise GateInputError(f"기준선에 corpora가 없습니다: {path}")
    if not corpus:
        raise GateInputError(
            f"--corpus로 현재 런이 처리한 코퍼스를 밝혀야 합니다 (기준선 코퍼스: {', '.join(corpora)})."
        )
    name = corpus
    if name not in corpora:
        raise GateInputError(f"기준선에 코퍼스 {name}가 없습니다 (있는 코퍼스: {', '.join(corpora)}).")
    entry = corpora[name]
    metrics = _numeric_metrics(entry.get("metrics") if isinstance(entry, Mapping) else None, f"기준선 {name}")
    tolerance = check_tolerance(data.get("tolerance", DEFAULT_TOLERANCE), "기준선")
    raw_identity = entry.get("identity") if isinstance(entry, Mapping) else None
    identity = {key: raw_identity[key] for key in IDENTITY_KEYS if key in raw_identity} if isinstance(raw_identity, Mapping) else {}
    identity.setdefault("corpus", name)
    return name, metrics, tolerance, identity


def _parse_time(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        stamp = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.timezone.utc)


def _span_seconds(items: Iterable[Mapping[str, object]]) -> float | None:
    starts: list[dt.datetime] = []
    ends: list[dt.datetime] = []
    for item in items:
        start, end = _parse_time(item.get("started_at")), _parse_time(item.get("finished_at"))
        if start is not None and end is not None:
            starts.append(start)
            ends.append(end)
    if not starts:
        return None
    return round(max(0.0, (max(ends) - min(starts)).total_seconds()), 3)


def plan_metrics(plan: Mapping[str, object]) -> dict[str, float]:
    """Step timings from a run plan (``groups`` -> ``tasks``)."""
    groups = [group for group in plan.get("groups") or [] if isinstance(group, Mapping)]  # type: ignore[union-attr]
    metrics: dict[str, float] = {}
    for group in groups:
        duration = group.get("duration_ms")
        if isinstance(duration, (int, float)) and not isinstance(duration, bool):
            if not math.isfinite(duration) or duration < 0:
                raise GateInputError(f"그룹 {group.get('id')}의 duration_ms가 유한한 0 이상의 수가 아닙니다: {duration!r}")
            metrics[f"group.{group.get('id')}_s"] = round(float(duration) / 1000.0, 3)
    if "group.prepare_s" in metrics:
        metrics["prepare_s"] = metrics["group.prepare_s"]
    providers = [
        task
        for group in groups
        for task in group.get("tasks") or []  # type: ignore[union-attr]
        if isinstance(task, Mapping) and task.get("type") == "provider"
    ]
    collection = _span_seconds(providers)
    if collection is not None:
        metrics["collection_s"] = collection
    total = _span_seconds(groups)
    if total is not None:
        metrics["total_s"] = total
    return metrics


def plan_problems(plan: Mapping[str, object]) -> dict[str, object]:
    """Why a plan's timings cannot stand for a full run (review P1-3): empty when comparable."""
    problems: dict[str, object] = {}
    outcome = plan.get("outcome")
    if outcome != "complete":
        problems["outcome"] = outcome
    unfinished: list[str] = []
    reused: list[str] = []
    for group in plan.get("groups") or []:  # type: ignore[union-attr]
        if not isinstance(group, Mapping):
            continue
        for task in group.get("tasks") or []:  # type: ignore[union-attr]
            if not isinstance(task, Mapping):
                continue
            task_id = f"{group.get('id')}/{task.get('id')}"
            status = task.get("status")
            if task.get("reused") or task.get("resumed_from_checkpoint") or status == "reused":
                reused.append(task_id)
            elif task.get("type") == "provider":
                skipped = status == "skipped"
                if not skipped and (status != "completed" or _parse_time(task.get("finished_at")) is None):
                    unfinished.append(f"{task_id}({status or '상태 없음'})")
    if unfinished:
        problems["unfinished_providers"] = unfinished
    if reused:
        problems["reused_steps"] = reused
    return problems


def current_metrics(path: Path) -> tuple[dict[str, float], dict[str, object], dict[str, object]]:
    """``(metrics, plan problems, identity)`` of the current run from a flat record, a run plan,
    or a summary/progress with ``plan``."""
    data = _read_json(path, "현재 처리 요약")
    if "metrics" in data:
        identity = {key: data[key] for key in IDENTITY_KEYS if data.get(key) is not None}
        return _numeric_metrics(data["metrics"], "현재 처리 요약"), {}, identity
    plan = data if isinstance(data.get("groups"), list) else data.get("plan")
    if isinstance(plan, Mapping):
        return plan_metrics(plan), plan_problems(plan), {}
    raise GateInputError(
        f"현재 처리 요약에서 단계 시간을 찾지 못했습니다: {path} (plan·groups·metrics 중 하나가 필요합니다)."
    )


def identity_mismatches(baseline: Mapping[str, object], current: Mapping[str, object]) -> list[dict[str, object]]:
    """Identity fields both sides state with different values."""
    return [
        {"field": key, "baseline": baseline[key], "current": current[key]}
        for key in IDENTITY_KEYS
        if key in baseline and key in current and baseline[key] != current[key]
    ]


def _split(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def folder_size(root: Path) -> int:
    """Total file bytes under ``root``; symbolic links and junctions are not followed."""
    if not root.is_dir():
        raise GateInputError(f"출력 폴더가 없습니다: {root}")
    total = 0
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
    return total


def compare(baseline: Mapping[str, float], current: Mapping[str, float], tolerance: float) -> list[dict[str, object]]:
    """One row per metric: baseline metrics first (in baseline order), then current-only ones."""
    steps: list[dict[str, object]] = []
    for name, base in baseline.items():
        row: dict[str, object] = {"step": name, "label": _label(name), "baseline": base, "current": current.get(name)}
        value = current.get(name)
        if value is None:
            row.update(status=UNMEASURED, reason="현재 처리 요약에 이 단계 값이 없음(미측정)")
        elif base <= 0:
            row.update(status=UNMEASURED, reason="기준선 값이 0 이하라 비교할 수 없음")
        else:
            ratio = value / base
            row.update(ratio=round(ratio, 4), change_pct=round((ratio - 1) * 100, 1))
            row["status"] = WORSENED if round(ratio - 1, 9) > tolerance else OK
        steps.append(row)
    for name in sorted(set(current) - set(baseline)):
        steps.append({"step": name, "label": _label(name), "baseline": None, "current": current[name], "status": NO_BASELINE})
    return steps


def _label(name: str) -> str:
    if name in STEP_LABELS:
        return STEP_LABELS[name]
    if name.startswith("group.") and name.endswith("_s"):
        return f"{name[6:-2]} 그룹 시간"
    return name


def _format(name: str, value: object) -> str:
    if not isinstance(value, (int, float)):
        return "-"
    if name.endswith("_bytes"):
        return f"{value / 1e9:.2f} GB"
    return f"{value:,.0f} s"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail when a processing step or the output size worsened by more than the tolerance (T-214).")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE, help="baseline JSON (default: docs/validation/perf-processing-baseline.json)")
    parser.add_argument("--current", type=Path, required=True, help="run summary / run plan / flat {metrics} JSON of the run to check")
    parser.add_argument("--corpus", help="baseline corpus the current run processed (required, e.g. IMG-B)")
    parser.add_argument("--output-dir-size", type=Path, help="measure output_bytes as the size of this run output folder")
    parser.add_argument("--allow-unmeasured", help="comma-separated baseline metrics that may be missing (default: none)")
    parser.add_argument("--tolerance", type=float, help="allowed worsening as a fraction in (0, 1] (default: the baseline's, 0.2)")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    args = parser.parse_args(argv)
    try:
        corpus, baseline, tolerance, baseline_identity = load_baseline(args.baseline, args.corpus)
        if args.tolerance is not None:
            tolerance = check_tolerance(args.tolerance, "--tolerance")
        allowed = _split(args.allow_unmeasured)
        unknown = sorted(set(allowed) - set(baseline))
        if unknown:
            raise GateInputError(f"--allow-unmeasured에 기준선에 없는 지표: {', '.join(unknown)}")
        current, problems, current_identity = current_metrics(args.current)
        if args.output_dir_size is not None:
            current["output_bytes"] = float(folder_size(args.output_dir_size))
    except GateInputError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return EXIT_INPUT
    steps = compare(baseline, current, tolerance)
    worsened = [str(row["step"]) for row in steps if row["status"] == WORSENED]
    unmeasured = [str(row["step"]) for row in steps if row["status"] == UNMEASURED]
    not_allowed = [name for name in unmeasured if name not in allowed]
    mismatches = identity_mismatches(baseline_identity, current_identity)
    insufficient: list[str] = []
    if problems.get("outcome", "complete") != "complete":
        insufficient.append(f"처리 결과가 complete가 아님(outcome: {problems['outcome']})")
    if problems.get("unfinished_providers"):
        insufficient.append("끝나지 않은 수집 작업: " + ", ".join(problems["unfinished_providers"]))  # type: ignore[arg-type]
    if problems.get("reused_steps"):
        insufficient.append("이전 런에서 재사용·재개한 단계: " + ", ".join(problems["reused_steps"]))  # type: ignore[arg-type]
    if mismatches:
        insufficient.append(
            "기준선 코퍼스와 다른 증거: "
            + ", ".join(f"{item['field']} {item['current']!r} ≠ 기준 {item['baseline']!r}" for item in mismatches)
        )
    if not_allowed:
        insufficient.append("미측정 지표(--allow-unmeasured로 허용하지 않음): " + ", ".join(not_allowed))
    plan_refused = bool(problems or mismatches)
    if plan_refused or (not_allowed and not worsened):
        verdict = INSUFFICIENT
    else:
        verdict = WORSENED if worsened else OK
    report = {
        "schema_version": SCHEMA_VERSION,
        "release_evidence_status": "engineering_check_only",
        "corpus": corpus,
        "corpus_identity": {"baseline": baseline_identity, "current": current_identity, "mismatches": mismatches},
        "tolerance": tolerance,
        "baseline": str(args.baseline),
        "current": str(args.current),
        "verdict": verdict,
        "verdict_label": INSUFFICIENT_LABEL if verdict == INSUFFICIENT else verdict,
        "worsened": worsened,
        "unmeasured": unmeasured,
        "allowed_unmeasured": [name for name in unmeasured if name in allowed],
        "plan_problems": problems,
        "insufficient_reasons": insufficient,
        "steps": steps,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    if args.json:
        sys.stdout.write(text)
    else:
        for row in steps:
            if row["status"] == NO_BASELINE:
                continue
            change = f" ({row['change_pct']:+.1f}%)" if "change_pct" in row else ""
            print(f"{row['label']}: {_format(str(row['step']), row['current'])} / 기준 {_format(str(row['step']), row['baseline'])}{change} -> {row['status']}")
        if worsened:
            print(f"나빠진 단계({int(tolerance * 100)}% 초과): " + ", ".join(worsened))
        if unmeasured:
            print("미측정: " + ", ".join(unmeasured))
        for reason in insufficient:
            print(f"{INSUFFICIENT_LABEL}: {reason}")
    if verdict == INSUFFICIENT:
        return EXIT_INSUFFICIENT
    return EXIT_WORSE if worsened else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
