#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/rule-validation.py --run <run output dir> [--rules A|<id,...>] \
#       [--expect expected.json] [--recompute [--incident-start T] [--incident-end T]] \
#       [--indicators <rapidtriage-indicators.json>] [--samples N] [--json] [--output F]
#   python scripts/rule-validation.py --ntfs-analysis <analyses/<id> dir of an ntfs-meta analysis> \
#       [--rules ntfs.si_before_fn,ntfs.ads_executable] [--expect expected.json] [--json] [--output F]
#
# R6 S4 lane A rule-validation harness (docs/plans/r6-followups-2026-10-19.md section 4.3,
# docs/validation/triage-rules-a-grade-2026-10-19.md). Reports, per triage rule, how often it
# fired on a real run, with up to N evidence samples, and compares the counts to expectations:
#
#   expected.json = {"<rule id>": {"min": n} | {"max": n} | {"min": n, "max": m}, ...}
#
# (positive control: {"min": 1}; negative control: {"max": 0}). Rules named in --expect are
# evaluated even when --rules does not list them. `--rules A` (default) = every catalogue rule of
# grade A; `B` / `C` likewise; otherwise a comma-separated list of rule ids.
#
# --run reads the run's joined flag set exactly as the API joins it (the newest completed
# `triage-flags` analysis under <run>/analyses/, see rapidtriage/api/app/triage_flags.py
# `flags_join`), plus the run's indicators (rapidtriage-indicators.json: IP indicators split
# into public / non-public by the rules' own `is_public_ip`, Q-S4-3). --recompute instead runs the
# current rule engine over the run's outputs into a temporary directory (use it when the stored
# flag set predates the current catalogue). --ntfs-analysis runs the rule engine over the rows of
# an `ntfs-meta` analysis (e.g. `source=mft` over an extracted $MFT) into a temporary directory,
# so ntfs.si_before_fn can be validated on a $MFT-only analysis; a rule that does not read those
# rows (ntfs.ads_executable reads `ads-stream-candidate` artifact rows of windows-filesystem, which
# an ntfs-meta analysis does not emit) is reported as `not_applicable`, never as a 0-hit pass.
#
# A negative expectation ({"max": n}) over a rule with no eligible input rows is a mismatch: a
# source that the rule cannot read proves nothing. Samples carry the row's artifact type, the
# path TAIL (last component) only, a timestamp and the rule's evidence fields with path-like
# values cut to their tail and URLs to scheme://host/…; no row content.
#
# Exit codes: 0 every expectation met (or none given), 1 mismatch, 2 input error.
# Read-only: nothing is written into the run / analysis directory (temporary engine output goes
# to the system temp directory and is removed). Engineering measurement only - not release evidence.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import dataclasses
import datetime as dt
import json
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.triage_rules import (
    RULE_CLASSES,
    CatalogError,
    RowView,
    load_catalog,
)
from rapidtriage.core.triage_rules.base import FlagContext, is_public_ip
from rapidtriage.core.triage_rules.catalog import Catalog
from rapidtriage.core.triage_rules.engine import (
    FLAGS_FILE_NAME,
    SUMMARY_FILE_NAME,
    FilesOutput,
    TriageInputs,
    run_triage_flags,
)
from rapidtriage.core.triage_rules.ntfs import MFT_TYPES
from rapidtriage.core.triage_rules.records import (
    iter_artifact_rows,
    iter_jsonl_rows,
)

SCHEMA_VERSION = "rapidtriage-rule-validation-v1"
EXIT_PASS, EXIT_MISMATCH, EXIT_INPUT_ERROR = 0, 1, 2
RUN_SUMMARY_NAME = "rapidtriage-run-summary.json"
INDICATORS_NAME = "rapidtriage-indicators.json"
ANALYSES_DIR = "analyses"
STATE_FILE = "analysis.json"
ROWS_FILE = "rows.jsonl"
TRIAGE_KIND = "triage-flags"
NTFS_KIND = "ntfs-meta"
JOINABLE = frozenset({"completed", "partial"})
ANALYSIS_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NTFS_DEFAULT_RULES = ("ntfs.si_before_fn", "ntfs.ads_executable")
# ntfs-meta analysis summary reason that the analysis' own $SI/$FN check uses for ntfs.si_before_fn.
NTFS_CROSS_CHECK = {"ntfs.si_before_fn": "si_created_before_fn"}
DEFAULT_SAMPLES = 10
# An artifacts manifest larger than this is not loaded just for its type counts (eligibility unknown).
MANIFEST_MAX_BYTES = 64 * 1024 * 1024
TIME_KEYS = (
    "timestamp",
    "event_time",
    "time_created",
    "si_created_at",
    "created_at",
    "modified_at",
    "last_run_time",
    "last_run_at",
    "deleted_at",
    "fs_modified_at",
)
NON_PUBLIC_SAMPLES = 10
# Rules whose ``apply`` reads only some artifact types of what their selector accepts (eligible-row
# counts would otherwise include rows the rule never judges): rule id -> artifact types it judges.
JUDGED_TYPES: dict[str, frozenset[str]] = {"ntfs.si_before_fn": frozenset(MFT_TYPES)}


class InputError(Exception):
    """Unusable input (exit 2)."""


# --- small helpers ------------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"{path} is not a JSON object")
    return payload


def _moment(value: object) -> dt.datetime:
    try:
        moment = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def path_tail(value: object) -> str:
    """Last component of a Windows or POSIX path (``""`` for none)."""
    text = str(value or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1]


_URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)")
_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")


def scrub(value: object) -> object:
    """Evidence value without content: URL -> ``scheme://host/…``, path -> ``…\\<tail>``."""
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): scrub(item) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    url = _URL.match(value)
    if url:
        return f"{url.group(1)}://{url.group(2)}/…" if len(value) > len(url.group(0)) else value
    if "\\" in value or _ABSOLUTE.match(value):
        tail = path_tail(value)
        return f"…\\{tail}" if tail != value else value
    return value


# --- rule selection / expectations ----------------------------------------------------------


def select_rules(catalog: Catalog, spec: str | None, default: Iterable[str]) -> list[str]:
    """Rule ids of ``--rules`` (a grade letter or ids) in catalogue order."""
    if spec is None or not spec.strip():
        wanted = list(default)
    elif spec.strip().upper() in {"A", "B", "C"}:
        grade = spec.strip().upper()
        wanted = [rule_id for rule_id, rule in catalog.specs.items() if rule.grade == grade]
    else:
        wanted = [part.strip() for part in spec.split(",") if part.strip()]
    unknown = [rule_id for rule_id in wanted if rule_id not in catalog.specs]
    if unknown:
        raise InputError(f"unknown rule id(s): {', '.join(unknown)}")
    return list(dict.fromkeys(wanted))


def load_expectations(path: Path | None, catalog: Catalog) -> dict[str, dict[str, int]]:
    if path is None:
        return {}
    raw = _read_json(path)
    expectations: dict[str, dict[str, int]] = {}
    for rule_id, bounds in raw.items():
        if rule_id not in catalog.specs:
            raise InputError(f"--expect names an unknown rule id: {rule_id}")
        if not isinstance(bounds, Mapping) or not bounds or set(bounds) - {"min", "max"}:
            raise InputError(f'--expect {rule_id}: use {{"min": n}}, {{"max": n}} or both')
        for key, value in bounds.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise InputError(f"--expect {rule_id}.{key} must be an integer >= 0")
        if "min" in bounds and "max" in bounds and bounds["min"] > bounds["max"]:
            raise InputError(f"--expect {rule_id}: min > max")
        expectations[rule_id] = {key: int(value) for key, value in bounds.items()}
    return expectations


def sub_catalog(catalog: Catalog, rule_ids: Iterable[str]) -> Catalog:
    """The catalogue restricted to ``rule_ids`` (the engine then builds and runs only those rules)."""
    wanted = set(rule_ids)
    return dataclasses.replace(catalog, specs={rule_id: spec for rule_id, spec in catalog.specs.items() if rule_id in wanted})


def rule_instance(catalog: Catalog, rule_id: str):
    return RULE_CLASSES[rule_id](dict(catalog.specs[rule_id].params))


def ntfs_candidates(catalog: Catalog, rule_id: str, rows_path: Path, row_count: int) -> int | None:
    """Rows the rule *considers* (before grading and bulk/servicing suppression) on an ntfs-meta analysis:
    a second read-only pass that only calls ``apply`` (``None`` when the rule has no ``candidate_count``)."""
    rule = rule_instance(catalog, rule_id)
    if not hasattr(rule, "candidate_count"):
        return None
    ctx = FlagContext()
    for index, row in iter_jsonl_rows(rows_path, limit=row_count):
        if row is None:
            continue
        view = RowView(kind=f"analysis:{NTFS_KIND}", collection="analysis", source_kind=NTFS_KIND, index=index, row=row)
        if rule.accepts("analysis", NTFS_KIND, view.type):
            rule.apply(view, ctx)
    return int(rule.candidate_count)


# --- flags ------------------------------------------------------------------------------------


def read_flags(path: Path, rule_ids: set[str], samples: int) -> tuple[dict[str, Counter], dict[str, Counter], dict[str, list[dict]]]:
    """Per rule: grades seen, hits per row kind, first ``samples`` ``{kind, record_index, evidence, note?}``."""
    grades: dict[str, Counter] = defaultdict(Counter)
    kinds: dict[str, Counter] = defaultdict(Counter)
    picked: dict[str, list[dict]] = defaultdict(list)
    try:
        handle = open(path, encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    with handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            kind, index = entry.get("kind"), entry.get("record_index")
            for flag in entry.get("flags") or []:
                rule_id = flag.get("id") if isinstance(flag, Mapping) else None
                if rule_id not in rule_ids:
                    continue
                grades[rule_id][str(flag.get("grade") or "?")] += 1
                kinds[rule_id][str(kind)] += 1
                if len(picked[rule_id]) < samples:
                    sample = {"kind": kind, "record_index": index, "evidence": flag.get("evidence") or {}}
                    if flag.get("note"):
                        sample["note"] = flag["note"]
                    picked[rule_id].append(sample)
    return grades, kinds, picked


def describe_row(kind: str, index: int, row: Mapping[str, object] | None) -> dict[str, object]:
    if row is None:
        return {"artifact_type": None, "path_tail": None, "timestamp": None}
    if kind.startswith("files:"):
        view = RowView(kind=kind, collection="files", source_kind="files", index=index, row=row, artifact_type="file")
        path = row.get("path")
    else:
        collection = "analysis" if kind.startswith("analysis:") else "artifacts"
        view = RowView(kind=kind, collection=collection, source_kind=kind, index=index, row=row)
        path = row.get("path") or view.get("path", "file_path", "source_path")
    return {
        "artifact_type": view.type or None,
        "path_tail": path_tail(path) or None,
        "timestamp": view.text(*TIME_KEYS) or None,
    }


def attach_rows(picked: Mapping[str, list[dict]], fetch) -> None:
    """Fill each sample's artifact_type / path_tail / timestamp from its row (one pass per kind)."""
    wanted: dict[str, set[int]] = defaultdict(set)
    for samples in picked.values():
        for sample in samples:
            if isinstance(sample.get("record_index"), int):
                wanted[str(sample["kind"])].add(int(sample["record_index"]))
    rows: dict[tuple[str, int], Mapping[str, object]] = {}
    for kind, indices in wanted.items():
        try:
            for index, row in fetch(kind, max(indices)):
                if index in indices and isinstance(row, Mapping):
                    rows[(kind, index)] = row
                if index >= max(indices):
                    break
        except (OSError, ValueError, InputError):
            continue  # samples of that kind keep null row fields
    for samples in picked.values():
        for sample in samples:
            row = rows.get((str(sample["kind"]), sample.get("record_index")))  # type: ignore[arg-type]
            sample.update(describe_row(str(sample["kind"]), int(sample.get("record_index") or 0), row))
            sample["evidence"] = scrub(sample["evidence"])


# --- run mode ---------------------------------------------------------------------------------


class RunOutputs(NamedTuple):
    directory: Path
    artifacts: dict[str, Path]
    files: Path | None
    indicators: Path | None


def _resolve_output(directory: Path, raw: object) -> Path | None:
    path = Path(str(raw))
    if path.is_file():
        return path
    moved = directory / path.name  # a run folder copied elsewhere keeps its file names
    return moved if moved.is_file() else None


def load_run(directory: Path) -> RunOutputs:
    directory = Path(directory)
    summary_path = directory / RUN_SUMMARY_NAME
    if not summary_path.is_file():
        raise InputError(f"not a run output directory (no {RUN_SUMMARY_NAME}): {directory}")
    summary = _read_json(summary_path)
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    artifacts: dict[str, Path] = {}
    files: Path | None = None
    indicators: Path | None = None
    for name, raw in sorted(outputs.items()):
        path = _resolve_output(directory, raw)
        if path is None:
            continue
        if str(name).startswith("artifacts_"):
            artifacts[str(name).removeprefix("artifacts_")] = path
        elif name == "files":
            files = path
        elif name == "indicators":
            indicators = path
    if indicators is None and (directory / INDICATORS_NAME).is_file():
        indicators = directory / INDICATORS_NAME
    return RunOutputs(directory, artifacts, files, indicators)


def analysis_states(directory: Path) -> list[dict[str, Any]]:
    root = Path(directory) / ANALYSES_DIR
    states: list[dict[str, Any]] = []
    try:
        children = sorted(child for child in root.iterdir() if child.is_dir())
    except OSError:
        return []
    for child in children:
        if not ANALYSIS_ID.fullmatch(child.name):
            continue
        try:
            state = json.loads((child / STATE_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(state, dict) and str(state.get("analysis_id") or child.name) == child.name:
            states.append({**state, "analysis_id": child.name, "_dir": child})
    return states


def joined_flag_set(directory: Path) -> dict[str, Any]:
    """The flag set the API joins: newest completed ``triage-flags`` analysis with a joinable summary."""
    found = []
    for state in analysis_states(directory):
        if state.get("kind") != TRIAGE_KIND or state.get("status") != "completed":
            continue
        folder: Path = state["_dir"]
        try:
            summary = json.loads((folder / SUMMARY_FILE_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(summary, dict) or summary.get("status") not in JOINABLE or not (folder / FLAGS_FILE_NAME).is_file():
            continue
        source = "run-stage" if (state.get("options") or {}).get("source") == "run-stage" else "analysis"
        found.append({"analysis_id": state["analysis_id"], "source": source, "dir": folder,
                      "generated_at": state.get("finished_at") or summary.get("generated_at"), "summary": summary})
    if not found:
        raise InputError(
            "no completed triage-flags set under <run>/analyses (run the 특이사항 analysis, or pass --recompute)"
        )
    found.sort(key=lambda item: _moment(item["generated_at"]), reverse=True)
    return found[0]


def run_inputs(run: RunOutputs, catalog: Catalog) -> TriageInputs:
    """Engine inputs like the API's ``triage_inputs`` (artifacts, files, completed analyses a rule reads)."""
    rules = [rule_instance(catalog, rule_id) for rule_id in catalog.specs]
    analyses = []
    for state in analysis_states(run.directory):
        kind, row_count = str(state.get("kind") or ""), int(state.get("row_count") or 0)
        if kind == TRIAGE_KIND or state.get("status") != "completed" or row_count <= 0:
            continue
        if any(rule.accepts("analysis", kind, f"{kind}-row") for rule in rules):
            analyses.append((state["analysis_id"], kind, state["_dir"] / ROWS_FILE, row_count))
    return TriageInputs(output_dir=run.directory, artifact_payloads=dict(run.artifacts), files_path=run.files, analyses=analyses)


def eligible_rows(run: RunOutputs, inputs: TriageInputs, catalog: Catalog, rule_ids: list[str]) -> dict[str, int | None]:
    """Rows each rule could read (artifact type counts of the manifests, files lists, analyses); None = unknown."""
    rules = {rule_id: rule_instance(catalog, rule_id) for rule_id in rule_ids}
    counts: dict[str, int | None] = dict.fromkeys(rule_ids, 0)

    def add(rule_id: str, value: int | None) -> None:
        current = counts[rule_id]
        counts[rule_id] = None if current is None or value is None else current + value

    for kind, path in run.artifacts.items():
        type_counts: Mapping[str, object] | None = None
        try:
            if path.stat().st_size <= MANIFEST_MAX_BYTES:
                payload = json.loads(path.read_text(encoding="utf-8"))
                summary = payload.get("summary") if isinstance(payload, Mapping) else None
                raw = summary.get("artifact_type_counts") if isinstance(summary, Mapping) else None
                type_counts = raw if isinstance(raw, Mapping) else None
        except (OSError, ValueError):
            type_counts = None
        for rule_id, rule in rules.items():
            if type_counts is None:
                if "artifacts" in rule.selector.collections and (rule.selector.kinds is None or kind in rule.selector.kinds):
                    add(rule_id, None)
                continue
            judged = JUDGED_TYPES.get(rule_id)
            add(
                rule_id,
                sum(
                    int(n)
                    for name, n in type_counts.items()
                    if isinstance(n, int) and rule.accepts("artifacts", kind, str(name)) and (judged is None or name in judged)
                ),
            )
    if run.files is not None:
        files = FilesOutput(None, run.files)
        for collection in ("candidates", "inventory"):
            total = files.total(collection)
            for rule_id, rule in rules.items():
                if rule.accepts("files", "files", "file"):
                    add(rule_id, total)
    for _analysis_id, kind, _rows, row_count in inputs.analyses:
        for rule_id, rule in rules.items():
            if rule.accepts("analysis", kind, f"{kind}-row"):
                add(rule_id, row_count)
    return counts


def run_row_fetcher(run: RunOutputs):
    def fetch(kind: str, _last: int):
        if kind.startswith("files:"):
            if run.files is None:
                return iter(())
            return FilesOutput(None, run.files).rows(kind.removeprefix("files:"))
        if kind.startswith("analysis:"):
            analysis_id = kind.removeprefix("analysis:")
            if not ANALYSIS_ID.fullmatch(analysis_id):
                return iter(())
            return iter_jsonl_rows(run.directory / ANALYSES_DIR / analysis_id / ROWS_FILE)
        path = run.artifacts.get(kind)
        if path is None:
            return iter(())
        return iter_artifact_rows(_read_json(path), path)

    return fetch


def indicator_block(path: Path | None) -> dict[str, Any]:
    """Indicator counts; IP indicators split public / non-public by the rules' ``is_public_ip`` (Q-S4-3)."""
    if path is None:
        return {"present": False}
    payload = _read_json(path)
    items = payload.get("indicators") if isinstance(payload.get("indicators"), list) else []
    types = Counter(str(item.get("type") or "") for item in items if isinstance(item, Mapping))
    ips = [str(item.get("value") or "") for item in items if isinstance(item, Mapping) and item.get("type") == "ip"]
    public = [value for value in ips if is_public_ip(value)]
    non_public = [value for value in ips if not is_public_ip(value)]
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    return {
        "present": True,
        "file": path.name,
        "indicator_count": len(items),
        "truncated": bool(summary.get("truncated")),
        "type_counts": dict(sorted(types.items())),
        "ip": {
            "total": len(ips),
            "public": len(public),
            "non_public": len(non_public),
            "non_public_samples": non_public[:NON_PUBLIC_SAMPLES],
        },
    }


# --- evaluation ------------------------------------------------------------------------------


def evaluate(
    catalog: Catalog,
    rule_ids: list[str],
    expectations: Mapping[str, Mapping[str, int]],
    *,
    grades: Mapping[str, Counter],
    kinds: Mapping[str, Counter],
    picked: Mapping[str, list[dict]],
    eligible: Mapping[str, int | None],
    used_versions: Mapping[str, object],
) -> list[dict[str, Any]]:
    results = []
    for rule_id in rule_ids:
        spec = catalog.specs[rule_id]
        hits = sum(grades.get(rule_id, Counter()).values())
        rows = eligible.get(rule_id)
        expectation = expectations.get(rule_id)
        warnings: list[str] = []
        used = used_versions.get(rule_id)
        if used is not None and used != spec.version:
            warnings.append(f"flag set computed with rule version {used}; catalogue now has {spec.version} (use --recompute)")
        if rows == 0:
            result, reason = "not_applicable", "규칙이 읽을 입력 행이 없습니다(적중 0은 음성 근거가 아님)"
        else:
            result, reason = "no_expectation", ""
        if expectation is not None:
            low, high = expectation.get("min"), expectation.get("max")
            if low is not None and hits < low:
                result, reason = "mismatch", f"적중 {hits}건 < 기대 최소 {low}건"
            elif high is not None and rows == 0:
                result, reason = "mismatch", "음성 대조 불성립: 규칙이 읽을 입력 행이 없습니다"
            elif high is not None and hits > high:
                result, reason = "mismatch", f"적중 {hits}건 > 기대 최대 {high}건"
            else:
                result, reason = "pass", ""
                if rows is None:
                    warnings.append("eligible input rows unknown (no artifact_type_counts)")
        validation = spec.validation or {}
        results.append(
            {
                "id": rule_id,
                "catalog_grade": spec.grade,
                "version": spec.version,
                "status": spec.status,
                "validation_synthetic_only": bool(validation) and not validation.get("real") and not validation.get("public"),
                "hits": hits,
                "grades": dict(sorted(grades.get(rule_id, Counter()).items())),
                "hits_by_kind": dict(sorted(kinds.get(rule_id, Counter()).items())),
                "eligible_rows": rows,
                "expectation": dict(expectation) if expectation is not None else None,
                "result": result,
                "reason_ko": reason,
                "warnings": warnings,
                "samples": picked.get(rule_id, []),
            }
        )
    return results


def finish(report: dict[str, Any]) -> int:
    results = report["rules"]
    report["totals"] = dict(Counter(item["result"] for item in results))
    code = EXIT_MISMATCH if any(item["result"] == "mismatch" for item in results) else EXIT_PASS
    report["exit_code"] = code
    report["verdict"] = "mismatch" if code else "pass"
    return code


def _engine(inputs: TriageInputs, catalog: Catalog, incident: tuple[str | None, str | None]) -> tuple[Path, dict, tempfile.TemporaryDirectory]:
    temp = tempfile.TemporaryDirectory(prefix="rule-validation-")
    out = Path(temp.name)
    summary = run_triage_flags(
        inputs, out, source_label="rule-validation", catalog=catalog, incident_start=incident[0], incident_end=incident[1]
    )
    return out / FLAGS_FILE_NAME, summary, temp


def validate_run(args: argparse.Namespace, catalog: Catalog) -> dict[str, Any]:
    run = load_run(args.run)
    rule_ids = select_rules(catalog, args.rules, [r for r, s in catalog.specs.items() if s.grade == "A"])
    expectations = load_expectations(args.expect, catalog)
    rule_ids += [rule_id for rule_id in expectations if rule_id not in rule_ids]
    inputs = run_inputs(run, catalog)
    temp = None
    started = time.monotonic()
    try:
        if args.recompute:
            flags_path, summary, temp = _engine(inputs, sub_catalog(catalog, rule_ids), (args.incident_start, args.incident_end))
            source = {"status": "recomputed", "catalog_version": catalog.version, "coverage": summary.get("status"),
                      "incident_window": summary.get("incident_window")}
        else:
            chosen = joined_flag_set(run.directory)
            summary = chosen["summary"]
            flags_path = chosen["dir"] / FLAGS_FILE_NAME
            source = {
                "status": "joined",
                "analysis_id": chosen["analysis_id"],
                "source": chosen["source"],
                "generated_at": chosen["generated_at"],
                "catalog_version": summary.get("catalog_version"),
                "coverage": summary.get("status"),
                "incident_window": summary.get("incident_window"),
            }
        grades, kinds, picked = read_flags(flags_path, set(rule_ids), args.samples)
        attach_rows(picked, run_row_fetcher(run))
    finally:
        if temp is not None:
            temp.cleanup()
    used = summary.get("rule_versions") if isinstance(summary.get("rule_versions"), Mapping) else {}
    report: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "mode": "run",
        "input": {"run_dir": str(run.directory), "artifact_kinds": sorted(run.artifacts), "files_output": run.files is not None},
        "catalog_version": catalog.version,
        "flag_source": source,
        "rows_scanned": summary.get("rows_scanned"),
        "elapsed_s": round(time.monotonic() - started, 3),
        "rules": evaluate(
            catalog, rule_ids, expectations, grades=grades, kinds=kinds, picked=picked,
            eligible=eligible_rows(run, inputs, catalog, rule_ids), used_versions={} if args.recompute else used,
        ),
        "indicators": indicator_block(args.indicators or run.indicators),
    }
    if source.get("coverage") == "partial":
        report["warnings"] = ["flag set is partial: some source was not read to its end (counts are lower bounds)"]
    return report


def validate_ntfs(args: argparse.Namespace, catalog: Catalog) -> dict[str, Any]:
    directory = Path(args.ntfs_analysis)
    state_path = directory / STATE_FILE
    if not state_path.is_file() or not (directory / ROWS_FILE).is_file():
        raise InputError(f"not an analysis directory (needs {STATE_FILE} and {ROWS_FILE}): {directory}")
    state = _read_json(state_path)
    if state.get("kind") != NTFS_KIND:
        raise InputError(f"analysis kind is {state.get('kind')!r}, expected {NTFS_KIND!r}")
    if state.get("status") != "completed":
        raise InputError(f"analysis status is {state.get('status')!r}, expected 'completed'")
    analysis_id = str(state.get("analysis_id") or directory.name)
    if not ANALYSIS_ID.fullmatch(analysis_id):
        analysis_id = "ntfs-meta"
    row_count = int(state.get("row_count") or 0)
    rule_ids = select_rules(catalog, args.rules, NTFS_DEFAULT_RULES)
    expectations = load_expectations(args.expect, catalog)
    rule_ids += [rule_id for rule_id in expectations if rule_id not in rule_ids]
    rows_path = directory / ROWS_FILE
    inputs = TriageInputs(output_dir=directory, analyses=[(analysis_id, NTFS_KIND, rows_path, row_count)])
    started = time.monotonic()
    flags_path, summary, temp = _engine(inputs, sub_catalog(catalog, rule_ids), (args.incident_start, args.incident_end))
    try:
        grades, kinds, picked = read_flags(flags_path, set(rule_ids), args.samples)
    finally:
        temp.cleanup()
    elapsed = round(time.monotonic() - started, 3)

    def fetch(_kind: str, _last: int):
        return iter_jsonl_rows(rows_path, limit=row_count)

    attach_rows(picked, fetch)
    analysis_summary = state.get("summary") if isinstance(state.get("summary"), Mapping) else {}
    mft_records = analysis_summary.get("mft_record_count")
    eligible = {
        rule_id: (
            (mft_records if rule_id in JUDGED_TYPES and isinstance(mft_records, int) else row_count)
            if rule_instance(catalog, rule_id).accepts("analysis", NTFS_KIND, f"{NTFS_KIND}-row")
            else 0
        )
        for rule_id in rule_ids
    }
    results = evaluate(catalog, rule_ids, expectations, grades=grades, kinds=kinds, picked=picked, eligible=eligible, used_versions={})
    reasons = analysis_summary.get("timestamp_mismatch_reason_counts_all")
    for item in results:
        if item["id"] == "ntfs.ads_executable" and item["result"] in {"not_applicable", "mismatch"} and not eligible[item["id"]]:
            item["reason_ko"] = (
                "ntfs-meta 분석 행에는 ADS 정보가 없습니다. 이 규칙은 windows-filesystem 아티팩트의 "
                "ads-stream-candidate 행을 읽으므로 이미지 런(--run)에서 검증하세요"
            ) + (f" ({item['reason_ko']})" if item["result"] == "mismatch" else "")
        reason = NTFS_CROSS_CHECK.get(item["id"])
        if reason and isinstance(reasons, Mapping):
            count = reasons.get(reason)
            # Since ntfs.si_before_fn v2 the flags omit uncorroborated bulk/servicing hits, so the analysis'
            # count is compared with the rows the rule considered (candidates), not with the flags.
            candidates = ntfs_candidates(catalog, item["id"], rows_path, row_count)
            compared = candidates if candidates is not None else item["hits"]
            item["analysis_cross_check"] = {
                "reason": reason,
                "analysis_count": count,
                "engine_candidates": candidates,
                "engine_hits": item["hits"],
                "not_flagged": compared - item["hits"],
                "agree": count == compared,
            }
    return {
        "schema": SCHEMA_VERSION,
        "mode": "ntfs-analysis",
        "input": {
            "analysis_dir": str(directory),
            "analysis_id": analysis_id,
            "row_count": row_count,
            "source": analysis_summary.get("source"),
            "parse_status": analysis_summary.get("parse_status"),
            "mft_record_count": analysis_summary.get("mft_record_count"),
            "timestamp_mismatch_status": analysis_summary.get("timestamp_mismatch_status"),
        },
        "catalog_version": catalog.version,
        "flag_source": {"status": "recomputed", "catalog_version": catalog.version, "coverage": summary.get("status")},
        "rows_scanned": summary.get("rows_scanned"),
        "elapsed_s": elapsed,
        "rules": results,
    }


# --- output ----------------------------------------------------------------------------------


def render_text(report: Mapping[str, Any]) -> str:
    lines = [f"rule-validation ({report['mode']}) catalog {report['catalog_version']} -> {report['verdict']}"]
    source = report.get("flag_source") or {}
    lines.append(f"flag source: {source.get('status')} {source.get('analysis_id') or ''} coverage={source.get('coverage')}")
    for item in report["rules"]:
        bound = item["expectation"]
        lines.append(
            f"  {item['result']:<14} {item['id']:<42} hits={item['hits']:<7} eligible={item['eligible_rows']} "
            f"expect={json.dumps(bound) if bound else '-'} {item['reason_ko']}"
        )
        for sample in item["samples"][:3]:
            lines.append(
                f"      {sample.get('artifact_type')} …\\{sample.get('path_tail')} {sample.get('timestamp')} "
                f"{json.dumps(sample.get('evidence'), ensure_ascii=False)[:160]}"
            )
        for warning in item["warnings"]:
            lines.append(f"      ! {warning}")
    indicators = report.get("indicators")
    if isinstance(indicators, Mapping) and indicators.get("present"):
        ip = indicators["ip"]
        lines.append(f"indicators: {indicators['indicator_count']} (ip {ip['total']}: public {ip['public']}, non-public {ip['non_public']})")
    for warning in report.get("warnings") or []:
        lines.append(f"! {warning}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate triage rules (hit counts, samples, expectations) on a run or an ntfs-meta analysis.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", type=Path, help="Run output directory (has rapidtriage-run-summary.json)")
    mode.add_argument("--ntfs-analysis", type=Path, help="An ntfs-meta analysis directory (<run>/analyses/<id>)")
    parser.add_argument("--rules", help="A | B | C (every rule of that grade) or comma-separated rule ids")
    parser.add_argument("--expect", type=Path, help='JSON {rule_id: {"min": n} | {"max": n}}')
    parser.add_argument("--recompute", action="store_true", help="--run: run the current rule engine instead of reading the stored flag set")
    parser.add_argument("--incident-start", help="ISO time for incident-window rules (--recompute / --ntfs-analysis)")
    parser.add_argument("--incident-end", help="ISO time for incident-window rules (--recompute / --ntfs-analysis)")
    parser.add_argument("--indicators", type=Path, help="--run: indicators JSON (default: the run's own)")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES, help="Evidence samples per rule (default 10)")
    parser.add_argument("--json", action="store_true", help="Print the JSON report")
    parser.add_argument("--output", type=Path, help="Also write the JSON report here")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.samples = max(0, min(int(args.samples), 1000))
    try:
        catalog = load_catalog()
        report = validate_run(args, catalog) if args.run is not None else validate_ntfs(args, catalog)
    except (InputError, CatalogError) as exc:
        print(f"rule-validation: input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    code = finish(report)
    text = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text if args.json else render_text(report))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
