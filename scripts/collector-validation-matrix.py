#!/usr/bin/env python3
"""Run the "collector x corpus x pass line" validation table in one command (T-213, QA-136).

    python scripts/collector-validation-matrix.py --json
    python scripts/collector-validation-matrix.py --inputs <inputs.json> --corpus C2,C3 \\
        --output-dir <folder outside Git> [--rows usb,browser] [--json]

The table (``docs/validation/collector-validation-matrix.json``, ``--matrix``) has one row per
collector: the comparison script(s) to run (``scripts/<name>.py``, called in-process through
``main(argv)``), an argument template and the pass line (one or more checks on the script's
JSON report, e.g. ``recall >= 0.99``). The real input paths live in a runtime inputs config
kept outside Git (``--inputs``; example ``docs/validation/collector-validation-inputs.example.json``)::

    {"corpora": {"C2": {"base_dir": ".", "rows": {
        "usb": {"ours": "run/artifacts/usb.jsonl", "reference": "ref/usb.csv",
                "extra_args": ["--reference-tz", "+09:00"]},
        "mail": {"not_measured": "C2 대본에 메일 클라이언트 없음"}}}}}

Relative paths resolve against ``base_dir`` (itself relative to the inputs file).
``extra_args`` (a list, or ``{run id: list}``) is passed to the script unchanged.

Each corpus cell is ``pass`` (통과), ``fail`` (미달, with the numbers) or ``not_measured``
(미측정 — <사유>): no inputs config, corpus or row not configured, an explicit reason, a
missing reference/our file, a script input error (exit 2), a reference with 0 comparable rows
("기준 행 0개 — 비교 불가") or a missing dependency, or a metric the report could not compute.
A report whose time values could not be read in a key or compared field
(``unparsed_time_uncompared`` > 0) is ``fail`` (미달) whatever its recall. A row is ``pass`` only when
every requested corpus passes, ``fail`` when any corpus fails, otherwise ``not_measured``.

Writes ``collector-validation-matrix.json`` and ``.md`` (plus each script's report under
``cells/``) to ``--output-dir``; without it the Markdown table goes to stdout. Exit 0 no
row below its pass line, 1 at least one ``fail``, 2 matrix/inputs config error.
Engineering measurement only, not release evidence.
"""

from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
DEFAULT_MATRIX = REPO_ROOT / "docs" / "validation" / "collector-validation-matrix.json"
SCHEMA_VERSION = "collector-validation-matrix-report-v1"
MATRIX_SCHEMA = "collector-validation-matrix-v1"
REPORT_JSON = "collector-validation-matrix.json"
REPORT_MD = "collector-validation-matrix.md"

PASS, FAIL, NOT_MEASURED = "pass", "fail", "not_measured"
LABELS = {PASS: "통과", FAIL: "미달", NOT_MEASURED: "미측정"}
EXIT_OK, EXIT_FAIL, EXIT_CONFIG = 0, 1, 2
OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, "==": lambda a, b: a == b}
AGGREGATES = {"min": min, "max": max, "mean": lambda values: sum(values) / len(values)}
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
_SCRIPT_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class MatrixConfigError(Exception):
    """Matrix or inputs config problem; the CLI exits 2 with a Korean message."""


class NotMeasured(Exception):
    """A cell cannot be measured; the message is the reason shown after "미측정 — "."""


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _read_json(path: Path, what: str) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise MatrixConfigError(f"{what} 파일이 없습니다: {path}") from exc
    except (OSError, ValueError) as exc:
        raise MatrixConfigError(f"{what} 파일을 읽지 못했습니다: {path} ({exc})") from exc
    if not isinstance(data, dict):
        raise MatrixConfigError(f"{what} 파일의 최상위가 객체가 아닙니다: {path}")
    return data


def load_matrix(path: Path) -> dict[str, object]:
    """Read and validate the matrix table."""
    matrix = _read_json(path, "검증표")
    if matrix.get("schema_version") != MATRIX_SCHEMA:
        raise MatrixConfigError(f"검증표 schema_version이 {MATRIX_SCHEMA}가 아닙니다: {path}")
    rows = matrix.get("rows")
    if not isinstance(rows, list) or not rows:
        raise MatrixConfigError("검증표에 rows가 없습니다.")
    seen: set[str] = set()
    for row in rows:
        row_id = str(row.get("id") or "") if isinstance(row, dict) else ""
        if not row_id or row_id in seen:
            raise MatrixConfigError(f"검증표 행 id가 비었거나 겹칩니다: {row_id or row!r}")
        seen.add(row_id)
        runs = row.get("runs")
        if not isinstance(runs, list) or not runs:
            raise MatrixConfigError(f"검증표 행 {row_id}에 runs가 없습니다.")
        for run in runs:
            _validate_run(row_id, run)
    return matrix


def _validate_run(row_id: str, run: object) -> None:
    if not isinstance(run, dict):
        raise MatrixConfigError(f"검증표 행 {row_id}의 run이 객체가 아닙니다.")
    script = str(run.get("script") or "")
    if not _SCRIPT_NAME.match(script) or not (SCRIPTS_DIR / f"{script}.py").is_file():
        raise MatrixConfigError(f"검증표 행 {row_id}: 대조 스크립트를 찾지 못했습니다 (scripts/{script}.py).")
    if not isinstance(run.get("args"), list):
        raise MatrixConfigError(f"검증표 행 {row_id}: args 목록이 없습니다.")
    checks = run.get("checks")
    if not isinstance(checks, list) or not checks:
        raise MatrixConfigError(f"검증표 행 {row_id}: checks(통과선)가 없습니다.")
    for check in checks:
        if not isinstance(check, dict) or not check.get("metric") or check.get("op") not in OPS or "value" not in check:
            raise MatrixConfigError(f"검증표 행 {row_id}: 통과선 형식이 틀렸습니다 ({check!r}).")
        if check.get("aggregate", "min") not in AGGREGATES:
            raise MatrixConfigError(f"검증표 행 {row_id}: 모르는 aggregate {check.get('aggregate')!r}.")


def load_inputs(path: Path | None) -> dict[str, dict[str, object]]:
    """``{corpus: {"base_dir": Path, "rows": {...}}}`` from the runtime inputs config."""
    if path is None:
        return {}
    data = _read_json(path, "입력 설정")
    corpora = data.get("corpora")
    if not isinstance(corpora, dict):
        raise MatrixConfigError(f"입력 설정에 corpora 객체가 없습니다: {path}")
    out: dict[str, dict[str, object]] = {}
    for name, spec in corpora.items():
        if not isinstance(spec, dict):
            raise MatrixConfigError(f"입력 설정의 코퍼스 {name}가 객체가 아닙니다.")
        base = Path(str(spec.get("base_dir") or "."))
        rows = spec.get("rows") if isinstance(spec.get("rows"), dict) else {}
        out[str(name)] = {"base_dir": base if base.is_absolute() else (path.parent / base), "rows": rows}
    return out


# ---------------------------------------------------------------------------
# Running one cell
# ---------------------------------------------------------------------------


_MODULES: dict[str, ModuleType] = {}


def load_script(name: str) -> ModuleType:
    """Import ``scripts/<name>.py`` once (hyphenated names are not importable by ``import``)."""
    if name in _MODULES:
        return _MODULES[name]
    path = SCRIPTS_DIR / f"{name}.py"
    module_name = "collector_matrix_" + name.replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise NotMeasured(f"대조 스크립트를 불러오지 못했습니다: scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:
        sys.modules.pop(module_name, None)
        raise NotMeasured(f"의존성 없음: {exc} (scripts/{name}.py)") from exc
    _MODULES[name] = module
    return module


def _resolve(base_dir: Path, value: object) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else base_dir / path


def build_argv(run: Mapping[str, object], row_inputs: Mapping[str, object], base_dir: Path) -> list[str]:
    """Fill the run's argument template from the row inputs; raise ``NotMeasured`` when one is missing."""
    files = {str(name) for name in run.get("files") or []}
    values: dict[str, str] = {}
    for name in files:
        raw = row_inputs.get(name)
        if raw in (None, ""):
            raise NotMeasured(f"기준 출력 미지정: 입력 설정에 '{name}' 없음")
        path = _resolve(base_dir, raw)
        if not path.exists():
            raise NotMeasured(f"기준 출력 파일 없음: {name} = {path}")
        values[name] = str(path)

    def fill(token: str) -> str:
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key in values:
                return values[key]
            raw = row_inputs.get(key)
            if raw in (None, ""):
                raise NotMeasured(f"기준 출력 미지정: 입력 설정에 '{key}' 없음")
            return str(raw)

        return _PLACEHOLDER.sub(replace, str(token))

    argv = [fill(token) for token in run.get("args") or []]
    for option in run.get("optional") or []:
        raw = row_inputs.get(str(option.get("input")))
        if raw in (None, ""):
            continue
        value = str(_resolve(base_dir, raw)) if option.get("path") else str(raw)
        if option.get("path") and not Path(value).exists():
            raise NotMeasured(f"입력 파일 없음: {option.get('input')} = {value}")
        argv += [str(option.get("flag")), value]
    extra = row_inputs.get("extra_args")
    if isinstance(extra, Mapping):
        extra = extra.get(str(run.get("id") or "main"))
    if isinstance(extra, list):
        argv += [str(item) for item in extra]
    return argv


def metric_values(report: object, path: str) -> list[object]:
    """Values at a dotted ``path``; a ``name[]`` segment walks every item of that list."""
    current: list[object] = [report]
    for segment in path.split("."):
        is_list = segment.endswith("[]")
        key = segment[:-2] if is_list else segment
        following: list[object] = []
        for item in current:
            value = item.get(key) if isinstance(item, Mapping) else None
            if is_list:
                following.extend(value if isinstance(value, list) else [])
            else:
                following.append(value)
        current = following
    return [value for value in current if value is not None]


def evaluate_check(report: Mapping[str, object], check: Mapping[str, object]) -> dict[str, object]:
    """``{metric, op, threshold, value, ok}``; ``value`` is ``None`` when the report has no number."""
    values = metric_values(report, str(check["metric"]))
    expected = check["value"]
    value: object = None
    if isinstance(expected, bool):
        value = values[0] if values and isinstance(values[0], bool) else None
    else:
        numbers = [float(item) for item in values if isinstance(item, (int, float)) and not isinstance(item, bool)]
        if numbers:
            value = round(AGGREGATES[str(check.get("aggregate", "min"))](numbers), 6)
    ok = None if value is None else bool(OPS[str(check["op"])](value, expected))
    return {"metric": check["metric"], "op": check["op"], "threshold": expected, "value": value, "ok": ok}


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return (lines[-1] if lines else "")[:200]


def run_cell_run(run: Mapping[str, object], argv: Sequence[str], report_path: Path) -> dict[str, object]:
    """Run one comparison script in-process and evaluate its checks."""
    script = str(run["script"])
    result: dict[str, object] = {"id": str(run.get("id") or "main"), "script": f"scripts/{script}.py"}
    module = load_script(script)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.unlink(missing_ok=True)
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main([*argv, "--output", str(report_path)])
    except SystemExit as exc:  # argparse usage error
        code = exc.code if isinstance(exc.code, int) else 2
    except ImportError as exc:
        raise NotMeasured(f"의존성 없음: {exc} (scripts/{script}.py)") from exc
    except Exception as exc:  # a crash in one cell must not stop the table
        raise NotMeasured(f"대조 스크립트 오류: {type(exc).__name__}: {str(exc)[:160]}") from exc
    result["exit_code"] = code
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else None
    if isinstance(report, Mapping) and report.get("status") == "no-reference":
        # WB-12 P1-4: an empty reference is not a clean result; nothing was compared.
        raise NotMeasured("기준 행 0개 — 비교 불가")
    if code == 2 or report is None:
        reason = _last_line(stderr.getvalue()) or f"보고서가 만들어지지 않음(종료 {code})"
        raise NotMeasured(f"대조 스크립트 입력 오류(종료 {code}): {reason}")
    result["report"] = str(report_path)
    result["checks"] = [evaluate_check(report, check) for check in run["checks"]]
    unread = report.get("unparsed_time_uncompared") if isinstance(report, Mapping) else None
    if isinstance(unread, int) and not isinstance(unread, bool) and unread > 0:
        # WB-12 P1-3: a time that could not be read was not compared -- the pass line is not met.
        result["checks"].append(
            {"metric": "unparsed_time_uncompared", "op": "==", "threshold": 0, "value": unread, "ok": False}
        )
    return result


def run_cell(row: Mapping[str, object], corpus: str, inputs: Mapping[str, dict[str, object]], cells_dir: Path) -> dict[str, object]:
    """One row x corpus cell: ``{status, label, reason, runs}``."""
    if not inputs:
        return _not_measured("입력 설정(--inputs) 없음")
    corpus_spec = inputs.get(corpus)
    if corpus_spec is None:
        return _not_measured(f"입력 설정에 코퍼스 {corpus} 없음")
    rows = corpus_spec["rows"]
    row_inputs = rows.get(str(row["id"])) if isinstance(rows, Mapping) else None
    if not isinstance(row_inputs, Mapping):
        return _not_measured("기준 출력 미지정: 입력 설정에 이 행 없음")
    if row_inputs.get("not_measured"):
        return _not_measured(str(row_inputs["not_measured"]))
    runs: list[dict[str, object]] = []
    reasons: list[str] = []
    multi = len(row["runs"]) > 1  # type: ignore[arg-type]
    for run in row["runs"]:  # type: ignore[union-attr]
        run_id = str(run.get("id") or "main")
        prefix = f"{run_id}: " if multi else ""
        try:
            argv = build_argv(run, row_inputs, Path(corpus_spec["base_dir"]))  # type: ignore[arg-type]
            suffix = f"-{run_id}" if multi else ""
            outcome = run_cell_run(run, argv, cells_dir / corpus / f"{row['id']}{suffix}.json")
        except NotMeasured as exc:
            reasons.append(prefix + str(exc))
            runs.append({"id": run_id, "script": f"scripts/{run['script']}.py", "status": NOT_MEASURED, "reason": str(exc)})
            continue
        checks = outcome["checks"]
        unknown = [check for check in checks if check["ok"] is None]  # type: ignore[union-attr]
        if any(check["ok"] is False for check in checks):  # type: ignore[union-attr]
            outcome["status"] = FAIL
        elif unknown:
            outcome["status"] = NOT_MEASURED
            outcome["reason"] = "지표 값 없음(기준 행 0건?): " + ", ".join(str(check["metric"]) for check in unknown)
            reasons.append(prefix + str(outcome["reason"]))
        else:
            outcome["status"] = PASS
        runs.append(outcome)
    statuses = {str(item["status"]) for item in runs}
    status = FAIL if FAIL in statuses else NOT_MEASURED if NOT_MEASURED in statuses else PASS
    return {"status": status, "label": LABELS[status], "reason": "; ".join(reasons) if status == NOT_MEASURED else "", "runs": runs}


def _not_measured(reason: str) -> dict[str, object]:
    return {"status": NOT_MEASURED, "label": LABELS[NOT_MEASURED], "reason": reason, "runs": []}


def row_status(cells: Mapping[str, Mapping[str, object]]) -> tuple[str, str]:
    """Row verdict over its corpora: any fail -> fail; all pass -> pass; else not measured."""
    statuses = [str(cell["status"]) for cell in cells.values()]
    if FAIL in statuses:
        return FAIL, ""
    if statuses and all(status == PASS for status in statuses):
        return PASS, ""
    unmeasured = [corpus for corpus, cell in cells.items() if cell["status"] == NOT_MEASURED]
    return NOT_MEASURED, "미측정 코퍼스: " + ", ".join(unmeasured)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_report(matrix_path: Path, matrix: Mapping[str, object], inputs_path: Path | None, corpora: Sequence[str],
                 rows: Sequence[Mapping[str, object]], inputs: Mapping[str, dict[str, object]], cells_dir: Path) -> dict[str, object]:
    out_rows: list[dict[str, object]] = []
    totals = {PASS: 0, FAIL: 0, NOT_MEASURED: 0}
    for row in rows:
        cells = {corpus: run_cell(row, corpus, inputs, cells_dir) for corpus in corpora}
        status, reason = row_status(cells)
        totals[status] += 1
        out_rows.append({
            "id": row["id"],
            "collector": row.get("collector", ""),
            "pass_line": row.get("pass_line", ""),
            "threshold_source": row.get("threshold_source", ""),
            "status": status,
            "label": LABELS[status],
            "reason": reason,
            "cells": cells,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Engineering measurement of RapidTriage collectors against reference tool outputs. "
            "Not release evidence; 미달·미측정 rows must be shown as 미검증."
        ),
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "matrix": {"path": _display_path(matrix_path), "sha256": _sha256(matrix_path), "row_count": len(matrix["rows"])},  # type: ignore[arg-type]
        "inputs_config": {"path": str(inputs_path), "sha256": _sha256(inputs_path)} if inputs_path else None,
        "corpora": list(corpora),
        "summary": {"rows": len(out_rows), **totals},
        "rows": out_rows,
    }


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _format_value(value: object) -> str:
    if isinstance(value, bool) or value is None:
        return str(value).lower()
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".") if value != int(value) else f"{value:.2f}"
    return str(value)


def cell_text(cell: Mapping[str, object]) -> str:
    """Markdown cell: ``통과 0.998`` / ``미달 recall 0.95 < 0.99`` / ``미측정 — <사유>``."""
    status = cell["status"]
    if status == NOT_MEASURED and not cell.get("runs"):
        return f"미측정 — {cell['reason']}"
    parts: list[str] = []
    for run in cell.get("runs") or []:  # type: ignore[union-attr]
        label = f"{run['id']} " if len(cell["runs"]) > 1 else ""  # type: ignore[arg-type]
        if run["status"] == NOT_MEASURED and not run.get("checks"):
            parts.append(f"{label}미측정 — {run['reason']}")
            continue
        for check in run.get("checks") or []:
            value = _format_value(check["value"])
            if check["ok"] is False:
                parts.append(f"{label}미달 {check['metric']} {value} (기준 {check['op']} {_format_value(check['threshold'])})")
            elif check["ok"] is None:
                parts.append(f"{label}미측정 — {check['metric']} 값 없음")
            else:
                parts.append(f"{label}통과 {check['metric']} {value}")
    return "; ".join(parts) or LABELS[str(status)]


def render_markdown(report: Mapping[str, object]) -> str:
    corpora = list(report["corpora"])  # type: ignore[call-overload]
    summary = report["summary"]
    lines = [
        "# 수집기 검증표 (수집기 × 코퍼스 × 통과선)",
        "",
        f"- 생성: {report['generated_at']} · 검증표: `{report['matrix']['path']}`",  # type: ignore[index]
        f"- 종합: 행 {summary['rows']} · 통과 {summary[PASS]} · 미달 {summary[FAIL]} · 미측정 {summary[NOT_MEASURED]}",  # type: ignore[index]
        "- 엔지니어링 측정값이며 출시 증거가 아니다. 미달·미측정 행은 화면에서 \"미검증\"으로 표시한다.",
        "",
        "| # | 수집기 | 통과선 | " + " | ".join(corpora) + " | 종합 |",
        "|---|---|---|" + "---|" * len(corpora) + "---|",
    ]
    for index, row in enumerate(report["rows"], start=1):  # type: ignore[arg-type]
        cells = [cell_text(row["cells"][corpus]).replace("|", "\\|") for corpus in corpora]
        overall = row["label"] + (f" — {row['reason']}" if row["reason"] else "")
        lines.append(f"| {index} | {row['collector']} (`{row['id']}`) | {row['pass_line']} | " + " | ".join(cells) + f" | {overall} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _split(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the collector x corpus x pass-line validation table (T-213).")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX, help="matrix table JSON (default: docs/validation/collector-validation-matrix.json)")
    parser.add_argument("--inputs", type=Path, help="runtime inputs config outside Git (corpus -> row -> input paths)")
    parser.add_argument("--corpus", help="comma-separated corpora (default: the matrix default_corpora)")
    parser.add_argument("--rows", help="comma-separated row ids to run (default: all rows)")
    parser.add_argument("--output-dir", type=Path, help="write the JSON + Markdown report and per-cell script reports here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    args = parser.parse_args(argv)
    try:
        matrix = load_matrix(args.matrix)
        inputs = load_inputs(args.inputs)
        corpora = _split(args.corpus) or [str(item) for item in matrix.get("default_corpora") or []]
        if not corpora:
            raise MatrixConfigError("코퍼스가 없습니다: --corpus C2,C3 처럼 주세요.")
        wanted = _split(args.rows)
        rows = [row for row in matrix["rows"] if not wanted or row["id"] in wanted]  # type: ignore[union-attr]
        unknown = sorted(set(wanted) - {str(row["id"]) for row in rows})
        if unknown:
            raise MatrixConfigError(f"검증표에 없는 행: {', '.join(unknown)}")
    except MatrixConfigError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    with contextlib.ExitStack() as stack:
        if args.output_dir is not None:
            cells_dir = args.output_dir / "cells"
        else:
            cells_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="collector-matrix-")))
        report = build_report(args.matrix, matrix, args.inputs, corpora, rows, inputs, cells_dir)
        if args.output_dir is None:
            for row in report["rows"]:  # drop paths into the deleted temp folder
                for cell in row["cells"].values():
                    for run in cell["runs"]:
                        run.pop("report", None)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    markdown = render_markdown(report)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / REPORT_JSON).write_text(text, encoding="utf-8", newline="\n")
        (args.output_dir / REPORT_MD).write_text(markdown, encoding="utf-8", newline="\n")
    if args.json:
        sys.stdout.write(text)
    else:
        sys.stdout.write(markdown)
        if args.output_dir is not None:
            print(f"-> {args.output_dir / REPORT_JSON}")
    return EXIT_FAIL if report["summary"][FAIL] else EXIT_OK  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
