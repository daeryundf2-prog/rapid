#!/usr/bin/env python3
"""Rebuild the R8 trace table from the plan appendices and report holes (T-003).

Reads (default ``docs/plans/r8``):
  A ``r8-ideal-state.md``  IS-xxx definitions
  B ``r8-gaps.md``         GAP-xxx -> IS column
  E ``r8-qa-scenarios.md`` QA-xxx -> IS column (E.3 tables)
  F ``r8-tasks.md``        F.3 task tables (bundle headings ``### WA-1 — ...``)
  G ``r8-traceability.md`` G.1 table, compared with the regenerated one

Checks (each is a failure when its item list is non-empty):
  is_without_gap, is_without_task, is_without_qa, gap_without_task,
  qa_without_task (bulk-run wave WZ excluded), task_without_gap_is,
  task_without_qa (QA "—(reason)" or a G.3 row counts as a reason),
  dangling_refs, dep_on_retired, wave_dependency, bundle_size, task_over_4h,
  file_overlap_in_bundle, verification_target_missing, same_as_wording,
  table_parse, g1_drift.

Read-only: the plan is never modified. ``--output`` writes the regenerated
trace (IS -> GAP -> task -> QA) plus the findings as JSON.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN_DIR = REPO_ROOT / "docs" / "plans" / "r8"

ID_TOKEN = re.compile(r"\b(IS|GAP|QA|T)-(\d{3})\b|(?<![\d.:-])(\d{3})(?![\d%])")
BUNDLE_HEADING = re.compile(r"^###\s+(W[A-Z]\d?)-(\d+)\b.*?\((\d+)\)\s*$")
BACKTICK = re.compile(r"`([^`]+)`")
MAX_BUNDLE = 6
MAX_HOURS = 4.0
# F.1 wave order: WA -> WB -> WC -> (WD || WE) -> WF -> WG -> WH -> WZ.
# Engine lanes run after WC; WP1 -> WP2 -> WP3, WP4/WP5 independent.
WAVE_RANK = {
    "WA": 0,
    "WB": 1,
    "WC": 2,
    "WD": 3,
    "WE": 3,
    "WF": 4,
    "WG": 5,
    "WH": 6,
    "WZ": 7,
}
WP_ORDER = {"WP1": 1, "WP2": 2, "WP3": 3}
BULK_WAVE = "WZ"
BULK_TITLE = (
    "일괄 실행"  # WZ "전 QA 일괄 실행 n/12" tasks run every QA; G.1/G.2 leave them out
)
SAME_AS = "같음"


# ---------------------------------------------------------------- markdown


def split_row(line: str) -> list[str]:
    """Split a markdown table row; ``\\|`` and pipes inside backticks stay in the cell."""
    body = line.strip()
    body = body.removeprefix("|")
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells: list[str] = []
    cur: list[str] = []
    fence = 0  # length of the backtick run that opened the current code span
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "`":
            run = len(body[i:]) - len(body[i:].lstrip("`"))
            if fence == 0:
                fence = run
            elif run == fence:
                fence = 0
            cur.append("`" * run)
            i += run
            continue
        if ch == "|" and not fence:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def iter_tables(text: str):
    """Yield (section_heading, header_cells, [(line_no, cells)]) for each table."""
    lines = text.splitlines()
    heading = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            heading = line.strip()
        if (
            line.lstrip().startswith("|")
            and i + 1 < len(lines)
            and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1])
        ):
            header = split_row(line)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                rows.append((j + 1, split_row(lines[j])))
                j += 1
            yield heading, header, rows
            i = j
            continue
        i += 1


def parse_ids(cell: str, default_kind: str | None = None) -> list[str]:
    """``GAP-373·204 / IS-067`` -> [GAP-373, GAP-204, IS-067]; bare numbers inherit the last prefix.

    ``a~b`` ranges expand. Text in backticks is ignored (paths, line numbers).
    """
    cell = BACKTICK.sub(" ", cell).replace("*", "")
    out: list[str] = []
    kind = default_kind
    last_num: int | None = None
    pos = 0
    for m in ID_TOKEN.finditer(cell):
        between = cell[pos : m.start()]
        pos = m.end()
        if m.group(1):
            kind = m.group(1)
            num = int(m.group(2))
        else:
            if kind is None:
                continue
            num = int(m.group(3))
        if (
            last_num is not None
            and re.fullmatch(r"\s*~\s*", between)
            and num > last_num
        ):
            out.extend(f"{kind}-{n:03d}" for n in range(last_num + 1, num + 1))
        else:
            out.append(f"{kind}-{num:03d}")
        last_num = num
    return out


def col(header: list[str], *names: str) -> int | None:
    for idx, h in enumerate(header):
        clean = h.replace("*", "").strip()
        if any(clean == n or clean.startswith(n) for n in names):
            return idx
    return None


# ---------------------------------------------------------------- plan model


class Plan:
    def __init__(self, plan_dir: Path) -> None:
        self.plan_dir = plan_dir
        self.is_ids: set[str] = set()
        self.gap_is: dict[str, list[str]] = {}
        self.qa_is: dict[str, list[str]] = {}
        self.tasks: dict[str, dict] = {}
        self.bundles: dict[str, dict] = {}
        self.retired: set[str] = set()
        self.g3_tasks: set[str] = set()
        self.g1: dict[str, dict[str, list[str]]] = {}
        self.parse_issues: list[str] = []
        self._load()

    def _read(self, name: str) -> str:
        return (self.plan_dir / name).read_text(encoding="utf-8")

    def _load(self) -> None:
        for _, header, rows in iter_tables(self._read("r8-ideal-state.md")):
            if col(header, "ID") == 0:
                for _, cells in rows:
                    if re.fullmatch(r"IS-\d{3}", cells[0]):
                        self.is_ids.add(cells[0])
        for _, header, rows in iter_tables(self._read("r8-gaps.md")):
            if header and header[0] == "GAP":
                ci = col(header, "IS")
                for line_no, cells in rows:
                    if not re.fullmatch(r"GAP-\d{3}", cells[0]):
                        continue
                    if len(cells) != len(header):
                        self.parse_issues.append(
                            f"r8-gaps.md:{line_no} {cells[0]}: {len(cells)} cells, header has {len(header)}"
                        )
                    self.gap_is[cells[0]] = (
                        parse_ids(cells[ci], "IS")
                        if ci is not None and ci < len(cells)
                        else []
                    )
        for _, header, rows in iter_tables(self._read("r8-qa-scenarios.md")):
            if header and header[0] == "QA" and col(header, "IS") is not None:
                ci = col(header, "IS")
                for line_no, cells in rows:
                    if not re.fullmatch(r"QA-\d{3}", cells[0]):
                        continue
                    if len(cells) != len(header):
                        self.parse_issues.append(
                            f"r8-qa-scenarios.md:{line_no} {cells[0]}: {len(cells)} cells, header has {len(header)}"
                        )
                    self.qa_is[cells[0]] = (
                        parse_ids(cells[ci], "IS") if ci < len(cells) else []
                    )
        self._load_tasks()
        self._load_traceability()

    def _load_tasks(self) -> None:
        text = self._read("r8-tasks.md")
        section = (
            text.split("## F.3", 1)[1].split("\n## F.4", 1)[0]
            if "## F.3" in text
            else ""
        )
        offset = text[: text.find("## F.3")].count("\n") if section else 0
        bundle = None
        lines = section.splitlines()
        header: list[str] | None = None
        for idx, line in enumerate(lines):
            line_no = offset + idx + 1
            m = BUNDLE_HEADING.match(line.strip())
            if m:
                bundle = f"{m.group(1)}-{m.group(2)}"
                self.bundles[bundle] = {
                    "wave": m.group(1),
                    "seq": int(m.group(2)),
                    "declared": int(m.group(3)),
                    "tasks": [],
                }
                header = None
                continue
            if not line.lstrip().startswith("|") or bundle is None:
                continue
            cells = split_row(line)
            if cells and cells[0] == "ID":
                header = cells
                continue
            if header is None or not re.fullmatch(
                r"T-\d{3}", cells[0] if cells else ""
            ):
                continue
            if len(cells) != len(header):
                self.parse_issues.append(
                    f"r8-tasks.md:{line_no} {cells[0]}: {len(cells)} cells, header has {len(header)}"
                )

            def get(*names: str, _cells=cells, _header=header) -> str:
                i = col(_header, *names)
                return _cells[i] if i is not None and i < len(_cells) else ""

            hours_text = get("h", "크기")
            try:
                hours = float(re.sub(r"[^\d.]", "", hours_text) or "nan")
            except ValueError:
                hours = float("nan")
            gap_is = parse_ids(get("GAP/IS", "닫는 GAP"))
            self.tasks[cells[0]] = {
                "id": cells[0],
                "line": line_no,
                "title": get("제목"),
                "bundle": bundle,
                "wave": self.bundles[bundle]["wave"],
                "seq": self.bundles[bundle]["seq"],
                "files_cell": get("파일", "배타 파일"),
                "deps": [d for d in parse_ids(get("의존"), "T") if d.startswith("T-")],
                "hours": hours,
                "accept": get("동작", "동작·수용"),
                "gaps": [x for x in gap_is if x.startswith("GAP-")],
                "is": [x for x in gap_is if x.startswith("IS-")],
                "qa_cell": get("QA"),
                "qa": [x for x in parse_ids(get("QA"), "QA") if x.startswith("QA-")],
                "verify": get("검증"),
            }
            self.bundles[bundle]["tasks"].append(cells[0])
        retired = (
            text.split("## F.4", 1)[1].split("\n## ", 1)[0] if "## F.4" in text else ""
        )
        for _, header, rows in iter_tables(retired):
            for _, cells in rows:
                if re.fullmatch(r"T-\d{3}", cells[0]):
                    self.retired.add(cells[0])

    def _load_traceability(self) -> None:
        text = self._read("r8-traceability.md")
        for heading, header, rows in iter_tables(text):
            if heading.startswith("## G.1"):
                for _, cells in rows:
                    if len(cells) >= 4 and re.fullmatch(r"IS-\d{3}", cells[0]):
                        self.g1[cells[0]] = {
                            "gaps": parse_ids(cells[1], "GAP"),
                            "tasks": parse_ids(cells[2], "T"),
                            "qa": parse_ids(cells[3], "QA"),
                        }
            elif heading.startswith("## G.3"):
                for _, cells in rows:
                    if cells and re.fullmatch(r"T-\d{3}", cells[0]):
                        self.g3_tasks.add(cells[0])


# ---------------------------------------------------------------- trace


def is_bulk(task: dict) -> bool:
    return task["wave"] == BULK_WAVE and BULK_TITLE in task["title"]


def build_trace(plan: Plan) -> dict[str, dict[str, list[str]]]:
    gaps_by_is: dict[str, set[str]] = defaultdict(set)
    for gap, is_list in plan.gap_is.items():
        for is_id in is_list:
            gaps_by_is[is_id].add(gap)
    tasks_by_gap: dict[str, set[str]] = defaultdict(set)
    tasks_by_is: dict[str, set[str]] = defaultdict(set)
    for tid, task in plan.tasks.items():
        if is_bulk(task):
            continue
        for gap in task["gaps"]:
            tasks_by_gap[gap].add(tid)
        for is_id in task["is"]:
            tasks_by_is[is_id].add(tid)
    qa_by_is: dict[str, set[str]] = defaultdict(set)
    for qa, is_list in plan.qa_is.items():
        for is_id in is_list:
            qa_by_is[is_id].add(qa)
    trace = {}
    for is_id in sorted(plan.is_ids):
        tasks = set(tasks_by_is[is_id])
        for gap in gaps_by_is[is_id]:
            tasks |= tasks_by_gap[gap]
        trace[is_id] = {
            "gaps": sorted(gaps_by_is[is_id]),
            "tasks": sorted(tasks),
            "qa": sorted(qa_by_is[is_id]),
        }
    return trace


# ---------------------------------------------------------------- file paths


def expand_braces(path: str) -> list[str]:
    m = re.search(r"\{([^{}]*)\}", path)
    if not m:
        return [path]
    out = []
    for alt in m.group(1).split(","):
        out.extend(expand_braces(path[: m.start()] + alt + path[m.end() :]))
    return out


def task_paths(files_cell: str) -> list[str]:
    """Backtick paths in a file cell, normalised (``:line`` suffix dropped, ``<x>`` -> ``*``)."""
    out: list[str] = []
    for raw in BACKTICK.findall(files_cell):
        token = raw.strip()
        if (
            " " in token
            or "/" not in token
            or token.startswith(("-", "http"))
            or "(" in token
        ):
            continue
        token = re.sub(r":[\d,\-]+$", "", token)
        token = re.sub(r"<[^>]*>", "*", token).lstrip("./")
        for path in expand_braces(token):
            if path not in out:
                out.append(path)
    return out


def _has_glob(p: str) -> bool:
    return any(c in p for c in "*?[")


def paths_overlap(a: str, b: str) -> bool:
    if a == b:
        return True
    if a.endswith("/") and b.startswith(a) or b.endswith("/") and a.startswith(b):
        return True
    if _has_glob(a) and fnmatch.fnmatchcase(b.rstrip("/"), a):
        return True
    if _has_glob(b) and fnmatch.fnmatchcase(a.rstrip("/"), b):
        return True
    if _has_glob(a) and _has_glob(b):
        # both globs: overlap when their literal prefixes nest
        pa, pb = re.split(r"[*?\[]", a, 1)[0], re.split(r"[*?\[]", b, 1)[0]
        return pa.startswith(pb) or pb.startswith(pa)
    return False


# ---------------------------------------------------------------- checks


def _wave_dep_problem(task: dict, dep: dict) -> str | None:
    tw, dw = task["wave"], dep["wave"]
    t_wp, d_wp = tw.startswith("WP"), dw.startswith("WP")
    if tw == dw:
        if dep["seq"] >= task["seq"]:
            return f"same wave {tw}: dependency in bundle {dep['bundle']} is not earlier than {task['bundle']}"
        return None
    if d_wp and not t_wp:
        if tw == BULK_WAVE:
            return None
        return f"{tw} task depends on engine lane {dw}"
    if t_wp and d_wp:
        if tw in WP_ORDER and dw in WP_ORDER and WP_ORDER[dw] < WP_ORDER[tw]:
            return None
        return f"engine lane {tw} depends on {dw} (order WP1 -> WP2 -> WP3; WP4/WP5 independent)"
    if t_wp:
        if WAVE_RANK.get(dw, 99) <= WAVE_RANK["WC"]:
            return None
        return f"engine lane {tw} (starts after WC) depends on later wave {dw}"
    if WAVE_RANK.get(dw, 99) < WAVE_RANK.get(tw, -1):
        return None
    if WAVE_RANK.get(dw) == WAVE_RANK.get(tw):
        return f"parallel waves: {tw} depends on {dw}"
    return f"{tw} depends on later wave {dw}"


def verify_targets(verify: str) -> list[tuple[str, str]]:
    """(kind, repo-relative candidate) pairs named by the verification cell."""
    out: list[tuple[str, str]] = []
    text = BACKTICK.sub(lambda m: " " + m.group(1) + " ", verify.replace("<br>", " "))
    for m in re.finditer(r"python\s+-m\s+unittest\s+((?:tests\.[\w.]+\s*)+)", text):
        for mod in m.group(1).split():
            out.append(("unittest", mod.replace(".", "/") + ".py"))
    for m in re.finditer(r"python\s+((?:scripts|tests)/[\w./-]+\.py)", text):
        out.append(("script", m.group(1)))
    for m in re.finditer(
        r"(?:e2e\s+--|vitest\s+run|playwright\s+test)\s+((?:[\w./*-]+\s*)+)", text
    ):
        for target in m.group(1).split():
            if target.startswith("-") or target in {"cd", "&&"}:
                break
            if "/" in target or target.endswith(".ts"):
                out.append(("frontend", "frontend/" + target.lstrip("./")))
    return out


def _target_present(path: str, task_files: list[str], repo_root: Path) -> bool:
    if any(
        paths_overlap(path, f) or f.startswith(path.rstrip("/") + "/")
        for f in task_files
    ):
        return True
    if _has_glob(path):
        return any(repo_root.glob(path))
    return (repo_root / path).exists()


def _transitive_deps(plan: Plan, tid: str) -> list[str]:
    seen: list[str] = []
    stack = list(plan.tasks[tid]["deps"])
    while stack:
        d = stack.pop()
        if d in plan.tasks and d not in seen and d != tid:
            seen.append(d)
            stack.extend(plan.tasks[d]["deps"])
    return seen


def _strip_quoted(text: str) -> str:
    return re.sub(r"\"[^\"]*\"|“[^”]*”|'[^']*'", " ", text)


def run_checks(plan: Plan, repo_root: Path) -> tuple[dict[str, list[str]], dict]:
    trace = build_trace(plan)
    checks: dict[str, list[str]] = {}
    defined = plan.is_ids | set(plan.gap_is) | set(plan.qa_is) | set(plan.tasks)

    gaps_by_is = {k for v in plan.gap_is.values() for k in v}
    checks["is_without_gap"] = sorted(i for i in plan.is_ids if i not in gaps_by_is)
    checks["is_without_task"] = sorted(i for i, t in trace.items() if not t["tasks"])
    checks["is_without_qa"] = sorted(i for i, t in trace.items() if not t["qa"])
    gaps_with_task = {g for t in plan.tasks.values() for g in t["gaps"]}
    checks["gap_without_task"] = sorted(
        g for g in plan.gap_is if g not in gaps_with_task
    )
    qa_closed = {q for t in plan.tasks.values() if not is_bulk(t) for q in t["qa"]}
    checks["qa_without_task"] = sorted(q for q in plan.qa_is if q not in qa_closed)
    checks["task_without_gap_is"] = sorted(
        t for t, v in plan.tasks.items() if not v["gaps"] and not v["is"]
    )
    checks["task_without_qa"] = sorted(
        t
        for t, v in plan.tasks.items()
        if not v["qa"]
        and t not in plan.g3_tasks
        and not re.match(r"^—\s*\(.+\)", v["qa_cell"])
    )

    dangling = []
    for gap, is_list in plan.gap_is.items():
        dangling += [f"{gap} -> {i}" for i in is_list if i not in defined]
    for qa, is_list in plan.qa_is.items():
        dangling += [f"{qa} -> {i}" for i in is_list if i not in defined]
    for tid, t in plan.tasks.items():
        dangling += [
            f"{tid} -> {r}" for r in t["gaps"] + t["is"] + t["qa"] if r not in defined
        ]
        dangling += [
            f"{tid} depends on {d}"
            for d in t["deps"]
            if d not in plan.tasks and d not in plan.retired
        ]
    checks["dangling_refs"] = dangling
    checks["dep_on_retired"] = [
        f"{t} depends on {d}"
        for t, v in plan.tasks.items()
        for d in v["deps"]
        if d in plan.retired
    ]

    wave_issues = []
    for tid, t in plan.tasks.items():
        for d in t["deps"]:
            if d in plan.tasks:
                problem = _wave_dep_problem(t, plan.tasks[d])
                if problem:
                    wave_issues.append(
                        f"{tid} ({t['bundle']}) -> {d} ({plan.tasks[d]['bundle']}): {problem}"
                    )
    checks["wave_dependency"] = wave_issues

    checks["bundle_size"] = [
        f"{b}: {len(v['tasks'])} tasks (heading says {v['declared']}, max {MAX_BUNDLE})"
        for b, v in plan.bundles.items()
        if len(v["tasks"]) > MAX_BUNDLE or len(v["tasks"]) != v["declared"]
    ]
    checks["task_over_4h"] = [
        f"{t}: {v['hours']}h"
        for t, v in plan.tasks.items()
        if not v["hours"] <= MAX_HOURS
    ]

    overlaps = []
    for b, v in plan.bundles.items():
        ids = v["tasks"]
        for i, a in enumerate(ids):
            for other in ids[i + 1 :]:
                for pa in task_paths(plan.tasks[a]["files_cell"]):
                    for pb in task_paths(plan.tasks[other]["files_cell"]):
                        if paths_overlap(pa, pb):
                            overlaps.append(f"{b}: {a} `{pa}` <-> {other} `{pb}`")
    checks["file_overlap_in_bundle"] = overlaps

    missing_targets = []
    for tid, t in plan.tasks.items():
        # a target may be created by this task or by any task it (transitively) depends on
        files = []
        for owner in [tid, *_transitive_deps(plan, tid)]:
            files += task_paths(plan.tasks[owner]["files_cell"])
        for kind, path in verify_targets(t["verify"]):
            if not _target_present(path, files, repo_root):
                missing_targets.append(
                    f"{tid}: {kind} `{path}` not in files column or repo"
                )
    checks["verification_target_missing"] = missing_targets

    checks["same_as_wording"] = [
        f"{tid} (r8-tasks.md:{t['line']})"
        for tid, t in plan.tasks.items()
        if SAME_AS in _strip_quoted(t["accept"])
    ]
    checks["table_parse"] = list(plan.parse_issues)

    drift = []
    for is_id, gen in trace.items():
        doc = plan.g1.get(is_id)
        if doc is None:
            drift.append(f"{is_id}: missing from G.1")
            continue
        for key in ("gaps", "tasks", "qa"):
            extra = sorted(set(gen[key]) - set(doc[key]))
            lost = sorted(set(doc[key]) - set(gen[key]))
            if extra or lost:
                drift.append(
                    f"{is_id} {key}: +{','.join(extra) or '-'} / -{','.join(lost) or '-'}"
                )
    drift += [f"{i}: in G.1 but not defined in A" for i in plan.g1 if i not in trace]
    checks["g1_drift"] = drift
    return checks, trace


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--plan-dir", type=Path, default=DEFAULT_PLAN_DIR)
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    ap.add_argument(
        "--check", action="store_true", help="exit 1 when any check has findings"
    )
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument(
        "--output", type=Path, help="write regenerated trace + findings JSON here"
    )
    ap.add_argument(
        "--limit", type=int, default=10, help="items shown per check in text mode"
    )
    args = ap.parse_args(argv)

    plan = Plan(args.plan_dir)
    checks, trace = run_checks(plan, args.repo_root)
    total = sum(len(v) for v in checks.values())
    report = {
        "counts": {
            "is": len(plan.is_ids),
            "gap": len(plan.gap_is),
            "qa": len(plan.qa_is),
            "tasks": len(plan.tasks),
            "bundles": len(plan.bundles),
        },
        "summary": {k: len(v) for k, v in checks.items()},
        "total_findings": total,
        "checks": checks,
    }
    if args.output:
        args.output.write_text(
            json.dumps({**report, "trace": trace}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        c = report["counts"]
        print(
            f"IS {c['is']} · GAP {c['gap']} · QA {c['qa']} · tasks {c['tasks']} · bundles {c['bundles']}"
        )
        for name, items in checks.items():
            print(f"{'FAIL' if items else 'ok  '} {name}: {len(items)}")
            for item in items[: args.limit]:
                print(f"       {item}")
            if len(items) > args.limit:
                print(f"       ... {len(items) - args.limit} more")
        print(f"total findings: {total}")
    return 1 if args.check and total else 0


if __name__ == "__main__":
    sys.exit(main())
