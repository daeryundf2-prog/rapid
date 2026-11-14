#!/usr/bin/env python3
"""Terminology lint for the console UI (R8 T-005, design system C.7, D70).

Scans user-visible source text in ``frontend/src`` (``.ts``/``.tsx``, tests
excluded) for the eight forbidden terms of R8 v3 and reports each hit as
``file:line``. Comments are stripped before matching, so only string
literals, template literals and JSX text are checked.

v3 scope: only the eight terms below are errors. Every other C.7 term is
checked by the real-data render checks (QA-035/045), not by this lint.

Ratchet: ``BASELINE`` records the hit count per term on the tree this lint
was introduced on. A term whose count rises above its baseline fails (exit
1); counts at or below baseline pass. When UI strings are fixed, lower the
baseline (``--print-baseline`` prints the current counts). T-117 promotes
the lint to "zero hits" once the rewrites land.

Exit status:
    1  a term exceeds its baseline (or any hit with --strict)
    0  otherwise
"""
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = Path("frontend") / "src"
EXTENSIONS = (".ts", ".tsx")

# Files that hold *old* labels on purpose (alias tables mapping legacy names to
# new ones). They are contract data, not screen copy.
EXCLUDED_FILES = frozenset({"frontend/src/contracts/uiContract.ts"})

_HANGUL = "가-힣"

# term id -> (display name, compiled pattern, replacement per C.7)
TERMS: dict[str, tuple[str, re.Pattern[str], str]] = {
    # "런" as a word (not the syllable inside 프런트·브런치 etc., not 런타임·런던).
    "run-ko": ("런", re.compile(rf"(?<![{_HANGUL}])런(?!타임|던)"), "처리 n차"),
    # "IOC" except the sanctioned analyst-mode form "지표(IOC)".
    "ioc": ("IOC", re.compile(r"(?<!지표\()(?<![A-Za-z0-9_])IOC(?![A-Za-z0-9_])"), "지표(IOC) — 분석 담당 모드만"),
    "web-ui": ("web-ui", re.compile(r"web-ui", re.IGNORECASE), "분석 담당"),
    "examiner-ko": ("검사관", re.compile(r"검사관"), "분석 담당 (서명란만 분석관)"),
    "review-board": ("리뷰보드", re.compile(r"리뷰\s?보드"), "검토 목록"),
    "unknown-seconds": ("알 수 없음초", re.compile(r"알 수 없음\s?초"), "— (시간 미상)"),
    "failed-to-fetch": ("Failed to fetch", re.compile(r"Failed to fetch", re.IGNORECASE), "한국어 연결 오류 문장"),
    "request-failed": ("Request failed", re.compile(r"Request failed", re.IGNORECASE), "한국어 요청 오류 문장"),
}

# Hit counts on feat/r6-ux @ 425fdb0 (T-005), lowered on wb12/review-terms
# (WB-12: 리뷰 -> 검토, 리뷰보드 -> 검토 목록). Lower these as strings are fixed.
BASELINE: dict[str, int] = {
    "run-ko": 210,
    "ioc": 13,
    "web-ui": 3,
    "examiner-ko": 10,
    "review-board": 0,
    "unknown-seconds": 0,
    "failed-to-fetch": 0,
    "request-failed": 0,
}


@dataclass(frozen=True)
class Hit:
    term: str
    path: str
    line: int
    text: str


def is_test_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return (
        ".test." in name
        or ".spec." in name
        or name.startswith("testSetup")
        or "/__tests__/" in rel
        or "/__mocks__/" in rel
    )


def strip_comments(src: str) -> str:
    """Blank out ``//`` and ``/* */`` comments, keeping strings and newlines.

    Tracks single/double-quoted strings and template literals with nested
    ``${ ... }`` code so comment markers inside strings are not treated as
    comments. Regex literals are not parsed (rare enough to accept).
    """
    out: list[str] = []
    i = 0
    n = len(src)
    # stack of modes: "code" (with brace depth) or "tpl"
    stack: list[list] = [["code", 0]]
    while i < n:
        mode = stack[-1]
        c = src[i]
        if mode[0] == "tpl":
            if c == "\\" and i + 1 < n:
                out.append(src[i : i + 2])
                i += 2
            elif c == "`":
                stack.pop()
                out.append(c)
                i += 1
            elif c == "$" and i + 1 < n and src[i + 1] == "{":
                stack.append(["code", 0])
                out.append("${")
                i += 2
            else:
                out.append(c)
                i += 1
            continue
        # code mode
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(src[i:j])
            i = j
        elif c == "`":
            stack.append(["tpl", 0])
            out.append(c)
            i += 1
        elif c == "{":
            mode[1] += 1
            out.append(c)
            i += 1
        elif c == "}":
            if mode[1] == 0 and len(stack) > 1:
                stack.pop()  # end of ${ ... }
            else:
                mode[1] -= 1
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def scan_text(rel: str, src: str) -> list[Hit]:
    hits: list[Hit] = []
    for lineno, line in enumerate(strip_comments(src).splitlines(), start=1):
        for term, (_name, pattern, _fix) in TERMS.items():
            for _ in pattern.finditer(line):
                hits.append(Hit(term, rel, lineno, line.strip()[:160]))
    return hits


def scan(root: Path) -> list[Hit]:
    base = root / SOURCE_DIR
    hits: list[Hit] = []
    if not base.is_dir():
        return hits
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix not in EXTENSIONS:
            continue
        rel = path.relative_to(root).as_posix()
        if rel in EXCLUDED_FILES or is_test_file(rel):
            continue
        hits.extend(scan_text(rel, path.read_text(encoding="utf-8", errors="replace")))
    return hits


def summarize(hits: list[Hit], baseline: dict[str, int], strict: bool) -> dict:
    counts = {term: 0 for term in TERMS}
    for hit in hits:
        counts[hit.term] += 1
    terms = []
    failed = False
    for term, (name, _p, fix) in TERMS.items():
        limit = 0 if strict else baseline.get(term, 0)
        over = counts[term] > limit
        failed = failed or over
        terms.append(
            {
                "term": term,
                "label": name,
                "replacement": fix,
                "count": counts[term],
                "baseline": baseline.get(term, 0),
                "status": "fail" if over else ("below-baseline" if counts[term] < limit else "ok"),
            }
        )
    return {"ok": not failed, "total": len(hits), "terms": terms, "counts": counts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to scan")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--strict", action="store_true", help="fail on any hit (ignore baseline)")
    parser.add_argument("--print-baseline", action="store_true", help="print current counts as a BASELINE dict")
    parser.add_argument("--quiet", action="store_true", help="omit per-hit lines")
    args = parser.parse_args(argv)

    hits = scan(args.root)
    report = summarize(hits, BASELINE, args.strict)

    if args.print_baseline:
        print("BASELINE: dict[str, int] = {")
        for term, count in report["counts"].items():
            print(f'    "{term}": {count},')
        print("}")
        return 0
    if args.json:
        report["hits"] = [hit.__dict__ for hit in hits]
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1

    if not args.quiet:
        for hit in hits:
            print(f"{hit.path}:{hit.line}: [{TERMS[hit.term][0]}] {hit.text}")
    for row in report["terms"]:
        print(f"{row['label']}: {row['count']} (baseline {row['baseline']}) {row['status']} -> {row['replacement']}")
    print(f"total {report['total']} — {'ok' if report['ok'] else 'FAIL: new forbidden terms'}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
