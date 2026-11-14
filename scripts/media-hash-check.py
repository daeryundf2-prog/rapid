#!/usr/bin/env python3
"""Check a media image's hashes against the acquisition log and ``ewfverify`` (T-212).

    python scripts/media-hash-check.py --reference <ewfverify.txt> \\
        --acquisition-log <image.txt> [--ours <rapidtriage.json>] \\
        --output <report.json> --json

Sources (at least one of ``--reference``/``--acquisition-log``):

- ``--reference`` (alias ``--ewfverify``): saved ``ewfverify`` console output.
  Reads ``<ALG> hash stored in file:`` (acquisition-time hash),
  ``<ALG> hash calculated over data:`` (hash of the data as read now),
  ``ewfverify: SUCCESS|FAILURE`` and the error ranges
  ``at sector(s): A - B (number: N)`` (one range = one error chunk).
- ``--acquisition-log``: acquisition tool log (FTK Imager ``.txt``,
  ewfacquire, Guymager ``.info``). The first MD5/SHA1/SHA256 value is the
  acquisition hash; ``bad sectors``/``bad blocks`` counts are read when present.
- ``--ours`` (alias ``--rapid``): optional RapidTriage JSON; the first
  ``md5``/``sha1``/``sha256`` keys found (any nesting) are its media hashes.

Each pair of sources is compared per algorithm. ``match`` is true only when
every comparison is equal, ewfverify did not report FAILURE and no error
chunk was found. Report keys: match, error_chunks, recall (equal
comparisons / comparisons), matched, missing, mismatched, reference_tool.
Shared helpers: rapidtriage/validation/reference_diff.py. Exit 0 match,
1 differences (or FAILURE / error chunks), 2 input error or no comparison possible.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

ALGORITHMS = {"md5": 32, "sha1": 40, "sha256": 64}
_ALG_RE = r"(MD5|SHA-?1|SHA-?256)"
EWF_STORED_RE = re.compile(_ALG_RE + r" hash stored in file:\s*([0-9a-fA-F]+)", re.IGNORECASE)
EWF_CALC_RE = re.compile(_ALG_RE + r" hash calculated over data:\s*([0-9a-fA-F]+)", re.IGNORECASE)
EWF_RESULT_RE = re.compile(r"ewfverify:\s*(SUCCESS|FAILURE)", re.IGNORECASE)
EWF_RANGE_RE = re.compile(r"at sector\(s\):\s*(\d+)\s*-\s*(\d+)(?:\s*\(number:\s*(\d+)\))?", re.IGNORECASE)
EWF_TOTAL_RE = re.compile(r"total number of errors:\s*(\d+)", re.IGNORECASE)
LOG_HASH_RE = re.compile(r"\b" + _ALG_RE + r"\b[^\n:=]*[:=]\s*([0-9a-fA-F]{32,64})\b", re.IGNORECASE)
LOG_NO_BAD_RE = re.compile(r"no bad (?:blocks|sectors)", re.IGNORECASE)
LOG_BAD_RE = re.compile(r"bad (?:blocks|sectors)[^\d\n]*(\d+)", re.IGNORECASE)
LOG_VERIFY_FAIL_RE = re.compile(r"does not match|mismatch|verification failed", re.IGNORECASE)


def _alg(name: str) -> str:
    return name.replace("-", "").casefold()


def _valid(alg: str, value: str) -> bool:
    return len(value) == ALGORITHMS.get(alg, -1)


def parse_ewfverify(text: str) -> dict[str, object]:
    stored: dict[str, str] = {}
    calculated: dict[str, str] = {}
    for pattern, target in ((EWF_STORED_RE, stored), (EWF_CALC_RE, calculated)):
        for match in pattern.finditer(text):
            alg, value = _alg(match.group(1)), match.group(2).casefold()
            if _valid(alg, value):
                target.setdefault(alg, value)
    ranges = [
        {"first_sector": int(m.group(1)), "last_sector": int(m.group(2)),
         "sectors": int(m.group(3)) if m.group(3) else int(m.group(2)) - int(m.group(1)) + 1}
        for m in EWF_RANGE_RE.finditer(text)
    ]
    totals = [int(m.group(1)) for m in EWF_TOTAL_RE.finditer(text)]
    result = EWF_RESULT_RE.search(text)
    return {
        "stored": stored,
        "calculated": calculated,
        "result": result.group(1).upper() if result else "",
        "error_ranges": ranges[: rd.DEFAULT_MAX_LIST],
        "error_chunks": max([len(ranges), *totals]),
    }


def parse_acquisition_log(text: str) -> dict[str, object]:
    hashes: dict[str, str] = {}
    for match in LOG_HASH_RE.finditer(text):
        alg, value = _alg(match.group(1)), match.group(2).casefold()
        if _valid(alg, value):
            hashes.setdefault(alg, value)
    bad = 0
    if not LOG_NO_BAD_RE.search(text):
        bad = sum(int(m.group(1)) for m in LOG_BAD_RE.finditer(text))
    return {"hashes": hashes, "bad_sectors": bad, "verify_failed": bool(LOG_VERIFY_FAIL_RE.search(text))}


def find_hashes(payload: object) -> dict[str, str]:
    found: dict[str, str] = {}

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                alg = re.sub(r"[^0-9a-z]", "", str(key).casefold())
                alg = next((name for name in ALGORITHMS if alg == name or alg.endswith(name)), "")
                if alg and isinstance(value, str) and _valid(alg, value.strip()):
                    found.setdefault(alg, value.strip().casefold())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return found


def _compare(name: str, left: dict[str, str], right: dict[str, str]) -> list[dict[str, object]]:
    return [
        {"pair": name, "algorithm": alg, "left": left[alg], "right": right[alg], "equal": left[alg] == right[alg]}
        for alg in ALGORITHMS
        if alg in left and alg in right
    ]


def check(ewf: dict | None, acquisition: dict | None, ours: dict[str, str] | None) -> dict[str, object]:
    comparisons: list[dict[str, object]] = []
    missing: list[dict[str, str]] = []
    current = (ewf or {}).get("calculated") or {}
    if ewf is not None:
        comparisons += _compare("ewfverify-stored-vs-calculated", ewf["stored"], current)
    if acquisition is not None and ewf is not None:
        comparisons += _compare("acquisition-log-vs-ewfverify-calculated", acquisition["hashes"], current)
    if ours is not None:
        baseline = current if ewf is not None else (acquisition or {}).get("hashes") or {}
        label = "ewfverify-calculated" if ewf is not None else "acquisition-log"
        comparisons += _compare(f"ours-vs-{label}", ours, baseline)
        missing += [{"source": label, "algorithm": alg} for alg in baseline if alg not in ours]
    error_chunks = int((ewf or {}).get("error_chunks") or 0)
    failed = (ewf or {}).get("result") == "FAILURE" or bool((acquisition or {}).get("verify_failed"))
    equal = sum(1 for item in comparisons if item["equal"])
    return {
        "match": bool(comparisons) and equal == len(comparisons) and not failed and error_chunks == 0,
        "error_chunks": error_chunks,
        "recall": round(equal / len(comparisons), 6) if comparisons else None,
        "matched": equal,
        "missing": missing,
        "mismatched": [item for item in comparisons if not item["equal"]],
        "comparisons": comparisons,
        "sources": {
            "ewfverify": ewf,
            "acquisition_log": acquisition,
            "ours": {"hashes": ours} if ours is not None else None,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reference", "--ewfverify", dest="reference", type=Path, help="saved ewfverify output")
    parser.add_argument("--acquisition-log", type=Path, help="acquisition tool log")
    parser.add_argument("--ours", "--rapid", dest="ours", type=Path, help="RapidTriage JSON with media hashes")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("--reference-tool", default="", help="reference tool name/version recorded in the report")
    args = parser.parse_args(argv)
    sources = (("reference", "--reference", args.reference), ("acquisition_log", "--acquisition-log",
               args.acquisition_log), ("ours", "--ours", args.ours))
    try:
        if args.reference is None and args.acquisition_log is None:
            raise rd.ReferenceDiffInputError("--reference(ewfverify 출력) 또는 --acquisition-log 인자가 필요합니다.")
        inputs = {name: rd.require_file(path, flag) for name, flag, path in sources if path is not None}
        ewf = parse_ewfverify(rd.read_text(args.reference)) if args.reference else None
        acquisition = parse_acquisition_log(rd.read_text(args.acquisition_log)) if args.acquisition_log else None
        try:
            ours = find_hashes(json.loads(rd.read_text(args.ours))) if args.ours else None
        except ValueError as exc:
            raise rd.ReferenceDiffInputError(f"우리 출력 파일을 읽지 못했습니다: {args.ours} ({exc})") from exc
        result = check(ewf, acquisition, ours)
        if not result["comparisons"]:
            raise rd.ReferenceDiffInputError("비교할 해시 쌍이 없습니다. 같은 알고리즘의 해시가 두 출처 이상에 있어야 합니다.")
    except rd.ReferenceDiffInputError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return rd.EXIT_INPUT
    tool = args.reference_tool or " + ".join(
        name for name, present in (("ewfverify", ewf), ("acquisition log", acquisition)) if present is not None
    )
    report: dict[str, object] = {
        "schema_version": rd.SCHEMA_VERSION,
        "comparison": "media-hash",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Engineering check of media hashes across the acquisition log, ewfverify and RapidTriage. "
            "Not release evidence."
        ),
        "reference_tool": tool,
        **result,
        "extra": [],
        "counts": {
            "comparisons": len(result["comparisons"]),
            "matched": result["matched"],
            "missing": len(result["missing"]),
            "extra": 0,
            "mismatched": len(result["mismatched"]),
        },
        "inputs": {name: {"path": str(path), "sha256": rd.file_sha256(path)} for name, path in inputs.items()},
        "warnings": [],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    if args.json:
        sys.stdout.write(text)
    else:
        print(
            f"media-hash: match={result['match']} error_chunks={result['error_chunks']} "
            f"comparisons={len(result['comparisons'])} mismatched={len(result['mismatched'])}"
        )
        if args.output is not None:
            print(f"-> {args.output}")
    return rd.EXIT_OK if result["match"] else rd.EXIT_DIFF


if __name__ == "__main__":
    raise SystemExit(main())
