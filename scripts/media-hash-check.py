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
Exit 2 when an input is missing or no comparison is possible.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

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
        "error_ranges": ranges[: H.LIST_CAP],
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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--reference-tool", default="ewfverify+acquisition-log")

    def body() -> int:
        args = parser.parse_args(argv)
        given = {
            name: path
            for name, path in (("--reference", args.reference), ("--acquisition-log", args.acquisition_log),
                               ("--ours", args.ours))
            if path is not None
        }
        if args.reference is None and args.acquisition_log is None:
            raise H.InputError("give --reference (ewfverify output) and/or --acquisition-log")
        H.require_inputs(given)
        ewf = parse_ewfverify(_read(args.reference)) if args.reference else None
        acquisition = parse_acquisition_log(_read(args.acquisition_log)) if args.acquisition_log else None
        ours = find_hashes(json.loads(_read(args.ours))) if args.ours else None
        result = check(ewf, acquisition, ours)
        if not result["comparisons"]:
            raise H.InputError("no hash pair to compare (need two sources with the same algorithm)")
        inputs = {name.lstrip("-").replace("-", "_"): path for name, path in given.items()}
        report = H.envelope("media-hash", args.reference_tool, inputs, result)
        summary = (
            f"match={result['match']} error_chunks={result['error_chunks']} "
            f"comparisons={len(result['comparisons'])} mismatched={len(result['mismatched'])}"
        )
        return H.emit(report, args.output, args.json, summary)

    return H.run_cli(body)


def _read(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise H.InputError(f"cannot read {path}: {exc}") from exc
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):  # some imagers write UTF-16 logs
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


if __name__ == "__main__":
    raise SystemExit(main())
