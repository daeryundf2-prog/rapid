#!/usr/bin/env python3
"""Check a media image's hashes against the acquisition log and ``ewfverify`` (T-212).

    python scripts/media-hash-check.py --reference <ewfverify.txt> \\
        --acquisition-log <image.txt> [--ours <rapidtriage.json> [--ours-scope auto|media|container]] \\
        --output <report.json> --json

Sources (at least one of ``--reference``/``--acquisition-log``):

- ``--reference`` (alias ``--ewfverify``): saved ``ewfverify`` console output.
  Reads ``<ALG> hash stored in file:`` (acquisition-time hash),
  ``<ALG> hash calculated over data:`` (hash of the data as read now),
  ``ewfverify: SUCCESS|FAILURE`` and the error ranges
  ``at sector(s): A - B (number: N)`` (one range = one error chunk).
- ``--acquisition-log``: acquisition tool log (FTK Imager ``.txt``,
  ewfacquire, Guymager ``.info``). The first MD5/SHA1/SHA256 value is the
  acquisition hash; every ``bad sectors``/``bad blocks``/``read errors`` count is
  summed (a "no bad blocks" line elsewhere does not zero a stated count).
- ``--ours`` (alias ``--rapid``): optional RapidTriage JSON. "Ours" is taken only from a
  hash RapidTriage computed (WB-12 review P1-5): the dotted ``--ours-key`` path, else the
  first present of ``OURS_COMPUTED_KEYS`` (the ``hashes`` of ``source-metadata`` with
  ``hash_status: computed`` = SHA/MD5 of the file's bytes). A key path naming an expected,
  recorded, stored, acquisition, record or inventory value is refused (that would compare a
  value with itself); the default ``hashes`` key needs ``hash_status: computed``. The key used
  and its scope are in ``sources.ours``. Scope (``--ours-scope``, default ``auto``): for an
  E01/Ex01/L01/AFF/VHD(X)/VMDK file (by the payload's ``extension`` / ``name`` / ``path``) the
  file bytes are the container, which never equals ``ewfverify``'s media hash, so it is not
  compared and reported "컨테이너 해시 — 매체 해시와 비교 불가"; only a raw image's file hash
  (``media``) is a media hash.

Each pair of sources is compared per algorithm. ``match`` is true only when
every comparison is equal, ewfverify did not report FAILURE, no error chunk
was found, the acquisition log states no bad sectors/blocks and, when ``--ours`` is given,
RapidTriage's hash was compared on every algorithm the other side has (R8 WB-13 review P1-4:
``--ours`` with zero ``ours-vs-*`` comparisons, a container hash, or a ``missing`` algorithm is
not a match; ``match_reasons`` says why in Korean). Report keys:
match, match_reasons, ours_compared (``null`` without ``--ours``), error_chunks (ewfverify
error ranges + the log's bad sector/block count; split in ``error_chunk_sources``),
bad_sectors, recall (equal comparisons / comparisons), matched, missing, mismatched,
reference_tool.
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
LOG_BAD_RE = re.compile(r"(?:bad (?:blocks?|sectors?)|read errors?)(?: count| found)?\s*[:=]?\s*(\d+)", re.IGNORECASE)
#: Where RapidTriage writes a hash it computed itself (tried in order unless --ours-key is given).
OURS_COMPUTED_KEYS = ("hashes", "computed_hashes", "media_hashes")
#: A key path containing any of these names a value RapidTriage did not compute.
_NOT_COMPUTED_MARKERS = ("expected", "recorded", "stored", "acquisition", "record_", "inventory", "header")
LOG_VERIFY_FAIL_RE = re.compile(r"does not match|mismatch|verification failed", re.IGNORECASE)
#: File formats whose bytes are a container around the media data (their file hash is not a media hash).
CONTAINER_SUFFIXES = (".e01", ".ex01", ".s01", ".l01", ".lx01", ".aff", ".aff4", ".vhd", ".vhdx", ".vmdk")
CONTAINER_REASON = "컨테이너 해시 — 매체 해시와 비교 불가"
NO_OVERLAP_REASON = "우리 해시와 겹치는 알고리즘 없음 — RapidTriage 해시를 하나도 비교하지 못함"


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
    bad = sum(int(m.group(1)) for m in LOG_BAD_RE.finditer(text))
    return {"hashes": hashes, "bad_sectors": bad, "verify_failed": bool(LOG_VERIFY_FAIL_RE.search(text))}


def _hashes_at(node: object) -> dict[str, str]:
    """``{alg: hex}`` from a dict of algorithm keys, or one hex string (algorithm by length)."""
    found: dict[str, str] = {}
    if isinstance(node, str):
        value = node.strip().casefold()
        alg = next((name for name, length in ALGORITHMS.items() if len(value) == length), "")
        if alg and re.fullmatch(r"[0-9a-f]+", value):
            found[alg] = value
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            alg = re.sub(r"[^0-9a-z]", "", str(key).casefold())
            if alg in ALGORITHMS and isinstance(value, str) and _valid(alg, value.strip()):
                found[alg] = value.strip().casefold()
    return found


def find_hashes(payload: object, key: str | None = None) -> tuple[dict[str, str], str]:
    """RapidTriage's own computed hashes and the key path they came from.

    Only ``key`` (dotted) or ``OURS_COMPUTED_KEYS`` are read; never an ``expected_*`` /
    recorded / header value (review P1-5: a recorded hash compared with itself is a circular pass).
    """
    candidates = [key] if key else list(OURS_COMPUTED_KEYS)
    for path in candidates:
        lowered = path.casefold()
        bad = next((marker for marker in _NOT_COMPUTED_MARKERS if marker in lowered), None)
        if bad:
            raise rd.ReferenceDiffInputError(
                f"--ours-key {path}: '{bad}'가 든 값은 RapidTriage가 계산한 해시가 아닙니다(기록값끼리 비교가 됨)."
            )
        node: object = payload
        for segment in path.split("."):
            node = node.get(segment) if isinstance(node, dict) else None
        if key is None and isinstance(payload, dict) and path == "hashes" and payload.get("hash_status") != "computed":
            continue  # WB-13 review P1-4: a hash map without hash_status: computed is not known to be computed
        found = _hashes_at(node)
        if found:
            return found, path
    tried = ", ".join(candidates)
    raise rd.ReferenceDiffInputError(
        f"우리 출력에서 RapidTriage가 계산한 해시를 찾지 못했습니다(찾은 키: {tried}). --ours-key로 경로를 지정하세요."
    )


def ours_scope(payload: object, requested: str = "auto") -> str:
    """``media`` or ``container`` for the file RapidTriage hashed (``auto``: by its file name)."""
    if requested in ("media", "container"):
        return requested
    if isinstance(payload, dict):
        for field in ("extension", "name", "path"):
            value = str(payload.get(field) or "").strip().casefold()
            if value and value.endswith(CONTAINER_SUFFIXES):
                return "container"
    return "media"


def _compare(name: str, left: dict[str, str], right: dict[str, str]) -> list[dict[str, object]]:
    return [
        {"pair": name, "algorithm": alg, "left": left[alg], "right": right[alg], "equal": left[alg] == right[alg]}
        for alg in ALGORITHMS
        if alg in left and alg in right
    ]


def check(
    ewf: dict | None,
    acquisition: dict | None,
    ours: dict[str, str] | None,
    ours_key: str | None = None,
    scope: str = "media",
) -> dict[str, object]:
    comparisons: list[dict[str, object]] = []
    missing: list[dict[str, str]] = []
    reasons: list[str] = []
    ours_compared: bool | None = None
    current = (ewf or {}).get("calculated") or {}
    if ewf is not None:
        comparisons += _compare("ewfverify-stored-vs-calculated", ewf["stored"], current)
    if acquisition is not None and ewf is not None:
        comparisons += _compare("acquisition-log-vs-ewfverify-calculated", acquisition["hashes"], current)
    if ours is not None:
        ours_compared = False
        if scope == "container":
            reasons.append(CONTAINER_REASON)
        else:
            baseline = current if ewf is not None else (acquisition or {}).get("hashes") or {}
            label = "ewfverify-calculated" if ewf is not None else "acquisition-log"
            pairs = _compare(f"ours-vs-{label}", ours, baseline)
            comparisons += pairs
            ours_compared = bool(pairs)
            missing += [{"source": label, "algorithm": alg} for alg in baseline if alg not in ours]
            if not pairs:
                reasons.append(NO_OVERLAP_REASON)
            elif missing:
                reasons.append(
                    "RapidTriage 해시에 없는 알고리즘: " + ", ".join(f"{item['algorithm']}({item['source']})" for item in missing)
                )
    ewf_chunks = int((ewf or {}).get("error_chunks") or 0)
    bad_sectors = int((acquisition or {}).get("bad_sectors") or 0)
    error_chunks = ewf_chunks + bad_sectors
    failed = (ewf or {}).get("result") == "FAILURE" or bool((acquisition or {}).get("verify_failed"))
    equal = sum(1 for item in comparisons if item["equal"])
    if equal != len(comparisons):
        reasons.append("해시 불일치: " + ", ".join(f"{item['pair']} {item['algorithm']}" for item in comparisons if not item["equal"]))
    if failed:
        reasons.append("검증 도구가 실패를 보고함(ewfverify FAILURE 또는 획득 로그 검증 실패)")
    if error_chunks:
        reasons.append(f"오류 청크·불량 섹터 {error_chunks}")
    return {
        "match": bool(comparisons) and not reasons,
        "match_reasons": reasons,
        "ours_compared": ours_compared,
        "error_chunks": error_chunks,
        "error_chunk_sources": {"ewfverify_error_ranges": ewf_chunks, "acquisition_log_bad_sectors": bad_sectors},
        "bad_sectors": bad_sectors,
        "recall": round(equal / len(comparisons), 6) if comparisons else None,
        "matched": equal,
        "missing": missing,
        "mismatched": [item for item in comparisons if not item["equal"]],
        "comparisons": comparisons,
        "sources": {
            "ewfverify": ewf,
            "acquisition_log": acquisition,
            "ours": (
                {
                    "hashes": ours,
                    "key": ours_key,
                    "scope": "RapidTriage가 계산한 파일 바이트 해시(원시 이미지 = 매체 데이터, E01 = 컨테이너라 ewfverify와 같을 수 없음)",
                    "scope_kind": scope,
                }
                if ours is not None
                else None
            ),
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
    parser.add_argument(
        "--ours-key",
        default=None,
        help="dotted path of the hash RapidTriage computed in --ours (default: " + ", ".join(OURS_COMPUTED_KEYS) + ")",
    )
    parser.add_argument(
        "--ours-scope",
        choices=("auto", "media", "container"),
        default="auto",
        help="what the --ours file hash covers (auto: container for E01/Ex01/L01/AFF/VHD(X)/VMDK by file name)",
    )
    args = parser.parse_args(argv)
    sources = (("reference", "--reference", args.reference), ("acquisition_log", "--acquisition-log",
               args.acquisition_log), ("ours", "--ours", args.ours))
    try:
        if args.reference is None and args.acquisition_log is None:
            raise rd.ReferenceDiffInputError("--reference(ewfverify 출력) 또는 --acquisition-log 인자가 필요합니다.")
        inputs = {name: rd.require_file(path, flag) for name, flag, path in sources if path is not None}
        ewf = parse_ewfverify(rd.read_text(args.reference)) if args.reference else None
        acquisition = parse_acquisition_log(rd.read_text(args.acquisition_log)) if args.acquisition_log else None
        ours: dict[str, str] | None = None
        ours_key: str | None = None
        scope = "media"
        if args.ours:
            try:
                payload = json.loads(rd.read_text(args.ours))
            except ValueError as exc:
                raise rd.ReferenceDiffInputError(f"우리 출력 파일을 읽지 못했습니다: {args.ours} ({exc})") from exc
            ours, ours_key = find_hashes(payload, args.ours_key)
            scope = ours_scope(payload, args.ours_scope)
        result = check(ewf, acquisition, ours, ours_key, scope)
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
        for reason in result["match_reasons"]:  # type: ignore[union-attr]
            print(f"일치 아님: {reason}")
        if args.output is not None:
            print(f"-> {args.output}")
    return rd.EXIT_OK if result["match"] else rd.EXIT_DIFF


if __name__ == "__main__":
    raise SystemExit(main())
