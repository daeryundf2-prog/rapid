#!/usr/bin/env python3
"""Corpus audit: check the six R8 corpus manifests (C1-C6) outside Git (R8 T-166, QA-201).

Each corpus lives under ``<corpus root>/<Cn>/manifest.json`` (default root
``$R8_CORPUS_ROOT`` or ``D:/rapid-qa/corpus``). A manifest records where the data came
from and how to re-verify it::

  {"corpus": "C2", "status": "available",          # or "unavailable" + "unavailable_reason"
   "source": "...", "license": "...", "created": "2026-11-12",
   "answer_key": "answer-key.json",                # path, or "none - <reason>"
   "size_bytes": 123,
   "items": [{"path": "img/IMG-B.E01", "size": 100, "sha256": "<64 hex>", "mtime_ns": 1}],
   "expected_tier1": ["documents", "web"],         # optional (default per corpus below)
   "runs": ["D:/rapid-qa/derived/.../run-folder"]} # processed result folders (optional)

Per corpus the audit reports: manifest present, the six required fields (source, license,
size, hash, created, answer key), item presence, size/mtime agreement (quick mode) or a
full SHA-256 re-hash (``--full``), the Tier 1 cards the corpus is expected to exercise and
whether a processed run has non-zero rows for each, and coverage gaps across all corpora.

  python scripts/r8-corpus-audit.py
  python scripts/r8-corpus-audit.py --corpus-root D:/rapid-qa/corpus --full --json
  python scripts/r8-corpus-audit.py --run C2=D:/rapid-qa/derived/r6-s1-run --output D:/qa/corpus-audit.json
  python scripts/r8-corpus-audit.py --check-summary docs/research/r8-corpus-plan.md

Read-only: evidence and manifests are only opened for reading; ``--output`` is refused
when it overlaps a corpus folder or item (``rapidtriage.core.output_guard`` rule). The
report holds counts and codes only - no paths, names, hashes, sources or licences - and is
scanned for identifier patterns before it is printed or written (a hit fails the audit).
Exit 0 = pass, 1 = audit failure, 2 = identifier found in a summary.
"""

from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.output_guard import output_evidence_problem

SCHEMA = "r8-corpus-audit/1"
CHUNK = 1024 * 1024
ENV_ROOT = "R8_CORPUS_ROOT"
DEFAULT_ROOT = "D:/rapid-qa/corpus"
MANIFEST_NAME = "manifest.json"
RUN_SUMMARY = "rapidtriage-run-summary.json"
CORPORA = ("C1", "C2", "C3", "C4", "C5", "C6")
REQUIRED_FIELDS = ("source", "license", "size", "hash", "created", "answer_key")
TIER1_CARDS = (
    "documents", "email", "messenger", "web", "exfil",
    "execution", "deleted", "accounts_logon", "ai_usage",
)
#: What each corpus is meant to exercise (r8-qa-scenarios E.1). A manifest may override.
DEFAULT_EXPECTED: dict[str, tuple[str, ...]] = {
    "C1": (),  # installer-only NTFS image: empty-image regression, zero-reason checks
    "C2": ("documents", "web", "exfil", "execution", "deleted", "accounts_logon"),
    "C3": ("documents", "email", "messenger", "web", "exfil", "execution", "deleted", "accounts_logon"),
    "C4": ("ai_usage",),
    "C5": ("email", "exfil", "deleted", "accounts_logon"),
    "C6": ("ai_usage",),
}
ABSENT_ANSWER_KEY = re.compile(r"^\s*(none|n/a|없음|미작성|불필요)\b", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Rows that only say "an app/hive exists" are not data for the card.
NON_CONTENT_SUFFIXES = ("-summary", "-inventory", "-hive")
NON_CONTENT_MARKERS = ("source-candidate", "crypto-material", "user-id-candidate")

#: Identifier patterns that must never appear in a repository summary.
IDENTIFIER_PATTERNS: dict[str, re.Pattern[str]] = {
    "windows_path": re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]"),
    "unc_path": re.compile(r"\\\\[A-Za-z0-9._$-]+\\"),
    "posix_home_path": re.compile(r"/(?:home|Users|mnt|media|root)/[^\s/]+"),
    "long_hex": re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "windows_sid": re.compile(r"\bS-1-5-21-\d+"),
    "evidence_file": re.compile(r"\b[\w.-]+\.(?:E0\d|Ex0\d|dd|raw|vhdx?|aff4?)\b", re.IGNORECASE),
}


# --------------------------------------------------------------------------- cards


def card_for(kind: str, artifact_type: str) -> str | None:
    """Tier 1 card of one ``(kind, artifact_type)`` row group (``None`` = not Tier 1)."""
    k, t = kind.lower(), artifact_type.lower()
    if t.endswith(NON_CONTENT_SUFFIXES) or any(m in t for m in NON_CONTENT_MARKERS):
        return None
    if k == "ai-agent" or t.startswith("ai-") or t == "browser-ai-usage":
        return "ai_usage"
    if (
        t.startswith(("usb-", "cloud-sync-"))
        or t in {"windows-usb-device", "windows-mounted-device"}
        or k == "cloud-sync"
    ):
        return "exfil"
    if k == "windows-os-account" or t.startswith("logon-") or t == "eventlog-logon-session":
        return "accounts_logon"
    if "deleted" in t or "recycle" in t or t == "usn-record" or k in {"recovered-files", "carving"}:
        return "deleted"
    if k == "email" or t.startswith("email-"):
        return "email"
    if k.startswith("kakaotalk") or k in {"mobile-export", "messenger"} or t.endswith("-message"):
        return "messenger"
    if k == "browser":
        return "web"
    if k in {"windows-prefetch", "windows-execution"} or t.startswith("execution-"):
        return "execution"
    if k in {"generic-documents", "recent-files"} or t == "registry-office-mru":
        return "documents"
    return None


def _read_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def run_card_rows(run_dir: Path) -> dict[str, int] | None:
    """Rows per Tier 1 card in one processed result folder (``None`` when not a run)."""
    if not (run_dir / RUN_SUMMARY).is_file():
        return None
    rows = dict.fromkeys(TIER1_CARDS, 0)
    for path in sorted((run_dir / "artifacts").glob("rapidtriage-artifacts-*.json")):
        kind = path.name[len("rapidtriage-artifacts-"):-len(".json")]
        try:
            payload = _read_json(path)
        except (OSError, ValueError):
            continue
        summary = payload.get("summary") if isinstance(payload, dict) else None
        counts = summary.get("artifact_type_counts") if isinstance(summary, dict) else None
        if not isinstance(counts, dict):
            continue
        for artifact_type, count in counts.items():
            card = card_for(kind, str(artifact_type))
            if card and isinstance(count, int) and count > 0:
                rows[card] += count
    return rows


# --------------------------------------------------------------------------- manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _resolve(base: Path, raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else base / path


def _valid_date(value: object) -> bool:
    if not _text(value):
        return False
    text = str(value).strip()
    try:
        date.fromisoformat(text[:10])
    except ValueError:
        return False
    if len(text) > 10:
        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return False
    return True


def missing_fields(manifest: dict) -> list[str]:
    """Required fields absent or malformed (subset of :data:`REQUIRED_FIELDS`)."""
    missing: list[str] = []
    if not _text(manifest.get("source")):
        missing.append("source")
    if not _text(manifest.get("license")):
        missing.append("license")
    size = manifest.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        missing.append("size")
    items = manifest.get("items")
    if (
        not isinstance(items, list)
        or not items
        or not all(isinstance(i, dict) and SHA256_RE.match(str(i.get("sha256", ""))) for i in items)
    ):
        missing.append("hash")
    if not _valid_date(manifest.get("created")):
        missing.append("created")
    if not _text(manifest.get("answer_key")):
        missing.append("answer_key")
    return missing


def verify_items(base: Path, items: list, *, full: bool) -> dict:
    """Presence and size/mtime (quick) or SHA-256 (full) agreement of every item, as counts."""
    out = {
        "items": 0, "present": 0, "missing": 0, "hash_recorded": 0,
        "size_ok": 0, "size_mismatch": 0, "size_unrecorded": 0,
        "mtime_ok": 0, "mtime_mismatch": 0, "mtime_unrecorded": 0,
        "sha256_ok": 0, "sha256_mismatch": 0, "sha256_unverified": 0,
        "bytes_on_disk": 0,
    }
    for item in items if isinstance(items, list) else []:
        out["items"] += 1
        if not isinstance(item, dict) or not _text(item.get("path")):
            out["missing"] += 1
            continue
        recorded_hash = str(item.get("sha256", ""))
        if SHA256_RE.match(recorded_hash):
            out["hash_recorded"] += 1
        path = _resolve(base, str(item["path"]))
        if not path.is_file():
            out["missing"] += 1
            continue
        out["present"] += 1
        st = path.stat()
        out["bytes_on_disk"] += st.st_size
        size = item.get("size")
        if isinstance(size, int) and not isinstance(size, bool):
            out["size_ok" if size == st.st_size else "size_mismatch"] += 1
        else:
            out["size_unrecorded"] += 1
        mtime = item.get("mtime_ns")
        if isinstance(mtime, int) and not isinstance(mtime, bool):
            out["mtime_ok" if mtime == st.st_mtime_ns else "mtime_mismatch"] += 1
        else:
            out["mtime_unrecorded"] += 1
        if full and SHA256_RE.match(recorded_hash):
            ok = sha256_file(path) == recorded_hash.lower()
            out["sha256_ok" if ok else "sha256_mismatch"] += 1
        else:
            out["sha256_unverified"] += 1
    return out


def _answer_key_state(base: Path, value: object) -> str:
    if not _text(value):
        return "missing"
    text = str(value).strip()
    if ABSENT_ANSWER_KEY.match(text):
        return "declared_absent"
    return "present" if _resolve(base, text).exists() else "not_found"


def _expected(corpus: str, manifest: dict) -> tuple[list[str], list[str]]:
    raw = manifest.get("expected_tier1")
    if raw is None:
        return list(DEFAULT_EXPECTED.get(corpus, ())), []
    values = [str(v) for v in raw] if isinstance(raw, list) else []
    return [v for v in values if v in TIER1_CARDS], [v for v in values if v not in TIER1_CARDS]


def audit_corpus(
    corpus: str, folder: Path, *, full: bool, extra_runs: list[Path], secrets: set[str]
) -> dict:
    """One corpus entry of the report (counts and codes only)."""
    entry: dict = {"corpus": corpus, "issues": []}
    manifest_path = folder / MANIFEST_NAME
    if not manifest_path.is_file():
        entry.update(status="no_manifest", manifest_present=False)
        entry["issues"].append("manifest_missing")
        return entry
    entry["manifest_present"] = True
    try:
        manifest = _read_json(manifest_path)
    except (OSError, ValueError):
        manifest = None
    if not isinstance(manifest, dict):
        entry["status"] = "invalid_manifest"
        entry["issues"].append("manifest_unreadable")
        return entry
    _collect_literals(manifest, secrets)
    if manifest.get("corpus") not in (None, corpus):
        entry["issues"].append("corpus_id_mismatch")
    status = str(manifest.get("status") or "available").strip().lower()
    if status == "unavailable":
        entry["status"] = "unavailable"
        entry["unavailable_reason_recorded"] = _text(manifest.get("unavailable_reason"))
        if not entry["unavailable_reason_recorded"]:
            entry["issues"].append("unavailable_without_reason")
        expected, unknown = _expected(corpus, manifest)
        entry["expected_tier1"] = expected
        entry["coverage_gaps"] = list(expected)
        if unknown:
            entry["issues"].append("unknown_tier1_card")
        return entry
    if status != "available":
        entry["issues"].append("unknown_status")
    entry["status"] = "available"
    missing = missing_fields(manifest)
    entry["fields_missing"] = missing
    entry["issues"].extend(f"field_missing:{name}" for name in missing)

    checks = verify_items(folder, manifest.get("items") or [], full=full)
    checks["mode"] = "full_sha256" if full else "quick_size_mtime"
    entry["items"] = checks
    if checks["missing"]:
        entry["issues"].append("item_missing")
    if checks["size_mismatch"]:
        entry["issues"].append("item_size_mismatch")
    if checks["mtime_mismatch"]:
        entry["issues"].append("item_mtime_changed")
    if checks["sha256_mismatch"]:
        entry["issues"].append("item_sha256_mismatch")
    size = manifest.get("size_bytes")
    if isinstance(size, int) and checks["missing"] == 0 and checks["items"] and size != checks["bytes_on_disk"]:
        entry["issues"].append("size_bytes_disagrees")

    answer_state = _answer_key_state(folder, manifest.get("answer_key"))
    entry["answer_key"] = answer_state
    if answer_state == "not_found":
        entry["issues"].append("answer_key_not_found")

    expected, unknown = _expected(corpus, manifest)
    if unknown:
        entry["issues"].append("unknown_tier1_card")
    entry["expected_tier1"] = expected
    runs_raw = manifest.get("runs") or []
    run_paths = [_resolve(folder, str(r)) for r in runs_raw if _text(r)] + extra_runs
    rows = dict.fromkeys(TIER1_CARDS, 0)
    runs_found = 0
    for run_dir in run_paths:
        card_rows = run_card_rows(run_dir)
        if card_rows is None:
            continue
        runs_found += 1
        for card, count in card_rows.items():
            rows[card] += count
    entry["runs"] = {"declared": len(run_paths), "found": runs_found}
    if run_paths and runs_found < len(run_paths):
        entry["issues"].append("run_not_found")
    entry["tier1_rows"] = rows if runs_found else None
    entry["coverage_gaps"] = [c for c in expected if not runs_found or rows[c] == 0]
    return entry


def _collect_literals(manifest: dict, secrets: set[str]) -> None:
    """Manifest strings that must not leak into a summary (sources, licences, names)."""
    for key in ("source", "license", "answer_key", "unavailable_reason"):
        if _text(manifest.get(key)):
            secrets.add(str(manifest[key]).strip())
    for item in manifest.get("items") or []:
        if isinstance(item, dict) and _text(item.get("path")):
            raw = str(item["path"]).strip()
            secrets.add(raw)
            secrets.add(Path(raw).name)
            if _text(item.get("sha256")):
                secrets.add(str(item["sha256"]).strip())
    for run in manifest.get("runs") or []:
        if _text(run):
            secrets.add(str(run).strip())


# --------------------------------------------------------------------------- report


def identifier_hits(text: str, literals: set[str] | None = None) -> dict[str, int]:
    """Count identifier-pattern hits in ``text`` (pattern name -> count; empty = clean)."""
    hits: dict[str, int] = {}
    for name, pattern in IDENTIFIER_PATTERNS.items():
        count = len(pattern.findall(text))
        if count:
            hits[name] = count
    leaked = sum(1 for lit in literals or () if len(lit) >= 4 and lit in text)
    if leaked:
        hits["manifest_literal"] = leaked
    return hits


def audit(root: Path, *, full: bool = False, runs: dict[str, list[Path]] | None = None) -> tuple[dict, set[str]]:
    """Audit every corpus under ``root``; returns ``(report, manifest literals)``."""
    secrets: set[str] = set()
    corpora = [
        audit_corpus(cid, root / cid, full=full, extra_runs=(runs or {}).get(cid, []), secrets=secrets)
        for cid in CORPORA
    ]
    covered = {
        card
        for entry in corpora
        for card, count in (entry.get("tier1_rows") or {}).items()
        if count > 0
    }
    field_failures = sum(1 for e in corpora if e["issues"])
    report = {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": "full_sha256" if full else "quick_size_mtime",
        "release_evidence": False,
        "totals": {
            "corpora": len(corpora),
            "manifests_present": sum(1 for e in corpora if e.get("manifest_present")),
            "available": sum(1 for e in corpora if e.get("status") == "available"),
            "unavailable_with_reason": sum(
                1 for e in corpora if e.get("status") == "unavailable" and e.get("unavailable_reason_recorded")
            ),
            "corpora_with_issues": field_failures,
            "items": sum((e.get("items") or {}).get("items", 0) for e in corpora),
            "items_present": sum((e.get("items") or {}).get("present", 0) for e in corpora),
        },
        "corpora": corpora,
        "tier1_covered": sorted(covered, key=TIER1_CARDS.index),
        "tier1_gaps": [c for c in TIER1_CARDS if c not in covered],
    }
    report["passed"] = field_failures == 0
    return report, secrets


def _guard_output(output: Path, root: Path, runs: dict[str, list[Path]]) -> None:
    evidence: list[Path] = [root / cid for cid in CORPORA if (root / cid).exists()]
    for paths in runs.values():
        evidence.extend(paths)
    problem = output_evidence_problem(output, evidence)
    if problem is not None:
        raise SystemExit(f"refusing to write the report ({problem.code}): {problem.message}")


def _parse_runs(values: list[str] | None) -> dict[str, list[Path]]:
    runs: dict[str, list[Path]] = {}
    for value in values or []:
        cid, sep, path = value.partition("=")
        cid = cid.strip().upper()
        if not sep or cid not in CORPORA or not path.strip():
            raise SystemExit(f"--run expects Cn=PATH with n in 1..6: {value!r}")
        runs.setdefault(cid, []).append(Path(path.strip()))
    return runs


def _print_text(report: dict) -> None:
    t = report["totals"]
    print(
        f"corpus audit ({report['mode']}): manifests {t['manifests_present']}/{t['corpora']} · "
        f"available {t['available']} · unavailable-with-reason {t['unavailable_with_reason']} · "
        f"items present {t['items_present']}/{t['items']} -> {'PASS' if report['passed'] else 'FAIL'}"
    )
    for entry in report["corpora"]:
        rows = entry.get("tier1_rows")
        nonzero = sum(1 for c in entry.get("expected_tier1", []) if rows and rows.get(c, 0) > 0)
        print(
            f"  {entry['corpus']}: {entry.get('status')} · expected Tier 1 "
            f"{nonzero}/{len(entry.get('expected_tier1', []))} with rows · "
            f"issues {', '.join(entry['issues']) or 'none'}"
        )
    print(f"  Tier 1 gaps (no corpus with rows): {', '.join(report['tier1_gaps']) or 'none'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-root", type=Path, help=f"folder holding C1..C6 (default ${ENV_ROOT} or {DEFAULT_ROOT})")
    ap.add_argument("--full", action="store_true", help="re-hash every item with SHA-256 (default: size/mtime only)")
    ap.add_argument("--run", action="append", metavar="Cn=PATH", help="processed result folder for a corpus (repeatable)")
    ap.add_argument("--output", type=Path, help="write the report JSON here (never inside a corpus)")
    ap.add_argument("--check-summary", type=Path, action="append", metavar="FILE",
                    help="fail when a repository summary file holds identifier patterns")
    ap.add_argument("--strict-coverage", action="store_true", help="also fail on Tier 1 coverage gaps")
    ap.add_argument("--json", action="store_true", help="print the report JSON")
    args = ap.parse_args(argv)

    root = args.corpus_root or Path(os.environ.get(ENV_ROOT) or DEFAULT_ROOT)
    runs = _parse_runs(args.run)
    report, literals = audit(root, full=args.full, runs=runs)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    hits = identifier_hits(text, literals)
    if hits:
        print(f"identifier patterns in the audit report: {hits}", file=sys.stderr)
        return 2

    code = 0 if report["passed"] else 1
    if args.strict_coverage and (report["tier1_gaps"] or any(e.get("coverage_gaps") for e in report["corpora"])):
        code = 1
    for summary in args.check_summary or []:
        summary_hits = identifier_hits(summary.read_text(encoding="utf-8"), literals)
        if summary_hits:
            print(f"identifier patterns in summary {summary.name}: {summary_hits}", file=sys.stderr)
            return 2
    if args.output:
        _guard_output(args.output, root, runs)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    if args.json:
        print(text, end="")
    else:
        _print_text(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
