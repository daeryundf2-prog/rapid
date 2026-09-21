#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   uv run scripts/carve-known-answer.py --output-dir <dir> --json
#
# Builds a deterministic synthetic carving corpus (planted files, truncated
# plants, false-signature plants, random filler), runs the bounded carving
# scanner, and reports per-kind TP/FP/FN, precision, recall, and
# false-positive rate against the planted ground truth.
#
# This is an ENGINEERING measurement on synthetic data. It is not release
# evidence and does not establish forensic accuracy on real media.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.carving import (
    STATUS_REJECTED,
    run_bounded_carving,
)

CORPUS_SEED = 20260921


def _jpeg(size: int) -> bytes:
    body = b"\xff\xd8\xff\xe0" + b"JFIF\x00" + bytes((i * 7) & 0xFF for i in range(size - 8))
    return body + b"\xff\xd9"


def _png(size: int) -> bytes:
    ihdr = b"\x00\x00\x00\x0dIHDR" + bytes((i * 3) & 0xFF for i in range(17))
    fill = bytes((i * 11) & 0xFF for i in range(max(0, size - 8 - len(ihdr) - 12)))
    return b"\x89PNG\r\n\x1a\n" + ihdr + fill + b"IEND\xaeB\x60\x82"


def _pdf(size: int) -> bytes:
    body = b"%PDF-1.7\n" + b"1 0 obj\n<<>>\nendobj\n" + bytes((i * 5) & 0xFF for i in range(size - 30))
    return body + b"%%EOF"


def _zip(size: int) -> bytes:
    # Local file header with method 0 (stored); no EOCD needed for detection.
    return b"PK\x03\x04" + b"\x14\x00\x00\x00\x00\x00" + bytes(size - 10)


def _sqlite(page_size: int, page_count: int) -> bytes:
    header = (
        b"SQLite format 3\x00"
        + page_size.to_bytes(2, "big")
        + b"\x02\x02"  # WAL write/read versions
        + b"\x00"  # reserved space
        + b"\x40\x20\x20"  # payload fractions
        + b"\x00\x00\x00\x01"  # change counter
        + page_count.to_bytes(4, "big")
    )
    return header + bytes(page_size * page_count - len(header))


def _gif(size: int) -> bytes:
    # GIF trailer is a single 0x3B byte; keep it out of the body so the
    # planted trailer is the first occurrence (single-byte footers are an
    # inherent carving limitation and are exercised separately).
    body = bytes((i * 13) & 0xFF or 1 for i in range(size - 7))
    body = body.replace(b"\x3b", b"\x3c")
    return b"GIF89a" + body + b"\x3b"


def _7z(size: int) -> bytes:
    return b"7z\xbc\xaf\x27\x1c" + b"\x00" + bytes(size - 7)


def _rar(size: int) -> bytes:
    return b"Rar!\x1a\x07" + b"\x01\x00" + bytes(size - 8)


def build_corpus(corpus_dir: Path) -> list[dict[str, object]]:
    """Write a deterministic corpus; returns planted ground truth."""
    rng = random.Random(CORPUS_SEED)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    truth: list[dict[str, object]] = []

    blob = bytearray()

    def pad() -> None:
        blob.extend(rng.randbytes(rng.randint(512, 2048)))

    def plant(item_id: str, kind: str, payload: bytes, status: str) -> None:
        pad()
        offset = len(blob)
        blob.extend(payload)
        truth.append(
            {
                "item_id": item_id,
                "kind": kind,
                "offset": offset,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "expected_status": status,
            }
        )

    plant("jpeg-a", "jpeg", _jpeg(4096), "present")
    plant("png-a", "png", _png(2048), "present")
    plant("pdf-a", "pdf", _pdf(3000), "present")
    plant("zip-a", "zip", _zip(1500), "present")
    plant("sqlite-a", "sqlite", _sqlite(1024, 3), "present")
    plant("gif-a", "gif", _gif(800), "present")
    plant("7z-a", "7z", _7z(1200), "present")
    plant("rar-a", "rar", _rar(900), "present")
    plant("jpeg-b", "jpeg", _jpeg(6000), "present")
    plant("pdf-b", "pdf", _pdf(1200), "present")

    # Truncated plants: valid headers, no footer -> must be detected as
    # partial, not silently dropped.
    plant("jpeg-truncated", "jpeg", _jpeg(5000)[:-2], "partial")
    plant("pdf-truncated", "pdf", _pdf(2000)[:-5], "partial")

    # False-signature plants: magic bytes followed by structure that the
    # validators must reject.
    pad()
    off = len(blob)
    blob.extend(b"SQLite format 3\x00" + b"\xff\xff" + b"\x09\x09" + b"junk" * 8)
    truth.append({"item_id": "false-sqlite", "kind": "sqlite", "offset": off,
                  "size_bytes": 60, "sha256": "", "expected_status": "rejected"})
    pad()
    off = len(blob)
    blob.extend(b"\x89PNG\r\n\x1a\n" + b"NOTAVALIDIHDR!!" + rng.randbytes(64))
    truth.append({"item_id": "false-png", "kind": "png", "offset": off,
                  "size_bytes": 87, "sha256": "", "expected_status": "rejected"})
    pad()
    off = len(blob)
    blob.extend(b"PK\x03\x04" + b"\x99\x99\x99\x99\xff\xff" + rng.randbytes(48))
    truth.append({"item_id": "false-zip", "kind": "zip", "offset": off,
                  "size_bytes": 58, "sha256": "", "expected_status": "rejected"})
    pad()

    source = corpus_dir / "known-answer-blob.bin"
    source.write_bytes(bytes(blob))
    for item in truth:
        item["source_path"] = str(source)
    return truth


def measure(truth: list[dict[str, object]], entries: list[dict[str, object]]) -> dict[str, object]:
    by_offset: dict[int, list[dict[str, object]]] = {}
    for entry in entries:
        by_offset.setdefault(int(entry.get("offset") or -1), []).append(entry)

    tp = fp = fn = tn = 0
    per_item: list[dict[str, object]] = []
    for item in truth:
        found = [e for e in by_offset.get(int(item["offset"]), []) if e.get("kind") == item["kind"]]
        expected = str(item["expected_status"])
        entry = found[0] if found else None
        status = str(entry.get("status") or "") if entry else ""
        if expected == "rejected":
            # Correct behaviour: either no candidate or an auditable rejection row.
            ok = entry is None or status == STATUS_REJECTED
            if ok:
                tn += 1
            else:
                fp += 1
            per_item.append({**item, "observed_status": status or "absent", "correct": ok})
            continue
        if entry is None or status == STATUS_REJECTED:
            fn += 1
            per_item.append({**item, "observed_status": status or "absent", "correct": False})
            continue
        offset_ok = True
        boundary_ok = True
        if expected == "present" and str(entry.get("status")) in ("footer-validated", "length-field"):
            offset_ok = int(entry.get("end_offset") or -1) == int(item["offset"]) + int(item["size_bytes"])
            boundary_ok = str(entry.get("sha256") or "") == str(item["sha256"])
        correct = offset_ok and boundary_ok
        if correct:
            tp += 1
        else:
            fp += 1
        per_item.append(
            {
                **item,
                "observed_status": status,
                "observed_end_offset": entry.get("end_offset"),
                "observed_sha256": entry.get("sha256"),
                "correct": correct,
            }
        )

    planted_offsets = {int(item["offset"]) for item in truth}
    stray = [
        e for e in entries
        if int(e.get("offset") or -1) not in planted_offsets and e.get("status") != STATUS_REJECTED
    ]
    fp += len(stray)

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {
        "metrics": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "stray_candidates": len(stray),
            "precision": round(precision, 6) if precision is not None else None,
            "recall": round(recall, 6) if recall is not None else None,
            "false_positive_rate": round(fpr, 6) if fpr is not None else None,
        },
        "items": per_item,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--extract", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    output_dir = args.output_dir.expanduser().resolve()
    corpus_dir = output_dir / "corpus"
    truth = build_corpus(corpus_dir)
    payload = run_bounded_carving(corpus_dir, output_dir / "carve-out", extract=args.extract)
    result = measure(truth, payload.get("entries", []))

    report = {
        "schema_version": "carve-known-answer-report-v1",
        "corpus_seed": CORPUS_SEED,
        "corpus_dir": str(corpus_dir),
        "corpus_sha256": hashlib.sha256((corpus_dir / "known-answer-blob.bin").read_bytes()).hexdigest(),
        "planted_count": len(truth),
        "candidate_count": payload["summary"]["candidate_count"],
        "status_counts": payload["summary"]["status_counts"],
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Synthetic corpus measurement; does not establish accuracy on real media "
            "and is not release evidence."
        ),
        **result,
    }
    out_path = output_dir / "carve-known-answer-report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report["output"] = str(out_path)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        m = result["metrics"]
        print(
            f"precision={m['precision']} recall={m['recall']} "
            f"fpr={m['false_positive_rate']} tp={m['true_positives']} "
            f"fp={m['false_positives']} fn={m['false_negatives']} "
            f"-> {out_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
