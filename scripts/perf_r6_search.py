#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/perf-r6.py search --run <run output dir> [--index <rapidtriage-search.db>]
#          [--query 계약 --query LiveUpdate ...] [--repeat 5] [--compare] [--output <report.json>]
#   python scripts/perf-r6.py search --base http://127.0.0.1:8881 --token <token> --run-id <id>
#          [--query ...] [--repeat 5] [--output <report.json>]
#   (scripts/perf-r6.py dispatches `search` / `--search` here; running this file directly works too.)
#
# R7 P2: the console's global search, v1 (`GET /api/runs/{id}/search`, case-DB FTS or scan) against
# v2 (`POST /api/runs/{id}/search/query` with `keywords`, the search index). Engineering
# measurement only -- not a unit test, not CI.
#
#   * --run: in-process, read-only. v1 = run_unified_search with the route's console defaults
#     (limit 250, compact metadata, no OCR/analysis/detail); v2 = run_query over --index (default
#     <run>/rapidtriage-search.db; build one into a scratch path with
#     `build_search_index(run, summary, index_path=<scratch>)` -- never into the run folder) and the
#     same v1-hit conversion as the route (search_index.hits). "cold" is the first call of the
#     process, "warm" the median of --repeat further calls; "bytes" is the JSON payload size.
#     --compare also collects every hit of both (no time budget) and reports the symmetric difference
#     by review locator (collection, kind, pointer), grouped by source with sampled reasons.
#     The run folder listing (path, size, mtime) is compared before / after: any change fails (exit 1).
#   * --base: the same two requests over HTTP against a running server (cold = first request).
#   Default queries: 계약, LiveUpdate, "LiveUpdate 계약" (two keywords), 계약 in Unicode NFD, zzqxnotfound.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")

import argparse
import json
import sqlite3
import statistics
import sys
import time
import unicodedata
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from perf_r6_common import folder_snapshot, snapshot_changes

PAGE = 250
DEFAULT_QUERIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("계약", ("계약",)),
    ("LiveUpdate", ("LiveUpdate",)),
    ("LiveUpdate+계약", ("LiveUpdate", "계약")),
    ("계약(NFD)", (unicodedata.normalize("NFD", "계약"),)),
    ("zzqxnotfound", ("zzqxnotfound",)),
)


def _json_bytes(payload: object) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))


def _time(call: Callable[[], dict[str, object]]) -> tuple[float, dict[str, object]]:
    started = time.perf_counter()
    payload = call()
    return (time.perf_counter() - started) * 1000, payload


def measure(label: str, call: Callable[[], dict[str, object]], repeat: int, count: Callable[[dict[str, object]], object]) -> dict[str, object]:
    cold_ms, payload = _time(call)
    warm = [_time(call)[0] for _ in range(repeat)]
    return {
        "label": label,
        "cold_ms": round(cold_ms, 1),
        "warm_ms": round(statistics.median(warm), 1) if warm else None,
        "warm_min_ms": round(min(warm), 1) if warm else None,
        "warm_max_ms": round(max(warm), 1) if warm else None,
        "bytes": _json_bytes(payload),
        "mb": round(_json_bytes(payload) / 1_000_000, 3),
        "result": count(payload),
    }


# ---- in-process ------------------------------------------------------------------------------


class InProcess:
    def __init__(self, run: Path, index: Path | None) -> None:
        self.run = run
        self.summary = json.loads((run / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
        self.index = index
        self.meta: dict[str, object] | None = None
        if index is not None:
            from rapidtriage.core.search_index.build import read_index_meta

            self.meta, problem = read_index_meta(index)
            if self.meta is None:
                raise SystemExit(f"--index unreadable: {problem or 'no index'}")
        self.run_id = str((self.meta or {}).get("run_id") or "")

    def v1(self, keywords: Sequence[str], *, limit: int = PAGE, offset: int = 0, budget: float | None = None) -> dict[str, object]:
        from rapidtriage.core.search import run_unified_search

        payload = run_unified_search(
            self.summary, list(keywords), include_ocr=False, limit=limit, offset=offset, detail=False,
            metadata="compact", include_analysis=False, search_mode="exact", scan_budget_seconds=budget,
        )
        for match in payload.get("matches") or []:
            if isinstance(match, dict) and isinstance(match.get("locator"), dict):
                match["locator"]["run_id"] = self.run_id
        return payload

    def v2(self, keywords: Sequence[str], *, cursor: str | None = None, limit: int = PAGE, offset: int = 0, budget: float = 15.0) -> dict[str, object]:
        from rapidtriage.core.search_index.engine import Budget, QueryRequest, run_query
        from rapidtriage.core.search_index.hits import (
            attach_console_hits,
            console_keywords,
            console_query,
        )

        assert self.index is not None and self.meta is not None
        words = console_keywords(keywords)
        request = QueryRequest(q=console_query(words), cursor=cursor, limit=limit, facets=False, aggregates=False, histogram=None)
        result = run_query(self.index, self.meta, request, budget=Budget(budget))
        result.pop("uses_review", None)
        return attach_console_hits(result, words, summary=self.summary, run_id=self.run_id, offset=offset)


def _v1_count(payload: Mapping[str, object]) -> dict[str, object]:
    pagination = payload.get("pagination") if isinstance(payload.get("pagination"), Mapping) else {}
    return {"returned": len(payload.get("matches") or []), "has_more": pagination.get("has_more"), "total": pagination.get("total"), "backend": payload.get("backend"), "truncated": payload.get("truncated")}


def _v2_count(payload: Mapping[str, object]) -> dict[str, object]:
    page = payload.get("page") if isinstance(payload.get("page"), Mapping) else {}
    return {"returned": len(payload.get("matches") or []), "has_more": bool(page.get("next_cursor")), "truncated": payload.get("truncated"), "elapsed_ms": payload.get("elapsed_ms")}


def hit_key(hit: Mapping[str, object]) -> tuple[str, str, str]:
    locator = hit.get("locator") if isinstance(hit.get("locator"), Mapping) else None
    if locator is not None:
        return str(locator.get("collection") or ""), str(locator.get("kind") or ""), str(locator.get("pointer") or "")
    return str(hit.get("source") or ""), str(hit.get("kind") or ""), str(hit.get("pointer") or "")


def collect_v2(engine: InProcess, keywords: Sequence[str]) -> tuple[list[dict[str, object]], bool]:
    hits: list[dict[str, object]] = []
    cursor: str | None = None
    truncated = False
    while True:
        payload = engine.v2(keywords, cursor=cursor, limit=1000, offset=len(hits), budget=600.0)
        hits.extend(hit for hit in payload.get("matches") or [] if isinstance(hit, dict))
        truncated = truncated or bool(payload.get("truncated"))
        page = payload.get("page") if isinstance(payload.get("page"), Mapping) else {}
        cursor = page.get("next_cursor") if isinstance(page.get("next_cursor"), str) else None
        if not cursor:
            return hits, truncated


def _fold(text: str) -> str:
    return unicodedata.normalize("NFC", text).casefold()


def timeline_sources(engine: InProcess, pointers: Sequence[str]) -> dict[str, tuple[str, str, str] | None]:
    """``/events/<n>`` -> the event's source artifact row key (``details.source_record``), streamed once."""
    from rapidtriage.core.json_stream import iter_array_items

    wanted = {int(pointer.rsplit("/", 1)[-1]): pointer for pointer in pointers if pointer.rsplit("/", 1)[-1].isdigit()}
    found: dict[str, tuple[str, str, str] | None] = {pointer: None for pointer in pointers}
    outputs = engine.summary.get("outputs") if isinstance(engine.summary.get("outputs"), Mapping) else {}
    path = outputs.get("timeline") if isinstance(outputs, Mapping) else None
    if not wanted or not path:
        return found
    last = max(wanted)
    for position, event in enumerate(iter_array_items(Path(str(path)), "events")):
        if position > last:
            break
        if position not in wanted or not isinstance(event, dict):
            continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        source = details.get("source_record") if isinstance(details.get("source_record"), dict) else None
        if source and str(source.get("output") or "").startswith("artifacts_") and isinstance(source.get("row_index"), int):
            found[wanted[position]] = ("artifacts", str(source["output"]).removeprefix("artifacts_"), f"/artifacts/{source['row_index']}")
    return found


def explain(engine: InProcess, keywords: Sequence[str], key: tuple[str, str, str], side: str, timeline: Mapping[str, object] | None = None, v2_keys: set[tuple[str, str, str]] | None = None) -> str:
    """Why one hit is on one side only (best effort, from the index row)."""
    collection, kind, pointer = key
    if collection == "timeline":
        source = (timeline or {}).get(pointer)
        if source is None:
            return "timeline event without an artifact source record: v2 has no timeline collection"
        if v2_keys is not None and source in v2_keys:
            return "timeline event: v2 has no timeline collection; its source artifact row is a v2 hit"
        return "timeline event: v2 has no timeline collection; its source artifact row is NOT a v2 hit"
    if collection == "indicators" and pointer.startswith("/ioc_scanner_hits/"):
        return "IOC scanner hit: not indexed by v2"
    assert engine.index is not None
    connection = sqlite3.connect(f"{engine.index.resolve().as_uri()}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT text FROM search_doc WHERE collection = ? AND kind = ? AND locator = ? AND text IS NOT NULL LIMIT 1",
            (collection, kind, pointer),
        ).fetchone()
    finally:
        connection.close()
    words = [_fold(word) for word in keywords]
    if side == "v1":
        if row is None:
            return "row not in the v2 index"
        if not any(word in _fold(str(row[0] or "")) for word in words):
            return "keyword only outside the v2 row text (JSON key, envelope/profile member or a capped value v1 searches)"
        return "keyword in the v2 row text but not returned (unexpected)"
    text = _fold(str(row[0] or "")) if row is not None else ""
    if not any(word in text for word in words):
        return "unexplained"
    # The case-DB FTS backend of v1 finds whole words and word prefixes only; v1's scan backend
    # and v2 find any substring ("samsungprinterliveupdateinstaller" holds "liveupdate").
    if all(_inside_word(text, word) for word in words if word in text):
        return "keyword only inside a longer word: v1 case-DB FTS matches whole words/prefixes (v1 scan and v2 match substrings)"
    return "keyword in the v2 row text as a word, v1 did not return the row (unexpected)"


def _inside_word(text: str, word: str) -> bool:
    """Every occurrence of ``word`` in ``text`` starts after a letter or digit (not a token start)."""
    start = text.find(word)
    while start >= 0:
        if start == 0 or not text[start - 1].isalnum():
            return False
        start = text.find(word, start + 1)
    return True


def compare(engine: InProcess, label: str, keywords: Sequence[str]) -> dict[str, object]:
    started = time.perf_counter()
    v1_payload = engine.v1(keywords, limit=1_000_000, budget=0)
    v1_hits = [hit for hit in v1_payload.get("matches") or [] if isinstance(hit, dict)]
    v1_seconds = time.perf_counter() - started
    started = time.perf_counter()
    v2_hits, v2_truncated = collect_v2(engine, keywords)
    v2_seconds = time.perf_counter() - started
    v1_keys = {hit_key(hit) for hit in v1_hits}
    v2_keys = {hit_key(hit) for hit in v2_hits}
    only_v1 = sorted(v1_keys - v2_keys)
    only_v2 = sorted(v2_keys - v1_keys)
    words = [_fold(word) for word in keywords]
    reasons: dict[str, Counter[str]] = {"v1_only": Counter(), "v2_only": Counter()}
    samples: dict[str, list[dict[str, str]]] = {"v1_only": [], "v2_only": []}
    timeline = timeline_sources(engine, [key[2] for key in only_v1 if key[0] == "timeline"])
    for side, keys in (("v1", only_v1), ("v2", only_v2)):
        bucket = f"{side}_only"
        for key in keys:
            reason = explain(engine, words, key, side, timeline, v2_keys)
            reasons[bucket][f"{key[0]}: {reason}"] += 1
            if len(samples[bucket]) < 8:
                samples[bucket].append({"collection": key[0], "kind": key[1], "pointer": key[2], "reason": reason})
    shape_v1 = sorted(set().union(*(hit.keys() for hit in v1_hits))) if v1_hits else []
    shape_v2 = sorted(set().union(*(hit.keys() for hit in v2_hits))) if v2_hits else []
    # Same row in both: the fields the grid, viewer and review marks key on must agree.
    by_key_v2 = {hit_key(hit): hit for hit in v2_hits}
    field_mismatch: Counter[str] = Counter()
    mismatch_samples: list[dict[str, object]] = []
    for hit in v1_hits:
        other = by_key_v2.get(hit_key(hit))
        if other is None:
            continue
        for name in ("source", "kind", "pointer", "path", "display_path", "artifact_type"):
            if str(hit.get(name) or "") != str(other.get(name) or ""):
                field_mismatch[name] += 1
                if len(mismatch_samples) < 8:
                    mismatch_samples.append({"field": name, "v1": hit.get(name), "v2": other.get(name), "locator": list(hit_key(hit))})
    return {
        "label": label,
        "keywords": list(keywords),
        "v1": {"hits": len(v1_hits), "unique_locators": len(v1_keys), "by_collection": dict(Counter(key[0] for key in v1_keys)), "backend": v1_payload.get("backend"), "truncated": v1_payload.get("truncated"), "seconds": round(v1_seconds, 2)},
        "v2": {"hits": len(v2_hits), "unique_locators": len(v2_keys), "by_collection": dict(Counter(key[0] for key in v2_keys)), "truncated": v2_truncated, "seconds": round(v2_seconds, 2)},
        "common": len(v1_keys & v2_keys),
        "symmetric_difference": len(only_v1) + len(only_v2),
        "v1_only": len(only_v1),
        "v2_only": len(only_v2),
        "reasons": {bucket: dict(counter.most_common()) for bucket, counter in reasons.items()},
        "samples": samples,
        "hit_keys_v1_not_v2": [key for key in shape_v1 if key not in shape_v2],
        "hit_keys_v2_not_v1": [key for key in shape_v2 if key not in shape_v1],
        "common_field_mismatch": dict(field_mismatch),
        "common_field_mismatch_samples": mismatch_samples,
    }


def run_in_process(args: argparse.Namespace, queries: Sequence[tuple[str, tuple[str, ...]]]) -> dict[str, object]:
    run = Path(args.run)
    index = Path(args.index) if args.index else (run / "rapidtriage-search.db")
    before = folder_snapshot(run)
    engine = InProcess(run, index if index.is_file() else None)
    timings: list[dict[str, object]] = []
    for label, keywords in queries:
        timings.append(measure(f"v1 {label} page 1", lambda k=keywords: engine.v1(k), args.repeat, _v1_count))
        timings.append(measure(f"v1 {label} page 2", lambda k=keywords: engine.v1(k, offset=PAGE), args.repeat, _v1_count))
        if engine.index is not None:
            timings.append(measure(f"v2 {label} page 1", lambda k=keywords: engine.v2(k), args.repeat, _v2_count))
            first = engine.v2(keywords)
            cursor = (first.get("page") or {}).get("next_cursor") if isinstance(first.get("page"), dict) else None
            if cursor:
                timings.append(measure(f"v2 {label} page 2", lambda k=keywords, c=cursor: engine.v2(k, cursor=c, offset=PAGE), args.repeat, _v2_count))
        print(json.dumps(timings[-1], ensure_ascii=False), flush=True)
    comparisons = [compare(engine, label, keywords) for label, keywords in queries] if args.compare and engine.index is not None else []
    changes = snapshot_changes(before, folder_snapshot(run))
    return {"mode": "in-process", "run": str(run), "index": str(index) if engine.index else None, "timings": timings, "comparisons": comparisons, "run_folder_changes": changes}


# ---- HTTP ------------------------------------------------------------------------------------


def run_http(args: argparse.Namespace, queries: Sequence[tuple[str, tuple[str, ...]]]) -> dict[str, object]:
    from urllib.parse import quote, urlencode

    base = args.base.rstrip("/")
    headers = {"X-RapidTriage-Token": args.token} if args.token else {}

    def call(method: str, path: str, body: object | None = None) -> dict[str, object]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(base + path, data=data, method=method, headers={**headers, **({"Content-Type": "application/json"} if data else {})})
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read())

    run = f"/api/runs/{quote(args.run_id)}"
    timings: list[dict[str, object]] = []
    for label, keywords in queries:
        v1_path = f"{run}/search?" + urlencode([("keyword", word) for word in keywords] + [("limit", str(PAGE)), ("search_mode", "exact")])
        timings.append(measure(f"v1 {label} page 1", lambda p=v1_path: call("GET", p), args.repeat, _v1_count))
        timings.append(measure(f"v1 {label} page 2", lambda p=v1_path: call("GET", p + f"&offset={PAGE}"), args.repeat, _v1_count))
        body = {"keywords": list(keywords), "page": {"limit": PAGE}, "aggregates": False, "facets": False}
        try:
            first = call("POST", f"{run}/search/query", body)
        except urllib.error.HTTPError as exc:
            timings.append({"label": f"v2 {label}", "error": f"HTTP {exc.code}"})
            continue
        timings.append(measure(f"v2 {label} page 1", lambda b=body: call("POST", f"{run}/search/query", b), args.repeat, _v2_count))
        cursor = (first.get("page") or {}).get("next_cursor") if isinstance(first.get("page"), dict) else None
        if cursor:
            body2 = {**body, "page": {"limit": PAGE, "cursor": cursor, "offset": PAGE}}
            timings.append(measure(f"v2 {label} page 2", lambda b=body2: call("POST", f"{run}/search/query", b), args.repeat, _v2_count))
        print(json.dumps(timings[-1], ensure_ascii=False), flush=True)
    return {"mode": "http", "base": base, "run_id": args.run_id, "timings": timings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("search", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--search", dest="search_flag", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--run", help="run output folder (in-process, read-only)")
    parser.add_argument("--index", help="v2 index file (default <run>/rapidtriage-search.db)")
    parser.add_argument("--base", help="server base URL (HTTP mode)")
    parser.add_argument("--token", default="", help="API token (HTTP mode)")
    parser.add_argument("--run-id", default="", help="run id (HTTP mode)")
    parser.add_argument("--query", action="append", default=[], help="keywords separated by spaces (repeatable)")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--compare", action="store_true", help="v1/v2 result sets by locator (in-process)")
    parser.add_argument("--output", help="write the JSON report here")
    args = parser.parse_args(argv)
    queries = [(text, tuple(text.split())) for text in args.query] if args.query else list(DEFAULT_QUERIES)
    if bool(args.run) == bool(args.base):
        print("give exactly one of --run (in-process) or --base (HTTP)", file=sys.stderr)
        return 2
    report = run_in_process(args, queries) if args.run else run_http(args, queries)
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    changes = [str(item) for item in report.get("run_folder_changes") or []]  # type: ignore[union-attr]
    # Reading a WAL-mode case DB updates its existing -shm index (v1 reads it, as the server does);
    # anything else -- above all a new file -- fails the run.
    failing = [item for item in changes if not (item.startswith("~") and item.endswith(("-shm", "-wal")))]
    if changes:
        print("run folder changes: " + ", ".join(changes[:10]), file=sys.stderr)
    if failing:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
