"""R6 단계 3 성능 측정 (plan docs/plans/r6-followups-2026-10-19.md §3.4).

One function per mode, chosen by flags (several may run in one call; the JSON report has one
block per mode):

* ``--geo`` -- 위치 행 색인 + 지도 묶음 (§3.3 갈래 C, Q-S3-6/7/8): ``GET /geo-clusters`` and the
  first map table page (``/artifacts?geo=…&limit=500`` across kinds) with the index file present,
  and the building path of a run without it (first request -> ``building`` -> ready).

Data: ``--synthetic`` writes a temporary run (``--artifacts`` rows over ``--kinds`` kinds,
``--located`` of them with coordinates); ``--run <dir>`` measures an existing run folder as it is
(the API may write ``rapidtriage-geo-index.json`` there, or keep it in memory when it cannot).

Times are medians of ``--repeat`` runs through FastAPI's ``TestClient`` (no server, no network).
Exit status 1 when a target is missed. Not part of CI (Antigravity request per §0).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

TOKEN = "perf-r6-token"
WORLD = "-90,-180,90,180"
# §3.1 / Q-S3-6 targets (seconds).
GEO_TARGETS = {"clusters_s": 0.5, "first_display_with_index_s": 2.0, "first_display_building_s": 10.0}


# --- shared helpers ------------------------------------------------------------------------------


def median_seconds(action: Callable[[], object], repeat: int, before: Callable[[], object] | None = None) -> float:
    samples = []
    for _ in range(repeat):
        if before is not None:
            before()
        started = time.perf_counter()
        action()
        samples.append(time.perf_counter() - started)
    return round(statistics.median(samples), 4)


def api_client(run_dir: Path):
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.core.jobs import RunJobStore

    store = RunJobStore()
    run_id = store.import_completed_run(run_dir).run_id
    client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
    return client, run_id


def get_json(client, url: str) -> dict[str, object]:
    response = client.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"{url}: {response.status_code} {response.text[:300]}")
    return response.json()


def synthetic_artifact_run(base: Path, *, rows: int, located: int, kinds: int) -> Path:
    """A run folder with ``rows`` artifact rows over ``kinds`` JSONL kinds, ``located`` with GPS."""
    run_dir = base / "run-perf"
    run_dir.mkdir(parents=True)
    per_kind = max(1, rows // kinds)
    every = max(1, (per_kind * kinds) // max(1, located))
    outputs: dict[str, str] = {}
    serial = 0
    placed = 0
    for number in range(kinds):
        kind = f"kind-{number:02d}"
        records = run_dir / f"{kind}.jsonl"
        with open(records, "w", encoding="utf-8", newline="\n") as handle:
            for index in range(per_kind):
                details: dict[str, object] = {
                    "timestamp": f"2025-05-{1 + serial % 28:02d}T{serial % 24:02d}:00:00Z",
                    "platform": "windows translate related latest",
                    "value": f"row {serial} of {kind}",
                }
                if serial % every == 0 and placed < located:
                    details["gps_latitude"] = 37.0 + (placed % 400) * 0.01
                    details["gps_longitude"] = 126.0 + (placed // 400) * 0.01
                    placed += 1
                row = {"artifact_type": f"type-{number}", "path": rf"C:\evidence\{kind}\{index}.bin", "details": details}
                handle.write(json.dumps(row) + "\n")
                serial += 1
        payload = {"record_count": per_kind, "records_path": str(records), "artifacts": [], "summary": {"artifact_count": per_kind}}
        path = run_dir / f"artifacts_{kind}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        outputs[f"artifacts_{kind}"] = str(path)
    summary_path = run_dir / "rapidtriage-run-summary.json"
    outputs["summary"] = str(summary_path)
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(base / "evidence"),
                "output_dir": str(run_dir),
                "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                "outputs": outputs,
                "summary": {"counts": {"artifacts": per_kind * kinds}},
            }
        ),
        encoding="utf-8",
    )
    return run_dir


# --- --geo ----------------------------------------------------------------------------------------


def _geo_sources(run_dir: Path):
    summary = json.loads((run_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
    sources = []
    for name, raw in sorted(summary["outputs"].items()):
        if name.startswith("artifacts_"):
            path = Path(raw)
            sources.append((name.removeprefix("artifacts_"), json.loads(path.read_text(encoding="utf-8")), path))
    return sources


def measure_geo(run_dir: Path, *, repeat: int, synthetic: bool) -> dict[str, object]:
    from rapidtriage.api.app import geo_index
    from rapidtriage.api.app.artifact_filter import filter_across_kinds
    from rapidtriage.api.app.row_conditions import parse_row_conditions

    client, run_id = api_client(run_dir)
    service = geo_index.GEO_INDEX_SERVICE
    clusters_url = f"/api/runs/{run_id}/geo-clusters?cell=0.01&geo={WORLD}"
    page_url = f"/api/runs/{run_id}/artifacts?limit=500&geo={WORLD}"
    index_file = run_dir / geo_index.GEO_INDEX_FILE_NAME
    report: dict[str, object] = {"run_dir": str(run_dir), "repeat": repeat, "targets": GEO_TARGETS}
    sources = _geo_sources(run_dir)

    def first_display() -> None:
        get_json(client, clusters_url)
        get_json(client, page_url)

    def wait_ready() -> dict[str, object]:
        deadline = time.perf_counter() + 120
        while True:
            payload = get_json(client, clusters_url)
            if payload["geo_index"] != "building" or time.perf_counter() > deadline:
                return payload
            time.sleep(0.05)

    # Building path: no index file, empty cache (an older run on first map request).
    if synthetic:
        building_samples = []
        statuses = []
        for _ in range(repeat):
            index_file.unlink(missing_ok=True)
            service.clear()
            started = time.perf_counter()
            statuses.append(get_json(client, clusters_url)["geo_index"])
            wait_ready()
            get_json(client, page_url)
            building_samples.append(time.perf_counter() - started)
        report["first_display_building_s"] = round(statistics.median(building_samples), 4)
        report["first_request_status"] = statuses
    else:
        started = time.perf_counter()
        report["first_request_status"] = [get_json(client, clusters_url)["geo_index"]]
        wait_ready()
        get_json(client, page_url)
        report["first_display_as_found_s"] = round(time.perf_counter() - started, 4)

    # Index path: the file written at run completion (persist step) and a fresh server cache.
    if synthetic:
        index_file.unlink(missing_ok=True)
        persist = geo_index.write_run_geo_index(run_dir, sources)
        report["persist_step"] = persist
    report["first_display_with_index_s"] = median_seconds(first_display, repeat, before=service.clear)
    ready = wait_ready()
    report["clusters_s"] = median_seconds(lambda: get_json(client, clusters_url), repeat)
    report["clusters_cold_s"] = median_seconds(lambda: get_json(client, clusters_url), repeat, before=service.clear)
    report["first_page_s"] = median_seconds(lambda: get_json(client, page_url), repeat)
    report["geo_index_source"] = ready.get("geo_index_source")
    report["located_total"] = ready.get("located_total")
    report["clusters_total"] = ready.get("clusters_total")
    report["index_file_bytes"] = index_file.stat().st_size if index_file.is_file() else None

    # Equivalence (Q-S3-7): the index path's located rows = the full scan's.
    if synthetic:
        indexed: list[tuple[str, int]] = []
        after = None
        while True:
            url = f"/api/runs/{run_id}/artifacts?limit=1000&geo={WORLD}" + (f"&after={after}" if after else "")
            cross = get_json(client, url)["cross_kind"]
            indexed.extend((kind, index) for kind, index in cross["order"])
            after = cross.get("next_after")
            if not after:
                break
        conditions = parse_row_conditions(geo=WORLD)
        scanned = filter_across_kinds(
            sources,
            path_contains=None,
            artifact_types=None,
            offset=0,
            limit=10_000_000,
            scan_cap=10_000_000,
            row_filter=conditions.predicate("artifacts") if conditions else None,
        )["cross_kind"]["order"]
        report["equivalent"] = indexed == [(kind, index) for kind, index in scanned]
        report["indexed_rows"] = len(indexed)

        # Read-only output folder (Q-S3-8): memory index, no 500.
        index_file.unlink(missing_ok=True)
        service.clear()
        with mock.patch.object(geo_index, "write_geo_index_file", side_effect=PermissionError("read-only")):
            payload = wait_ready()
            get_json(client, page_url)
        report["read_only_source"] = payload.get("geo_index_source")

    checks = {
        "clusters_s": report["clusters_s"] <= GEO_TARGETS["clusters_s"],  # type: ignore[operator]
        "first_display_with_index_s": report["first_display_with_index_s"] <= GEO_TARGETS["first_display_with_index_s"],  # type: ignore[operator]
    }
    if "first_display_building_s" in report:
        checks["first_display_building_s"] = report["first_display_building_s"] <= GEO_TARGETS["first_display_building_s"]  # type: ignore[operator]
    if "equivalent" in report:
        checks["equivalent"] = bool(report["equivalent"])
        checks["read_only_memory"] = report.get("read_only_source") == "memory"
    report["checks"] = checks
    report["passed"] = all(checks.values())
    return report


# --- dispatch -----------------------------------------------------------------------------------


def run_geo(args: argparse.Namespace, workdir: Path) -> dict[str, object]:
    if args.run:
        return measure_geo(Path(args.run), repeat=args.repeat, synthetic=False)
    started = time.perf_counter()
    run_dir = synthetic_artifact_run(workdir, rows=args.artifacts, located=args.located, kinds=args.kinds)
    report = measure_geo(run_dir, repeat=args.repeat, synthetic=True)
    report["synthetic"] = {
        "artifacts": args.artifacts,
        "located": args.located,
        "kinds": args.kinds,
        "generate_s": round(time.perf_counter() - started, 2),
    }
    return report


MODES: dict[str, Callable[[argparse.Namespace, Path], dict[str, object]]] = {"geo": run_geo}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--geo", action="store_true", help="위치 행 색인 + 지도 묶음 (갈래 C)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--synthetic", action="store_true", help="임시 합성 런으로 측정(기본)")
    source.add_argument("--run", help="기존 런 출력 폴더로 측정")
    parser.add_argument("--artifacts", type=int, default=640_000, help="합성 아티팩트 행 수")
    parser.add_argument("--located", type=int, default=2_000, help="합성 위치 행 수")
    parser.add_argument("--kinds", type=int, default=8, help="합성 아티팩트 종류 수")
    parser.add_argument("--repeat", type=int, default=5, help="중앙값을 낼 반복 횟수")
    parser.add_argument("--output", help="JSON 보고서 경로(없으면 표준 출력)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    chosen = [name for name in MODES if getattr(args, name)]
    if not chosen:
        print("측정할 모드를 하나 이상 고르세요: " + ", ".join(f"--{name}" for name in MODES), file=sys.stderr)
        return 2
    report: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="perf-r6-") as temp:
        for name in chosen:
            workdir = Path(temp) / name
            workdir.mkdir()
            report[name] = MODES[name](args, workdir)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if all(block.get("passed", True) for block in report.values() if isinstance(block, dict)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
