"""Row conditions of ``GET /artifacts`` · ``/files`` · ``/timeline`` (plan r4 §2.3 V3 필터):
relative time bounds, 요일·업무 외 시간 (time zone aware), 부분 결과, 콘텐츠 유형, 좌표 상자 —
their composition with channel / browser / flag / category filters and the Korean 422s."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_sort, create_app, tree
    from rapidtriage.api.app.row_conditions import (
        parse_row_conditions,
        row_content_types,
        row_coordinates,
        row_is_partial,
        row_time,
    )

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.triage_rules.stage import run_triage_stage

TOKEN = "row-conditions-test-token"
HANGUL = range(0xAC00, 0xD7A4)


def event(timestamp: str | None, channel: str, event_id: str = "4624", **details: object) -> dict[str, object]:
    body: dict[str, object] = {"event_id": event_id, "channel": channel, "provider": "Microsoft-Windows-Security-Auditing", **details}
    if timestamp:
        body["timestamp"] = timestamp
    return {"artifact_type": "eventlog-event", "path": rf"C:\Windows\System32\winevt\Logs\{channel}.evtx", "details": body}


# UTC instants and their Asia/Seoul (+09:00) wall clock:
EVENTS = [
    event("2025-05-26T01:00:00Z", "Security"),  # 0: Mon 10:00 KST — 업무 시간
    event("2025-05-26T10:30:00Z", "Security", parser_error=True),  # 1: Mon 19:30 KST — 업무 외, 부분 결과
    event("2025-05-31T02:00:00Z", "System"),  # 2: Sat 11:00 KST — 주말
    event("2025-05-27T23:30:00Z", "System"),  # 3: Wed 08:30 KST — 업무 외(이른 아침)
    event(None, "Security"),  # 4: no time
    event("2025-05-28T12:00:00Z", "Security", event_id="1102"),  # 5: Wed 21:00 KST — 로그 삭제(특이사항 A)
]
BROWSER = [
    {"artifact_type": "browser-history", "path": r"C:\Users\a\Chrome\History", "details": {"browser": "chrome", "timestamp": "2025-05-26T11:00:00Z"}},  # Mon 20:00 KST
    {"artifact_type": "browser-history", "path": r"C:\Users\a\Chrome\History", "details": {"browser": "chrome", "timestamp": "2025-05-26T02:00:00Z"}},  # Mon 11:00
    {"artifact_type": "browser-history", "path": r"C:\Users\a\Edge\History", "details": {"browser": "edge", "timestamp": "2025-05-26T11:00:00Z"}},
    {"artifact_type": "browser-download", "path": r"C:\Users\a\Chrome\History", "details": {"browser": "chrome", "target_path": r"C:\Users\a\Downloads\setup.exe", "timestamp": "2025-05-26T03:00:00Z"}},
]
RECENT = [
    {"artifact_type": "recent-shortcut", "path": r"C:\Users\a\Recent\report.lnk", "details": {"target_path": r"C:\Users\a\Documents\report.docx"}},
    {"artifact_type": "recent-shortcut", "path": r"C:\Users\a\Recent\photo.lnk", "details": {"target_path": r"C:\Users\a\Pictures\photo.JPG"}},
    {"artifact_type": "recent-shortcut-invalid-content", "path": r"C:\Users\a\Recent\broken.lnk", "details": {}},
    {"artifact_type": "jumplist-entry", "path": r"C:\Users\a\Recent\x.automaticDestinations-ms", "details": {"target_path": r"D:\backup\all.7z", "parse_status": "truncated-item"}},
]
MEDIA = [
    {"artifact_type": "media-image", "path": r"C:\Users\a\Pictures\a.jpg", "details": {"gps_latitude": 37.4812384, "gps_longitude": 126.9497216}},
    {"artifact_type": "media-image", "path": r"C:\Users\a\Pictures\b.jpg", "details": {"exif_gps_profile": {"latitude": 37.4851, "longitude": 126.9411}}},
    {"artifact_type": "media-image", "path": r"C:\Users\a\Pictures\c.jpg", "details": {"gps_latitude": 35.1, "gps_longitude": 129.04}},
    {"artifact_type": "media-image", "path": r"C:\Users\a\Pictures\d.png", "details": {"gps_latitude": 0, "gps_longitude": 0}},
    {"artifact_type": "media-video", "path": r"C:\Users\a\Videos\v.mp4", "details": {}},
]
FILES = {
    "candidates": [
        {"path": r"C:\Users\a\Documents\r.docx", "name": "r.docx", "extension": ".docx", "categories": ["documents"], "fs_modified_at": "2025-05-31T03:00:00Z"},
        {"path": r"C:\Users\a\Pictures\p.jpg", "name": "p.jpg", "extension": ".jpg", "categories": ["images"], "modified_at": "2025-05-26T01:00:00Z"},
        {"path": r"C:\Users\a\x.zip", "name": "x.zip", "extension": ".zip", "categories": ["archives"], "modified_at": "2025-05-26T13:00:00Z", "modified_at_origin": "acquisition-copy"},
        {"path": r"C:\Users\a\v.mp4", "name": "v.mp4", "extension": ".mp4", "categories": ["other"], "modified_at": "2025-05-26T12:00:00Z"},
    ],
    "inventory": [{"path": r"C:\Windows\a.exe", "name": "a.exe", "extension": ".exe", "categories": ["executables"], "modified_at": "2025-05-25T12:00:00Z"}],
}
TIMELINE = {
    "events": [
        {"timestamp": "2025-05-26T01:00:00Z", "source": "artifacts", "event_type": "e0", "path": r"C:\x", "details": {"artifact_type": "recent-shortcut", "target_path": r"C:\a.docx"}},
        {"timestamp": "2025-05-26T10:30:00Z", "source": "artifacts", "event_type": "e1", "path": r"C:\x", "details": {"artifact_type": "prefetch-file"}},
        {"timestamp": "2025-05-31T02:00:00Z", "source": "artifacts", "event_type": "e2", "path": r"C:\x", "details": {"artifact_type": "eventlog-event", "event_data_truncated": True}},
        {"timestamp": None, "source": "artifacts", "event_type": "e3", "path": r"C:\x", "details": {}},
    ]
}


def counts(rows: list[dict[str, object]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[str(row["artifact_type"])] = out.get(str(row["artifact_type"]), 0) + 1
    return out


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RowConditionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        tree._FACET_CACHE.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = run_dir = base / "run"
        run_dir.mkdir()
        outputs: dict[str, dict[str, object]] = {}
        self.artifact_paths: dict[str, Path] = {}
        for kind, rows, jsonl in (("eventlog", EVENTS, True), ("browser", BROWSER, True), ("recent-files", RECENT, False), ("media-image", MEDIA, False)):
            payload: dict[str, object] = {"record_count": len(rows), "summary": {"artifact_count": len(rows), "artifact_type_counts": counts(rows)}}
            if jsonl:
                records = run_dir / f"{kind}.jsonl"
                records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                payload.update({"records_path": str(records), "artifacts": []})
            else:
                payload["artifacts"] = rows
            outputs[f"artifacts_{kind}"] = payload
        outputs["files"] = FILES
        outputs["timeline"] = TIMELINE
        summary_outputs: dict[str, str] = {}
        for name, payload in outputs.items():
            path = run_dir / f"{name}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            summary_outputs[name] = str(path)
            if name.startswith("artifacts_"):
                self.artifact_paths[name.removeprefix("artifacts_")] = path
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"artifacts": 19}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    # --- helpers -------------------------------------------------------------------------

    def call(self, endpoint: str, query: str, expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{endpoint}?{query}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def kind_indices(self, query: str, kind: str = "eventlog") -> list[int]:
        page = self.call("artifacts", f"kind={kind}&limit=50&{query}")["artifacts"][kind]
        return [row["record_index"] for row in page["artifacts"]]

    def cross(self, query: str) -> list[tuple[str, int]]:
        payload = self.call("artifacts", f"limit=50&{query}")
        return [(kind, index) for kind, index in payload["cross_kind"]["order"]]

    def korean_422(self, endpoint: str, query: str, fragment: str) -> None:
        detail = self.call(endpoint, query, expect=422)["detail"]
        self.assertIsInstance(detail, str)
        self.assertIn(fragment, detail)
        self.assertTrue(any(ord(char) in HANGUL for char in detail), detail)

    # --- artifacts -----------------------------------------------------------------------

    def test_offhours_is_time_zone_aware(self) -> None:
        self.assertEqual(self.kind_indices("offhours=1&tz=Asia/Seoul"), [1, 2, 3, 5])
        self.assertEqual(self.kind_indices("offhours=1&tz=%2B09:00"), [1, 2, 3, 5])
        # In UTC the same instants fall elsewhere: 01:00 / 10:30 / 02:00 / 23:30 / 12:00 → 01:00, Sat and 23:30.
        self.assertEqual(self.kind_indices("offhours=1&tz=UTC"), [0, 2, 3])
        page = self.call("artifacts", "kind=eventlog&limit=50&offhours=1&tz=Asia/Seoul")["artifacts"]["eventlog"]
        self.assertEqual(page["matched"], 4)
        self.assertEqual(page["pagination"]["conditions"], {"tz": "Asia/Seoul", "offhours": True})

    def test_weekday_and_hours(self) -> None:
        self.assertEqual(self.kind_indices("weekday=sat&tz=Asia/Seoul"), [2])
        self.assertEqual(self.kind_indices("weekday=mon,wed&tz=Asia/Seoul"), [0, 1, 3, 5])
        self.assertEqual(self.kind_indices("hours=18-09&tz=Asia/Seoul"), [1, 3, 5])
        self.assertEqual(self.kind_indices("weekday=mon&weekday=tue&hours=09-18&tz=Asia/Seoul"), [0])
        # 업무 외 시간 with custom hours (20-08) and days (sun): 19:30 Mon and 08:30 Wed no longer count.
        self.assertEqual(self.kind_indices("offhours=1&hours=20-08&weekday=sun&tz=Asia/Seoul"), [5])

    def test_time_bounds_compose_with_channel_and_flag(self) -> None:
        window = "from=2025-05-26T00:00:00Z&to=2025-05-28T23:59:59Z"
        self.assertEqual(self.kind_indices(window), [0, 1, 3, 5])
        self.assertEqual(self.kind_indices(f"{window}&channel=Security"), [0, 1, 5])
        self.assertEqual(self.kind_indices(f"{window}&channel=Security&offhours=1&tz=Asia/Seoul"), [1, 5])
        # Offset-less bounds are read in tz: 2025-05-26 09:00 KST = 00:00 UTC.
        self.assertEqual(self.kind_indices("from=2025-05-26T09:30&to=2025-05-26T20:00&tz=Asia/Seoul"), [0, 1])
        step = run_triage_stage(self.run_dir, artifact_outputs=self.artifact_paths)
        self.assertEqual(step["status"], "completed", step)
        self.assertEqual(self.kind_indices("flag=eventlog.log_cleared"), [5])
        self.assertEqual(self.kind_indices("flag=eventlog.log_cleared&offhours=1&tz=Asia/Seoul"), [5])
        self.assertEqual(self.kind_indices("flag=eventlog.log_cleared&weekday=mon&tz=Asia/Seoul"), [])

    def test_browser_field_and_cross_kind_composition(self) -> None:
        self.assertEqual(self.kind_indices("browser=chrome&offhours=1&tz=Asia/Seoul", kind="browser"), [0])
        # No kind: the conditions page across kinds like artifact_type does.
        order = self.cross("offhours=1&tz=Asia/Seoul")
        self.assertEqual(order, [("browser", 0), ("browser", 2), ("eventlog", 1), ("eventlog", 2), ("eventlog", 3), ("eventlog", 5)])
        payload = self.call("artifacts", "limit=50&offhours=1&tz=Asia/Seoul")
        self.assertEqual(payload["cross_kind"]["conditions"]["offhours"], True)
        self.assertEqual(payload["cross_kind"]["matched"], 6)

    def test_partial_results(self) -> None:
        order = self.cross("partial=1")
        self.assertEqual(sorted(order), [("eventlog", 1), ("recent-files", 2), ("recent-files", 3)])

    def test_content_types(self) -> None:
        self.assertEqual(sorted(self.cross("content=document")), [("recent-files", 0)])
        self.assertEqual(
            sorted(self.cross("content=image")),
            [("media-image", 0), ("media-image", 1), ("media-image", 2), ("media-image", 3), ("recent-files", 1)],
        )
        self.assertEqual(sorted(self.cross("content=executable")), [("browser", 3)])
        self.assertEqual(sorted(self.cross("content=video")), [("media-image", 4)])
        self.assertEqual(sorted(self.cross("content=archive&content=video")), [("media-image", 4), ("recent-files", 3)])
        self.assertEqual(sorted(self.cross("content=document,executable")), [("browser", 3), ("recent-files", 0)])
        # Eventlog rows point at .evtx files: no content type.
        self.assertEqual(self.kind_indices("content=document,image,video,audio,archive,executable,database,mail"), [])

    def test_geo_box(self) -> None:
        self.assertEqual(self.kind_indices("geo=37.48,126.94,37.49,126.95", kind="media-image"), [0, 1])
        self.assertEqual(self.kind_indices("geo=-90,-180,90,180", kind="media-image"), [0, 1, 2])

    def test_sorted_kind_is_narrowed(self) -> None:
        query = "kind=eventlog&limit=50&sort=timestamp&order=desc&offhours=1&tz=Asia/Seoul"
        deadline = time.monotonic() + 10
        while True:
            page = self.call("artifacts", query)["artifacts"]["eventlog"]
            if page.get("sort", {}).get("status") != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [2, 5, 3, 1])
        self.assertEqual(page["pagination"]["conditions"]["offhours"], True)

    def test_korean_422s_and_limit(self) -> None:
        self.korean_422("artifacts", "limit=10&weekday=funday", "weekday")
        self.korean_422("artifacts", "limit=10&hours=25-03", "hours")
        self.korean_422("artifacts", "limit=10&hours=9-9", "hours")
        self.korean_422("artifacts", "limit=10&hours=evening", "hours")
        self.korean_422("artifacts", "limit=10&offhours=1&tz=Mars/Olympus", "tz")
        self.korean_422("artifacts", "limit=10&tz=%2B15:00&offhours=1", "tz")
        self.korean_422("artifacts", "limit=10&from=yesterday", "from")
        self.korean_422("artifacts", "limit=10&from=2025-06-01T00:00:00Z&to=2025-05-01T00:00:00Z", "from")
        self.korean_422("artifacts", "limit=10&content=movie", "content")
        self.korean_422("artifacts", "limit=10&offhours=maybe", "offhours")
        self.korean_422("artifacts", "limit=10&partial=2", "partial")
        self.korean_422("artifacts", "limit=10&geo=1,2,3", "geo")
        self.korean_422("artifacts", "limit=10&geo=50,0,10,0", "geo")
        self.korean_422("files", "limit=10&weekday=xyz", "weekday")
        self.korean_422("timeline", "limit=10&hours=1", "hours")
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/artifacts?offhours=1").status_code, 400)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/timeline?partial=1").status_code, 400)
        # tz alone is no condition (the plain listing).
        self.assertNotIn("cross_kind", self.call("artifacts", "limit=5&tz=Asia/Seoul"))

    # --- files ---------------------------------------------------------------------------

    def test_files_conditions(self) -> None:
        def paths(query: str, scope: str = "candidates") -> list[str]:
            page = self.call("files", f"limit=50&scope={scope}&{query}")
            return [row["name"] for row in page[scope]]

        self.assertEqual(paths("content=document"), ["r.docx"])
        self.assertEqual(paths("content=image,archive"), ["p.jpg", "x.zip"])
        self.assertEqual(paths("content=video"), ["v.mp4"])
        self.assertEqual(paths("content=executable", scope="inventory"), ["a.exe"])
        # Row time: fs_modified_at, else modified_at; an acquisition copy without an NTFS join has none.
        self.assertEqual(paths("from=2025-05-26T00:00:00Z&to=2025-05-31T23:59:59Z"), ["r.docx", "p.jpg", "v.mp4"])
        self.assertEqual(paths("offhours=1&tz=Asia/Seoul"), ["r.docx", "v.mp4"])
        self.assertEqual(paths("category=images&content=image&weekday=mon&tz=Asia/Seoul"), ["p.jpg"])
        page = self.call("files", "limit=1&content=image,archive")
        self.assertEqual((page["matched"], page["pagination"]["has_more"]), (2, True))
        self.assertEqual(page["candidates"][0]["record_index"], 1)
        self.assertEqual(page["pagination"]["conditions"]["content"], ["archive", "image"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files?content=image").status_code, 400)

    # --- timeline ------------------------------------------------------------------------

    def test_timeline_conditions(self) -> None:
        page = self.call("timeline", "limit=50&offhours=1&tz=Asia/Seoul")
        self.assertEqual([event["event_type"] for event in page["events"]], ["e1", "e2"])
        self.assertEqual([event["record_index"] for event in page["events"]], [1, 2])
        self.assertEqual((page["matched"], page["record_count"]), (2, 4))
        self.assertEqual([e["event_type"] for e in self.call("timeline", "limit=50&partial=1")["events"]], ["e2"])
        self.assertEqual([e["event_type"] for e in self.call("timeline", "limit=50&content=document")["events"]], ["e0"])
        self.assertEqual([e["event_type"] for e in self.call("timeline", "limit=50&content=executable")["events"]], ["e1"])
        paged = self.call("timeline", "limit=1&offset=1&from=2025-05-26T00:00:00Z")
        self.assertEqual([e["event_type"] for e in paged["events"]], ["e1"])
        self.assertTrue(paged["pagination"]["has_more"])
        # Without a condition the listing is unchanged (no record_index added).
        self.assertNotIn("record_index", self.call("timeline", "limit=2")["events"][0])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RowConditionUnitTests(unittest.TestCase):
    def test_row_time_per_collection(self) -> None:
        self.assertEqual(row_time({"details": {"time_created": "2025-01-01T00:00:00.1234567Z"}}, "artifacts").year, 2025)
        self.assertIsNone(row_time({"details": {"timestamp": {"x": 1}}}, "artifacts"))
        copy = {"modified_at": "2025-01-01T00:00:00Z", "modified_at_origin": "acquisition-copy"}
        self.assertIsNone(row_time(copy, "files"))
        self.assertEqual(row_time({**copy, "ntfs": {"si_modified_at": "2020-02-02T00:00:00Z"}}, "files").year, 2020)
        self.assertEqual(row_time({"fs_modified_at": "2019-01-01 10:00:00", **copy}, "files").year, 2019)
        self.assertEqual(row_time({"timestamp": 0}, "timeline").year, 1970)

    def test_partial_and_coordinates(self) -> None:
        self.assertTrue(row_is_partial({"details": {"decrypt_status": "candidate-keys-tried-sqlite-header-not-found"}}))
        self.assertFalse(row_is_partial({"details": {"decrypt_status": "success", "parse_status": "parsed"}}))
        self.assertTrue(row_is_partial({"details": {"coverage": {"status": "partial"}}}))
        self.assertTrue(row_is_partial({"artifact_type": "media-image-unreadable"}))
        self.assertEqual(row_coordinates({"details": {"latitude": "37.5", "longitude": "127"}}), (37.5, 127.0))
        self.assertIsNone(row_coordinates({"details": {"gps_latitude": 91, "gps_longitude": 0}}))
        self.assertEqual(row_content_types({"artifact_type": "email-message", "details": {}}, "artifacts"), {"mail"})

    def test_parse_returns_none_without_conditions(self) -> None:
        self.assertIsNone(parse_row_conditions(tz="Asia/Seoul"))
        conditions = parse_row_conditions(offhours=True, tz="+09:00")
        self.assertIsNotNone(conditions)
        self.assertEqual(conditions.describe(), {"tz": "+09:00", "offhours": True})


if __name__ == "__main__":
    unittest.main()
