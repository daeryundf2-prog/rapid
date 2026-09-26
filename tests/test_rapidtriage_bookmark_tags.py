from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.case import (
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)


def _apply(case_json: Path, **kwargs) -> dict[str, object]:
    payload = create_or_update_case_payload(case_json, **kwargs)
    save_case_payload(case_json, payload)
    return payload

TIMELINE_EVENT = {
    "timestamp": "2024-03-01T08:45:00+00:00",
    "source": "artifacts",
    "event_type": "browser-download",
    "path": "/cases/case-001/evidence.zip",
    "input_file": "/cases/case-001/artifacts.json",
    "summary": "Browser download: evidence.zip",
    "details": {},
}


def _timeline_payload() -> dict[str, object]:
    return {
        "command": "timeline",
        "generated_at": "2024-03-03T00:00:00+00:00",
        "root": "/cases/case-001",
        "inputs": {"files": [], "docs": [], "artifacts": []},
        "summary": {
            "input_file_count": 0,
            "event_count": 1,
            "source_counts": {"artifacts": 1},
            "event_type_counts": {"browser-download": 1},
            "earliest_event_at": "2024-03-01T08:45:00+00:00",
            "latest_event_at": "2024-03-01T08:45:00+00:00",
        },
        "events": [TIMELINE_EVENT],
    }


class BookmarkTagToggleTests(unittest.TestCase):
    def test_remove_tags_toggles_priority_tag_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case.json"
            timeline_json = root / "timeline.json"
            timeline_json.write_text(json.dumps(_timeline_payload()), encoding="utf-8")

            # Assign p1 + p3 priority tags.
            payload = _apply(
                case_json,
                case_id="case-001",
                title="Case",
                source_path=timeline_json,
                source_pointer="/events/0",
                tags=["p1", "p3"],
            )
            (bookmark,) = payload["bookmarks"]
            self.assertEqual(sorted(bookmark["tags"]), ["p1", "p3"])

            # Toggle p1 off via remove_tags while keeping p3.
            payload = _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                remove_tags=["p1"],
            )
            (bookmark,) = payload["bookmarks"]
            self.assertEqual(bookmark["tags"], ["p3"])
            # Removal is recorded in review history.
            history = bookmark["review_history"]
            self.assertTrue(any(entry.get("action") == "updated" for entry in history))

    def test_remove_tags_does_not_clear_other_tags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case.json"
            timeline_json = root / "timeline.json"
            timeline_json.write_text(json.dumps(_timeline_payload()), encoding="utf-8")

            _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                tags=["keep-me", "p5"],
            )
            payload = _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                remove_tags=["p5"],
            )
            (bookmark,) = payload["bookmarks"]
            self.assertEqual(bookmark["tags"], ["keep-me"])

    def test_add_and_remove_tags_in_same_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case.json"
            timeline_json = root / "timeline.json"
            timeline_json.write_text(json.dumps(_timeline_payload()), encoding="utf-8")

            _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                tags=["p1"],
            )
            payload = _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                tags=["p2"],
                remove_tags=["p1"],
            )
            (bookmark,) = payload["bookmarks"]
            self.assertEqual(bookmark["tags"], ["p2"])

    def test_case_persists_to_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case.json"
            timeline_json = root / "timeline.json"
            timeline_json.write_text(json.dumps(_timeline_payload()), encoding="utf-8")

            payload = _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                tags=["p4"],
            )
            case_json.write_text(json.dumps(payload), encoding="utf-8")
            payload = _apply(
                case_json,
                source_path=timeline_json,
                source_pointer="/events/0",
                remove_tags=["p4"],
            )
            (bookmark,) = payload["bookmarks"]
            self.assertEqual(bookmark["tags"], [])
            self.assertIsInstance(load_case_payload(case_json), dict)


if __name__ == "__main__":
    unittest.main()
