"""R6 S2 console review fixes (plan r6-followups-2026-10-19 §7): timeline time zone of antivirus
rows, AhnLab inventory rows kept off the timeline, catalogue labels of the new detail keys and the
``volume-information`` row filter."""

from __future__ import annotations

import unittest

from fastapi import HTTPException

from rapidtriage.api.app.routes_analyses import ROW_SOURCES, parse_detail_filters
from rapidtriage.core.timeline import TimelineStats, iter_artifact_detail_events
from rapidtriage.core.triage_rules.catalog import DERIVE_IDS, load_catalog


def av_row(timezone: str) -> dict[str, object]:
    return {
        "av_product": "ahnlab-v3",
        "detected_at": "2026-05-01T03:04:05",
        "timestamp": "2026-05-01T03:04:05",
        "timestamp_kind": "event",
        "timestamp_timezone": timezone,
        "threat_name": "Trojan/Win.Test",
    }


class AvTimelineTimezoneTests(unittest.TestCase):
    def events(self, details: dict[str, object]) -> list[dict[str, object]]:
        return list(iter_artifact_detail_events("av-detection-log", details, stats=TimelineStats()))

    def test_row_timezone_wins_over_the_fixed_local_label(self) -> None:
        # AhnLab SQLite epoch cells are UTC: the mapped detected_at event is UTC, not local-unknown.
        events = self.events(av_row("UTC"))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["timezone"], "UTC")
        self.assertEqual(events[0]["field_path"], "details.detected_at")

    def test_local_text_log_rows_stay_local_unknown(self) -> None:
        self.assertEqual(self.events(av_row("local-unknown"))[0]["timezone"], "local-unknown")

    def test_row_without_timezone_keeps_the_field_default(self) -> None:
        details = av_row("")
        del details["timestamp_timezone"]
        self.assertEqual(self.events(details)[0]["timezone"], "local-unknown")

    def test_av_product_presence_is_excluded_not_unmapped(self) -> None:
        stats = TimelineStats()
        details = {"presence_kind": "log-candidate", "timestamp": "", "source_file_mtime": "2026-05-01T00:00:00Z"}
        self.assertEqual(list(iter_artifact_detail_events("av-product-presence", details, stats=stats)), [])
        self.assertEqual(stats.unmapped_types.get("av-product-presence", 0), 0)
        self.assertEqual(stats.excluded_types["av-product-presence"], 1)


def family(catalog, family_id: str) -> dict[str, object]:
    return next(item for item in catalog.families if item["id"] == family_id)


def columns(item: dict[str, object]) -> dict[str, dict[str, object]]:
    return {column["key"]: column for column in [*item["core_columns"], *(item.get("aux_columns") or [])]}


class CatalogueLabelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()

    def test_av_detection_columns(self) -> None:
        cols = columns(family(self.catalog, "av-detection-log"))
        self.assertEqual(cols["detected_at"]["label"], "탐지 시각")  # McAfee local, AhnLab DB UTC: neutral
        self.assertEqual(cols["action_label"]["derive"], "av_action")
        self.assertIn("av_action", DERIVE_IDS)
        self.assertEqual(cols["schema_confidence"]["value_labels"]["heuristic-sqlite"], "DB 표·열 이름 추정(형식 미확인)")
        self.assertEqual(cols["parse_status"]["value_labels"]["error"], "해석 오류")
        self.assertIn("parse_error", cols)

    def test_av_presence_columns(self) -> None:
        item = family(self.catalog, "av-product-presence")
        core = [column["key"] for column in item["core_columns"]]
        self.assertEqual(core[core.index("parse_outcome") + 1], "parse_error")  # an error row shows its reason
        cols = columns(item)
        self.assertIn("true", cols["count_truncated"]["value_labels"])
        self.assertIn("true", cols["walk_truncated"]["value_labels"])

    def test_carved_url_and_backup_member_columns(self) -> None:
        url = columns(family(self.catalog, "carved-url-candidate"))
        self.assertEqual(url["cluster"]["label"], "클러스터 번호(NTFS)")
        self.assertEqual(url["partition_start_sector"]["label"], "파티션 시작 섹터")
        member = columns(family(self.catalog, "android-backup-member"))
        self.assertEqual(member["inner_path"]["label"], "해제 사본(증거 아님)")
        self.assertEqual(
            set(member["inner_extract_skipped_reason"]["value_labels"]),
            {"size", "count", "total", "unsafe-name", "name-collision", "cap"},
        )
        self.assertEqual(set(member["inner_extract_skipped"]["value_labels"]), {"cap", "unsafe-name", "name-collision"})


class VolumeInformationFilterTests(unittest.TestCase):
    def test_volume_information_is_a_row_source(self) -> None:
        self.assertIn("volume-information", ROW_SOURCES)
        self.assertEqual(parse_detail_filters(["volume-information"], [], []), {"source": frozenset({"volume-information"})})
        with self.assertRaises(HTTPException):
            parse_detail_filters(["volume-info"], [], [])


if __name__ == "__main__":
    unittest.main()
