from __future__ import annotations

import unittest

from rapidtriage.api.app.timeline_hist import (
    build_timeline_histogram,
    choose_bucket_seconds,
    parse_event_timestamp,
)


class TimelineHistogramTests(unittest.TestCase):
    def test_parse_event_timestamp_handles_iso_variants(self) -> None:
        self.assertEqual(
            parse_event_timestamp("2024-01-01T10:00:00Z").isoformat(),
            "2024-01-01T10:00:00+00:00",
        )
        self.assertEqual(
            parse_event_timestamp("2024-01-01 10:00:00").isoformat(),
            "2024-01-01T10:00:00+00:00",
        )
        self.assertIsNone(parse_event_timestamp("not-a-date"))
        self.assertIsNone(parse_event_timestamp(None))
        self.assertIsNone(parse_event_timestamp(""))

    def test_choose_bucket_seconds_stays_bounded(self) -> None:
        self.assertEqual(choose_bucket_seconds(0), 3600)
        self.assertLessEqual(choose_bucket_seconds(3600), 3600)
        # Year-scale spans get large buckets.
        self.assertGreaterEqual(choose_bucket_seconds(365 * 86400), 86400)

    def test_histogram_buckets_by_time_and_source(self) -> None:
        payload = {
            "events": [
                {"timestamp": "2024-01-01T10:00:00Z", "source": "files"},
                {"timestamp": "2024-01-01T10:30:00Z", "source": "files"},
                {"timestamp": "2024-01-01T12:00:00Z", "source": "evtx"},
                {"timestamp": "bad", "source": "files"},
            ]
        }
        result = build_timeline_histogram(payload)

        self.assertEqual(result["total_events"], 4)
        self.assertEqual(result["parsed_events"], 3)
        self.assertEqual(result["unparsed_events"], 1)
        self.assertGreater(result["bucket_count"], 0)
        self.assertEqual(sum(b["count"] for b in result["buckets"]), 3)
        sources = {item["name"] for item in result["sources"]}
        self.assertEqual(sources, {"files", "evtx"})
        per_source = sum(
            sum(b["by_source"].values()) for b in result["buckets"]
        )
        self.assertEqual(per_source, 3)
        self.assertEqual(result["max_bucket_count"], max(b["count"] for b in result["buckets"]))

    def test_out_of_range_timestamps_are_excluded(self) -> None:
        payload = {
            "events": [
                {"timestamp": "1628-03-01T00:00:00Z", "source": "lnk"},
                {"timestamp": "9999-12-31T23:59:59Z", "source": "lnk"},
                {"timestamp": "2024-01-01T10:00:00Z", "source": "files"},
                {"timestamp": "2024-06-01T10:00:00Z", "source": "files"},
            ]
        }
        result = build_timeline_histogram(payload)
        self.assertEqual(result["out_of_range_count"], 2)
        self.assertTrue(result["out_of_range_min"].startswith("1628"))
        self.assertTrue(result["out_of_range_max"].startswith("9999"))
        self.assertEqual(result["parsed_events"], 2)
        self.assertEqual(sum(b["count"] for b in result["buckets"]), 2)
        self.assertLessEqual(result["bucket_count"], 2000)

    def test_only_out_of_range_returns_empty_with_count(self) -> None:
        result = build_timeline_histogram({"events": [{"timestamp": "1628-03-01T00:00:00Z"}]})
        self.assertEqual(result["out_of_range_count"], 1)
        self.assertEqual(result["buckets"], [])

    def test_empty_timeline_returns_empty_profile(self) -> None:
        result = build_timeline_histogram({"events": []})
        self.assertEqual(result["parsed_events"], 0)
        self.assertEqual(result["buckets"], [])
        self.assertIsNone(result["bucket_seconds"])

    def test_non_mapping_events_are_counted_unparsed(self) -> None:
        result = build_timeline_histogram({"events": ["x", 1, {"timestamp": "2024-01-01T00:00:00Z"}]})
        self.assertEqual(result["unparsed_events"], 2)
        self.assertEqual(result["parsed_events"], 1)


if __name__ == "__main__":
    unittest.main()
