"""R8 T-023: processing scope on four axes (``rapidtriage/api/app/run_scope.py``).

Synthetic summaries only (counts, no evidence identifiers). The IMG-B-like shape
mirrors the corrected R7 diagnosis: the allocated walk finished, the extraction
cap truncated deleted MFT records, unallocated space was never scanned.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app, run_scope
from rapidtriage.api.app.run_scope import build_run_scope, tally_mft_headers
from rapidtriage.core.jobs import RunJobStore

TOKEN = "r8-run-scope-token"
#: IMG-B-like extraction stats (counts only).
IMG_B_STATS = {
    "files": 200_000,
    "bytes": 1,
    "errors": 2_175,
    "depth_skips": 0,
    "truncated": 430_052,
    "deleted_files": 54_693,
    "deleted_read_errors": 2_170,
    "alias_skips": 41_937,
    "file_limit": 200_000,
}


def image_summary(stats: dict[str, int] | None, run_dir: Path, *, mft: Path | None = None) -> dict[str, Any]:
    manifest: dict[str, Any] = {"profile_version": "rapidtriage-recovered-root-manifest-v1"}
    if stats is not None:
        manifest["native_extraction_stats"] = stats
    if mft is not None:
        manifest["system_artifacts"] = {"mft": str(mft)}
    return {
        "output_dir": str(run_dir),
        "outputs": {},
        "source": {
            "type": "e01",
            "partition_start_sector": 2048,
            "partition_selection": {
                "selected_start_sector": 2048,
                "partition_count": 4,
                "supported_partition_count": 2,
            },
            "recovered_root_manifest": manifest,
        },
    }


def mft_record(*, in_use: bool, directory: bool = False, base: int = 0, record_size: int = 1024) -> bytes:
    record = bytearray(record_size)
    record[0:4] = b"FILE"
    record[22] = (0x01 if in_use else 0) | (0x02 if directory else 0)
    record[0x1C:0x20] = record_size.to_bytes(4, "little")
    record[32:38] = base.to_bytes(6, "little")
    return bytes(record)


def write_mft(path: Path, *, record_size: int = 1024) -> dict[str, int]:
    """Synthetic $MFT: 6 in-use files, 2 in-use dirs, 9 deleted files, 3 deleted dirs, 2 extension, 1 blank."""
    plan = (
        [mft_record(in_use=True, record_size=record_size)] * 6
        + [mft_record(in_use=True, directory=True, record_size=record_size)] * 2
        + [mft_record(in_use=False, record_size=record_size)] * 9
        + [mft_record(in_use=False, directory=True, record_size=record_size)] * 3
        + [mft_record(in_use=False, base=7, record_size=record_size)] * 2
        + [bytes(record_size)]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(plan))
    return {
        "records": 23,
        "invalid": 1,
        "extension_records": 2,
        "in_use_files": 6,
        "in_use_dirs": 2,
        "deleted_files": 9,
        "deleted_dirs": 3,
    }


def all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for item in value.values():
            keys |= all_keys(item)
        return keys
    if isinstance(value, list):
        return set().union(*(all_keys(item) for item in value)) if value else set()
    return set()


class RunScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"
        self.run_dir.mkdir()
        run_scope._mft_cache.clear()

    def test_img_b_shape_without_mft_copy(self) -> None:
        scope = build_run_scope(image_summary(IMG_B_STATS, self.run_dir), self.run_dir)
        self.assertEqual(scope["basis"], "inferred")
        self.assertEqual(scope["partitions"], {"total": 4, "supported": 2, "processed": 1})
        allocated = scope["allocated"]
        self.assertEqual(allocated["listed_pct"], 100.0)
        self.assertEqual(allocated["basis"], "inferred")
        self.assertEqual(allocated["copies"], 145_307)
        self.assertEqual(allocated["read_errors"], 5)
        # 145,307 / 145,312 floors to 99.9 — never rounded up to 100.
        self.assertEqual(allocated["content_pct"], 99.9)
        deleted = scope["deleted"]
        self.assertEqual(deleted["records_source"], "extraction_stats")
        self.assertEqual(deleted["records"], 54_693 + 2_170 + 430_052)
        self.assertEqual(deleted["attempted"], 56_863)
        self.assertEqual(deleted["not_attempted"], 430_052)
        self.assertAlmostEqual(deleted["attempted_pct"], 11.6, delta=0.05)
        self.assertLess(deleted["listed_pct"], deleted["attempted_pct"])
        self.assertIsNone(deleted["directories"])
        self.assertEqual(scope["unallocated"], {"scanned_pct": None, "measured": False})
        self.assertEqual(
            scope["caps"],
            [{"code": "native_extract_file_limit", "limit": 200_000, "reached": True, "skipped": 430_052, "axis": "deleted"}],
        )
        self.assertTrue(scope["partial"])
        self.assertIsNone(scope["mft"])

    def test_notes_are_korean_state_basis_and_never_a_single_number(self) -> None:
        scope = build_run_scope(image_summary(IMG_B_STATS, self.run_dir), self.run_dir)
        notes = scope["notes"]
        self.assertTrue(notes[0].startswith("추정"))
        self.assertIn("fls", notes[0])
        self.assertIn("비할당 영역은 측정하지 않았습니다.", notes)
        self.assertTrue(any("1개만 처리" in note for note in notes))
        self.assertTrue(any("430,052건" in note for note in notes))
        joined = " ".join(notes)
        self.assertNotIn("볼륨의", joined)
        self.assertNotIn("%", joined)
        self.assertNotIn("percent", all_keys(scope))

    def test_cap_number_comes_from_stats_not_a_constant(self) -> None:
        stats = {**IMG_B_STATS, "files": 50, "deleted_files": 10, "deleted_read_errors": 0, "errors": 0,
                 "truncated": 40, "file_limit": 50}
        scope = build_run_scope(image_summary(stats, self.run_dir), self.run_dir)
        self.assertEqual(scope["caps"][0]["limit"], 50)
        joined = " ".join(scope["notes"])
        self.assertIn("(50개)", joined)
        self.assertNotIn("200,000", joined)
        self.assertEqual(scope["deleted"]["records"], 50)
        self.assertEqual(scope["deleted"]["attempted_pct"], 20.0)
        self.assertEqual(scope["allocated"]["content_pct"], 100.0)

    def test_truncated_walk_leaves_allocated_unknown(self) -> None:
        # The sweep wrote nothing while the cap was hit: the allocated walk may be truncated.
        stats = {**IMG_B_STATS, "files": 50, "deleted_files": 0, "deleted_read_errors": 0, "errors": 0,
                 "truncated": 70, "file_limit": 50}
        scope = build_run_scope(image_summary(stats, self.run_dir), self.run_dir)
        self.assertIsNone(scope["allocated"]["listed_pct"])
        self.assertIsNone(scope["allocated"]["content_pct"])
        self.assertIsNone(scope["deleted"]["records"])
        self.assertIsNone(scope["deleted"]["attempted_pct"])
        self.assertIsNone(scope["deleted"]["not_attempted"])
        self.assertEqual(scope["caps"][0]["axis"], "unknown")
        self.assertTrue(scope["partial"])
        self.assertTrue(any("잘렸을 수 있습니다" in note for note in scope["notes"]))

    def test_mft_copy_header_tally_drives_deleted_denominator(self) -> None:
        mft = self.run_dir / "_e01" / "_system" / "MFT.bin"
        expected = write_mft(mft)
        stats = {"files": 8, "errors": 0, "truncated": 4, "deleted_files": 2, "deleted_read_errors": 1, "file_limit": 8}
        # Recorded path missing (moved run folder): falls back to <run_dir>/_e01/_system/MFT.bin.
        summary = image_summary(stats, self.run_dir, mft=Path(self._tmp.name) / "elsewhere" / "MFT.bin")
        scope = build_run_scope(summary, self.run_dir)
        self.assertEqual(scope["mft"], expected)
        deleted = scope["deleted"]
        self.assertEqual(deleted["records_source"], "mft_header")
        self.assertEqual(deleted["records"], 9)
        self.assertEqual(deleted["attempted"], 3)
        self.assertEqual(deleted["attempted_pct"], 33.3)
        self.assertEqual(deleted["listed_pct"], 22.2)
        self.assertEqual(deleted["directories"], 3)
        self.assertEqual(scope["allocated"]["records"], 6)
        self.assertTrue(any("디렉터리 레코드 3건" in note for note in scope["notes"]))

    def test_mft_tally_reads_record_size_and_caches(self) -> None:
        mft = self.run_dir / "MFT.bin"
        expected = write_mft(mft, record_size=4096)
        self.assertEqual(tally_mft_headers(mft), expected)
        summary = image_summary({"files": 1, "file_limit": 10}, self.run_dir, mft=mft)
        first = build_run_scope(summary, self.run_dir)["mft"]
        self.assertEqual(first, expected)
        self.assertEqual(len(run_scope._mft_cache), 1)
        self.assertEqual(build_run_scope(summary, self.run_dir)["mft"], expected)

    def test_complete_small_image_is_not_partial(self) -> None:
        stats = {"files": 12, "errors": 0, "truncated": 0, "deleted_files": 2, "deleted_read_errors": 0, "file_limit": 200_000}
        summary = image_summary(stats, self.run_dir)
        summary["source"]["partition_selection"]["supported_partition_count"] = 1
        scope = build_run_scope(summary, self.run_dir)
        self.assertEqual(scope["allocated"]["listed_pct"], 100.0)
        self.assertEqual(scope["deleted"]["attempted_pct"], 100.0)
        self.assertEqual(scope["caps"], [])
        self.assertFalse(scope["partial"])

    def test_folder_evidence_and_old_results_are_unavailable(self) -> None:
        for summary in (None, {"output_dir": str(self.run_dir), "outputs": {}}, {"source": {"type": "folder"}}):
            with self.subTest(summary=summary):
                scope = build_run_scope(summary, self.run_dir)
                self.assertEqual(scope["basis"], "unavailable")
                self.assertIsNone(scope["partial"])
                self.assertIsNone(scope["allocated"]["listed_pct"])
                self.assertEqual(scope["caps"], [])
                self.assertIn("추출 통계가 없어", scope["notes"][0])

    def test_older_summary_reads_e01_output_inside_run_dir(self) -> None:
        payload = image_summary(IMG_B_STATS, self.run_dir)["source"]
        (self.run_dir / "rapidtriage-e01.json").write_text(json.dumps(payload), encoding="utf-8")
        summary = {"output_dir": str(self.run_dir), "outputs": {"e01": "rapidtriage-e01.json"}}
        self.assertEqual(build_run_scope(summary, self.run_dir)["basis"], "inferred")
        outside = Path(self._tmp.name) / "outside-e01.json"
        outside.write_text(json.dumps(payload), encoding="utf-8")
        summary["outputs"]["e01"] = str(outside)
        self.assertEqual(build_run_scope(summary, self.run_dir)["basis"], "unavailable")


class DashboardScopeTests(unittest.TestCase):
    def test_dashboard_exposes_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp) / "run"
            run_dir.mkdir()
            # Evidence lives beside the run folder: a run inside its evidence would be opened read-only
            # (T-032) and the temp-folder cleanup refused.
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            summary = {"profile_version": "rapidtriage-run-summary-v1", "mode": "fraud", "root": str(evidence),
                       **image_summary(IMG_B_STATS, run_dir)}
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary["outputs"] = {"summary": str(summary_path)}
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
            response = client.get(f"/api/runs/{job.run_id}/dashboard")
            self.assertEqual(response.status_code, 200, response.text)
            scope = response.json()["scope"]
            self.assertEqual(scope["basis"], "inferred")
            self.assertEqual(scope["partitions"]["processed"], 1)
            self.assertEqual(scope["allocated"]["listed_pct"], 100.0)
            self.assertEqual(scope["caps"][0]["skipped"], 430_052)


if __name__ == "__main__":
    unittest.main()
