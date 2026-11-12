"""Collector caps inventory ratchet (T-165, GAP-286 / GAP-272).

``scripts/check-collector-caps.py`` lists every hard cap under ``rapidtriage/artifacts`` and
``rapidtriage/core`` and whether hitting it is disclosed (``*_truncated`` + ``*_total`` keys or a
warning sentence). This test pins the caps named in the plan and fails when a file gains an
undisclosed cap beyond the baseline below. When a change discloses a cap, lower the baseline with::

    python tests/test_collector_caps_inventory.py --print-baseline
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-collector-caps.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("check_collector_caps", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


caps_script = _load_script()

MIB = 1024 * 1024

# Caps named in the plan (r8-tasks T-165 / T-184 / GAP-286): id -> (value, unit).
KNOWN_CAPS = {
    "rapidtriage/artifacts/windows/filesystem.py::NATIVE_SCAN_LIMIT": (16 * MIB, "bytes"),  # MFT 16 MiB
    "rapidtriage/artifacts/windows/filesystem.py::parse_mft_record_headers:len>=5000": (5000, "count"),  # MFT 5,000
    "rapidtriage/artifacts/windows/filesystem.py::USN_RECORD_SCAN_LIMIT": (5000, "count"),
    "rapidtriage/artifacts/windows/filesystem.py::NTFS_LOGFILE_SCAN_LIMIT": (8 * MIB, "bytes"),
    "rapidtriage/core/e01_native.py::MAX_NATIVE_EXTRACT_FILES": (200_000, "count"),
    "rapidtriage/artifacts/synthetic_media.py::SYNTHETIC_MEDIA_MAX_FILES": (512, "count"),
    "rapidtriage/core/derived/engine.py::MAX_VALUES_PER_TABLE": (200_000, "count"),
    "rapidtriage/core/bundle.py::build_submission_bundle(max_items)": (500, "count"),
    "rapidtriage/artifacts/ai_agents/base.py::DEFAULT_AI_READ_MB": (4096, "MiB"),
    "rapidtriage/core/case_db/search.py::DOCUMENT_SUBSTRING_SCAN_BUDGET": (200_000, "count"),
}

# GAP-272: collectors whose cap had no disclosure when the plan was written (7 kinds, 8 caps).
# T-301..T-307 add the disclosure; the values themselves must not change.
GAP_272_CAPS = {
    "rapidtriage/artifacts/kakaotalk_messages.py::PICTURE_ROW_LIMIT": 20_000,
    "rapidtriage/artifacts/kakaotalk_windows.py::KAKAO_APP_DB_LIMIT": 500,
    "rapidtriage/artifacts/email.py::CONTAINER_SCAN_LIMIT": 16 * MIB,
    "rapidtriage/artifacts/cloud.py::CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT": 25,
    "rapidtriage/artifacts/cloud.py::CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT": 50,
    "rapidtriage/artifacts/windows/execution.py::SHIMCACHE_MAX_ENTRIES": 8192,
    "rapidtriage/artifacts/windows/eventlog.py::ETL_SCAN_LIMIT": 4 * MIB,
    "rapidtriage/artifacts/memory.py::MEMORY_DUMP_SCAN_LIMIT": 256 * MIB,
}

# Undisclosed caps per file at T-165 (heuristic of scripts/check-collector-caps.py). Ratchet: may only go down.
BASELINE_UNDISCLOSED_PER_FILE = {
    "rapidtriage/artifacts/__init__.py": 1,
    "rapidtriage/artifacts/ai_agents/adapters/_common.py": 2,
    "rapidtriage/artifacts/ai_agents/adapters/antigravity.py": 1,
    "rapidtriage/artifacts/ai_agents/adapters/claude_code.py": 6,
    "rapidtriage/artifacts/ai_agents/adapters/claude_desktop.py": 2,
    "rapidtriage/artifacts/ai_agents/adapters/claude_swap.py": 3,
    "rapidtriage/artifacts/ai_agents/adapters/codex.py": 4,
    "rapidtriage/artifacts/ai_agents/adapters/cursor.py": 2,
    "rapidtriage/artifacts/ai_agents/adapters/gemini_cli.py": 1,
    "rapidtriage/artifacts/ai_agents/adapters/kiro.py": 3,
    "rapidtriage/artifacts/ai_agents/adapters/omo.py": 3,
    "rapidtriage/artifacts/ai_agents/adapters/stubs.py": 1,
    "rapidtriage/artifacts/ai_agents/adapters/zcode.py": 2,
    "rapidtriage/artifacts/ai_agents/base.py": 1,
    "rapidtriage/artifacts/ai_agents/execution_match.py": 1,
    "rapidtriage/artifacts/ai_agents/git_trailers.py": 6,
    "rapidtriage/artifacts/ai_agents/local_llm_ext.py": 2,
    "rapidtriage/artifacts/ai_agents/presence.py": 4,
    "rapidtriage/artifacts/ai_agents/run_indirect.py": 2,
    "rapidtriage/artifacts/android.py": 4,
    "rapidtriage/artifacts/cloud.py": 7,
    "rapidtriage/artifacts/cloud_sync.py": 10,
    "rapidtriage/artifacts/email.py": 4,
    "rapidtriage/artifacts/email_clients.py": 12,
    "rapidtriage/artifacts/email_external.py": 5,
    "rapidtriage/artifacts/email_pst.py": 6,
    "rapidtriage/artifacts/generic.py": 10,
    "rapidtriage/artifacts/kakaotalk_macos.py": 5,
    "rapidtriage/artifacts/kakaotalk_messages.py": 9,
    "rapidtriage/artifacts/kakaotalk_windows.py": 4,
    "rapidtriage/artifacts/linux.py": 2,
    "rapidtriage/artifacts/macos.py": 2,
    "rapidtriage/artifacts/media.py": 21,
    "rapidtriage/artifacts/memory.py": 3,
    "rapidtriage/artifacts/mobile/adb_backup.py": 8,
    "rapidtriage/artifacts/mobile/constants.py": 4,
    "rapidtriage/artifacts/mobile/correlation.py": 4,
    "rapidtriage/artifacts/mobile/vendor.py": 2,
    "rapidtriage/artifacts/p2p.py": 6,
    "rapidtriage/artifacts/synthetic_media.py": 2,
    "rapidtriage/artifacts/windows/antiforensics.py": 3,
    "rapidtriage/artifacts/windows/av_ahnlab.py": 3,
    "rapidtriage/artifacts/windows/browser.py": 17,
    "rapidtriage/artifacts/windows/browser_analytics.py": 2,
    "rapidtriage/artifacts/windows/browser_cache.py": 10,
    "rapidtriage/artifacts/windows/browser_webcache.py": 3,
    "rapidtriage/artifacts/windows/ese.py": 2,
    "rapidtriage/artifacts/windows/ese_native.py": 5,
    "rapidtriage/artifacts/windows/eventlog.py": 15,
    "rapidtriage/artifacts/windows/execution.py": 5,
    "rapidtriage/artifacts/windows/filesystem.py": 12,
    "rapidtriage/artifacts/windows/leveldb.py": 6,
    "rapidtriage/artifacts/windows/location_urls.py": 1,
    "rapidtriage/artifacts/windows/media_players.py": 6,
    "rapidtriage/artifacts/windows/messenger.py": 15,
    "rapidtriage/artifacts/windows/os_account.py": 1,
    "rapidtriage/artifacts/windows/pca.py": 1,
    "rapidtriage/artifacts/windows/phone_link.py": 7,
    "rapidtriage/artifacts/windows/prefetch.py": 9,
    "rapidtriage/artifacts/windows/recent_files.py": 10,
    "rapidtriage/artifacts/windows/registry.py": 6,
    "rapidtriage/artifacts/windows/registry_depth.py": 5,
    "rapidtriage/artifacts/windows/remote_access.py": 1,
    "rapidtriage/artifacts/windows/shellbags.py": 1,
    "rapidtriage/artifacts/windows/shellitem.py": 2,
    "rapidtriage/artifacts/windows/srum_ese.py": 1,
    "rapidtriage/artifacts/windows/system.py": 27,
    "rapidtriage/artifacts/windows/system_extras.py": 15,
    "rapidtriage/artifacts/windows/web_upload.py": 1,
    "rapidtriage/artifacts/windows/xpress_huffman.py": 1,
    "rapidtriage/core/ai_catalog/catalog.py": 2,
    "rapidtriage/core/analysis.py": 14,
    "rapidtriage/core/artifact_profiles.py": 1,
    "rapidtriage/core/artifacts.py": 3,
    "rapidtriage/core/benchmark_fts.py": 1,
    "rapidtriage/core/browse.py": 1,
    "rapidtriage/core/browser_stress.py": 1,
    "rapidtriage/core/bundle.py": 1,
    "rapidtriage/core/carving.py": 1,
    "rapidtriage/core/carving_formats.py": 5,
    "rapidtriage/core/case_db/constants.py": 1,
    "rapidtriage/core/case_db/database.py": 4,
    "rapidtriage/core/case_db/intake.py": 1,
    "rapidtriage/core/case_db/reporting.py": 1,
    "rapidtriage/core/case_db/review_schema.py": 2,
    "rapidtriage/core/case_db/review_tools.py": 4,
    "rapidtriage/core/case_db/search.py": 2,
    "rapidtriage/core/case_export.py": 1,
    "rapidtriage/core/case_report.py": 3,
    "rapidtriage/core/cli_constants.py": 12,
    "rapidtriage/core/cloud_api.py": 1,
    "rapidtriage/core/collect_plan.py": 1,
    "rapidtriage/core/columnar_store.py": 2,
    "rapidtriage/core/commercial_readiness.py": 1,
    "rapidtriage/core/confidence.py": 1,
    "rapidtriage/core/crash.py": 1,
    "rapidtriage/core/credential_files.py": 1,
    "rapidtriage/core/cross_case.py": 2,
    "rapidtriage/core/cross_device.py": 1,
    "rapidtriage/core/cross_tool.py": 14,
    "rapidtriage/core/derived/engine.py": 6,
    "rapidtriage/core/derived/map_urls.py": 3,
    "rapidtriage/core/derived/normalize.py": 1,
    "rapidtriage/core/derived/tables_ai.py": 2,
    "rapidtriage/core/doc_text.py": 3,
    "rapidtriage/core/docs.py": 6,
    "rapidtriage/core/e01.py": 2,
    "rapidtriage/core/e01_native.py": 1,
    "rapidtriage/core/egg_archive.py": 8,
    "rapidtriage/core/eventlog_channels.py": 2,
    "rapidtriage/core/extraction_failures.py": 6,
    "rapidtriage/core/families.py": 2,
    "rapidtriage/core/files.py": 11,
    "rapidtriage/core/frametrace_import.py": 2,
    "rapidtriage/core/hash_cache.py": 4,
    "rapidtriage/core/incremental.py": 1,
    "rapidtriage/core/indicators.py": 4,
    "rapidtriage/core/iso9660.py": 6,
    "rapidtriage/core/jobs.py": 3,
    "rapidtriage/core/kakaotalk.py": 11,
    "rapidtriage/core/large_case_readiness.py": 2,
    "rapidtriage/core/macos_live_smoke.py": 1,
    "rapidtriage/core/native_accel.py": 1,
    "rapidtriage/core/ntfs_logfile.py": 4,
    "rapidtriage/core/ntfs_metadata.py": 1,
    "rapidtriage/core/ntfs_unalloc.py": 2,
    "rapidtriage/core/ocr_queue.py": 2,
    "rapidtriage/core/process_bounds.py": 2,
    "rapidtriage/core/reporting.py": 1,
    "rapidtriage/core/rules.py": 1,
    "rapidtriage/core/run/constants.py": 3,
    "rapidtriage/core/run/memory.py": 2,
    "rapidtriage/core/run/progress.py": 1,
    "rapidtriage/core/run/steps.py": 1,
    "rapidtriage/core/search.py": 1,
    "rapidtriage/core/search_budget.py": 2,
    "rapidtriage/core/search_fts.py": 1,
    "rapidtriage/core/search_hits.py": 3,
    "rapidtriage/core/search_index/build.py": 15,
    "rapidtriage/core/search_index/engine.py": 16,
    "rapidtriage/core/search_index/hashsets.py": 3,
    "rapidtriage/core/search_index/hits.py": 1,
    "rapidtriage/core/search_index/lists.py": 5,
    "rapidtriage/core/search_index/patterns.py": 3,
    "rapidtriage/core/search_index/query.py": 4,
    "rapidtriage/core/search_index/regex_guard.py": 3,
    "rapidtriage/core/search_index/schema.py": 1,
    "rapidtriage/core/silent_failure.py": 1,
    "rapidtriage/core/source_reader.py": 12,
    "rapidtriage/core/sqlite_snapshot.py": 1,
    "rapidtriage/core/sqlite_wal.py": 6,
    "rapidtriage/core/timeline.py": 4,
    "rapidtriage/core/triage_rules/base.py": 1,
    "rapidtriage/core/triage_rules/engine.py": 4,
    "rapidtriage/core/url_carving.py": 1,
    "rapidtriage/core/vsc.py": 2,
    "rapidtriage/core/worker.py": 1,
}


class CapsHeuristicTests(unittest.TestCase):
    """The detection rules on a tiny synthetic tree (fast, no repository scan)."""

    def _inventory(self, files: dict[str, str]) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, source in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(source), encoding="utf-8")
            return caps_script.build_inventory(root)

    def test_detection_and_disclosure_levels(self) -> None:
        inventory = self._inventory(
            {
                "rapidtriage/artifacts/__init__.py": "",
                "rapidtriage/artifacts/sample.py": """
                    ROW_LIMIT = 100
                    SCAN_LIMIT_BYTES = 4 * 1024 * 1024
                    FLAG_MAX_ITEMS = 10
                    MAX_UNIX = 4_102_444_800
                    SAMPLE_VERSION = 3

                    def rows(items):
                        out = items[:ROW_LIMIT]
                        return {"rows": out, "rows_truncated": len(items) > ROW_LIMIT, "rows_total": len(items)}

                    def scan(blob):
                        return {"scan_limit": SCAN_LIMIT_BYTES, "data": blob[:SCAN_LIMIT_BYTES]}

                    def flagged(items):
                        return {"items": items[:FLAG_MAX_ITEMS], "items_truncated": len(items) > FLAG_MAX_ITEMS}

                    def walk(paths, *, max_files: int = 5000):
                        found = []
                        for path in paths:
                            if len(found) >= 2000:
                                break
                            found.append(path)
                        return found[:max_files]
                    """,
                "rapidtriage/core/limits.py": """
                    from ..artifacts.sample import SCAN_LIMIT_BYTES

                    HARD_CAP = 7

                    def hard_cap():
                        return HARD_CAP

                    def run(rows):
                        if len(rows) > hard_cap():
                            return f"상한 {hard_cap()}건 초과로 {len(rows)}건 중 일부만 읽었습니다."
                        return ""

                    def window():
                        return {"window": SCAN_LIMIT_BYTES}
                    """,
            }
        )
        caps = {cap["id"]: cap for cap in inventory["caps"]}
        sample = "rapidtriage/artifacts/sample.py"
        self.assertEqual(caps[f"{sample}::ROW_LIMIT"]["disclosure"], "full")
        self.assertEqual(caps[f"{sample}::SCAN_LIMIT_BYTES"]["disclosure"], "none")
        self.assertEqual(caps[f"{sample}::SCAN_LIMIT_BYTES"]["unit"], "bytes")
        self.assertEqual(caps[f"{sample}::SCAN_LIMIT_BYTES"]["value"], 4 * MIB)
        self.assertIn("rapidtriage/core/limits.py:window", caps[f"{sample}::SCAN_LIMIT_BYTES"]["used_in"])
        self.assertEqual(caps[f"{sample}::FLAG_MAX_ITEMS"]["disclosure"], "flag")
        self.assertFalse(caps[f"{sample}::FLAG_MAX_ITEMS"]["disclosed"])
        self.assertIn(f"{sample}::walk(max_files)", caps)
        self.assertIn(f"{sample}::walk:len>=2000", caps)
        self.assertNotIn(f"{sample}::MAX_UNIX", caps)
        self.assertNotIn(f"{sample}::SAMPLE_VERSION", caps)
        # accessor hop: the warning sits next to hard_cap() calls, not next to HARD_CAP
        self.assertTrue(caps["rapidtriage/core/limits.py::HARD_CAP"]["disclosed"])
        self.assertEqual(inventory["summary"]["undisclosed"], len(inventory["undisclosed"]))
        markdown = caps_script.render_markdown(inventory)
        self.assertIn("| file:line | name | value | unit | kind | disclosed |", markdown)
        self.assertIn("| rapidtriage/artifacts/sample.py:3 | `SCAN_LIMIT_BYTES` | 4 MiB | bytes | constant | no |", markdown)


class CollectorCapsInventoryTests(unittest.TestCase):
    """Repository scan: pinned caps and the undisclosed-cap ratchet."""

    inventory: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = caps_script.build_inventory(REPO)
        cls.caps = {cap["id"]: cap for cap in cls.inventory["caps"]}

    def test_scan_is_clean_and_serialisable(self) -> None:
        self.assertEqual(self.inventory["parse_errors"], [])
        self.assertGreater(self.inventory["summary"]["files_scanned"], 100)
        json.dumps(self.inventory, ensure_ascii=False)

    def test_known_caps_are_inventoried(self) -> None:
        for cap_id, (value, unit) in KNOWN_CAPS.items():
            with self.subTest(cap=cap_id):
                self.assertIn(cap_id, self.caps)
                self.assertEqual((self.caps[cap_id]["value"], self.caps[cap_id]["unit"]), (value, unit))

    def test_gap_272_caps_are_inventoried(self) -> None:
        for cap_id, value in GAP_272_CAPS.items():
            with self.subTest(cap=cap_id):
                self.assertIn(cap_id, self.caps)
                self.assertEqual(self.caps[cap_id]["value"], value)

    def test_undisclosed_caps_do_not_grow(self) -> None:
        current = self.inventory["undisclosed_per_file"]
        grown = {
            path: (count, BASELINE_UNDISCLOSED_PER_FILE.get(path, 0))
            for path, count in current.items()
            if count > BASELINE_UNDISCLOSED_PER_FILE.get(path, 0)
        }
        details = [
            f"{cap['id']} ({cap['file']}:{cap['line']}, value {cap['value']})"
            for cap in self.inventory["caps"]
            if not cap["disclosed"] and cap["file"] in grown
        ]
        self.assertEqual(
            grown,
            {},
            "new undisclosed cap(s) -- emit <name>_truncated + <name>_total (or a warning line) when the cap "
            "is hit, or justify and raise the baseline:\n  " + "\n  ".join(details),
        )
        self.assertLessEqual(self.inventory["summary"]["undisclosed"], sum(BASELINE_UNDISCLOSED_PER_FILE.values()))
        shrunk = {path: count for path, count in BASELINE_UNDISCLOSED_PER_FILE.items() if current.get(path, 0) < count}
        if shrunk:
            print(
                f"\n[collector-caps] {len(shrunk)} file(s) now below baseline; lower it with "
                "`python tests/test_collector_caps_inventory.py --print-baseline`",
                file=sys.stderr,
            )


if __name__ == "__main__":
    if "--print-baseline" in sys.argv:
        per_file = caps_script.build_inventory(REPO)["undisclosed_per_file"]
        print("BASELINE_UNDISCLOSED_PER_FILE = {")
        for path, count in per_file.items():
            print(f'    "{path}": {count},')
        print("}")
    else:
        unittest.main()
