"""Record slimming and streaming (run-pipeline-mitigations §7: I10-I13, Q14).

Covers profile hoisting and its exact inverse, per-record list caps, the
eventlog triage projection / structure-row switch, JSONL-backed per-kind
payloads, envelope-only ArtifactRecordV1 rows, and the memory-cap fail-fast.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import rapidtriage.core.run.memory as memory_module
from rapidtriage.api.app.pagination import paginate_artifact_output
from rapidtriage.artifacts import clear_collect_cache, get_artifact_collector
from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider
from rapidtriage.core.artifact_profiles import (
    PROFILE_REF_KEY,
    cap_list_field,
    expand_profile,
    hoist_constant_blocks,
    is_hoistable_detail_key,
    is_hoistable_scalar_key,
    iter_artifact_output_rows,
    iter_payload_records,
)
from rapidtriage.core.artifact_store import (
    artifact_record_with_fields,
    attach_artifact_record_contracts,
    build_artifact_record_v1_from_legacy,
)
from rapidtriage.core.artifacts import (
    materialize_artifact_payload,
    resolve_collector_options,
    run_artifact_collection,
)
from rapidtriage.core.docs import write_result
from rapidtriage.core.input_root import resolve_input_root
from rapidtriage.core.json_stream import iter_jsonl_items
from rapidtriage.core.run import RUN_PROGRESS_FILE_NAME, run_triage_mode
from rapidtriage.core.run.memory import (
    MEMORY_CAP_ENV,
    MemoryCapExceeded,
    memory_cap_source,
    resolve_memory_cap_bytes,
)
from tests.test_rapidtriage_run import build_run_fixture
from tests.windows_artifact_fixtures import (
    build_corrupt_evtx_record_candidate,
    build_evtx_with_checked_chunk,
    build_windows_artifact_fixture,
)


def _row(artifact_type: str, details: dict[str, object], **extra: object) -> dict[str, object]:
    return {"provider": "p", "artifact_type": artifact_type, "path": f"C:/{artifact_type}", "supported": True, "details": details, **extra}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class HoistExpandTests(unittest.TestCase):
    def test_constant_and_partially_constant_blocks_round_trip(self) -> None:
        rows = [
            _row(
                "t",
                {
                    "parser": "x",
                    "source_path": f"C:/f{index}",
                    "core_accuracy_gates": [
                        {"gap_id": "#1", "required": ["a", "b"], "evidence_refs": [f"record:{index}"]},
                        {"gap_id": "#2", "required": ["c"]},
                    ],
                    "commercial_uplift_evidence": {
                        "batch_id": "b1",
                        "nested": {"constant": [1, 2, 3], "varying": index},
                        "source_refs": [f"source:{index}"],
                    },
                    "forensic_review": {"gap_id": "#9", "caveats": ["same"]},
                    "validation_guidance": "validate" if index else "different",
                },
            )
            for index in range(5)
        ]
        original = copy.deepcopy(rows)

        hoisted, profiles = hoist_constant_blocks(rows)

        self.assertEqual(set(profiles), {"t"})
        templates = profiles["t"]["details"]
        self.assertEqual(templates["forensic_review"], {"gap_id": "#9", "caveats": ["same"]})
        self.assertEqual(templates["commercial_uplift_evidence"]["nested"], {"constant": [1, 2, 3]})
        self.assertNotIn("validation_guidance", templates)  # varies: never hoisted
        for row in hoisted:
            self.assertEqual(row[PROFILE_REF_KEY], "t")
            self.assertNotIn("forensic_review", row["details"])
            self.assertEqual(row["details"]["source_path"], original[hoisted.index(row)]["details"]["source_path"])
        self.assertEqual(hoisted[3]["details"]["commercial_uplift_evidence"], {"nested": {"varying": 3}, "source_refs": ["source:3"]})
        for row, before in zip(hoisted, original):
            expanded = expand_profile(row, profiles)
            self.assertEqual(_canonical(expanded), _canonical(before))

    def test_identity_keys_and_type_mismatches_are_never_hoisted(self) -> None:
        rows = [
            _row("t", {"source_hashes": {"sha256": "aa"}, "parser": "x", "forensic_review": {"flag": 1}}),
            _row("t", {"source_hashes": {"sha256": "aa"}, "parser": "x", "forensic_review": {"flag": True}}),
        ]
        original = copy.deepcopy(rows)
        hoisted, profiles = hoist_constant_blocks(rows)
        # Only the constant scalar label moves; identity keys and values that
        # differ only in JSON type (1 vs true) stay on the rows.
        self.assertEqual(profiles, {"t": {"details": {"parser": "x"}}})
        self.assertFalse(is_hoistable_detail_key("source_hashes"))
        self.assertFalse(is_hoistable_scalar_key("source_hashes"))
        self.assertFalse(is_hoistable_scalar_key("record_count"))
        self.assertFalse(is_hoistable_scalar_key("last_run_at"))
        self.assertTrue(is_hoistable_scalar_key("parser"))
        self.assertTrue(is_hoistable_detail_key("prefetch_validation_matrix"))
        for row, before in zip(hoisted, original):
            self.assertEqual(row["details"]["source_hashes"], before["details"]["source_hashes"])
            self.assertEqual(row["details"]["forensic_review"], before["details"]["forensic_review"])
            self.assertEqual(_canonical(expand_profile(row, profiles)), _canonical(before))

    def test_rows_sharing_a_source_file_hoist_per_file_context(self) -> None:
        rows = [
            _row(
                "ref",
                {
                    "source_path": f"C:/{name}.pf",
                    "source_hashes": {"sha256": name * 4},
                    "referenced_path": f"C:/{name}/{index}",
                    "forensic_review": {"primary": [f"exe={name}"], "gap": "#16"},
                },
                path=f"C:/{name}.pf",
            )
            for name in ("a", "b")
            for index in range(10)
        ]
        original = copy.deepcopy(rows)
        hoisted, profiles = hoist_constant_blocks(rows)
        contexts = profiles["ref"]["contexts"]
        self.assertEqual(set(contexts), {"C:/a.pf", "C:/b.pf"})
        self.assertEqual(contexts["C:/a.pf"]["details"]["source_hashes"], {"sha256": "aaaa"})
        self.assertEqual(profiles["ref"]["details"]["forensic_review"], {"gap": "#16"})
        for row, before in zip(hoisted, original):
            self.assertIs(row["context_ref"], True)
            self.assertEqual(set(row["details"]), {"referenced_path"})
            self.assertEqual(_canonical(expand_profile(row, profiles)), _canonical(before))

    def test_keys_missing_from_some_records_stay_on_records(self) -> None:
        rows = [
            _row("t", {"forensic_review": {"a": 1}}),
            _row("t", {"forensic_review": {"a": 1}}),
            _row("t", {"other": 2}),
            _row("u", {"forensic_review": {"a": 1}}),
        ]
        original = copy.deepcopy(rows)
        _, profiles = hoist_constant_blocks(rows)
        self.assertEqual(profiles, {})  # "t" lacks the key on one row; "u" has a single row
        self.assertEqual(rows, original)

    def test_envelope_is_hoisted_and_restored(self) -> None:
        rows = []
        for index in range(3):
            row = _row("t", {"source_path": f"C:/f{index}", "parser": "x"})
            row["artifact_record"] = build_artifact_record_v1_from_legacy(
                row, kind="k", provider_name="p", root="C:/", index=index + 1, include_fields=False
            )
            rows.append(row)
        original = copy.deepcopy(rows)
        _, profiles = hoist_constant_blocks(rows)
        self.assertIn("artifact_record", profiles["t"])
        self.assertEqual(profiles["t"]["artifact_record"]["schema"], "ArtifactRecordV1")
        self.assertIn("artifact_id", rows[0]["artifact_record"])
        self.assertNotIn("schema", rows[0]["artifact_record"])
        for row, before in zip(rows, original):
            self.assertEqual(_canonical(expand_profile(row, profiles)), _canonical(before))

    def test_cap_list_field_marks_truncation_only_when_needed(self) -> None:
        details: dict[str, object] = {"short": [1, 2], "long": list(range(10))}
        cap_list_field(details, "short", 4)
        cap_list_field(details, "long", 4)
        self.assertEqual(details["short"], [1, 2])
        self.assertNotIn("short_truncated", details)
        self.assertEqual(details["long"], [0, 1, 2, 3])
        self.assertTrue(details["long_truncated"])
        self.assertEqual(details["long_total"], 10)


class ProviderRoundTripTests(unittest.TestCase):
    """Q14: profile-expanded run rows equal the pre-slimming rows field for field."""

    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()

    def test_expanded_rows_match_unhoisted_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            build_run_fixture(root)
            input_root = resolve_input_root(root)
            for kind in ("windows-prefetch", "windows-registry", "recent-files", "eventlog"):
                collector = get_artifact_collector(kind)
                options = resolve_collector_options(kind, None)
                if options:
                    collector = collector.with_options(**options)
                baseline = attach_artifact_record_contracts(
                    {
                        "provider": {"name": collector.name},
                        "artifacts": [item.to_dict() for item in collector.collect(input_root.root_path)],
                    },
                    kind=kind,
                    root=input_root.root_path,
                    include_fields=False,
                )["artifacts"]
                records_path = Path(tmp_dir) / f"{kind}.jsonl"
                payload = run_artifact_collection(root, kind=kind, records_path=records_path, preview_limit=1, use_cache=False)
                expanded = list(iter_payload_records(payload))
                self.assertEqual(len(expanded), len(baseline), kind)
                self.assertEqual(payload["record_count"], len(baseline), kind)
                for got, want in zip(expanded, baseline):
                    got.pop("incremental_reuse", None)
                    # generated_at-style volatile values do not live on rows.
                    self.assertEqual(_canonical(got), _canonical(want), kind)


class EnvelopeTests(unittest.TestCase):
    def test_fields_are_rebuilt_from_details(self) -> None:
        row = _row("browser-history", {"parser": "chromium", "source_path": "C:/h", "browser": "chrome"})
        full = build_artifact_record_v1_from_legacy(row, kind="browser", provider_name="p", root="C:/", index=3)
        envelope = build_artifact_record_v1_from_legacy(
            row, kind="browser", provider_name="p", root="C:/", index=3, include_fields=False
        )
        self.assertNotIn("fields", envelope)
        self.assertEqual(envelope["fields_source"], "details")
        rebuilt = artifact_record_with_fields({**row, "artifact_record": envelope})
        self.assertEqual(_canonical(rebuilt), _canonical(full))


class EventlogProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()

    def test_pipeline_defaults_drop_structure_rows_and_use_triage_projection(self) -> None:
        self.assertEqual(resolve_collector_options("eventlog", None), {"structure_rows": False, "record_detail": "triage"})
        self.assertEqual(
            resolve_collector_options("eventlog", {"structure_rows": True})["structure_rows"],
            True,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            fixture = build_windows_artifact_fixture(root)
            logs_dir = fixture.evtx_file.parent
            when = datetime(2024, 4, 1, 9, 0, tzinfo=timezone.utc)
            (logs_dir / "Chunked.evtx").write_bytes(build_evtx_with_checked_chunk(7, when, ["powershell.exe -enc AAA="]))
            (logs_dir / "Corrupt.evtx").write_bytes(build_corrupt_evtx_record_candidate(9, when, ["cmd.exe /c whoami"]))
            full = [item.to_dict() for item in WindowsEventLogProvider().collect(root)]
            triage_payload = run_artifact_collection(root, kind="eventlog", use_cache=False)
            triage = list(iter_payload_records(triage_payload))
            structure_payload = run_artifact_collection(
                root,
                kind="eventlog",
                collector_options={"structure_rows": True, "record_detail": "full"},
                use_cache=False,
            )

        structural = {"eventlog-chunk", "eventlog-record-candidate"}
        self.assertTrue(any(row["artifact_type"] in structural for row in full))
        self.assertFalse(any(row["artifact_type"] in structural for row in triage))
        self.assertEqual(
            sorted(row["artifact_type"] for row in full if row["artifact_type"] not in structural),
            sorted(row["artifact_type"] for row in triage),
        )
        self.assertEqual(
            structure_payload["summary"]["artifact_type_counts"],
            {key: value for key, value in _type_counts(full).items()},
        )
        evtx_file = next(row for row in triage if row["artifact_type"] == "eventlog-file")
        self.assertFalse(evtx_file["details"]["structure_rows_emitted"])
        self.assertGreaterEqual(evtx_file["details"]["native_chunk_count"], 1)

        full_events = [row for row in full if row["artifact_type"] == "eventlog-event"]
        triage_events = [row for row in triage if row["artifact_type"] == "eventlog-event"]
        for want, got in zip(full_events, triage_events):
            for key in ("event_id", "record_id", "provider_name", "channel", "computer", "timestamp", "source_path"):
                self.assertEqual(got["details"].get(key), want["details"].get(key), key)
            self.assertNotIn("core_accuracy_gates", got["details"])
            self.assertNotIn("data", got["details"])
            self.assertEqual(got["details"]["record_projection"]["record_detail"], "triage")
        # Derived rows are built from the full events before projection.
        for derived in ("eventlog-detection", "eventlog-logon-session"):
            self.assertEqual(
                [row["details"].get("rule", {}).get("id") for row in full if row["artifact_type"] == derived],
                [row["details"].get("rule", {}).get("id") for row in triage if row["artifact_type"] == derived],
                derived,
            )
        full_sessions = [row["details"]["session_key"] for row in full if row["artifact_type"] == "eventlog-logon-session"]
        triage_sessions = [row["details"]["session_key"] for row in triage if row["artifact_type"] == "eventlog-logon-session"]
        self.assertEqual(full_sessions, triage_sessions)


def _type_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["artifact_type"])] = counts.get(str(row["artifact_type"]), 0) + 1
    return counts


class JsonlPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()

    def test_records_stream_to_jsonl_with_bounded_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            build_windows_artifact_fixture(root)
            output = Path(tmp_dir) / "out" / "rapidtriage-artifacts-windows-prefetch.json"
            payload = run_artifact_collection(
                root,
                kind="windows-prefetch",
                records_path=output.with_suffix(".jsonl"),
                preview_limit=1,
                use_cache=False,
            )
            write_result(payload, output)
            lines = list(iter_jsonl_items(output.with_suffix(".jsonl")))
            self.assertGreater(len(lines), 1)
            self.assertEqual(payload["record_count"], len(lines))
            self.assertEqual(payload["summary"]["artifact_count"], len(lines))
            self.assertEqual(len(payload["artifacts"]), 1)
            self.assertTrue(payload["artifacts_preview"])
            self.assertEqual(payload["records_file"], output.with_suffix(".jsonl").name)
            self.assertIn("artifact_type_profiles", payload)
            for line in lines:
                self.assertNotIn("fields", line["artifact_record"])  # serialized once (I10)
            self.assertEqual(iter_jsonl_items(output.with_suffix(".jsonl"), offset=1, limit=1).__next__(), lines[1])

            # File-level readers stream the JSONL (and survive a moved run dir).
            moved = Path(tmp_dir) / "moved"
            output.parent.rename(moved)
            rows = list(iter_artifact_output_rows(moved / output.name))
            self.assertEqual(len(rows), len(lines))
            on_disk = json.loads((moved / output.name).read_text(encoding="utf-8"))
            page = paginate_artifact_output(on_disk, payload_path=moved / output.name, offset=1, limit=2)
            self.assertEqual(page["pagination"]["total"], len(lines))
            self.assertEqual(len(page["artifacts"]), min(2, len(lines) - 1))
            materialized = materialize_artifact_payload(on_disk, payload_path=moved / output.name)
            self.assertEqual(len(materialized["artifacts"]), len(lines))
            self.assertNotIn("records_path", materialized)
            self.assertNotIn("artifact_type_profiles", materialized)


class MemoryCapTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()

    def test_default_cap_is_half_of_physical_ram(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(MEMORY_CAP_ENV, None)
            with mock.patch.object(memory_module, "physical_memory_bytes", return_value=64 * 1024**3):
                self.assertEqual(resolve_memory_cap_bytes(0), 32 * 1024**3)
                self.assertEqual(memory_cap_source(0), "default-physical-ram-fraction")
            with mock.patch.object(memory_module, "physical_memory_bytes", return_value=0):
                self.assertEqual(resolve_memory_cap_bytes(0), 16 * 1024**3)
            self.assertEqual(resolve_memory_cap_bytes(123), 123)
            self.assertEqual(memory_cap_source(123), "argument")
        with mock.patch.dict(os.environ, {MEMORY_CAP_ENV: "0"}):
            self.assertEqual(resolve_memory_cap_bytes(0), 0)
            self.assertEqual(memory_cap_source(0), "environment")

    def test_cap_breach_after_a_provider_fails_the_run_fast(self) -> None:
        original_row = memory_module.memory_cap_stage_check_row

        def breach_on_artifacts(stage, memory_cap_bytes, *, sequence=0, current_rss_bytes=None):
            if str(stage).startswith("artifacts:"):
                current_rss_bytes = memory_cap_bytes * 4
            return original_row(stage, memory_cap_bytes, sequence=sequence, current_rss_bytes=current_rss_bytes)

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "out"
            root.mkdir()
            build_run_fixture(root)
            with mock.patch.object(memory_module, "memory_cap_stage_check_row", side_effect=breach_on_artifacts):
                with self.assertRaises(MemoryCapExceeded) as raised:
                    run_triage_mode(root, mode="fraud", output_dir=output_dir, memory_cap_bytes=1024**3)
            # Queued providers were cancelled; providers already running finish
            # in the background -- wait for them before the temp dir goes away.
            for thread in threading.enumerate():
                if thread.name.startswith("rapidtriage-artifact"):
                    thread.join(timeout=120)
            self.assertTrue(raised.exception.stage.startswith("artifacts:"))
            progress = json.loads((output_dir / RUN_PROGRESS_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(progress["status"], "failed")
            self.assertEqual(progress["stage"], "artifacts")
            self.assertEqual(progress["error"]["code"], "memory-cap")
            self.assertEqual(progress["error"]["error_type"], "MemoryCapExceeded")
            self.assertFalse((output_dir / "rapidtriage-manifest.json").exists())
            finished = list((output_dir / "artifacts").glob("rapidtriage-artifacts-*.json"))
            self.assertTrue(finished)


if __name__ == "__main__":
    unittest.main()


class EvidenceStatMemoTests(unittest.TestCase):
    def test_snapshot_paths_memoize_stat_and_resolve_for_the_run(self) -> None:
        from rapidtriage.core import files as files_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            target = root / "sub" / "evidence.txt"
            target.parent.mkdir()
            target.write_text("x", encoding="utf-8")
            files_module.enable_evidence_path_cache()
            try:
                paths = [path for path in files_module.iter_evidence_paths(root, "*") if path.name == "evidence.txt"]
                self.assertEqual(paths, [target])
                path = paths[0]
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_dir())
                self.assertEqual(path.resolve(), target.resolve())
                target.unlink()
                # The evidence tree is treated as immutable during a run.
                self.assertTrue(path.is_file())
                self.assertTrue(path.exists())
                self.assertFalse((path.parent / "missing.txt").exists())
                # Errors are memoized as plain fields, never as exception objects
                # (whose tracebacks would pin caller frames for the whole run).
                self.assertFalse(
                    any(isinstance(value, BaseException) for value in files_module._EVIDENCE_STAT_MEMO.values())
                )
                with self.assertRaises(FileNotFoundError):
                    (path.parent / "missing.txt").stat()
            finally:
                files_module.disable_evidence_path_cache()
            self.assertEqual(files_module._EVIDENCE_STAT_MEMO, {})
            self.assertFalse(path.is_file())  # cache off: live filesystem again


class CapabilitySignalTests(unittest.TestCase):
    def test_rows_are_flattened_once_and_counts_match_the_naive_scan(self) -> None:
        from rapidtriage.core import visible_capabilities as caps

        artifacts = {
            "windows-prefetch": {
                "summary": {"artifact_count": 3},
                "artifacts": [
                    {"artifact_type": "prefetch-file", "details": {"executable_hint": "POWERSHELL.EXE"}},
                    {"artifact_type": "prefetch-reference", "details": {"referenced_path": "C:/Windows/amcache.hve"}},
                    {"artifact_type": "other", "details": {"note": "nothing to see"}},
                ],
            },
            "eventlog": {"artifacts": [{"artifact_type": "eventlog-event", "details": {"event_id": "4624"}}]},
        }
        calls: list[int] = []
        original = caps.compact_text

        def counting(value, *, depth=0):
            if depth == 0:
                calls.append(id(value))
            return original(value, depth=depth)

        with mock.patch.object(caps, "compact_text", side_effect=counting):
            response = caps.build_visible_capability_response(run_summary={"summary": {}}, artifacts=artifacts)
        rows = [row for payload in artifacts.values() for row in payload["artifacts"]]
        self.assertEqual(sorted(calls), sorted(id(row) for row in rows))  # once per row

        def naive(terms):
            lower = [str(term).lower() for term in terms]
            count = 0
            for name, payload in artifacts.items():
                if any(term in name for term in lower):
                    count += caps.artifact_payload_size(payload)
                    continue
                count += sum(1 for row in payload["artifacts"] if any(t in original(row).lower() for t in lower))
            return count

        rendered = {item["id"]: item for group in response["groups"] for item in group["capabilities"]}
        for group in caps.CAPABILITY_GROUPS:
            for capability in group["capabilities"]:
                self.assertEqual(rendered[capability["id"]]["signal_count"], naive(capability["terms"]), capability["id"])
        index = caps.ArtifactSignalIndex(artifacts)
        self.assertEqual(index.signal_count(("powershell",)), 1)
        self.assertEqual(index.signal_count(("",)), 4)
        self.assertEqual(index.signal_count(("ws/am",)), naive(["ws/am"]))  # crosses a "/" boundary


class UnicodeImagePathTests(unittest.TestCase):
    def test_media_provider_decodes_korean_named_images(self) -> None:
        try:
            from PIL import Image
        except ImportError:  # pragma: no cover - optional dependency
            self.skipTest("Pillow unavailable")
        from rapidtriage.artifacts.media import MediaImageProvider
        from rapidtriage.core.image_io import imread_unicode_safe

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            folder = root / "Users" / "사용자" / "Downloads"
            folder.mkdir(parents=True)
            png_path = folder / "증명서.png"
            Image.new("RGB", (17, 9), (200, 30, 30)).save(png_path)
            jpg_path = folder / "휴가계획.jpg"
            exif = Image.Exif()
            exif[0x010F] = "RapidTriageCam"  # Make
            Image.new("RGB", (32, 24), (10, 120, 220)).save(jpg_path, exif=exif.tobytes())

            rows = {Path(row.path).name: row.details for row in MediaImageProvider().collect(root)}
            self.assertEqual(set(rows), {"증명서.png", "휴가계획.jpg"})
            png = rows["증명서.png"]
            self.assertTrue(png["decoded"])
            self.assertEqual((png["width"], png["height"]), (17, 9))
            self.assertTrue(png["perceptual_hash"])
            jpg = rows["휴가계획.jpg"]
            self.assertTrue(jpg["decoded"])
            self.assertEqual((jpg["width"], jpg["height"]), (32, 24))
            self.assertTrue(jpg["perceptual_hash"])
            self.assertTrue(jpg["exif_gps_profile"]["has_exif"])

            class FakeCv2:
                IMREAD_COLOR = 1

                def __init__(self) -> None:
                    self.calls: list[str] = []

                def imread(self, path, *flags):
                    self.calls.append("imread")
                    return "imread-result"

                def imdecode(self, buffer, flags):
                    self.calls.append("imdecode")
                    return buffer.size

            fake = FakeCv2()
            ascii_path = root / "plain.png"
            Image.new("RGB", (2, 2)).save(ascii_path)
            self.assertEqual(imread_unicode_safe(fake, ascii_path), "imread-result")
            self.assertEqual(imread_unicode_safe(fake, png_path), png_path.stat().st_size)
            self.assertEqual(fake.calls, ["imread", "imdecode"])
            self.assertIsNone(imread_unicode_safe(fake, folder / "없음.png"))


class RunListPollingTests(unittest.TestCase):
    def test_console_backs_off_when_idle_and_renders_progress(self) -> None:
        app_js = (Path(__file__).resolve().parents[1] / "rapidtriage" / "web" / "static" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("setInterval(loadRuns", app_js)
        self.assertIn("const RUN_POLL_IDLE_MS = 5000;", app_js)
        self.assertIn("const RUN_POLL_ACTIVE_MS = 1500;", app_js)
        self.assertIn("${renderRunProgress(run.progress)}", app_js)

    def test_run_list_carries_compact_progress_for_active_runs(self) -> None:
        from rapidtriage.api.app.routes_runs import compact_run_progress

        progress = {
            "status": "running",
            "stage": "artifacts",
            "completed_count": 3,
            "total_count": 24,
            "error_count": 0,
            "running": [{"kind": "eventlog", "started_at": "x"}, {"kind": "windows-prefetch"}],
            "providers": {"eventlog": {}},
            "updated_at": "now",
        }
        self.assertEqual(
            compact_run_progress(progress),
            {
                "status": "running",
                "stage": "artifacts",
                "completed_count": 3,
                "total_count": 24,
                "error_count": 0,
                "running": ["eventlog", "windows-prefetch"],
                "updated_at": "now",
            },
        )
        self.assertIsNone(compact_run_progress(None))


class StreamingCollectionMemoryTests(unittest.TestCase):
    def test_streaming_collection_memory_is_bounded_for_300k_rows(self) -> None:
        from rapidtriage.core.artifacts import stream_artifact_collection
        from rapidtriage.core.models import ArtifactRecord
        from rapidtriage.core.run.memory import current_memory_rss_bytes

        row_total = 300_000

        class SyntheticProvider:
            name = "synthetic-stream"
            collector_kind = "synthetic-stream"
            description = "synthetic rows"
            target_platform = "any"

            def supported(self) -> bool:
                return True

            def collect(self, root: Path):
                for index in range(row_total):
                    yield ArtifactRecord(
                        provider=self.name,
                        artifact_type="synthetic-row",
                        path=f"{root}/file-{index % 50}.bin",
                        supported=True,
                        details={
                            "parser": "synthetic",
                            "source_path": f"{root}/file-{index % 50}.bin",
                            "source_index": index,
                            "status": "ok" if index % 3 else "warn",
                            "forensic_review": {"gap_id": "#1", "checked": index % 2 == 0},
                        },
                    )

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            records_path = Path(tmp_dir) / "out" / "rapidtriage-artifacts-synthetic.jsonl"
            # Sample this process's RSS while streaming (tracemalloc would make
            # 300k rows x 3 passes several times slower).
            baseline = current_memory_rss_bytes()
            samples = [baseline]
            done = threading.Event()

            def sample() -> None:
                while not done.is_set():
                    samples.append(current_memory_rss_bytes())
                    done.wait(0.05)

            sampler = threading.Thread(target=sample, daemon=True)
            sampler.start()
            try:
                payload = stream_artifact_collection(
                    SyntheticProvider(),
                    resolve_input_root(root),
                    kind="synthetic-stream",
                    options={},
                    rule_set=None,
                    records_path=records_path,
                )
            finally:
                done.set()
                sampler.join()
            samples.append(current_memory_rss_bytes())
            peak = max(samples) - baseline
            with records_path.open(encoding="utf-8") as handle:
                lines = sum(1 for _ in handle)
            self.assertEqual(lines, row_total)
            self.assertEqual(payload["record_count"], row_total)
            self.assertEqual(payload["summary"]["artifact_type_counts"], {"synthetic-row": row_total})
            self.assertLess(peak, 150 * 1024 * 1024, f"peak RSS growth {peak / 2**20:.1f} MiB")
            self.assertEqual(len(payload["artifacts"]), 200)
            # Rows round-trip through the streamed profiles.
            first = next(iter_payload_records(payload))
            self.assertEqual(first["details"]["forensic_review"], {"gap_id": "#1", "checked": True})
            self.assertEqual(first["details"]["parser"], "synthetic")
            self.assertEqual(first["artifact_record"]["schema"], "ArtifactRecordV1")
