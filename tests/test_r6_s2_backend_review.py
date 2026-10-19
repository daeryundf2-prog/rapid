"""R6 S2 adversarial-review fixes (backend): each reviewer repro script as a regression test.

Synthetic data only (built in ``tempfile``). Covers: a planted ``mobile-inner`` marker never hides
evidence (item 1), the CLI / provider never write adb copies into the evidence and a re-run keeps
every copy listed (item 2), ``$Boot`` / ``$Bitmap`` icat streams are cut while streaming (item 3),
a negative / past-the-volume ``$Bitmap`` LCN is a Korean error (item 4), ``$Bitmap`` -> runs is
fast, cancellable and exact (item 5), AhnLab rows are streamed against the row budget (item 6),
a truncated adb member leaves no partial copy (item 7) and the "plausible" follow-ups.
"""

from __future__ import annotations

import io
import json
import os
import random
import sqlite3
import struct
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.api.app import analysis_kinds
from rapidtriage.api.app.analysis_kinds import run_output_pruner
from rapidtriage.artifacts.mobile import MobileExportProvider, adb_backup
from rapidtriage.artifacts.mobile.adb_backup import collect_adb_backup
from rapidtriage.artifacts.windows import av_ahnlab
from rapidtriage.artifacts.windows.av_ahnlab import collect_ahnlab_v3
from rapidtriage.core import ntfs_metadata, ntfs_unalloc
from rapidtriage.core.docs import scan_document_candidates
from rapidtriage.core.e01_native import RawMediaHandle, locate_ntfs_partition
from rapidtriage.core.files import (
    EXCLUSION_TOOL_OUTPUT_DIR,
    MOBILE_INNER_DIR_NAME,
    MOBILE_INNER_INDEX_NAME,
    MOBILE_INNER_MARKER_NAME,
    iter_evidence_paths,
    register_tool_output_dir,
    scan_file_candidates,
    unregister_tool_output_dir,
)
from rapidtriage.core.link_safe_walk import WalkStats, iter_files_no_links
from rapidtriage.core.ntfs_unalloc import (
    NtfsUnallocError,
    bitmap_unallocated_runs,
    boot_mft_consistency,
    open_unallocated_image,
)
from tests.test_r6_s2_unalloc_carve import _mft_record, boot_sector, build_ntfs_image

SQLITE_DB = b"SQLite format 3\x00" + b"\x10\x00" + b"\x00" * (4096 - 18)
WAL = b"\x37\x7f\x06\x82" + b"\x00" * 60
DOCX = b"PK\x03\x04" + b"0" * 100


def tar_of(members: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def ab_plain(payload: bytes) -> bytes:
    return b"ANDROID BACKUP\n5\n0\nnone\n" + payload


def files_under(root: Path) -> set[Path]:
    return {Path(dirpath) / name for dirpath, _dirs, names in os.walk(root) for name in names}


class _Temp(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)


# --- item 1: a planted marker never hides evidence ------------------------------------------


class PlantedMarkerTests(_Temp):
    def setUp(self) -> None:
        super().setUp()
        self.evidence = self.base / "evidence"
        self.hidden = self.evidence / "Users" / "bob" / MOBILE_INNER_DIR_NAME
        self.hidden.mkdir(parents=True)
        (self.hidden / MOBILE_INNER_MARKER_NAME).write_text("x", encoding="utf-8")
        (self.hidden / "plan.docx").write_bytes(DOCX)
        (self.evidence / "visible.docx").write_bytes(DOCX)

    def test_planted_marker_is_scanned_everywhere(self) -> None:
        names = sorted(path.name for path in iter_evidence_paths(self.evidence) if path.is_file())
        self.assertIn("plan.docx", names)
        docs = [Path(candidate.path).name for candidate in scan_document_candidates(self.evidence)]
        self.assertIn("plan.docx", docs)
        self.assertFalse(run_output_pruner(self.base / "out")(self.hidden))
        walked = [path.name for path in iter_files_no_links(self.evidence, prune_dir=run_output_pruner(self.base / "out"))]
        self.assertIn("plan.docx", walked)

    def test_only_the_runs_own_copy_folder_is_pruned_and_counted(self) -> None:
        output = self.evidence / "case-out"
        own_inner = output / MOBILE_INNER_DIR_NAME
        own_inner.mkdir(parents=True)
        (own_inner / "copy.docx").write_bytes(DOCX)
        stats = WalkStats()
        walked = [path.name for path in iter_files_no_links(self.evidence, prune_dir=run_output_pruner(output), stats=stats)]
        self.assertNotIn("copy.docx", walked)
        self.assertIn("plan.docx", walked)
        self.assertGreaterEqual(stats.pruned_dirs, 1)
        # a registered (active run) copy folder is pruned from the other walkers, counted in the file scan
        register_tool_output_dir(own_inner)
        self.addCleanup(unregister_tool_output_dir, own_inner)
        names = [path.name for path in iter_evidence_paths(self.evidence) if path.is_file()]
        self.assertNotIn("copy.docx", names)
        self.assertIn("plan.docx", names)
        exclusions: dict[str, object] = {}
        candidates, _scanned = scan_file_candidates(
            self.evidence,
            categories=["documents"],
            name_contains=[],
            path_contains=[],
            extensions=[],
            modified_after=None,
            modified_before=None,
            limit=0,
            exclusions=exclusions,
        )
        self.assertIn("plan.docx", [candidate.name for candidate in candidates])
        self.assertNotIn("copy.docx", [candidate.name for candidate in candidates])
        self.assertEqual(exclusions["reasons"].get(EXCLUSION_TOOL_OUTPUT_DIR), 1)  # type: ignore[union-attr]


# --- item 2 + 7 + plausible: adb copies --------------------------------------------------------


class AdbCopyTests(_Temp):
    def setUp(self) -> None:
        super().setUp()
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.inner = self.base / "out" / MOBILE_INNER_DIR_NAME

    def test_truncated_member_leaves_no_partial_copy(self) -> None:
        members = [
            ("apps/x/db/foo.db-wal", WAL),
            ("apps/x/db/Foo.db", SQLITE_DB),
            ("apps/x/db/foo.db", SQLITE_DB),
            ("apps/x/f/foo.db", SQLITE_DB),
            ("apps/x/db/trunc.db", SQLITE_DB + b"\0" * (10 * 1024 * 1024 - len(SQLITE_DB))),
        ]
        raw = tar_of(members)
        backup = self.evidence / "b.ab"
        backup.write_bytes(ab_plain(raw[: len(raw) - 9 * 1024 * 1024]))
        copies: list[dict[str, object]] = []
        records = list(collect_adb_backup(backup, inner_root=self.inner, inner_copies=copies))
        self.assertEqual(records[0].details["status"], "partial")
        on_disk = {path.name for path in self.inner.rglob("*") if path.is_file()} - {MOBILE_INNER_MARKER_NAME}
        self.assertNotIn("trunc.db", on_disk)
        self.assertEqual(on_disk, {Path(str(entry["inner_path"])).name for entry in copies})
        self.assertEqual(records[0].details["inner_databases_extracted"], 3)

    def test_rerun_keeps_every_copy_listed(self) -> None:
        (self.evidence / "phone.ab").write_bytes(ab_plain(tar_of([("apps/com.example/db/app.db", SQLITE_DB)])))
        for _ in range(2):
            list(MobileExportProvider(inner_dir=self.inner).collect(self.evidence))
        index = json.loads((self.inner / MOBILE_INNER_INDEX_NAME).read_text(encoding="utf-8"))
        listed = {os.path.normcase(str(entry["inner_path"])) for entry in index["copies"]}
        on_disk = {
            os.path.normcase(str(path))
            for path in self.inner.rglob("*")
            if path.is_file() and path.name not in {MOBILE_INNER_MARKER_NAME, MOBILE_INNER_INDEX_NAME}
        }
        self.assertEqual(len(on_disk), 2)
        self.assertEqual(listed, on_disk, "no unlisted -1 duplicate")
        self.assertEqual(index["copy_count"], 2)

    def test_folder_name_needs_no_full_backup_read(self) -> None:
        backup = self.evidence / "phone.ab"
        backup.write_bytes(ab_plain(tar_of([("apps/com.example/db/app.db", SQLITE_DB)])))
        list(collect_adb_backup(backup, inner_root=self.inner, inner_copies=[]))
        self.assertTrue((self.inner / adb_backup._backup_key(backup)).is_dir())
        self.assertFalse(hasattr(adb_backup, "_file_sha256"))

    def test_run_total_cap_across_backups(self) -> None:
        for name in ("a.ab", "b.ab"):
            (self.evidence / name).write_bytes(ab_plain(tar_of([("apps/com.example/db/app.db", SQLITE_DB)])))
        with mock.patch.object(adb_backup, "MAX_RUN_INNER_EXTRACT_BYTES", len(SQLITE_DB) + 10):
            rows = list(MobileExportProvider(inner_dir=self.inner).collect(self.evidence))
        headers = [row.details for row in rows if row.artifact_type == "android-backup"]
        self.assertEqual(sorted(header["inner_databases_extracted"] for header in headers), [0, 1])
        skipped = [row.details for row in rows if row.details.get("inner_extract_skipped_reason") == "total"]
        self.assertEqual(len(skipped), 1)

    def test_provider_and_cli_never_write_into_the_evidence(self) -> None:
        from rapidtriage.cli import main

        (self.evidence / "phone.ab").write_bytes(ab_plain(tar_of([("apps/com.example/db/app.db", SQLITE_DB)])))
        before = files_under(self.evidence)
        provider = MobileExportProvider(inner_dir=self.evidence / "nested" / MOBILE_INNER_DIR_NAME)
        rows = list(provider.collect(self.evidence))
        self.assertTrue(any(row.artifact_type == "android-backup-member" for row in rows))
        self.assertFalse(any(row.details.get("recovery_method") == "adb-backup-extracted" for row in rows))
        self.assertTrue(any("증거 폴더 안" in note for note in provider.collection_notes))
        self.assertEqual(files_under(self.evidence), before)
        output = self.evidence / "mobile.json"
        stderr = io.StringIO()
        with mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", stderr):
            code = main(["artifacts", str(self.evidence), "--kind", "mobile-export", "--output", str(output)])
        self.assertIn(code, (0, None))
        self.assertIn("증거 폴더", stderr.getvalue())
        self.assertFalse((self.evidence / MOBILE_INNER_DIR_NAME).exists())


# --- item 3: icat streams cut while streaming ----------------------------------------------------


class BoundedStreamTests(_Temp):
    ENDLESS = (sys.executable, "-c", "import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)")

    def test_endless_stream_is_killed_at_the_cap(self) -> None:
        target = self.base / "Boot.bin"
        started = time.monotonic()
        result, capped, size = ntfs_metadata.run_stream_capped(
            ntfs_metadata.default_stream_runner, self.ENDLESS, target, ntfs_metadata.BOOT_MAX_BYTES
        )
        self.assertLess(time.monotonic() - started, 30)
        self.assertTrue(capped)
        self.assertIsNone(size)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(target.stat().st_size, ntfs_metadata.BOOT_MAX_BYTES)

    def test_short_stream_is_complete(self) -> None:
        target = self.base / "out.bin"
        command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'y' * 1000); sys.exit(3)"]
        result, capped, _size = ntfs_metadata.run_stream_capped(ntfs_metadata.default_stream_runner, command, target, 8192)
        self.assertFalse(capped)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(target.read_bytes(), b"y" * 1000)

    def test_default_boot_and_bitmap_runners_pass_a_cap(self) -> None:
        seen: list[int] = []

        def fake_bounded(command, output_path, *, max_bytes, chunk_bytes=0):
            seen.append(max_bytes)
            output_path.write_bytes(b"\x00" * min(max_bytes, 600))
            result = ntfs_metadata.subprocess.CompletedProcess(list(command), 0, b"", b"")
            result.stream_capped = True  # type: ignore[attr-defined]
            return result

        with mock.patch.object(ntfs_metadata, "bounded_stream_runner", fake_bounded):
            entry, _reason = ntfs_metadata._extract_boot(ntfs_metadata.default_stream_runner, self.base / "img", 0, self.base)
            with self.assertRaises(NtfsUnallocError):
                ntfs_unalloc._read_bitmap_icat(self.base / "img", 0, self.base / "work", ntfs_unalloc._default_stream_runner)
        self.assertEqual(seen, [ntfs_metadata.BOOT_MAX_BYTES, ntfs_unalloc.MAX_BITMAP_BYTES])
        self.assertIsNotNone(entry)
        self.assertEqual(entry["extraction_mode"], "first-8KiB")  # type: ignore[index]
        self.assertFalse((self.base / "work" / "Bitmap.bin").exists())


# --- item 4 + 5 + EWF partial: unallocated clusters ---------------------------------------------


def negative_lcn_image(path: Path) -> None:
    image = bytearray(64 * 4096)
    vbr = bytearray(512)
    vbr[3:11] = b"NTFS    "
    struct.pack_into("<H", vbr, 0x0B, 512)
    vbr[0x0D] = 8
    struct.pack_into("<Q", vbr, 0x28, 64 * 8)
    struct.pack_into("<Q", vbr, 0x30, 1)
    vbr[0x40] = 0xF6
    vbr[510:512] = b"\x55\xaa"
    image[0:512] = vbr
    record = bytearray(1024)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 0x30, 3)
    struct.pack_into("<H", record, 0x14, 0x38)
    record[0x30:0x32] = b"\x01\x00"
    record[510:512] = b"\x01\x00"
    record[1022:1024] = b"\x01\x00"
    attr = 0x38
    struct.pack_into("<II", record, attr, 0x80, 0x50)
    record[attr + 8] = 1
    struct.pack_into("<H", record, attr + 0x20, 0x40)
    struct.pack_into("<Q", record, attr + 0x30, 8)
    record[attr + 0x40 : attr + 0x43] = bytes([0x11, 0x01, 0xF0])  # one cluster at LCN -16
    struct.pack_into("<I", record, attr + 0x50, 0xFFFFFFFF)
    image[4096 + 6 * 1024 : 4096 + 7 * 1024] = record
    path.write_bytes(bytes(image))


def naive_runs(bitmap: bytes, total: int, max_runs: int) -> tuple[list[tuple[int, int]], int, bool]:
    runs: list[tuple[int, int]] = []
    free = 0
    for cluster in range(min(total, len(bitmap) * 8)):
        if not bitmap[cluster // 8] & (1 << (cluster % 8)):
            free += 1
            if runs and runs[-1][0] + runs[-1][1] == cluster:
                runs[-1] = (runs[-1][0], runs[-1][1] + 1)
            else:
                runs.append((cluster, 1))
    return runs[:max_runs], free, len(runs) > max_runs


class UnallocatedTests(_Temp):
    def test_negative_lcn_is_a_korean_error(self) -> None:
        image = self.base / "x.dd"
        negative_lcn_image(image)
        with self.assertRaises(NtfsUnallocError) as caught:
            with open_unallocated_image(image, work_dir=self.base / "w", tool_resolver=lambda name: None):
                pass
        self.assertIn("볼륨 범위", str(caught.exception))

    def test_value_errors_become_korean_errors(self) -> None:
        image = build_ntfs_image(self.base / "d.dd")
        with mock.patch.object(ntfs_unalloc, "bitmap_unallocated_runs", side_effect=OverflowError("boom")):
            with self.assertRaises(NtfsUnallocError):
                with open_unallocated_image(image.path, work_dir=self.base / "w", tool_resolver=lambda name: None):
                    pass

    def test_bitmap_fast_on_alternating_bits(self) -> None:
        bitmap = b"\x55" * (8 * 1024 * 1024)
        started = time.monotonic()
        result = bitmap_unallocated_runs(bitmap, len(bitmap) * 8)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.runs), ntfs_unalloc.MAX_RUNS)
        self.assertEqual(result.free_clusters, len(bitmap) * 4)

    def test_bitmap_matches_naive_randomized(self) -> None:
        rng = random.Random(1)
        for trial in range(300):
            size = rng.randint(1, 300)
            bitmap = bytes(rng.choice([0, 0, 0xFF, 0xFF, rng.randint(0, 255)]) for _ in range(size))
            total = rng.randint(1, size * 8 + 20)
            max_runs = rng.choice([1, 5, 1000])
            result = bitmap_unallocated_runs(bitmap, total, max_runs=max_runs)
            runs, free, truncated = naive_runs(bitmap, total, max_runs)
            self.assertEqual((result.runs, result.free_clusters, result.truncated), (runs, free, truncated), trial)

    def test_bitmap_is_cancellable(self) -> None:
        calls = []

        def check() -> None:
            calls.append(1)
            if len(calls) > 2:
                raise RuntimeError("cancelled")

        with self.assertRaises(RuntimeError):
            bitmap_unallocated_runs(b"\x55" * (16 * 1024 * 1024), 16 * 1024 * 1024 * 8, check_cancel=check)

    def test_icat_offset_uses_512_byte_units(self) -> None:
        image = build_ntfs_image(self.base / "d.dd")
        commands: list[list[str]] = []

        def fake_icat(command, output_path: Path):
            commands.append(list(command))
            return ntfs_metadata.subprocess.CompletedProcess(list(command), 1, b"", b"no")

        with open_unallocated_image(
            image.path, work_dir=self.base / "w", stream_runner=fake_icat, tool_resolver=lambda name: "/bin/icat"
        ) as source:
            self.assertEqual(source.bitmap_method, "native-mft-record-6")
        self.assertEqual(commands[0][2], str(image.partition_offset // 512))


class PartialImageScanTests(_Temp):
    """EWF read error mid-scan: candidates found so far are kept and the summary says partial."""

    def test_read_error_keeps_candidates(self) -> None:
        from tests.test_r6_s2_unalloc_carve import ImageUnallocatedAnalysisTests as Base

        case = Base("test_default_sources_unchanged")
        case.setUp()
        self.addCleanup(case.tearDown)
        original = ntfs_unalloc.UnallocatedImage.windows

        def failing_windows(self_, read_limit, *, stats, check_cancel=None):
            for window in original(self_, read_limit, stats=stats, check_cancel=check_cancel):
                yield window
                if window.image_offset + len(window.data) > case.big_offset + 100:
                    raise OSError("EWF chunk read failed")

        with mock.patch.object(ntfs_unalloc.UnallocatedImage, "windows", failing_windows):
            created = case.submit({"sources": ["image-unallocated"], "image_path": str(case.image.path)})
            state = case.wait(created.json()["analysis_id"])
        self.assertEqual(state["status"], "completed", state)
        summary = state["summary"]
        self.assertEqual(summary["image_unallocated_status"], "partial")
        self.assertIn("EWF chunk read failed", summary["image_unallocated_error"])
        self.assertTrue(summary["image_unallocated_truncated"])
        self.assertEqual([row["details"]["url"] for row in case.rows(state["analysis_id"])], [case.BIG_URL.decode()])


class SectorSizeTests(_Temp):
    def test_4kn_mbr_partition_is_found(self) -> None:
        image = bytearray(16 * 4096 + 64 * 4096)
        entry = bytearray(16)
        entry[4] = 0x07
        struct.pack_into("<II", entry, 8, 16, 64)  # LBA 16 in 4096-byte sectors
        image[0x1BE:0x1CE] = entry
        image[510:512] = b"\x55\xaa"
        image[16 * 4096 : 16 * 4096 + 512] = boot_sector(sectors_per_cluster=1, total_sectors=512)
        path = self.base / "4kn.dd"
        path.write_bytes(bytes(image))
        handle = RawMediaHandle(path)
        self.addCleanup(handle.close)
        partition = locate_ntfs_partition(handle)
        self.assertEqual((partition["byte_offset"], partition["sector_size_bytes"]), (16 * 4096, 4096))

    def test_4kn_gpt_sector_size_detected(self) -> None:
        path = self.base / "gpt.dd"
        data = bytearray(8192)
        data[4096:4104] = b"EFI PART"
        path.write_bytes(bytes(data))
        handle = RawMediaHandle(path)
        self.addCleanup(handle.close)
        self.assertEqual(handle.bytes_per_sector, 4096)


class SiblingBootTests(_Temp):
    def record0(self, lcn: int) -> bytes:
        attr = bytearray(0x48)
        struct.pack_into("<IIBB", attr, 0, 0x80, 0x48, 1, 0)
        struct.pack_into("<H", attr, 0x20, 0x40)
        attr[0x40:0x44] = bytes([0x11, 0x04, lcn, 0x00])
        return _mft_record(0, bytes(attr))

    def test_same_volume_check(self) -> None:
        boot = boot_sector(sectors_per_cluster=2, total_sectors=1200)  # mft_lcn 4, 1024-byte records
        self.assertEqual(boot_mft_consistency(boot, self.record0(4), 1024), ("match", ""))
        verdict, reason = boot_mft_consistency(boot, self.record0(9), 1024)
        self.assertEqual(verdict, "mismatch")
        self.assertIn("다른 볼륨", reason)
        self.assertEqual(boot_mft_consistency(boot, self.record0(4), 4096)[0], "mismatch")
        self.assertEqual(boot_mft_consistency(b"\x00" * 512, self.record0(4), 1024)[0], "mismatch")
        self.assertEqual(boot_mft_consistency(boot, _mft_record(0, b""), 1024)[0], "unverified")

    def test_mismatched_sibling_boot_is_skipped(self) -> None:
        mft = self.base / "$MFT"
        mft.write_bytes(self.record0(9) * 4)
        boot = self.base / "$Boot"
        boot.write_bytes(boot_sector(sectors_per_cluster=2, total_sectors=1200))
        verdict, reason = analysis_kinds._sibling_boot_check(boot, mft)
        self.assertEqual(verdict, "mismatch", reason)
        self.assertIsNone(analysis_kinds.ntfs_cluster_size(None, None, [mft], sibling_boot=False))
        self.assertEqual(analysis_kinds.ntfs_cluster_size(None, None, [mft], sibling_boot=False, boot_files=[boot]), 1024)


# --- item 6 + plausible: AhnLab ----------------------------------------------------------------


class AhnLabStreamingTests(_Temp):
    def product(self) -> Path:
        folder = self.base / "ProgramData" / "AhnLab" / "V3Lite" / "Log"
        folder.mkdir(parents=True)
        return folder

    def test_five_big_logs_are_fast_and_bounded(self) -> None:
        folder = self.product()
        line = "2026-10-18 09:15:01 detected Trojan C:\\x\\a.exe\n" * 20000
        for index in range(5):
            (folder / f"detect_log{index}.log").write_text(line, encoding="utf-8")
        original = av_ahnlab._ahnlab_root_records
        produced: list[int] = []

        def counting(*args, **kwargs):
            for record in original(*args, **kwargs):
                produced.append(1)
                yield record

        started = time.monotonic()
        with mock.patch.object(av_ahnlab, "_ahnlab_root_records", counting):
            records = list(collect_ahnlab_v3(self.base, "p"))
        self.assertLess(time.monotonic() - started, 10)
        detections = [record for record in records if record.artifact_type == "av-detection-log"]
        self.assertEqual(len(detections), av_ahnlab.MAX_ROWS_PER_TYPE)
        self.assertLessEqual(len(produced), av_ahnlab.MAX_ROWS_PER_TYPE + 10)
        outcomes = sorted(
            record.details["parse_outcome"] for record in records if record.details.get("presence_kind") == "log-candidate"
        )
        self.assertEqual(outcomes.count("skipped-row-cap"), 4)
        # base_details once per file: the source path is shared, rows are separate dicts
        self.assertIsNot(detections[0].details, detections[1].details)
        self.assertIsNot(detections[0].details["risk_flags"], detections[1].details["risk_flags"])

    def test_quarantine_like_folders_are_never_opened(self) -> None:
        folder = self.product().parent
        for name in ("격리함", "V3 Vault Backup", "QuarantineStore"):
            inside = folder / name
            inside.mkdir()
            (inside / "detect_log.txt").write_text("2026-10-18 09:15:01 detected Trojan C:\\x\\a.exe\n", encoding="utf-8")
        opened: list[str] = []
        real_open = Path.open

        def watching_open(self_, *args, **kwargs):
            opened.append(str(self_))
            return real_open(self_, *args, **kwargs)

        with mock.patch.object(Path, "open", watching_open):
            records = list(collect_ahnlab_v3(self.base, "p"))
        quarantines = [record.details for record in records if record.details.get("presence_kind") == "quarantine-folder"]
        self.assertEqual(len(quarantines), 3)
        self.assertTrue(all(details["file_count"] == 1 for details in quarantines))
        self.assertFalse([path for path in opened if "detect_log.txt" in path])
        self.assertFalse([record for record in records if record.artifact_type == "av-detection-log"])

    def test_quarantine_walk_depth_and_dir_caps(self) -> None:
        folder = self.product().parent / "Quarantine"
        deep = folder
        for index in range(30):
            deep = deep / f"d{index}"
        deep.mkdir(parents=True)
        (deep / "x.bin").write_bytes(b"x")
        records = list(collect_ahnlab_v3(self.base, "p"))
        details = next(record.details for record in records if record.details.get("presence_kind") == "quarantine-folder")
        self.assertTrue(details["count_truncated"])
        self.assertEqual(details["file_count"], 0)
        with mock.patch.object(av_ahnlab, "MAX_QUARANTINE_DIRS", 3):
            records = list(collect_ahnlab_v3(self.base, "p"))
        details = next(record.details for record in records if record.details.get("presence_kind") == "quarantine-folder")
        self.assertTrue(details["count_truncated"])

    def test_sqlite_secret_columns_are_masked(self) -> None:
        folder = self.product()
        database = folder / "detect_history.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE detect_history(id INTEGER PRIMARY KEY, file_path TEXT, detect_date TEXT, password TEXT, api_key TEXT, note TEXT)")
        connection.execute(
            "INSERT INTO detect_history(file_path, detect_date, password, api_key, note) VALUES (?,?,?,?,?)",
            ("C:\\x\\a.exe", "2026-10-18 09:15:01", "hunter2-SECRET", "AKIA-SECRET", "y" * 5000),
        )
        connection.commit()
        connection.close()
        records = list(collect_ahnlab_v3(self.base, "p"))
        rows = [record.details for record in records if record.artifact_type == "av-detection-log"]
        self.assertEqual(len(rows), 1)
        message = rows[0]["message"]
        self.assertNotIn("SECRET", message)
        self.assertIn("숨김", message)
        self.assertLessEqual(len(message), 1000)


if __name__ == "__main__":
    unittest.main()
