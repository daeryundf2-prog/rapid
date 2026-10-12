"""Analysis workbench API (plan analysis-workbench-p1 §3 / §5 "B")."""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import (
        analyses,
        analysis_kinds,
        artifact_sort,
        create_app,
        files_ntfs,
    )

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core import vsc
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.ntfs_metadata import missing_ntfs_metadata_tools

TOKEN = "analyses-test-token"
JPEG = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00" + b"\x11" * 64 + b"\xff\xd9"


def filetime(value: str) -> int:
    moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int((moment.timestamp() + 11644473600) * 10_000_000)


def mft_record(
    *, name: str, parent: int, in_use: bool, directory: bool, created: str, size: int = 0, record_size: int = 1024
) -> bytes:
    """One ``record_size``-byte FILE record: $STANDARD_INFORMATION + $FILE_NAME, fixups applied."""
    record = bytearray(record_size)
    record[0:4] = b"FILE"
    sectors = record_size // 512
    first_attribute = (0x30 + 2 * (sectors + 1) + 7) // 8 * 8
    struct.pack_into("<HH", record, 0x04, 0x30, sectors + 1)  # update sequence array offset/count
    struct.pack_into("<H", record, 0x10, 1)  # sequence number
    struct.pack_into("<H", record, 0x12, 1)  # hard links
    struct.pack_into("<H", record, 0x14, first_attribute)  # first attribute
    struct.pack_into("<H", record, 0x16, (1 if in_use else 0) | (2 if directory else 0))
    struct.pack_into("<I", record, 0x1C, record_size)
    times = struct.pack("<QQQQ", filetime(created), filetime(created), filetime(created), filetime("2024-03-01T00:00:00Z"))
    si_value = times + struct.pack("<I", 0x20) + bytes(36)
    offset = first_attribute
    struct.pack_into("<IIBBHHHIHBB", record, offset, 0x10, 24 + len(si_value), 0, 0, 0x18, 0, 0, len(si_value), 0x18, 0, 0)
    record[offset + 24 : offset + 24 + len(si_value)] = si_value
    offset += 24 + len(si_value)
    encoded = name.encode("utf-16le")
    fn_value = (
        struct.pack("<Q", parent | (1 << 48))
        + times
        + struct.pack("<QQII", size, size, 0x20, 0)
        + struct.pack("<BB", len(name), 1)
        + encoded
    )
    attr_len = (24 + len(fn_value) + 7) // 8 * 8
    struct.pack_into("<IIBBHHHIHBB", record, offset, 0x30, attr_len, 0, 0, 0x18, 0, 1, len(fn_value), 0x18, 0, 0)
    record[offset + 24 : offset + 24 + len(fn_value)] = fn_value
    offset += attr_len
    struct.pack_into("<I", record, offset, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x18, offset + 8)
    struct.pack_into("<H", record, 0x30, 1)  # USN 1; original sector tails stay 0
    for sector in range(sectors):
        struct.pack_into("<H", record, 512 * (sector + 1) - 2, 1)
    return bytes(record)


def synthetic_mft(
    extra: dict[int, bytes] | None = None, *, alice_created: str = "2024-01-02T03:04:05Z", record_size: int = 1024
) -> bytes:
    def make(**kwargs) -> bytes:
        return mft_record(record_size=record_size, **kwargs)

    records = {
        5: make(name=".", parent=5, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
        64: make(name="Users", parent=5, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
        65: make(name="alice.txt", parent=64, in_use=True, directory=False, created=alice_created, size=11),
        66: make(name="deleted.bin", parent=64, in_use=False, directory=False, created="2024-01-03T00:00:00Z"),
        **(extra or {}),
    }
    return b"".join(records.get(number, bytes(record_size)) for number in range(max(records) + 1))


def usn_record(name: str, *, parent: int, entry: int, usn: int) -> bytes:
    encoded = name.encode("utf-16le")
    length = (60 + len(encoded) + 7) // 8 * 8
    head = struct.pack(
        "<IHHQQQQIIIIHH",
        length,
        2,
        0,
        entry | (1 << 48),
        parent | (1 << 48),
        usn,
        filetime("2024-01-02T03:04:05Z"),
        0x100,
        0,
        0,
        0x20,
        len(encoded),
        60,
    )
    return (head + encoded).ljust(length, b"\x00")


def tiny_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = b"\x00\xff\xff\xff"
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def write_volatility(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "windows.pslist.json").write_text(
        json.dumps({"rows": [{"PID": 4242, "PPID": 888, "ImageFileName": "powershell.exe", "CommandLine": "powershell.exe -enc AAA"}]}),
        encoding="utf-8",
    )
    (root / "windows.netscan.jsonl").write_text(
        json.dumps({"PID": 4242, "ImageFileName": "powershell.exe", "LocalAddr": "10.0.0.5:5151", "ForeignAddr": "203.0.113.10:443"}) + "\n",
        encoding="utf-8",
    )


def build_case_db(path: Path, case_id: str, sha256: str, *, with_source: bool = False) -> None:
    """One shared file record; ``with_source`` ties it to an evidence source like a persisted run (locatable)."""
    database = open_case_database(path)
    database.create_case(case_id=case_id, name=case_id)
    with database.connect() as connection:
        source_id = None
        if with_source:
            source_id = connection.execute(
                "INSERT INTO evidence_source (citation_id, case_id, display_name, source_type, original_path, added_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (f"{case_id}-S1", case_id, "disk", "e01", "/evidence/disk.E01", "2026-01-01T00:00:00+00:00"),
            ).lastrowid
        connection.execute(
            "INSERT INTO file_record (citation_id, case_id, evidence_source_id, path, normalized_path, extension, hash_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f"{case_id}-F1", case_id, source_id, "/evidence/shared.pdf", "/evidence/shared.pdf", ".pdf", sha256),
        )


def write_run(base: Path, name: str, evidence: Path, *, extra_outputs: dict[str, object] | None = None) -> Path:
    run_dir = base / name
    run_dir.mkdir()
    outputs: dict[str, str] = {}
    for output_name, payload in (extra_outputs or {}).items():
        path = run_dir / f"{output_name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        outputs[output_name] = str(path)
    summary_path = run_dir / "rapidtriage-run-summary.json"
    outputs["summary"] = str(summary_path)
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(evidence),
                "scan_scope_root": str(evidence),
                "output_dir": str(run_dir),
                "source": {"type": "e01", "source_path": str(evidence / "disk.E01"), "analysis_root": str(evidence)},
                "outputs": outputs,
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def make_directory_link(target: Path, link: Path) -> list[str]:
    """Junction (Windows: ``_winapi``, then ``mklink /J``) or symlink; returns the errors when none could be made."""
    errors: list[str] = []
    if os.name == "nt":
        try:
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
            return []
        except (OSError, AttributeError, ImportError) as exc:
            errors.append(f"CreateJunction: {exc}")
        try:
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and link.is_dir():
                return []
            errors.append(f"mklink /J: exit {result.returncode} {result.stderr.strip()}")
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"mklink /J: {exc}")
    try:
        os.symlink(target, link, target_is_directory=True)
        return []
    except (OSError, NotImplementedError) as exc:
        errors.append(f"symlink: {exc}")
    return errors


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for analysis API tests")
class AnalysisApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        files_ntfs.clear_ntfs_index_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.evidence = self.base / "evidence"
        (self.evidence / "Users").mkdir(parents=True)
        (self.evidence / "Users" / "alice.txt").write_text("hello alice", encoding="utf-8")
        (self.evidence / "blob1.bin").write_bytes(b"\x00" * 100 + JPEG + b"\x00" * 50)
        (self.evidence / "blob2.bin").write_bytes(b"\x01" * 10 + JPEG + JPEG)
        (self.evidence / "notes.txt").write_bytes(JPEG)  # excluded by ext=.bin
        (self.evidence / "disk.E01").write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(64))
        (self.evidence / "photo.png").write_bytes(tiny_png())
        self.media_records = self.base / "media-records.jsonl"
        self.media_records.write_text(
            json.dumps({"artifact_type": "image", "path": str(self.evidence / "photo.png"), "details": {}}) + "\n",
            encoding="utf-8",
        )
        system_rows = [
            {"artifact_type": "web-server-log", "path": str(self.evidence / "w3svc.log"), "details": {"n": 1}},
            {"artifact_type": "service", "path": str(self.evidence / "svc"), "details": {"n": 2}},
            {"artifact_type": "webshell-source-candidate", "path": str(self.evidence / "cmd.aspx"), "details": {"n": 3}},
            {"artifact_type": "service", "path": str(self.evidence / "svc2"), "details": {"n": 4}},
        ]
        self.system_records = self.base / "system-records.jsonl"
        self.system_records.write_text("\n".join(json.dumps(row) for row in system_rows) + "\n", encoding="utf-8")
        files = {
            "candidates": [
                {"path": str(self.evidence / "Users" / "alice.txt"), "name": "alice.txt", "size": 11, "categories": ["documents"]},
                {"path": str(self.evidence / "blob1.bin"), "name": "blob1.bin", "size": 164, "categories": ["archives"]},
                {"path": str(self.evidence / "notes.txt"), "name": "notes.txt", "size": 7, "categories": ["documents"]},
            ]
        }
        self.run_dir = write_run(
            self.base,
            "run",
            self.evidence,
            extra_outputs={
                "files": files,
                "artifacts_media-image": {"records_path": str(self.media_records), "record_count": 1, "artifacts": []},
                "artifacts_windows-system": {
                    "records_path": str(self.system_records),
                    "record_count": 4,
                    "artifacts": [],
                    "summary": {
                        "artifact_count": 4,
                        "artifact_type_counts": {"web-server-log": 1, "service": 2, "webshell-source-candidate": 1},
                    },
                },
            },
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    # -- helpers ---------------------------------------------------------------

    def submit(self, kind: str, options: dict[str, object] | None = None, *, expect: int = 202) -> dict[str, object]:
        response = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": kind, "options": options or {}})
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def wait(self, analysis_id: str, timeout: float = 20.0) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while True:
            state = self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}").json()
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                return state
            if time.monotonic() > deadline:
                self.fail(f"analysis did not finish: {state}")
            time.sleep(0.02)

    def rows(self, analysis_id: str, **params) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}/rows", params=params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def run_ntfs(
        self, *, usn: bytes | None = None, mft: bytes | None = None, options: dict[str, object] | None = None
    ) -> dict[str, object]:
        def fake_extract(image, output_dir, *, partition_start_sector=None, sparse_journal=True):
            output_dir.mkdir(parents=True, exist_ok=True)
            mft_path = output_dir / "MFT.bin"
            mft_path.write_bytes(mft if mft is not None else synthetic_mft())
            outputs = {"mft": {"path": str(mft_path), "size_bytes": mft_path.stat().st_size, "sha256": "x"}}
            if usn is not None:
                journal = output_dir / "UsnJrnl_J.bin"
                journal.write_bytes(usn)
                outputs["usn_journal"] = {"path": str(journal), "size_bytes": len(usn), "sha256": "y"}
            return {"outputs": outputs, "extraction_status": "complete", "partition": {"start_sector": 2048}, "skipped": []}

        with patch.object(analysis_kinds, "NTFS_EXTRACTOR", fake_extract):
            created = self.submit("ntfs-meta", options)
            return self.wait(str(created["analysis_id"]))

    # -- §3.1 lifecycle ------------------------------------------------------------

    def test_carve_runs_and_rows_page_sort_locate(self) -> None:
        created = self.submit("carve", {"ext": ".bin", "max_candidates": 50})
        self.assertEqual(created["status"], "queued")
        self.assertEqual(created["kind"], "carve")
        state = self.wait(str(created["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["progress"]["total"], 2)  # two .bin files = two units
        self.assertEqual(state["progress"]["done"], 2)
        self.assertEqual(state["progress"]["percent"], 100.0)
        self.assertEqual(state["row_count"], 3)
        self.assertTrue(Path(state["output_dir"], "analysis.json").is_file())
        page = self.rows(str(created["analysis_id"]), limit=10)
        self.assertEqual(page["record_count"], 3)
        self.assertEqual([row["record_index"] for row in page["rows"]], [0, 1, 2])
        first = page["rows"][0]
        self.assertEqual(first["artifact_type"], "carve-row")
        self.assertEqual(first["details"]["signature_kind"], "jpeg")
        self.assertEqual(first["details"]["offset"], 100)
        self.assertEqual(first["details"]["length"], len(JPEG))
        self.assertEqual(first["path"], str(self.evidence / "blob1.bin"))
        for key in ("source_path", "sha256", "confidence", "notes", "extracted_path"):
            self.assertIn(key, first["details"])
        sorted_page = self.rows(str(created["analysis_id"]), limit=10, sort="details.offset", order="desc", locate=0)
        deadline = time.monotonic() + 10
        while sorted_page["sort"]["status"] == "building" and time.monotonic() < deadline:
            time.sleep(0.02)
            sorted_page = self.rows(str(created["analysis_id"]), limit=10, sort="details.offset", order="desc", locate=0)
        self.assertEqual(sorted_page["sort"]["status"], "ready", sorted_page["sort"])
        offsets = [row["details"]["offset"] for row in sorted_page["rows"]]
        self.assertEqual(offsets, sorted(offsets, reverse=True))
        self.assertEqual(sorted_page["sort"]["position"], [row["record_index"] for row in sorted_page["rows"]].index(0))
        cache_kinds = {key[1] for key in artifact_sort.SORT_INDEX_CACHE.cached_keys()}
        self.assertIn(f"analysis:{created['analysis_id']}#3", cache_kinds)  # bounded by row_count
        filtered = self.rows(str(created["analysis_id"]), path_contains="BLOB2")
        self.assertEqual(len(filtered["rows"]), 2)
        self.assertTrue(all(row["path"].endswith("blob2.bin") for row in filtered["rows"]))
        listing = self.client.get(f"/api/runs/{self.run_id}/analyses").json()["analyses"]
        self.assertEqual(listing[0]["analysis_id"], created["analysis_id"])

    def test_carve_candidate_cap_finishes_at_full_progress(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin", "max_candidates": 1})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["row_count"], 1)
        self.assertTrue(state["summary"]["candidate_cap_reached"])
        self.assertEqual(state["progress"]["percent"], 100.0)
        self.assertIn("후보 상한", state["progress"]["message"])

    def test_same_kind_running_conflicts_and_cancel_keeps_partial_rows(self) -> None:
        # blob1.bin is scanned, blob2.bin is held: the cancel lands inside blob2's scan
        # (per-chunk check), so blob1's row is kept and blob2 yields none.
        slow_scan, entered, gate = self._blocking_scan(block_on_call=2)
        with patch.object(analysis_kinds, "_scan_source", slow_scan):
            created = self.submit("carve", {"ext": [".bin"]})
            self.assertTrue(entered.wait(10))
            conflict = self.submit("carve", {}, expect=409)
            self.assertEqual(conflict["detail"], analyses.ALREADY_RUNNING_MESSAGE)
            response = self.client.post(f"/api/runs/{self.run_id}/analyses/{created['analysis_id']}/cancel")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], "running")  # stays until the runner stops
            self.assertTrue(response.json()["cancel_requested_at"])
            # cancel requested, thread still inside the unit: resubmitting the same kind is refused
            self.assertEqual(self.submit("carve", {}, expect=409)["detail"], analyses.ALREADY_RUNNING_MESSAGE)
            gate.set()
            state = self.wait(str(created["analysis_id"]))
        self.assertEqual(state["status"], "cancelled")
        self.assertEqual(state["progress"]["done"], 1)  # blob2.bin never finished
        self.assertEqual(state["row_count"], 1)  # blob1.bin rows kept
        self.assertEqual(len(self.rows(str(created["analysis_id"]))["rows"]), 1)
        again = self.submit("carve", {"ext": ".bin"})  # thread finished: accepted again
        self.assertEqual(self.wait(str(again["analysis_id"]))["status"], "completed")

    def test_restart_recovery_uses_owner_pid_boot_and_heartbeat(self) -> None:
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait()
        now = time.time()
        boot = analyses.boot_id()
        cases = {
            "nn-no-owner": (None, "failed"),
            "nn-same-pid": ({"pid": os.getpid(), "boot_id": boot, "heartbeat_at": now}, "failed"),
            "nn-dead-pid": ({"pid": finished.pid, "boot_id": boot, "heartbeat_at": now}, "failed"),
            "nn-live-fresh": ({"pid": sleeper.pid, "boot_id": boot, "heartbeat_at": now}, "running"),
            "nn-live-stale": ({"pid": sleeper.pid, "boot_id": boot, "heartbeat_at": now - 3600}, "failed"),
            "nn-rebooted": ({"pid": sleeper.pid, "boot_id": boot - 86400, "heartbeat_at": now}, "failed"),
        }
        for name, (owner, _expected) in cases.items():
            directory = self.run_dir / "analyses" / name
            directory.mkdir(parents=True)
            state = {
                "analysis_id": name,
                "kind": "carve",
                "status": "running",
                "created_at": "2026-01-01T00:00:00+00:00",
                "started_at": "2026-01-01T00:00:01+00:00",
                "row_count": 0,
            }
            if owner is not None:
                state["_owner"] = owner
            (directory / "analysis.json").write_text(json.dumps(state), encoding="utf-8")
        listing = {item["analysis_id"]: item for item in self.client.get(f"/api/runs/{self.run_id}/analyses").json()["analyses"]}
        for name, (_owner, expected) in cases.items():
            self.assertEqual(listing[name]["status"], expected, name)
            if expected == "failed":
                self.assertEqual(listing[name]["error"], analyses.RESTART_MESSAGE)
            self.assertNotIn("_owner", listing[name])
            stored = json.loads((self.run_dir / "analyses" / name / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["status"], "running", f"{name}: reads must not rewrite state files")

    def test_run_not_ready_validation_and_unknown_kind(self) -> None:
        self.submit("nope", expect=400)
        errors = self.submit("carve", {"max_candidates": 0}, expect=422)["detail"]
        self.assertEqual(errors[0]["loc"], ["options", "max_candidates"])
        self.assertIn("최대 후보 수", errors[0]["msg"])
        self.assertIn("1 이상", errors[0]["msg"])
        self.store.get(self.run_id).status = "running"
        self.submit("carve", {}, expect=409)

    def test_paths_outside_allowed_roots_are_forbidden(self) -> None:
        outside = self.base / "outside"
        write_volatility(outside)
        detail = self.submit("memory-import", {"volatility_output_dir": str(outside)}, expect=403)["detail"]
        self.assertIn("허용 범위", detail)
        escape = str(self.evidence) + os.sep + ".." + os.sep + "outside"
        self.submit("memory-import", {"volatility_output_dir": escape}, expect=403)
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        snapshot.mkdir()
        self.submit("vsc-compare", {"snapshot_root": str(snapshot)}, expect=403)
        self.submit("ocr-batch", {"target": {"locators": [str(outside / "windows.pslist.json")]}}, expect=403)

    def test_path_forms_rejected_lexically(self) -> None:
        marker = "rtprobe"
        forms = ["relative" + os.sep + marker, "~" + os.sep + marker]
        if os.name == "nt":
            forms += [
                rf"\\server\share\{marker}",
                rf"\\?\C:\{marker}",
                rf"\\.\{marker}Drive0",
                f"//server/share/{marker}",
                f"C:{marker}",
                rf"\{marker}",
            ]
        else:
            forms += [f"//server/share/{marker}"]
        touched: list[str] = []

        def recorder(real):
            def wrapper(path, *args, **kwargs):
                if isinstance(path, (str, os.PathLike)) and marker in os.fspath(path):
                    touched.append(f"{real.__name__}({path})")
                return real(path, *args, **kwargs)

            return wrapper

        real_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            if marker in str(path):
                touched.append(f"Path.resolve({path})")
            return real_resolve(path, *args, **kwargs)

        with (
            patch.object(Path, "resolve", resolve),
            patch.object(os, "stat", recorder(os.stat)),
            patch.object(os, "lstat", recorder(os.lstat)),
            patch.object(os, "scandir", recorder(os.scandir)),
            patch.object(os.path, "realpath", recorder(os.path.realpath)),
        ):
            for form in forms:
                response = self.client.post(
                    f"/api/runs/{self.run_id}/analyses", json={"kind": "memory-import", "options": {"volatility_output_dir": form}}
                )
                self.assertEqual(response.status_code, 403, (form, response.text))
                self.assertIsInstance(response.json()["detail"], str)
        self.assertEqual(touched, [], "rejected path forms must never reach the filesystem")

    def test_link_escape_is_forbidden_after_resolve(self) -> None:
        outside = self.base / "outside"
        write_volatility(outside)
        link = self.evidence / "vol-link"
        errors = make_directory_link(outside, link)
        if errors:
            self.skipTest(f"cannot create a junction/symlink here: {errors}")
        detail = self.submit("memory-import", {"volatility_output_dir": str(link)}, expect=403)["detail"]
        self.assertIn("링크", detail)

    def test_env_roots_parsing(self) -> None:
        good = str(self.base / "extra")
        value = os.pathsep.join([f'"{good}"', "relative-dir", "", "'~/x'"])
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: value}), self.assertLogs(analyses.LOGGER, "WARNING") as logs:
            roots = analyses.extra_analysis_roots()
        self.assertIn(Path(os.path.abspath(good)), roots)
        self.assertEqual({str(root) for root in roots} - {os.path.abspath(good), str(Path(good).resolve())}, set())
        self.assertEqual(len(logs.records), 2)

    def test_vsc_discover_compare_extract_chain(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        (snapshot / "Users").mkdir(parents=True)
        (snapshot / "Users" / "gone.txt").write_text("deleted later", encoding="utf-8")
        # Without an allowed root covering the sibling snapshot, discover does not offer it ...
        discover = self.wait(str(self.submit("vsc-discover")["analysis_id"]))
        self.assertEqual(discover["status"], "completed", discover)
        self.assertGreaterEqual(discover["summary"]["excluded_outside_roots"], 1)
        roots = [row["details"]["snapshot_root"] for row in self.rows(discover["analysis_id"])["rows"]]
        self.assertNotIn(str(snapshot.resolve()), roots)
        # ... and compare refuses it even though discover saw it (no discover bypass).
        self.submit("vsc-compare", {"snapshot_root": str(snapshot)}, expect=403)
        self.submit("vsc-discover", {"max_depth": 2}, expect=422)
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            discover = self.wait(str(self.submit("vsc-discover")["analysis_id"]))
            roots = [row["details"]["snapshot_root"] for row in self.rows(discover["analysis_id"])["rows"]]
            self.assertIn(str(snapshot.resolve()), roots)
            compare = self.wait(str(self.submit("vsc-compare", {"snapshot_root": roots[0]})["analysis_id"]))
            self.assertEqual(compare["status"], "completed", compare)
            statuses = {row["details"]["path"]: row["details"]["status"] for row in self.rows(compare["analysis_id"])["rows"]}
            self.assertEqual(statuses["Users/gone.txt"], "deleted")
            self.assertEqual(statuses["Users/alice.txt"], "added")
            self.submit("vsc-extract", {"snapshot_root": str(snapshot), "output_dir": str(self.base / "elsewhere")}, expect=403)
            extract = self.wait(str(self.submit("vsc-extract", {"snapshot_root": str(snapshot), "status": ["deleted"]})["analysis_id"]))
        self.assertEqual(extract["status"], "completed", extract)
        copied = [row for row in self.rows(extract["analysis_id"])["rows"] if row["details"]["destination"]]
        self.assertEqual(len(copied), 1)
        self.assertTrue(Path(copied[0]["details"]["destination"]).is_file())
        self.assertTrue(Path(copied[0]["details"]["destination"]).is_relative_to(self.run_dir.resolve()))

    def test_ntfs_meta_with_mocked_sleuthkit_and_files_join(self) -> None:
        before = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        self.assertEqual(
            {k: before["ntfs_join"][k] for k in ("analysis_id", "status", "matched", "total", "analysis_total")},
            {"analysis_id": None, "status": "no_analysis", "matched": 0, "total": 3, "analysis_total": None},
        )
        self.assertIsNone(before["candidates"][0]["ntfs"])
        self.assertEqual(before["candidates"][0]["source_image"], str(self.evidence / "disk.E01"))
        journal = usn_record("alice.txt", parent=64, entry=65, usn=8) + bytes(64)
        state = self.run_ntfs(usn=journal)
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["mft_record_count"], 4)
        self.assertEqual(state["summary"]["usn_record_count"], 1)
        rows = self.rows(state["analysis_id"], limit=50)["rows"]
        by_name = {row["details"].get("name"): row["details"] for row in rows if row["details"]["source"] == "mft"}
        alice = by_name["alice.txt"]
        self.assertEqual(alice["entry_number"], 65)
        self.assertEqual(alice["path"], "\\Users\\alice.txt")
        self.assertEqual(alice["parent_path"], "\\Users")
        self.assertTrue(alice["created_at"].startswith("2024-01-02T03:04:05"))
        self.assertFalse(by_name["deleted.bin"]["in_use"])
        usn = next(row["details"] for row in rows if row["details"]["source"] == "usn")
        self.assertEqual(usn["file_name"], "alice.txt")
        self.assertEqual(usn["path"], "\\Users\\alice.txt")
        self.assertIn("FILE_CREATE", usn["reason"])
        after = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        join = after["ntfs_join"]
        self.assertEqual(
            {k: join[k] for k in ("analysis_id", "status", "matched", "total", "analysis_total", "partition")},
            {"analysis_id": state["analysis_id"], "status": "joined", "matched": 1, "total": 3, "analysis_total": state["row_count"], "partition": 2048},
        )
        self.assertEqual(join["volume_prefix"], os.path.abspath(self.evidence))
        self.assertEqual(join["prefix_method"], "scan-root")
        joined = after["candidates"][0]
        self.assertEqual(joined["filesystem"], "NTFS")
        self.assertEqual(joined["ntfs"]["entry_number"], 65)
        self.assertTrue(joined["ntfs"]["accessed_at"].startswith("2024-03-01"))
        self.assertIsNone(after["candidates"][1]["ntfs"])

    @unittest.skipUnless(missing_ntfs_metadata_tools(), "Sleuth Kit is installed; the missing-tool path cannot be exercised")
    def test_ntfs_meta_without_sleuthkit_fails_with_reason(self) -> None:
        state = self.wait(str(self.submit("ntfs-meta")["analysis_id"]))
        self.assertEqual(state["status"], "failed")
        self.assertIn("Sleuth Kit", state["error"])

    def test_ntfs_meta_requires_image_source(self) -> None:
        detail = self.submit("ntfs-meta", {"image_path": str(self.evidence / "Users")}, expect=400)["detail"]
        self.assertIn("디스크 이미지", detail)

    def test_ocr_batch_without_engine_fails_in_korean(self) -> None:
        class TesseractNotFoundError(EnvironmentError):
            pass

        def missing():
            raise TesseractNotFoundError("tesseract is not installed or it's not in your PATH. See README file for more information.")

        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", missing):
            state = self.wait(str(self.submit("ocr-batch", {"target": {"kind": "media-image"}})["analysis_id"]))
        self.assertEqual(state["status"], "failed", state)
        self.assertEqual(state["error"], "OCR 엔진(tesseract)을 찾을 수 없습니다. tesseract를 설치하고 PATH에 추가하세요.")
        self.assertNotIn("README", state["error"])
        self.assertEqual(state["row_count"], 0)  # no row per image for an engine that never ran
        self.assertEqual((state["summary"]["failed_count"], state["summary"]["succeeded_count"]), (0, 0))
        self.assertIn("TesseractNotFoundError", state["summary"]["engine_error_detail"])
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: (_ for _ in ()).throw(ModuleNotFoundError("x", name="pytesseract"))):
            module = self.wait(str(self.submit("ocr-batch")["analysis_id"]))
        self.assertEqual(module["status"], "failed", module)
        self.assertIn("pytesseract", module["error"])
        self.assertIn("설치", module["error"])

    def test_ocr_batch_partial_failures_complete_with_counts(self) -> None:
        broken = self.evidence / "broken.png"
        broken.write_bytes(b"not an image")
        engine = (
            SimpleNamespace(imread=lambda path, *args: None if "broken" in str(path) else object()),
            SimpleNamespace(
                Output=SimpleNamespace(DICT="dict"),
                image_to_data=lambda image, **_kwargs: {"text": ["hi"], "conf": ["90"], "block_num": [1], "par_num": [1], "line_num": [1]},
            ),
        )
        options = {"target": {"locators": [str(self.evidence / "photo.png"), str(broken)]}}
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: engine):
            state = self.wait(str(self.submit("ocr-batch", options)["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual((state["summary"]["succeeded_count"], state["summary"]["failed_count"]), (1, 1))
        statuses = {Path(row["path"]).name: row["details"]["status"] for row in self.rows(state["analysis_id"])["rows"]}
        self.assertEqual(statuses, {"photo.png": "ok", "broken.png": "failed"})

    def test_ocr_batch_results_reused_by_viewer(self) -> None:
        calls: list[str] = []
        fake_cv2 = SimpleNamespace(imread=lambda path, *args: calls.append(path) or object())
        fake_tess = SimpleNamespace(
            Output=SimpleNamespace(DICT="dict"),
            image_to_data=lambda image, **_kwargs: {
                "text": ["안녕", "세계", ""],
                "conf": ["91", "89", "-1"],
                "block_num": [1, 1, 1],
                "par_num": [1, 1, 1],
                "line_num": [1, 1, 2],
            },
        )
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: (fake_cv2, fake_tess)):
            state = self.wait(str(self.submit("ocr-batch", {"target": {"locators": ["/artifacts/0"]}, "languages": ["kor"]})["analysis_id"]))
            self.assertEqual(state["status"], "completed", state)
            details = self.rows(state["analysis_id"])["rows"][0]["details"]
            self.assertEqual(details["text"], "안녕 세계")
            self.assertEqual(details["status"], "ok")
            self.assertEqual(details["confidence"], 90.0)
            self.assertEqual(details["language"], "kor")
            again = self.wait(str(self.submit("ocr-batch", {"target": {"kind": "media-image"}})["analysis_id"]))
            reused = self.rows(again["analysis_id"])["rows"][0]["details"]
            self.assertEqual(reused["reused_from"], state["analysis_id"])
        self.assertEqual(len(calls), 1)  # second batch reused the stored result
        preview = self.client.get(f"/api/runs/{self.run_id}/source-preview", params={"path": str(self.evidence / "photo.png")})
        self.assertEqual(preview.status_code, 200, preview.text)
        sidecar = preview.json()["image"]["ocr_sidecar"]
        self.assertEqual(sidecar["text"], "안녕 세계")
        self.assertEqual(sidecar["source"], "analysis")

    def test_memory_import_rows(self) -> None:
        volatility = self.evidence / "vol"
        write_volatility(volatility)
        state = self.wait(str(self.submit("memory-import", {"volatility_output_dir": str(volatility)})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["progress"]["total"], 2)
        rows = self.rows(state["analysis_id"])["rows"]
        types = {row["details"]["memory_artifact_type"] for row in rows}
        self.assertEqual(types, {"memory-process", "memory-network"})
        self.assertTrue(all(row["artifact_type"] == "memory-import-row" for row in rows))

    def test_cross_case_between_two_runs(self) -> None:
        sha = "ab" * 32
        build_case_db(self.run_dir / "rapidtriage-case.db", f"run-{self.run_id}", sha)
        other_dir = write_run(self.base, "other-run", self.evidence)
        other_id = self.store.import_completed_run(other_dir).run_id
        build_case_db(other_dir / "rapidtriage-case.db", f"run-{other_id}", sha)
        state = self.wait(str(self.submit("cross-case", {"case_ids": [other_id]})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        rows = self.rows(state["analysis_id"])["rows"]
        hashes = [row["details"] for row in rows if row["details"]["kind"] == "sha256"]
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]["indicator"], sha)
        self.assertEqual(hashes[0]["cases"], sorted([self.run_id, other_id]))
        self.assertEqual(sorted(o["case_id"] for o in hashes[0]["occurrences"]), sorted([self.run_id, other_id]))
        self.assertEqual((hashes[0]["first_seen"], hashes[0]["last_seen"]), (None, None))
        paths = [row["details"] for row in rows if row["details"]["kind"] == "path"]
        self.assertEqual([item["indicator"] for item in paths], ["/evidence/shared.pdf"])
        self.assertEqual(state["summary"]["shared_hash_count"], 1)
        self.submit("cross-case", {"case_ids": ["missing-run"]}, expect=400)

    # -- §3.3 ---------------------------------------------------------------------------

    def test_artifact_type_filter_composes_with_sort_and_path(self) -> None:
        params = [("kind", "windows-system"), ("limit", "10"), ("artifact_type", "web-server-log"), ("artifact_type", "webshell-source-candidate")]
        page = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=params).json()["artifacts"]["windows-system"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [0, 2])
        self.assertEqual(page["pagination"]["artifact_types"], ["web-server-log", "webshell-source-candidate"])
        self.assertEqual(page["pagination"]["scanned"], 4)
        self.assertFalse(page["pagination"]["truncated"])
        with_path = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=[*params, ("path_contains", "CMD")]).json()
        self.assertEqual([row["record_index"] for row in with_path["artifacts"]["windows-system"]["artifacts"]], [2])
        sorted_params = [*params, ("sort", "details.n"), ("order", "desc")]
        deadline = time.monotonic() + 10
        while True:
            body = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=sorted_params).json()["artifacts"]["windows-system"]
            if body["sort"]["status"] != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.02)
        self.assertEqual(body["sort"]["status"], "ready")
        self.assertEqual([row["details"]["n"] for row in body["artifacts"]], [3, 1])

    def test_counts_agree_between_rows_and_artifacts_endpoints(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        plain = self.rows(state["analysis_id"], limit=1)
        self.assertEqual((plain["record_count"], plain["matched"]), (3, 3))
        exact = self.rows(state["analysis_id"], limit=10, path_contains="blob2")
        self.assertEqual((exact["record_count"], exact["matched"]), (3, 2))
        self.assertEqual(exact["pagination"]["scanned"], 3)
        self.assertFalse(exact["pagination"]["truncated"])
        early = self.rows(state["analysis_id"], limit=1, path_contains="blob")
        self.assertEqual((early["record_count"], early["matched"]), (3, None))
        self.assertTrue(early["pagination"]["has_more"])
        base = [("kind", "windows-system"), ("limit", "10")]
        page = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=base).json()["artifacts"]["windows-system"]
        self.assertEqual((page["record_count"], page["matched"]), (4, 4))
        typed = [*base, ("artifact_type", "service")]
        page = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=typed).json()["artifacts"]["windows-system"]
        self.assertEqual((page["record_count"], page["matched"], page["pagination"]["matched"]), (4, 2, 2))
        page = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=[*typed, ("limit", "1")]).json()["artifacts"]["windows-system"]
        self.assertEqual((page["record_count"], page["matched"]), (4, None))

    def test_artifact_type_pages_across_kinds(self) -> None:
        types = [("artifact_type", "image"), ("artifact_type", "web-server-log"), ("artifact_type", "webshell-source-candidate")]
        url = f"/api/runs/{self.run_id}/artifacts"
        first = self.client.get(url, params=[*types, ("limit", "2")]).json()
        meta = first["cross_kind"]
        self.assertEqual(meta["order"], [["media-image", 0], ["windows-system", 0]])
        self.assertTrue(meta["has_more"])
        self.assertIsNone(meta["matched"])
        self.assertEqual(meta["record_count"], 5)
        self.assertEqual([row["record_index"] for row in first["artifacts"]["windows-system"]["artifacts"]], [0])
        by_offset = self.client.get(url, params=[*types, ("limit", "2"), ("offset", "2")]).json()["cross_kind"]
        by_after = self.client.get(url, params=[*types, ("limit", "2"), ("after", meta["next_after"])]).json()["cross_kind"]
        for later in (by_offset, by_after):
            self.assertEqual(later["order"], [["windows-system", 2]])
            self.assertEqual(later["offset"], 2)
            self.assertFalse(later["has_more"])
            self.assertEqual(later["matched"], 3)
            self.assertFalse(later["truncated"])
        ordered = self.client.get(url, params=[*types, ("limit", "5"), ("kind", "windows-system"), ("kind", "media-image")]).json()
        self.assertEqual(ordered["cross_kind"]["order"][0], ["windows-system", 0])
        self.assertEqual(self.client.get(url, params=[*types, ("limit", "2"), ("after", "nope")]).status_code, 400)
        from rapidtriage.api.app.artifact_filter import filter_across_kinds

        payload = {"records_path": str(self.system_records), "record_count": 4, "artifacts": []}
        capped = filter_across_kinds(
            [("windows-system", payload, self.system_records)],
            path_contains=None,
            artifact_types={"webshell-source-candidate"},
            offset=0,
            limit=5,
            scan_cap=2,
        )["cross_kind"]
        self.assertEqual((capped["returned"], capped["scanned"], capped["truncated"], capped["matched"]), (0, 2, True, None))
        self.assertEqual(capped["next_after"], "windows-system:1:0")
        resumed = filter_across_kinds(
            [("windows-system", payload, self.system_records)],
            path_contains=None,
            artifact_types={"webshell-source-candidate"},
            offset=0,
            limit=5,
            after=capped["next_after"],
            scan_cap=2,
        )["cross_kind"]
        self.assertEqual((resumed["order"], resumed["matched"], resumed["truncated"]), ([["windows-system", 2]], 1, False))

    def test_path_contains_pages_across_kinds(self) -> None:
        url = f"/api/runs/{self.run_id}/artifacts"
        first = self.client.get(url, params={"path_contains": "SVC", "limit": 1}).json()["cross_kind"]
        self.assertEqual(first["order"], [["windows-system", 0]])  # w3svc.log
        self.assertTrue(first["has_more"])
        self.assertIsNone(first["artifact_types"])
        rest = self.client.get(url, params={"path_contains": "SVC", "limit": 5, "after": first["next_after"]}).json()["cross_kind"]
        self.assertEqual((rest["order"], rest["matched"], rest["has_more"]), ([["windows-system", 1], ["windows-system", 3]], 3, False))
        both = self.client.get(url, params=[("path_contains", "photo"), ("kind", "media-image"), ("kind", "windows-system"), ("limit", "5")]).json()
        self.assertEqual(both["cross_kind"]["order"], [["media-image", 0]])
        single = self.client.get(url, params={"path_contains": "svc", "kind": "windows-system", "limit": 5}).json()
        self.assertNotIn("cross_kind", single)
        self.assertEqual(single["artifacts"]["windows-system"]["matched"], 3)

    def test_byte_limits_are_reported_in_mb(self) -> None:
        errors = self.submit("carve", {"max_scan_bytes": 17 * 1024**3, "max_carve_bytes": 0}, expect=422)["detail"]
        by_field = {error["loc"][1]: error["msg"] for error in errors}
        self.assertIn("16,384 MB 이하", by_field["max_scan_bytes"])
        self.assertIn("0 MB보다 커야", by_field["max_carve_bytes"])
        errors = self.submit("vsc-extract", {"snapshot_root": "x", "max_total_bytes": 300 * 1024**3}, expect=422)["detail"]
        self.assertIn("262,144 MB 이하", errors[0]["msg"])
        self.assertEqual(errors[0]["loc"], ["options", "max_total_bytes"])

    def test_files_category_filter(self) -> None:
        url = f"/api/runs/{self.run_id}/files"
        page = self.client.get(url, params=[("category", "documents"), ("limit", "1")]).json()
        self.assertEqual([row["name"] for row in page["candidates"]], ["alice.txt"])
        self.assertEqual((page["record_count"], page["matched"]), (3, 2))
        self.assertEqual((page["pagination"]["scanned"], page["pagination"]["truncated"]), (3, False))
        self.assertTrue(page["pagination"]["has_more"])
        self.assertIn("ntfs_join", page)
        self.assertEqual(page["candidates"][0]["record_index"], 0)
        rest = self.client.get(url, params=[("category", "documents"), ("limit", "5"), ("offset", "1")]).json()
        self.assertEqual([row["name"] for row in rest["candidates"]], ["notes.txt"])
        self.assertEqual(rest["candidates"][0]["record_index"], 2)  # blob1.bin (index 1) was skipped
        archives = self.client.get(url, params=[("category", "archives"), ("limit", "5")]).json()
        self.assertEqual([(row["name"], row["record_index"]) for row in archives["candidates"]], [("blob1.bin", 1)])
        unfiltered = self.client.get(url, params={"limit": 2, "offset": 1}).json()
        self.assertEqual([row["record_index"] for row in unfiltered["candidates"]], [1, 2])
        whole = self.client.get(url).json()
        self.assertEqual([row["record_index"] for row in whole["candidates"]], [0, 1, 2])
        either = self.client.get(url, params=[("category", "documents"), ("category", "archives"), ("limit", "5")]).json()
        self.assertEqual(either["matched"], 3)
        self.assertEqual(self.client.get(url, params={"category": "nope", "limit": 5}).json()["matched"], 0)

    def test_error_shapes(self) -> None:
        forbidden = self.submit("memory-import", {"volatility_output_dir": str(self.base)}, expect=403)
        self.assertIsInstance(forbidden["detail"], str)
        invalid = self.submit("carve", {"max_candidates": "x"}, expect=422)
        self.assertIsInstance(invalid["detail"], list)
        self.store.get(self.run_id).status = "running"
        conflict = self.submit("carve", {}, expect=409)
        self.assertIsInstance(conflict["detail"], str)

    def test_tree_analyses_group_and_web_log_node(self) -> None:
        tree = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        group = next(node for node in tree["nodes"] if node["id"] == "analyses")
        self.assertEqual(group["label"], "분석 작업")
        ids = [child["id"] for child in group["children"]]
        self.assertEqual(
            ids,
            ["analysis:carve", "analysis:vsc", "analysis:ntfs-meta", "analysis:ocr-batch", "analysis:memory-import", "analysis:web-logs", "analysis:cross-case"],
        )
        self.assertIsNone(group["children"][0]["state"])
        self.assertIsNone(group["children"][0]["latest"])
        self.assertIsNone(group["children"][0]["latest_completed"])
        system = next(
            kind
            for node in tree["nodes"]
            if node["id"] == "artifacts"
            for grp in node["children"]
            for kind in grp["children"]
            if kind["id"] == "artifacts:windows-system"
        )
        self.assertEqual(system["artifact_type_counts"], {"service": 2, "web-server-log": 1, "webshell-source-candidate": 1})
        web = next(child for child in group["children"] if child["id"] == "analysis:web-logs")
        self.assertEqual(web["count"], 2)
        self.assertEqual(web["link"]["artifact_types"], ["web-server-log", "webshell-source-candidate"])
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        carve = next(
            child
            for child in next(node for node in self.client.get(f"/api/runs/{self.run_id}/tree").json()["nodes"] if node["id"] == "analyses")["children"]
            if child["id"] == "analysis:carve"
        )
        self.assertEqual(carve["state"]["status"], "completed")
        self.assertEqual(carve["latest"], carve["state"])
        self.assertEqual(carve["latest_completed"]["analysis_id"], state["analysis_id"])
        self.assertEqual(carve["state"]["analysis_id"], state["analysis_id"])
        self.assertEqual(carve["count"], state["row_count"])

    def test_review_batch_maps_analysis_rows(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        database = self.run_dir / "rapidtriage-case.db"
        case_id = f"run-{self.run_id}"
        open_case_database(database).create_case(case_id=case_id, name="run case")
        body = {
            "database": str(database),
            "case_id": case_id,
            "run_id": self.run_id,
            "status": "relevant",
            "targets": [{"collection": "analysis", "kind": state["analysis_id"], "locator": "/rows/1"}],
        }
        response = self.client.post("/api/case-db/review-batch", json=body)
        self.assertEqual(response.status_code, 200, response.text)
        missing = dict(body, targets=[{"collection": "analysis", "kind": state["analysis_id"], "locator": "/rows/99"}])
        self.assertEqual(self.client.post("/api/case-db/review-batch", json=missing).status_code, 400)
        marks = self.client.get(f"/api/runs/{self.run_id}/review-map").json()["marks"]
        self.assertEqual(
            [(mark["collection"], mark["kind"], mark["locator"]) for mark in marks],
            [("analysis", state["analysis_id"], "/rows/1")],
        )

    # -- adversarial-review regressions ---------------------------------------------------

    def test_cross_kind_scan_cap_boundary_over_http(self) -> None:
        url = f"/api/runs/{self.run_id}/artifacts"
        types = [("artifact_type", "image"), ("artifact_type", "service"), ("limit", "10")]
        from rapidtriage.api.app import artifact_filter

        with patch.object(artifact_filter, "CROSS_KIND_SCAN_CAP", 5):  # exactly every row (1 + 4)
            exact = self.client.get(url, params=types).json()["cross_kind"]
        self.assertEqual((exact["scanned"], exact["truncated"], exact["matched"], exact["next_after"]), (5, False, 3, None))
        with patch.object(artifact_filter, "CROSS_KIND_SCAN_CAP", 3):
            first = self.client.get(url, params=types).json()["cross_kind"]
            self.assertEqual((first["scanned"], first["truncated"], first["matched"]), (3, True, None))
            self.assertEqual(first["order"], [["media-image", 0], ["windows-system", 1]])
            self.assertEqual(first["next_after"], "windows-system:1:2")
            rest = self.client.get(url, params=[*types, ("after", first["next_after"])]).json()["cross_kind"]
        self.assertEqual((rest["order"], rest["matched"], rest["truncated"]), ([["windows-system", 3]], 3, False))

    def test_after_cursor_parts_must_be_digits(self) -> None:
        url = f"/api/runs/{self.run_id}/artifacts"
        for token in ("windows-system:-1:0", "windows-system:1:-2", ":1:0", "windows-system:x:0"):
            response = self.client.get(url, params={"artifact_type": "service", "limit": 5, "after": token})
            self.assertEqual(response.status_code, 400, token)

    def test_filters_require_positive_limit(self) -> None:
        for params in ({"path_contains": "svc"}, {"artifact_type": "service", "kind": "windows-system"}):
            response = self.client.get(f"/api/runs/{self.run_id}/artifacts", params={**params, "limit": 0})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["detail"], "필터는 limit>0에서만 지원합니다")
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files", params={"category": "documents"}).status_code, 400)

    def test_malformed_body_gets_korean_422(self) -> None:
        url = f"/api/runs/{self.run_id}/analyses"
        broken = self.client.post(url, content=b"{not json", headers={"Content-Type": "application/json"})
        self.assertEqual(broken.status_code, 422)
        self.assertIn("JSON", broken.json()["detail"][0]["msg"])
        listed = self.client.post(url, json=[1, 2])
        self.assertEqual(listed.status_code, 422)
        self.assertIn("객체", listed.json()["detail"][0]["msg"])
        missing = self.client.post(url, json={"options": {}})
        self.assertEqual(missing.json()["detail"][0]["msg"], "분석 종류(kind) 값이 필요합니다")
        other = self.client.post("/api/runs/import", json=[1])  # other routes keep FastAPI's English errors
        self.assertEqual(other.status_code, 422)
        self.assertNotIn("객체", json.dumps(other.json(), ensure_ascii=False))

    def test_files_join_skipped_without_output_dir(self) -> None:
        from rapidtriage.api.app import routes_runs

        def no_scope(*_args, **_kwargs):
            raise analyses.HTTPException(status_code=409, detail="런 요약에 출력 디렉터리가 없습니다")

        with patch.object(routes_runs, "run_scope", no_scope):
            page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 5})
        self.assertEqual(page.status_code, 200, page.text)
        self.assertEqual(page.json()["ntfs_join"]["status"], "skipped")
        self.assertIsNone(page.json()["candidates"][0]["ntfs"])

    def test_analysis_row_locator_requires_run_output_dir(self) -> None:
        from rapidtriage.api.app.run_review import RunLocatorIndex

        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE evidence_source (id INTEGER PRIMARY KEY, case_id TEXT)")
        target = ("analysis", "/rows/0", state["analysis_id"])
        self.assertIsNone(RunLocatorIndex(connection, "c", {}).resolve(*target))
        other_run = self.base / "other-output"
        other_run.mkdir()
        self.assertIsNone(RunLocatorIndex(connection, "c", {}, output_dir=other_run).resolve(*target))
        self.assertEqual(
            RunLocatorIndex(connection, "c", {}, output_dir=self.run_dir).resolve(*target),
            ("analysis_row", f"{state['analysis_id']}/0"),
        )

    def test_mft_records_beyond_first_chunk(self) -> None:
        extra = {3000: mft_record(name="late.txt", parent=64, in_use=True, directory=False, created="2024-02-02T00:00:00Z")}
        state = self.run_ntfs(mft=synthetic_mft(extra))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["mft_record_count"], 5)
        late = [row["details"] for row in self.rows(state["analysis_id"], limit=50)["rows"] if row["details"].get("name") == "late.txt"]
        self.assertEqual((late[0]["entry_number"], late[0]["path"], late[0]["record_offset"]), (3000, "\\Users\\late.txt", 3000 * 1024))

    def test_usn_records_across_windows(self) -> None:
        records = [usn_record(f"file{n}.txt", parent=64, entry=65, usn=n) for n in range(6)]
        journal = bytes(40) + records[0] + records[1] + bytes(24) + b"".join(records[2:]) + bytes(16)
        expected_offsets = []
        cursor = 40
        for index, record in enumerate(records):
            expected_offsets.append(cursor)
            cursor += len(record) + (24 if index == 1 else 0)
        with patch.object(analysis_kinds, "USN_WINDOW_BYTES", 128), patch.object(analysis_kinds, "USN_WINDOW_OVERLAP", 128):
            state = self.run_ntfs(usn=journal)
        self.assertEqual(state["status"], "completed", state)
        usn = [row["details"] for row in self.rows(state["analysis_id"], limit=100)["rows"] if row["details"]["source"] == "usn"]
        self.assertEqual([item["file_name"] for item in usn], [f"file{n}.txt" for n in range(6)])
        self.assertEqual([item["record_offset"] for item in usn], expected_offsets)

    def test_two_ntfs_analyses_latest_wins_and_evicts(self) -> None:
        first = self.run_ntfs()
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 5}).json()
        self.assertTrue(page["candidates"][0]["ntfs"]["created_at"].startswith("2024-01-02"))
        second = self.run_ntfs(mft=synthetic_mft(alice_created="2025-05-05T00:00:00Z"))
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 5}).json()
        self.assertEqual(page["ntfs_join"]["analysis_id"], second["analysis_id"])
        self.assertTrue(page["candidates"][0]["ntfs"]["created_at"].startswith("2025-05-05"))
        keys = files_ntfs.NTFS_INDEX_CACHE.cached_keys()
        self.assertEqual([key[1] for key in keys if key[0] == self.run_id], [second["analysis_id"]])
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])

    def test_join_never_strips_components(self) -> None:
        extra = {
            67: mft_record(name="Windows", parent=5, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
            68: mft_record(name="System32", parent=67, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
            69: mft_record(name="foo.dll", parent=68, in_use=True, directory=False, created="2024-01-01T00:00:00Z"),
        }
        nested = self.evidence / "Backup" / "Old" / "Windows" / "System32"
        nested.mkdir(parents=True)
        (nested / "foo.dll").write_bytes(b"MZ")
        files_path = Path(json.loads((self.run_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))["outputs"]["files"])
        payload = json.loads(files_path.read_text(encoding="utf-8"))
        payload["candidates"].append({"path": str(nested / "foo.dll"), "name": "foo.dll", "size": 2, "categories": []})
        files_path.write_text(json.dumps(payload), encoding="utf-8")
        state = self.run_ntfs(mft=synthetic_mft(extra))
        rows = {row["details"]["path"] for row in self.rows(state["analysis_id"], limit=50)["rows"]}
        self.assertIn("\\Windows\\System32\\foo.dll", rows)
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        by_name = {row["name"]: row for row in page["candidates"]}
        self.assertIsNone(by_name["foo.dll"]["ntfs"], "Backup/Old/Windows/... must not join \\Windows\\...")
        self.assertEqual(by_name["alice.txt"]["ntfs"]["entry_number"], 65)
        self.assertEqual(page["ntfs_join"]["volume_prefix"], os.path.abspath(self.evidence))

    def test_volume_prefix_detected_below_scan_root(self) -> None:
        index = files_ntfs.NtfsIndex(key=("r", "a", 0, 0), entries={}, top_level=frozenset({"windows", "users"}))
        root = Path(os.path.abspath(self.base / "stage"))
        rows = [{"path": str(root / "p2" / "Users" / "x.txt")}, {"path": str(root / "p2" / "Windows" / "y")}]
        self.assertEqual(files_ntfs.detect_volume_prefix([root], rows, index.top_level), (str(root / "p2"), "sentinel-depth-1"))
        self.assertEqual(files_ntfs.detect_volume_prefix([root], rows, frozenset())[0], None)

    def test_join_index_single_flight_and_too_large(self) -> None:
        state = self.run_ntfs()
        rows_path = self.run_dir / "analyses" / state["analysis_id"] / "rows.jsonl"
        cache = files_ntfs.NtfsIndexCache()
        real_build = files_ntfs.build_ntfs_index
        gate = threading.Event()

        def slow_build(*args):
            gate.wait(5)
            return real_build(*args)

        results: list[object] = []
        with patch.object(files_ntfs, "build_ntfs_index", slow_build):
            threads = [threading.Thread(target=lambda: results.append(cache.get("r", "a", rows_path))) for _ in range(4)]
            for thread in threads:
                thread.start()
            time.sleep(0.1)
            gate.set()
            for thread in threads:
                thread.join(10)
        self.assertEqual(cache.builds, 1)
        self.assertEqual(len({id(item) for item in results}), 1)
        with patch.object(files_ntfs, "INDEX_MAX_BYTES", 10):
            join = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 5}).json()["ntfs_join"]
        self.assertEqual(join["status"], "too_large")
        self.assertIn("한도", join["reason"])

    def test_failed_and_stale_ocr_results(self) -> None:
        def undecodable():
            return (SimpleNamespace(imread=lambda path, *args: None), SimpleNamespace(Output=SimpleNamespace(DICT="dict")))

        calls: list[str] = []
        engine = (
            SimpleNamespace(imread=lambda path, *args: calls.append(path) or object()),
            SimpleNamespace(
                Output=SimpleNamespace(DICT="dict"),
                image_to_data=lambda image, **_kwargs: {"text": ["late"], "conf": ["80"], "block_num": [1], "par_num": [1], "line_num": [1]},
            ),
        )
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", undecodable):
            failed = self.wait(str(self.submit("ocr-batch")["analysis_id"]))
        self.assertEqual((failed["status"], failed["summary"]["failed_count"]), ("completed", 1), failed)
        preview = self.client.get(f"/api/runs/{self.run_id}/source-preview", params={"path": str(self.evidence / "photo.png")}).json()
        self.assertFalse((preview["image"]["ocr_sidecar"] or {}).get("text"))  # failures are never shown as OCR text
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: engine):
            copied = self.wait(str(self.submit("ocr-batch")["analysis_id"]))
            reused = self.rows(copied["analysis_id"])["rows"][0]["details"]
            self.assertEqual((reused["status"], reused["reused_from"]), ("failed", failed["analysis_id"]))
            self.assertEqual(calls, [])
            retried = self.wait(str(self.submit("ocr-batch", {"retry_failures": True})["analysis_id"]))
        self.assertEqual(self.rows(retried["analysis_id"])["rows"][0]["details"]["text"], "late")
        self.assertEqual(len(calls), 1)
        # A newer failed batch never hides an older batch's text.
        newest = self.run_dir / "analyses" / "99991231T000000-ffffffff"
        newest.mkdir()
        (newest / "analysis.json").write_text(
            json.dumps({"analysis_id": newest.name, "kind": "ocr-batch", "status": "completed", "created_at": "9999-12-31T00:00:00+00:00", "row_count": 1}),
            encoding="utf-8",
        )
        (newest / "rows.jsonl").write_text(
            json.dumps({"artifact_type": "ocr-batch-row", "details": {"source_path": str(self.evidence / "photo.png"), "status": "failed"}}) + "\n",
            encoding="utf-8",
        )
        found = analysis_kinds.find_ocr_result(self.run_dir, self.evidence / "photo.png")
        self.assertEqual((found["analysis_id"], found["text"]), (retried["analysis_id"], "late"))
        self.assertEqual(analysis_kinds.find_ocr_result(self.run_dir, self.evidence / "photo.png", include_failed=True)["analysis_id"], newest.name)

    def test_corrupt_rows_jsonl_is_tolerated(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        directory = self.run_dir / "analyses" / state["analysis_id"]
        rows_path = directory / "rows.jsonl"
        good = rows_path.read_bytes().splitlines(keepends=True)
        self.assertEqual(len(good), 3)
        # Corrupt lines *inside* the counted range: "{"-lines consume a record index, others do not.
        rows_path.write_bytes(good[0] + b"{not json\n[1, 2]\n\xff\xfe garbage\n{\"bad\": \xff}\n" + good[1] + good[2])
        stored = json.loads((directory / "analysis.json").read_text(encoding="utf-8"))
        stored["row_count"] = 5  # 3 rows + 2 corrupt "{"-records, all flushed
        (directory / "analysis.json").write_text(json.dumps(stored), encoding="utf-8")
        page = self.rows(state["analysis_id"], limit=10)
        self.assertEqual([row["record_index"] for row in page["rows"]], [0, 3, 4])
        self.assertEqual(page["record_count"], 5)
        filtered = self.rows(state["analysis_id"], limit=10, path_contains="blob")
        self.assertEqual([row["record_index"] for row in filtered["rows"]], [0, 3, 4])
        deadline = time.monotonic() + 10
        while True:
            ordered = self.rows(state["analysis_id"], limit=10, sort="details.offset", order="asc")
            if ordered["sort"]["status"] != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.02)
        self.assertEqual(ordered["sort"]["status"], "ready", ordered["sort"])
        self.assertEqual(sorted(row["record_index"] for row in ordered["rows"]), [0, 3, 4])

    def test_progress_is_monotonic(self) -> None:
        snapshots: list[dict[str, object]] = []
        real_write = analyses.AnalysisContext.write_state

        def recording(context, *args, **kwargs):
            with context.lock:
                snapshots.append({"status": context.state.get("status"), **dict(context.state.get("progress") or {})})
            return real_write(context, *args, **kwargs)

        journal = b"".join(usn_record(f"f{n}.txt", parent=64, entry=65, usn=n) for n in range(8))
        with patch.object(analyses.AnalysisContext, "write_state", recording), patch.object(analyses, "PROGRESS_WRITE_INTERVAL_SECONDS", 0):
            with patch.object(analysis_kinds, "USN_WINDOW_BYTES", 160), patch.object(analysis_kinds, "USN_WINDOW_OVERLAP", 160):
                state = self.run_ntfs(usn=journal)
        self.assertEqual(state["status"], "completed")
        dones = [int(item.get("done") or 0) for item in snapshots]
        self.assertEqual(dones, sorted(dones))
        for item in snapshots:
            if isinstance(item.get("total"), int):
                self.assertGreaterEqual(item["total"], item.get("done") or 0)
            if item["status"] != "completed" and item.get("percent") is not None:
                self.assertLessEqual(item["percent"], analyses.RUNNING_PERCENT_CAP)
        self.assertEqual(state["progress"]["percent"], 100.0)

    def test_sort_cache_keys_unique_per_analysis(self) -> None:
        ids = [self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))["analysis_id"] for _ in range(2)]
        for analysis_id in ids:
            deadline = time.monotonic() + 10
            while self.rows(analysis_id, limit=5, sort="details.offset")["sort"]["status"] == "building" and time.monotonic() < deadline:
                time.sleep(0.02)
        kinds = [key[1] for key in artifact_sort.SORT_INDEX_CACHE.cached_keys()]
        self.assertEqual(sorted(kind for kind in kinds if kind.startswith("analysis:")), sorted(f"analysis:{item}#3" for item in ids))

    def test_shutdown_hook_cancels_active_analyses(self) -> None:
        gate = threading.Event()
        entered = threading.Event()
        real_scan = analysis_kinds._scan_source

        def slow_scan(*args, **kwargs):
            entered.set()
            gate.wait(10)
            return real_scan(*args, **kwargs)

        app = create_app(self.store, auth_token=TOKEN)
        with patch.object(analysis_kinds, "_scan_source", slow_scan):
            with TestClient(app, headers={"X-RapidTriage-Token": TOKEN}) as client:
                created = client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "carve", "options": {"ext": ".bin"}}).json()
                self.assertTrue(entered.wait(10))
            # lifespan shutdown ran: the running analysis is asked to stop
            context = analyses.ANALYSIS_RUNNER._context(self.run_dir, created["analysis_id"])
            self.assertTrue(context is None or context.cancel_event.is_set())
            gate.set()
            state = self.wait(str(created["analysis_id"]))
        self.assertEqual(state["status"], "cancelled")
        self.assertTrue(all(thread.daemon for thread in threading.enumerate() if thread.name.startswith("rapidtriage-analysis")))
        after = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))  # pool restarts lazily
        self.assertEqual(after["status"], "completed")

    # -- audit follow-ups ------------------------------------------------------------------

    def _blocking_scan(self, *, block_on_call: int = 1):
        """``_scan_source`` stand-in blocking on call ``block_on_call``: (fake, entered, gate)."""
        gate = threading.Event()
        entered = threading.Event()
        real_scan = analysis_kinds._scan_source
        calls = [0]

        def slow_scan(*args, **kwargs):
            calls[0] += 1
            if calls[0] == block_on_call:
                entered.set()
                gate.wait(10)
            return real_scan(*args, **kwargs)

        self.addCleanup(gate.set)
        return slow_scan, entered, gate

    def test_vsc_compare_cancel_stops_walk_promptly(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        snapshot.mkdir()
        for number in range(40):
            (snapshot / f"f{number:02d}.txt").write_text(str(number), encoding="utf-8")
        gate = threading.Event()
        entered = threading.Event()
        self.addCleanup(gate.set)
        checks: list[int] = []
        real_check = analyses.AnalysisContext.check_cancel

        def check_cancel(context):
            checks.append(1)
            if len(checks) == 1:  # first walk-time check: hold the walk mid-index
                entered.set()
                gate.wait(10)
            return real_check(context)

        with (
            patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}),
            patch.object(vsc, "CANCEL_CHECK_EVERY", 1),
            patch.object(analyses.AnalysisContext, "check_cancel", check_cancel),
        ):
            created = self.submit("vsc-compare", {"snapshot_root": str(snapshot)})
            self.assertTrue(entered.wait(10))
            response = self.client.post(f"/api/runs/{self.run_id}/analyses/{created['analysis_id']}/cancel")
            self.assertEqual(response.status_code, 200, response.text)
            started = time.monotonic()
            gate.set()
            state = self.wait(str(created["analysis_id"]), timeout=5)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(state["status"], "cancelled", state)
        self.assertEqual(len(checks), 1, "the walk must stop at the first check after the cancel")
        self.assertEqual(state["row_count"], 0)
        self.assertFalse((Path(state["output_dir"]) / "vsc-compare.json").exists())
        # Core/CLI default (no hook) is unchanged: the same walk completes.
        payload = vsc.compare_vsc_snapshots(self.evidence, [snapshot])
        self.assertEqual(payload["comparisons"][0]["summary"]["snapshot_file_count"], 40)

    def test_vsc_discover_never_touches_outside_parent(self) -> None:
        outside = self.base / "vss-outside-1"
        outside.mkdir()
        (outside / "x.txt").write_text("x", encoding="utf-8")
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        (snapshot / "Users").mkdir(parents=True)
        (snapshot / "Users" / "gone.txt").write_text("deleted later", encoding="utf-8")
        counted: list[Path] = []
        listed: list[Path] = []
        real_count = vsc.count_files_bounded
        real_iterdir = Path.iterdir

        def count(path, *args, **kwargs):
            counted.append(Path(path))
            return real_count(path, *args, **kwargs)

        def iterdir(path):
            listed.append(Path(path))
            return real_iterdir(path)

        parent = self.evidence.resolve().parent
        with patch.object(vsc, "count_files_bounded", count), patch.object(Path, "iterdir", iterdir):
            discover = self.wait(str(self.submit("vsc-discover")["analysis_id"]))
            with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
                allowed = self.wait(str(self.submit("vsc-discover")["analysis_id"]))
                compare = self.wait(str(self.submit("vsc-compare", {"snapshot_root": str(snapshot)})["analysis_id"]))
        for state in (discover, allowed, compare):
            self.assertEqual(state["status"], "completed", state)
        self.assertNotIn(parent, listed, "the outside-root parent must never be listed")
        self.assertFalse([path for path in counted + listed if path == outside or outside in path.parents])
        self.assertGreaterEqual(discover["summary"]["excluded_outside_roots"], 1)
        self.assertNotIn(str(parent), discover["summary"]["search_roots"])
        written = json.loads((Path(discover["output_dir"]) / "vsc-discovery.json").read_text(encoding="utf-8"))
        self.assertNotIn(str(parent), written["search_roots"])
        self.assertEqual(written["snapshots"], [])
        self.assertNotIn(str(outside), json.dumps(written))
        # An allowed sibling below the outside parent is still discovered, without walking the parent.
        allowed_json = json.loads((Path(allowed["output_dir"]) / "vsc-discovery.json").read_text(encoding="utf-8"))
        found = [row["path"] for row in allowed_json["snapshots"]]
        self.assertIn(str(snapshot.resolve()), found)
        self.assertTrue(all(Path(path) == snapshot.resolve() or snapshot.resolve() in Path(path).parents for path in found), found)
        self.assertNotIn(str(parent), allowed_json["search_roots"])
        self.assertNotIn(str(outside), json.dumps(allowed_json))
        compare_json = json.loads((Path(compare["output_dir"]) / "vsc-compare.json").read_text(encoding="utf-8"))
        self.assertNotIn(str(parent), compare_json["snapshot_discovery"]["search_roots"])
        self.assertNotIn(str(outside), json.dumps(compare_json))

    def test_shutdown_is_scoped_to_the_app_that_submitted(self) -> None:
        slow_scan, entered, gate = self._blocking_scan()
        app_a = create_app(self.store, auth_token=TOKEN)
        app_b = create_app(self.store, auth_token=TOKEN)
        headers = {"X-RapidTriage-Token": TOKEN}
        with patch.object(analysis_kinds, "_scan_source", slow_scan):
            with TestClient(app_b, headers=headers) as client_b:
                created = client_b.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "carve", "options": {"ext": ".bin"}}).json()
                self.assertTrue(entered.wait(10))
                context = analyses.ANALYSIS_RUNNER._context(self.run_dir, created["analysis_id"])
                self.assertIs(context.owner, app_b.state.analysis_owner)
                with TestClient(app_a, headers=headers) as client_a:
                    self.assertEqual(client_a.get(f"/api/runs/{self.run_id}/analyses").status_code, 200)
                # app A's lifespan ended: B's analysis keeps running
                self.assertFalse(context.cancel_event.is_set())
                self.assertEqual(client_b.get(f"/api/runs/{self.run_id}/analyses/{created['analysis_id']}").json()["status"], "running")
            self.assertTrue(context.cancel_event.is_set())  # B's own shutdown cancels it
            gate.set()
            state = self.wait(str(created["analysis_id"]))
        self.assertEqual(state["status"], "cancelled")

    def test_queued_tasks_dropped_at_shutdown_end_cancelled(self) -> None:
        slow_scan, entered, gate = self._blocking_scan()
        volatility = self.evidence / "vol"
        write_volatility(volatility)
        runner = analyses.AnalysisRunner(max_workers=1)
        self.addCleanup(runner.shutdown)
        scope = analyses.run_scope(self.store, self.run_id)
        owner_a, owner_b = object(), object()

        def state_of(analysis_id: str) -> dict[str, object]:
            deadline = time.monotonic() + 10
            while True:
                state = runner.load_state(self.run_dir, analysis_id) or {}
                if state.get("status") in analyses.TERMINAL_STATUSES or time.monotonic() > deadline:
                    return state
                time.sleep(0.02)

        with patch.object(analysis_kinds, "_scan_source", slow_scan):
            running = runner.submit(scope, "carve", {"ext": ".bin"}, owner=owner_b)
            self.assertTrue(entered.wait(10))
            queued = runner.submit(scope, "memory-import", {"volatility_output_dir": str(volatility)}, owner=owner_a)
            self.assertEqual(queued["status"], "queued")
            runner.shutdown(owner=owner_a)  # A's queued task is dropped, B's running one is untouched
            stored = analyses.read_state_file(self.run_dir / "analyses" / str(queued["analysis_id"]) / "analysis.json")
            self.assertEqual(stored["status"], "cancelled", stored)
            self.assertTrue(stored["finished_at"])
            self.assertIsNone(runner._context(self.run_dir, str(queued["analysis_id"])))
            gate.set()
            self.assertEqual(state_of(str(running["analysis_id"]))["status"], "completed")
        # Full shutdown (no owner): the running one is cancelled, every queued one dropped as cancelled.
        slow_scan, entered, gate = self._blocking_scan()
        with patch.object(analysis_kinds, "_scan_source", slow_scan):
            running = runner.submit(scope, "carve", {"ext": ".bin"}, owner=owner_b)
            self.assertTrue(entered.wait(10))
            queued = runner.submit(scope, "memory-import", {"volatility_output_dir": str(volatility)}, owner=owner_a)
            runner.shutdown()
            stored = analyses.read_state_file(self.run_dir / "analyses" / str(queued["analysis_id"]) / "analysis.json")
            self.assertEqual(stored["status"], "cancelled", stored)
            gate.set()
            self.assertEqual(state_of(str(running["analysis_id"]))["status"], "cancelled")

    def test_running_rows_bounded_by_flushed_row_count(self) -> None:
        slow_scan, entered, gate = self._blocking_scan(block_on_call=2)  # blob1.bin scanned, blob2.bin held
        with (
            patch.object(analysis_kinds, "_scan_source", slow_scan),
            patch.object(analyses, "PROGRESS_WRITE_INTERVAL_SECONDS", 3600),
        ):
            created = self.submit("carve", {"ext": ".bin"})
            analysis_id = str(created["analysis_id"])
            self.assertTrue(entered.wait(10))
            context = analyses.ANALYSIS_RUNNER._context(self.run_dir, analysis_id)
            rows_path = self.run_dir / "analyses" / analysis_id / "rows.jsonl"

            def sorted_rows() -> dict[str, object]:
                deadline = time.monotonic() + 10
                while True:
                    page = self.rows(analysis_id, limit=10, sort="details.offset", order="desc")
                    if page["sort"]["status"] != "building" or time.monotonic() > deadline:
                        return page
                    time.sleep(0.02)

            # An unrelated cached index must survive the running analysis's sort requests.
            cache = artifact_sort.SORT_INDEX_CACHE
            unrelated = ("other-run", "other-kind", "details.n", 1, 1)
            with cache._lock:
                cache._entries[unrelated] = SimpleNamespace(nbytes=0)
            self.addCleanup(cache.clear)
            # blob1.bin's row reached the disk (buffer flush) but row_count was not updated yet.
            with context.lock:
                context._rows_handle.flush()
            self.assertIn(b"blob1.bin", rows_path.read_bytes())
            self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}").json()["row_count"], 0)
            for page in (self.rows(analysis_id, limit=10), self.rows(analysis_id, limit=10, path_contains="blob"), sorted_rows()):
                self.assertEqual(page["record_count"], 0)
                self.assertEqual(page["rows"], [], page)
            # Flushed row counted; then a complete and a partial line land past row_count.
            context.write_state()
            with context.lock:
                context._rows_handle.write(b'{"artifact_type": "carve-row", "path": "leak.bin", "details": {"offset": 999}}\n')
                context._rows_handle.write(b'{"artifact_type": "carve-row", "path": "leak-partial')
                context._rows_handle.flush()
            plain = self.rows(analysis_id, limit=10)
            self.assertEqual((plain["record_count"], [row["record_index"] for row in plain["rows"]]), (1, [0]))
            self.assertEqual(self.rows(analysis_id, limit=10, path_contains="leak")["rows"], [])
            self.assertEqual(len(self.rows(analysis_id, limit=10, path_contains="bin")["rows"]), 1)
            # Sorting a running analysis: explained "unsupported", JSONL order, still bounded,
            # and no sort index is built (no cache churn while row_count grows).
            for _ in range(3):
                ordered = sorted_rows()
                self.assertEqual(ordered["sort"]["status"], "unsupported", ordered["sort"])
                self.assertIn("실행 중", ordered["sort"]["reason"])
                self.assertEqual([row["path"] for row in ordered["rows"]], [str(self.evidence / "blob1.bin")])
                context.write_state()
            keys = artifact_sort.SORT_INDEX_CACHE.cached_keys()
            self.assertFalse([key for key in keys if str(key[1]).startswith("analysis:")], keys)
            self.assertIn(unrelated, keys)
            self.client.post(f"/api/runs/{self.run_id}/analyses/{analysis_id}/cancel")
            gate.set()
            final = self.wait(analysis_id)
        self.assertEqual(final["status"], "cancelled")
        # Finished: the sort index is built once, keyed by the final row_count.
        deadline = time.monotonic() + 10
        while True:
            done = self.rows(analysis_id, limit=10, sort="details.offset", order="desc")
            if done["sort"]["status"] != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.02)
        self.assertEqual(done["sort"]["status"], "ready", done["sort"])
        kinds = [key[1] for key in artifact_sort.SORT_INDEX_CACHE.cached_keys() if str(key[1]).startswith("analysis:")]
        self.assertEqual(kinds, [f"analysis:{analysis_id}#{final['row_count']}"])

    # -- adversarial review 2 -------------------------------------------------------------

    def _link_or_skip(self, target: Path, link: Path) -> None:
        errors = make_directory_link(target, link)
        if errors:
            self.skipTest(f"cannot create a junction/symlink here: {errors}")

    def test_carve_never_follows_links_loops_or_other_run_outputs(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "escape.bin").write_bytes(JPEG)
        self._link_or_skip(outside, self.evidence / "esc")
        self._link_or_skip(self.evidence, self.evidence / "loop")  # junction back at an ancestor
        other_run = self.evidence / "rapidtriage-run-20260101"
        other_run.mkdir()
        (other_run / "other.bin").write_bytes(JPEG)
        started = time.monotonic()
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]), timeout=30)
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(state["status"], "completed", state)
        paths = {row["path"] for row in self.rows(state["analysis_id"], limit=100)["rows"]}
        self.assertEqual(paths, {str(self.evidence / "blob1.bin"), str(self.evidence / "blob2.bin")})
        self.assertEqual(state["summary"]["source_file_count"], 2)
        self.assertGreaterEqual(state["summary"]["skipped_link_count"], 2)
        self.assertGreaterEqual(state["summary"]["pruned_output_dir_count"], 1)
        self.assertFalse((Path(state["output_dir"]) / "carve-sources.staging.jsonl").exists())

    def test_carve_walk_in_junction_loop_is_cancellable(self) -> None:
        self._link_or_skip(self.evidence, self.evidence / "loop")
        checks: list[int] = []
        entered = threading.Event()
        gate = threading.Event()
        self.addCleanup(gate.set)
        real_check = analyses.AnalysisContext.check_cancel

        def check_cancel(context):
            checks.append(1)
            if len(checks) == 1:  # first walk-time check: hold the walk
                entered.set()
                gate.wait(10)
            return real_check(context)

        with patch.object(analysis_kinds, "CANCEL_CHECK_EVERY", 1), patch.object(analyses.AnalysisContext, "check_cancel", check_cancel):
            created = self.submit("carve", {"ext": ".bin"})
            self.assertTrue(entered.wait(10))
            self.client.post(f"/api/runs/{self.run_id}/analyses/{created['analysis_id']}/cancel")
            gate.set()
            state = self.wait(str(created["analysis_id"]), timeout=10)
        self.assertEqual(state["status"], "cancelled", state)
        self.assertEqual(len(checks), 1)

    def test_memory_import_never_follows_links(self) -> None:
        volatility = self.evidence / "vol"
        volatility.mkdir()
        (volatility / "windows.pslist.json").write_text(
            json.dumps({"rows": [{"PID": 1, "PPID": 0, "ImageFileName": "System"}]}), encoding="utf-8"
        )
        outside = self.base / "outside-vol"
        write_volatility(outside)  # pslist + netscan outside the allowed roots
        self._link_or_skip(outside, volatility / "esc")
        self._link_or_skip(volatility, volatility / "loop")
        state = self.wait(str(self.submit("memory-import", {"volatility_output_dir": str(volatility)})["analysis_id"]), timeout=30)
        self.assertEqual(state["status"], "completed", state)
        rows = self.rows(state["analysis_id"], limit=100)["rows"]
        self.assertEqual({row["details"]["memory_artifact_type"] for row in rows}, {"memory-process"})
        self.assertTrue(all(str(outside) not in json.dumps(row) for row in rows))
        self.assertEqual(state["summary"]["file_count"], 1)
        self.assertGreaterEqual(state["summary"]["skipped_link_count"], 2)

    def test_vsc_compare_never_indexes_through_links(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        (snapshot / "Users").mkdir(parents=True)
        (snapshot / "Users" / "gone.txt").write_text("deleted later", encoding="utf-8")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside", encoding="utf-8")
        self._link_or_skip(outside, snapshot / "esc")
        self._link_or_skip(snapshot, snapshot / "loop")
        self._link_or_skip(outside, self.evidence / "esc")
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            state = self.wait(str(self.submit("vsc-compare", {"snapshot_root": str(snapshot)})["analysis_id"]), timeout=30)
        self.assertEqual(state["status"], "completed", state)
        paths = {row["details"]["path"] for row in self.rows(state["analysis_id"], limit=100)["rows"]}
        self.assertIn("Users/gone.txt", paths)
        self.assertFalse([path for path in paths if "secret" in path or path.startswith(("esc/", "loop/"))], paths)
        compare_json = json.loads((Path(state["output_dir"]) / "vsc-compare.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(compare_json["comparisons"][0]["summary"]["link_skipped_count"], 3)

    def test_ntfs_join_indexes_only_full_unambiguous_paths(self) -> None:
        rows_path = self.base / "ntfs-rows.jsonl"
        full = "reconstructed-bounded-parent-cache"

        def row(path: str, entry: int, *, in_use: bool = True, status: str = full) -> dict[str, object]:
            return {
                "artifact_type": "ntfs-meta-row",
                "details": {"source": "mft", "path": path, "path_status": status, "entry_number": entry, "in_use": in_use},
            }

        rows = [
            row("orphan.txt", 10, status="partial-parent-outside-bounded-scan"),  # bare name of a partial path
            row("\\Users\\twice.txt", 11),
            row("\\Users\\twice.txt", 12),  # two in-use rows: ambiguous
            row("\\Users\\kept.txt", 13, in_use=False),
            row("\\Users\\kept.txt", 14),  # one in-use beats deleted
            row("\\Users\\kept.txt", 15, in_use=False),
            row("\\Users\\ghost.txt", 16, in_use=False),
            row("\\Users\\ghost.txt", 17, in_use=False),  # only deleted rows, two: ambiguous
            row("\\Users\\once.txt", 18, in_use=False),  # a single deleted row still joins
            row("\\Windows", 19, status="partial-cycle-detected"),
        ]
        rows_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n", encoding="utf-8")
        index = files_ntfs.build_ntfs_index(("r", "a", 0, 0), rows_path)
        self.assertIsNone(index.lookup("orphan.txt"))
        self.assertIsNone(index.lookup("users/twice.txt"))
        self.assertEqual(index.lookup("users/kept.txt")["entry_number"], 14)
        self.assertIsNone(index.lookup("users/ghost.txt"))
        self.assertEqual(index.lookup("users/once.txt")["entry_number"], 18)
        self.assertEqual(index.ambiguous, 2)
        self.assertNotIn("windows", index.top_level)  # a partial "Windows" row is no volume sentinel

    def test_ntfs_rows_with_partial_paths_never_join_files(self) -> None:
        # alice.txt's parent (64) is outside this MFT: its path is the bare name "alice.txt".
        records = {
            5: mft_record(name=".", parent=5, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
            63: mft_record(name="Users", parent=5, in_use=True, directory=True, created="2024-01-01T00:00:00Z"),
            65: mft_record(name="alice.txt", parent=64, in_use=True, directory=False, created="2024-01-02T03:04:05Z"),
        }
        mft = b"".join(records.get(number, bytes(1024)) for number in range(66))
        files_path = Path(json.loads((self.run_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))["outputs"]["files"])
        payload = json.loads(files_path.read_text(encoding="utf-8"))
        payload["candidates"].append({"path": str(self.evidence / "alice.txt"), "name": "alice.txt", "size": 1, "categories": []})
        files_path.write_text(json.dumps(payload), encoding="utf-8")
        state = self.run_ntfs(mft=mft)
        self.assertEqual(state["status"], "completed", state)
        alice = next(row["details"] for row in self.rows(state["analysis_id"], limit=50)["rows"] if row["details"].get("name") == "alice.txt")
        self.assertNotEqual(alice["path_status"], "reconstructed-bounded-parent-cache")
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        self.assertEqual(page["ntfs_join"]["matched"], 0, page["ntfs_join"])
        self.assertTrue(all(row["ntfs"] is None for row in page["candidates"]))

    def test_mft_with_4096_byte_records(self) -> None:
        state = self.run_ntfs(mft=synthetic_mft(record_size=4096))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["mft_record_size"], 4096)
        self.assertEqual(state["summary"]["mft_record_count"], 4)
        by_name = {row["details"]["name"]: row["details"] for row in self.rows(state["analysis_id"], limit=50)["rows"]}
        alice = by_name["alice.txt"]
        self.assertEqual((alice["entry_number"], alice["path"], alice["record_offset"]), (65, "\\Users\\alice.txt", 65 * 4096))
        self.assertEqual(alice["path_status"], "reconstructed-bounded-parent-cache")
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        self.assertEqual(page["candidates"][0]["ntfs"]["entry_number"], 65)

    def test_files_join_skips_unparsed_ntfs_analyses(self) -> None:
        parsed = self.run_ntfs()
        unparsed = self.run_ntfs(options={"parse": False})
        self.assertEqual(unparsed["status"], "completed", unparsed)
        with patch.object(analysis_kinds, "MFT_MAX_PARSE_RECORDS", 2):
            too_large = self.run_ntfs()
        self.assertEqual(too_large["status"], "completed", too_large)
        self.assertEqual(too_large["summary"]["parse_status"], "too_large")
        self.assertIn("한도", too_large["summary"]["parse_skipped_reason"])
        self.assertEqual(too_large["row_count"], 0)
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        self.assertEqual(page["ntfs_join"]["analysis_id"], parsed["analysis_id"])
        self.assertEqual(page["ntfs_join"]["status"], "joined")
        self.assertEqual(page["candidates"][0]["ntfs"]["entry_number"], 65)

    def test_vsc_extract_refuses_output_inside_evidence(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        (snapshot / "Users").mkdir(parents=True)
        (snapshot / "Users" / "gone.txt").write_text("deleted later", encoding="utf-8")
        elsewhere = self.base / "elsewhere"
        roots = os.pathsep.join(f'"{path}"' for path in (snapshot, self.evidence))
        outputs = os.pathsep.join(f'"{path}"' for path in (snapshot, self.evidence, elsewhere))
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: roots, analyses.ANALYSIS_OUTPUT_ROOTS_ENV: outputs}):
            for target in (snapshot / "out", snapshot, self.evidence / "out", self.evidence):
                detail = self.submit("vsc-extract", {"snapshot_root": str(snapshot), "output_dir": str(target)}, expect=403)["detail"]
                self.assertIn("증거 경로", detail)
            allowed = self.submit("vsc-extract", {"snapshot_root": str(snapshot), "output_dir": str(elsewhere), "status": ["deleted"]})
            state = self.wait(str(allowed["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertFalse((snapshot / "out").exists())
        self.assertFalse((self.evidence / "out").exists())

    def test_vsc_extract_inside_run_output_next_to_evidence_is_allowed(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        snapshot.mkdir()
        (snapshot / "gone.txt").write_text("x", encoding="utf-8")
        scope = analyses.run_scope(self.store, self.run_id)
        evidence_scope = analyses.RunScope(
            store=scope.store,
            run_id=scope.run_id,
            job=scope.job,
            summary={**scope.summary, "root": str(self.base), "scan_scope_root": str(self.base)},
            output_dir=scope.output_dir,
        )
        # The evidence root (base) holds the run output dir: a destination in the latter is fine ...
        analysis_kinds.reject_output_in_evidence((self.run_dir / "x").resolve(), snapshot.resolve(), evidence_scope)
        # ... but not one beside it in the evidence, and never one inside a stage dir under the output dir.
        with self.assertRaises(analyses.HTTPException):
            analysis_kinds.reject_output_in_evidence((self.base / "x").resolve(), snapshot.resolve(), evidence_scope)
        stage_scope = analyses.RunScope(
            store=scope.store,
            run_id=scope.run_id,
            job=scope.job,
            summary={**scope.summary, "source": {**scope.source, "stage_dir": str(self.run_dir / "stage")}},
            output_dir=scope.output_dir,
        )
        with self.assertRaises(analyses.HTTPException) as caught:
            analysis_kinds.reject_output_in_evidence((self.run_dir / "stage" / "x").resolve(), snapshot.resolve(), stage_scope)
        self.assertEqual(caught.exception.status_code, 403)

    def _blocking_runner(self):
        slow_scan, entered, gate = self._blocking_scan()
        runner = analyses.AnalysisRunner(max_workers=1)
        self.addCleanup(runner.shutdown)
        patcher = patch.object(analysis_kinds, "_scan_source", slow_scan)
        patcher.start()
        self.addCleanup(patcher.stop)
        return runner, entered, gate

    def test_cancelling_a_queued_analysis_ends_it_at_once(self) -> None:
        volatility = self.evidence / "vol"
        write_volatility(volatility)
        runner, entered, gate = self._blocking_runner()
        scope = analyses.run_scope(self.store, self.run_id)
        running = runner.submit(scope, "carve", {"ext": ".bin"})
        self.assertTrue(entered.wait(10))
        queued = runner.submit(scope, "memory-import", {"volatility_output_dir": str(volatility)})
        self.assertEqual(queued["status"], "queued")
        state = runner.cancel(self.run_dir, str(queued["analysis_id"]))  # the only worker is still busy
        self.assertEqual(state["status"], "cancelled", state)
        self.assertTrue(state["finished_at"])
        self.assertIsNone(runner._context(self.run_dir, str(queued["analysis_id"])))
        stored = analyses.read_state_file(self.run_dir / "analyses" / str(queued["analysis_id"]) / "analysis.json")
        self.assertEqual(stored["status"], "cancelled")
        again = runner.submit(scope, "memory-import", {"volatility_output_dir": str(volatility)})  # kind freed
        self.assertEqual(again["status"], "queued")
        gate.set()
        deadline = time.monotonic() + 10
        while (runner.load_state(self.run_dir, str(again["analysis_id"])) or {}).get("status") != "completed":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        self.assertEqual(runner.load_state(self.run_dir, str(running["analysis_id"]))["status"], "completed")
        self.assertEqual(runner.load_state(self.run_dir, str(queued["analysis_id"]))["status"], "cancelled")

    def test_submit_failure_after_registration_is_not_left_registered(self) -> None:
        def broken_pool(_runner):
            raise RuntimeError("can't start new thread")

        with patch.object(analyses.AnalysisRunner, "_get_pool", broken_pool):
            created = self.submit("carve", {"ext": ".bin"})
        self.assertEqual(created["status"], "failed", created)
        self.assertIn("분석 실행기를 시작할 수 없습니다", created["analysis"]["error"])
        self.assertIsNone(analyses.ANALYSIS_RUNNER._context(self.run_dir, str(created["analysis_id"])))
        stored = self.client.get(f"/api/runs/{self.run_id}/analyses/{created['analysis_id']}").json()
        self.assertEqual(stored["status"], "failed")
        self.assertTrue(stored["finished_at"])

        def broken_submit(_pool, *_args):
            raise MemoryError("no memory")

        with patch.object(analyses.DaemonWorkerPool, "submit", broken_submit):
            created = self.submit("carve", {"ext": ".bin"})
        self.assertEqual(created["status"], "failed", created)
        again = self.submit("carve", {"ext": ".bin"})  # the kind is free again (no 409)
        self.assertEqual(self.wait(str(again["analysis_id"]))["status"], "completed")

    def test_ocr_reuse_index_stops_at_row_count(self) -> None:
        directory = self.run_dir / "analyses" / "20990101T000000-aaaaaaaa"
        directory.mkdir(parents=True)
        (directory / "analysis.json").write_text(
            json.dumps({"analysis_id": directory.name, "kind": "ocr-batch", "status": "running", "created_at": "2099-01-01T00:00:00+00:00", "row_count": 1}),
            encoding="utf-8",
        )
        counted = {"artifact_type": "ocr-batch-row", "details": {"source_path": str(self.evidence / "a.png"), "status": "ok", "text": "a"}}
        unflushed = {"artifact_type": "ocr-batch-row", "details": {"source_path": str(self.evidence / "b.png"), "status": "ok", "text": "b"}}
        (directory / "rows.jsonl").write_text(json.dumps(counted) + "\n" + json.dumps(unflushed) + "\n", encoding="utf-8")
        states = [{"analysis_id": directory.name, "kind": "ocr-batch", "status": "running", "row_count": 1}]
        self.assertEqual(analysis_kinds.find_ocr_result(self.run_dir, self.evidence / "a.png", states=states)["text"], "a")
        self.assertIsNone(analysis_kinds.find_ocr_result(self.run_dir, self.evidence / "b.png", states=states))

    def test_analysis_route_errors_are_korean(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        response = self.client.get(f"/api/runs/{self.run_id}/analyses/{state['analysis_id']}/rows", params={"sort": "details.offset", "order": "sideways"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("정렬 순서", response.json()["detail"])
        url = f"/api/runs/{self.run_id}/artifacts"
        for token, needle in (("nope", "형식"), ("zzz-none:0:0", "없는 종류")):
            response = self.client.get(url, params={"artifact_type": "service", "limit": 5, "after": token})
            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn(needle, response.json()["detail"])

    def test_vsc_discover_never_suggests_run_outputs(self) -> None:
        run_dir = write_run(self.base, "rapidtriage-run-20261012", self.evidence)
        # A previous extract copy inside the run output dir, named like a snapshot.
        (run_dir / "analyses" / "x" / "extract" / "evidence" / "HarddiskVolumeShadowCopy9").mkdir(parents=True)
        (run_dir / "HarddiskVolumeShadowCopy8").mkdir()
        (self.base / "rapidtriage-run-old-vss1").mkdir()
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        snapshot.mkdir()
        run_id = self.store.import_completed_run(run_dir).run_id
        for env in ({}, {analyses.ANALYSIS_ROOTS_ENV: f'"{self.base}"'}):
            with patch.dict(os.environ, env):
                response = self.client.post(f"/api/runs/{run_id}/analyses", json={"kind": "vsc-discover", "options": {}})
                self.assertEqual(response.status_code, 202, response.text)
                analysis_id = response.json()["analysis_id"]
                deadline = time.monotonic() + 20
                while True:
                    state = self.client.get(f"/api/runs/{run_id}/analyses/{analysis_id}").json()
                    if state["status"] in analyses.TERMINAL_STATUSES or time.monotonic() > deadline:
                        break
                    time.sleep(0.02)
            self.assertEqual(state["status"], "completed", state)
            rows = self.client.get(f"/api/runs/{run_id}/analyses/{analysis_id}/rows").json()["rows"]
            roots = [Path(row["details"]["snapshot_root"]) for row in rows]
            own = run_dir.resolve()
            self.assertFalse([root for root in roots if root == own or own in root.parents], roots)
            self.assertFalse([root for root in roots if root.name.startswith("rapidtriage-run")], roots)
            if env:
                self.assertIn(snapshot.resolve(), roots)

    def test_link_to_network_share_refused_before_resolve(self) -> None:
        resolved: list[str] = []
        real_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            if "netlink" in str(path):
                resolved.append(str(path))
            return real_resolve(path, *args, **kwargs)

        for target in ("\\\\server\\share\\vol", "\\\\?\\UNC\\server\\share\\vol", "//server/share/vol"):
            def fake_target(path, target=target):
                return target if Path(path).name == "netlink" else None

            with patch.object(analyses, "_link_target", fake_target), patch.object(Path, "resolve", resolve):
                response = self.client.post(
                    f"/api/runs/{self.run_id}/analyses",
                    json={"kind": "memory-import", "options": {"volatility_output_dir": str(self.evidence / "netlink" / "sub")}},
                )
            self.assertEqual(response.status_code, 403, (target, response.text))
            self.assertIn("링크", response.json()["detail"])
        self.assertEqual(resolved, [], "a link to a network path must be refused before resolve()")

    def test_link_precheck_follows_targets_inside_roots(self) -> None:
        inner = self.evidence / "vol"
        write_volatility(inner)
        self._link_or_skip(inner, self.evidence / "vol-link")
        state = self.wait(str(self.submit("memory-import", {"volatility_output_dir": str(self.evidence / "vol-link")})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(Path(state["options"]["volatility_output_dir"]), inner.resolve())

    def test_filter_scan_ending_exactly_at_cap_is_not_truncated(self) -> None:
        from rapidtriage.api.app.artifact_filter import filter_artifact_page

        payload = {"records_path": str(self.system_records), "record_count": 4, "artifacts": []}
        exact = filter_artifact_page(payload, payload_path=self.system_records, path_contains="svc", offset=0, limit=10, scan_cap=4)
        self.assertEqual((exact["pagination"]["scanned"], exact["pagination"]["truncated"], exact["pagination"]["total"]), (4, False, 3))
        short = filter_artifact_page(payload, payload_path=self.system_records, path_contains="svc", offset=0, limit=10, scan_cap=3)
        self.assertEqual((short["pagination"]["scanned"], short["pagination"]["truncated"], short["pagination"]["total"]), (3, True, None))

    def test_sort_cache_drops_older_record_limits_of_a_kind(self) -> None:
        cache = artifact_sort.SortIndexCache()

        def ready(record_limit: int):
            deadline = time.monotonic() + 10
            while True:
                state = cache.lookup(
                    run_id="r", kind="analysis:x", key="details.n", records_path=self.system_records, profiles=None, record_limit=record_limit
                )
                if state.status != "building" or time.monotonic() > deadline:
                    return state
                time.sleep(0.02)

        self.assertEqual(ready(2).status, "ready")
        self.assertEqual(ready(3).status, "ready")
        self.assertEqual([key[1] for key in cache.cached_keys()], ["analysis:x#3"])

    # -- real-data QA follow-ups (2026-10-12) ---------------------------------------------

    def test_carve_cancel_lands_inside_a_large_file(self) -> None:
        from rapidtriage.core import carving

        chunk = 8192
        (self.evidence / "big.big").write_bytes(b"".join(b"\x00" * 100 + JPEG + b"\x00" * (chunk - 100 - len(JPEG)) for _ in range(64)))
        checks: list[int] = []
        real_check = analyses.AnalysisContext.check_cancel
        real_write = analyses.AnalysisContext.write_row

        def check_cancel(context):
            checks.append(1)
            return real_check(context)

        def write_row(context, row):
            real_write(context, row)
            if context._pending_rows + int(context.state.get("row_count") or 0) >= 2:
                context.cancel_event.set()  # cancel requested while the single big file is mid-scan

        with (
            patch.object(carving, "SCAN_CHUNK_BYTES", chunk),
            patch.object(analyses.AnalysisContext, "check_cancel", check_cancel),
            patch.object(analyses.AnalysisContext, "write_row", write_row),
        ):
            state = self.wait(str(self.submit("carve", {"ext": ".big", "kinds": ["jpeg"]})["analysis_id"]))
        self.assertEqual(state["status"], "cancelled", state)
        self.assertEqual(state["row_count"], 2, "rows found before the cancel are flushed; the rest of the file is not scanned")
        self.assertEqual(state["progress"]["done"], 0)  # the cancel landed inside the only source file
        self.assertEqual(len(self.rows(state["analysis_id"])["rows"]), 2)
        # A file without hits is still checked once per chunk (no 256 MB read without a check).
        (self.evidence / "zeros.zz").write_bytes(bytes(chunk * 16))
        checks.clear()
        with patch.object(carving, "SCAN_CHUNK_BYTES", chunk), patch.object(analyses.AnalysisContext, "check_cancel", check_cancel):
            done = self.wait(str(self.submit("carve", {"ext": ".zz"})["analysis_id"]))
        self.assertEqual(done["status"], "completed", done)
        self.assertGreaterEqual(len(checks), 16)

    def test_carve_rejected_candidates_do_not_consume_cap(self) -> None:
        (self.evidence / "hive.fp").write_bytes(b"\xff\xd8\xff\x02" * 5 + b"\x00" * 64 + JPEG)
        state = self.wait(str(self.submit("carve", {"ext": ".fp", "max_candidates": 1})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        rows = self.rows(state["analysis_id"])["rows"]
        self.assertEqual([row["details"]["status"] for row in rows], ["footer-validated"], rows)
        self.assertEqual((state["summary"]["candidate_count"], state["summary"]["rejected_count"]), (1, 5))
        self.assertEqual(state["summary"]["rejected_row_count"], 0)
        listed = self.wait(str(self.submit("carve", {"ext": ".fp", "max_candidates": 1, "include_rejected": True})["analysis_id"]))
        statuses = [row["details"]["status"] for row in self.rows(listed["analysis_id"], limit=50)["rows"]]
        self.assertEqual(statuses.count("false-positive-rejected"), 1)  # rejected rows have their own cap
        self.assertEqual(statuses.count("footer-validated"), 1)
        self.assertEqual(listed["summary"]["rejected_count"], 5)

    def _snapshot_with_deletions(self) -> Path:
        snapshot = self.base / "HarddiskVolumeShadowCopy1"
        snapshot.mkdir()
        for name in ("zz-gone-1.txt", "zz-gone-2.txt", "zz-gone-3.txt"):  # sort after every current file
            (snapshot / name).write_text(name, encoding="utf-8")
        return snapshot

    def test_vsc_compare_cap_lists_changes_before_additions(self) -> None:
        snapshot = self._snapshot_with_deletions()
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            state = self.wait(str(self.submit("vsc-compare", {"snapshot_root": str(snapshot), "max_records": 2})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        rows = self.rows(state["analysis_id"])["rows"]
        self.assertEqual([row["details"]["status"] for row in rows], ["deleted", "deleted"])
        summary = state["summary"]
        self.assertEqual((summary["deleted"], summary["modified"]), (3, 0))
        self.assertGreaterEqual(summary["added"], 5)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["change_count"], 3 + summary["added"])
        self.assertIn("최대 기록 수", summary["truncated_reason"])
        # Default cap: everything listed, deleted first, then added; not truncated.
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            full = self.wait(str(self.submit("vsc-compare", {"snapshot_root": str(snapshot)})["analysis_id"]))
        statuses = [row["details"]["status"] for row in self.rows(full["analysis_id"], limit=100)["rows"]]
        self.assertEqual(statuses, sorted(statuses, key=lambda value: value != "deleted"))
        self.assertFalse(full["summary"]["truncated"])
        self.assertIsNone(full["summary"]["truncated_reason"])
        # Core/CLI: exact counts beyond the cap, deletions listed first, truncated only when rows were left out.
        payload = vsc.compare_vsc_snapshots(self.evidence, [snapshot], max_records=2)
        comparison = payload["comparisons"][0]
        self.assertEqual([record["status"] for record in comparison["records"]], ["deleted", "deleted"])
        self.assertEqual(payload["summary"]["deleted"], 3)
        self.assertTrue(comparison["summary"]["truncated"])
        exact = vsc.compare_vsc_snapshots(self.evidence, [snapshot], max_records=comparison["summary"]["change_count"])
        self.assertFalse(exact["comparisons"][0]["summary"]["truncated"])

    def test_vsc_extract_selects_from_the_complete_change_set(self) -> None:
        snapshot = self._snapshot_with_deletions()
        # Core/CLI: --max-records caps the *selected* statuses, never filled by unselected additions.
        manifest = vsc.extract_vsc_changes(self.evidence, [snapshot], self.base / "cli-extract", statuses=["deleted"], max_records=2)
        self.assertEqual(manifest["summary"]["copied_count"], 2)
        self.assertTrue(manifest["summary"]["selection_truncated"])
        self.assertEqual(manifest["comparison_summary"]["deleted"], 3)
        captured: dict[str, object] = {}
        real_extract = vsc.extract_vsc_changes

        def spy(*args, **kwargs):
            captured.update(kwargs)
            return real_extract(*args, **kwargs)

        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}), patch.object(vsc, "extract_vsc_changes", spy):
            state = self.wait(str(self.submit("vsc-extract", {"snapshot_root": str(snapshot), "max_file_count": 2})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(captured["max_records"], 0)  # no listing cap before selection
        summary = state["summary"]
        self.assertEqual((summary["selected_count"], summary["copied_count"]), (3, 2))
        self.assertEqual(summary["skipped_reason_counts"], {"max-file-count": 1})
        self.assertTrue(summary["truncated"])
        self.assertIn("최대 파일 수", summary["truncated_reason"])
        rows = self.rows(state["analysis_id"])["rows"]
        self.assertEqual(sorted(row["details"]["path"] for row in rows), ["zz-gone-1.txt", "zz-gone-2.txt", "zz-gone-3.txt"])

    def test_ntfs_meta_parses_an_extracted_mft_without_sleuthkit(self) -> None:
        mft = self.evidence / "$MFT"
        record_zero = mft_record(name="$MFT", parent=5, in_use=True, directory=False, created="2024-01-01T00:00:00Z")
        mft.write_bytes(synthetic_mft({0: record_zero}))  # a real $MFT starts with its own FILE record

        def no_extract(*_args, **_kwargs):
            raise AssertionError("an extracted $MFT must not go through Sleuth Kit")

        with patch.object(analysis_kinds, "NTFS_EXTRACTOR", no_extract):
            created = self.submit("ntfs-meta", {"image_path": str(mft)})
            self.assertEqual(created["analysis"]["options"]["source"], "mft")  # detected
            state = self.wait(str(created["analysis_id"]))
            explicit = self.wait(str(self.submit("ntfs-meta", {"image_path": str(mft), "source": "mft"})["analysis_id"]))
        for item in (state, explicit):
            self.assertEqual(item["status"], "completed", item)
            self.assertEqual(item["summary"]["mft_record_count"], 5)
            self.assertEqual(item["summary"]["extraction_status"], "not-needed-raw-mft")
            self.assertEqual(item["summary"]["source"], "mft")
        page = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10}).json()
        self.assertEqual(page["ntfs_join"]["status"], "joined", page["ntfs_join"])
        self.assertEqual(page["candidates"][0]["ntfs"]["entry_number"], 65)
        # A disk image is not taken as a raw $MFT; an explicit wrong source is a Korean 400.
        detail = self.submit("ntfs-meta", {"image_path": str(self.evidence / "disk.E01"), "source": "mft"}, expect=400)["detail"]
        self.assertIn("$MFT", detail)
        truncated = self.evidence / "partial.mft"
        truncated.write_bytes(mft.read_bytes()[:1500])  # FILE at 0 but not a whole number of records
        self.assertIsNone(analysis_kinds.raw_mft_record_size(truncated))
        self.assertEqual(analysis_kinds.raw_mft_record_size(mft), 1024)

    def test_ntfs_meta_explicit_image_path_error_names_the_option(self) -> None:
        detail = self.submit("ntfs-meta", {"image_path": str(self.evidence / "Users")}, expect=400)["detail"]
        self.assertIn("image_path", detail)
        self.assertNotIn("이 런의 소스", detail)

    def test_korean_particles_follow_the_final_consonant(self) -> None:
        errors = self.submit("carve", {"max_scan_bytes": 17 * 1024**3, "max_candidates": 0, "extract": "x"}, expect=422)["detail"]
        by_field = {error["loc"][1]: error["msg"] for error in errors}
        self.assertEqual(by_field["max_scan_bytes"], "파일당 최대 스캔 바이트는 16,384 MB 이하여야 합니다")
        self.assertEqual(by_field["max_candidates"], "최대 후보 수는 1 이상이어야 합니다")
        self.assertEqual(by_field["extract"], "카빙 파일 저장은 true/false 여야 합니다")
        self.assertFalse([msg for msg in by_field.values() if "(는)" in msg or "(가)" in msg])
        body = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": 5}).json()["detail"]
        self.assertEqual(body[0]["msg"], "분석 종류(kind)는 문자열이어야 합니다")
        cases = {
            ("디스크 이미지", "은", "는"): "디스크 이미지는",
            ("파싱", "은", "는"): "파싱은",
            ("파티션 시작 섹터", "이", "가"): "파티션 시작 섹터가",
            ("스냅샷 루트", "이", "가"): "스냅샷 루트가",
            ("OCR 언어", "이", "가"): "OCR 언어가",
            ("최대 1", "은", "는"): "최대 1은",
            ("target", "은", "는"): "target은(는)",
        }
        for (word, final, open_), expected in cases.items():
            self.assertEqual(analyses.with_josa(word, final, open_), expected)

    def test_console_route_errors_are_korean(self) -> None:
        missing = self.client.get("/api/runs/no-such-run")
        self.assertEqual((missing.status_code, missing.json()["detail"]), (404, "런을 찾을 수 없습니다"))
        self.assertEqual(self.client.get("/api/runs/no-such-run/files").json()["detail"], "런 출력을 찾을 수 없습니다")
        database = self.run_dir / "rapidtriage-case.db"
        case_id = f"run-{self.run_id}"
        open_case_database(database).create_case(case_id=case_id, name="run case")
        body = {
            "database": str(database),
            "case_id": case_id,
            "run_id": self.run_id,
            "status": "relevant",
            "targets": [{"collection": "files", "locator": "/candidates/0"}],
        }
        response = self.client.post("/api/case-db/review-batch", json=body)
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("케이스 DB에 이 런 로케이터에 해당하는 행이 없습니다", response.json()["detail"])

    def test_rows_order_is_validated_without_sort(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        url = f"/api/runs/{self.run_id}/analyses/{state['analysis_id']}/rows"
        response = self.client.get(url, params={"order": "up"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "정렬 순서(order)는 asc 또는 desc여야 합니다")
        self.assertEqual(self.client.get(url, params={"order": "DESC"}).status_code, 200)
        # GET /artifacts keeps ignoring an order without sort.
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/artifacts", params={"order": "up"}).status_code, 200)

    def test_analysis_roots_env_is_input_only(self) -> None:
        snapshot = self._snapshot_with_deletions()
        inputs = self.base / "operator-inputs"
        (inputs / "out").mkdir(parents=True)
        roots = os.pathsep.join(f'"{path}"' for path in (snapshot, inputs))
        options = {"snapshot_root": str(snapshot), "status": ["deleted"]}
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: roots}):
            os.environ.pop(analyses.ANALYSIS_OUTPUT_ROOTS_ENV, None)
            for target in (inputs, inputs / "out"):
                detail = self.submit("vsc-extract", {**options, "output_dir": str(target)}, expect=403)["detail"]
                self.assertIn("허용 범위", detail)
            # An output root inside an operator input root is still evidence.
            with patch.dict(os.environ, {analyses.ANALYSIS_OUTPUT_ROOTS_ENV: f'"{inputs / "out"}"'}):
                detail = self.submit("vsc-extract", {**options, "output_dir": str(inputs / "out")}, expect=403)["detail"]
                self.assertIn("증거 경로", detail)
            target = self.base / "exports"
            with patch.dict(os.environ, {analyses.ANALYSIS_OUTPUT_ROOTS_ENV: f'"{target}"'}):
                state = self.wait(str(self.submit("vsc-extract", {**options, "output_dir": str(target)})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["copied_count"], 3)
        self.assertEqual(list((inputs / "out").iterdir()), [])
        scope = analyses.run_scope(self.store, self.run_id)
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: roots}):
            self.assertFalse([root for root in scope.output_roots() if root in analyses.extra_analysis_roots()])

    def test_cross_case_eligibility_and_occurrence_links(self) -> None:
        sha = "cd" * 32
        build_case_db(self.run_dir / "rapidtriage-case.db", f"run-{self.run_id}", sha, with_source=True)
        other_dir = write_run(self.base, "other-run", self.evidence)
        other_id = self.store.import_completed_run(other_dir).run_id
        build_case_db(other_dir / "rapidtriage-case.db", f"run-{other_id}", sha, with_source=True)
        bare_dir = write_run(self.base, "bare-run", self.evidence)
        bare_id = self.store.import_completed_run(bare_dir).run_id
        runs = {row["run_id"]: row for row in self.client.get("/api/runs").json()["runs"]}
        self.assertEqual((runs[other_id]["case_db_available"], runs[other_id]["cross_case_eligible"]), (True, True))
        self.assertIsNone(runs[other_id]["cross_case_ineligible_reason"])
        self.assertEqual((runs[bare_id]["case_db_available"], runs[bare_id]["cross_case_eligible"]), (False, False))
        self.assertIn("케이스 DB", runs[bare_id]["cross_case_ineligible_reason"])
        self.assertFalse(self.client.get(f"/api/runs/{bare_id}").json()["cross_case_eligible"])
        self.store.get(other_id).status = "running"
        running = next(row for row in self.client.get("/api/runs").json()["runs"] if row["run_id"] == other_id)
        self.assertEqual((running["case_db_available"], running["cross_case_eligible"]), (True, False))
        self.store.get(other_id).status = "completed"
        state = self.wait(str(self.submit("cross-case", {"case_ids": [other_id]})["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        shared = next(row["details"] for row in self.rows(state["analysis_id"])["rows"] if row["details"]["kind"] == "sha256")
        by_run = {occurrence["run_id"]: occurrence for occurrence in shared["occurrences"]}
        self.assertEqual(set(by_run), {self.run_id, other_id})
        for run_id, occurrence in by_run.items():
            self.assertEqual(occurrence["case_id"], run_id)
            self.assertEqual(occurrence["target"], {"collection": "files", "kind": "", "locator": "/candidates/0"})

    def test_directory_rows_get_metadata_without_preview(self) -> None:
        params = {"path": str(self.evidence / "Users")}
        metadata = self.client.get(f"/api/runs/{self.run_id}/source-metadata", params={**params, "hash": "true"})
        self.assertEqual(metadata.status_code, 200, metadata.text)
        self.assertEqual((metadata.json()["is_directory"], metadata.json()["size"], metadata.json()["hash_status"]), (True, None, "not-applicable-directory"))
        preview = self.client.get(f"/api/runs/{self.run_id}/source-preview", params=params)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual((preview.json()["is_directory"], preview.json()["preview_type"]), (True, "directory"))
        self.assertIn("디렉터리", preview.json()["message"])
        file_metadata = self.client.get(f"/api/runs/{self.run_id}/source-metadata", params={"path": str(self.evidence / "notes.txt")}).json()
        self.assertFalse(file_metadata["is_directory"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/source-hex-range", params=params).status_code, 404)



    # -- real-data QA round 2 ------------------------------------------------------------

    def _run_case_db(self) -> tuple[Path, str]:
        database = self.run_dir / "rapidtriage-case.db"
        case_id = f"run-{self.run_id}"
        open_case_database(database).create_case(case_id=case_id, name="run case")
        return database, case_id

    def _mark(self, database: Path, case_id: str, analysis_id: str, locator: str, status: str) -> None:
        body = {
            "database": str(database),
            "case_id": case_id,
            "run_id": self.run_id,
            "status": status,
            "targets": [{"collection": "analysis", "kind": analysis_id, "locator": locator}],
        }
        response = self.client.post("/api/case-db/review-batch", json=body)
        self.assertEqual(response.status_code, 200, response.text)

    def test_cleared_review_marks_leave_board_and_counts(self) -> None:
        state = self.wait(str(self.submit("carve", {"ext": ".bin"})["analysis_id"]))
        database, case_id = self._run_case_db()
        self._mark(database, case_id, state["analysis_id"], "/rows/0", "relevant")
        self._mark(database, case_id, state["analysis_id"], "/rows/1", "relevant")
        self._mark(database, case_id, state["analysis_id"], "/rows/1", "unreviewed")  # toggled back: cleared
        marks = self.client.get(f"/api/runs/{self.run_id}/review-map").json()["marks"]
        self.assertEqual([mark["locator"] for mark in marks], ["/rows/0"])
        counts = self.client.get(f"/api/runs/{self.run_id}/review-counts").json()
        self.assertEqual(counts["by_status"], {"relevant": 1})
        self.assertEqual(counts["cleared"], 1)
        # The audit trail keeps the cleared mark.
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_mark").fetchone()[0], 2)
        finally:
            connection.close()
        # A note keeps an unreviewed mark on the board.
        body = {
            "database": str(database),
            "case_id": case_id,
            "run_id": self.run_id,
            "note": "확인 필요",
            "targets": [{"collection": "analysis", "kind": state["analysis_id"], "locator": "/rows/1"}],
        }
        self.assertEqual(self.client.post("/api/case-db/review-batch", json=body).status_code, 200)
        counts = self.client.get(f"/api/runs/{self.run_id}/review-counts").json()
        self.assertEqual((counts["by_status"], counts["cleared"]), ({"relevant": 1, "unreviewed": 1}, 0))
        # Board items for analysis rows carry a human title and a kind label, never the raw id.
        marks = self.client.get(f"/api/runs/{self.run_id}/review-map").json()["marks"]
        first = next(mark for mark in marks if mark["locator"] == "/rows/0")
        row = self.rows(state["analysis_id"])["rows"][0]
        self.assertEqual(first["target_kind"], "카빙 결과")
        self.assertEqual(first["analysis_kind"], "carve")
        self.assertNotIn(state["analysis_id"], first["title"])
        self.assertNotIn("analysis_row", first["title"])
        self.assertIn(Path(row["details"]["source_path"]).name, first["title"])
        self.assertIn(row["details"]["offset_hex"], first["title"])
        self.assertEqual(first["path"], row["path"])

    def test_analysis_row_titles_per_kind(self) -> None:
        title = analysis_kinds.analysis_row_title
        self.assertEqual(title("vsc-compare", {"details": {"status": "deleted", "path": "a/b.txt"}}, 0), "삭제 · a/b.txt")
        self.assertEqual(
            title("ntfs-meta", {"details": {"source": "mft", "entry_number": 70, "in_use": False, "name": None, "path": ""}}, 3),
            "MFT 엔트리 #70 (이름 없음) (삭제됨)",
        )
        self.assertEqual(title("ocr-batch", {"details": {"source_path": "C:\\x\\p.png", "text": "안녕\n세계"}}, 0), "p.png · 안녕 세계")
        self.assertEqual(title("cross-case", {"details": {"kind": "sha256", "indicator": "ab"}}, 0), "sha256 · ab")
        self.assertEqual(title("carve", {"details": {}}, 4), "카빙 결과 #4")
        self.assertEqual(analysis_kinds.analysis_kind_label("vsc-compare"), "볼륨 섀도우 비교 결과")

    def test_vsc_compare_snapshot_rows_open_in_viewer_by_row_locator(self) -> None:
        snapshot = self._snapshot_with_deletions()
        outside = self.base / "elsewhere.txt"
        outside.write_text("not evidence", encoding="utf-8")
        url = f"/api/runs/{self.run_id}/source-metadata"
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            state = self.wait(str(self.submit("vsc-compare", {"snapshot_root": str(snapshot)})["analysis_id"]))
            rows = self.rows(state["analysis_id"], limit=100)["rows"]
            deleted = [row for row in rows if row["details"]["status"] == "deleted"]
            first = deleted[0]
            other = next(row for row in rows if row["record_index"] != first["record_index"])
            plain = self.client.get(url, params={"path": first["path"]})
            # Without the row reference: the QA 404, now in Korean.
            self.assertEqual(plain.status_code, 404, plain.text)
            self.assertEqual(plain.json()["detail"]["message"], "허용된 증거 루트에서 원본 파일을 찾을 수 없습니다")
            ref = {"analysis_id": state["analysis_id"], "locator": f"/rows/{first['record_index']}"}
            opened = self.client.get(url, params={"path": first["path"], **ref})
            self.assertEqual(opened.status_code, 200, opened.text)
            self.assertEqual(opened.json()["name"], Path(first["path"]).name)
            preview = self.client.get(f"/api/runs/{self.run_id}/source-preview", params={"path": first["path"], **ref})
            self.assertEqual(preview.status_code, 200, preview.text)
            self.assertIn("zz-gone", preview.json()["text"])
            # Only the row's own path: another row's locator, or any other path, gets no access.
            mismatch = self.client.get(url, params={"path": first["path"], **ref, "locator": f"/rows/{other['record_index']}"})
            self.assertEqual(mismatch.status_code, 403, mismatch.text)
            self.assertEqual(self.client.get(url, params={"path": str(outside), **ref}).status_code, 403)
            self.assertEqual(self.client.get(url, params={"path": first["path"], **ref, "locator": "/rows/x"}).status_code, 400)
            self.assertEqual(self.client.get(url, params={"path": first["path"], **ref, "locator": "/rows/9999"}).status_code, 404)
            # A row path whose file vanished: 404 in Korean.
            Path(first["path"]).unlink()
            gone = self.client.get(url, params={"path": first["path"], **ref})
            self.assertEqual(gone.status_code, 404, gone.text)
            self.assertIn("원본 파일을 찾을 수 없습니다", gone.json()["detail"]["message"])
        # The snapshot root is re-checked now: once it is no longer an allowed input root, nothing is served.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(analyses.ANALYSIS_ROOTS_ENV, None)
            still = deleted[1]
            ref = {"analysis_id": state["analysis_id"], "locator": f"/rows/{still['record_index']}"}
            self.assertEqual(self.client.get(url, params={"path": still["path"], **ref}).status_code, 403)

    def test_analysis_row_source_never_follows_links_out(self) -> None:
        snapshot = self.base / "HarddiskVolumeShadowCopy2"
        snapshot.mkdir()
        secret = self.base / "secret"
        secret.mkdir()
        (secret / "zz-secret.txt").write_text("secret", encoding="utf-8")
        errors = make_directory_link(secret, snapshot / "zz-link")
        if errors:
            self.skipTest(f"cannot create a directory link: {errors}")
        directory = self.run_dir / "analyses" / "20990101T000000-aaaaaaaa"
        directory.mkdir(parents=True)
        linked = str(snapshot / "zz-link" / "zz-secret.txt")
        state = {"analysis_id": directory.name, "kind": "vsc-compare", "status": "completed", "row_count": 1, "options": {"snapshot_root": str(snapshot)}}
        (directory / "analysis.json").write_text(json.dumps(state), encoding="utf-8")
        row = {"artifact_type": "vsc-compare-row", "path": linked, "details": {"status": "deleted", "source_path": linked}}
        (directory / "rows.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{snapshot}"'}):
            response = self.client.get(
                f"/api/runs/{self.run_id}/source-metadata",
                params={"path": linked, "analysis_id": directory.name, "locator": "/rows/0"},
            )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("링크", response.json()["detail"])

    def test_source_not_found_message_is_korean(self) -> None:
        response = self.client.get(f"/api/runs/{self.run_id}/source-metadata", params={"path": str(self.evidence / "missing.txt")})
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(response.json()["detail"]["message"], "허용된 증거 루트에서 원본 파일을 찾을 수 없습니다")

    def test_ocr_row_errors_are_korean_with_raw_detail(self) -> None:
        english = "Error opening data file /usr/share/tessdata/kor.traineddata"

        def failing(image, **_kwargs):
            raise RuntimeError(english)

        engine = (SimpleNamespace(imread=lambda path, *args: object()), SimpleNamespace(Output=SimpleNamespace(DICT="dict"), image_to_data=failing))
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: engine):
            state = self.wait(str(self.submit("ocr-batch")["analysis_id"]))
        self.assertEqual(state["status"], "completed", state)
        details = self.rows(state["analysis_id"])["rows"][0]["details"]
        self.assertEqual(details["status"], "failed")
        self.assertTrue(details["error"].startswith("OCR 실패: OCR 언어 데이터"), details)
        self.assertNotIn("Error opening", details["error"])
        self.assertIn(english, details["error_detail"])
        # The missing-engine text raised from image_to_data fails the analysis (Korean), not a row.
        missing_text = "tesseract is not installed or it's not in your PATH. See README file for more information."

        def missing(image, **_kwargs):
            raise RuntimeError(missing_text)

        engine = (SimpleNamespace(imread=lambda path, *args: object()), SimpleNamespace(Output=SimpleNamespace(DICT="dict"), image_to_data=missing))
        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", lambda: engine):
            failed = self.wait(str(self.submit("ocr-batch", {"retry_failures": True})["analysis_id"]))
        self.assertEqual(failed["status"], "failed", failed)
        self.assertEqual(failed["error"], analysis_kinds.OCR_ENGINE_MISSING_MESSAGE)
        # Rows stored by older builds (English tail) are served, and copied, with a Korean error.
        legacy = self.run_dir / "analyses" / "99991231T000000-eeeeeeee"
        legacy.mkdir()
        legacy_state = {"analysis_id": legacy.name, "kind": "ocr-batch", "status": "completed", "created_at": "9999-12-31T00:00:00+00:00", "row_count": 1}
        (legacy / "analysis.json").write_text(json.dumps(legacy_state), encoding="utf-8")
        stored = {"source_path": str(self.evidence / "photo.png"), "status": "failed", "error": f"OCR 실패: {missing_text}"}
        (legacy / "rows.jsonl").write_text(json.dumps({"artifact_type": "ocr-batch-row", "details": stored}) + "\n", encoding="utf-8")
        served = self.rows(legacy.name)["rows"][0]["details"]
        self.assertEqual(served["error"], "OCR 실패: " + analysis_kinds.OCR_ENGINE_MISSING_MESSAGE)
        self.assertEqual(served["error_detail"], f"OCR 실패: {missing_text}")

        def never():
            raise AssertionError("copied rows never run OCR")

        with patch.object(analysis_kinds, "OCR_ENGINE_LOADER", never):
            copied = self.wait(str(self.submit("ocr-batch")["analysis_id"]))
        copied_row = json.loads((Path(copied["output_dir"]) / "rows.jsonl").read_text(encoding="utf-8").splitlines()[0])["details"]
        self.assertEqual(copied_row["reused_from"], legacy.name)
        self.assertNotIn("not installed", copied_row["error"])
        self.assertIn("not installed", copied_row["error_detail"])

    def test_scoped_browse_lists_only_allowed_roots(self) -> None:
        def browse(**params):
            return self.client.get("/api/browse", params=params)

        def keys(items) -> set[str]:
            return {os.path.normcase(item["path"]) for item in items}

        roots = browse(scope="analysis-input", run_id=self.run_id)
        self.assertEqual(roots.status_code, 200, roots.text)
        payload = roots.json()
        root_paths = keys(payload["roots"])
        self.assertIn(os.path.normcase(str(self.evidence.resolve())), root_paths)
        self.assertIn(os.path.normcase(str(self.run_dir.resolve())), root_paths)
        self.assertNotIn(os.path.normcase(str(self.base.resolve())), root_paths)
        self.assertEqual((payload["path"], payload["parent"], payload["at_roots"]), ("", None, True))
        self.assertEqual(keys(payload["entries"]), root_paths)
        listing = browse(scope="analysis-input", run_id=self.run_id, path=str(self.evidence)).json()
        self.assertIn("Users", [entry["name"] for entry in listing["entries"]])
        self.assertIsNone(listing["parent"])  # at a root: back to the root list
        nested = browse(scope="analysis-input", run_id=self.run_id, path=str(self.evidence / "Users")).json()
        self.assertEqual(os.path.normcase(nested["parent"]), os.path.normcase(str(self.evidence.resolve())))
        outside = browse(scope="analysis-input", run_id=self.run_id, path=str(self.base))
        self.assertEqual(outside.status_code, 403, outside.text)
        self.assertIn("허용 범위", outside.json()["detail"])
        # Operator input roots are listed for input fields but never for output fields.
        extra = self.base / "operator-inputs"
        extra.mkdir()
        with patch.dict(os.environ, {analyses.ANALYSIS_ROOTS_ENV: f'"{extra}"'}):
            os.environ.pop(analyses.ANALYSIS_OUTPUT_ROOTS_ENV, None)
            inputs = keys(browse(scope="analysis-input", run_id=self.run_id).json()["roots"])
            outputs = keys(browse(scope="analysis-output", run_id=self.run_id).json()["roots"])
            self.assertIn(os.path.normcase(str(extra.resolve())), inputs)
            self.assertEqual(outputs, {os.path.normcase(str(self.run_dir.resolve()))})
            self.assertEqual(browse(scope="analysis-output", run_id=self.run_id, path=str(extra)).status_code, 403)
        self.assertEqual(browse(scope="nope", run_id=self.run_id).status_code, 400)
        self.assertIn("run_id", browse(scope="analysis-input").json()["detail"])
        # The run dialog's unscoped picker is unchanged.
        self.assertEqual(browse(path=str(self.base)).status_code, 200)

    def test_ntfs_unnamed_mft_records_have_null_name(self) -> None:
        record = bytearray(mft_record(name="x", parent=64, in_use=False, directory=False, created="2024-01-04T00:00:00Z"))
        first_attribute = struct.unpack_from("<H", record, 0x14)[0]
        file_name_attribute = first_attribute + struct.unpack_from("<I", record, first_attribute + 4)[0]
        struct.pack_into("<I", record, file_name_attribute, 0xFFFFFFFF)  # drop $FILE_NAME: an unnamed record
        state = self.run_ntfs(mft=synthetic_mft({70: bytes(record)}))
        self.assertEqual(state["status"], "completed", state)
        rows = self.rows(state["analysis_id"], limit=100)["rows"]
        unnamed = next(row["details"] for row in rows if row["details"].get("entry_number") == 70)
        self.assertIsNone(unnamed["name"])
        self.assertFalse(unnamed["in_use"])
        self.assertEqual(analysis_kinds.analysis_row_title("ntfs-meta", {"details": unnamed}, 0), "MFT 엔트리 #70 (이름 없음) (삭제됨)")

if __name__ == "__main__":
    unittest.main()
