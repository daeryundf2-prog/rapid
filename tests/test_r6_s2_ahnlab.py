"""R6 S2 lane A: AhnLab V3 inventory-first rows (plan r6-followups-2026-10-19 §2.3 갈래 A, Q-S2-1, Q-S2-12).

Every input is synthetic and built here. The quarantine folder holds bytes that would turn into a
row (a SQLite header, a candidate-looking name, a planted secret) if anything opened them; the
collector runs with ``open`` guarded so that opening any quarantine file fails the test.
"""

from __future__ import annotations

import builtins
import json
import os
import sqlite3
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows import av_ahnlab
from rapidtriage.artifacts.windows.av_ahnlab import (
    collect_ahnlab_v3,
    product_of,
    sniff_format,
)
from rapidtriage.artifacts.windows.system_extras import collect_system_extras
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.timeline import iter_artifact_detail_events
from rapidtriage.core.triage_rules import load_catalog

ROOT = Path(__file__).resolve().parents[1]
SECRET_QUARANTINE = b"R6S2-AHNLAB-QUARANTINE-SECRET-7f3a"
SECRET_LICENSE = b"R6S2-AHNLAB-LICENSE-SECRET-91bc"
PROVIDER = "windows-system"

TEXT_LOG = "\r\n".join(
    [
        "2026.10.18 오후 3:05:11 [실시간 검사] 악성코드 탐지 - 진단명: Trojan/Win32.Agent.C1234, 경로: C:\\Users\\alice\\Downloads\\invoice.exe, 처리: 치료",
        "2026-10-17 14:05:11 Detected - Threat Name: EICAR-Test-File, Path: C:\\Temp\\eicar.com, Action: Quarantined",
        "2026-10-17 14:06:00 정밀 검사 완료 - 탐지되지 않음",
        "2026-10-17 14:07:00 엔진 업데이트 완료",
        "garbage 탐지 line without a time prefix",
    ]
)


def _sqlite_log(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE DetectHistory (id INTEGER PRIMARY KEY, detect_time INTEGER, threat_name TEXT, file_path TEXT, action TEXT, extra BLOB)")
        connection.execute("CREATE TABLE Settings (k TEXT, v TEXT)")
        connection.executemany(
            "INSERT INTO DetectHistory (detect_time, threat_name, file_path, action, extra) VALUES (?, ?, ?, ?, ?)",
            [
                (1_760_771_111, "Malware/Win.Generic.R1", "C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe", "Deleted", b"\x00\x01"),
                (1_760_771_222_000, "PUP/Win.Toolbar", "C:\\Users\\alice\\Desktop\\tool.exe", "격리", None),
            ],
        )
        connection.execute("INSERT INTO Settings VALUES ('k', 'v')")
        connection.commit()
    finally:
        connection.close()


def build_tree(root: Path) -> Path:
    product = root / "Program Files" / "AhnLab" / "V3Lite40"
    (product / "Log").mkdir(parents=True)
    (product / "version.ini").write_text("[Info]\r\nVersion=4.0.10.1\r\n", encoding="utf-8")
    (product / "V3Lite.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (product / "license.dat").write_bytes(SECRET_LICENSE)  # not a log candidate name
    (product / "Log" / "V3Detect.log").write_bytes(TEXT_LOG.encode("utf-8"))
    _sqlite_log(product / "Log" / "ScanHistory.db")
    (product / "Log" / "EventLog.dat").write_bytes(b"\x00\x00\x00\x00" + b"\xef\xcd\xab\x89" + b"\x00" * 120)
    (product / "Log" / "broken_history.db").write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)
    quarantine = product / "Quarantine"
    (quarantine / "sub").mkdir(parents=True)
    (quarantine / "a1b2.vir").write_bytes(b"SQLite format 3\x00" + SECRET_QUARANTINE)
    (quarantine / "detect_log.txt").write_bytes(b"2026-10-18 09:00:00 Detected " + SECRET_QUARANTINE)
    (quarantine / "sub" / "c3d4.vir").write_bytes(SECRET_QUARANTINE * 3)
    # An AhnLab folder outside the install parents is not a product folder.
    stray = root / "Users" / "alice" / "Downloads" / "AhnLab" / "V3Lite"
    stray.mkdir(parents=True)
    (stray / "detect.log").write_text("2026-10-18 09:00:00 탐지 Trojan C:\\x.exe", encoding="utf-8")
    return root


class _QuarantineGuard:
    """Fail on any ``open`` of a path under a quarantine folder (builtins, io, os)."""

    def __init__(self, quarantine: Path) -> None:
        self.marker = str(quarantine.resolve()).casefold()
        self.opened: list[str] = []

    def _check(self, target: object) -> None:
        if isinstance(target, (str, bytes, os.PathLike)):
            text = os.fsdecode(target)
            try:
                text = str(Path(text).resolve())
            except OSError:
                pass
            if text.casefold().startswith(self.marker):
                self.opened.append(text)
                raise AssertionError(f"quarantine file opened: {text}")

    def patches(self) -> list[mock._patch]:  # type: ignore[name-defined]
        real_open = builtins.open
        real_os_open = os.open

        def guarded_open(file: object, *args: object, **kwargs: object) -> object:
            self._check(file)
            return real_open(file, *args, **kwargs)  # type: ignore[call-overload]

        def guarded_os_open(path: object, *args: object, **kwargs: object) -> int:
            self._check(path)
            return real_os_open(path, *args, **kwargs)  # type: ignore[arg-type]

        return [
            mock.patch("builtins.open", guarded_open),
            mock.patch("io.open", guarded_open),
            mock.patch("os.open", guarded_os_open),
        ]


def rows_of(records: list, artifact_type: str, **match: object) -> list[dict]:
    return [r.details for r in records if r.artifact_type == artifact_type and all(r.details.get(k) == v for k, v in match.items())]


class AhnLabInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = build_tree(Path(cls.temp.name) / "case")
        cls.quarantine = cls.root / "Program Files" / "AhnLab" / "V3Lite40" / "Quarantine"
        cls.guard = _QuarantineGuard(cls.quarantine)
        patches = cls.guard.patches()
        for patch in patches:
            patch.start()
        try:
            cls.records = list(collect_ahnlab_v3(cls.root, PROVIDER))
        finally:
            for patch in reversed(patches):
                patch.stop()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_guard_is_effective(self) -> None:
        with self.assertRaises(AssertionError):
            patches = self.guard.patches()
            for patch in patches:
                patch.start()
            try:
                with (self.quarantine / "a1b2.vir").open("rb"):
                    pass
            finally:
                for patch in reversed(patches):
                    patch.stop()
        self.guard.opened.clear()

    def test_one_product_folder_row(self) -> None:
        products = rows_of(self.records, "av-product-presence", presence_kind="product-folder")
        self.assertEqual(len(products), 1)
        row = products[0]
        self.assertEqual((row["av_product"], row["av_product_label"]), ("ahnlab-v3", "AhnLab V3 Lite"))
        self.assertEqual((row["product_version"], row["product_version_source"]), ("4.0.10.1", "version.ini"))
        self.assertEqual(row["install_scope"], "program-files")
        self.assertEqual(row["log_candidate_count"], 4)
        self.assertEqual((row["quarantine_folder_count"], row["quarantine_file_count"]), (1, 3))
        self.assertFalse(row["walk_truncated"])
        # The stray Downloads\AhnLab folder yields nothing.
        self.assertFalse(any("Downloads" in str(r.details.get("source_path")) for r in self.records))

    def test_log_candidates_and_formats(self) -> None:
        candidates = {row["file_name"]: row for row in rows_of(self.records, "av-product-presence", presence_kind="log-candidate")}
        self.assertEqual(set(candidates), {"V3Detect.log", "ScanHistory.db", "EventLog.dat", "broken_history.db"})
        self.assertEqual(candidates["V3Detect.log"]["sniffed_format"], "text")
        self.assertEqual((candidates["V3Detect.log"]["parse_outcome"], candidates["V3Detect.log"]["detection_row_count"]), ("detection-rows", 2))
        self.assertEqual((candidates["ScanHistory.db"]["sniffed_format"], candidates["ScanHistory.db"]["detection_row_count"]), ("sqlite", 2))
        self.assertEqual((candidates["EventLog.dat"]["sniffed_format"], candidates["EventLog.dat"]["parse_outcome"]), ("ese", "inventory-only"))
        self.assertEqual(candidates["broken_history.db"]["parse_outcome"], "error")
        self.assertEqual(candidates["V3Detect.log"]["relative_path"], str(Path("Log") / "V3Detect.log"))
        self.assertTrue(candidates["V3Detect.log"]["source_file_mtime"])

    def test_quarantine_counted_never_opened(self) -> None:
        self.assertEqual(self.guard.opened, [])
        rows = rows_of(self.records, "av-product-presence", presence_kind="quarantine-folder")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["file_count"], rows[0]["contents_opened"], rows[0]["count_truncated"]), (3, False, False))
        self.assertEqual(rows[0]["total_size"], sum(p.stat().st_size for p in self.quarantine.rglob("*") if p.is_file()))
        marker = str(self.quarantine.resolve()).casefold()
        inside = [r for r in self.records if str(r.details.get("source_path", "")).casefold().startswith(marker + os.sep)]
        self.assertEqual(inside, [])

    def test_text_detection_lines(self) -> None:
        rows = rows_of(self.records, "av-detection-log", field_extraction="heuristic-lines")
        self.assertEqual(len(rows), 2)
        korean = next(row for row in rows if row["detected_at"] == "2026-10-18T15:05:11")
        self.assertEqual(korean["threat_name"], "Trojan/Win32.Agent.C1234")
        self.assertEqual(korean["object_path"], "C:\\Users\\alice\\Downloads\\invoice.exe")
        self.assertEqual((korean["action"], korean["action_label"]), ("cleaned", "치료"))
        english = next(row for row in rows if row["detected_at"] == "2026-10-17T14:05:11")
        self.assertEqual((english["threat_name"], english["object_path"], english["action"]), ("EICAR-Test-File", "C:\\Temp\\eicar.com", "quarantined"))
        self.assertEqual(english["source_offset"], 2)

    def test_sqlite_detection_rows(self) -> None:
        rows = sorted(rows_of(self.records, "av-detection-log", field_extraction="heuristic-sqlite"), key=lambda row: row["source_rowid"])
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["source_table"] for row in rows}, {"DetectHistory"})
        self.assertEqual(rows[0]["detected_at"], "2025-10-18T07:05:11")
        self.assertEqual(rows[0]["timestamp_timezone"], "UTC")
        self.assertEqual(rows[1]["detected_at"], "2025-10-18T07:07:02")  # milliseconds
        self.assertEqual((rows[0]["threat_name"], rows[0]["action"]), ("Malware/Win.Generic.R1", "deleted"))
        self.assertEqual((rows[1]["object_path"], rows[1]["action"]), ("C:\\Users\\alice\\Desktop\\tool.exe", "quarantined"))
        self.assertEqual(rows[0]["schema_confidence"], "heuristic-sqlite")
        self.assertIn("(이진 2바이트)", rows[0]["message"])

    def test_corrupt_database_isolated(self) -> None:
        errors = rows_of(self.records, "av-detection-log", parse_status="error")
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["log_name"], "broken_history.db")
        self.assertTrue(errors[0]["parse_error"])

    def test_every_row_unconfirmed_with_provenance(self) -> None:
        self.assertGreater(len(self.records), 0)
        for record in self.records:
            details = record.details
            self.assertEqual(details["verification"], "unconfirmed", record.artifact_type)
            self.assertEqual(details["parser_version"], "av-ahnlab-v1")
            self.assertTrue(details["recovery_method"])
            self.assertTrue(details["source_path"])
            self.assertEqual(details["av_vendor"], "ahnlab")
        detections = [r for r in self.records if r.artifact_type == "av-detection-log"]
        self.assertTrue(all(r.details["av_product"] == "ahnlab-v3" for r in detections))
        counts = Counter(r.artifact_type for r in self.records)
        self.assertEqual(counts, Counter({"av-product-presence": 6, "av-detection-log": 5}))

    def test_planted_secrets_never_in_rows(self) -> None:
        text = json.dumps([record.details for record in self.records], ensure_ascii=False, default=str)
        for secret in (SECRET_QUARANTINE, SECRET_LICENSE):
            self.assertNotIn(secret.decode(), text)

    def test_timeline_only_for_detection_rows(self) -> None:
        for record in self.records:
            events = list(iter_artifact_detail_events(record.artifact_type, record.details))
            if record.artifact_type == "av-product-presence":
                self.assertEqual(events, [])
            elif record.details.get("detected_at"):
                self.assertTrue(events)


class AhnLabBoundsTests(unittest.TestCase):
    def test_quarantine_and_walk_caps(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            product = Path(temp) / "ProgramData" / "AhnLab" / "V3IS90"
            (product / "Vault").mkdir(parents=True)
            for index in range(5):
                (product / "Vault" / f"{index}.bin").write_bytes(b"x")
                (product / f"file{index}.bin").write_bytes(b"y")
            with mock.patch.object(av_ahnlab, "MAX_QUARANTINE_FILES", 3), mock.patch.object(av_ahnlab, "MAX_WALK_ENTRIES", 2):
                records = list(collect_ahnlab_v3(Path(temp), PROVIDER))
        product_row = rows_of(records, "av-product-presence", presence_kind="product-folder")[0]
        self.assertEqual(product_row["av_product_label"], "AhnLab V3 Internet Security")
        self.assertEqual(product_row["install_scope"], "programdata")
        self.assertTrue(product_row["walk_truncated"])
        vault = rows_of(records, "av-product-presence", presence_kind="quarantine-folder")
        if vault:  # the walk cap may stop before the Vault folder; when reached it is capped
            self.assertTrue(vault[0]["count_truncated"])
            self.assertEqual(vault[0]["file_count"], 3)

    def test_quarantine_cap_alone(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            product = Path(temp) / "Program Files (x86)" / "AhnLab" / "V3Lite"
            (product / "Quarantine").mkdir(parents=True)
            for index in range(5):
                (product / "Quarantine" / f"{index}.bin").write_bytes(b"x")
            with mock.patch.object(av_ahnlab, "MAX_QUARANTINE_FILES", 3):
                records = list(collect_ahnlab_v3(Path(temp), PROVIDER))
        vault = rows_of(records, "av-product-presence", presence_kind="quarantine-folder")[0]
        self.assertEqual((vault["file_count"], vault["count_truncated"]), (3, True))

    def test_user_local_appdata_and_text_line_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            product = Path(temp) / "Users" / "bob" / "AppData" / "Local" / "AhnLab" / "V3Lite"
            product.mkdir(parents=True)
            lines = "\n".join(f"2026-10-18 09:00:{index:02d} 탐지 Threat: T{index}" for index in range(10))
            (product / "detect_history.txt").write_text(lines, encoding="utf-16")
            with mock.patch.object(av_ahnlab, "MAX_ROWS_PER_TYPE", 4):
                records = list(collect_ahnlab_v3(Path(temp), PROVIDER))
        detections = rows_of(records, "av-detection-log")
        self.assertEqual(len(detections), 4)
        self.assertEqual(detections[0]["threat_name"], "T0")
        presence = rows_of(records, "av-product-presence", presence_kind="product-folder")[0]
        self.assertEqual((presence["install_scope"], presence["user"]), ("user-local-appdata", "bob"))

    def test_empty_tree_yields_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(list(collect_ahnlab_v3(Path(temp), PROVIDER)), [])

    def test_helpers(self) -> None:
        self.assertEqual(product_of("V3 Lite 4.0")[0], "ahnlab-v3")
        self.assertEqual(product_of("ASTx")[0], "ahnlab-safe-transaction")
        self.assertEqual(product_of("Policy Agent")[0], "ahnlab-other")
        self.assertEqual(sniff_format(b"SQLite format 3\x00rest"), "sqlite")
        self.assertEqual(sniff_format("탐지".encode("utf-16-le")), "text")
        self.assertEqual(sniff_format(b"\x01\x02\x03\x04\x05\x06\x07\x08" * 4), "unknown")


class AhnLabRegistrationTests(unittest.TestCase):
    def test_system_extras_runs_the_collector(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = build_tree(Path(temp) / "case")
            types = Counter(record.artifact_type for record in collect_system_extras(root, PROVIDER) if record.details.get("av_vendor") == "ahnlab")
        self.assertEqual(types, Counter({"av-product-presence": 6, "av-detection-log": 5}))

    def test_catalog_domain_and_tree_node(self) -> None:
        catalog = load_catalog()
        self.assertEqual(catalog.family_for("av-product-presence", "windows-system"), "av-product-presence")
        self.assertEqual(catalog.family_for("av-detection-log", "windows-system"), "av-detection-log")
        self.assertEqual(artifact_type_domain("windows-system", "av-product-presence"), "anti-forensics")
        domains = (ROOT / "frontend" / "src" / "features" / "tree" / "domains.ts").read_text(encoding="utf-8")
        self.assertIn('a("windows-system", ["av-product-presence"])', domains)
        fallback = json.loads((ROOT / "frontend" / "src" / "features" / "flags" / "families.fallback.json").read_text(encoding="utf-8"))
        self.assertIn("av-product-presence", {family["id"] for family in fallback["families"]})


if __name__ == "__main__":
    unittest.main()
