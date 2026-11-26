"""Synthetic LSB x86 login accounting fixtures; offsets are independent of the reader."""

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.linux import LinuxSystemArtifactsProvider
from rapidtriage.artifacts.linux_login import SUMMARY


def utmp(kind=7, usec=123456, address=bytes([192, 0, 2, 7]) + bytes(12)):
    data = bytearray(384)
    struct.pack_into("<h", data, 0, kind)
    struct.pack_into("<i", data, 4, 321)
    data[8:13] = b"pts/2"
    data[40:42] = b"ts"
    data[44:50] = "시험".encode()
    data[76:87] = b"example.org"
    struct.pack_into("<hh", data, 332, 15, 2)
    struct.pack_into("<iii", data, 336, 99, 1_700_000_000, usec)
    data[348:364] = address
    return bytes(data)


def lastlog():
    return struct.pack("<i32s256s", 1_700_000_000, b"tty1", b"example.org")


class LinuxLoginAccountingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.logs = self.root / "var/log"
        self.logs.mkdir(parents=True)

    def rows(self):
        return [r for r in LinuxSystemArtifactsProvider().collect(self.root) if r.details.get("log_kind")]

    def test_provider_decodes_all_logs_and_keeps_evidence_offsets(self):
        run = self.root / "run"
        run.mkdir()
        (self.root / "var/run").symlink_to("../run", target_is_directory=True)
        (run / "utmp").write_bytes(utmp())
        (self.logs / "wtmp").write_bytes(utmp(2) + utmp(500) + utmp(8) + b"tail")
        (self.logs / "btmp").write_bytes(utmp(6))
        (self.root / "etc").mkdir()
        (self.root / "etc/passwd").write_text("연습:x:1001:10::/:/bin/sh\n", encoding="utf-8")
        with (self.logs / "lastlog").open("wb") as output:
            output.seek(1001 * 292)
            output.write(lastlog())
            output.seek(1003 * 292)
            output.write(lastlog())
        rows = self.rows()
        self.assertEqual([r.artifact_type for r in rows if r.artifact_type != SUMMARY],
                         ["linux-utmp", "linux-wtmp", "linux-wtmp", "linux-btmp", "linux-lastlog", "linux-lastlog"])
        self.assertEqual(sum(r.artifact_type == SUMMARY for r in rows), 4)
        records = [r.details for r in rows if r.artifact_type == "linux-wtmp"]
        self.assertEqual([r["source_offset"] for r in records], [0, 768])
        self.assertEqual([r["type_name"] for r in records], ["BOOT_TIME", "DEAD_PROCESS"])
        record = records[1]
        self.assertEqual((record["user"], record["tty"], record["host"]), ("시험", "pts/2", "example.org"))
        self.assertEqual((record["pid"], record["type"], record["session"]), (321, 8, 99))
        self.assertEqual((record["id"], record["address"]), ("ts", "192.0.2.7"))
        self.assertEqual((record["exit_termination"], record["exit_status"]), (15, 2))
        self.assertEqual((record["timestamp_sec"], record["timestamp_usec"]), (1_700_000_000, 123456))
        self.assertEqual(record["timestamp"], "2023-11-14T22:13:20.123456+00:00")
        self.assertEqual(record["length"], 384)
        self.assertEqual(record["record_sha256"], hashlib.sha256(utmp(8)).hexdigest())
        summary = next(r.details for r in rows if r.artifact_type == SUMMARY and r.details["log_kind"] == "wtmp")
        self.assertEqual((summary["damaged_records"], summary["truncated_records"], summary["trailing_bytes"]), (1, 1, 4))
        records = [r.details for r in rows if r.artifact_type == "linux-lastlog"]
        self.assertEqual([(r["uid"], r["user"]) for r in records], [(1001, "연습"), (1003, "")])
        self.assertEqual(records[0]["source_offset"], 1001 * 292)
        self.assertEqual(records[0]["length"], 292)
        self.assertIsNone(records[0]["timestamp_usec"])
        self.assertEqual(records[0]["timestamp"], "2023-11-14T22:13:20+00:00")

    def test_unknown_layout_and_short_files_are_visible(self):
        (self.logs / "wtmp").write_bytes(utmp() + bytes(16))  # incompatible 400-byte stride
        (self.logs / "lastlog").write_bytes(struct.pack("<q32s256s", 1_700_000_000, b"tty2", b""))
        (self.logs / "btmp").write_bytes(b"truncated")
        rows = self.rows()
        self.assertTrue(all(r.artifact_type == SUMMARY for r in rows))
        stats = {r.details["log_kind"]: r.details for r in rows}
        self.assertEqual(stats["wtmp"]["candidate_record_size"], 400)
        self.assertEqual(stats["lastlog"]["candidate_record_size"], 296)
        self.assertEqual(stats["btmp"]["truncated_records"], 1)
        self.assertTrue(all(s["layout"] == "unknown-layout" for s in stats.values()))

    def test_common_multiple_uses_record_alignment(self):
        (self.logs / "wtmp").write_bytes(utmp() * 25)
        (self.logs / "lastlog").write_bytes(lastlog() * 74)
        rows = self.rows()
        self.assertEqual(sum(r.artifact_type == "linux-wtmp" for r in rows), 25)
        self.assertEqual(sum(r.artifact_type == "linux-lastlog" for r in rows), 74)
        (self.logs / "wtmp").write_bytes((utmp() + bytes(16)) * 24)
        rows = self.rows()
        self.assertFalse(any(r.artifact_type == "linux-wtmp" for r in rows))

    def test_unaligned_foreign_record_and_supported_damaged_prefix(self):
        # The 64-bit time puts this tty four bytes past the supported offset.
        (self.logs / "lastlog").write_bytes(struct.pack("<q32s256s", 1_700_000_000, b"tty2", b"") + b"x")
        (self.logs / "wtmp").write_bytes(utmp(500) + utmp() + utmp() + b"x")
        rows = self.rows()
        self.assertFalse(any(r.artifact_type == "linux-lastlog" for r in rows))
        summary = rows[-1].details
        self.assertEqual((summary["layout"], summary["candidate_record_size"]), ("unknown-layout", 296))
        self.assertEqual((summary["truncated_records"], summary["trailing_bytes"]), (1, 1))
        self.assertEqual([r.details["source_offset"] for r in rows if r.artifact_type == "linux-wtmp"], [384, 768])

    def test_damaged_final_slot_before_short_tail(self):
        (self.logs / "wtmp").write_bytes(utmp() + utmp(500) + b"tail")
        record, summary = self.rows()
        self.assertEqual(record.details["source_offset"], 0)
        self.assertEqual(summary.details["damaged_records"], 1)
        self.assertEqual(summary.details["truncated_records"], 1)
        self.assertEqual(summary.details["trailing_bytes"], 4)

    def test_sparse_lastlog_at_common_multiple_and_partial_last_record(self):
        path = self.logs / "lastlog"
        with path.open("wb") as handle:
            handle.seek(73_999 * 292)
            handle.write(lastlog())
        rows = self.rows()
        self.assertEqual([r.details["uid"] for r in rows if r.artifact_type == "linux-lastlog"],
                         [73_999])
        # Also divisible by 296, but the tty bytes rule out a 64-bit ll_time.
        path.write_bytes(lastlog() + b"tail")
        rows = self.rows()
        self.assertEqual(rows[0].details["uid"], 0)
        self.assertEqual(rows[1].details["trailing_bytes"], 4)

    def test_record_and_row_caps_are_independent(self):
        (self.logs / "wtmp.1").write_bytes(utmp(usec=-1) + utmp() * 3)
        with patch("rapidtriage.artifacts.linux_login.MAX_LOGIN_ROWS", 1):
            rows = self.rows()
        self.assertEqual(rows[-1].details["rows_emitted"], 1)
        self.assertEqual(rows[-1].details["damaged_records"], 1)
        self.assertTrue(rows[-1].details["capped"])
        with patch("rapidtriage.artifacts.linux_login.MAX_RECORDS_READ", 3):
            rows = self.rows()
        self.assertEqual(rows[-1].details["rows_emitted"], 2)
        self.assertEqual(rows[-1].details["records_examined"], 3)
        self.assertTrue(rows[-1].details["capped"])

    def test_run_only_and_outside_root_link(self):
        other = self.root / "other"
        evidence = self.root / "subset"
        other.mkdir()
        (other / "wtmp").write_bytes(utmp())
        (evidence / "run").mkdir(parents=True)
        (evidence / "run/utmp").write_bytes(utmp())
        self.assertEqual([r.artifact_type for r in LinuxSystemArtifactsProvider().collect(evidence)],
                         ["linux-utmp", SUMMARY])
        (evidence / "var/log").mkdir(parents=True)
        (evidence / "var/log/wtmp").symlink_to(other / "wtmp")
        self.assertEqual([r.artifact_type for r in LinuxSystemArtifactsProvider().collect(evidence)],
                         ["linux-utmp", SUMMARY])

    def test_ipv6_and_empty_addresses(self):
        ipv6 = bytes.fromhex("20010db8000000000000000000000001")
        (self.logs / "wtmp").write_bytes(utmp(address=ipv6) + utmp(address=bytes(16)))
        records = [r.details for r in self.rows() if r.artifact_type == "linux-wtmp"]
        self.assertEqual([r["address"] for r in records], ["2001:db8::1", ""])

    def test_rotations_are_read_and_compressed_ones_disclosed(self):
        for name in ("wtmp", "wtmp.1", "wtmp-20261101", "btmp-20261101"):
            (self.logs / name).write_bytes(utmp())
        (self.logs / "wtmp.2.gz").write_bytes(b"\x1f\x8b compressed")
        (self.logs / "wtmpx").write_bytes(utmp())  # not a login accounting name
        rows = self.rows()
        read = [Path(r.details["source_path"]).name for r in rows if r.artifact_type in {"linux-wtmp", "linux-btmp"}]
        self.assertEqual(read, ["wtmp", "wtmp.1", "wtmp-20261101", "btmp-20261101"])
        compressed, = (r.details for r in rows if r.details["source_path"].endswith(".gz"))
        self.assertEqual((compressed["coverage_status"], compressed["layout"], compressed["log_kind"]),
                         ("unsupported-compression", "compressed", "wtmp"))
        with patch("rapidtriage.artifacts.linux_login.MAX_ROTATED_FILES", 1):
            statuses = {Path(r.details["source_path"]).name: r.details["coverage_status"]
                        for r in self.rows() if r.artifact_type == SUMMARY}
        self.assertEqual(statuses["wtmp-20261101"], "skipped-file-cap")
        self.assertEqual(statuses["wtmp.2.gz"], "skipped-file-cap")
        self.assertEqual(statuses["wtmp.1"], "parsed")
