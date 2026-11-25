from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import clear_collect_cache, kakaotalk_memory
from rapidtriage.artifacts.kakaotalk_memory import KakaoTalkMemoryProvider
from rapidtriage.cli import build_parser
from tests.test_kakaotalk_residue_memory import synthetic_hiberfil

DUMP_MESSAGE = (
    b'{"attachment":"","authorId":11,"chatId":500,"deleted":false,'
    b'"logId":600,"message":"dump message","sendAt":1700000100,"type":1}'
)


def build_minidump(
    process_image: str, *, pid: int, payload: bytes, size: int = 80 * 1024
) -> bytes:
    module_rva = 32 + 2 * 12
    name_rva = module_rva + 4 + 108
    name = process_image.encode("utf-16le")
    misc_rva = name_rva + 4 + len(name)
    payload_rva = misc_rva + 24
    blob = bytearray(max(size, payload_rva + len(payload)))
    struct.pack_into("<4sIIIIIQ", blob, 0, b"MDMP", 0xA793, 2, 32, 0, 1700000200, 0)
    struct.pack_into("<III", blob, 32, 4, 4 + 108, module_rva)
    struct.pack_into("<III", blob, 44, 15, 24, misc_rva)
    struct.pack_into("<I", blob, module_rva, 1)
    struct.pack_into(
        "<QIIII", blob, module_rva + 4, 0x140000000, 0x1000, 0, 0, name_rva
    )
    struct.pack_into("<I", blob, name_rva, len(name))
    blob[name_rva + 4 : name_rva + 4 + len(name)] = name
    struct.pack_into("<IIIIII", blob, misc_rva, 24, 0x3, pid, 1700000000, 0, 0)
    blob[payload_rva : payload_rva + len(payload)] = payload
    return bytes(blob)


def build_evidence_tree(root: Path) -> None:
    desktop = root / "Users" / "kim" / "Desktop"
    downloads = root / "Users" / "kim" / "Downloads"
    deep = root / "cases" / "a" / "b" / "c" / "d" / "e"
    for folder in (desktop, downloads, deep):
        folder.mkdir(parents=True)
    (desktop / "memo.bin").write_bytes(
        build_minidump(
            r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe",
            pid=4242,
            payload=DUMP_MESSAGE,
        )
    )
    (downloads / "notepad.dmp").write_bytes(
        build_minidump(r"C:\Windows\System32\notepad.exe", pid=77, payload=DUMP_MESSAGE)
    )
    (deep / "crash.dmp").write_bytes(
        build_minidump("KakaoTalk.exe", pid=99, payload=b"nothing to see")
    )
    (downloads / "tiny.dmp").write_bytes(b"MDMP" + b"\0" * 100)
    (downloads / "unrelated.mem").write_bytes(b"\0" * (70 * 1024))
    (root / "hiberfil.sys").write_bytes(synthetic_hiberfil())


class KakaoTalkMemoryDiscoveryTests(unittest.TestCase):
    def test_finds_kakaotalk_dumps_anywhere_by_content_and_skips_other_processes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "kakao-case" / "evidence"
            build_evidence_tree(root)
            records = [
                record.to_dict() for record in KakaoTalkMemoryProvider().collect(root)
            ]

        dumps = {
            Path(row["path"]).name: row
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-dump"
        }
        skipped = {
            Path(row["path"]).name: row
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-dump-skipped"
        }
        self.assertEqual(sorted(dumps), ["crash.dmp", "memo.bin"])
        self.assertEqual(sorted(skipped), ["notepad.dmp", "unrelated.mem"])
        memo = dumps["memo.bin"]["details"]
        self.assertEqual(memo["process_name"], "KakaoTalk.exe")
        self.assertEqual(memo["pid"], 4242)
        self.assertIn("process-image:KakaoTalk.exe", memo["identification_reasons"])
        self.assertEqual(len(memo["source_hashes"]["sha256"]), 64)
        self.assertTrue(memo["dump_time"].startswith("2023-11-14"))
        self.assertEqual(memo["analysis_counts"]["chat_message_residues"], 1)
        self.assertEqual(
            skipped["notepad.dmp"]["details"]["skip_reason"], "other-process-dump"
        )
        self.assertEqual(
            skipped["notepad.dmp"]["details"]["process_name"], "notepad.exe"
        )

        messages = [
            row["details"]
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-message-residue"
        ]
        by_message = {item["message"]: item for item in messages}
        self.assertEqual(set(by_message), {"dump message", "residue message"})
        self.assertTrue(by_message["dump message"]["source_path"].endswith("memo.bin"))
        self.assertEqual(
            by_message["dump message"]["timestamp"], "2023-11-14T22:15:00+00:00"
        )
        self.assertEqual(by_message["residue message"]["source_kind"], "hiberfil")
        self.assertEqual(by_message["residue message"]["confidence"], "triage")
        summary = [
            row
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-analysis-summary"
        ]
        self.assertEqual(
            summary[0]["details"]["memory_carve"]["memory_source_count"], 2
        )

    def test_tree_without_dumps_yields_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            (Path(tmp_dir) / "notes.txt").write_text("no memory here", encoding="utf-8")
            self.assertEqual(list(KakaoTalkMemoryProvider().collect(Path(tmp_dir))), [])

    def test_dump_over_in_memory_cap_is_segmented_and_never_read_whole(self) -> None:
        whole_reads: list[str] = []
        real_read_bytes = Path.read_bytes

        def tracking_read_bytes(path: Path) -> bytes:
            whole_reads.append(path.name)
            return real_read_bytes(path)

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "kakao-case" / "evidence"
            build_evidence_tree(root)
            with (
                mock.patch.object(kakaotalk_memory, "MAX_IN_MEMORY_DUMP_BYTES", 64 * 1024),
                mock.patch.object(Path, "read_bytes", tracking_read_bytes),
            ):
                records = [record.to_dict() for record in KakaoTalkMemoryProvider().collect(root)]

        self.assertNotIn("memo.bin", whole_reads)
        self.assertNotIn("crash.dmp", whole_reads)
        memo = next(
            row["details"]
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-dump" and row["path"].endswith("memo.bin")
        )
        self.assertEqual(memo["analysis_mode"], "segmented")
        self.assertIn("postpatch-ikm", memo["not_applied"])
        self.assertEqual(memo["analysis_counts"]["chat_message_residues"], 1)
        message = next(
            row["details"]
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-message-residue"
            and row["details"]["message"] == "dump message"
        )
        self.assertEqual(message["source_kind"], "process-dump")
        self.assertEqual(message["evidence_class"], "process-memory")
        self.assertEqual(message["confidence"], "needs-validation")

    def test_confirmed_dumps_over_the_analysis_limit_are_reported_not_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "kakao-case" / "evidence"
            build_evidence_tree(root)
            with mock.patch.object(kakaotalk_memory, "MAX_ANALYSED_DUMPS", 1):
                records = [record.to_dict() for record in KakaoTalkMemoryProvider().collect(root)]

        analysed = [row for row in records if row["artifact_type"] == "kakaotalk-memory-dump"]
        limited = [
            row
            for row in records
            if row["artifact_type"] == "kakaotalk-memory-dump-skipped"
            and row["details"]["skip_reason"] == "analysis-limit"
        ]
        self.assertEqual([Path(row["path"]).name for row in analysed], ["crash.dmp"])
        self.assertEqual([Path(row["path"]).name for row in limited], ["memo.bin"])


class KakaoTalkMemoryRunTests(unittest.TestCase):
    def test_main_run_reports_memory_rows_in_artifacts_and_timeline(self) -> None:
        from rapidtriage.core.run import run_triage_mode

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            build_evidence_tree(root)
            clear_collect_cache()
            summary = run_triage_mode(
                root, mode="seizure", output_dir=Path(tmp_dir) / "out"
            )
            clear_collect_cache()
            counts = summary["summary"]["artifacts"]["kakaotalk-memory"]
            rows = Path(summary["outputs"]["artifacts_kakaotalk-memory"]).read_text(
                encoding="utf-8"
            )
            timeline = (Path(tmp_dir) / "out" / "rapidtriage-timeline.json").read_text(
                encoding="utf-8"
            )

        self.assertGreaterEqual(int(counts["artifact_count"]), 5)
        self.assertIn("kakaotalk-memory-message-residue", rows)
        self.assertIn("dump message", rows)
        self.assertIn("kakaotalk-memory-message-residue", timeline)
        self.assertIn("2023-11-14T22:15:00", timeline)

    def test_opt_out_flag_skips_the_task(self) -> None:
        from rapidtriage.core.run import run_triage_mode

        args = build_parser().parse_args(
            ["run", ".", "--mode", "seizure", "--no-kakaotalk-memory"]
        )
        self.assertFalse(args.kakaotalk_memory)
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            build_evidence_tree(root)
            clear_collect_cache()
            summary = run_triage_mode(
                root,
                mode="seizure",
                output_dir=Path(tmp_dir) / "out",
                skip_tasks=["kakaotalk-memory"],
            )
            clear_collect_cache()
        self.assertNotIn("kakaotalk-memory", summary["summary"]["artifacts"])


if __name__ == "__main__":
    unittest.main()
