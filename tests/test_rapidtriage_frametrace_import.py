from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.frametrace_import import (
    FrametraceImportError,
    import_frametrace_package,
    verify_frametrace_package,
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_package(root: Path, *, videos: list[dict[str, object]] | None = None) -> Path:
    package = root / "package_1700000000"
    files: dict[str, bytes] = {
        "case.json": b'{"case_id":"FT-1"}',
        "db/case.db": b"sqlite placeholder",
        "db/video_index.json": json.dumps(
            {"schema_version": 3, "case_id": "FT-1", "videos": videos or []}
        ).encode("utf-8"),
        "db/videos.jsonl": "".join(json.dumps(v) + "\n" for v in (videos or [])).encode("utf-8"),
        "db/video_paths.tsv": b"id\tsource_path\n",
        "reports/case-report.html": b"<html></html>",
    }
    for rel, data in files.items():
        target = package / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    checksum_lines = "".join(f"{sha256_bytes(data)}  {rel}\n" for rel, data in sorted(files.items()))
    (package / "manifest.sha256").write_text(checksum_lines, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "package_type": "frametrace-case-package",
        "created_unix": 1700000000,
        "file_count": len(files),
        "files": [
            {"relative_path": rel, "size_bytes": len(data), "sha256": sha256_bytes(data)}
            for rel, data in sorted(files.items())
        ],
        "missing_optional_files": [],
        "pdf_ready_note": "stub",
    }
    (package / "package-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (package / "README.txt").write_text("FrameTrace case package\n", encoding="utf-8")
    return package


def two_videos() -> list[dict[str, object]]:
    return [
        {
            "id": "vid_000001",
            "source_path": "C:/evidence/cam1.mp4",
            "file_url": "file:///C:/evidence/cam1.mp4",
            "relative_path": "cam1.mp4",
            "size_bytes": 1024,
            "sha256": "a" * 64,
            "source_profile": {"vendor": "stub", "parser": "mp4"},
            "ffprobe_ok": True,
        },
        {
            "id": "vid_000002",
            "source_path": "C:/evidence/cam2.mp4",
            "relative_path": "cam2.mp4",
            "size_bytes": 2048,
            "ffprobe_ok": False,
        },
    ]


class FrametraceImportTests(unittest.TestCase):
    def test_verify_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            package = build_package(Path(tmp_dir), videos=two_videos())
            verification = verify_frametrace_package(package)

            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["summary"]["verified_count"], 6)
            self.assertTrue(verification["package_type_ok"])

    def test_import_happy_path_loads_videos(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            package = build_package(root, videos=two_videos())
            db_path = root / "case.db"
            result = import_frametrace_package(package, case_id="FT-1", db_path=db_path)

            self.assertEqual(result["status"], "imported")
            self.assertEqual(result["video_count"], 2)
            self.assertEqual(result["import"]["summary"]["evidence_source_count"], 1)
            self.assertEqual(result["import"]["summary"]["file_record_count"], 2)
            self.assertEqual(result["import"]["summary"]["artifact_count"], 2)

            database = open_case_database(db_path)
            summary = database.case_storage_summary("FT-1")
            self.assertEqual(summary["summary"]["file_record_count"], 2)
            self.assertEqual(summary["summary"]["evidence_source_count"], 1)

    def test_hash_mismatch_recorded_not_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            package = build_package(root, videos=two_videos())
            (package / "db" / "videos.jsonl").write_bytes(b"tampered after packaging\n")

            verification = verify_frametrace_package(package)
            self.assertEqual(verification["status"], "mismatch")
            self.assertEqual(verification["summary"]["mismatch_count"], 1)

            result = import_frametrace_package(package, case_id="FT-2", db_path=root / "case.db")
            self.assertEqual(result["status"], "imported-with-integrity-findings")

            database = open_case_database(root / "case.db")
            with database.connect() as connection:
                integrity_rows = connection.execute(
                    "SELECT artifact_type, data_json FROM artifact WHERE artifact_type = ?",
                    ("frametrace-package-integrity",),
                ).fetchall()
                audit_rows = connection.execute(
                    "SELECT action, result, error FROM audit_event WHERE action = ?",
                    ("frametrace.package-imported",),
                ).fetchall()

            self.assertEqual(len(integrity_rows), 1)
            data = json.loads(integrity_rows[0]["data_json"])
            self.assertEqual(data["details"]["integrity_status"], "mismatch")
            self.assertEqual(data["details"]["relative_path"], "db/videos.jsonl")
            self.assertEqual(len(audit_rows), 1)
            self.assertEqual(audit_rows[0]["result"], "partial")

    def test_missing_checksum_manifest_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            package = build_package(Path(tmp_dir), videos=two_videos())
            (package / "manifest.sha256").unlink()

            with self.assertRaises(FrametraceImportError):
                verify_frametrace_package(package)

    def test_unsafe_manifest_path_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            package = build_package(Path(tmp_dir), videos=two_videos())
            with (package / "manifest.sha256").open("a", encoding="utf-8") as handle:
                handle.write(f"{'b' * 64}  ../outside.bin\n")

            verification = verify_frametrace_package(package)
            unsafe = [e for e in verification["entries"] if e["status"] == "unsafe-path"]
            self.assertEqual(len(unsafe), 1)
            self.assertEqual(verification["status"], "mismatch")


if __name__ == "__main__":
    unittest.main()
