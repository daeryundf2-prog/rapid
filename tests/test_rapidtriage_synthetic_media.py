from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import get_artifact_collector
from rapidtriage.artifacts.synthetic_media import (
    SYNTHETIC_MEDIA_SCORE_SEMANTICS,
    SyntheticMediaProvider,
)
from rapidtriage.core.artifacts import run_artifact_collection


def make_stub_deepfake_lens() -> types.ModuleType:
    module = types.ModuleType("deepfake_lens")

    class StubResult:
        def to_json(self) -> dict[str, object]:
            return {
                "score": 72,
                "band": "high",
                "band_label": "높음",
                "verdict": "stub verdict",
                "signals": [{"title": "stub-signal", "detail": "stub detail", "weight": 40}],
                "limitations": ["stub limitation"],
                "source_guess": {"label": "stub-source", "confidence": "medium", "reasons": ["stub"]},
                "next_checks": ["stub next check"],
                "model_analysis": {"available": True, "name": "stub-model"},
            }

    class StubItem:
        def __init__(self, path: Path) -> None:
            self._path = Path(path)

        def to_json(self) -> dict[str, object]:
            return {
                "path": str(self._path),
                "name": self._path.name,
                "kind": "image",
                "status": "analyzed",
                "size_bytes": self._path.stat().st_size,
                "result": StubResult().to_json(),
                "error": None,
            }

    def analyze_file(path, **_kwargs):
        return StubItem(Path(path))

    module.analyze_file = analyze_file  # type: ignore[attr-defined]
    return module


class SyntheticMediaProviderTests(unittest.TestCase):
    def test_collector_kind_is_registered(self) -> None:
        collector = get_artifact_collector("synthetic-media")

        self.assertIsInstance(collector, SyntheticMediaProvider)
        self.assertEqual(collector.collector_kind, "synthetic-media")

    def test_provider_reports_unavailable_when_module_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with patch.dict(sys.modules, {"deepfake_lens": None}):
                provider = SyntheticMediaProvider()
                self.assertFalse(provider.supported())
                records = list(provider.collect(root))

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertFalse(record.supported)
            self.assertEqual(record.artifact_type, "synthetic-media-scan-status")
            self.assertEqual(record.details["coverage_status"], "provider-unavailable")
            self.assertEqual(record.details["scan_status"], "skipped-optional-dependency")

    def test_run_artifact_collection_survives_missing_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with patch.dict(sys.modules, {"deepfake_lens": None}):
                payload = run_artifact_collection(root, kind="synthetic-media")

            self.assertEqual(payload["summary"]["collection_status"], "completed")
            self.assertFalse(payload["provider"]["supported"])
            self.assertEqual(payload["summary"]["artifact_count"], 1)

    def test_collect_emits_score_band_and_prioritization_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "suspect.png").write_bytes(b"\x89PNG\r\n\x1a\nstub")
            (root / "notes.txt").write_text("stub text", encoding="utf-8")
            (root / "movie.mp4").write_bytes(b"not scanned")
            with patch.dict(sys.modules, {"deepfake_lens": make_stub_deepfake_lens()}):
                provider = SyntheticMediaProvider()
                self.assertTrue(provider.supported())
                records = list(provider.collect(root))

            scan_records = [r for r in records if r.artifact_type.startswith("synthetic-media-") and r.details.get("scan_status") != "completed"]
            summary_records = [r for r in records if r.artifact_type == "synthetic-media-scan-summary"]
            self.assertEqual(len(scan_records), 2)
            self.assertEqual(len(summary_records), 1)
            for record in scan_records:
                self.assertTrue(record.supported)
                self.assertEqual(record.details["score"], 72)
                self.assertEqual(record.details["band"], "high")
                self.assertEqual(record.details["limitations"], ["stub limitation"])
                self.assertEqual(record.details["score_semantics"], SYNTHETIC_MEDIA_SCORE_SEMANTICS)
                self.assertTrue(record.details["validation_required"])
                self.assertTrue(record.details["model_analysis_available"])
            self.assertEqual(summary_records[0].details["scan_file_count"], 2)

    def test_collect_caps_scanned_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for index in range(5):
                (root / f"img{index}.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with patch.dict(sys.modules, {"deepfake_lens": make_stub_deepfake_lens()}), patch(
                "rapidtriage.artifacts.synthetic_media.SYNTHETIC_MEDIA_MAX_FILES", 3
            ):
                records = list(SyntheticMediaProvider().collect(root))

            summary = next(r for r in records if r.artifact_type == "synthetic-media-scan-summary")
            self.assertEqual(summary.details["scan_file_count"], 3)
            self.assertTrue(summary.details["scan_capped"])

    def test_collect_survives_per_file_analyze_errors(self) -> None:
        module = types.ModuleType("deepfake_lens")

        def analyze_file(_path, **_kwargs):
            raise RuntimeError("stub boom")

        module.analyze_file = analyze_file  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "bad.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with patch.dict(sys.modules, {"deepfake_lens": module}):
                records = list(SyntheticMediaProvider().collect(root))

            error_records = [r for r in records if r.artifact_type == "synthetic-media-scan-error"]
            self.assertEqual(len(error_records), 1)
            self.assertIn("stub boom", error_records[0].details["scan_error"])


if __name__ == "__main__":
    unittest.main()
