from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.ocr_queue import build_ocr_queue, build_ocr_queue_trusted_diff, ocr_queue_core_accuracy_gates


class RapidTriageOcrQueueTests(unittest.TestCase):
    def test_parser_exposes_ocr_queue_command(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("ocr-queue", commands)
        self.assertIn("--retry-failures", commands["ocr-queue"].format_help())

    def test_build_ocr_queue_imports_sidecars_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "screen.png"
            image_path.write_bytes(b"\x89PNG\r\n\x1a\nfake")
            image_path.with_name("screen.ocr.txt").write_text("한글 OCR password", encoding="utf-8")
            image_path.with_name("screen.ocr.json").write_text(
                json.dumps({"language": "ko+en", "confidence": 0.91, "engine": "external"}),
                encoding="utf-8",
            )
            image_path.with_name("screen.translation.txt").write_text("Korean OCR password", encoding="utf-8")

            payload = build_ocr_queue(root)

            self.assertEqual(payload["command"], "ocr-queue")
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["sidecar_imported_count"], 1)
            self.assertIn("#58", payload["summary"]["commercial_gap_ids"])
            self.assertIn("#59", payload["ocr_queue_report_grade_assessment"]["commercial_gap_ids"])
            queue_gates = {gate["gap_id"]: gate for gate in payload["core_accuracy_gates"]}
            self.assertIn("queue item generation", queue_gates["#58"]["satisfied_checks"])
            self.assertIn("sidecar import and hashes", queue_gates["#58"]["satisfied_checks"])
            self.assertIn("Korean language hinting", queue_gates["#59"]["satisfied_checks"])
            self.assertIn("translation sidecar import", queue_gates["#59"]["satisfied_checks"])
            self.assertFalse(payload["ocr_queue_native_capabilities"]["native_ocr_engine_execution"])
            queue_uplift = payload["commercial_uplift_evidence"]
            self.assertEqual(queue_uplift["batch_id"], "commercial-uplift-056-060")
            self.assertEqual(queue_uplift["item_numbers"], [58, 59])
            self.assertIn("sidecar import and hashes", queue_uplift["passed_validation_check_ids_by_item"]["#58"])
            self.assertIn("Korean language hinting", queue_uplift["passed_validation_check_ids_by_item"]["#59"])
            self.assertFalse(queue_uplift["large_data_controls"]["native_ocr_engine_execution"])
            self.assertEqual(payload["trusted_ocr_queue_diffs"]["58"]["status"], "missing")
            self.assertIn(
                "#58:ocr-queue-trusted-engine-log-diff-required",
                queue_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(
                queue_uplift["reportability_decision"]["decision"],
                "do-not-report-ocr-or-translation-as-engine-validated",
            )
            self.assertEqual(
                queue_uplift["reportability_decision"]["allowed_use"],
                "ocr-sidecar-and-queue-triage-pivot",
            )
            self.assertIn(
                "#59:certified-translation-workflow",
                queue_uplift["reportability_decision"]["blockers"],
            )
            item = payload["items"][0]
            self.assertEqual(item["status"], "sidecar-imported")
            self.assertIn("#58", item["commercial_gap_ids"])
            self.assertEqual(item["core_accuracy_gates"][0]["gap_id"], "#58")
            self.assertEqual(item["commercial_uplift_evidence"]["item_numbers"], [58, 59])
            self.assertEqual(
                item["commercial_uplift_evidence"]["reportability_decision"]["allowed_use"],
                "ocr-sidecar-and-queue-triage-pivot",
            )
            self.assertIn("#59", item["korean_ocr_translation_workflow"]["commercial_gap_ids"])
            self.assertFalse(item["report_grade_assessment"]["ready_for_court_report"])
            self.assertEqual(item["language_hint"], "ko+en")
            self.assertAlmostEqual(item["confidence"], 0.91)
            self.assertEqual(item["sidecar"]["metadata"]["engine"], "external")
            self.assertEqual(item["translation_status"], "sidecar-imported")
            self.assertEqual(item["translation_sidecar"]["target_language"], "en")
            self.assertTrue(item["quality_metrics"]["korean_text_present"])

    def test_ocr_queue_cli_writes_json_and_requeues_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "failed.jpg"
            image_path.write_bytes(b"\xff\xd8fake\xff\xd9")
            previous = root / "previous.json"
            previous.write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "source_path": str(image_path.resolve()),
                                "status": "failed",
                                "attempt_count": 1,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "queue.json"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "ocr-queue",
                        str(root),
                        "--previous",
                        str(previous),
                        "--retry-failures",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(output.is_file())
            self.assertEqual(payload["summary"]["failed_retry_queued_count"], 1)
            self.assertEqual(payload["items"][0]["status"], "failed-retry-queued")
            self.assertEqual(payload["items"][0]["attempt_count"], 2)
            self.assertIn("#58", payload["items"][0]["report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#58")

    def test_ocr_queue_trusted_diffs_control_core_accuracy_gates(self) -> None:
        row = {
            "queue_id": "queue-1",
            "source_path": "/case/screen.png",
            "source_sha256": "source-hash",
            "status": "sidecar-imported",
            "sidecar": {"sha256": "sidecar-hash", "text_sha256": "text-hash", "metadata": {"engine": "external"}},
            "translation_sidecar": {"sha256": "translation-hash", "text_sha256": "translation-text-hash"},
            "language_hint": "ko+en",
            "confidence": 0.91,
        }
        ocr_diff = build_ocr_queue_trusted_diff(58, [row], [dict(row)], trusted_tool="ocr-engine-log")
        translation_diff = build_ocr_queue_trusted_diff(59, [row], [dict(row)], trusted_tool="korean-ocr-review")
        self.assertEqual(ocr_diff["status"], "pass")
        self.assertEqual(translation_diff["status"], "pass")

        gates = ocr_queue_core_accuracy_gates(
            items=[row],
            root=Path("/case"),
            trusted_diffs={"58": ocr_diff, "59": translation_diff},
        )
        by_gap = {gate["gap_id"]: gate for gate in gates}
        self.assertIn("trusted OCR queue engine/sidecar diff pass", by_gap["#58"]["satisfied_checks"])
        self.assertIn("trusted Korean OCR/translation review diff pass", by_gap["#59"]["satisfied_checks"])

        mismatch = build_ocr_queue_trusted_diff(
            58,
            [row],
            [{**row, "status": "queued"}],
            trusted_tool="ocr-engine-log",
        )
        self.assertEqual(mismatch["status"], "diffs-present")
        self.assertIn("ocr-queue-trusted-engine-log-diff-required", mismatch["reportability_decision"]["blockers"])


if __name__ == "__main__":
    unittest.main()
