from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from rapidtriage.artifacts.media import average_hash
from rapidtriage.cli import build_parser, main


class RapidTriageMediaImageTests(unittest.TestCase):
    def test_parser_exposes_media_image_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("media-image", help_text)

    def test_media_image_artifacts_collect_dimensions_hashes_and_similarity_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "Pictures" / "screen.png"
            image_path.parent.mkdir()
            write_image_fixture(image_path)
            (image_path.parent / "screen.ocr.txt").write_text("한글 OCR test password", encoding="utf-8")
            (image_path.parent / "screen.translation.txt").write_text("Korean OCR test password", encoding="utf-8")
            output = root / "media-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "media-image", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "media-image")
            self.assertEqual(payload["provider"]["name"], "media-image-artifacts")
            self.assertEqual(payload["summary"]["artifact_count"], 1)
            artifact = payload["artifacts"][0]
            details = artifact["details"]
            self.assertEqual(artifact["artifact_type"], "media-image")
            self.assertEqual(details["width"], 16)
            self.assertEqual(details["height"], 16)
            self.assertEqual(len(details["perceptual_hash"]), 16)
            self.assertEqual(details["similarity_bucket"], details["perceptual_hash"][:8])
            self.assertIn("sha256", details["hashes"])
            self.assertIn("#56", details["commercial_gap_ids"])
            self.assertIn("#58", details["commercial_gap_ids"])
            self.assertIn("#59", details["commercial_gap_ids"])
            self.assertIn("#56", details["media_report_grade_assessment"]["commercial_gap_ids"])
            media_gates = {gate["gap_id"]: gate for gate in details["core_accuracy_gates"]}
            self.assertIn("image metadata and source hashes", media_gates["#56"]["satisfied_checks"])
            self.assertIn("sidecar import and hashes", media_gates["#58"]["satisfied_checks"])
            self.assertIn("Korean language hinting", media_gates["#59"]["satisfied_checks"])
            self.assertIn("translation sidecar import", media_gates["#59"]["satisfied_checks"])
            self.assertTrue(details["media_native_capabilities"]["image_gallery_review_metadata"])
            self.assertGreaterEqual(details["parser_confidence"], 0.8)
            self.assertTrue(details["ocr_candidate"])
            self.assertIn("#56", details["gallery_review_mode"]["commercial_gap_ids"])
            media_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(media_uplift["batch_id"], "commercial-uplift-056-060")
            self.assertEqual(media_uplift["item_numbers"], [56, 58, 59])
            self.assertIn("image metadata and source hashes", media_uplift["passed_validation_check_ids_by_item"]["#56"])
            self.assertIn("sidecar import and hashes", media_uplift["passed_validation_check_ids_by_item"]["#58"])
            self.assertIn("Korean language hinting", media_uplift["passed_validation_check_ids_by_item"]["#59"])
            self.assertFalse(media_uplift["large_data_controls"]["native_ocr_execution"])
            self.assertEqual(
                media_uplift["reportability_decision"]["decision"],
                "do-not-report-media-image-output-as-gallery-ocr-or-translation-complete",
            )
            self.assertEqual(
                media_uplift["reportability_decision"]["allowed_use"],
                "image-gallery-ocr-sidecar-triage-pivot",
            )
            self.assertIn(
                "#56:ml-visual-similarity",
                media_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(details["ocr_plan"]["status"], "sidecar-imported")
            self.assertIn("#58", details["ocr_plan"]["commercial_gap_ids"])
            self.assertEqual(details["ocr_plan"]["recommended_languages"], ["kor", "eng"])
            self.assertTrue(details["ocr_plan"]["korean_language_pack_required"])
            self.assertEqual(details["translation_plan"]["status"], "sidecar-imported")
            self.assertIn("#59", details["translation_plan"]["commercial_gap_ids"])
            self.assertIn("#59", details["korean_ocr_translation_workflow"]["commercial_gap_ids"])
            self.assertEqual(details["translation_sidecar"]["target_language"], "en")
            self.assertIn("text_sha256", details["translation_sidecar"])
            self.assertEqual(details["ocr_sidecar"]["language_hint"], "ko+en")
            self.assertIn("text_sha256", details["ocr_sidecar"])
            self.assertTrue(details["ocr_sidecar"]["quality_metrics"]["korean_text_present"])
            self.assertGreater(details["ocr_sidecar"]["quality_metrics"]["hangul_count"], 0)
            self.assertEqual(details["visual_classification"]["validation_status"], "triage-hint")
            self.assertEqual(details["classifier_validation"]["deepfake_detection_status"], "not-run")
            thumbnail = details["thumbnail_preview"]
            self.assertTrue(thumbnail["available"])
            self.assertEqual(thumbnail["strategy"], "bounded-inline-png")
            self.assertEqual(thumbnail["format"], "png")
            self.assertEqual(thumbnail["width"], 16)
            self.assertEqual(thumbnail["height"], 16)
            self.assertIn("sha256", thumbnail)
            self.assertTrue(thumbnail["data_uri"].startswith("data:image/png;base64,"))

    def test_average_hash_does_not_require_numpy_mean_or_flatten(self) -> None:
        image = FakeMatrix()

        with patch("rapidtriage.artifacts.media.cv2.resize", return_value=FakeMatrix()):
            perceptual_hash = average_hash(image)

        self.assertEqual(len(perceptual_hash), 16)


def write_image_fixture(path: Path) -> None:
    image = Image.new("RGB", (16, 16), "black")
    for x in range(8):
        for y in range(16):
            image.putpixel((x, y), (255, 255, 255))
    image.save(path)


class FakeMatrix:
    shape = (8, 8)

    def tolist(self) -> list[list[int]]:
        return [[255 if x < 4 else 0 for x in range(8)] for _ in range(8)]

    def mean(self) -> float:
        raise AssertionError("average_hash should not require numpy mean()")

    def flatten(self) -> list[int]:
        raise AssertionError("average_hash should not require numpy flatten()")


if __name__ == "__main__":
    unittest.main()
