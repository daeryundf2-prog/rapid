from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

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
            self.assertTrue(details["ocr_candidate"])
            self.assertEqual(details["ocr_plan"]["status"], "sidecar-imported")
            self.assertEqual(details["ocr_plan"]["recommended_languages"], ["kor", "eng"])
            self.assertTrue(details["ocr_plan"]["korean_language_pack_required"])
            self.assertEqual(details["translation_plan"]["status"], "required-not-run")
            self.assertEqual(details["ocr_sidecar"]["language_hint"], "ko+en")
            self.assertIn("text_sha256", details["ocr_sidecar"])
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


def write_image_fixture(path: Path) -> None:
    image = Image.new("RGB", (16, 16), "black")
    for x in range(8):
        for y in range(16):
            image.putpixel((x, y), (255, 255, 255))
    image.save(path)


if __name__ == "__main__":
    unittest.main()
