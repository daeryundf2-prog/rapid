from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import cv2
import numpy as np

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


def write_image_fixture(path: Path) -> None:
    image = np.zeros((16, 16, 3), dtype=np.uint8)
    image[:, :8] = (255, 255, 255)
    if not cv2.imwrite(str(path), image):
        raise RuntimeError(f"failed to write image fixture: {path}")


if __name__ == "__main__":
    unittest.main()
