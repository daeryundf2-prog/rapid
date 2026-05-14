from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HAS_PILLOW = True
try:
    from PIL import Image
except ModuleNotFoundError as exc:
    if exc.name == "PIL":
        HAS_PILLOW = False
    else:
        raise

from rapidtriage.artifacts.media import (
    average_hash,
    build_image_gallery_manifest,
    build_media_trusted_diff,
    exif_gps_map_review_profile,
    extract_exif_gps_profile,
    media_core_accuracy_gates,
    media_review_risk_flags,
)
from rapidtriage.cli import build_parser, main


class RapidTriageExifGpsProfileTests(unittest.TestCase):
    def test_exif_gps_profile_decodes_map_marker_with_fake_pillow(self) -> None:
        class FakeExif(dict):
            def get_ifd(self, tag: int) -> dict[object, object]:
                return self[tag]

        class FakeImageHandle:
            def __enter__(self) -> "FakeImageHandle":
                return self

            def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
                return None

            def getexif(self) -> FakeExif:
                return FakeExif(
                    {
                        306: "2026:05:14 10:20:30",
                        36867: "2026:05:14 10:20:30",
                        34853: {
                            1: "N",
                            2: ((37, 1), (33, 1), (30, 1)),
                            3: "E",
                            4: ((127, 1), (0, 1), (0, 1)),
                            5: 0,
                            6: (25, 1),
                            7: ((10, 1), (20, 1), (30, 1)),
                            16: "T",
                            17: (90, 1),
                            18: "WGS-84",
                            29: "2026:05:14",
                        },
                    }
                )

        class FakeImageModule:
            @staticmethod
            def open(path: Path) -> FakeImageHandle:  # noqa: ARG004
                return FakeImageHandle()

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "gps.jpg"
            path.write_bytes(b"\xff\xd8\xff\xd9")

            with patch("rapidtriage.artifacts.media.Image", FakeImageModule):
                profile = extract_exif_gps_profile(path)

            self.assertEqual(profile["status"], "parsed")
            self.assertTrue(profile["has_gps"])
            self.assertAlmostEqual(profile["latitude"], 37.5583333)
            self.assertAlmostEqual(profile["longitude"], 127.0)
            self.assertEqual(profile["altitude_meters"], 25.0)
            self.assertEqual(profile["gps_datetime_utc_candidate"], "2026:05:14 10:20:30Z")
            self.assertEqual(profile["map_marker"]["status"], "ready")
            self.assertEqual(profile["field_presence"]["direction"], True)

            map_profile = exif_gps_map_review_profile(profile, source_path=path)
            self.assertEqual(map_profile["status"], "map-marker-ready")
            self.assertEqual(map_profile["source_viewer_locator"]["viewer"], "source-map")
            self.assertEqual(map_profile["source_viewer_locator"]["open_action"], "open-map-at-exif-marker")

            flags = media_review_risk_flags(
                decoded=True,
                steganography_profile={},
                authenticity_profile={},
                exif_gps_profile=profile,
            )
            self.assertIn("exif-gps-location-candidate", flags)
            self.assertIn("exif-datetime-candidate", flags)


@unittest.skipUnless(HAS_PILLOW, "Pillow is required for RapidTriage media image fixture tests")
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
            with image_path.open("ab") as handle:
                handle.write(b"PK\x03\x04hidden-review-payload")
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
            self.assertEqual(details["image_gallery_manifest"]["manifest_version"], "image-gallery-source-manifest-v1")
            self.assertEqual(details["image_gallery_manifest_hash"], details["image_gallery_manifest"]["manifest_hash"])
            self.assertEqual(details["image_gallery_manifest"]["source_viewer_locator"]["viewer"], "source-image-gallery")
            self.assertTrue(details["image_gallery_manifest"]["image_row_hash"])
            media_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(media_uplift["batch_id"], "commercial-uplift-056-060")
            self.assertEqual(media_uplift["item_numbers"], [56, 58, 59])
            self.assertIn("image metadata and source hashes", media_uplift["passed_validation_check_ids_by_item"]["#56"])
            self.assertIn("image gallery source manifest", media_uplift["passed_validation_check_ids_by_item"]["#56"])
            self.assertTrue(media_uplift["large_data_controls"]["image_gallery_manifest_present"])
            self.assertEqual(media_uplift["large_data_controls"]["image_gallery_manifest_hash"], details["image_gallery_manifest_hash"])
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
            self.assertTrue(details["media_native_capabilities"]["steganography_suspicion_scan"])
            self.assertTrue(details["media_native_capabilities"]["media_authenticity_metadata_scan"])
            self.assertTrue(details["media_native_capabilities"]["exif_gps_location_profile"])
            self.assertIn("exif_gps_profile", details)
            self.assertIn("exif_map_review_profile", details)
            stego_profile = details["steganography_suspicion_profile"]
            self.assertEqual(stego_profile["status"], "completed")
            self.assertTrue(stego_profile["trailing_data_present"])
            self.assertGreater(stego_profile["trailing_data_bytes"], 0)
            self.assertIn("embedded-signature-after-image-end", stego_profile["suspicion_reasons"])
            self.assertEqual(stego_profile["embedded_signature_candidates"][0]["signature"], "zip-local-file-header")
            self.assertIn("steganography-suspicion-candidate", details["risk_flags"])
            self.assertIn("embedded-payload-signature-candidate", details["risk_flags"])
            authenticity_profile = details["media_authenticity_profile"]
            self.assertEqual(authenticity_profile["classifier_status"], "heuristic-metadata-only")
            self.assertEqual(authenticity_profile["deepfake_detection_status"], "not-run")
            self.assertEqual(authenticity_profile["suspicion_level"], "none")
            self.assertEqual(details["media_trusted_diffs"]["56"]["status"], "missing")
            self.assertIn(
                "#56:image-gallery-trusted-manifest-diff-required",
                media_uplift["reportability_decision"]["blockers"],
            )
            thumbnail = details["thumbnail_preview"]
            self.assertTrue(thumbnail["available"])
            self.assertEqual(thumbnail["strategy"], "bounded-inline-png")
            self.assertEqual(thumbnail["format"], "png")
            self.assertEqual(thumbnail["width"], 16)
            self.assertEqual(thumbnail["height"], 16)
            self.assertIn("sha256", thumbnail)
            self.assertTrue(thumbnail["data_uri"].startswith("data:image/png;base64,"))

    def test_media_collector_inventories_video_audio_and_transcript_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            media_dir = root / "Media"
            media_dir.mkdir()
            video = media_dir / "interview.mp4"
            audio = media_dir / "call.wav"
            ftyp_box = b"\x00\x00\x00\x18ftypmp42" + b"\x00\x00\x00\x00" + b"mp42isom"
            mvhd_payload = b"\x00\x00\x00\x00" + (0).to_bytes(4, "big") + (0).to_bytes(4, "big") + (1000).to_bytes(4, "big") + (2500).to_bytes(4, "big")
            mvhd_box = (8 + len(mvhd_payload)).to_bytes(4, "big") + b"mvhd" + mvhd_payload
            moov_box = (8 + len(mvhd_box)).to_bytes(4, "big") + b"moov" + mvhd_box
            video.write_bytes(ftyp_box + moov_box)
            write_image_fixture(media_dir / "interview.mp4.jpg")
            (media_dir / "interview.mp4.ffprobe.json").write_text(
                json.dumps(
                    {
                        "format": {
                            "filename": "interview.mp4",
                            "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
                            "duration": "2.500000",
                            "size": "128",
                            "bit_rate": "4096",
                        },
                        "streams": [
                            {
                                "index": 0,
                                "codec_type": "video",
                                "codec_name": "h264",
                                "width": 1920,
                                "height": 1080,
                                "duration": "2.500000",
                                "bit_rate": "2048",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            pcm_samples = b"".join(int(sample).to_bytes(2, "little", signed=True) for sample in (0, 12000, -12000, 24000, -24000, 8000, -8000, 0) * 128)
            audio.write_bytes(
                b"RIFF"
                + (36 + len(pcm_samples)).to_bytes(4, "little")
                + b"WAVEfmt "
                + (16).to_bytes(4, "little")
                + (1).to_bytes(2, "little")
                + (1).to_bytes(2, "little")
                + (8000).to_bytes(4, "little")
                + (16000).to_bytes(4, "little")
                + (2).to_bytes(2, "little")
                + (16).to_bytes(2, "little")
                + b"data"
                + len(pcm_samples).to_bytes(4, "little")
                + pcm_samples
            )
            (media_dir / "call.wav.ffprobe.json").write_text(
                json.dumps(
                    {
                        "format": {"filename": "call.wav", "format_name": "wav", "duration": str(len(pcm_samples) / 16000)},
                        "streams": [
                            {
                                "index": 0,
                                "codec_type": "audio",
                                "codec_name": "pcm_s16le",
                                "sample_rate": "8000",
                                "channels": 1,
                                "duration": str(len(pcm_samples) / 16000),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (media_dir / "interview.mp4.vtt").write_text("WEBVTT\n\n00:00.000 --> 00:01.000\n안녕하세요", encoding="utf-8")
            output = root / "media-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "media-image", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            type_counts = payload["summary"]["artifact_type_counts"]
            self.assertEqual(type_counts["media-video"], 1)
            self.assertEqual(type_counts["media-audio"], 1)
            video_row = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "media-video")
            audio_row = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "media-audio")
            self.assertEqual(video_row["details"]["media_kind"], "video")
            self.assertEqual(video_row["details"]["container_profile"]["parse_status"], "ftyp-header-parsed")
            self.assertEqual(video_row["details"]["container_profile"]["major_brand"], "mp42")
            self.assertEqual(video_row["details"]["container_profile"]["box_inventory"][0]["type"], "ftyp")
            self.assertEqual(video_row["details"]["container_profile"]["box_inventory"][1]["type"], "moov")
            self.assertEqual(video_row["details"]["container_profile"]["mvhd_profile"]["status"], "parsed")
            self.assertEqual(video_row["details"]["container_profile"]["mvhd_profile"]["estimated_duration_seconds"], 2.5)
            self.assertEqual(video_row["details"]["transcript_sidecar_count"], 1)
            self.assertEqual(video_row["details"]["transcript_cue_sample_count"], 1)
            self.assertEqual(video_row["details"]["transcript_cue_samples"][0]["text"], "안녕하세요")
            self.assertTrue(video_row["details"]["transcript_sidecars"][0]["contains_hangul"])
            self.assertEqual(video_row["details"]["preview_sidecar_count"], 1)
            self.assertEqual(video_row["details"]["preview_workflow"]["thumbnail_status"], "sidecar-linked")
            self.assertTrue(video_row["details"]["preview_sidecars"][0]["image_profile"]["decoded"])
            self.assertEqual(video_row["details"]["codec_metadata_sidecar_count"], 1)
            self.assertEqual(video_row["details"]["preview_workflow"]["codec_metadata_status"], "sidecar-linked")
            self.assertEqual(video_row["details"]["codec_metadata_sidecars"][0]["tool_hint"], "ffprobe-json")
            self.assertEqual(video_row["details"]["codec_metadata_summary"]["duration_seconds"], 2.5)
            self.assertEqual(video_row["details"]["codec_metadata_summary"]["primary_video"]["codec_name"], "h264")
            self.assertEqual(video_row["details"]["codec_metadata_summary"]["primary_video"]["width"], 1920)
            self.assertFalse(video_row["details"]["commercial_grade_ready"])
            self.assertEqual(audio_row["details"]["preview_workflow"]["waveform_status"], "pcm16-peak-preview")
            self.assertEqual(audio_row["details"]["codec_metadata_summary"]["primary_audio"]["codec_name"], "pcm_s16le")
            self.assertEqual(audio_row["details"]["codec_metadata_summary"]["primary_audio"]["sample_rate"], 8000)
            self.assertEqual(audio_row["details"]["waveform_preview"]["bucket_count"], 32)
            self.assertGreater(audio_row["details"]["waveform_preview"]["peaks"][0]["peak"], 0)
            self.assertEqual(audio_row["details"]["container_profile"]["parse_status"], "riff-wave-header-parsed")
            self.assertEqual(audio_row["details"]["container_profile"]["sample_rate"], 8000)
            self.assertEqual(audio_row["details"]["container_profile"]["estimated_duration_seconds"], len(pcm_samples) / 16000)

    def test_average_hash_does_not_require_numpy_mean_or_flatten(self) -> None:
        image = FakeMatrix()

        with patch("rapidtriage.artifacts.media.cv2.resize", return_value=FakeMatrix()):
            perceptual_hash = average_hash(image)

        self.assertEqual(len(perceptual_hash), 16)

    def test_media_trusted_diffs_control_core_accuracy_gates(self) -> None:
        image_row = {
            "source_path": "/case/screen.png",
            "hashes": {"sha256": "image-hash"},
            "width": 16,
            "height": 16,
            "perceptual_hash": "f0f0f0f0f0f0f0f0",
            "similarity_bucket": "f0f0f0f0",
        }
        ocr_row = {
            "source_path": "/case/screen.png.ocr.txt",
            "source_sha256": "image-hash",
            "sidecar_sha256": "sidecar-hash",
            "text_sha256": "text-hash",
            "engine": "external",
        }
        translation_row = {
            "source_path": "/case/screen.translation.txt",
            "language_hint": "ko+en",
            "translation_sha256": "translation-hash",
            "text_sha256": "translation-text-hash",
            "review_status": "human-reviewed",
        }
        gallery_diff = build_media_trusted_diff(56, [image_row], [dict(image_row)], trusted_tool="image-gallery-ground-truth")
        ocr_diff = build_media_trusted_diff(58, [ocr_row], [dict(ocr_row)], trusted_tool="ocr-engine-log")
        translation_diff = build_media_trusted_diff(59, [translation_row], [dict(translation_row)], trusted_tool="korean-ocr-review")
        self.assertEqual(gallery_diff["status"], "pass")
        self.assertEqual(ocr_diff["status"], "pass")
        self.assertEqual(translation_diff["status"], "pass")

        gates = media_core_accuracy_gates(
            details={
                **image_row,
                "source_format": "png",
                "source_size": 128,
                "thumbnail_preview": {"available": True},
                "gallery_review_mode": {"status": "ready"},
                "ocr_plan": {"status": "sidecar-imported"},
                "ocr_sidecar": {"text_sha256": "text-hash", "source_sha256": "image-hash", "sha256": "sidecar-hash", "metadata": {"engine": "external"}, "quality_metrics": {"korean_text_present": True}},
                "translation_sidecar": {"text_sha256": "translation-text-hash"},
                "korean_ocr_translation_workflow": {"language_hints": ["kor", "eng"]},
                "media_trusted_diffs": {"56": gallery_diff, "58": ocr_diff, "59": translation_diff},
            },
            source_path=Path("/case/screen.png"),
        )
        by_gap = {gate["gap_id"]: gate for gate in gates}
        self.assertIn("trusted image gallery manifest diff pass", by_gap["#56"]["satisfied_checks"])
        self.assertIn("trusted OCR engine/sidecar diff pass", by_gap["#58"]["satisfied_checks"])
        self.assertIn("trusted Korean OCR/translation review diff pass", by_gap["#59"]["satisfied_checks"])

        mismatch = build_media_trusted_diff(56, [image_row], [{**image_row, "width": 32}], trusted_tool="image-gallery-ground-truth")
        self.assertEqual(mismatch["status"], "diffs-present")
        self.assertIn("image-gallery-trusted-manifest-diff-required", mismatch["reportability_decision"]["blockers"])

    def test_image_gallery_manifest_hashes_source_row_for_review(self) -> None:
        details = {
            "entry_name": "screen.png",
            "source_format": "png",
            "source_size": 128,
            "decoded": True,
            "width": 16,
            "height": 16,
            "channel_count": 3,
            "hashes": {"sha256": "image-hash"},
            "perceptual_hash": "f0f0f0f0f0f0f0f0",
            "similarity_bucket": "f0f0f0f0",
            "thumbnail_preview": {"sha256": "thumb-hash"},
            "visual_classification": {"label": "image", "validation_status": "triage-hint"},
            "exif_gps_profile": {
                "has_gps": True,
                "latitude": 37.5583333,
                "longitude": 127.0,
                "gps_datetime_utc_candidate": "2026:05:14 10:20:30Z",
            },
            "exif_map_review_profile": {
                "source_viewer_locator": {
                    "viewer": "source-map",
                    "path": "/case/screen.png",
                    "open_action": "open-map-at-exif-marker",
                    "latitude": 37.5583333,
                    "longitude": 127.0,
                }
            },
        }
        manifest = build_image_gallery_manifest(details=details, source_path=Path("/case/screen.png"))

        self.assertEqual(manifest["manifest_version"], "image-gallery-source-manifest-v1")
        self.assertEqual(manifest["source_viewer_locator"]["viewer"], "source-image-gallery")
        self.assertEqual(manifest["image_row"]["sha256"], "image-hash")
        self.assertEqual(manifest["image_row"]["similarity_bucket"], "f0f0f0f0")
        self.assertTrue(manifest["image_row"]["exif_gps_present"])
        self.assertEqual(manifest["image_row"]["exif_gps_latitude"], 37.5583333)
        self.assertEqual(manifest["map_source_viewer_locator"]["viewer"], "source-map")
        self.assertRegex(manifest["image_row_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(manifest["manifest_hash"], r"^[0-9a-f]{64}$")


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
