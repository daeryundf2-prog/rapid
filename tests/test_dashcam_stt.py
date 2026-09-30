"""Dashcam audio-probe + STT lane tests."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from dashcam_tools import audio as dc_audio
from dashcam_tools import stt as dc_stt

FFMPEG = shutil.which("ffmpeg")


def _make_mp4(dst: Path, with_audio: bool) -> bool:
    if not FFMPEG:
        return False
    cmd = [
        "ffmpeg", "-y", "-v", "error",
        "-f", "lavfi", "-i", "testsrc=duration=1:size=64x64:rate=10",
    ]
    if with_audio:
        cmd += ["-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-shortest"]
    cmd += ["-c:v", "libx264", "-pix_fmt", "yuv420p", str(dst)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    except Exception:
        return False
    return dst.is_file()


@unittest.skipUnless(FFMPEG and shutil.which("ffprobe"), "ffmpeg/ffprobe not on PATH")
class AudioProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="dc-audio-"))
        cls.with_audio = cls.tmp / "cam_audio.mp4"
        cls.no_audio = cls.tmp / "cam_video_only.mp4"
        if not (_make_mp4(cls.with_audio, True) and _make_mp4(cls.no_audio, False)):
            raise unittest.SkipTest("could not synthesize test mp4s")

    def test_audio_stream_detected(self):
        streams = dc_audio.audio_streams(self.with_audio)
        self.assertTrue(dc_audio.has_audio(self.with_audio))
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]["codec_name"], "aac")
        self.assertIn("sample_rate", streams[0])

    def test_video_only_reports_no_audio(self):
        self.assertFalse(dc_audio.has_audio(self.no_audio))
        self.assertEqual(dc_audio.audio_streams(self.no_audio), [])

    def test_extract_audio_wav(self):
        wav = self.tmp / "out.wav"
        self.assertTrue(dc_audio.extract_audio_wav(self.with_audio, wav))
        self.assertGreater(wav.stat().st_size, 1000)
        self.assertFalse(dc_audio.extract_audio_wav(self.no_audio, self.tmp / "none.wav"))


class TranscribeVideoTests(unittest.TestCase):
    class FakeModel:
        def transcribe(self, wav, **options):
            return {
                "language": options.get("language") or "ko",
                "text": "테스트 음성입니다",
                "segments": [
                    {"id": 0, "start": 0.0, "end": 0.9, "text": " 테스트 음성입니다"},
                ],
            }

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="dc-stt-"))
        if not (FFMPEG and shutil.which("ffprobe")):
            raise unittest.SkipTest("ffmpeg/ffprobe not on PATH")
        cls.with_audio = cls.tmp / "clip.mp4"
        cls.no_audio = cls.tmp / "silent.mp4"
        if not (_make_mp4(cls.with_audio, True) and _make_mp4(cls.no_audio, False)):
            raise unittest.SkipTest("could not synthesize test mp4s")

    def test_transcribe_writes_sidecars_with_provenance(self):
        out = self.tmp / "out"
        row = dc_stt.transcribe_video(
            self.with_audio, out, self.FakeModel(), model_name="fake", language="ko"
        )
        self.assertEqual(row["status"], "transcribed")
        self.assertEqual(row["language"], "ko")
        self.assertEqual(row["segment_count"], 1)

        transcript = json.loads(Path(row["transcript_json"]).read_text(encoding="utf-8"))
        self.assertEqual(transcript["schema"], "dashcam-stt-transcript-v1")
        self.assertEqual(transcript["source_sha256"], row["sha256"])
        self.assertEqual(len(row["sha256"]), 64)
        self.assertEqual(transcript["model"], "whisper:fake")
        self.assertEqual(transcript["segments"][0]["start"], 0.0)
        self.assertIn("테스트 음성입니다", transcript["text"])

        txt = Path(row["transcript_txt"]).read_text(encoding="utf-8")
        self.assertIn("0.0 -", txt)
        self.assertIn("테스트 음성입니다", txt)

    def test_no_audio_stream_skips_cleanly(self):
        row = dc_stt.transcribe_video(self.no_audio, self.tmp / "out2", self.FakeModel())
        self.assertEqual(row["status"], "no-audio-stream")
        self.assertEqual(row["audio_streams"], [])

    def test_probe_only_cli(self):
        out = self.tmp / "probe-out"
        rc = dc_stt.cli(
            ["--dir", str(self.tmp), "--output-dir", str(out), "--probe-only"]
        )
        self.assertEqual(rc, 0)
        audit = json.loads((out / "dashcam-stt-audit.json").read_text(encoding="utf-8"))
        self.assertEqual(audit["mode"], "probe-only")
        self.assertEqual(audit["status_counts"].get("has-audio"), 1)
        self.assertEqual(audit["status_counts"].get("no-audio-stream"), 1)


if __name__ == "__main__":
    unittest.main()
