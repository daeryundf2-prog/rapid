#!/usr/bin/env python3
"""Speech-to-text lane for dashcam videos.

For each video with an audio stream: extract a 16 kHz mono WAV via ffmpeg,
transcribe with openai-whisper (lazy import — the package is an optional
dependency), and write sidecar transcripts plus a run-level audit JSON.

Whisper runs locally; nothing leaves the machine. CPU is the default —
whisper auto-selects CUDA when torch was built with it. Transcripts are
reviewer aids, not verbatim court records; the audit JSON records model,
language, and source hash so every transcript keeps provenance.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

from .audio import (
    audio_streams,
    extract_audio_wav,
    ffmpeg_available,
)
from .report import compute_hash, iter_videos, tool_version

_whisper = None
_WHISPER_IMPORT_ERROR = ""


def load_whisper():
    global _whisper, _WHISPER_IMPORT_ERROR
    if _whisper is not None:
        return _whisper
    try:
        import whisper as _whisper_mod  # type: ignore

        _whisper = _whisper_mod
    except Exception as exc:
        _WHISPER_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
        _whisper = None
    return _whisper


def whisper_available() -> bool:
    return load_whisper() is not None


def transcribe_video(
    video: Path,
    out_dir: Path,
    model,
    *,
    model_name: str = "",
    language: str | None = "ko",
    keep_wav: bool = False,
) -> dict[str, Any]:
    """Probe, extract, and transcribe one video. Returns a status row."""
    row: dict[str, Any] = {
        "path": str(video),
        "sha256": "",
        "status": "pending",
        "audio_streams": audio_streams(video),
        "transcript_json": "",
        "transcript_txt": "",
    }
    try:
        row["sha256"] = compute_hash(video)
    except OSError as exc:
        row["status"] = "hash-error"
        row["error"] = str(exc)
        return row
    if not row["audio_streams"]:
        row["status"] = "no-audio-stream"
        return row

    wav_dir = out_dir / "_wav" if keep_wav else None
    with tempfile.TemporaryDirectory(prefix="dashcam-stt-") as tmp:
        wav_path = Path(wav_dir or tmp) / (video.stem + ".wav")
        if not extract_audio_wav(video, wav_path):
            row["status"] = "audio-extract-failed"
            return row
        options: dict[str, Any] = {}
        if language:
            options["language"] = language
        result = model.transcribe(str(wav_path), **options)

    segments = [
        {
            "id": seg.get("id"),
            "start": round(float(seg.get("start") or 0.0), 3),
            "end": round(float(seg.get("end") or 0.0), 3),
            "text": str(seg.get("text") or "").strip(),
        }
        for seg in (result.get("segments") or [])
    ]
    transcript = {
        "schema": "dashcam-stt-transcript-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_path": str(video),
        "source_sha256": row["sha256"],
        "model": f"whisper:{model_name or 'unknown'}",
        "language": result.get("language") or language or "auto",
        "segment_count": len(segments),
        "segments": segments,
        "text": str(result.get("text") or "").strip(),
        "note": "Local whisper transcript for reviewer triage; verify against audio before citing.",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{video.name}.transcript.json"
    txt_path = out_dir / f"{video.name}.transcript.txt"
    json_path.write_text(json.dumps(transcript, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [f"[{seg['start']:>8.1f} - {seg['end']:>8.1f}] {seg['text']}" for seg in segments]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    row["status"] = "transcribed"
    row["language"] = transcript["language"]
    row["segment_count"] = len(segments)
    row["transcript_json"] = str(json_path)
    row["transcript_txt"] = str(txt_path)
    return row


def cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Detect audio streams in dashcam videos and optionally transcribe them with whisper"
    )
    ap.add_argument("--dir", required=True, help="Target directory or single video file")
    ap.add_argument("--output-dir", default="dashcam-stt", help="Transcript/audit output directory")
    ap.add_argument("--model", default="small", help="whisper model name or path (default: small)")
    ap.add_argument("--language", default="ko", help="Whisper language code; empty for auto-detect")
    ap.add_argument("--probe-only", action="store_true", help="Only report audio streams; skip transcription")
    ap.add_argument("--keep-wav", action="store_true", help="Keep extracted WAVs under <output-dir>/_wav")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of videos (0=all)")
    ap.add_argument("--json", action="store_true", help="Print machine-readable summary")
    args = ap.parse_args(argv)

    root = Path(args.dir).expanduser().resolve()
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    model = None
    if not args.probe_only:
        whisper_mod = load_whisper()
        if whisper_mod is None:
            print(f"whisper is not importable: {_WHISPER_IMPORT_ERROR}", file=sys.stderr)
            print("Install the optional STT dependency: pip install openai-whisper", file=sys.stderr)
            return 2
        if not ffmpeg_available():
            print("ffmpeg is required to extract audio for STT but was not found on PATH", file=sys.stderr)
            return 2
        model = whisper_mod.load_model(args.model)

    language = args.language.strip() or None
    total = 0
    for p in iter_videos(root):
        if args.limit and total >= args.limit:
            break
        total += 1
        if args.probe_only:
            streams = audio_streams(p)
            rows.append(
                {
                    "path": str(p),
                    "status": "has-audio" if streams else "no-audio-stream",
                    "audio_streams": streams,
                }
            )
        else:
            rows.append(
                transcribe_video(
                p, out_dir, model, model_name=args.model, language=language, keep_wav=args.keep_wav
            )
            )

    status_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1

    audit = {
        "schema": "dashcam-stt-audit-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(root),
        "mode": "probe-only" if args.probe_only else "transcribe",
        "video_count": len(rows),
        "status_counts": status_counts,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "ffprobe": tool_version(["ffprobe", "-version"]),
            "ffmpeg": tool_version(["ffmpeg", "-version"]),
            "whisper_model": None if args.probe_only else args.model,
            "language": language or "auto",
        },
        "rows": rows,
        "note": "Audio-stream presence is container metadata. Transcripts are local whisper output for reviewer triage; verify before report inclusion.",
    }
    audit_path = out_dir / "dashcam-stt-audit.json"
    audit_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(audit, ensure_ascii=False, indent=2))
    else:
        print(f"Videos: {len(rows)}")
        for status, count in sorted(status_counts.items()):
            print(f"  {status}: {count}")
        print(f"Audit: {audit_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
