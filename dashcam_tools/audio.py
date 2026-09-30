#!/usr/bin/env python3
"""Audio-stream probing and extraction for dashcam videos.

ffprobe reports every elementary stream in the container; dashcam MP4s
typically carry one H.264/H.265 video track plus an optional PCM/AAC audio
track recorded by the cabin microphone. This module exposes that inventory
(``has_audio``/``audio_streams``) and a bounded WAV extractor used by the
STT lane.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def ffprobe_available() -> bool:
    return shutil.which("ffprobe") is not None


def ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def probe_media_streams(path: Path) -> dict[str, Any] | None:
    """Return the ffprobe ``streams``/``format`` payload, or None on failure."""
    if not ffprobe_available():
        return None
    try:
        out = subprocess.check_output(
            [
                "ffprobe",
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                "-show_streams",
                str(path),
            ],
            stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    try:
        info = json.loads(out.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    return info if isinstance(info, dict) else None


def audio_streams(path: Path) -> list[dict[str, Any]]:
    """Audio streams in the container, with forensic-relevant fields."""
    info = probe_media_streams(path)
    streams = (info or {}).get("streams") or []
    rows: list[dict[str, Any]] = []
    for st in streams:
        if not isinstance(st, dict) or st.get("codec_type") != "audio":
            continue
        rows.append(
            {
                "index": st.get("index"),
                "codec_name": st.get("codec_name") or "",
                "codec_long_name": st.get("codec_long_name") or "",
                "channels": st.get("channels"),
                "channel_layout": st.get("channel_layout") or "",
                "sample_rate": st.get("sample_rate"),
                "duration_seconds": _float_or_none(st.get("duration")),
                "bit_rate": st.get("bit_rate"),
            }
        )
    return rows


def has_audio(path: Path) -> bool:
    """True when the container carries at least one audio stream.

    Presence of the stream is reported even if the track is silent —
    silence detection is a decode-level question and stays out of scope
    here so the probe stays cheap.
    """
    return bool(audio_streams(path))


def extract_audio_wav(
    src: Path,
    dst: Path,
    *,
    sample_rate: int = 16000,
    timeout_s: int = 600,
) -> bool:
    """Decode the first audio stream to 16 kHz mono PCM WAV for STT.

    Returns False when ffmpeg is missing, the file has no audio stream,
    or decoding fails; callers record the failure rather than guessing.
    """
    if not ffmpeg_available():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-v",
                "error",
                "-i",
                str(src),
                "-vn",
                "-map",
                "a:0",
                "-ac",
                "1",
                "-ar",
                str(sample_rate),
                "-c:a",
                "pcm_s16le",
                str(dst),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return dst.is_file() and dst.stat().st_size > 44


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
