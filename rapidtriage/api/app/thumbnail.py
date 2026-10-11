"""Cached JPEG thumbnails for evidence images (console thumbnail view, plan §9 X6/X16).

The thumbnail is a derived preview only: it is written under the run's output
directory (``<output_dir>/thumbs``), never next to the evidence, and the
original stays the reference for any reportable finding.
"""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import warnings
from pathlib import Path

from fastapi import HTTPException

THUMBNAIL_DEFAULT_SIZE = 160
THUMBNAIL_MAX_SIZE = 512
THUMBNAIL_MAX_SOURCE_BYTES = 64 * 1024 * 1024
# Decoded-pixel ceiling (decompression-bomb guard); tighter than Pillow's default.
THUMBNAIL_MAX_PIXELS = 64_000_000
THUMBNAIL_JPEG_QUALITY = 82
THUMBNAIL_CACHE_DIRNAME = "thumbs"


def thumbnail_cache_path(output_dir: Path, source_path: Path, size: int) -> Path:
    digest = hashlib.sha256(str(source_path).encode("utf-8", errors="replace")).hexdigest()
    return output_dir / THUMBNAIL_CACHE_DIRNAME / f"{digest}-{size}.jpg"


def _cache_is_fresh(cache_path: Path, source_path: Path) -> bool:
    try:
        return cache_path.is_file() and cache_path.stat().st_mtime >= source_path.stat().st_mtime
    except OSError:
        return False


def render_thumbnail_jpeg(source_path: Path, size: int) -> bytes:
    """Decode ``source_path`` with Pillow and return a JPEG no larger than ``size`` px on either side."""
    try:
        from PIL import Image, ImageOps, UnidentifiedImageError
    except ModuleNotFoundError as exc:  # Pillow is optional for the server
        raise HTTPException(status_code=503, detail="thumbnail support requires Pillow") from exc

    try:
        source_bytes = source_path.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=404, detail="source file is not readable") from exc
    if source_bytes > THUMBNAIL_MAX_SOURCE_BYTES:
        raise HTTPException(status_code=413, detail="source image is too large for a thumbnail")

    limit = THUMBNAIL_MAX_PIXELS
    if Image.MAX_IMAGE_PIXELS:
        limit = min(limit, int(Image.MAX_IMAGE_PIXELS))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(source_path) as image:
                width, height = image.size
                if width * height > limit:
                    raise HTTPException(status_code=413, detail="source image has too many pixels for a thumbnail")
                if image.format == "JPEG":
                    image.draft("RGB", (size, size))
                image.load()
                frame = ImageOps.exif_transpose(image) or image
                frame.thumbnail((size, size))
                if frame.mode in ("RGBA", "LA", "P"):
                    rgba = frame.convert("RGBA")
                    canvas = Image.new("RGB", rgba.size, (255, 255, 255))
                    canvas.paste(rgba, mask=rgba.getchannel("A"))
                    frame = canvas
                elif frame.mode != "RGB":
                    frame = frame.convert("RGB")
                out = io.BytesIO()
                frame.save(out, format="JPEG", quality=THUMBNAIL_JPEG_QUALITY, optimize=True)
                return out.getvalue()
    except HTTPException:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise HTTPException(status_code=413, detail="source image has too many pixels for a thumbnail") from exc
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise HTTPException(status_code=415, detail="source file could not be decoded as an image") from exc


def cached_thumbnail(source_path: Path, size: int, output_dir: Path | None) -> tuple[Path | None, bytes | None]:
    """Return ``(cache_path, None)`` for a cached thumbnail, or ``(None, jpeg)`` when no cache dir is usable."""
    if output_dir is not None and output_dir.is_dir():
        cache_path = thumbnail_cache_path(output_dir, source_path, size)
        if _cache_is_fresh(cache_path, source_path):
            return cache_path, None
        data = render_thumbnail_jpeg(source_path, size)
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(dir=cache_path.parent, suffix=".tmp")
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(temp_name, cache_path)
            return cache_path, None
        except OSError:
            return None, data
    return None, render_thumbnail_jpeg(source_path, size)
