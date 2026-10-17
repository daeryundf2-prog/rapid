"""Fixtures of ``rapidtriage.core.triage_rules.media`` (see ``tests.triage_cases``)."""

from __future__ import annotations

PICTURES = "C:\\Users\\analyst\\Pictures"


def image(name: str = "IMG_0001.JPG", folder: str = PICTURES, **details: object) -> dict[str, object]:
    path = f"{folder}\\{name}"
    return {
        "kind": "media-image",
        "row": {
            "artifact_type": "media-image",
            "path": path,
            "details": {"source_path": path, "content_format": "jpeg", **details},
        },
    }


def camera(name: str = "IMG_0001.JPG", folder: str = PICTURES, **details: object) -> dict[str, object]:
    """A phone-camera JPEG with Make/Model and a capture time."""
    base = {"exif_make": "ExampleCam", "exif_model": "Model X1", "exif_datetime_original": "2024:03:01 10:00:00"}
    return image(name, folder, **{**base, **details})


def listed(path: str) -> dict[str, object]:
    return {"files": "inventory", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


CASES = {
    "media.exif_vs_fs_time": {
        # Captured 2024-03-01 10:00 KST (01:00Z) but the file was last modified three months later.
        "positive": {"rows": [camera(source_file_mtime="2024-06-01T00:00:00Z")], "flagged": [0]},
        # Saved by the camera a few minutes after capture (offset known): same instant within the tolerance.
        "negative": {
            "rows": [camera(exif_offset_time_original="+09:00", source_file_mtime="2024-03-01T01:05:00Z")],
            "flagged": [],
        },
    },
    "media.exif_future_or_pre_device": {
        "positive": {
            "rows": [
                # Captured ten days after the file was last written.
                camera(exif_datetime_original="2024:06:10 12:00:00", source_file_mtime="2024-06-01T00:00:00Z"),
                # Capture year before digital-camera era (clock reset / fabricated).
                camera("IMG_0002.JPG", exif_datetime_original="1980:01:01 00:00:00"),
            ],
            "flagged": [0, 1],
        },
        # Written to the card two hours after capture: normal.
        "negative": {"rows": [camera(source_file_mtime="2024-03-01T03:00:00Z")], "flagged": []},
    },
    "media.gps_present": {
        "positive": {"rows": [camera(gps_latitude=37.5665, gps_longitude=126.9780)], "flagged": [0]},
        # 0/0 placeholder written by apps without a fix is not a location.
        "negative": {"rows": [camera(gps_latitude=0, gps_longitude=0)], "flagged": []},
    },
    "media.gps_time_tz_inconsistent": {
        "positive": {
            "rows": [
                # Offset known: 10:00+09:00 = 01:00Z, but GPS says 03:00Z.
                camera(exif_offset_time_original="+09:00", gps_timestamp="2024-03-01T03:00:00Z"),
                # No offset: 9 h 7 min apart is not a whole-quarter-hour zone.
                camera("IMG_0002.JPG", gps_timestamp="2024-03-01T00:53:00Z"),
            ],
            "flagged": [0, 1],
        },
        "negative": {
            "rows": [
                # GPS fix 30 s after the shutter (camera clock drift within tolerance).
                camera(exif_offset_time_original="+09:00", gps_timestamp="2024-03-01T01:00:30Z"),
                # No offset tag: a plain UTC+9 difference.
                camera("IMG_0002.JPG", gps_timestamp="2024-03-01T01:00:20Z"),
            ],
            "flagged": [],
        },
    },
    "media.editing_software": {
        "positive": {"rows": [camera(exif_software="Adobe Photoshop 25.0 (Windows)")], "flagged": [0]},
        # Camera firmware / a viewer re-save is not an editor.
        "negative": {
            "rows": [camera(exif_software="Firmware Ver.1.02"), camera("IMG_0002.JPG", exif_software="Microsoft Windows Photo Viewer 6.1")],
            "flagged": [],
        },
    },
    "media.exif_stripped": {
        # A JPEG received through a messenger: no Make/Model/DateTimeOriginal.
        "positive": {"rows": [image("KakaoTalk_20240301_101500123.jpg")], "flagged": [0]},
        # A PNG screenshot never carried EXIF; a camera JPEG keeps it.
        "negative": {
            "rows": [image("Screenshot_20240301-101500.png", content_format="png"), camera()],
            "flagged": [],
        },
    },
    "media.phash_dup_cross_folder": {
        "positive": {
            "rows": [
                camera(perceptual_hash="c3a5f00f1e2d3c4b", width=1920, height=1080),
                camera("backup_01.jpg", "C:\\Users\\analyst\\Documents\\old", perceptual_hash="c3a5f00f1e2d3c48", width=1920, height=1080),
            ],
            "flagged": [0, 1],
        },
        "negative": {
            "rows": [
                # Burst shots in the same folder.
                camera(perceptual_hash="c3a5f00f1e2d3c4b", width=1920, height=1080),
                camera("IMG_0002.JPG", perceptual_hash="c3a5f00f1e2d3c4a", width=1920, height=1080),
                # A small cached thumbnail elsewhere (below min_pixels).
                camera("thumb_0001.jpg", "C:\\Users\\analyst\\AppData\\Local\\Thumbs", perceptual_hash="c3a5f00f1e2d3c4b", width=160, height=90),
            ],
            "flagged": [],
        },
    },
    "media.thumb_mismatch": {
        "positive": {"rows": [camera(perceptual_hash="f0f0f0f0f0f0f0f0", thumbnail_perceptual_hash="0f0f0f0f0f0f0f0f")], "flagged": [0]},
        # Thumbnail re-scaled by the camera: a few bits off only.
        "negative": {"rows": [camera(perceptual_hash="f0f0f0f0f0f0f0f0", thumbnail_perceptual_hash="f0f0f0f0f0f0f0f3")], "flagged": []},
    },
    "media.screenshot_flag": {
        "positive": {
            "rows": [
                image("Screenshot_20240301-101500.png", content_format="png"),
                image("export.png", content_format="png", width=1170, height=2532),
            ],
            "flagged": [0, 1],
        },
        # A camera photo with Make/Model, even at a screen-like resolution.
        "negative": {"rows": [camera(width=1920, height=1080), camera("IMG_0002.JPG", width=4032, height=3024)], "flagged": []},
    },
    "media.live_photo_orphan": {
        "positive": {
            "rows": [
                camera("IMG_0101.HEIC", content_format="heic"),
                listed(f"{PICTURES}\\IMG_0101.HEIC"),
                listed(f"{PICTURES}\\IMG_0102.HEIC"),
                listed(f"{PICTURES}\\IMG_0102.MOV"),
            ],
            "flagged": [0],
        },
        # The Live Photo pair is complete.
        "negative": {
            "rows": [
                camera("IMG_0102.HEIC", content_format="heic"),
                listed(f"{PICTURES}\\IMG_0102.HEIC"),
                listed(f"{PICTURES}\\IMG_0102.MOV"),
            ],
            "flagged": [],
        },
    },
    "media.metadata_conflict": {
        "positive": {
            "rows": [camera(exif_datetime_digitized="2024:03:01 10:00:00", xmp_create_date="2024-03-05T14:00:00")],
            "flagged": [0],
        },
        # MWG-style tool: XMP CreateDate carries the same local time with its zone.
        "negative": {
            "rows": [camera(exif_datetime_digitized="2024:03:01 10:00:00", xmp_create_date="2024-03-01T10:00:00+09:00")],
            "flagged": [],
        },
    },
}
