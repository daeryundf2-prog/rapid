"""Media explorer index (plan r4 §2.2 V2): pHash neighbours and EXIF groups of the run's images.

``GET /api/runs/{id}/media/similar`` and ``/media/groups`` read one index of
the ``media-image`` artifact rows: per image its row (``record_index``),
path, 64-bit perceptual hash (``details.perceptual_hash``, 16 hex digits),
SHA-256, EXIF camera (``exif_make`` + ``exif_model``) and capture time
(``exif_datetime_original``, else the row's ``timestamp``).

* **Similar.** Hamming distance of the pHashes, ``0 <= max_distance <=
  MEDIA_SIMILAR_MAX_DISTANCE`` (default 8, the same "pHash 거리 ≤ 8" rule the
  관련 미디어 panel uses). The reference image is excluded; an image with the
  same SHA-256 is ``same_hash`` (distance 0 by construction). Sorted by
  distance, then path; at most ``limit`` items.
* **Groups.** ``by=camera`` (make + model; ``""`` = no EXIF camera) or
  ``by=date`` (capture day ``YYYY-MM-DD``; ``""`` = no capture time) with
  counts; ``key=`` returns that group's paths (bounded).
* **Bounds / cache.** At most ``MEDIA_INDEX_MAX_ROWS`` rows are indexed
  (``truncated`` past that); one index per run output signature.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

from ...core.jobs import RunJobStore
from .index_cache import SingleFlightIndexCache
from .jsonl_records import iter_artifact_records, jsonl_records_path
from .tree import _file_signature

MEDIA_KIND = "media-image"
MEDIA_INDEX_MAX_ROWS = 500_000
MEDIA_INDEX_CACHE_RUNS = 4
MEDIA_SIMILAR_DEFAULT_DISTANCE = 8
MEDIA_SIMILAR_MAX_DISTANCE = 16
MEDIA_SIMILAR_DEFAULT_LIMIT = 100
MEDIA_SIMILAR_MAX_LIMIT = 500
MEDIA_GROUP_MAX_PATHS = 2000
MEDIA_GROUP_SAMPLE_PATHS = 3
NO_CAMERA_LABEL = "카메라 정보 없음"
NO_DATE_LABEL = "촬영일 없음"
NO_MEDIA_REASON = "이 런에는 이미지 아티팩트(media-image) 출력이 없습니다"


def path_key(value: str) -> str:
    return value.replace("\\", "/").casefold()


@dataclass(frozen=True)
class MediaEntry:
    record_index: int
    path: str
    artifact_type: str
    phash: int | None
    sha256: str
    camera: str
    captured_at: str


@dataclass
class MediaIndex:
    key: tuple[object, ...]
    entries: list[MediaEntry] = field(default_factory=list)
    by_path: dict[str, int] = field(default_factory=dict)
    rows: int = 0
    with_phash: int = 0
    truncated: bool = False

    def info(self) -> dict[str, object]:
        info: dict[str, object] = {"rows": self.rows, "indexed": len(self.entries), "with_phash": self.with_phash, "truncated": self.truncated}
        if self.truncated:
            info["reason"] = f"이미지 행이 {MEDIA_INDEX_MAX_ROWS:,}개를 넘어 앞부분만 색인했습니다"
        return info


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def parse_phash(value: object) -> int | None:
    text = _text(value).lower()
    if len(text) != 16:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def build_media_index(key: tuple[object, ...], payload: Mapping[str, object], payload_path: Path) -> MediaIndex:
    index = MediaIndex(key=key)
    for record_index, row in iter_artifact_records(payload, payload_path=payload_path):
        index.rows += 1
        if len(index.entries) >= MEDIA_INDEX_MAX_ROWS:
            index.truncated = True
            continue
        details = row.get("details")
        details = details if isinstance(details, Mapping) else {}
        artifact_type = str(row.get("artifact_type") or "")
        if not artifact_type.startswith("media-image"):
            continue
        path = _text(row.get("path")) or _text(details.get("source_path"))
        if not path:
            continue
        hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
        camera = " ".join(part for part in (_text(details.get("exif_make")), _text(details.get("exif_model"))) if part)
        captured = _text(details.get("exif_datetime_original")) or _text(details.get("timestamp"))
        phash = parse_phash(details.get("perceptual_hash"))
        entry = MediaEntry(
            record_index=record_index,
            path=path,
            artifact_type=artifact_type,
            phash=phash,
            sha256=_text(hashes.get("sha256")).lower(),
            camera=camera,
            captured_at=captured,
        )
        index.by_path.setdefault(path_key(path), len(index.entries))
        index.entries.append(entry)
        if phash is not None:
            index.with_phash += 1
    return index


class MediaIndexCache(SingleFlightIndexCache[MediaIndex]):
    """Per-run LRU of :class:`MediaIndex`; built single-flight per key, never under the cache-wide lock."""

    def __init__(self, max_runs: int = MEDIA_INDEX_CACHE_RUNS) -> None:
        super().__init__(max_runs)

    def get(self, key: tuple[object, ...], payload: Mapping[str, object], payload_path: Path) -> MediaIndex:
        return self.get_or_build(key, lambda: build_media_index(key, payload, payload_path))


MEDIA_INDEX_CACHE = MediaIndexCache()


def clear_media_index_cache() -> None:
    MEDIA_INDEX_CACHE.clear()


def load_media_index(store: RunJobStore, run_id: str) -> MediaIndex:
    name = f"artifacts_{MEDIA_KIND}"
    try:
        path = store.output_path(run_id, name)
        payload = store.read_output(run_id, name)
    except (KeyError, FileNotFoundError):
        raise HTTPException(status_code=404, detail=NO_MEDIA_REASON) from None
    except (RuntimeError, PermissionError, OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=f"이미지 아티팩트 출력을 읽을 수 없습니다: {exc}") from None
    if not isinstance(payload, Mapping):
        raise HTTPException(status_code=409, detail="이미지 아티팩트 출력 형식이 올바르지 않습니다")
    key = (run_id, *_file_signature(path), *_file_signature(jsonl_records_path(payload, path)))
    return MEDIA_INDEX_CACHE.get(key, payload, path)


def _bounded_int(value: str | None, name: str, *, default: int, low: int, high: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        number = int(value.strip())
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{name}은(는) {low}~{high} 사이의 정수여야 합니다") from None
    if not low <= number <= high:
        raise HTTPException(status_code=422, detail=f"{name}은(는) {low}~{high} 사이의 정수여야 합니다")
    return number


def parse_distance(value: str | None) -> int:
    return _bounded_int(value, "max_distance", default=MEDIA_SIMILAR_DEFAULT_DISTANCE, low=0, high=MEDIA_SIMILAR_MAX_DISTANCE)


def parse_media_limit(value: str | None) -> int:
    return _bounded_int(value, "limit", default=MEDIA_SIMILAR_DEFAULT_LIMIT, low=1, high=MEDIA_SIMILAR_MAX_LIMIT)


def require_ref(index: MediaIndex, ref: str | None) -> MediaEntry:
    text = (ref or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="ref(기준 이미지 경로)를 지정하세요")
    if len(text) > 4096 or any(ord(char) < 0x20 for char in text):
        raise HTTPException(status_code=422, detail="ref(기준 이미지 경로)가 올바르지 않습니다")
    position = index.by_path.get(path_key(text))
    if position is None:
        raise HTTPException(status_code=404, detail="기준 이미지가 이미지 아티팩트 목록에 없습니다")
    entry = index.entries[position]
    if entry.phash is None:
        raise HTTPException(status_code=409, detail="기준 이미지에 pHash(지각 해시)가 없어 유사 사진을 찾을 수 없습니다")
    return entry


def _item(entry: MediaEntry, distance: int, ref: MediaEntry) -> dict[str, object]:
    return {
        "path": entry.path,
        "name": entry.path.replace("\\", "/").rsplit("/", 1)[-1],
        "kind": MEDIA_KIND,
        "record_index": entry.record_index,
        "locator": f"/artifacts/{entry.record_index}",
        "distance": distance,
        "same_hash": bool(ref.sha256 and entry.sha256 == ref.sha256),
        "sha256": entry.sha256 or None,
        "camera": entry.camera or None,
        "captured_at": entry.captured_at or None,
    }


def similar_media(index: MediaIndex, ref: MediaEntry, *, max_distance: int, limit: int) -> dict[str, object]:
    matches: list[tuple[int, str, MediaEntry]] = []
    same_hash = 0
    ref_key = path_key(ref.path)
    assert ref.phash is not None
    for entry in index.entries:
        if entry.phash is None or path_key(entry.path) == ref_key:
            continue
        distance = (entry.phash ^ ref.phash).bit_count()
        if ref.sha256 and entry.sha256 == ref.sha256:
            same_hash += 1
        if distance <= max_distance:
            matches.append((distance, path_key(entry.path), entry))
    matches.sort(key=lambda item: (item[0], item[1]))
    items = [_item(entry, distance, ref) for distance, _key, entry in matches[:limit]]
    near = sum(1 for _distance, _key, entry in matches if not (ref.sha256 and entry.sha256 == ref.sha256))
    return {
        "ref": {
            "path": ref.path,
            "record_index": ref.record_index,
            "perceptual_hash": f"{ref.phash:016x}",
            "sha256": ref.sha256 or None,
        },
        "max_distance": max_distance,
        "limit": limit,
        "items": items,
        "counts": {
            "indexed": len(index.entries),
            "with_phash": index.with_phash,
            "same_hash": same_hash,
            "near": near,
            "matched": len(matches),
            "returned": len(items),
        },
        "index": index.info(),
    }


def parse_group_by(value: str | None) -> str:
    text = (value or "").strip()
    if text not in ("camera", "date"):
        raise HTTPException(status_code=422, detail="by는 camera(카메라) 또는 date(촬영일)여야 합니다")
    return text


def _group_key(entry: MediaEntry, by: str) -> str:
    if by == "camera":
        return entry.camera
    text = entry.captured_at.replace(":", "-", 2) if len(entry.captured_at) >= 10 and entry.captured_at[4] == ":" else entry.captured_at
    return text[:10] if len(text) >= 10 else ""


def media_groups(index: MediaIndex, by: str, key: str | None) -> dict[str, object]:
    buckets: dict[str, list[MediaEntry]] = {}
    for entry in index.entries:
        buckets.setdefault(_group_key(entry, by), []).append(entry)
    empty_label = NO_CAMERA_LABEL if by == "camera" else NO_DATE_LABEL

    def describe(group_key: str, members: list[MediaEntry]) -> dict[str, object]:
        return {
            "key": group_key,
            "label": group_key or empty_label,
            "count": len(members),
            "sample_paths": [member.path for member in members[:MEDIA_GROUP_SAMPLE_PATHS]],
        }

    # Named groups by count (desc) then label; the empty group last.
    ordered = sorted(((k, v) for k, v in buckets.items() if k), key=lambda item: (-len(item[1]), item[0].casefold()))
    if by == "date":
        ordered = sorted(((k, v) for k, v in buckets.items() if k), key=lambda item: item[0], reverse=True)
    if "" in buckets:
        ordered.append(("", buckets[""]))
    payload: dict[str, object] = {
        "by": by,
        "groups": [describe(group_key, members) for group_key, members in ordered],
        "index": index.info(),
    }
    if key is not None:
        members = buckets.get(key.strip())
        if members is None:
            raise HTTPException(status_code=404, detail="그룹을 찾을 수 없습니다: " + key.strip()[:200])
        payload["key"] = key.strip()
        payload["paths"] = [member.path for member in members[:MEDIA_GROUP_MAX_PATHS]]
        payload["records"] = [member.record_index for member in members[:MEDIA_GROUP_MAX_PATHS]]
        payload["path_total"] = len(members)
        payload["paths_truncated"] = len(members) > MEDIA_GROUP_MAX_PATHS
    return payload
