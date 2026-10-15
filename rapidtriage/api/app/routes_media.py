"""Run source-file preview and viewer API routes."""

from __future__ import annotations

import mimetypes
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import (
    FileResponse,
    Response,
)

from ...core.jobs import RunJobStore
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from .analyses import AnalysisRowRef, analysis_row_ref
from .constants import (
    HEX_RANGE_EXPORT_MAX_BYTES,
    IMAGE_GALLERY_DEFAULT_LIMIT,
    IMAGE_GALLERY_MAX_ITEMS,
    SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
    SQLITE_TABLE_PAGE_MAX_ROWS,
)
from .email import (
    build_email_attachment_package,
)
from .helpers import (
    get_job,
    is_image_preview_candidate,
    is_sqlite_candidate,
    parse_source_preview_archive_request,
    resolve_allowed_source_file,
)
from .hex import (
    build_hex_range_citation_package,
)
from .image import (
    build_image_gallery_page,
    build_source_ocr_queue,
    build_source_ocr_translation_package,
)
from .media import (
    build_media_cue_package,
)
from .runops import (
    build_archived_source_api_preview,
    build_directory_metadata,
    build_directory_preview,
    build_source_metadata,
    build_source_preview,
)
from .sqlite import (
    build_sqlite_table_page,
)
from .thumbnail import THUMBNAIL_DEFAULT_SIZE, THUMBNAIL_MAX_SIZE, cached_thumbnail

THUMBNAIL_CACHE_CONTROL = "private, max-age=86400"


def stored_ocr_sidecar(store: RunJobStore, run_id: str, source_path: Path) -> dict[str, object] | None:
    """The newest ``ocr-batch`` analysis result for ``source_path`` as an OCR sidecar, or ``None``."""
    from .analysis_kinds import find_ocr_result

    summary = get_job(store, run_id).summary or {}
    output_value = summary.get("output_dir")
    if not isinstance(output_value, str) or not output_value:
        return None
    found = find_ocr_result(Path(output_value).expanduser().resolve(), source_path)
    if found is None or found.get("status") == "failed":
        return None
    return {
        "text": str(found.get("text") or ""),
        "text_length": found.get("text_length"),
        "language_hint": found.get("language"),
        "confidence": found.get("confidence"),
        "status": found.get("status"),
        "source": "analysis",
        "analysis_id": found.get("analysis_id"),
        "source_path": str(source_path),
    }


def build_media_router(
    store: RunJobStore,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/runs/{run_id}/source-file")
    def download_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
    ) -> FileResponse:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        return FileResponse(source_path, filename=source_path.name)


    @router.get("/api/runs/{run_id}/source-thumbnail")
    def source_thumbnail(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        size: int = Query(THUMBNAIL_DEFAULT_SIZE, ge=16, le=THUMBNAIL_MAX_SIZE),
    ) -> Response:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=415, detail="source file is not a supported image")
        summary = get_job(store, run_id).summary or {}
        output_value = summary.get("output_dir")
        output_dir = Path(output_value) if isinstance(output_value, str) and output_value else None
        cache_path, data = cached_thumbnail(source_path, size, output_dir)
        headers = {"Cache-Control": THUMBNAIL_CACHE_CONTROL}
        if cache_path is not None:
            return FileResponse(cache_path, media_type="image/jpeg", headers=headers)
        return Response(content=data or b"", media_type="image/jpeg", headers=headers)


    @router.get("/api/runs/{run_id}/source-preview")
    def preview_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
    ) -> dict[str, object]:
        archive_request = parse_source_preview_archive_request(path)
        if archive_request:
            source_path = resolve_allowed_source_file(store, run_id, archive_request["archive_path"], **row_ref)
            return build_archived_source_api_preview(run_id, source_path, archive_request["entry_name"])
        source_path = resolve_allowed_source_file(store, run_id, path, allow_directory=True, **row_ref)
        if source_path.is_dir():
            return build_directory_preview(run_id, source_path)
        payload = build_source_preview(run_id, source_path)
        image = payload.get("image")
        if isinstance(image, dict) and not (image.get("ocr_sidecar") or {}).get("text"):
            stored = stored_ocr_sidecar(store, run_id, source_path)
            if stored is not None:
                # Reuse the OCR-batch analysis result instead of re-running OCR.
                image["ocr_sidecar"] = stored
        return payload


    @router.get("/api/runs/{run_id}/source-hex-range")
    def source_hex_range(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        offset: int = Query(0, ge=0),
        length: int = Query(256, ge=1, le=HEX_RANGE_EXPORT_MAX_BYTES),
        include_hashes: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        return build_hex_range_citation_package(
            run_id=run_id,
            source_path=source_path,
            offset=offset,
            length=length,
            include_source_hashes=include_hashes,
        )


    @router.get("/api/runs/{run_id}/source-sqlite-table")
    def source_sqlite_table(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        table: str = Query(..., min_length=1),
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=SQLITE_TABLE_PAGE_MAX_ROWS),
        where_column: str | None = Query(default=None, min_length=1),
        where_contains: str | None = Query(default=None, min_length=1),
        order_by: str | None = Query(default=None, min_length=1),
        descending: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_sqlite_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported SQLite database")
        return build_sqlite_table_page(
            run_id=run_id,
            source_path=source_path,
            table=table,
            offset=offset,
            limit=limit,
            where_column=where_column,
            where_contains=where_contains,
            order_by=order_by,
            descending=descending,
        )


    @router.get("/api/runs/{run_id}/source-sqlite-wal-preview")
    def source_sqlite_wal_preview(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        max_frames: int = Query(20, ge=1, le=100),
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_sqlite_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported SQLite database")
        try:
            payload = build_sqlite_wal_preview(database_path=source_path, output_dir=None, max_frames=max_frames)
        except (SqliteWalPreviewError, OSError, sqlite3.DatabaseError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        payload["api_profile"] = {
            "profile_version": "source-sqlite-wal-preview-api-v1",
            "gui_binding": "sqlite-sidecar-preview",
            "source_path": str(source_path),
            "max_frames": max_frames,
            "reportability_warning": (
                "WAL preview rows are recovery leads; validate with a trusted SQLite recovery tool before reporting."
            ),
        }
        return payload


    @router.get("/api/runs/{run_id}/source-email-attachment")
    def source_email_attachment(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        message_index: int = Query(1, ge=1),
        attachment_index: int = Query(1, ge=1),
        include_content: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        suffix = source_path.suffix.lower()
        if suffix not in {".eml", ".mbox"}:
            raise HTTPException(status_code=400, detail="source file is not a supported EML/MBOX email preview")
        return build_email_attachment_package(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            message_index=message_index,
            attachment_index=attachment_index,
            include_content=include_content,
        )


    @router.get("/api/runs/{run_id}/source-image-gallery")
    def source_image_gallery(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        offset: int = Query(0, ge=0),
        limit: int = Query(IMAGE_GALLERY_DEFAULT_LIMIT, ge=1, le=IMAGE_GALLERY_MAX_ITEMS),
        similarity_bucket: str | None = Query(default=None, min_length=1),
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        return build_image_gallery_page(
            run_id=run_id,
            anchor_path=source_path,
            offset=offset,
            limit=limit,
            similarity_bucket=similarity_bucket,
        )


    @router.get("/api/runs/{run_id}/source-media-cue")
    def source_media_cue(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        sidecar_index: int = Query(1, ge=1),
        cue_index: int = Query(1, ge=1),
        include_source_hashes: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        mime_type = mimetypes.guess_type(source_path.name)[0] or ""
        if not mime_type.startswith(("audio/", "video/")):
            raise HTTPException(status_code=400, detail="source file is not a supported audio/video preview")
        return build_media_cue_package(
            run_id=run_id,
            source_path=source_path,
            sidecar_index=sidecar_index,
            cue_index=cue_index,
            include_source_hashes=include_source_hashes,
        )


    @router.get("/api/runs/{run_id}/source-ocr-queue")
    def source_ocr_queue(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        max_items: int = Query(SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS, ge=1, le=1000),
        retry_failures: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        return build_source_ocr_queue(
            run_id=run_id,
            anchor_path=source_path,
            max_items=max_items,
            retry_failures=retry_failures,
        )


    @router.get("/api/runs/{run_id}/source-ocr-translation")
    def source_ocr_translation(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        include_text: bool = True,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        package = build_source_ocr_translation_package(
            run_id=run_id,
            source_path=source_path,
            include_text=include_text,
        )
        package["analysis_ocr"] = stored_ocr_sidecar(store, run_id, source_path)
        return package


    @router.get("/api/runs/{run_id}/source-metadata")
    def source_metadata(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        hash: bool = False,
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path, allow_directory=True, **row_ref)
        if source_path.is_dir():
            return build_directory_metadata(source_path)
        return build_source_metadata(source_path, include_hashes=hash)

    return router
