from __future__ import annotations

import json
import mimetypes
import re
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..core.audit import audit_path_for, write_audit_record
from ..core.case import CaseBookmarkError, create_or_update_case_payload, load_case_payload, save_case_payload
from ..core.case_report import build_case_report_markdown
from ..core.docs import SUPPORTED_DOC_EXTS, extract_text
from ..core.jobs import RunJobStore, RunRequest, default_job_store, is_relative_to, run_output_dir
from ..core.search import SearchError, run_unified_search
from ..core.submission import build_submission_manifest


class RunCreateRequest(BaseModel):
    root: str = Field(..., min_length=1)
    mode: str = Field(..., min_length=1)
    output_dir: Optional[str] = None
    input_kind: Optional[str] = None
    rules: Optional[str] = None
    dry_run: bool = False
    read_only: bool = False
    max_extract_size_bytes: int = 0
    max_file_count: int = 0
    overwrite: bool = False
    wait: bool = False


class RunImportRequest(BaseModel):
    output_dir: str = Field(..., min_length=1)


class BookmarkCreateRequest(BaseModel):
    source: str = Field(..., min_length=1)
    pointer: str = Field(..., min_length=1)
    bookmark_id: Optional[str] = None
    tag: Optional[str] = None
    tags: Optional[list[str]] = None
    note: Optional[str] = None
    case_id: Optional[str] = None
    title: Optional[str] = None
    review_status: Optional[str] = None
    include_in_report: Optional[bool] = None


class CaseReportCreateRequest(BaseModel):
    title: Optional[str] = None
    case_number: Optional[str] = None
    investigator: Optional[str] = None
    organization: Optional[str] = None
    requester: Optional[str] = None
    scope: Optional[str] = None
    conclusion: Optional[str] = None
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


def create_app(job_store: RunJobStore | None = None) -> FastAPI:
    store = job_store or default_job_store
    api = FastAPI(title="rapidtriage local API", version="0.2.0")
    static_dir = Path(__file__).resolve().parent.parent / "web" / "static"

    @api.get("/api/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @api.post("/api/runs", status_code=202)
    def create_run(request: RunCreateRequest) -> Dict[str, Any]:
        run_request = RunRequest(
            root=request.root,
            mode=request.mode,
            output_dir=request.output_dir,
            input_kind=request.input_kind,
            rules=request.rules,
            dry_run=request.dry_run,
            read_only=request.read_only,
            max_extract_size_bytes=request.max_extract_size_bytes,
            max_file_count=request.max_file_count,
            overwrite=request.overwrite,
        )
        job = store.run_sync(run_request) if request.wait else store.submit(run_request)
        return job.to_dict(include_summary=request.wait)

    @api.post("/api/runs/import", status_code=201)
    def import_run(request: RunImportRequest) -> Dict[str, Any]:
        try:
            job = store.import_completed_run(request.output_dir)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return job.to_dict(include_summary=True)

    @api.get("/api/runs")
    def list_runs() -> Dict[str, Any]:
        return {"runs": [job.to_dict() for job in store.list()]}

    @api.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> Dict[str, Any]:
        return get_job_payload(store, run_id, include_summary=True)

    @api.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> None:
        try:
            store.remove(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")

    @api.get("/api/runs/{run_id}/summary")
    def get_run_summary(run_id: str) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return job.summary

    @api.get("/api/runs/{run_id}/outputs/{output_name}")
    def get_run_output(run_id: str, output_name: str) -> Dict[str, object]:
        try:
            return store.read_output(run_id, output_name)
        except KeyError:
            raise HTTPException(status_code=404, detail="run output not found")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @api.get("/api/runs/{run_id}/output-files")
    def get_run_output_files(run_id: str) -> Dict[str, object]:
        try:
            return {"files": store.output_files(run_id)}
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    @api.get("/api/runs/{run_id}/outputs/{output_name}/file")
    def download_run_output(run_id: str, output_name: str) -> FileResponse:
        path = get_output_path(store, run_id, output_name)
        return FileResponse(path, filename=path.name)

    @api.get("/api/runs/{run_id}/source-file")
    def download_source_file(run_id: str, path: str = Query(..., min_length=1)) -> FileResponse:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return FileResponse(source_path, filename=source_path.name)

    @api.get("/api/runs/{run_id}/source-preview")
    def preview_source_file(run_id: str, path: str = Query(..., min_length=1)) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_preview(run_id, source_path)

    @api.get("/api/runs/{run_id}/source-search")
    def search_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(100, ge=1, le=500),
        context: int = Query(120, ge=20, le=500),
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_search(source_path, keyword, limit=limit, context=context)

    @api.get("/api/runs/{run_id}/timeline")
    def get_run_timeline(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit)

    @api.get("/api/runs/{run_id}/artifacts")
    def get_run_artifacts(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, dict):
            raise HTTPException(status_code=409, detail="run has no outputs")
        artifacts = {}
        for name in sorted(outputs):
            if name.startswith("artifacts_"):
                try:
                    artifact_payload = store.read_output(run_id, name)
                    artifacts[name.removeprefix("artifacts_")] = paginate_payload(
                        artifact_payload,
                        "artifacts",
                        offset=offset,
                        limit=limit,
                    )
                except RuntimeError as exc:
                    raise HTTPException(status_code=409, detail=str(exc))
                except PermissionError as exc:
                    raise HTTPException(status_code=403, detail=str(exc))
                except FileNotFoundError as exc:
                    raise HTTPException(status_code=404, detail=str(exc))
        return {"artifacts": artifacts}

    @api.get("/api/runs/{run_id}/files")
    def get_run_files(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "files")
        return paginate_payload(payload, "candidates", offset=offset, limit=limit)

    @api.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "docs")
        return paginate_payload(payload, "results", offset=offset, limit=limit, omit_fields=("candidates", "manifest"))

    @api.get("/api/runs/{run_id}/search")
    def search_run(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        ocr: bool = True,
        limit: int = Query(500, ge=1, le=1000),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            return run_unified_search(job.summary, keyword, include_ocr=ocr, limit=limit)
        except SearchError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_run_report(run_id: str) -> str:
        path = get_output_path(store, run_id, "report")
        return path.read_text(encoding="utf-8")

    @api.get("/api/runs/{run_id}/case")
    def get_run_case(run_id: str) -> Dict[str, object]:
        case_path = default_case_path(store, run_id)
        if not case_path.is_file():
            return {"exists": False, "case_path": str(case_path), "case": None}
        try:
            return {"exists": True, "case_path": str(case_path), "case": load_case_payload(case_path)}
        except CaseBookmarkError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @api.get("/api/runs/{run_id}/submission-manifest")
    def get_submission_manifest(
        run_id: str,
        include_all: bool = False,
        max_items: int = Query(500, ge=1, le=5000),
    ) -> Dict[str, object]:
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(
            store,
            run_id,
            include_all=include_all,
            max_items=max_items,
        )
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=max_items)
        return manifest

    @api.get("/api/runs/{run_id}/submission-manifest/file")
    def download_submission_manifest(run_id: str, include_all: bool = False) -> FileResponse:
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(store, run_id, include_all=include_all, max_items=500)
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=500)
        return FileResponse(manifest_path, filename=manifest_path.name)

    @api.post("/api/runs/{run_id}/case-report")
    def create_case_report(run_id: str, request: CaseReportCreateRequest) -> Dict[str, object]:
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(markdown, encoding="utf-8")
        write_case_report_audit(store, run_id, report_path, request)
        return {
            "report_path": str(report_path),
            "audit": str(audit_path_for(report_path)),
            "markdown": markdown,
        }

    @api.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        request = CaseReportCreateRequest()
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(markdown, encoding="utf-8")
        write_case_report_audit(store, run_id, report_path, request)
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")

    @api.post("/api/runs/{run_id}/bookmarks")
    def create_run_bookmark(run_id: str, request: BookmarkCreateRequest) -> Dict[str, object]:
        source_name = normalize_bookmark_source(request.source)
        source_path = get_output_path(store, run_id, source_name)
        case_path = default_case_path(store, run_id)
        try:
            payload = create_or_update_case_payload(
                case_path,
                case_id=request.case_id or f"run-{run_id}",
                title=request.title or f"rapidtriage run {run_id}",
                source_path=source_path,
                source_pointer=request.pointer,
                bookmark_id=request.bookmark_id,
                tags=normalize_bookmark_tags(request),
                note=request.note,
                review_status=request.review_status,
                include_in_report=request.include_in_report,
            )
        except (FileNotFoundError, CaseBookmarkError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        save_case_payload(case_path, payload)
        audit_output = audit_path_for(case_path)
        write_audit_record(
            audit_output,
            command="case",
            options={
                "case_id": request.case_id,
                "title": request.title,
                "source": str(source_path),
                "pointer": request.pointer,
                "bookmark_id": request.bookmark_id,
                "tags": normalize_bookmark_tags(request),
                "review_status": request.review_status,
                "include_in_report": request.include_in_report,
            },
            input_files=[("source-json", source_path)],
            output_files=[("case-json", case_path)],
        )
        return {"case_path": str(case_path), "audit": str(audit_output), "case": payload}

    if static_dir.is_dir():
        api.mount("/assets", StaticFiles(directory=static_dir), name="rapidtriage-assets")

        @api.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(static_dir / "index.html")

    return api


def get_job(store: RunJobStore, run_id: str):
    try:
        return store.get(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="run not found")


def get_job_payload(store: RunJobStore, run_id: str, *, include_summary: bool) -> Dict[str, object]:
    return get_job(store, run_id).to_dict(include_summary=include_summary)


def get_named_output(store: RunJobStore, run_id: str, output_name: str) -> Dict[str, object]:
    try:
        return store.read_output(run_id, output_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="run output not found")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def paginate_payload(
    payload: Dict[str, object],
    collection_name: str,
    *,
    offset: int,
    limit: int,
    omit_fields: tuple[str, ...] = (),
) -> Dict[str, object]:
    if limit <= 0:
        return payload
    rows = payload.get(collection_name)
    if not isinstance(rows, list):
        rows = []
    total = len(rows)
    end = min(offset + limit, total)
    page = dict(payload)
    for field in omit_fields:
        if field in page:
            page[field] = [] if isinstance(page[field], list) else None
    if omit_fields:
        page["omitted_fields"] = list(omit_fields)
    page[collection_name] = rows[offset:end]
    page["pagination"] = {
        "collection": collection_name,
        "offset": offset,
        "limit": limit,
        "returned": max(0, end - offset),
        "total": total,
        "next_offset": end if end < total else None,
        "previous_offset": max(0, offset - limit) if offset > 0 else None,
        "has_more": end < total,
    }
    return page


def get_output_path(store: RunJobStore, run_id: str, output_name: str) -> Path:
    try:
        return store.output_path(run_id, output_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="run output not found")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def resolve_allowed_source_file(store: RunJobStore, run_id: str, raw_path: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    candidate = Path(raw_path).expanduser().resolve()
    allowed_roots = allowed_source_roots(job.summary)
    if not any(is_relative_to(candidate, root) for root in allowed_roots):
        raise HTTPException(status_code=403, detail=f"source file is outside allowed evidence roots: {candidate}")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail=f"source file not found: {candidate}")
    return candidate


def allowed_source_roots(summary: Dict[str, object]) -> list[Path]:
    roots: list[Path] = []
    for key in ("root", "scan_scope_root", "output_dir"):
        value = summary.get(key)
        if isinstance(value, str) and value:
            roots.append(Path(value).expanduser().resolve())
    source = summary.get("source")
    if isinstance(source, dict):
        for key in ("analysis_root", "stage_dir"):
            value = source.get(key)
            if isinstance(value, str) and value:
                roots.append(Path(value).expanduser().resolve())
    try:
        roots.append(run_output_dir(summary))
    except RuntimeError:
        pass
    deduped: list[Path] = []
    for root in roots:
        if root not in deduped:
            deduped.append(root)
    return deduped


def build_run_submission_manifest(
    store: RunJobStore,
    run_id: str,
    *,
    include_all: bool,
    max_items: int,
) -> Dict[str, object]:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    try:
        return build_submission_manifest(
            case_payload,
            allowed_roots=allowed_source_roots(job.summary),
            include_all=include_all,
            max_items=max_items,
        )
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def default_submission_manifest_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-submission-manifest.json")


def default_case_report_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-case-report.md")


def build_run_case_report(
    store: RunJobStore,
    run_id: str,
    request: CaseReportCreateRequest,
) -> str:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    manifest = build_run_submission_manifest(
        store,
        run_id,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    manifest_path = default_submission_manifest_path(store, run_id)
    write_json_file(manifest_path, manifest)
    write_submission_audit(
        store,
        run_id,
        manifest_path,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    return build_case_report_markdown(
        run_summary=job.summary,
        case_payload=case_payload,
        submission_manifest=manifest,
        metadata=model_to_dict(request),
    )


def write_json_file(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_submission_audit(
    store: RunJobStore,
    run_id: str,
    manifest_path: Path,
    *,
    include_all: bool,
    max_items: int,
) -> None:
    case_path = default_case_path(store, run_id)
    write_audit_record(
        audit_path_for(manifest_path),
        command="submission-manifest",
        options={"include_all": include_all, "max_items": max_items},
        input_files=[("case-json", case_path)],
        output_files=[("submission-manifest", manifest_path)],
    )


def write_case_report_audit(
    store: RunJobStore,
    run_id: str,
    report_path: Path,
    request: CaseReportCreateRequest,
) -> None:
    case_path = default_case_path(store, run_id)
    manifest_path = default_submission_manifest_path(store, run_id)
    write_audit_record(
        audit_path_for(report_path),
        command="case-report",
        options=model_to_dict(request),
        input_files=[("case-json", case_path), ("submission-manifest", manifest_path)],
        output_files=[("case-report", report_path)],
    )


def model_to_dict(model: BaseModel) -> Dict[str, object]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def build_source_preview(run_id: str, source_path: Path, *, max_chars: int = 20000) -> Dict[str, object]:
    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    payload: Dict[str, object] = {
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "modified_at": source_path.stat().st_mtime,
        "mime_type": mime_type,
        "download_url": f"/api/runs/{run_id}/source-file?path={quote(str(source_path))}",
        "preview_type": "binary",
        "text": "",
        "truncated": False,
        "message": "No inline preview is available for this file type.",
    }
    if mime_type.startswith("image/"):
        payload["preview_type"] = "image"
        payload["image_url"] = payload["download_url"]
        payload["message"] = "Image preview is available."
        return payload

    text = ""
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
        except Exception as exc:
            payload["message"] = f"Text extraction failed: {exc}"
            return payload
    elif stat.st_size <= 2_000_000:
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except UnicodeError as exc:
            payload["message"] = f"Text decoding failed: {exc}"
            return payload

    if text:
        payload["preview_type"] = "text"
        payload["text"] = text[:max_chars]
        payload["truncated"] = len(text) > max_chars
        payload["message"] = "Text preview is available."
    return payload


def build_source_search(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int = 100,
    context: int = 120,
    max_plain_text_bytes: int = 50_000_000,
) -> Dict[str, object]:
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one keyword is required")

    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    matches: list[dict[str, object]] = []
    truncated = False
    searchable = True
    message = "File search completed."

    if mime_type.startswith("image/"):
        searchable = False
        message = "Image files are not text-searchable in the file viewer. Use OCR from the full evidence search."
    elif suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
            matches = search_text_content(text, normalized, limit=limit, context=context)
        except Exception as exc:
            searchable = False
            message = f"Text extraction failed: {exc}"
    elif stat.st_size <= max_plain_text_bytes:
        try:
            matches, truncated = search_plain_text_file(source_path, normalized, limit=limit, context=context)
        except UnicodeError as exc:
            searchable = False
            message = f"Text decoding failed: {exc}"
    else:
        searchable = False
        message = f"File is larger than the {max_plain_text_bytes} byte inline search limit."

    return {
        "command": "source-search",
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "mime_type": mime_type,
        "keywords": normalized,
        "searchable": searchable,
        "truncated": truncated or len(matches) >= limit,
        "message": message,
        "summary": {
            "match_count": len(matches),
            "limit": limit,
        },
        "matches": matches,
    }


def search_text_content(text: str, keywords: Sequence[str], *, limit: int, context: int) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    lowered = text.lower()
    for keyword in keywords:
        start = 0
        while len(matches) < limit:
            index = lowered.find(keyword, start)
            if index < 0:
                break
            line_number = text.count("\n", 0, index) + 1
            matches.append(
                {
                    "keyword": keyword,
                    "line": line_number,
                    "offset": index,
                    "snippet": snippet_around(text, index, len(keyword), context=context),
                }
            )
            start = index + max(len(keyword), 1)
        if len(matches) >= limit:
            break
    matches.sort(key=lambda item: int(item["offset"]))
    return matches


def search_plain_text_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
) -> tuple[list[dict[str, object]], bool]:
    matches: list[dict[str, object]] = []
    truncated = False
    with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, line in enumerate(handle, start=1):
            lowered = line.lower()
            for keyword in keywords:
                for match in re.finditer(re.escape(keyword), lowered):
                    matches.append(
                        {
                            "keyword": keyword,
                            "line": line_number,
                            "offset": match.start(),
                            "snippet": snippet_around(line.rstrip("\n"), match.start(), len(keyword), context=context),
                        }
                    )
                    if len(matches) >= limit:
                        truncated = True
                        return matches, truncated
    return matches, truncated


def snippet_around(text: str, index: int, length: int, *, context: int) -> str:
    start = max(0, index - context)
    end = min(len(text), index + length + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def default_case_path(store: RunJobStore, run_id: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    output_dir = job.summary.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise HTTPException(status_code=409, detail="run summary does not include output_dir")
    return Path(output_dir).expanduser().resolve() / "rapidtriage-case.json"


def normalize_bookmark_source(source: str) -> str:
    normalized = source.strip()
    aliases = {
        "timeline": "timeline",
        "files": "files",
        "docs": "docs",
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized.startswith("artifacts:"):
        kind = normalized.split(":", 1)[1].strip()
        if kind:
            return f"artifacts_{kind}"
    if normalized.startswith("artifacts_"):
        return normalized
    raise HTTPException(status_code=400, detail=f"unsupported bookmark source: {source}")


def normalize_bookmark_tags(request: BookmarkCreateRequest) -> list[str]:
    raw_tags: list[str] = []
    if request.tag:
        raw_tags.append(request.tag)
    if request.tags:
        raw_tags.extend(request.tags)
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw_tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


app = create_app()
