"""Run, source-file, and docs-index search API routes."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query

from ...core.docs import query_docs_index
from ...core.jobs import RunJobStore
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_selection_profile,
    resolve_keyword_packs,
)
from ...core.search import SearchError, run_unified_search
from ...core.search_fts import regex_literal_prefix_problem
from .analyses import AnalysisRowRef, analysis_row_ref
from .helpers import (
    get_job,
    get_output_path,
    parse_source_preview_archive_request,
    resolve_allowed_source_file,
    run_not_finished_message,
)
from .runops import (
    attach_search_result_source_actions,
    build_archived_source_search,
    build_search_result_source_action_profile,
    build_source_search,
)

# Console page size (R7): a page renders fast; the grid loads the next page on scroll.
SEARCH_DEFAULT_LIMIT = 250
# Deep offsets re-collect every earlier hit: bounded so a page stays interactive.
SEARCH_MAX_OFFSET = 20_000


def build_search_router(
    store: RunJobStore,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/runs/{run_id}/source-search")
    def search_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        row_ref: AnalysisRowRef = Depends(analysis_row_ref),
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(100, ge=1, le=500),
        context: int = Query(120, ge=20, le=500),
        sqlite_resume_token: str | None = Query(default=None),
        file_resume_token: str | None = Query(default=None),
    ) -> dict[str, object]:
        archive_request = parse_source_preview_archive_request(path)
        if archive_request:
            source_path = resolve_allowed_source_file(store, run_id, archive_request["archive_path"], **row_ref)
            return build_archived_source_search(
                source_path,
                archive_request["entry_name"],
                keyword,
                limit=limit,
                context=context,
                sqlite_resume_token=sqlite_resume_token,
                file_resume_token=file_resume_token,
            )
        source_path = resolve_allowed_source_file(store, run_id, path, **row_ref)
        return build_source_search(
            source_path,
            keyword,
            limit=limit,
            context=context,
            sqlite_resume_token=sqlite_resume_token,
            file_resume_token=file_resume_token,
        )


    @router.get("/api/runs/{run_id}/docs-index-search")
    def search_run_docs_index(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(500, ge=1, le=5000),
    ) -> dict[str, object]:
        index_path = get_output_path(store, run_id, "docs_index")
        try:
            payload = query_docs_index(index_path, keyword, limit=limit)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        query_terms = [
            str(term)
            for term in ((payload.get("query") or {}).get("terms") if isinstance(payload.get("query"), dict) else keyword)
            if str(term).strip()
        ]
        keyword_query = "".join(f"&keyword={quote(term)}" for term in query_terms)
        for index, result in enumerate(payload.get("results", [])):
            if not isinstance(result, dict) or not result.get("path"):
                continue
            result["pointer"] = str(result.get("source_locator") or f"docs-index:/results/{index}")
            result["source"] = "docs-index"
            result["matched_keywords"] = [
                item["term"]
                for item in result.get("matched_terms", [])
                if isinstance(item, dict) and item.get("term")
            ]
            matched_term_text = ", ".join(
                f"{item.get('term')}:{item.get('count')}"
                for item in result.get("matched_terms", [])
                if isinstance(item, dict) and item.get("term")
            )
            review_note_text = (
                f"Docs-index hit: {result.get('source_locator')} path={result.get('path')}\n"
                f"Matched terms: {matched_term_text or ', '.join(query_terms)}\n"
                f"Result hash: {result.get('result_hash') or ''}\n"
                "Review hint: open source viewer and current-file source-search before report inclusion"
            )
            result["review_note_citation"] = {
                "profile_version": "docs-index-review-note-citation-v1",
                "source_locator": result.get("source_locator"),
                "result_hash": result.get("result_hash"),
                "text": review_note_text,
                "ready_for_review_note": True,
                "report_use_rule": "Docs-index hits are leads until source-search confirms hit context in the original source.",
            }
            result["source_viewer_url"] = (
                f"/api/runs/{run_id}/source-preview?path={quote(str(result['path']))}"
            )
            result["source_search_url"] = (
                f"/api/runs/{run_id}/source-search?path={quote(str(result['path']))}{keyword_query}"
            )
            result["source_viewer_action_profile"] = build_search_result_source_action_profile(
                run_id,
                {
                    "path": result.get("path"),
                    "pointer": result.get("pointer"),
                    "source": "docs-index",
                    "kind": result.get("kind") or "docs-index",
                    "title": Path(str(result.get("path") or "")).name,
                    "preview": review_note_text,
                    "matched_keywords": result.get("matched_keywords") or query_terms,
                    "search_result_id": result.get("result_hash") or result.get("source_locator") or "",
                },
                index=index,
            )
        payload["run_id"] = run_id
        payload["api_profile"] = {
            "profile_version": "docs-index-search-api-v1",
            "output_name": "docs_index",
            "gui_binding": "docs-index-sidecar-search",
            "source_verification_required": True,
            "reportability_warning": (
                "Docs-index hits are fast leads only; open the source viewer or source-search hit context before reporting."
            ),
        }
        return payload


    @router.get("/api/runs/{run_id}/search")
    def search_run(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        ocr: bool = False,
        limit: int = Query(SEARCH_DEFAULT_LIMIT, ge=1, le=1000),
        offset: int = Query(0, ge=0, le=SEARCH_MAX_OFFSET),
        source: list[str] = Query(default=[]),
        extension: list[str] = Query(default=[]),
        path_contains: str | None = Query(default=None),
        analysis: bool = False,
        detail: bool = False,
        metadata: str = Query("compact", pattern="^(compact|full)$"),
        search_mode: str = Query("exact", pattern="^(exact|fuzzy|regex)$"),
        fuzzy_distance: int = Query(1, ge=0, le=2),
        proximity_window: int = Query(0, ge=0, le=100),
        hide_known_good: bool = False,
        keyword_pack: list[str] = Query(default=[]),
    ) -> dict[str, object]:
        """Unified keyword search over a finished run (case-DB FTS, else a bounded scan).

        Defaults favour the console grid (R7): ``analysis`` and ``ocr`` are off
        (``analysis=1`` adds the entity/co-occurrence analysis, ``ocr=1`` or
        ``source=ocr`` the OCR sidecars), ``detail`` is off (``detail=1`` adds
        the per-hit source-viewer/verification/manifest profiles and the
        top-level ``advanced_*`` blocks), ``metadata=compact`` keeps only the
        record fields the grid reads (``metadata=full``: the whole record).
        ``limit`` (default 250) and ``offset`` page the hits in a stable order;
        ``pagination`` reports ``has_more``/``next_offset``/``total``. A regex
        keyword must start with a literal word (Korean 422 otherwise).
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        if search_mode == "regex":
            for pattern in keyword:
                problem = regex_literal_prefix_problem(pattern)
                if problem:
                    raise HTTPException(status_code=422, detail=problem)
        try:
            selected_pack_names = [name.strip() for name in keyword_pack if name.strip()]
            keywords = resolve_keyword_packs(keyword, pack_names=selected_pack_names)
            payload = run_unified_search(
                job.summary,
                keywords,
                include_ocr=ocr or any(item.strip().lower() == "ocr" for item in source),
                limit=limit,
                offset=offset,
                detail=detail,
                metadata=metadata,
                sources=source,
                extensions=extension,
                path_contains=path_contains,
                include_analysis=analysis,
                search_mode=search_mode,
                fuzzy_distance=fuzzy_distance,
                proximity_window=proximity_window,
                hide_known_good=hide_known_good,
            )
            payload["keyword_pack_selection_profile"] = keyword_pack_selection_profile(
                pack_names=selected_pack_names,
                keyword_count=len(keywords),
                expanded_keywords=keywords,
            )
            if detail:
                attach_search_result_source_actions(payload, run_id)
            for match in payload.get("matches") or []:
                # The review locator names its run (the console resolves it to the source row).
                if isinstance(match, dict) and isinstance(match.get("locator"), dict):
                    match["locator"]["run_id"] = run_id
            # v1 scan search stays for the global box when a run has no index (plan search §3.3).
            payload["deprecated"] = True
            payload["successor"] = f"/api/runs/{run_id}/search/query"
            return payload
        except (SearchError, KeywordPackError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    return router
