"""Case intake routes (AXIOM adoption E1): cases, evidence, case runs, notes, snapshots, problems.

Contract (docs/plans/axiom-adoption-2026-10-17.md §3.1). Errors are Korean:
404 (case / evidence / note / run not found), 409 (duplicate case number,
duplicate evidence number or path, run already linked, note already deleted,
run still active, output folder used by another queued/running run, hash already
running), 422 (body validation, path policy, evidence kind, mode, run root differs
from the evidence path, register-only evidence).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ...core.case_db.base import CaseDatabaseError
from ...core.case_db.intake import CaseConflictError, CaseNotFoundError
from ...core.jobs import RunJobStore
from ...core.run.profiles import RUN_PROFILES
from .case_workspace import (
    SNAPSHOT_FILE_NAME,
    CaseWorkspace,
    build_processing_snapshot,
    checked_local_path,
    evidence_slug,
    expected_hash_algorithm,
    infer_source_type,
    run_brief,
    run_readiness,
    same_path,
    validate_evidence_kind,
)
from .helpers import (
    get_job,
    job_output_dir,
    resolve_request_reviewer,
    validate_run_evidence_source,
)
from .models import (
    CaseCreateRequest,
    CaseEvidenceCheckRequest,
    CaseEvidenceCreateRequest,
    CaseNoteCreateRequest,
    CasePatchRequest,
    CaseRunCreateRequest,
    CaseRunLinkRequest,
)
from .routes_runs import run_request_from_body
from .run_problems import PROBLEM_MAX_LIMIT, PROBLEM_PREVIEW_LIMIT, build_run_problems

#: Korean field names for 422 bodies on these routes (factory exception handler).
CASE_FIELD_LABELS = {
    "case_number": "사건 번호",
    "name": "사건명",
    "case_type": "사건 유형",
    "examiner": "검사관",
    "requester": "의뢰처",
    "organization": "소속",
    "description": "설명",
    "case_root": "케이스 폴더",
    "status": "상태",
    "evidence_number": "증거 번호",
    "display_name": "표시 이름",
    "source_type": "증거 종류",
    "path": "증거 경로",
    "verify_hash": "해시 검증",
    "expected_hash": "기대 해시",
    "evidence_citation_id": "증거 인용 ID",
    "run_id": "런 ID",
    "text": "메모 내용",
    "author": "작성자",
    "actor": "작업자",
    "mode": "처리 모드",
    "root": "증거 경로",
    "output_dir": "출력 폴더",
    "limit": "개수(limit)",
    "force": "강제 연결",
    "force_reason": "강제 연결 사유",
}


def _raise(exc: CaseDatabaseError) -> None:
    if isinstance(exc, CaseNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, CaseConflictError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail=str(exc)) from exc


def _integrity_conflict(exc: sqlite3.IntegrityError) -> HTTPException:
    """A unique index caught a concurrent duplicate the pre-check missed."""
    return HTTPException(status_code=409, detail=f"같은 번호가 이미 등록되었습니다. 목록을 새로 읽으세요 ({exc})")


def _actor(explicit: str, fallback: str = "") -> str:
    return resolve_request_reviewer(explicit) or fallback.strip()


def _same_output_dir_job(store: RunJobStore, output_dir: str) -> str | None:
    """Run id of a queued/running job that already writes into ``output_dir`` (None when free)."""
    for other in store.list():
        if other.status not in ("queued", "running"):
            continue
        other_dir = job_output_dir(other)
        if other_dir is not None and same_path(str(other_dir), output_dir):
            return other.run_id
    return None


def _write_snapshot_file(output_dir: Path | None, snapshot: dict[str, object]) -> tuple[str | None, str | None]:
    if output_dir is None:
        return None, "출력 폴더를 알 수 없습니다"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / SNAPSHOT_FILE_NAME
        temporary = target.with_name(f"{target.name}.tmp")
        temporary.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(target)
        return str(target), None
    except OSError as exc:
        return None, f"스냅숏 파일을 쓰지 못했습니다: {exc}"


def build_cases_router(store: RunJobStore, workspace: CaseWorkspace) -> APIRouter:
    router = APIRouter()
    # The output-folder check and the submit are one step (two case runs cannot both pass the check).
    submit_lock = threading.Lock()

    def intake():
        return workspace.intake

    def case_or_404(case_id: str) -> dict[str, object]:
        try:
            return intake().get_case(case_id)
        except CaseDatabaseError as exc:
            _raise(exc)
            raise  # pragma: no cover - _raise always raises

    def evidence_with_runs(case_id: str) -> list[dict[str, object]]:
        evidence = [workspace.present_evidence(item) for item in intake().list_evidence(case_id)]
        snapshots = intake().list_snapshots(case_id)
        for item in evidence:
            item["runs"] = [
                {**run_brief(store, str(snap["run_id"])), "captured_at": snap["captured_at"]}
                for snap in snapshots
                if snap["evidence_citation_id"] == item["citation_id"]
            ]
        return evidence

    def case_detail(case: dict[str, object]) -> dict[str, object]:
        case_id = str(case["case_id"])
        evidence = evidence_with_runs(case_id)
        counts = intake().case_counts([case_id])[case_id]
        return {**case, **counts, "evidence": evidence}

    # --- cases -------------------------------------------------------------------

    @router.post("/api/cases", status_code=201)
    def create_case(request: CaseCreateRequest) -> dict[str, Any]:
        case_number = request.case_number.strip()
        if not case_number:
            raise HTTPException(status_code=422, detail="사건 번호가 비어 있습니다")
        case_root = checked_local_path(request.case_root, label="케이스 폴더") if request.case_root.strip() else ""
        fields = request.model_dump()
        fields["case_number"] = case_number
        try:
            case = intake().create_case(
                case_id=f"case-{uuid.uuid4().hex[:12]}",
                fields=fields,
                case_root=case_root,
                actor=_actor("", request.examiner),
            )
        except CaseDatabaseError as exc:
            _raise(exc)
        except sqlite3.IntegrityError as exc:
            raise _integrity_conflict(exc) from exc
        return {"command": "case.create", "case": case_detail(case)}

    @router.get("/api/cases")
    def list_cases() -> dict[str, Any]:
        cases = intake().list_cases()
        return {"command": "case.list", "cases": [case_detail(case) for case in cases], "count": len(cases)}

    @router.get("/api/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        return {"command": "case.get", "case": case_detail(case_or_404(case_id))}

    @router.patch("/api/cases/{case_id}")
    def patch_case(case_id: str, request: CasePatchRequest) -> dict[str, Any]:
        current = case_or_404(case_id)
        changes = request.model_dump(exclude_unset=True, exclude={"actor"})
        changes = {key: value for key, value in changes.items() if value is not None}
        if "case_number" in changes and not str(changes["case_number"]).strip():
            raise HTTPException(status_code=422, detail="사건 번호가 비어 있습니다")
        try:
            case = intake().update_case(case_id, changes, actor=_actor(request.actor, str(current["examiner"])))
        except CaseDatabaseError as exc:
            _raise(exc)
        return {"command": "case.update", "case": case_detail(case)}

    # --- evidence ----------------------------------------------------------------

    @router.post("/api/cases/{case_id}/evidence", status_code=201)
    def add_evidence(case_id: str, request: CaseEvidenceCreateRequest) -> dict[str, Any]:
        case = case_or_404(case_id)
        number = request.evidence_number.strip()
        if not number:
            raise HTTPException(status_code=422, detail="증거 번호가 비어 있습니다")
        lexical = checked_local_path(request.path, label="증거", confine_to_analysis_roots=True)
        path = Path(lexical)
        validate_evidence_kind(path, request.source_type)
        algorithm = expected_hash_algorithm(request.expected_hash) if request.verify_hash else None
        if request.expected_hash.strip() and request.source_type == "e01":
            raise HTTPException(
                status_code=422,
                detail="E01은 컨테이너 바이트만 해시하므로 획득(매체) 해시와 비교할 수 없습니다. 기대 해시 없이 계산만 하세요",
            )
        if request.expected_hash.strip() and not request.verify_hash:
            raise HTTPException(status_code=422, detail="기대 해시는 해시 검증을 켠 경우에만 지정할 수 있습니다")
        hashable = path.is_file()
        if not request.verify_hash:
            status, message = "not-requested", ""
        elif not hashable:
            status, message = "not-applicable", "폴더 증거는 해시를 계산하지 않습니다"
        else:
            status, message = "hashing", f"기대값 {algorithm.upper()}" if algorithm else ""
        try:
            size = path.stat().st_size if hashable else None
        except OSError:
            size = None
        try:
            evidence = intake().add_evidence(
                case_id,
                evidence_number=number,
                display_name=request.display_name.strip() or path.name or lexical,
                source_type=request.source_type,
                path=lexical,
                size_bytes=size,
                hash_verify=request.verify_hash,
                hash_expected=request.expected_hash.strip().lower() if request.verify_hash else "",
                hash_status=status,
                hash_message=message,
                actor=_actor(request.actor, str(case["examiner"])),
            )
        except CaseDatabaseError as exc:
            _raise(exc)
        except sqlite3.IntegrityError as exc:
            raise _integrity_conflict(exc) from exc
        if status == "hashing":
            workspace.start_hash(
                case_id=case_id, citation_id=str(evidence["citation_id"]), path=path,
                expected=request.expected_hash,
            )
        return {"command": "case.evidence.add", "evidence": {**workspace.present_evidence(evidence), "runs": []}}

    @router.post("/api/cases/{case_id}/evidence/{citation_id}/hash", status_code=202)
    def rehash_evidence(case_id: str, citation_id: str, actor: str = Query("", max_length=200)) -> dict[str, Any]:
        """Hash (again) a file evidence item: after a restart (`interrupted`), a failure, or never asked."""
        case = case_or_404(case_id)
        try:
            current = intake().get_evidence(case_id, citation_id)
        except CaseDatabaseError as exc:
            _raise(exc)
        path = Path(str(current["path"]))
        if not path.is_file():
            raise HTTPException(status_code=422, detail="파일 증거만 해시를 계산할 수 있습니다 (폴더·없는 경로 제외)")
        if workspace.hash_running(citation_id):
            raise HTTPException(status_code=409, detail="이미 해시를 계산하고 있습니다")
        try:
            evidence = intake().restart_hash(case_id, citation_id, actor=_actor(actor, str(case["examiner"])))
        except CaseDatabaseError as exc:
            _raise(exc)
        workspace.start_hash(case_id=case_id, citation_id=citation_id, path=path,
                             expected=str(evidence.get("hash_expected") or ""))
        return {"command": "case.evidence.hash", "evidence": workspace.present_evidence(evidence)}

    @router.post("/api/cases/evidence-check")
    def check_evidence(request: CaseEvidenceCheckRequest) -> dict[str, Any]:
        """Pre-check one evidence path before anything is saved: path policy, kind, runnable."""
        try:
            lexical = checked_local_path(request.path, label="증거", confine_to_analysis_roots=True)
            path = Path(lexical)
            if request.source_type:
                validate_evidence_kind(path, request.source_type)
            elif not path.exists():
                raise HTTPException(status_code=422, detail=f"증거 경로가 없습니다: {path}")
        except HTTPException as exc:
            return {"command": "case.evidence.check", "path": request.path, "ok": False, "problem": str(exc.detail),
                    "runnable": False, "run_blocked_reason": ""}
        runnable, reason = run_readiness(path)
        return {"command": "case.evidence.check", "path": lexical, "ok": True, "problem": "",
                "runnable": runnable, "run_blocked_reason": reason}

    @router.get("/api/cases/{case_id}/evidence")
    def list_evidence(case_id: str) -> dict[str, Any]:
        case_or_404(case_id)
        evidence = evidence_with_runs(case_id)
        return {"command": "case.evidence.list", "case_id": case_id, "evidence": evidence, "count": len(evidence)}

    # --- runs --------------------------------------------------------------------

    @router.post("/api/cases/{case_id}/runs", status_code=202)
    def create_case_run(case_id: str, request: CaseRunCreateRequest) -> dict[str, Any]:
        case = case_or_404(case_id)
        try:
            evidence = intake().get_evidence(case_id, request.evidence_citation_id.strip())
        except CaseDatabaseError as exc:
            _raise(exc)
        if request.mode not in RUN_PROFILES:
            raise HTTPException(status_code=422, detail=f"알 수 없는 처리 모드입니다: {request.mode}")
        evidence_path = str(evidence["path"])
        if request.root.strip() and not same_path(request.root.strip(), evidence_path):
            raise HTTPException(status_code=422, detail="런 경로가 증거 경로와 다릅니다")
        root = checked_local_path(evidence_path, label="증거", confine_to_analysis_roots=True)
        if not Path(root).exists():
            raise HTTPException(status_code=422, detail=f"증거 경로가 없습니다: {root}")
        try:
            validate_run_evidence_source(root)
        except HTTPException as exc:
            raise HTTPException(status_code=422, detail=f"이 증거는 바로 처리할 수 없습니다: {exc.detail}") from exc
        output_dir: str | None = None
        explicit_output = bool(request.output_dir and request.output_dir.strip())
        if explicit_output:
            output_dir = checked_local_path(str(request.output_dir), label="출력 폴더")
        elif case.get("case_root"):
            stamp = uuid.uuid4().hex[:8]
            output_dir = str(
                Path(str(case["case_root"]))
                / f"{evidence_slug(str(evidence['evidence_number']))}-rapidtriage-run-{request.mode}-{stamp}"
            )
        run_request = run_request_from_body(request, root=root, output_dir=output_dir)
        with submit_lock:
            if explicit_output and output_dir:
                # Two concurrent runs in one folder overwrite each other's summary, case DB and snapshot.
                busy = _same_output_dir_job(store, output_dir)
                if busy:
                    raise HTTPException(
                        status_code=409,
                        detail=f"같은 출력 폴더를 쓰는 런({busy})이 대기·실행 중입니다. 출력 폴더를 비우거나 다른 폴더를 지정하세요",
                    )
            job = store.submit(run_request) if not request.wait else None
        if job is None:
            job = store.run_sync(run_request)
        snapshot = build_processing_snapshot(run_request=run_request, case=case, evidence=evidence, origin="case-run")
        # Written into the run's own output folder: with wait=false (the default) this happens right
        # after the run is queued, before its first step, so the file is part of the run output from
        # the start; the path is also recorded in the case audit (run.created params).
        file_path, file_error = _write_snapshot_file(job_output_dir(job), snapshot)
        snapshot["file"] = file_path
        try:
            saved = intake().save_snapshot(
                run_id=job.run_id, case_id=case_id, evidence_citation_id=str(evidence["citation_id"]),
                snapshot=snapshot, actor=_actor(request.actor, str(case["examiner"])),
                audit_params={"snapshot_file": file_path, "snapshot_file_error": file_error},
            )
        except CaseDatabaseError as exc:
            _raise(exc)
        return {
            "command": "case.run.create",
            "case_id": case_id,
            "run": store.get(job.run_id).to_dict(include_summary=request.wait),
            "snapshot": saved,
            "snapshot_file": file_path,
            "snapshot_file_error": file_error,
        }

    @router.post("/api/cases/{case_id}/runs/link", status_code=201)
    def link_case_run(case_id: str, request: CaseRunLinkRequest) -> dict[str, Any]:
        case = case_or_404(case_id)
        job = get_job(store, request.run_id)
        if job.status in ("queued", "running"):
            raise HTTPException(status_code=409, detail="실행 중인 런은 끝난 뒤 케이스에 연결할 수 있습니다")
        existing = intake().get_snapshot(job.run_id)
        if existing is not None:
            linked = case_or_404(str(existing["case_id"])) if existing["case_id"] != case_id else case
            raise HTTPException(status_code=409, detail=f"이미 케이스 {linked['case_number']}에 연결된 런입니다")
        actor = _actor(request.actor, str(case["examiner"]))
        force_reason = request.force_reason.strip()
        if request.force and not force_reason:
            raise HTTPException(status_code=422, detail="강제 연결 사유를 입력하세요")
        forced = False
        try:
            if (request.evidence_citation_id or "").strip():
                evidence = intake().get_evidence(case_id, str(request.evidence_citation_id).strip())
                # The citation's 증거 번호 must name the evidence the run actually processed.
                run_root = str(job.request.root or "")
                if not run_root or not same_path(run_root, str(evidence["path"])):
                    if not request.force:
                        raise HTTPException(status_code=422, detail="런 경로가 증거 경로와 다릅니다")
                    forced = True
            else:
                root = (
                    checked_local_path(job.request.root, label="런 증거", confine_to_analysis_roots=True)
                    if job.request.root
                    else ""
                )
                evidence = intake().find_evidence_by_path(case_id, root) if root else None
                if evidence is None:
                    number = (request.evidence_number or "").strip()
                    if not number:
                        raise HTTPException(status_code=422, detail="증거 번호 값이 필요합니다")
                    if not root:
                        raise HTTPException(status_code=422, detail="런에 증거 경로가 없어 증거를 만들 수 없습니다")
                    path = Path(root)
                    evidence = intake().add_evidence(
                        case_id,
                        evidence_number=number,
                        display_name=path.name or root,
                        source_type=infer_source_type(path),
                        path=root,
                        size_bytes=path.stat().st_size if path.is_file() else None,
                        hash_verify=False,
                        hash_expected="",
                        hash_status="not-requested",
                        hash_message="",
                        actor=actor,
                    )
            snapshot = build_processing_snapshot(
                run_request=job.request, case=case, evidence=evidence, origin="linked-run", summary=job.summary
            )
            if forced:
                snapshot["forced_link"] = {"reason": force_reason, "run_root": job.request.root,
                                           "evidence_path": evidence["path"]}
            # A finished run's output folder is not touched after the fact: the linked snapshot file
            # lives in the workspace (next to the cases DB) and its path is in the audit.
            file_path, file_error = _write_snapshot_file(workspace.linked_snapshot_dir(job.run_id), snapshot)
            snapshot["file"] = file_path
            audit_params: dict[str, object] = {"snapshot_file": file_path, "snapshot_file_error": file_error}
            if forced:
                audit_params.update(forced=True, force_reason=force_reason, run_root=job.request.root,
                                    evidence_path=evidence["path"])
            saved = intake().save_snapshot(
                run_id=job.run_id, case_id=case_id, evidence_citation_id=str(evidence["citation_id"]),
                snapshot=snapshot, actor=actor, action="run.linked", audit_params=audit_params,
            )
        except CaseDatabaseError as exc:
            _raise(exc)
        except sqlite3.IntegrityError as exc:
            raise _integrity_conflict(exc) from exc
        except OSError as exc:
            raise HTTPException(status_code=422, detail=f"증거 경로를 읽을 수 없습니다: {exc}") from exc
        return {"command": "case.run.link", "case_id": case_id, "snapshot": saved,
                "snapshot_file": file_path, "snapshot_file_error": file_error}

    @router.get("/api/cases/{case_id}/runs")
    def list_case_runs(case_id: str) -> dict[str, Any]:
        case_or_404(case_id)
        evidence = {str(item["citation_id"]): item for item in intake().list_evidence(case_id)}
        runs = []
        for snap in intake().list_snapshots(case_id):
            item = evidence.get(str(snap["evidence_citation_id"]), {})
            runs.append({
                **run_brief(store, str(snap["run_id"])),
                "evidence_citation_id": snap["evidence_citation_id"],
                "evidence_number": item.get("evidence_number", ""),
                "captured_at": snap["captured_at"],
            })
        return {"command": "case.run.list", "case_id": case_id, "runs": runs, "count": len(runs)}

    @router.get("/api/runs/{run_id}/processing-snapshot")
    def get_processing_snapshot(run_id: str) -> dict[str, Any]:
        try:
            saved = intake().get_snapshot(run_id)
        except (CaseDatabaseError, sqlite3.Error, OSError):
            # The workspace case DB is unusable: the run still shows its request snapshot.
            saved = None
        if saved is not None:
            case = None
            evidence = None
            try:
                case = intake().get_case(str(saved["case_id"]))
                evidence = workspace.present_evidence(
                    intake().get_evidence(str(saved["case_id"]), str(saved["evidence_citation_id"]))
                )
            except CaseDatabaseError:
                pass
            return {"command": "run.processing-snapshot", "source": "case-db", **saved, "case": case,
                    "evidence": evidence}
        job = get_job(store, run_id)
        snapshot = build_processing_snapshot(
            run_request=job.request, case=None, evidence=None, origin="run-request", summary=job.summary
        )
        return {"command": "run.processing-snapshot", "source": "run-request", "run_id": run_id, "case_id": None,
                "evidence_citation_id": None, "captured_at": job.created_at, "snapshot": snapshot, "case": None,
                "evidence": None}

    @router.get("/api/runs/{run_id}/problems")
    def get_run_problems(
        run_id: str,
        reason_id: str | None = Query(None, max_length=64),
        limit: int = Query(PROBLEM_PREVIEW_LIMIT, ge=1, le=PROBLEM_MAX_LIMIT),
    ) -> dict[str, Any]:
        return build_run_problems(store, run_id, reason_id=reason_id, limit=limit)

    # --- notes -------------------------------------------------------------------

    @router.get("/api/cases/{case_id}/notes")
    def list_notes(case_id: str, include_deleted: bool = False) -> dict[str, Any]:
        try:
            payload = intake().list_notes(case_id, include_deleted=include_deleted)
        except CaseDatabaseError as exc:
            _raise(exc)
        return {"command": "case.note.list", "case_id": case_id, **payload}

    @router.post("/api/cases/{case_id}/notes", status_code=201)
    def add_note(case_id: str, request: CaseNoteCreateRequest) -> dict[str, Any]:
        case = case_or_404(case_id)
        text = request.text.strip()
        if not text:
            raise HTTPException(status_code=422, detail="메모 내용이 비어 있습니다")
        try:
            note = intake().add_note(case_id, text=text, author=_actor(request.author, str(case["examiner"])))
        except CaseDatabaseError as exc:
            _raise(exc)
        return {"command": "case.note.add", "note": note}

    @router.delete("/api/cases/{case_id}/notes/{note_id}")
    def delete_note(case_id: str, note_id: int, actor: str = Query("", max_length=200)) -> dict[str, Any]:
        case = case_or_404(case_id)
        try:
            note = intake().delete_note(case_id, note_id, actor=_actor(actor, str(case["examiner"])))
        except CaseDatabaseError as exc:
            _raise(exc)
        return {"command": "case.note.delete", "note": note}

    return router
