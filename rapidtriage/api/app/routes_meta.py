"""Health, diagnostics, and environment metadata API routes."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ...core.browse import BrowseError, browse_directory
from ...core.collect_plan import (
    CollectPlanError,
    build_collect_plan,
    supported_collect_profiles,
)
from ...core.commercial_readiness import (
    CommercialReadinessError,
    build_commercial_readiness_report,
)
from ...core.crash import (
    export_crash_report_bundle,
    list_crash_reports,
    read_crash_report,
)
from ...core.credential_stores import is_credential_store_path
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.jobs import RunJobStore
from ...core.keyword_packs import (
    keyword_pack_library_assessment,
    list_keyword_packs,
)
from ...core.visible_capabilities import build_visible_capability_response
from .models import (
    CollectPlanRequest,
    EvidenceIdentifyRequest,
)
from .runops import (
    build_commercial_readiness_api_payload,
)
from .viewer_core import (
    build_workbench_large_result_evidence,
    build_workbench_smoke_contract,
    resolve_commercial_readiness_validation_package,
)

#: Set by ``rapidtriage web`` for a ``--remote`` (or non-loopback) server: ``/api/browse`` lists
#: only inside the browse roots. Read once when the app is built (``create_app``).
BROWSE_REMOTE_ENV = "RAPIDTRIAGE_REMOTE"
#: ``--browse-root`` values (os.pathsep list). Unset: the run (case) folders the server knows + home.
BROWSE_ROOTS_ENV = "RAPIDTRIAGE_BROWSE_ROOTS"
#: ``detail.code`` of a remote browse outside the browse roots (core/error_codes.py, stable).
PATH_OUTSIDE_ALLOWED_ROOT = "PATH_OUTSIDE_ALLOWED_ROOT"
BROWSE_REMOTE_SCOPE = "원격 서버의 찾아보기 루트(--browse-root)"


def configured_browse_roots(values: Iterable[str | Path] | None) -> list[Path]:
    """``--browse-root`` values (explicit, else ``RAPIDTRIAGE_BROWSE_ROOTS``) as lexical + resolved roots.

    Relative, ``~``, UNC and device entries are dropped with a warning; when the setting is
    present but no entry survives, the remote picker lists nothing (fail closed)."""
    from .analyses import _root_forms, extra_analysis_roots

    if values is None:
        return extra_analysis_roots(BROWSE_ROOTS_ENV)
    return _root_forms(str(value) for value in values)


def remote_browse_roots(store: RunJobStore | None, configured: Sequence[Path] | None) -> list[Path]:
    """Roots a remote server may list: the configured ``--browse-root`` set, or by default the
    output (case) folder of every run this server knows plus the server user's home."""
    from .analyses import _root_forms

    if configured is not None:
        return list(configured)
    values: list[str] = [str(Path.home())]
    for job in store.list() if store is not None else ():
        for value in (job.request.output_dir if job.request is not None else None, (job.summary or {}).get("output_dir")):
            if isinstance(value, str) and value.strip():
                values.append(value)
    return _root_forms(values)


def _display_roots(roots: Sequence[Path]) -> list[str]:
    """The picker's jump list: one entry per existing root folder, no lexical/resolved duplicates."""
    seen: set[str] = set()
    shown: list[str] = []
    for root in roots:
        try:
            if not root.is_dir():
                continue
            key = os.path.normcase(str(root.resolve()))
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            shown.append(str(root))
    return shown


#: Korean note of a remote listing: credential stores are never listed (T-350 follow-up).
CREDENTIAL_STORE_NOTE = (
    "원격 찾아보기에서는 자격 증명 저장소(.ssh·.gnupg·.aws·.azure·.kube·.config/gcloud, "
    "브라우저 로그인 데이터, Windows 자격 증명·DPAPI 폴더)를 숨김 파일 표시와 관계없이 보여 주지 않습니다."
)


def _outside_browse_roots(message: object) -> HTTPException:
    return HTTPException(status_code=403, detail={"code": PATH_OUTSIDE_ALLOWED_ROOT, "message": str(message)})


def browse_remote(
    store: RunJobStore | None, configured: Sequence[Path] | None, *, path: str | None, show_hidden: bool
) -> dict[str, object]:
    """``/api/browse`` on a remote server: only inside the browse roots, anything else 403.

    The path is confined lexically, link components are walked without following them out, and
    the resolved folder is re-checked (``analyses.confine_path``), so ``..`` and junctions cannot
    leave the roots. ``parent`` is ``None`` at a root; ``roots`` is the root list, not the drives."""
    from .analyses import _under_any, confine_path

    roots = remote_browse_roots(store, configured)
    shown = _display_roots(roots)
    home = str(Path.home())
    if not path or not path.strip():
        home_allowed = _under_any(Path(home), roots)
        if not home_allowed and not shown:
            raise _outside_browse_roots("이 원격 서버에는 찾아볼 수 있는 루트가 없습니다 — 서버를 --browse-root <폴더>로 시작하세요")
        path = home if home_allowed else shown[0]
    try:
        resolved = confine_path(path, roots, label="찾아보기", scope=BROWSE_REMOTE_SCOPE)
    except HTTPException as exc:
        if exc.status_code == 403:
            raise _outside_browse_roots(exc.detail) from exc
        raise
    directory = resolved.parent if resolved.is_file() else resolved
    if not _under_any(directory, roots):
        raise _outside_browse_roots(f"찾아보기 경로가 허용 범위({BROWSE_REMOTE_SCOPE}) 밖에 있습니다: {directory}")
    if is_credential_store_path(directory):
        raise _outside_browse_roots(f"{CREDENTIAL_STORE_NOTE} 이 폴더는 열 수 없습니다")
    try:
        listing = browse_directory(directory, show_hidden=show_hidden, hide_credential_stores=True)
    except BrowseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    root_keys = {os.path.normcase(str(root)) for root in roots}
    parent = listing.get("parent")
    if os.path.normcase(str(listing.get("path"))) in root_keys or not isinstance(parent, str) or not _under_any(Path(parent), roots):
        parent = None
    return {
        **listing,
        "parent": parent,
        "home": home if _under_any(Path(home), roots) else (shown[0] if shown else ""),
        "roots": shown,
        "browse_mode": "remote",
        "credential_note": CREDENTIAL_STORE_NOTE,
    }


def build_meta_router(
    store: RunJobStore | None = None,
    *,
    browse_remote_mode: bool = False,
    browse_roots: Sequence[Path] | None = None,
) -> APIRouter:
    """``browse_remote_mode``: ``/api/browse`` lists only inside ``browse_roots`` (``None``: the
    default roots of :func:`remote_browse_roots`); a loopback server lists the whole disk."""
    router = APIRouter()

    @router.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}


    @router.get("/api/workbench/smoke-contract")
    def workbench_smoke_contract() -> dict[str, object]:
        return build_workbench_smoke_contract()


    @router.get("/api/workbench/large-result-evidence")
    def workbench_large_result_evidence(record_count: int = Query(100_000, ge=1, le=10_000_000)) -> dict[str, object]:
        return build_workbench_large_result_evidence(record_count=record_count)


    @router.get("/api/commercial-readiness")
    def commercial_readiness(
        next_gate: str = Query("commercial_grade", min_length=1, max_length=64),
        limit: int = Query(8, ge=1, le=50),
        validation_package: str | None = Query(default=None, max_length=4096),
        mac_first_evidence: str | None = Query(default=None, max_length=4096),
        include_internal_validation: bool = Query(False),
    ) -> dict[str, object]:
        try:
            validation_package_path = resolve_commercial_readiness_validation_package(
                validation_package,
                include_internal_validation=include_internal_validation,
            )
            mac_first_evidence_paths = [Path(mac_first_evidence).expanduser().resolve()] if mac_first_evidence else []
            report = build_commercial_readiness_report(
                validation_package_path=validation_package_path,
                mac_first_evidence_paths=mac_first_evidence_paths,
                uplift_targets=limit,
                uplift_batch_size=5,
            )
        except CommercialReadinessError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return build_commercial_readiness_api_payload(
            report,
            next_gate=next_gate,
            limit=limit,
            validation_package_path=validation_package_path,
            include_internal_validation=include_internal_validation,
        )


    @router.get("/api/doctor")
    def doctor() -> dict[str, object]:
        return run_doctor(include_port_check=False)


    @router.get("/api/crash-reports")
    def crash_reports(limit: int = Query(50, ge=1, le=500)) -> dict[str, object]:
        return list_crash_reports(limit=limit)


    @router.get("/api/crash-reports/{crash_id}")
    def crash_report_detail(crash_id: str) -> dict[str, object]:
        try:
            return read_crash_report(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


    @router.post("/api/crash-reports/{crash_id}/export")
    def crash_report_export(crash_id: str) -> dict[str, object]:
        try:
            return export_crash_report_bundle(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


    @router.get("/api/enterprise/policy")
    def enterprise_policy() -> dict[str, object]:
        return build_enterprise_policy()


    @router.get("/api/evidence/formats")
    def evidence_formats() -> dict[str, object]:
        return {"formats": supported_evidence_formats()}


    @router.get("/api/browse")
    def browse_filesystem(
        path: str | None = Query(default=None, max_length=4096),
        show_hidden: bool = Query(False),
        scope: str | None = Query(
            default=None,
            max_length=32,
            description="analysis-input | analysis-output: 분석 대화상자용 — run_id 런의 허용 입력/출력 루트 안만 나열 (없으면 예전처럼 전체 파일 시스템)",
        ),
        run_id: str | None = Query(default=None, max_length=128),
    ) -> dict[str, object]:
        if scope:
            if store is None:
                raise HTTPException(status_code=400, detail="이 서버에서는 분석 찾아보기를 쓸 수 없습니다")
            from .analyses import browse_analysis_scope

            return browse_analysis_scope(store, run_id=run_id, scope_name=scope.strip(), path=path, show_hidden=show_hidden)
        if browse_remote_mode:
            return browse_remote(store, browse_roots, path=path, show_hidden=show_hidden)
        try:
            # Loopback server: the whole disk — the analyst picks evidence wherever it is.
            return {**browse_directory(path, show_hidden=show_hidden), "browse_mode": "local"}
        except BrowseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/evidence/identify")
    def identify_evidence_path(request: EvidenceIdentifyRequest) -> dict[str, object]:
        try:
            result = identify_evidence(Path(request.path))
            return {
                "command": "evidence.identify",
                "result": result.to_dict(),
                "formats": supported_evidence_formats(),
            }
        except OSError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.get("/api/collect/profiles")
    def collect_profiles() -> dict[str, object]:
        return {"profiles": list(supported_collect_profiles())}


    @router.get("/api/keyword-packs")
    def keyword_packs() -> dict[str, object]:
        return {
            "command": "keyword-packs",
            "packs": list_keyword_packs(),
            "keyword_pack_library_assessment": keyword_pack_library_assessment(),
        }


    @router.post("/api/collect/plan")
    def collect_plan(request: CollectPlanRequest) -> dict[str, object]:
        try:
            return build_collect_plan(
                Path(request.root).expanduser().resolve(),
                profile=request.profile,
                input_kind=request.input_kind,
            )
        except (CollectPlanError, OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.get("/api/forensic-capabilities")
    def get_forensic_capabilities() -> dict[str, object]:
        return build_visible_capability_response()

    return router
