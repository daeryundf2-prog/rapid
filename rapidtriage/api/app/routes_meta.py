"""Health, diagnostics, and environment metadata API routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

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
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
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


def build_meta_router() -> APIRouter:
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
