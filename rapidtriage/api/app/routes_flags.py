"""특이사항 (triage flags) routes (plan viewer-families §3.1): catalogue meta, run flag summary, row citations."""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, HTTPException, Query

from ...core.jobs import RunJobStore
from ...core.triage_rules import CatalogError, load_catalog
from .analyses import ANALYSIS_ID_PATTERN, ANALYSIS_RUNNER, read_analysis_row, run_scope
from .jsonl_records import iter_records_at
from .triage_flags import flags_join, row_citations, tree_flags_section


def build_flags_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/meta/families")
    def get_families() -> dict[str, object]:
        """The triage catalogue: ``{version, families: [{id, label, types, kinds?, prefixes?, suffixes?,
        core_columns, aux_columns, rules, sources?}], rules: [{id, family, grade, label_ko, rationale_ko,
        false_positive_ko, sources, version, status, params}]}``; columns are ``{key, label, format?,
        ts_kind?, width?, aliases?}``."""
        try:
            return load_catalog().payload()
        except CatalogError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @router.get("/api/runs/{run_id}/flags")
    def get_run_flags(run_id: str) -> dict[str, object]:
        """The run's joined flag set: ``{run_id, flags_join, flags}`` (``flags`` = the ``/tree`` section or ``null``)."""
        scope = run_scope(store, run_id, require_ready=False)
        section, _summary = tree_flags_section(scope.output_dir)
        return {"run_id": run_id, "flags_join": dict(flags_join(scope.output_dir, build_index=False).info), "flags": section}

    @router.get("/api/runs/{run_id}/flags/row")
    def get_row_flags(
        run_id: str,
        kind: str = Query(default=""),
        record_index: str = Query(default=""),
    ) -> dict[str, object]:
        """One row's flags for report citations: ``{run_id, kind, record_index, flags_join, citations:
        [{id, version, citation: "<id>@<version>", grade, label, status, evidence, note?, text}]}``.

        ``kind`` = artifact kind, ``files:candidates`` / ``files:inventory`` or ``analysis:<analysis_id>``
        (only a lookup key into the flag index; never a path). A kind the run does not have, or a
        ``record_index`` that is not an integer ≥ 0, is a Korean 422."""
        scope = run_scope(store, run_id, require_ready=False)
        index_text = record_index.strip()
        if not index_text.isdigit() or len(index_text) > 12:
            raise HTTPException(status_code=422, detail="record_index는 0 이상의 정수여야 합니다")
        record_index_value = int(index_text)
        kind = kind.strip()
        if kind not in _known_kinds(scope):
            raise HTTPException(status_code=422, detail="이 런에 없는 행 종류(kind)입니다. 아티팩트 kind, files:candidates, files:inventory, analysis:<분석 id> 중 하나여야 합니다")
        join = flags_join(scope.output_dir)
        row = _read_row(scope, kind, record_index_value) if join.index is not None else None
        return {
            "run_id": run_id,
            "kind": kind,
            "record_index": record_index_value,
            "flags_join": dict(join.info),
            "citations": row_citations(join, kind, record_index_value, row),
        }

    def _known_kinds(scope) -> set[str]:
        """Row kinds of this run: its artifact kinds, both files lists and ``analysis:<id>`` of its analyses."""
        outputs = scope.summary.get("outputs") if isinstance(scope.summary.get("outputs"), Mapping) else {}
        kinds = {str(name).removeprefix("artifacts_") for name in outputs if str(name).startswith("artifacts_")}
        if "files" in outputs:
            kinds.update({"files:candidates", "files:inventory"})
        kinds.update(
            f"analysis:{state.get('analysis_id')}"
            for state in ANALYSIS_RUNNER.list_states(scope.output_dir)
            if ANALYSIS_ID_PATTERN.fullmatch(str(state.get("analysis_id") or ""))
        )
        return kinds

    def _read_row(scope, kind: str, record_index: int) -> Mapping[str, object] | None:
        """The row as the grid serves it (by output name / validated analysis id; never a path from the request)."""
        try:
            if kind.startswith("files:"):
                rows = store.read_output(scope.run_id, "files").get(kind.removeprefix("files:"))
                row = rows[record_index] if isinstance(rows, list) and record_index < len(rows) else None
                return row if isinstance(row, Mapping) else None
            if kind.startswith("analysis:"):
                found = read_analysis_row(scope.output_dir, kind.removeprefix("analysis:"), record_index)
                return found[1] if found is not None else None
            outputs = scope.summary.get("outputs") if isinstance(scope.summary.get("outputs"), Mapping) else {}
            name = f"artifacts_{kind}"
            if name not in outputs:
                return None
            payload = store.read_output(scope.run_id, name)
            return next((row for _index, row in iter_records_at(payload, store.output_path(scope.run_id, name), [record_index])), None)
        except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError, ValueError):
            return None

    return router
