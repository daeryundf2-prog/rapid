"""Run-level indirect AI evidence (R7 stage 3.5 §3.4, lane C): appended to the ``ai-agent`` output.

Within one run the artifact kinds are collected in parallel, so the ``ai-agent`` provider cannot see
the Prefetch / Amcache / SRUM / ShimCache rows (other kinds) nor the files inventory (a later stage).
:func:`append_ai_indirect_rows` runs once after the files stage and adds to the ``ai-agent`` output:

* execution traces -- :func:`execution_match.execution_presence_from_artifacts_dir` over the run's
  ``artifacts/`` folder (``ai-tool-presence``, ``install_kind = execution``);
* git trailers -- :func:`git_trailers.git_trailer_rows` over the ``.git`` folders listed in the files
  inventory (``ai-code-attribution``, ``source = git-trailer``, + one ``git-repo-scan`` row per repo).

It is idempotent: rows a previous call added (same parsers) are replaced, so a resumed run never
doubles them. The JSONL is rewritten and the in-memory payload (``artifact_payloads["ai-agent"]``:
``artifact_count``, ``artifact_type_counts``, ``summary.ai_indirect``) is replaced; the run writes the
``.json`` once afterwards (the artifact stage defers it), so the file on disk is that one payload. The
``ai-agents`` provider row of the manifest (and of the docs manifest summary) gets the new count. A
failure is recorded in the returned block and never fails the run.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping, MutableMapping
from pathlib import Path

from .base import AI_PROVIDER_NAME, AiRow

__all__ = ["AI_KIND", "AI_RUN_OPTION_KEYS", "INDIRECT_PARSERS", "append_ai_indirect_rows", "normalize_run_collector_options", "retention_rows"]

AI_KIND = "ai-agent"
INDIRECT_PARSERS = frozenset({"ai-tool-execution-match", "ai-git-trailers"})


AI_RUN_OPTION_KEYS = ("ai_bodies", "ai_hash_dbs", "org_email_domain", "evidence_roots")
MAX_EVIDENCE_ROOTS = 64


def normalize_run_collector_options(value: object) -> dict[str, dict[str, object]] | None:
    """Validated ``collector_options`` of a run request: only ``ai-agent`` with ``ai_bodies`` /
    ``ai_hash_dbs`` (bool), ``org_email_domain`` (str) and ``evidence_roots`` (list of str).
    ``ValueError`` (Korean) for anything else; ``None`` when nothing is set."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("collector_options는 {종류: {옵션: 값}} 객체여야 합니다")
    unknown_kinds = sorted(str(kind) for kind in value if kind != AI_KIND)
    if unknown_kinds:
        raise ValueError(f"collector_options에서 지원하지 않는 종류입니다: {', '.join(unknown_kinds)} (가능: {AI_KIND})")
    options = value.get(AI_KIND)
    if options is None:
        return None
    if not isinstance(options, Mapping):
        raise ValueError(f"collector_options[{AI_KIND}]는 객체여야 합니다")
    unknown = sorted(str(key) for key in options if key not in AI_RUN_OPTION_KEYS)
    if unknown:
        raise ValueError(f"{AI_KIND} 옵션에 알 수 없는 키가 있습니다: {', '.join(unknown)} (가능: {', '.join(AI_RUN_OPTION_KEYS)})")
    out: dict[str, object] = {}
    for key in ("ai_bodies", "ai_hash_dbs"):
        if options.get(key) is not None:
            if not isinstance(options[key], bool):
                raise ValueError(f"{AI_KIND}.{key}는 true/false여야 합니다")
            out[key] = options[key]
    domain = options.get("org_email_domain")
    if domain is not None:
        text = str(domain).strip().lower().lstrip("@") if isinstance(domain, str) else ""
        if not isinstance(domain, str) or (text and ("." not in text or any(char.isspace() or char in "/\\@" for char in text))):
            raise ValueError(f"{AI_KIND}.org_email_domain은 이메일 도메인(예: example.com)이어야 합니다")
        if text:
            out["org_email_domain"] = text
    roots = options.get("evidence_roots")
    if roots is not None:
        if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots) or len(roots) > MAX_EVIDENCE_ROOTS:
            raise ValueError(f"{AI_KIND}.evidence_roots는 경로 문자열 목록(최대 {MAX_EVIDENCE_ROOTS}개)이어야 합니다")
        cleaned = [item.strip() for item in roots if item.strip()]
        if cleaned:
            out["evidence_roots"] = cleaned
    return {AI_KIND: out} if out else None


def _parser_of(row: Mapping[str, object]) -> str:
    details = row.get("details")
    return str(details.get("parser") or "") if isinstance(details, Mapping) else ""


def retention_rows(rows: list[Mapping[str, object]]) -> int:
    """AI records under a retention limit: tools whose presence row says the vendor deletes local
    history automatically, plus cleanup markers (``ai-retention-cleanup``)."""
    tools: set[str] = set()
    markers = 0
    for row in rows:
        details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        kind = str(row.get("artifact_type") or "")
        if kind == "ai-retention-cleanup":
            markers += 1
        elif kind == "ai-tool-presence" and details.get("retention_auto_delete") is True:  # type: ignore[union-attr]
            tools.add(str(details.get("tool") or ""))  # type: ignore[union-attr]
    return len(tools) + markers


def _patch_provider_rows(rows: object, count: int, type_counts: Mapping[str, int]) -> None:
    if not isinstance(rows, list):
        return
    for row in rows:
        if isinstance(row, MutableMapping) and row.get("name") == AI_PROVIDER_NAME:
            row["artifact_count"] = count
            if "artifact_type_counts" in row:
                row["artifact_type_counts"] = dict(type_counts)


def append_ai_indirect_rows(
    artifacts_dir: Path,
    artifact_payloads: MutableMapping[str, dict[str, object]],
    artifact_outputs: Mapping[str, Path],
    *,
    files_payload: Mapping[str, object] | None,
    manifest_payload: MutableMapping[str, object] | None = None,
    manifest_path: Path | None = None,
    manifest_summary: MutableMapping[str, object] | None = None,
) -> dict[str, object]:
    """Add the indirect rows to the run's ``ai-agent`` output (see module doc); returns a status block."""
    started = time.monotonic()
    payload = artifact_payloads.get(AI_KIND)
    artifact_path = artifact_outputs.get(AI_KIND)
    if payload is None or artifact_path is None:
        return {"status": "skipped", "reason": "ai-agent kind not collected in this run"}
    try:
        from ...core.artifact_store import ArtifactIdAllocator, adapt_artifact_row
        from ...core.artifacts import (
            finalize_artifact_payload,
            materialize_artifact_payload,
        )
        from ...core.docs import write_result
        from .execution_match import execution_presence_from_artifacts_dir
        from .git_trailers import git_trailer_rows

        new_rows: list[AiRow] = [
            *execution_presence_from_artifacts_dir(Path(artifacts_dir)),
            *git_trailer_rows(files_payload),
        ]
        materialized = materialize_artifact_payload(payload, payload_path=artifact_path)
        rows = [row for row in materialized.get("artifacts") or [] if isinstance(row, Mapping)]
        kept = [row for row in rows if _parser_of(row) not in INDIRECT_PARSERS]
        replaced = len(rows) - len(kept)
        allocator = ArtifactIdAllocator()
        root = str(payload.get("root") or "")
        appended: list[dict[str, object]] = []
        for offset, ai_row in enumerate(new_rows, start=1):
            adapted, _error = adapt_artifact_row(
                ai_row.to_record().to_dict(),
                index=len(kept) + offset,
                kind=AI_KIND,
                provider_name=AI_PROVIDER_NAME,
                root=root,
                include_fields=False,
                id_allocator=allocator,
            )
            if isinstance(adapted, dict):
                appended.append(adapted)
        all_rows: list[dict[str, object]] = [dict(row) for row in kept] + appended
        type_counts = Counter(str(row.get("artifact_type") or "") for row in all_rows)
        summary = dict(materialized.get("summary") or {}) if isinstance(materialized.get("summary"), Mapping) else {}
        summary["artifact_count"] = len(all_rows)
        summary["artifact_type_counts"] = dict(type_counts)
        block = {
            "status": "completed",
            "execution_rows": sum(1 for row in new_rows if row.parser == "ai-tool-execution-match"),
            "git_trailer_commits": sum(1 for row in new_rows if row.artifact_type == "ai-code-attribution"),
            "git_repositories": sum(1 for row in new_rows if row.payload.get("presence_kind") == "git-repo-scan"),
            "replaced_rows": replaced,
            "retention_rows": retention_rows(all_rows),
        }
        summary["ai_indirect"] = dict(block)
        materialized["summary"] = summary
        materialized["artifacts"] = all_rows
        finalized = finalize_artifact_payload(materialized, records_path=Path(artifact_path).with_suffix(".jsonl"))
        artifact_payloads[AI_KIND] = finalized
        if manifest_payload is not None:
            _patch_provider_rows(manifest_payload.get("providers"), len(all_rows), type_counts)
            if manifest_path is not None:
                write_result(dict(manifest_payload), Path(manifest_path))
        if manifest_summary is not None:
            _patch_provider_rows(manifest_summary.get("providers"), len(all_rows), type_counts)
        block["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return block
    except Exception as exc:  # indirect evidence never fails the run
        failed: dict[str, object] = {
            "status": "failed_isolated",
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        # Recorded on the payload the run writes (fresh collection) or reports (reused output).
        current = artifact_payloads.get(AI_KIND)
        if isinstance(current, dict) and isinstance(current.get("summary"), dict):
            current["summary"]["ai_indirect"] = dict(failed)
        return failed
