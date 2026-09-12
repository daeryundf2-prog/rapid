from __future__ import annotations

import datetime as dt
import hashlib
import json
import mimetypes
import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel

from ...core.evidence import identify_evidence
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.jobs import (
    RunJobStore,
    is_relative_to,
    run_output_dir,
)
from ...core.source_paths import (
    candidate_source_paths,
    source_path_resolution_diagnostics,
)
from ...core.source_reader import (
    SourceReadError,
    parse_archived_source_request,
)
from .constants import (
    LOCAL_API_HOSTS,
    SQLITE_HEADER,
    SQLITE_PREVIEW_EXTS,
)


def stable_payload_sha256(payload: Mapping[str, object] | Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def request_host(value: str | None) -> str:
    if not value:
        return ""
    host = value.strip()
    if host.startswith("["):
        return host[1:].split("]", 1)[0].lower()
    return host.rsplit(":", 1)[0].lower()


def allowed_api_hosts() -> set[str]:
    extra = {
        item.strip().lower()
        for item in os.environ.get("RAPIDTRIAGE_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }
    return LOCAL_API_HOSTS | extra


def resolve_request_reviewer(explicit: str | None) -> str | None:
    """Resolve reviewer attribution for API review marks.

    An explicit request ``reviewer`` wins; otherwise ``RAPIDTRIAGE_REVIEWER``
    supplies a server-side default for multi-examiner deployments. When
    neither is set the mark keeps the previous reviewer/empty behavior.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env_value = os.environ.get("RAPIDTRIAGE_REVIEWER", "").strip()
    return env_value or None


def get_job(store: RunJobStore, run_id: str):
    try:
        return store.get(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="run not found")


def validate_run_evidence_source(raw_root: str) -> None:
    source = Path(raw_root).expanduser()
    try:
        evidence = identify_evidence(source)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = evidence.to_dict()
    if source.is_dir():
        return
    if source.is_file() and not bool(result.get("can_extract")):
        detail = str(result.get("message") or "This evidence file cannot be scanned directly.")
        raise HTTPException(
            status_code=400,
            detail=(
                f"{detail} Mount or export the evidence first, then select the resulting folder. "
                "Use Check evidence support for adapter details."
            ),
        )


def get_job_payload(store: RunJobStore, run_id: str, *, include_summary: bool) -> dict[str, object]:
    return get_job(store, run_id).to_dict(include_summary=include_summary)


def get_named_output(store: RunJobStore, run_id: str, output_name: str) -> dict[str, object]:
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


def read_run_artifacts_for_capabilities(
    store: RunJobStore,
    run_id: str,
    summary: Mapping[str, object],
) -> dict[str, object]:
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        return {}
    artifacts: dict[str, object] = {}
    for output_name in outputs:
        name = str(output_name)
        if not name.startswith("artifacts_"):
            continue
        try:
            artifacts[name.removeprefix("artifacts_")] = store.read_output(run_id, name)
        except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError):
            artifacts[name.removeprefix("artifacts_")] = {
                "artifacts": [],
                "capability_load_error": True,
            }
    return artifacts


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
    allowed_roots = allowed_source_roots(job.summary)
    candidates = candidate_source_paths(raw_path, allowed_roots)
    scoped_candidates = [candidate for candidate in candidates if any(is_relative_to(candidate, root) for root in allowed_roots)]
    for candidate in scoped_candidates:
        if candidate.is_file():
            return candidate
    diagnostics = source_path_resolution_diagnostics(raw_path, allowed_roots)
    if scoped_candidates:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "source file not found in allowed evidence roots",
                "source_path_resolution": diagnostics,
            },
        )
    candidate = candidates[0] if candidates else Path(raw_path).expanduser().resolve()
    raise HTTPException(
        status_code=403,
        detail={
            "message": f"source file is outside allowed evidence roots: {candidate}",
            "source_path_resolution": diagnostics,
        },
    )


def parse_source_preview_archive_request(raw_path: str) -> dict[str, str] | None:
    try:
        return parse_archived_source_request(raw_path)
    except SourceReadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def allowed_source_roots(summary: dict[str, object]) -> list[Path]:
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


def case_db_roots_from_env() -> set[Path]:
    """Extra case-DB roots from RAPIDTRIAGE_CASE_DB_ROOTS (os.pathsep-separated:
    colon on POSIX, semicolon on Windows)."""
    roots: set[Path] = set()
    for item in os.environ.get("RAPIDTRIAGE_CASE_DB_ROOTS", "").split(os.pathsep):
        item = item.strip()
        if item:
            roots.add(Path(item).expanduser().resolve())
    return roots


def allowed_case_db_roots(store: RunJobStore, extra_roots: Iterable[str | Path] = ()) -> set[Path]:
    roots: set[Path] = {
        (Path.home() / ".rapidtriage").resolve(),
        Path.cwd().resolve(),
    }
    roots.update(case_db_roots_from_env())
    roots.update(Path(root).expanduser().resolve() for root in extra_roots)
    for job in store.list():
        if job.summary:
            try:
                roots.add(run_output_dir(job.summary))
            except RuntimeError:
                continue
    return roots


def case_db_path_restricted() -> bool:
    return not truthy_env("RAPIDTRIAGE_CASE_DB_UNRESTRICTED")


def _resolve_confined_case_path(
    store: RunJobStore,
    raw_path: str | Path,
    extra_roots: Iterable[str | Path],
    *,
    kind: str,
) -> Path:
    candidate = Path(raw_path).expanduser().resolve()
    if not case_db_path_restricted():
        return candidate
    roots = allowed_case_db_roots(store, extra_roots)
    if any(is_relative_to(candidate, root) for root in roots):
        return candidate
    raise HTTPException(
        status_code=403,
        detail=(
            f"{kind} path is outside allowed case-db roots: {candidate}; "
            "allowed roots are run output directories, the server working directory, "
            "~/.rapidtriage, and RAPIDTRIAGE_CASE_DB_ROOTS entries "
            "(set RAPIDTRIAGE_CASE_DB_UNRESTRICTED=1 to disable this restriction)"
        ),
    )


def resolve_case_db_path(
    store: RunJobStore,
    raw_path: str | Path,
    extra_roots: Iterable[str | Path] = (),
) -> Path:
    return _resolve_confined_case_path(store, raw_path, extra_roots, kind="case database")


def resolve_case_catalog_path(
    store: RunJobStore,
    raw_path: str | Path,
    extra_roots: Iterable[str | Path] = (),
) -> Path:
    """Case catalogs share the case-db allowed roots: catalog JSON files are
    case-management state and there is no separate RAPIDTRIAGE_CATALOG_ROOTS
    env var — use RAPIDTRIAGE_CASE_DB_ROOTS for extra roots."""
    return _resolve_confined_case_path(store, raw_path, extra_roots, kind="case catalog")


def default_submission_manifest_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-submission-manifest.json")


def default_run_validation_package_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidforensic-run-validation-package.json")


def default_case_report_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-case-report.md")


def default_reviewer_bundle_dir_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-reviewer-bundle")


def extract_tool_preflight(summary: Mapping[str, object]) -> list[object]:
    candidates: list[object] = []
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    for key in ("tool_preflight", "dependency_preflight"):
        value = source.get(key) or summary.get(key)
        if isinstance(value, list):
            candidates.extend(value)
    e01_metadata = source.get("e01_metadata") if isinstance(source.get("e01_metadata"), Mapping) else {}
    value = e01_metadata.get("tool_preflight")
    if isinstance(value, list):
        candidates.extend(value)
    return candidates


def extract_external_command_history(summary: Mapping[str, object]) -> list[object]:
    candidates: list[object] = []
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    workflow = source.get("workflow_status") if isinstance(source.get("workflow_status"), Mapping) else {}
    for container in (summary, source, workflow):
        value = container.get("command_history") if isinstance(container, Mapping) else None
        if isinstance(value, list):
            candidates.extend(value)
    return candidates


def model_to_dict(model: BaseModel) -> dict[str, object]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def preview_sandbox_core_accuracy_gates(
    *,
    source_path: Path,
    active_content_blocked: bool,
    max_chars: int,
    policy_profile: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "read-only bounded preview",
        "active content execution blocked",
        "external network access disabled",
        "preview caps recorded",
        "OS sandbox limitation warning",
        "preview sandbox policy profile emitted",
    ]
    if policy_profile and policy_profile.get("renderer_strategy"):
        satisfied.append("escaped bounded renderer strategy recorded")
    if policy_profile and policy_profile.get("source_path_sha256"):
        satisfied.append("preview policy row hashes emitted")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("preview sandbox report-grade validation plan emitted")
        satisfied.append("preview sandbox report-grade ready slots emitted")
    evidence_refs = [
        f"source_path:{source_path}",
        f"active_content_blocked:{active_content_blocked}",
        f"max_inline_text_chars:{max_chars}",
    ]
    if validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(f"preview_sandbox_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256')}")
        evidence_refs.append(f"preview_sandbox_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}")
        evidence_refs.append(f"preview_sandbox_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted preview sandbox/no-exec diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            73,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def is_probably_binary(source_path: Path, *, sample_size: int = 4096) -> bool:
    try:
        with source_path.open("rb") as handle:
            sample = handle.read(sample_size)
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.08


def is_sqlite_candidate(path: Path, suffix: str | None = None) -> bool:
    normalized_suffix = suffix if suffix is not None else path.suffix.lower()
    if normalized_suffix not in SQLITE_PREVIEW_EXTS:
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def is_image_preview_candidate(path: Path) -> bool:
    mime_type = mimetypes.guess_type(path.name)[0] or ""
    return mime_type.startswith("image/")


def stable_source_queue_id(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).encode("utf-8", errors="replace")).hexdigest()[:16]


def _hex_viewer_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("offset_hex") or row.get("offset") or "")


def _hex_viewer_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "offset": optional_int_for_api(row.get("offset")) or 0,
        "offset_hex": str(row.get("offset_hex") or ""),
        "hex": str(row.get("hex") or ""),
        "ascii": str(row.get("ascii") or ""),
    }


def _sqlite_viewer_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("name") or "")


def _sqlite_viewer_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    columns = row.get("columns") if isinstance(row.get("columns"), Sequence) else []
    rows = row.get("rows") if isinstance(row.get("rows"), Sequence) else []
    return {
        "name": str(row.get("name") or ""),
        "row_count": optional_int_for_api(row.get("row_count")),
        "schema_sha256": hashlib.sha256(str(row.get("schema_sql") or "").encode("utf-8", errors="replace")).hexdigest(),
        "columns_sha256": stable_json_sha256(list(columns)),
        "sample_rows_sha256": stable_json_sha256(list(rows)),
    }


def _email_thread_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("thread_id") or row.get("subject") or "")


def _email_thread_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    participants = row.get("participants") if isinstance(row.get("participants"), Sequence) else []
    order = row.get("message_order") if isinstance(row.get("message_order"), Sequence) else []
    return {
        "subject": str(row.get("subject") or ""),
        "message_count": optional_int_for_api(row.get("message_count")) or 0,
        "participants_sha256": stable_json_sha256(sorted(str(item) for item in participants)),
        "message_order_sha256": stable_json_sha256(list(order)),
        "attachment_count": optional_int_for_api(row.get("attachment_count")) or 0,
    }


def _media_transcript_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("path") or row.get("name") or "")


def _media_transcript_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    cues = row.get("cues") if isinstance(row.get("cues"), Sequence) else []
    preview = str(row.get("preview") or "")
    return {
        "sha256": str(row.get("sha256") or ""),
        "cue_count": optional_int_for_api(row.get("cue_count")) or len(cues),
        "cues_sha256": stable_json_sha256(list(cues)),
        "preview_sha256": hashlib.sha256(preview.encode("utf-8", errors="replace")).hexdigest() if preview else "",
    }


def stable_json_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def safe_read_text(source_path: Path, *, max_chars: int) -> str:
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_chars)
    except OSError:
        return ""


def optional_int_for_api(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compute_hashes_for_bytes(value: bytes) -> dict[str, str]:
    import hashlib

    return {
        "md5": hashlib.md5(value).hexdigest(),
        "sha1": hashlib.sha1(value).hexdigest(),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def dt_from_epoch(value: float) -> str:
    return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).isoformat()


def default_case_path(store: RunJobStore, run_id: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    output_dir = job.summary.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise HTTPException(status_code=409, detail="run summary does not include output_dir")
    return Path(output_dir).expanduser().resolve() / "rapidtriage-case.json"
