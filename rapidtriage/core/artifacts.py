from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from ..artifacts import artifact_collectors, collect_cached, get_artifact_collector
from .artifact_profiles import (
    PROFILES_PAYLOAD_KEY,
    StreamingProfileBuilder,
    hoist_constant_blocks,
    iter_payload_records,
)
from .artifact_store import (
    adapt_artifact_row,
    artifact_record_contract_summary,
    attach_artifact_record_contracts,
)
from .input_root import InputRoot, resolve_input_root
from .json_safe import json_default
from .models import ArtifactRecord
from .rules import RuleSet, StreamingArtifactAnnotator, annotate_artifacts_payload

SUPPORTED_ARTIFACT_KINDS = tuple(sorted(artifact_collectors()))

# Rows kept inline in a JSONL-backed per-kind payload (``artifacts``); the
# full row stream lives in ``records_path`` (run-pipeline-mitigations I13).
ARTIFACT_PREVIEW_LIMIT = 200

# Collector options applied by the artifacts pipeline unless the caller
# overrides them. EVTX chunk/record-candidate structure rows are opt-in
# (``--eventlog-structure-rows``) and decoded events use the compact triage
# projection; ``record_detail="full"`` restores every per-event block.
DEFAULT_COLLECTOR_OPTIONS: dict[str, dict[str, object]] = {
    "eventlog": {"structure_rows": False, "record_detail": "triage"},
}


class ArtifactCollectionError(ValueError):
    """Raised when the requested artifact collector is invalid."""


def resolve_collector_options(kind: str, collector_options: Mapping[str, object] | None) -> dict[str, object]:
    """Pipeline defaults for ``kind`` overlaid with caller-supplied options."""
    options = dict(DEFAULT_COLLECTOR_OPTIONS.get(kind.strip().lower(), {}))
    options.update({key: value for key, value in (collector_options or {}).items() if value is not None})
    return options


def run_artifact_collection(
    root: InputRoot | Path,
    *,
    kind: str,
    input_kind: str | None = None,
    rule_set: RuleSet | None = None,
    collector_options: dict[str, object] | None = None,
    records_path: Path | None = None,
    preview_limit: int = ARTIFACT_PREVIEW_LIMIT,
    use_cache: bool = True,
) -> dict[str, object]:
    """Collect one artifact kind into a per-kind payload.

    Rows carry an ArtifactRecordV1 *envelope* (``fields`` rebuilt from
    ``details`` on demand). With ``records_path`` the provider is consumed
    as a generator and streamed to that JSONL file with per-type constant
    blocks hoisted into ``artifact_type_profiles`` (``profile_ref``); no
    per-provider row list is held (``stream_artifact_collection``), and the
    payload keeps only the first ``preview_limit`` rows plus
    ``records_path``/``record_count``. Otherwise complete rows stay inline
    (``use_cache`` then shares the per-process collect memo).
    """
    input_root = resolve_input_root(root, kind=input_kind)
    try:
        collector = get_artifact_collector(kind)
    except KeyError as exc:
        raise ArtifactCollectionError(str(exc)) from exc
    options = resolve_collector_options(str(getattr(collector, "collector_kind", kind)), collector_options)
    if options and hasattr(collector, "with_options"):
        collector = collector.with_options(**options)
    if records_path is not None:
        return stream_artifact_collection(
            collector,
            input_root,
            kind=kind,
            options=options,
            rule_set=rule_set,
            records_path=records_path,
            preview_limit=preview_limit,
        )

    parser_errors: list[dict[str, str]] = []
    collection_status = "completed"
    try:
        items = collect_cached(collector, input_root.root_path) if use_cache else list(collector.collect(input_root.root_path))
        artifacts = [item.to_dict() for item in items]
        del items
    except Exception as exc:
        artifacts = []
        collection_status = "failed-isolated"
        parser_errors.append(
            {
                "kind": kind,
                "collector": str(getattr(collector, "name", kind)),
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )
    artifact_type_counts = Counter()
    for artifact in artifacts:
        artifact_type = artifact.get("artifact_type")
        if artifact_type:
            artifact_type_counts[str(artifact_type)] += 1

    collector_kind = str(getattr(collector, "collector_kind", kind))
    payload = {
        "command": "artifacts",
        "kind": collector_kind,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "provider": {
            "name": str(collector.name),
            "description": str(collector.description),
            "target_platform": str(collector.target_platform),
            "supported": bool(collector.supported()),
        },
        "summary": {
            "artifact_count": len(artifacts),
            "artifact_type_counts": dict(artifact_type_counts),
            "parser_error_count": len(parser_errors),
            "collection_status": collection_status,
        },
        "parser_errors": parser_errors,
        "artifacts": artifacts,
    }
    if options:
        payload["collector_options"] = {key: options[key] for key in sorted(options)}
    payload = attach_artifact_record_contracts(
        payload,
        kind=collector_kind,
        root=input_root.root_path,
        include_fields=False,
    )
    if rule_set is not None:
        annotate_artifacts_payload(payload, rule_set)
    return finalize_artifact_payload(payload, records_path=records_path, preview_limit=preview_limit)


def _provider_header(collector: object) -> dict[str, object]:
    return {
        "name": str(collector.name),  # type: ignore[attr-defined]
        "description": str(collector.description),  # type: ignore[attr-defined]
        "target_platform": str(collector.target_platform),  # type: ignore[attr-defined]
        "supported": bool(collector.supported()),  # type: ignore[attr-defined]
    }


_STREAM_BUFFER_BYTES = 1 << 20


def _shallow_row(item: object) -> object:
    if isinstance(item, ArtifactRecord):
        return {
            "provider": item.provider,
            "artifact_type": item.artifact_type,
            "path": item.path,
            "supported": item.supported,
            "details": item.details,
        }
    return item.to_dict() if hasattr(item, "to_dict") else item


def _dump_row(row: object) -> str:
    return json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=json_default)


def stream_artifact_collection(
    collector: object,
    input_root: InputRoot,
    *,
    kind: str,
    options: Mapping[str, object],
    rule_set: RuleSet | None,
    records_path: Path,
    preview_limit: int = ARTIFACT_PREVIEW_LIMIT,
) -> dict[str, object]:
    """Bounded-memory collection: provider generator -> hoisted JSONL.

    Pass 1 consumes ``collector.collect`` one row at a time, attaches the
    ArtifactRecordV1 envelope (and rule annotations), feeds the per-type
    template trackers, and writes the un-hoisted row to a temporary JSONL.
    Pass 2 strips the type level and builds per-file contexts and code
    tables; pass 3 strips those and writes ``records_path``. Memory holds
    O(templates + preview) rows, never the provider's full row list. A
    provider that raises is isolated exactly like the in-memory path
    (``failed-isolated``, no rows).
    """
    collector_kind = str(getattr(collector, "collector_kind", kind))
    provider = _provider_header(collector)
    records_path = records_path.expanduser()
    records_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path = records_path.with_name(records_path.name + ".raw.tmp")
    final_tmp = records_path.with_name(records_path.name + ".tmp")
    builder = StreamingProfileBuilder()
    annotator = StreamingArtifactAnnotator(rule_set) if rule_set is not None else None
    type_counts: Counter[str] = Counter()
    contract_errors: list[dict[str, object]] = []
    valid_count = 0
    invalid_count = 0
    record_count = 0
    parser_errors: list[dict[str, str]] = []
    collection_status = "completed"
    try:
        with raw_path.open("w", encoding="utf-8", newline="\n", buffering=_STREAM_BUFFER_BYTES) as raw:
            for index, item in enumerate(collector.collect(input_root.root_path), start=1):  # type: ignore[attr-defined]
                # Rows are serialized and dropped right away and nothing below
                # mutates nested values, so the provider's details are not copied.
                row = _shallow_row(item)
                adapted, error = adapt_artifact_row(
                    row,
                    index=index,
                    kind=collector_kind,
                    provider_name=str(provider["name"] or kind),
                    root=input_root.root_path,
                    include_fields=False,
                )
                if error is None:
                    valid_count += 1
                else:
                    invalid_count += 1
                    if len(contract_errors) < 100:
                        contract_errors.append(error)
                if isinstance(adapted, dict):
                    if annotator is not None:
                        annotator.annotate(adapted)
                    artifact_type = adapted.get("artifact_type")
                    if artifact_type:
                        type_counts[str(artifact_type)] += 1
                    builder.observe(adapted)
                raw.write(_dump_row(adapted) + "\n")
                record_count += 1
    except Exception as exc:
        collection_status = "failed-isolated"
        parser_errors.append(
            {
                "kind": kind,
                "collector": str(getattr(collector, "name", kind)),
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )
        # Same as the in-memory path: an isolated failure keeps no rows.
        record_count = valid_count = invalid_count = 0
        contract_errors = []
        type_counts = Counter()
        builder = StreamingProfileBuilder()
        annotator = StreamingArtifactAnnotator(rule_set) if rule_set is not None else None
        raw_path.write_text("", encoding="utf-8")
    builder.finish_types()
    # Pass 2 is read-only (contexts/codes); pass 3 re-applies the type level
    # and writes the final rows -- cheaper than writing an intermediate file.
    with raw_path.open("r", encoding="utf-8", buffering=_STREAM_BUFFER_BYTES) as raw:
        for line in raw:
            row = json.loads(line)
            if isinstance(row, dict):
                builder.strip_type(row)
                builder.observe_context(row)
    builder.finish_contexts()
    preview: list[object] = []
    with raw_path.open("r", encoding="utf-8", buffering=_STREAM_BUFFER_BYTES) as raw, final_tmp.open(
        "w", encoding="utf-8", newline="\n", buffering=_STREAM_BUFFER_BYTES
    ) as final:
        for line in raw:
            row = json.loads(line)
            if isinstance(row, dict):
                builder.strip_type(row)
                row = builder.strip_context(row)
            if len(preview) < max(0, preview_limit):
                preview.append(row)
            final.write(_dump_row(row) + "\n")
    raw_path.unlink()
    final_tmp.replace(records_path)

    payload: dict[str, object] = {
        "command": "artifacts",
        "kind": collector_kind,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "provider": provider,
        "summary": {
            "artifact_count": record_count,
            "artifact_type_counts": dict(type_counts),
            "parser_error_count": len(parser_errors),
            "collection_status": collection_status,
            "artifact_record_contract_valid_count": valid_count,
            "artifact_record_contract_invalid_count": invalid_count,
        },
        "parser_errors": parser_errors,
        "artifacts": preview,
    }
    if options:
        payload["collector_options"] = {key: options[key] for key in sorted(options)}
    payload["artifact_record_contract"] = artifact_record_contract_summary(
        record_count=record_count,
        valid_count=valid_count,
        invalid_count=invalid_count,
        errors=contract_errors,
    )
    if annotator is not None:
        annotator.apply(payload)
    payload[PROFILES_PAYLOAD_KEY] = builder.profiles
    payload["artifacts_preview"] = True
    payload["record_count"] = record_count
    payload["records_path"] = str(records_path.resolve())
    payload["records_file"] = records_path.name
    payload["records_format"] = "jsonl"
    return payload


# Keys a JSONL-backed payload adds on top of the inline payload shape.
RECORDS_STREAM_KEYS = (
    "artifacts_preview",
    "record_count",
    "records_path",
    "records_file",
    "records_format",
)


def finalize_artifact_payload(
    payload: dict[str, object],
    *,
    records_path: Path | None = None,
    preview_limit: int = ARTIFACT_PREVIEW_LIMIT,
) -> dict[str, object]:
    """Stream rows to JSONL with per-type constant blocks hoisted.

    ``payload["artifacts"]`` must hold full (expanded) rows. With
    ``records_path``, rows are hoisted into ``artifact_type_profiles`` and
    streamed to that JSONL, and the payload keeps a ``preview_limit``-row
    ``artifacts`` preview plus ``records_path``/``records_file``/
    ``record_count``; preview rows are stored hoisted like the JSONL (top-
    level ``provider``/``artifact_type``/``path`` are always complete; use
    ``iter_payload_records`` for full ``details``). Without ``records_path`` (inline
    payloads: standalone ``rapidtriage artifacts``, API/timeline in-memory
    collections) rows stay complete and ``artifact_type_profiles`` is empty.
    """
    rows = payload.get("artifacts")
    rows = rows if isinstance(rows, list) else []
    profiles = hoist_constant_blocks(rows)[1] if records_path is not None else {}
    payload["artifacts"] = rows
    payload[PROFILES_PAYLOAD_KEY] = profiles
    for key in RECORDS_STREAM_KEYS:
        payload.pop(key, None)
    if records_path is not None:
        record_count = write_artifact_records_jsonl(rows, records_path)
        payload["artifacts"] = rows[: max(0, preview_limit)]
        payload["artifacts_preview"] = True
        payload["record_count"] = record_count
        payload["records_path"] = str(records_path.expanduser().resolve())
        payload["records_file"] = records_path.name
        payload["records_format"] = "jsonl"
    return payload


def materialize_artifact_payload(
    payload: Mapping[str, object],
    *,
    payload_path: Path | None = None,
) -> dict[str, object]:
    """Inline, profile-expanded copy of a per-kind payload (inverse of finalize).

    Used where whole-row lists are required (evidence-delta merges).
    """
    rows = list(iter_payload_records(payload, payload_path=payload_path, expand=True))
    materialized = {
        key: value
        for key, value in payload.items()
        if key not in RECORDS_STREAM_KEYS and key != PROFILES_PAYLOAD_KEY
    }
    materialized["artifacts"] = rows
    return materialized


def write_artifact_records_jsonl(rows: list[object], records_path: Path) -> int:
    """Stream artifact rows to ``records_path`` (one compact JSON object per line)."""
    records_path = records_path.expanduser()
    records_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = records_path.with_name(records_path.name + ".tmp")
    count = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=json_default))
            handle.write("\n")
            count += 1
    temporary.replace(records_path)
    return count
