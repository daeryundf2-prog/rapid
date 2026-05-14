from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path
from typing import Dict, Union

from ..artifacts import artifact_collectors, get_artifact_collector
from .artifact_store import attach_artifact_record_contracts
from .input_root import InputRoot, resolve_input_root
from .rules import RuleSet, annotate_artifacts_payload

SUPPORTED_ARTIFACT_KINDS = tuple(sorted(artifact_collectors()))


class ArtifactCollectionError(ValueError):
    """Raised when the requested artifact collector is invalid."""


def run_artifact_collection(
    root: Union[InputRoot, Path],
    *,
    kind: str,
    input_kind: str | None = None,
    rule_set: RuleSet | None = None,
    collector_options: Dict[str, object] | None = None,
) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    try:
        collector = get_artifact_collector(kind)
    except KeyError as exc:
        raise ArtifactCollectionError(str(exc)) from exc
    if collector_options and hasattr(collector, "with_options"):
        collector = collector.with_options(**collector_options)

    parser_errors: list[dict[str, str]] = []
    collection_status = "completed"
    try:
        artifacts = [item.to_dict() for item in collector.collect(input_root.root_path)]
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

    payload = {
        "command": "artifacts",
        "kind": str(getattr(collector, "collector_kind", kind)),
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
    payload = attach_artifact_record_contracts(
        payload,
        kind=str(getattr(collector, "collector_kind", kind)),
        root=input_root.root_path,
    )
    if rule_set is not None:
        annotate_artifacts_payload(payload, rule_set)
    return payload
