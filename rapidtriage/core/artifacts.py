from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path
from typing import Dict, Union

from ..artifacts import artifact_collectors, get_artifact_collector
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
) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    try:
        collector = get_artifact_collector(kind)
    except KeyError as exc:
        raise ArtifactCollectionError(str(exc)) from exc

    artifacts = [item.to_dict() for item in collector.collect(input_root.root_path)]
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
        },
        "artifacts": artifacts,
    }
    if rule_set is not None:
        annotate_artifacts_payload(payload, rule_set)
    return payload
