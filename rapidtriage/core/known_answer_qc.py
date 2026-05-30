from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Mapping

from .docs import write_result
from .validation import (
    ValidationError,
    build_known_answer_trusted_diff,
    build_known_answer_validation,
)


KNOWN_ANSWER_QC_VERSION = "known-answer-qc-runner-v1"


def run_known_answer_qc(
    *,
    manifest_path: Path,
    output_dir: Path,
    trusted_manifest_path: Path | None = None,
    overwrite: bool = False,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise ValidationError(f"known-answer QC output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_path.expanduser().resolve()
    if not manifest_path.is_file():
        raise ValidationError(f"known-answer manifest not found: {manifest_path}")

    rapid_validation = build_known_answer_validation(manifest_path)
    trusted_validation: Mapping[str, object] | None = None
    trusted_diff: Mapping[str, object] | None = None
    if trusted_manifest_path is not None:
        trusted_manifest_path = trusted_manifest_path.expanduser().resolve()
        if not trusted_manifest_path.is_file():
            raise ValidationError(f"trusted known-answer manifest not found: {trusted_manifest_path}")
        trusted_validation = build_known_answer_validation(trusted_manifest_path)
        trusted_diff = build_known_answer_trusted_diff(rapid_validation, trusted_validation)
        rapid_validation = build_known_answer_validation(manifest_path, trusted_diff=trusted_diff)

    json_path = output_dir / "known-answer-qc.json"
    markdown_path = output_dir / "known-answer-qc.md"
    payload: dict[str, object] = {
        "command": "known-answer-qc",
        "profile_version": KNOWN_ANSWER_QC_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifest_path": str(manifest_path),
        "trusted_manifest_path": str(trusted_manifest_path) if trusted_manifest_path else "",
        "validation": rapid_validation,
        "trusted_validation": dict(trusted_validation) if trusted_validation else {},
        "trusted_diff": dict(trusted_diff) if trusted_diff else rapid_validation.get("trusted_known_answer_diff", {}),
        "summary": {
            "dataset_count": rapid_validation.get("dataset_count", 0),
            "status": rapid_validation.get("status", ""),
            "trusted_diff_status": str((trusted_diff or {}).get("status") or "missing"),
            "ready_for_court_report": bool(rapid_validation.get("ready_for_court_report")),
            "commercial_grade_ready": bool(rapid_validation.get("ready_for_court_report")),
        },
        "outputs": {"json": str(json_path), "markdown": str(markdown_path)},
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_known_answer_qc_markdown(payload), encoding="utf-8")
    return payload


def render_known_answer_qc_markdown(payload: Mapping[str, object]) -> str:
    validation = payload.get("validation") if isinstance(payload.get("validation"), Mapping) else {}
    datasets = validation.get("datasets") if isinstance(validation.get("datasets"), list) else []
    trusted_diff = payload.get("trusted_diff") if isinstance(payload.get("trusted_diff"), Mapping) else {}
    lines = [
        "# Known-Answer QC",
        "",
        f"- Status: `{validation.get('status', '')}`",
        f"- Dataset count: `{validation.get('dataset_count', 0)}`",
        f"- Trusted diff: `{trusted_diff.get('status', 'missing')}`",
        f"- Pipeline manifest hash: `{validation.get('known_answer_pipeline_manifest_hash', '')}`",
        "",
        "## Datasets",
    ]
    for row in datasets:
        if not isinstance(row, Mapping):
            continue
        lines.append(
            f"- `{row.get('id')}` status={row.get('status')} assertions={row.get('expected_assertion_count')} "
            f"evidence_hashes={row.get('evidence_hash_count')}"
        )
    blockers = validation.get("blockers") if isinstance(validation.get("blockers"), list) else []
    lines.extend(["", "## Blockers"])
    lines.extend(f"- {blocker}" for blocker in blockers)
    lines.append("")
    return "\n".join(lines)
