"""Per-rule fixtures of the triage-flag rule library (``rapidtriage.core.triage_rules``).

Each family module defines ``CASES: dict[str, dict[str, Case]]`` --
``{rule_id: {"positive": Case, "negative": Case}}`` -- where a case is a
small synthetic run: rows plus the rows the rule must flag. ``run_case``
writes the rows as a run output (inline per-kind artifacts payloads, a files
output, analysis ``rows.jsonl`` files) and runs the *whole* engine over it, so
cross-row context (removable letters, host names, the file listing, …) works
exactly as on a real run.

Row spec (one dict per row, kept in the given order):

* ``{"kind": "<artifact kind>", "row": {"artifact_type": ..., "path"?: ..., "details": {...}}}``
* ``{"files": "candidates" | "inventory", "row": {"path": ..., "name": ..., ...}}``
* ``{"analysis": "<analysis kind>", "row": {"artifact_type": "<kind>-row", "details": {...}}}``

``flagged`` lists the positions (in ``rows``) the rule must flag -- exactly
those, no others. A negative case has ``flagged: []`` and usually is the
positive case with the one property changed that the catalogue's
false-positive note warns about. Optional ``params`` override the rule's
catalogue params, ``incident`` = ``(start, end)`` ISO strings.
"""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypedDict

from rapidtriage.core.triage_rules.engine import (
    FLAGS_FILE_NAME,
    TriageInputs,
    run_triage_flags,
)


class Case(TypedDict, total=False):
    rows: list[dict[str, Any]]
    flagged: list[int]
    params: dict[str, Any]
    incident: tuple[str | None, str | None]


def row_refs(rows: list[Mapping[str, Any]]) -> list[tuple[str, int]]:
    """``(flag kind, record_index)`` of every row spec, in order."""
    counters: dict[str, int] = defaultdict(int)
    refs: list[tuple[str, int]] = []
    for spec in rows:
        if "files" in spec:
            kind = f"files:{spec['files']}"
        elif "analysis" in spec:
            kind = f"analysis:a-{spec['analysis']}"
        else:
            kind = str(spec["kind"])
        refs.append((kind, counters[kind]))
        counters[kind] += 1
    return refs


def run_case(case: Mapping[str, Any], rule_id: str, *, base: Path | None = None) -> tuple[set[tuple[str, int]], set[tuple[str, int]], dict[str, Any]]:
    """``(refs the rule flagged, refs expected, engine summary)`` of one case."""
    rows = list(case.get("rows") or [])
    refs = row_refs(rows)
    with tempfile.TemporaryDirectory(dir=base) as temp:
        root = Path(temp)
        kinds: dict[str, list[dict[str, Any]]] = defaultdict(list)
        files: dict[str, list[dict[str, Any]]] = defaultdict(list)
        analyses: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for spec in rows:
            if "files" in spec:
                files[str(spec["files"])].append(dict(spec["row"]))
            elif "analysis" in spec:
                analyses[str(spec["analysis"])].append(dict(spec["row"]))
            else:
                kinds[str(spec["kind"])].append(dict(spec["row"]))
        artifact_paths: dict[str, Path] = {}
        for kind, kind_rows in kinds.items():
            path = root / f"artifacts_{kind}.json"
            path.write_text(json.dumps({"artifacts": kind_rows, "record_count": len(kind_rows)}), encoding="utf-8")
            artifact_paths[kind] = path
        files_path = None
        if files:
            files_path = root / "files.json"
            files_path.write_text(json.dumps(dict(files)), encoding="utf-8")
        analysis_inputs = []
        for kind, kind_rows in analyses.items():
            rows_path = root / f"rows-{kind}.jsonl"
            rows_path.write_text("".join(json.dumps(row) + "\n" for row in kind_rows), encoding="utf-8")
            analysis_inputs.append((f"a-{kind}", kind, rows_path, len(kind_rows)))
        incident = case.get("incident") or (None, None)
        out = root / "out"
        summary = run_triage_flags(
            TriageInputs(output_dir=root, artifact_payloads=artifact_paths, files_path=files_path, analyses=analysis_inputs),
            out,
            source_label="test",
            params={rule_id: dict(case["params"])} if case.get("params") else None,
            incident_start=incident[0],
            incident_end=incident[1],
        )
        flagged: set[tuple[str, int]] = set()
        with open(out / FLAGS_FILE_NAME, encoding="utf-8") as handle:
            for line in handle:
                entry = json.loads(line)
                if any(flag["id"] == rule_id for flag in entry["flags"]):
                    flagged.add((entry["kind"], entry["record_index"]))
    expected = {refs[position] for position in case.get("flagged") or []}
    return flagged, expected, summary


def all_cases() -> dict[str, dict[str, Case]]:
    """Every family module's ``CASES`` merged (import errors propagate)."""
    import importlib
    import pkgutil

    merged: dict[str, dict[str, Case]] = {}
    for module_info in pkgutil.iter_modules(__path__):
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        for rule_id, cases in getattr(module, "CASES", {}).items():
            if rule_id in merged:
                raise ValueError(f"duplicate triage cases for {rule_id}")
            merged[rule_id] = cases
    return merged
