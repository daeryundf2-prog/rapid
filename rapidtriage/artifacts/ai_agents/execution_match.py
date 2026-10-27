"""Execution traces of catalog AI tools (R7 stage 3.5 §3.4, lane A).

Matches the executable names in existing Prefetch / Amcache / ShimCache / SRUM / BAM / UserAssist /
PCA rows against the catalog ``binaries`` and ``process_names`` and emits ``ai-tool-presence``
rows with ``install_kind=execution`` (one per tool × trace family × executable). No parser is
re-run or changed: the input is the run's own artifact rows —

* :func:`execution_presence_rows` takes row dicts (``ArtifactRecord.to_dict()`` or the run's
  JSONL records, ``details`` or ``fields``);
* :func:`execution_presence_from_artifacts_dir` reads a finished run's
  ``artifacts/rapidtriage-artifacts-{windows-prefetch,windows-execution,windows-registry}.json``
  (+ JSONL records) read-only.

The ``ai-agent`` provider uses the second when the collector option ``execution_artifacts_dir``
names a run's artifacts folder; within one run the kinds run in parallel, so the run-level
wiring (after the artifacts stage) belongs to the derived / report stage (lane C hand-off).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from ...core.ai_catalog.catalog import AiCatalog, execution_names, load_catalog
from .base import AiRow

__all__ = [
    "EXECUTION_SOURCE_KINDS",
    "execution_family",
    "execution_presence_from_artifacts_dir",
    "execution_presence_rows",
    "iter_run_execution_rows",
]

PARSER = "ai-tool-execution-match"
EXECUTION_SOURCE_KINDS: tuple[str, ...] = ("windows-prefetch", "windows-execution", "windows-registry")
_FAMILIES: tuple[tuple[str, str], ...] = (
    ("prefetch", "prefetch"),
    ("amcache", "amcache"),
    ("shimcache", "shimcache"),
    ("srum", "srum"),
    ("bam", "bam"),
    ("userassist", "userassist"),
    ("execution-pca", "pca"),
    ("pca", "pca"),
    ("feature-usage", "feature-usage"),
    ("windows-execution", "windows-execution"),
)
_NAME_KEYS: tuple[str, ...] = (
    "executable_name",
    "header_executable_name",
    "executable_hint",
    "executable_path",
    "program_name",
    "program_path",
    "app_name",
    "app_id",
    "application",
    "file_name",
    "target_path",
    "image_path",
    "name",
)
_TIME_KEYS: tuple[str, ...] = ("timestamp", "last_run_time", "last_executed_at", "last_execution_time", "executed_at", "last_modified")
_EXE_IN_TEXT = re.compile(r"(?:^|(?<=[\\/]))([^\\/\"']+?\.(?:exe|cmd))(?=$|[-\\/\"'\s,;)])", re.IGNORECASE)
MAX_SAMPLES = 5


def execution_family(artifact_type: str) -> str:
    """``prefetch`` / ``amcache`` / ``shimcache`` / ``srum`` / ``bam`` / ``userassist`` / ``pca`` /
    ``feature-usage`` / ``windows-execution`` for an execution row type, ``""`` otherwise."""
    lowered = str(artifact_type or "").lower()
    for needle, family in _FAMILIES:
        if needle in lowered:
            return family
    return ""


def _details(row: Mapping[str, object]) -> Mapping[str, object]:
    for key in ("details", "fields"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _executables(row: Mapping[str, object], details: Mapping[str, object]) -> list[tuple[str, str]]:
    """(lower-case stem, original text) of every executable the row names."""
    found: list[tuple[str, str]] = []
    texts: list[str] = []
    for key in _NAME_KEYS:
        value = details.get(key)
        if isinstance(value, str) and value:
            texts.append(value)
    texts.append(str(row.get("path") or ""))
    for text in texts:
        for match in _EXE_IN_TEXT.finditer(text):
            name = match.group(1)
            stem = name.lower().rsplit(".", 1)[0]
            if stem and all(stem != existing for existing, _ in found):
                found.append((stem, text if len(text) <= 260 else name))
    return found


def _times(details: Mapping[str, object]) -> list[str]:
    values: list[str] = []
    for key in _TIME_KEYS:
        value = details.get(key)
        if isinstance(value, str) and len(value) >= 10 and value[:4].isdigit():
            values.append(value)
    return values


def execution_presence_rows(rows: Iterable[Mapping[str, object]], *, catalog: AiCatalog | None = None) -> list[AiRow]:
    """Aggregate execution rows into ``ai-tool-presence`` (``install_kind=execution``) rows."""
    catalog = catalog or load_catalog()
    index = execution_names(catalog)
    groups: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        family = execution_family(str(row.get("artifact_type") or ""))
        if not family:
            continue
        details = _details(row)
        for stem, original in _executables(row, details):
            tools = index.get(stem)
            if not tools:
                continue
            user = str(details.get("user") or "")
            for tool_id in tools:
                key = (tool_id, family, stem, user)
                group = groups.setdefault(
                    key,
                    {"count": 0, "times": [], "sources": [], "originals": [], "types": set(), "ambiguous": [t for t in tools if t != tool_id]},
                )
                group["count"] = int(group["count"]) + 1  # type: ignore[arg-type]
                group["times"].extend(_times(details))  # type: ignore[union-attr]
                source = str(details.get("source_path") or row.get("path") or "")
                if source and source not in group["sources"] and len(group["sources"]) < MAX_SAMPLES:  # type: ignore[arg-type]
                    group["sources"].append(source)  # type: ignore[union-attr]
                if original not in group["originals"] and len(group["originals"]) < MAX_SAMPLES:  # type: ignore[arg-type]
                    group["originals"].append(original)  # type: ignore[union-attr]
                group["types"].add(str(row.get("artifact_type") or ""))  # type: ignore[union-attr]
    result: list[AiRow] = []
    for (tool_id, family, stem, user), group in sorted(groups.items()):
        tool = catalog.tool(tool_id)
        if tool is None:
            continue
        times = sorted(group["times"])  # type: ignore[arg-type]
        last = times[-1] if times else ""
        result.append(
            AiRow(
                artifact_type="ai-tool-presence",
                tool=tool.id,
                tool_label=tool.label,
                account_key=user,
                profile_label=user,
                user=user,
                path=str(group["sources"][0]) if group["sources"] else "",  # type: ignore[index]
                timestamp=last,
                timestamp_kind="executed" if last else "",
                coverage_status=tool.coverage_status(),
                parser=PARSER,
                payload={
                    "install_kind": "execution",
                    "source": f"execution:{family}",
                    "execution_source": family,
                    "category": tool.category,
                    "vendor": tool.vendor,
                    "executable_name": stem,
                    "executable_texts": list(group["originals"]),  # type: ignore[arg-type]
                    "execution_row_count": int(group["count"]),  # type: ignore[arg-type]
                    "execution_row_types": sorted(group["types"]),  # type: ignore[arg-type]
                    "first_seen": times[0] if times else "",
                    "last_seen": last,
                    "source_paths": list(group["sources"]),  # type: ignore[arg-type]
                    "ambiguous_tools": list(group["ambiguous"]),  # type: ignore[arg-type]
                    "version": "",
                    "retention": tool.retention,
                    "retention_auto_delete": tool.retention_auto_delete,
                    "catalog_confidence": tool.confidence,
                },
            )
        )
    return result


def iter_run_execution_rows(artifacts_dir: Path, kinds: Iterable[str] = EXECUTION_SOURCE_KINDS) -> Iterator[dict[str, object]]:
    """Execution-family rows of a finished run's artifacts folder (read-only)."""
    from ...core.artifact_profiles import iter_payload_records

    for kind in kinds:
        payload_path = Path(artifacts_dir) / f"rapidtriage-artifacts-{kind}.json"
        try:
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, Mapping):
            continue
        try:
            for row in iter_payload_records(payload, payload_path=payload_path):
                if execution_family(str(row.get("artifact_type") or "")):
                    yield row
        except (OSError, ValueError):
            continue


def execution_presence_from_artifacts_dir(artifacts_dir: Path, *, catalog: AiCatalog | None = None) -> list[AiRow]:
    return execution_presence_rows(iter_run_execution_rows(artifacts_dir), catalog=catalog)
