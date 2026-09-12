"""Cross-case correlation across multiple case databases (R-8a).

Given N case database paths, find shared entities across case scopes:
file content hashes, file paths, and artifact identifiers. Emits a stable,
deterministically-ordered JSON correlation report.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from pathlib import Path

from .case_db.base import normalize_identifier
from .case_db.schema import assert_supported_existing_schema_version, list_tables
from .docs import write_result

__all__ = [
    "CROSS_CASE_DEFAULT_REPORT_NAME",
    "CROSS_CASE_REPORT_VERSION",
    "CrossCaseError",
    "correlate_case_databases",
    "resolve_cross_case_output",
    "write_cross_case_report",
]

CROSS_CASE_REPORT_VERSION = "cross-case-correlation-v1"
CROSS_CASE_DEFAULT_REPORT_NAME = "cross-case-correlation.json"
CROSS_CASE_MAX_SHARED = 5000
CROSS_CASE_MAX_OCCURRENCES = 200
_REQUIRED_TABLES = {"case_record", "file_record", "artifact"}
_HASH_COLUMNS: tuple[tuple[str, str], ...] = (
    ("md5", "hash_md5"),
    ("sha1", "hash_sha1"),
    ("sha256", "hash_sha256"),
)


class CrossCaseError(ValueError):
    """Raised when a cross-case correlation request is invalid."""


def _open_readonly(path: Path) -> sqlite3.Connection:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise CrossCaseError(f"case database not found: {resolved}")
    try:
        assert_supported_existing_schema_version(resolved)
    except Exception as exc:
        raise CrossCaseError(f"unsupported case DB: {resolved}: {exc}") from exc
    try:
        uri = f"file:{resolved}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.DatabaseError as exc:
        raise CrossCaseError(f"cannot open case DB {resolved}: {exc}") from exc
    missing = _REQUIRED_TABLES - set(list_tables(connection))
    if missing:
        connection.close()
        raise CrossCaseError(
            f"{resolved} is missing required case DB tables: {', '.join(sorted(missing))}"
        )
    return connection


def _scope_label(database_path: Path, case_id: str) -> str:
    return f"{database_path.name}:{case_id}"


def _occurrence(database_path: Path, case_id: str, citation_id: str, **extra: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "database": str(database_path),
        "case_id": case_id,
        "citation_id": citation_id,
        "scope": _scope_label(database_path, case_id),
    }
    entry.update({key: value for key, value in extra.items() if value not in (None, "")})
    return entry


def _normalized_path(raw_path: object, normalized: object) -> str:
    text = str(normalized or "").strip() or str(raw_path or "").strip()
    return text.replace("\\", "/").lower()


def correlate_case_databases(
    database_paths: Sequence[Path],
    *,
    case_ids: Sequence[str] | None = None,
    max_shared: int = CROSS_CASE_MAX_SHARED,
) -> dict[str, object]:
    """Correlate shared hashes, paths, and artifact identifiers across case DBs."""
    resolved_paths = [Path(path).expanduser().resolve() for path in database_paths]
    if len(resolved_paths) < 2:
        raise CrossCaseError("cross-case correlation requires at least two case databases")
    wanted_cases = {
        normalize_identifier(case_id, fallback="") for case_id in (case_ids or [])
    }
    wanted_cases.discard("")

    hash_index: dict[tuple[str, str], list[dict[str, object]]] = {}
    path_index: dict[str, list[dict[str, object]]] = {}
    artifact_index: dict[tuple[str, str], list[dict[str, object]]] = {}
    scopes: list[dict[str, object]] = []

    for database_path in resolved_paths:
        with closing(_open_readonly(database_path)) as connection:
            case_rows = connection.execute(
                "SELECT case_id, name FROM case_record ORDER BY case_id ASC"
            ).fetchall()
            for case_row in case_rows:
                case_id = str(case_row["case_id"])
                if wanted_cases and case_id not in wanted_cases:
                    continue
                file_rows = connection.execute(
                    """
                    SELECT citation_id, path, normalized_path,
                           hash_md5, hash_sha1, hash_sha256
                    FROM file_record WHERE case_id = ? ORDER BY id ASC
                    """,
                    (case_id,),
                ).fetchall()
                artifact_rows = connection.execute(
                    """
                    SELECT citation_id, artifact_type, title
                    FROM artifact WHERE case_id = ? ORDER BY id ASC
                    """,
                    (case_id,),
                ).fetchall()
                scopes.append(
                    {
                        "database": str(database_path),
                        "case_id": case_id,
                        "scope": _scope_label(database_path, case_id),
                        "file_record_count": len(file_rows),
                        "artifact_count": len(artifact_rows),
                    }
                )
                for row in file_rows:
                    citation_id = str(row["citation_id"])
                    path = str(row["path"] or "")
                    for algorithm, column in _HASH_COLUMNS:
                        value = str(row[column] or "").strip().lower()
                        if not value:
                            continue
                        hash_index.setdefault((algorithm, value), []).append(
                            _occurrence(database_path, case_id, citation_id, path=path)
                        )
                    normalized = _normalized_path(path, row["normalized_path"])
                    if normalized:
                        path_index.setdefault(normalized, []).append(
                            _occurrence(database_path, case_id, citation_id, path=path)
                        )
                for row in artifact_rows:
                    identifier = (
                        str(row["artifact_type"] or ""),
                        str(row["title"] or ""),
                    )
                    if not identifier[0]:
                        continue
                    artifact_index.setdefault(identifier, []).append(
                        _occurrence(
                            database_path,
                            case_id,
                            str(row["citation_id"]),
                            artifact_type=identifier[0],
                            title=identifier[1],
                        )
                    )

    if len(scopes) < 2:
        raise CrossCaseError(
            "cross-case correlation requires at least two case scopes"
            + (" matching --case-id" if wanted_cases else "")
        )

    def shared_entries(index: Mapping[object, list[dict[str, object]]]) -> list[tuple[object, list[dict[str, object]]]]:
        shared = [
            (key, occurrences)
            for key, occurrences in index.items()
            if len({entry["scope"] for entry in occurrences}) >= 2
        ]
        return sorted(shared, key=lambda item: (str(item[0]), str(item[1][0].get("citation_id") or "")))

    limit = max(1, int(max_shared))

    shared_hashes: list[dict[str, object]] = []
    truncated = False
    for (algorithm, value), occurrences in shared_entries(hash_index):
        if len(shared_hashes) >= limit:
            truncated = True
            break
        shared_hashes.append(
            {
                "algorithm": algorithm,
                "value": value,
                "occurrences": sorted(
                    occurrences,
                    key=lambda entry: (str(entry["scope"]), str(entry["citation_id"])),
                )[:CROSS_CASE_MAX_OCCURRENCES],
                "occurrence_count": len(occurrences),
                "scope_count": len({entry["scope"] for entry in occurrences}),
            }
        )

    shared_paths: list[dict[str, object]] = []
    for normalized, occurrences in shared_entries(path_index):
        if len(shared_paths) >= limit:
            truncated = True
            break
        shared_paths.append(
            {
                "normalized_path": normalized,
                "occurrences": sorted(
                    occurrences,
                    key=lambda entry: (str(entry["scope"]), str(entry["citation_id"])),
                )[:CROSS_CASE_MAX_OCCURRENCES],
                "occurrence_count": len(occurrences),
                "scope_count": len({entry["scope"] for entry in occurrences}),
            }
        )

    shared_artifacts: list[dict[str, object]] = []
    for (artifact_type, title), occurrences in shared_entries(artifact_index):
        if len(shared_artifacts) >= limit:
            truncated = True
            break
        shared_artifacts.append(
            {
                "artifact_type": artifact_type,
                "title": title,
                "occurrences": sorted(
                    occurrences,
                    key=lambda entry: (str(entry["scope"]), str(entry["citation_id"])),
                )[:CROSS_CASE_MAX_OCCURRENCES],
                "occurrence_count": len(occurrences),
                "scope_count": len({entry["scope"] for entry in occurrences}),
            }
        )

    pair_counts: dict[tuple[str, str], int] = {}
    for group in (shared_hashes, shared_paths, shared_artifacts):
        for entry in group:
            scope_names = sorted({occ["scope"] for occ in entry["occurrences"]})
            for index, left in enumerate(scope_names):
                for right in scope_names[index + 1 :]:
                    pair_counts[(left, right)] = pair_counts.get((left, right), 0) + 1
    correlated_pairs = [
        {"left_scope": left, "right_scope": right, "shared_entity_count": count}
        for (left, right), count in sorted(pair_counts.items())
    ]

    report = {
        "command": "cross-case-correlate",
        "profile_version": CROSS_CASE_REPORT_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "databases": [str(path) for path in resolved_paths],
        "case_id_filter": sorted(wanted_cases),
        "scopes": sorted(scopes, key=lambda scope: (str(scope["database"]), str(scope["case_id"]))),
        "summary": {
            "scope_count": len(scopes),
            "shared_hash_count": len(shared_hashes),
            "shared_path_count": len(shared_paths),
            "shared_artifact_identifier_count": len(shared_artifacts),
            "correlated_scope_pair_count": len(correlated_pairs),
            "truncated": truncated,
        },
        "shared_hashes": shared_hashes,
        "shared_paths": shared_paths,
        "shared_artifact_identifiers": shared_artifacts,
        "correlated_scope_pairs": correlated_pairs,
        "commercial_claim_allowed": False,
    }
    report["report_hash"] = hashlib.sha256(
        json.dumps(
            {
                "scopes": report["scopes"],
                "shared_hashes": report["shared_hashes"],
                "shared_paths": report["shared_paths"],
                "shared_artifact_identifiers": report["shared_artifact_identifiers"],
                "correlated_scope_pairs": report["correlated_scope_pairs"],
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return report


def resolve_cross_case_output(
    database_paths: Sequence[Path],
    output: Path | None,
) -> Path:
    if output is not None:
        return output.expanduser().resolve()
    first = Path(database_paths[0]).expanduser().resolve()
    return first.parent / CROSS_CASE_DEFAULT_REPORT_NAME


def write_cross_case_report(payload: Mapping[str, object], output: Path) -> Path:
    resolved = output.expanduser().resolve()
    write_result(dict(payload), resolved)
    return resolved
