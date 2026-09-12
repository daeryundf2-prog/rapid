"""CASE/UCO JSON-LD export for case database contents.

R-7a: RapidTriage does not bundle a CASE/UCO library, so this module emits
spec-shaped JSON-LD by hand. The document follows the CASE/UCO namespace
conventions (``uco-core``, ``uco-observable``, ``case-investigation``) so a
downstream CASE-aware consumer can map it onto real ontology classes.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path

from .case_db.base import CaseDatabaseError, normalize_identifier
from .case_db.helpers import parse_json_object
from .case_db.schema import get_schema_version
from .docs import write_result

__all__ = [
    "CASE_UCO_CONTEXT",
    "CASE_UCO_EXPORT_VERSION",
    "CaseExportError",
    "build_case_uco_document",
    "case_uco_default_output",
    "export_case_uco_jsonld",
    "resolve_case_uco_output",
]

CASE_UCO_EXPORT_VERSION = "case-uco-jsonld-export-v1"
CASE_UCO_DEFAULT_MAX_ROWS = 25000
CASE_UCO_CONTEXT: dict[str, str] = {
    "kb": "https://rapidtriage.local/kb/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "uco-vocabulary": "https://ontology.unifiedcyberontology.org/uco/vocabulary/",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "rapidtriage": "https://rapidtriage.local/schema/",
}
_HASH_COLUMNS: tuple[tuple[str, str], ...] = (
    ("MD5", "hash_md5"),
    ("SHA1", "hash_sha1"),
    ("SHA256", "hash_sha256"),
)
_EXPORT_TABLES: tuple[str, ...] = (
    "evidence_source",
    "file_record",
    "artifact",
    "event",
    "hash_record",
    "acquisition_metadata",
)


class CaseExportError(ValueError):
    """Raised when a case export request is invalid."""


def _iso_literal(value: object) -> dict[str, str] | None:
    text = str(value or "").strip()
    if not text:
        return None
    return {"@type": "xsd:dateTime", "@value": text}


def _node_id(kind: str, citation_id: str, row_id: object) -> str:
    slug = normalize_identifier(str(citation_id or ""), fallback=f"{kind}-{row_id}")
    return f"kb:{kind}-{slug}"


def _hash_facets(row: Mapping[str, object]) -> list[dict[str, object]]:
    hashes: list[dict[str, object]] = []
    for method, column in _HASH_COLUMNS:
        value = str(row.get(column) or "").strip()
        if not value:
            continue
        hashes.append(
            {
                "@type": "uco-types:Hash",
                "uco-types:hashMethod": {"@type": "uco-vocabulary:HashNameVocab", "@value": method},
                "uco-types:hashValue": {"@type": "xsd:hexBinary", "@value": value.lower()},
            }
        )
    return hashes


def _file_record_node(row: Mapping[str, object]) -> dict[str, object]:
    path = str(row["path"] or "")
    name = Path(path).name or path or str(row["citation_id"])
    file_facet: dict[str, object] = {
        "@type": "uco-observable:FileFacet",
        "uco-observable:fileName": name,
        "uco-observable:filePath": path,
        "uco-observable:extension": str(row["extension"] or ""),
        "uco-observable:isAllocated": not bool(row["is_deleted"]),
    }
    if row["size_bytes"] is not None:
        file_facet["uco-observable:sizeInBytes"] = int(row["size_bytes"])
    for key, column in (
        ("modifiedTime", "modified_at"),
        ("accessedTime", "accessed_at"),
        ("createdTime", "created_at"),
        ("metadataChangeTime", "changed_at"),
    ):
        literal = _iso_literal(row[column])
        if literal:
            file_facet[f"uco-observable:{key}"] = literal
    content_facet: dict[str, object] = {"@type": "uco-observable:ContentDataFacet"}
    if row["size_bytes"] is not None:
        content_facet["uco-observable:sizeInBytes"] = int(row["size_bytes"])
    hashes = _hash_facets(row)
    if hashes:
        content_facet["uco-observable:hash"] = hashes
    node: dict[str, object] = {
        "@id": _node_id("file", str(row["citation_id"]), row["id"]),
        "@type": ["uco-core:UcoObject", "uco-observable:ObservableObject", "uco-observable:File"],
        "uco-core:name": name,
        "uco-core:hasFacet": [file_facet, content_facet],
        "rapidtriage:citationId": str(row["citation_id"]),
        "rapidtriage:fileRecordId": int(row["id"]),
        "rapidtriage:isDeleted": bool(row["is_deleted"]),
        "rapidtriage:isRecovered": bool(row["is_recovered"]),
    }
    if row["mime_type"]:
        node["rapidtriage:mimeType"] = str(row["mime_type"])
    return node


def _artifact_node(row: Mapping[str, object]) -> dict[str, object]:
    data = parse_json_object(str(row["data_json"] or "{}"))
    facet: dict[str, object] = {
        "@type": "rapidtriage:ArtifactFacet",
        "rapidtriage:artifactType": str(row["artifact_type"]),
        "rapidtriage:parserName": str(row["parser_name"] or ""),
        "rapidtriage:parserVersion": str(row["parser_version"] or ""),
        "rapidtriage:data": data,
    }
    if row["confidence"] is not None:
        facet["rapidtriage:confidence"] = float(row["confidence"])
    node: dict[str, object] = {
        "@id": _node_id("artifact", str(row["citation_id"]), row["id"]),
        "@type": ["uco-core:UcoObject", "uco-observable:ObservableObject"],
        "uco-core:name": str(row["title"] or row["artifact_type"]),
        "uco-core:hasFacet": [facet],
        "rapidtriage:citationId": str(row["citation_id"]),
        "rapidtriage:artifactId": int(row["id"]),
        "rapidtriage:artifactType": str(row["artifact_type"]),
    }
    if row["summary"]:
        node["uco-core:description"] = str(row["summary"])
    created = _iso_literal(row["created_at"])
    if created:
        node["uco-core:objectCreatedTime"] = created
    return node


def _event_node(row: Mapping[str, object]) -> dict[str, object]:
    node: dict[str, object] = {
        "@id": _node_id("event", str(row["citation_id"]), row["id"]),
        "@type": ["uco-core:UcoObject", "uco-action:Action"],
        "uco-core:name": str(row["event_type"]),
        "uco-action:name": str(row["action"] or row["event_type"]),
        "uco-action:description": str(row["description"] or ""),
        "rapidtriage:citationId": str(row["citation_id"]),
        "rapidtriage:eventId": int(row["id"]),
        "rapidtriage:eventType": str(row["event_type"]),
        "rapidtriage:eventSource": str(row["source"] or ""),
    }
    timestamp = _iso_literal(row["timestamp"])
    if timestamp:
        node["uco-action:startTime"] = timestamp
    if row["actor"]:
        node["uco-action:actor"] = {"uco-core:name": str(row["actor"])}
    if row["confidence"] is not None:
        node["rapidtriage:confidence"] = float(row["confidence"])
    return node


def _hash_record_node(row: Mapping[str, object]) -> dict[str, object]:
    facet = {
        "@type": "rapidtriage:HashRecordFacet",
        "rapidtriage:hashScope": str(row["hash_scope"] or ""),
        "rapidtriage:targetType": str(row["target_type"] or ""),
        "rapidtriage:targetCitationId": str(row["target_id"] or ""),
        "rapidtriage:calculatedAt": str(row["calculated_at"] or ""),
    }
    return {
        "@id": _node_id("hash", str(row["citation_id"]), row["id"]),
        "@type": ["uco-core:UcoObject", "uco-observable:ObservableObject"],
        "uco-core:name": f"{row['algorithm']} {row['hash_scope']} hash",
        "uco-core:hasFacet": [
            facet,
            {
                "@type": "uco-observable:ContentDataFacet",
                "uco-observable:hash": [
                    {
                        "@type": "uco-types:Hash",
                        "uco-types:hashMethod": {
                            "@type": "uco-vocabulary:HashNameVocab",
                            "@value": str(row["algorithm"]).upper(),
                        },
                        "uco-types:hashValue": {
                            "@type": "xsd:hexBinary",
                            "@value": str(row["value"]).lower(),
                        },
                    }
                ],
            },
        ],
        "rapidtriage:citationId": str(row["citation_id"]),
        "rapidtriage:hashRecordId": int(row["id"]),
    }


def _relationship_node(
    rel_id: str,
    *,
    source: str,
    target: str,
    kind: str,
) -> dict[str, object]:
    return {
        "@id": rel_id,
        "@type": ["uco-core:UcoObject", "uco-observable:ObservableRelationship"],
        "uco-core:source": {"@id": source},
        "uco-core:target": {"@id": target},
        "uco-core:kindOfRelationship": kind,
        "uco-core:isDirectional": True,
    }


def _evidence_provenance_node(
    row: Mapping[str, object],
    *,
    child_ids: Sequence[str],
    acquisition: Mapping[str, object] | None,
) -> dict[str, object]:
    citation_id = str(row["citation_id"])
    node: dict[str, object] = {
        "@id": _node_id("provenance", citation_id, row["id"]),
        "@type": ["uco-core:UcoObject", "case-investigation:ProvenanceRecord"],
        "uco-core:name": str(row["display_name"] or citation_id),
        "uco-core:description": (
            f"{row['source_type']} evidence source imported from {row['original_path']}"
        ),
        "case-investigation:exhibitNumber": citation_id,
        "rapidtriage:citationId": citation_id,
        "rapidtriage:evidenceSourceId": int(row["id"]),
        "rapidtriage:sourceType": str(row["source_type"] or ""),
        "rapidtriage:originalPath": str(row["original_path"] or ""),
        "rapidtriage:stagedPath": str(row["staged_path"] or ""),
        "rapidtriage:sourceStatus": str(row["status"] or ""),
        "rapidtriage:detectedFormat": str(row["detected_format"] or ""),
        "rapidtriage:adapterName": str(row["adapter_name"] or ""),
        "rapidtriage:adapterVersion": str(row["adapter_version"] or ""),
    }
    added = _iso_literal(row["added_at"])
    if added:
        node["uco-core:objectCreatedTime"] = added
    hashes = _hash_facets(row)
    if hashes or row["size_bytes"] is not None:
        content_facet: dict[str, object] = {"@type": "uco-observable:ContentDataFacet"}
        if row["size_bytes"] is not None:
            content_facet["uco-observable:sizeInBytes"] = int(row["size_bytes"])
        if hashes:
            content_facet["uco-observable:hash"] = hashes
        node["uco-core:hasFacet"] = [content_facet]
    if child_ids:
        node["uco-core:object"] = [{"@id": child_id} for child_id in child_ids]
    if acquisition:
        node["rapidtriage:acquisition"] = {
            key: str(acquisition.get(key) or "")
            for key in (
                "citation_id",
                "operator",
                "acquisition_started_at",
                "acquisition_completed_at",
                "source_identifier",
                "write_blocker",
                "acquisition_tool",
                "acquisition_tool_version",
                "whole_source_sha256",
                "notes",
            )
            if str(acquisition.get(key) or "")
        }
    return node


def _acquisition_provenance_node(row: Mapping[str, object], *, linked_id: str | None) -> dict[str, object]:
    citation_id = str(row["citation_id"])
    node: dict[str, object] = {
        "@id": _node_id("acquisition", citation_id, row["id"]),
        "@type": ["uco-core:UcoObject", "case-investigation:ProvenanceRecord"],
        "uco-core:name": f"acquisition metadata {citation_id}",
        "uco-core:description": str(row["notes"] or "acquisition record"),
        "case-investigation:exhibitNumber": citation_id,
        "rapidtriage:citationId": citation_id,
        "rapidtriage:operator": str(row["operator"] or ""),
        "rapidtriage:acquisitionTool": str(row["acquisition_tool"] or ""),
        "rapidtriage:acquisitionToolVersion": str(row["acquisition_tool_version"] or ""),
        "rapidtriage:sourceIdentifier": str(row["source_identifier"] or ""),
        "rapidtriage:writeBlocker": str(row["write_blocker"] or ""),
    }
    if row["whole_source_sha256"]:
        node["rapidtriage:wholeSourceSha256"] = str(row["whole_source_sha256"])
    started = _iso_literal(row["acquisition_started_at"])
    if started:
        node["uco-action:startTime"] = started
    completed = _iso_literal(row["acquisition_completed_at"])
    if completed:
        node["uco-action:endTime"] = completed
    if linked_id:
        node["uco-core:object"] = [{"@id": linked_id}]
    return node


def _select_rows(
    connection: sqlite3.Connection,
    table: str,
    case_id: str,
    order_by: str,
    max_rows: int,
) -> list[dict[str, object]]:
    return [
        dict(row)
        for row in connection.execute(
            f"SELECT * FROM {table} WHERE case_id = ? ORDER BY {order_by} LIMIT ?",
            (case_id, max_rows),
        ).fetchall()
    ]


def _table_count(connection: sqlite3.Connection, table: str, case_id: str) -> int:
    row = connection.execute(
        f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    return int(row["count"]) if row is not None else 0


def build_case_uco_document(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    max_rows: int = CASE_UCO_DEFAULT_MAX_ROWS,
) -> dict[str, object]:
    """Build a CASE/UCO-shaped JSON-LD document for one case."""
    normalized_case_id = normalize_identifier(case_id, fallback="case")
    limit = max(1, int(max_rows))
    case_row = connection.execute(
        "SELECT * FROM case_record WHERE case_id = ?",
        (normalized_case_id,),
    ).fetchone()
    if case_row is None:
        raise CaseExportError(f"case not found: {normalized_case_id}")

    rows: dict[str, list[dict[str, object]]] = {
        "evidence_source": _select_rows(
            connection, "evidence_source", normalized_case_id, "id ASC", limit
        ),
        "file_record": _select_rows(
            connection, "file_record", normalized_case_id, "id ASC", limit
        ),
        "artifact": _select_rows(
            connection, "artifact", normalized_case_id, "id ASC", limit
        ),
        "event": _select_rows(connection, "event", normalized_case_id, "id ASC", limit),
        "hash_record": _select_rows(
            connection, "hash_record", normalized_case_id, "id ASC", limit
        ),
        "acquisition_metadata": _select_rows(
            connection, "acquisition_metadata", normalized_case_id, "id ASC", limit
        ),
    }
    row_counts = {
        table: _table_count(connection, table, normalized_case_id)
        for table in _EXPORT_TABLES
    }
    truncated_tables = [
        table for table in _EXPORT_TABLES if row_counts[table] > len(rows[table])
    ]

    nodes: list[dict[str, object]] = []
    node_ids: set[str] = set()
    file_node_by_row_id: dict[int, str] = {}
    artifact_node_by_row_id: dict[int, str] = {}
    node_id_by_citation: dict[str, str] = {}
    evidence_children: dict[int, list[str]] = {}

    def register(node: dict[str, object]) -> str:
        node_id = str(node["@id"])
        nodes.append(node)
        node_ids.add(node_id)
        citation = str(node.get("rapidtriage:citationId") or "")
        if citation:
            node_id_by_citation.setdefault(citation, node_id)
        return node_id

    def track_child(evidence_source_id: object, node_id: str) -> None:
        if evidence_source_id is None:
            return
        evidence_children.setdefault(int(evidence_source_id), []).append(node_id)

    for file_row in rows["file_record"]:
        node = _file_record_node(file_row)
        node_id = register(node)
        file_node_by_row_id[int(file_row["id"])] = node_id
        track_child(file_row["evidence_source_id"], node_id)

    relationships: list[dict[str, object]] = []
    for artifact_row in rows["artifact"]:
        node = _artifact_node(artifact_row)
        node_id = register(node)
        artifact_node_by_row_id[int(artifact_row["id"])] = node_id
        track_child(artifact_row["evidence_source_id"], node_id)

    for event_row in rows["event"]:
        node = _event_node(event_row)
        node_id = register(node)
        track_child(event_row["evidence_source_id"], node_id)

    for hash_row in rows["hash_record"]:
        node = _hash_record_node(hash_row)
        register(node)

    # Evidence-source provenance records reference their child observables.
    acquisitions_by_source: dict[str, dict[str, object]] = {}
    acquisition_rows = rows["acquisition_metadata"]
    evidence_rows = rows["evidence_source"]
    evidence_ids_by_citation = {
        str(row["citation_id"]): _node_id("provenance", str(row["citation_id"]), row["id"])
        for row in evidence_rows
    }
    for evidence_row in evidence_rows:
        citation_id = str(evidence_row["citation_id"])
        acquisition = next(
            (
                row
                for row in acquisition_rows
                if str(row["evidence_source_citation_id"] or "") == citation_id
            ),
            None,
        )
        node = _evidence_provenance_node(
            evidence_row,
            child_ids=evidence_children.get(int(evidence_row["id"]), []),
            acquisition=acquisition,
        )
        register(node)
        if acquisition is not None:
            acquisitions_by_source[citation_id] = acquisition

    for acquisition_row in acquisition_rows:
        source_citation = str(acquisition_row["evidence_source_citation_id"] or "")
        if source_citation and source_citation in acquisitions_by_source:
            continue
        linked_id = evidence_ids_by_citation.get(source_citation)
        node = _acquisition_provenance_node(acquisition_row, linked_id=linked_id)
        register(node)

    # Observable relationships: artifact -> file, event -> file/artifact,
    # hash_record -> cited target.
    for artifact_row in rows["artifact"]:
        file_id = artifact_row["file_record_id"]
        if file_id is None:
            continue
        target = file_node_by_row_id.get(int(file_id))
        source = artifact_node_by_row_id.get(int(artifact_row["id"]))
        if source and target:
            relationships.append(
                _relationship_node(
                    f"kb:relationship-artifact-{normalize_identifier(str(artifact_row['citation_id']), fallback=str(artifact_row['id']))}",
                    source=source,
                    target=target,
                    kind="derived-from",
                )
            )
    for event_row in rows["event"]:
        source = _node_id("event", str(event_row["citation_id"]), event_row["id"])
        if source not in node_ids:
            continue
        for column, lookup, kind in (
            ("file_record_id", file_node_by_row_id, "occurred-on"),
            ("artifact_id", artifact_node_by_row_id, "referenced-artifact"),
        ):
            value = event_row[column]
            if value is None:
                continue
            target = lookup.get(int(value))
            if target:
                relationships.append(
                    _relationship_node(
                        f"kb:relationship-event-{normalize_identifier(str(event_row['citation_id']), fallback=str(event_row['id']))}-{kind}",
                        source=source,
                        target=target,
                        kind=kind,
                    )
                )
    for hash_row in rows["hash_record"]:
        target = node_id_by_citation.get(str(hash_row["target_id"] or ""))
        if not target:
            continue
        source = _node_id("hash", str(hash_row["citation_id"]), hash_row["id"])
        if source in node_ids:
            relationships.append(
                _relationship_node(
                    f"kb:relationship-hash-{normalize_identifier(str(hash_row['citation_id']), fallback=str(hash_row['id']))}",
                    source=source,
                    target=target,
                    kind="hash-of",
                )
            )
    for relationship in relationships:
        nodes.append(relationship)
        node_ids.add(str(relationship["@id"]))

    case_slug = normalize_identifier(normalized_case_id, fallback="case")
    bundle: dict[str, object] = {
        "@id": f"kb:case-{case_slug}",
        "@type": [
            "uco-core:UcoObject",
            "uco-core:Bundle",
            "case-investigation:Investigation",
        ],
        "uco-core:name": str(case_row["name"] or normalized_case_id),
        "uco-core:description": str(case_row["description"] or ""),
        "uco-core:specVersion": "UCO-1.3.0",
        "case-investigation:focus": "rapidtriage case database export",
        "rapidtriage:caseId": normalized_case_id,
        "rapidtriage:examiner": str(case_row["examiner"] or ""),
        "rapidtriage:organization": str(case_row["organization"] or ""),
        "rapidtriage:caseStatus": str(case_row["status"] or ""),
        "rapidtriage:caseRoot": str(case_row["case_root"] or ""),
        "rapidtriage:citationPrefix": str(case_row["citation_prefix"] or ""),
        "rapidtriage:exportProfile": CASE_UCO_EXPORT_VERSION,
        "uco-core:object": [{"@id": str(node["@id"])} for node in nodes],
    }
    created = _iso_literal(case_row["created_at"])
    if created:
        bundle["uco-core:objectCreatedTime"] = created
    modified = _iso_literal(case_row["updated_at"])
    if modified:
        bundle["uco-core:objectModifiedTime"] = modified

    document = {
        "@context": dict(CASE_UCO_CONTEXT),
        "@graph": [bundle, *nodes],
        "rapidtriage:exportSummary": {
            "case_id": normalized_case_id,
            "row_counts": row_counts,
            "node_counts": {
                "provenance": len(evidence_rows)
                + sum(
                    1
                    for row in acquisition_rows
                    if str(row["evidence_source_citation_id"] or "")
                    not in acquisitions_by_source
                ),
                "file": len(rows["file_record"]),
                "artifact": len(rows["artifact"]),
                "event": len(rows["event"]),
                "hash": len(rows["hash_record"]),
                "relationship": len(relationships),
            },
            "truncated": bool(truncated_tables),
            "truncated_tables": truncated_tables,
        },
    }
    return document


def case_uco_default_output(database_path: Path, case_id: str) -> Path:
    case_slug = normalize_identifier(case_id, fallback="case")
    return database_path.parent / "report" / f"{case_slug}-case-uco.jsonld"


def resolve_case_uco_output(
    database_path: Path,
    case_id: str,
    output: Path | None,
) -> Path:
    resolved = (
        output.expanduser().resolve()
        if output is not None
        else case_uco_default_output(database_path, case_id)
    )
    case_dir = database_path.expanduser().resolve().parent
    if resolved != case_dir and case_dir not in resolved.parents:
        raise CaseExportError(
            "output path must stay under the case database directory"
        )
    return resolved


def export_case_uco_jsonld(
    database,
    *,
    case_id: str,
    output: Path | None = None,
    max_rows: int = CASE_UCO_DEFAULT_MAX_ROWS,
) -> dict[str, object]:
    """Export one case to CASE/UCO-shaped JSON-LD under the case directory."""
    normalized_case_id = normalize_identifier(case_id, fallback="case")
    output_path = resolve_case_uco_output(database.path, normalized_case_id, output)
    try:
        with database.connect() as connection:
            schema_version = get_schema_version(connection)
            document = build_case_uco_document(
                connection,
                normalized_case_id,
                max_rows=max_rows,
            )
    except sqlite3.DatabaseError as exc:
        raise CaseDatabaseError(f"unsupported case DB file: {exc}") from exc
    write_result(document, output_path)
    summary = document.get("rapidtriage:exportSummary")
    return {
        "command": "case-export-uco",
        "case_id": normalized_case_id,
        "database": str(database.path),
        "output": str(output_path),
        "schema_version": schema_version,
        "export_version": CASE_UCO_EXPORT_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "summary": summary if isinstance(summary, dict) else {},
        "document": document,
    }
