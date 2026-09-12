from __future__ import annotations

import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.case_export import (
    CASE_UCO_CONTEXT,
    CASE_UCO_EXPORT_VERSION,
    CaseExportError,
    build_case_uco_document,
    export_case_uco_jsonld,
    resolve_case_uco_output,
)

_IRI_PATTERN = re.compile(r"^kb:[A-Za-z0-9_-]+$")


def _build_case_db(db_path: Path) -> None:
    database = open_case_database(db_path)
    database.create_case(
        case_id="CASE-UCO-1",
        name="UCO Export Case",
        description="synthetic case for JSON-LD export",
        examiner="examiner-a",
        organization="lab-x",
    )
    with database.connect() as connection:
        evidence_id = connection.execute(
            """
            INSERT INTO evidence_source (
                citation_id, case_id, display_name, source_type, original_path,
                staged_path, size_bytes, hash_sha256, detected_format,
                adapter_name, adapter_version, status, added_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "EVD-1",
                "CASE-UCO-1",
                "Mounted evidence folder",
                "folder",
                "/evidence/source-a",
                "/staged/source-a",
                4096,
                "a" * 64,
                "dir",
                "folder-adapter",
                "1",
                "imported",
                "2026-01-01T00:00:00+00:00",
            ),
        ).lastrowid
        file_one = connection.execute(
            """
            INSERT INTO file_record (
                citation_id, case_id, evidence_source_id, path, normalized_path,
                extension, mime_type, size_bytes, modified_at, accessed_at,
                hash_md5, hash_sha1, hash_sha256, is_deleted, is_recovered
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "FILE-1",
                "CASE-UCO-1",
                evidence_id,
                "/evidence/source-a/report.pdf",
                "/evidence/source-a/report.pdf",
                ".pdf",
                "application/pdf",
                1024,
                "2026-01-02T03:04:05+00:00",
                "2026-01-03T00:00:00+00:00",
                "b" * 32,
                "c" * 40,
                "d" * 64,
                0,
                0,
            ),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO file_record (
                citation_id, case_id, evidence_source_id, path, normalized_path,
                extension, size_bytes, is_deleted, is_recovered
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "FILE-2",
                "CASE-UCO-1",
                evidence_id,
                "/evidence/source-a/deleted.txt",
                "/evidence/source-a/deleted.txt",
                ".txt",
                10,
                1,
                1,
            ),
        )
        connection.execute(
            """
            INSERT INTO artifact (
                citation_id, case_id, evidence_source_id, file_record_id,
                artifact_type, parser_name, parser_version, title, summary,
                data_json, confidence, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ART-1",
                "CASE-UCO-1",
                evidence_id,
                file_one,
                "browser-history",
                "fixture-parser",
                "1",
                "Browser history artifact",
                "visited example.test",
                json.dumps({"url": "https://example.test"}, sort_keys=True),
                0.8,
                "2026-01-02T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO event (
                citation_id, case_id, evidence_source_id, file_record_id,
                event_type, timestamp, timestamp_kind, actor, action,
                target, description, source, confidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "EVT-1",
                "CASE-UCO-1",
                evidence_id,
                file_one,
                "file-modified",
                "2026-01-02T03:04:05+00:00",
                "mtime",
                "user-a",
                "modify",
                "/evidence/source-a/report.pdf",
                "report.pdf modified",
                "fixture",
                0.9,
            ),
        )
        connection.execute(
            """
            INSERT INTO hash_record (
                citation_id, case_id, target_type, target_id, hash_scope,
                algorithm, value, calculated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "HASH-1",
                "CASE-UCO-1",
                "file_record",
                "FILE-1",
                "whole-file",
                "sha256",
                "e" * 64,
                "2026-01-02T03:05:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO acquisition_metadata (
                citation_id, case_id, evidence_source_citation_id, operator,
                acquisition_started_at, acquisition_completed_at,
                source_identifier, write_blocker, acquisition_tool,
                acquisition_tool_version, whole_source_sha256, notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ACQ-1",
                "CASE-UCO-1",
                "EVD-1",
                "operator-a",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:10:00+00:00",
                "SRC-A",
                "wb-1",
                "rapidtriage",
                "1",
                "f" * 64,
                "acquired source A",
                "2026-01-01T00:10:00+00:00",
            ),
        )


def _collect_iri_references(node: object) -> list[str]:
    refs: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"uco-core:object", "uco-core:source", "uco-core:target"}:
                if isinstance(value, list):
                    refs.extend(
                        str(item["@id"])
                        for item in value
                        if isinstance(item, dict) and "@id" in item
                    )
                elif isinstance(value, dict) and "@id" in value:
                    refs.append(str(value["@id"]))
            else:
                refs.extend(_collect_iri_references(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_collect_iri_references(item))
    return refs


class RapidTriageCaseExportTests(unittest.TestCase):
    def test_parser_exposes_case_export_uco(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("case-export-uco", commands)
        help_text = commands["case-export-uco"].format_help()
        self.assertIn("--case-id", help_text)
        self.assertIn("--output", help_text)
        self.assertIn("--max-rows", help_text)

    def test_export_jsonld_shape_counts_and_connectivity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            _build_case_db(db_path)
            database = open_case_database(db_path)

            payload = export_case_uco_jsonld(database, case_id="CASE-UCO-1")

            output_path = Path(payload["output"])
            self.assertTrue(output_path.is_file())
            self.assertEqual(output_path.parent, db_path.parent.resolve() / "report")
            self.assertEqual(payload["export_version"], CASE_UCO_EXPORT_VERSION)

            document = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(document, payload["document"])

            context = document["@context"]
            for prefix in (
                "uco-core",
                "uco-observable",
                "case-investigation",
                "uco-action",
                "uco-types",
                "xsd",
                "kb",
            ):
                self.assertIn(prefix, context)
            self.assertEqual(context, CASE_UCO_CONTEXT)

            graph = document["@graph"]
            self.assertGreater(len(graph), 1)
            bundle = graph[0]
            self.assertIn("uco-core:Bundle", bundle["@type"])
            self.assertIn("case-investigation:Investigation", bundle["@type"])
            self.assertEqual(bundle["rapidtriage:caseId"], "CASE-UCO-1")
            self.assertTrue(str(bundle["@id"]).startswith("kb:case-"))

            nodes = graph[1:]
            node_ids = {node["@id"] for node in nodes}
            self.assertEqual(len(node_ids), len(nodes))
            for node in nodes:
                self.assertRegex(str(node["@id"]), _IRI_PATTERN)
                self.assertIn("uco-core:UcoObject", node["@type"])

            file_nodes = [
                node for node in nodes if "uco-observable:File" in node["@type"]
            ]
            self.assertEqual(len(file_nodes), 2)
            file_facets = {
                node["rapidtriage:citationId"]: node["uco-core:hasFacet"][0]
                for node in file_nodes
            }
            self.assertEqual(
                file_facets["FILE-1"]["uco-observable:filePath"],
                "/evidence/source-a/report.pdf",
            )
            self.assertTrue(file_facets["FILE-1"]["uco-observable:isAllocated"])
            self.assertFalse(file_facets["FILE-2"]["uco-observable:isAllocated"])

            artifact_nodes = [
                node
                for node in nodes
                if node["@id"].startswith("kb:artifact-")
            ]
            self.assertEqual(len(artifact_nodes), 1)
            artifact_facet = artifact_nodes[0]["uco-core:hasFacet"][0]
            self.assertEqual(artifact_facet["@type"], "rapidtriage:ArtifactFacet")
            self.assertEqual(artifact_facet["rapidtriage:artifactType"], "browser-history")

            provenance_nodes = [
                node
                for node in nodes
                if "case-investigation:ProvenanceRecord" in node["@type"]
            ]
            self.assertEqual(len(provenance_nodes), 1)
            provenance = provenance_nodes[0]
            self.assertEqual(provenance["case-investigation:exhibitNumber"], "EVD-1")
            self.assertEqual(provenance["rapidtriage:sourceType"], "folder")
            self.assertEqual(
                provenance["rapidtriage:acquisition"]["acquisition_tool"],
                "rapidtriage",
            )
            self.assertEqual(len(provenance["uco-core:object"]), 4)

            event_nodes = [node for node in nodes if node["@id"].startswith("kb:event-")]
            self.assertEqual(len(event_nodes), 1)
            self.assertIn("uco-action:Action", event_nodes[0]["@type"])

            relationship_nodes = [
                node
                for node in nodes
                if "uco-observable:ObservableRelationship" in node["@type"]
            ]
            self.assertGreaterEqual(len(relationship_nodes), 3)

            # Graph connectivity: every node is reachable from the bundle and
            # every embedded reference resolves inside the graph.
            bundle_refs = {str(item["@id"]) for item in bundle["uco-core:object"]}
            self.assertEqual(bundle_refs, node_ids)
            all_ids = node_ids | {str(bundle["@id"])}
            for ref in _collect_iri_references(document):
                self.assertIn(ref, all_ids)

            summary = document["rapidtriage:exportSummary"]
            self.assertEqual(summary["row_counts"]["file_record"], 2)
            self.assertEqual(summary["row_counts"]["artifact"], 1)
            self.assertEqual(summary["row_counts"]["event"], 1)
            self.assertEqual(summary["row_counts"]["hash_record"], 1)
            self.assertEqual(summary["row_counts"]["evidence_source"], 1)
            self.assertEqual(summary["row_counts"]["acquisition_metadata"], 1)
            self.assertEqual(summary["node_counts"]["file"], 2)
            self.assertEqual(summary["node_counts"]["artifact"], 1)
            self.assertEqual(summary["node_counts"]["provenance"], 1)
            self.assertFalse(summary["truncated"])

    def test_export_truncates_and_reports_over_limit_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            _build_case_db(db_path)
            database = open_case_database(db_path)
            with database.connect() as connection:
                document = build_case_uco_document(
                    connection, "CASE-UCO-1", max_rows=1
                )

            summary = document["rapidtriage:exportSummary"]
            self.assertTrue(summary["truncated"])
            self.assertIn("file_record", summary["truncated_tables"])
            self.assertEqual(summary["node_counts"]["file"], 1)

    def test_export_rejects_unknown_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-UCO-2")

            with self.assertRaises(CaseExportError):
                export_case_uco_jsonld(database, case_id="CASE-MISSING")

    def test_output_must_stay_under_case_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case" / "case.db"
            db_path.parent.mkdir(parents=True)
            outside = Path(tmp_dir) / "outside" / "export.jsonld"

            with self.assertRaises(CaseExportError):
                resolve_case_uco_output(db_path, "CASE-UCO-1", outside)

            inside = resolve_case_uco_output(
                db_path, "CASE-UCO-1", db_path.parent / "report" / "ok.jsonld"
            )
            self.assertTrue(str(inside).startswith(str(db_path.parent.resolve())))

    def test_cli_case_export_uco_writes_default_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            _build_case_db(db_path)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = main(
                    [
                        "case-export-uco",
                        str(db_path),
                        "--case-id",
                        "CASE-UCO-1",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("CASE/UCO JSON-LD", output.getvalue())
            exported = json.loads(
                (db_path.parent / "report" / "CASE-UCO-1-case-uco.jsonld").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("@graph", exported)

    def test_cli_case_export_uco_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            _build_case_db(db_path)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = main(
                    [
                        "case-export-uco",
                        str(db_path),
                        "--case-id",
                        "CASE-UCO-1",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["command"], "case-export-uco")
            self.assertIn("@context", payload["document"])


if __name__ == "__main__":
    unittest.main()
