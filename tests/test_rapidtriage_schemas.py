from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from tests.schema_validation import validate
from tests.test_rapidtriage_run import build_run_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "rapidtriage" / "schemas"


def load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))


class RapidTriageSchemaValidationTests(unittest.TestCase):
    def test_manifest_docs_files_extract_artifacts_and_case_outputs_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            manifest_path = root / "manifest.json"
            docs_path = root / "docs.json"
            files_path = root / "files.json"
            artifacts_path = root / "artifacts-browser.json"
            indicators_path = root / "indicators.json"
            case_path = root / "case.json"
            extract_dir = root / "extract-out"
            extract_path = extract_dir / "rapidtriage-extract-manifest.json"
            case_path = root / "case.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(manifest_path)]), 0)
            self.assertEqual(main(["docs", str(root), "-k", "fraud", "-k", "deleted", "--output", str(docs_path)]), 0)
            self.assertEqual(main(["files", str(root), "--output", str(files_path)]), 0)
            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(artifacts_path)]), 0)
            self.assertEqual(
                main(["run", str(root), "--mode", "fraud", "--output-dir", str(root / "run-output")]),
                0,
            )
            self.assertEqual(main(["indicators", str(root / "run-output"), "--output", str(indicators_path)]), 0)
            self.assertEqual(main(["extract", str(files_path), str(extract_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "case",
                        str(case_path),
                        "--case-id",
                        "schema-case",
                        "--title",
                        "Schema Validation Case",
                        "--source",
                        str(files_path),
                        "--pointer",
                        "/candidates/0",
                        "--bookmark-id",
                        "bookmark-1",
                        "--tag",
                        "schema",
                        "--note",
                        "Schema validation fixture",
                    ]
                ),
                0,
            )

            validate(json.loads(manifest_path.read_text(encoding="utf-8")), load_schema("manifest.schema.json"))
            validate(json.loads(docs_path.read_text(encoding="utf-8")), load_schema("docs.schema.json"))
            validate(json.loads(files_path.read_text(encoding="utf-8")), load_schema("files.schema.json"))
            validate(json.loads(artifacts_path.read_text(encoding="utf-8")), load_schema("artifacts.schema.json"))
            validate(json.loads(indicators_path.read_text(encoding="utf-8")), load_schema("indicators.schema.json"))
            validate(json.loads(extract_path.read_text(encoding="utf-8")), load_schema("extract.schema.json"))
            validate(json.loads(case_path.read_text(encoding="utf-8")), load_schema("case.schema.json"))

    def test_case_schema_accepts_excluded_review_status(self) -> None:
        schema = load_schema("case.schema.json")
        payload = {
            "command": "case",
            "case_id": "schema-case",
            "title": "Schema Case",
            "generated_at": "2026-05-11T00:00:00+00:00",
            "updated_at": "2026-05-11T00:01:00+00:00",
            "summary": {
                "bookmark_count": 1,
                "tagged_bookmark_count": 0,
                "report_item_count": 0,
                "review_status_counts": {"excluded": 1},
                "tag_counts": {},
                "source_command_counts": {"files": 1},
                "review_revision_count": 1,
            },
            "bookmarks": [
                {
                    "bookmark_id": "bm-1",
                    "reference": {
                        "command": "files",
                        "file": "/case/files.json",
                        "pointer": "/candidates/0",
                        "root": None,
                        "stable_key": "bookmark-files-0",
                    },
                    "snapshot": {
                        "path": "/case/evidence.txt",
                        "hash": None,
                        "timestamp": None,
                        "artifact_key": None,
                        "summary": "evidence.txt",
                    },
                    "tags": [],
                    "note": "Excluded as noise after source review.",
                    "summary": "evidence.txt",
                    "review": {
                        "status": "excluded",
                        "include_in_report": False,
                        "reviewed_at": "2026-05-11T00:01:00+00:00",
                    },
                    "review_history": [
                        {
                            "action": "created",
                            "at": "2026-05-11T00:01:00+00:00",
                            "status": "excluded",
                            "include_in_report": False,
                            "tags": [],
                            "note": "Excluded as noise after source review.",
                            "changed_fields": ["created"],
                        }
                    ],
                    "created_at": "2026-05-11T00:01:00+00:00",
                    "updated_at": "2026-05-11T00:01:00+00:00",
                }
            ],
        }

        validate(payload, schema)

    def test_run_summaries_validate_for_all_modes(self) -> None:
        schema = load_schema("run-summary.schema.json")
        for mode in ("seizure", "fraud", "hacking", "recovery"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    root = Path(tmp_dir) / "case-root"
                    output_dir = Path(tmp_dir) / f"run-{mode}"
                    root.mkdir(parents=True, exist_ok=True)
                    build_run_fixture(root)

                    self.assertEqual(main(["run", str(root), "--mode", mode, "--output-dir", str(output_dir)]), 0)

                    summary_path = output_dir / "rapidtriage-run-summary.json"
                    validate(json.loads(summary_path.read_text(encoding="utf-8")), schema)

    def test_artifact_record_v1_schema_accepts_worker_output_contract(self) -> None:
        payload = {
            "schema": "ArtifactRecordV1",
            "artifact_id": "CASE:SRC:file:1",
            "artifact_family": "file-system",
            "artifact_type": "file-inventory-record",
            "parser": "rapid-worker-file-inventory",
            "parser_version": "0.1.0",
            "source": {
                "case_id": "CASE",
                "source_id": "SRC",
                "source_path": "/case/source",
                "offset": None,
                "length": 10,
                "hashes": {},
            },
            "confidence": 0.9,
            "validation_required": False,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["large-case-corpus-validation-required"],
            "legal_limitations": ["File metadata alone does not prove user intent."],
            "fields": {"path": "/case/source/a.txt", "size_bytes": 10},
        }

        validate(payload, load_schema("artifact-record-v1.schema.json"))


if __name__ == "__main__":
    unittest.main()
