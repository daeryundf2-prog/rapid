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
    def test_manifest_docs_files_extract_and_artifacts_outputs_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            manifest_path = root / "manifest.json"
            docs_path = root / "docs.json"
            files_path = root / "files.json"
            artifacts_path = root / "artifacts-browser.json"
            case_path = root / "case.json"
            extract_dir = root / "extract-out"
            extract_path = extract_dir / "rapidtriage-extract-manifest.json"
            timeline_path = root / "timeline.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(manifest_path)]), 0)
            self.assertEqual(main(["docs", str(root), "-k", "fraud", "-k", "deleted", "--output", str(docs_path)]), 0)
            self.assertEqual(main(["files", str(root), "--output", str(files_path)]), 0)
            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(artifacts_path)]), 0)
            self.assertEqual(main(["extract", str(files_path), str(extract_dir)]), 0)
            self.assertEqual(main(["timeline", str(root), "--output", str(timeline_path)]), 0)
            self.assertEqual(
                main(
                    [
                        "case",
                        str(case_path),
                        "--source",
                        str(timeline_path),
                        "--pointer",
                        "/events/0",
                        "--tag",
                        "schema-check",
                    ]
                ),
                0,
            )

            validate(json.loads(manifest_path.read_text(encoding="utf-8")), load_schema("manifest.schema.json"))
            validate(json.loads(docs_path.read_text(encoding="utf-8")), load_schema("docs.schema.json"))
            validate(json.loads(files_path.read_text(encoding="utf-8")), load_schema("files.schema.json"))
            validate(json.loads(artifacts_path.read_text(encoding="utf-8")), load_schema("artifacts.schema.json"))
            validate(json.loads(extract_path.read_text(encoding="utf-8")), load_schema("extract.schema.json"))
            validate(json.loads(case_path.read_text(encoding="utf-8")), load_schema("case.schema.json"))

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


if __name__ == "__main__":
    unittest.main()
