from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
SAMPLES_DIR = DOCS_DIR / "samples"
README_PATH = REPO_ROOT / "README.md"


class RapidTriageDocumentationContractTests(unittest.TestCase):
    def load_sample(self, name: str) -> dict[str, object]:
        return json.loads((SAMPLES_DIR / name).read_text(encoding="utf-8"))

    def test_schema_doc_exists_and_mentions_all_commands(self) -> None:
        schema_doc = (DOCS_DIR / "rapidtriage-output-schema.md").read_text(encoding="utf-8")
        self.assertIn("`manifest` JSON", schema_doc)
        self.assertIn("`docs` JSON", schema_doc)
        self.assertIn("`files` JSON", schema_doc)
        self.assertIn("`extract` JSON", schema_doc)
        self.assertIn("`run` JSON", schema_doc)
        self.assertIn("Windows artifact collector", schema_doc)

    def test_readme_links_schema_and_sample_json_files(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/rapidtriage-output-schema.md", readme)
        self.assertIn("docs/samples/rapidtriage-manifest.sample.json", readme)
        self.assertIn("docs/samples/rapidtriage-docs.sample.json", readme)
        self.assertIn("docs/samples/rapidtriage-files.sample.json", readme)
        self.assertIn("docs/samples/rapidtriage-extract.sample.json", readme)
        self.assertIn("rapidtriage run . --mode fraud --output-dir ./rapidtriage-run-fraud", readme)

    def test_manifest_sample_includes_windows_collectors(self) -> None:
        payload = self.load_sample("rapidtriage-manifest.sample.json")
        self.assertEqual(payload["root"], "/cases/case-001")
        providers = {item["name"]: item for item in payload["providers"]}
        self.assertIn("windows-browser-artifacts", providers)
        self.assertIn("windows-recent-files", providers)
        self.assertIn("windows-eventlog", providers)
        self.assertIn("windows-registry", providers)
        self.assertIn("windows-shellbags", providers)
        browser_artifact = providers["windows-browser-artifacts"]["artifacts"][0]
        self.assertEqual(browser_artifact["artifact_type"], "browser-history-downloads")
        self.assertIn("downloads", browser_artifact["details"])

    def test_docs_sample_matches_expected_shape(self) -> None:
        payload = self.load_sample("rapidtriage-docs.sample.json")
        self.assertEqual(payload["command"], "docs")
        self.assertEqual(sorted(payload["summary"]["supported_extensions"]), [".docx", ".pdf", ".txt"])
        self.assertIn("manifest", payload)
        self.assertIn("candidates", payload)
        self.assertIn("results", payload)
        result = payload["results"][0]
        self.assertEqual(sorted(result), ["kind", "matched_keywords", "path", "preview", "size"])

    def test_files_sample_matches_expected_shape(self) -> None:
        payload = self.load_sample("rapidtriage-files.sample.json")
        self.assertEqual(payload["command"], "files")
        self.assertIn("filters", payload)
        self.assertIn("summary", payload)
        candidate = payload["candidates"][0]
        self.assertEqual(
            sorted(candidate),
            ["categories", "extension", "modified_at", "modified_epoch", "name", "path", "reasons", "size"],
        )

    def test_extract_sample_matches_docs_extract_shape(self) -> None:
        payload = self.load_sample("rapidtriage-extract.sample.json")
        self.assertEqual(payload["command"], "extract")
        self.assertEqual(payload["source_command"], "docs")
        self.assertEqual(payload["filters"]["kinds"], ["pdf"])
        entry = payload["entries"][0]
        self.assertEqual(
            sorted(entry),
            [
                "extracted_path",
                "kind",
                "matched_keywords",
                "modified_at",
                "original_path",
                "relative_path",
                "sha256",
                "size",
            ],
        )

    def assert_help_contains(self, *args: str, expected: str) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "rapidtriage", *args, "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(expected, result.stdout)
        self.assertIn("Examples:", result.stdout)

    def test_cli_help_includes_examples(self) -> None:
        self.assert_help_contains(expected="rapidtriage docs . -k incident -k registry")
        self.assert_help_contains("manifest", expected="rapidtriage manifest /cases/image-mount --output case-manifest.json")
        self.assert_help_contains("docs", expected="rapidtriage docs /cases/image-mount -k password --limit 250 --output docs-hits.json")
        self.assert_help_contains("files", expected="rapidtriage files . --name-contains note --path-contains desktop --output desktop-notes.json")
        self.assert_help_contains(
            "extract",
            expected=f"rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf --manifest ./docs-out/{'rapidtriage-extract-manifest.json'}",
        )
        self.assert_help_contains("run", expected="rapidtriage run /cases/image-mount --mode hacking --output-dir ./rapidtriage-run")


if __name__ == "__main__":
    unittest.main()
