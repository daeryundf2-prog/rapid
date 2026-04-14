from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README_PATH = REPO_ROOT / "README.md"
RULE_ENGINE_DOC = REPO_ROOT / "docs" / "rapidtriage-rule-engine.md"
RULE_SAMPLE_PATH = REPO_ROOT / "docs" / "samples" / "rapidtriage-rules.sample.yaml"


class RapidTriageRuleEngineDocsTests(unittest.TestCase):
    def test_rule_engine_doc_exists_and_covers_requested_conditions(self) -> None:
        text = RULE_ENGINE_DOC.read_text(encoding="utf-8")
        self.assertIn("rule engine and IOC lookup plan", text)
        self.assertIn("matched_rules", text)
        self.assertIn("ioc_hits", text)
        for token in ("ext", "path", "date", "artifact", "keyword", "hash", "domain", "url"):
            self.assertIn(f"`{token}`", text)

    def test_rule_engine_sample_exists_and_covers_requested_condition_blocks(self) -> None:
        text = RULE_SAMPLE_PATH.read_text(encoding="utf-8")
        for token in ("ext:", "path:", "date:", "artifact:", "keyword:", "hash:", "domain:", "url:"):
            self.assertIn(token, text)
        self.assertIn("iocs:", text)
        self.assertIn("rules:", text)

    def test_readme_links_rule_engine_doc_and_sample(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/rapidtriage-rule-engine.md", readme)
        self.assertIn("docs/samples/rapidtriage-rules.sample.yaml", readme)


if __name__ == "__main__":
    unittest.main()
