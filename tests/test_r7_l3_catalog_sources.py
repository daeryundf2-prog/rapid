"""R7 stage 1 L3 (C-R4): triage rules cite their own sources, not one file-wide list.

The rule-evidence popover shows each rule's `sources`; before R7 every rule of a catalogue file
shared the same YAML-anchored list (every event-log rule cited the 7045 page and the log-cleared
Sigma rule). Each rule now carries the references that support it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from rapidtriage.core.triage_rules.catalog import load_catalog

CATALOG_DIR = Path(__file__).resolve().parents[1] / "rapidtriage" / "core" / "triage_rules" / "catalog"


class CatalogSourcesTests(unittest.TestCase):
    def test_no_rule_shares_an_anchored_sources_list(self) -> None:
        for path in sorted(CATALOG_DIR.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"^\s*sources:\s*[&*]", text, re.MULTILINE), path.name)

    def test_rules_cite_https_sources_specific_to_them(self) -> None:
        by_id: dict[str, tuple[str, ...]] = {}
        for rule in load_catalog().rules:
            sources = tuple(rule["sources"])
            self.assertTrue(sources, rule["id"])
            self.assertTrue(all(url.startswith("https://") for url in sources), rule["id"])
            self.assertLessEqual(len(sources), 6, rule["id"])
            by_id[rule["id"]] = sources
        # Spot checks: the source names the rule's own subject.
        self.assertIn("https://attack.mitre.org/techniques/T1070/001/", by_id["eventlog.log_cleared"])
        self.assertNotIn(
            "https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html",
            by_id["eventlog.log_cleared"],
        )
        self.assertIn("https://www.rfc-editor.org/rfc/rfc7208", by_id["email.spf_fail"])
        self.assertIn("https://attack.mitre.org/techniques/T1543/003/", by_id["eventlog.new_service"])
        # Within one file, the rules no longer all cite one list.
        lists: dict[str, set[tuple[str, ...]]] = {}
        for rule_id, sources in by_id.items():
            lists.setdefault(rule_id.split(".")[0], set()).add(sources)
        for family in ("eventlog", "browser", "email", "ntfs", "registry", "usb", "documents", "media"):
            self.assertGreater(len(lists[family]), 1, family)

    def test_rule_texts_carry_no_raw_ids(self) -> None:
        """The popover shows label / rationale / false-positive text: no snake_case keys or enum ids."""
        raw = re.compile(r"(?<![\w$<])([a-z][a-z0-9]*_[a-z0-9_]+|[A-Z]+_[A-Z_]{4,})(?![\w>])")
        # USN reason flags are the documented Windows names an examiner looks up (allowed in prose).
        allowed = {"BASIC_INFO_CHANGE", "RENAME_NEW_NAME"}
        for rule in load_catalog().rules:
            label = rule["label_ko"]
            self.assertIsNone(raw.search(label), f"{rule['id']} label: {label}")
            for field in ("rationale_ko", "false_positive_ko"):
                hits = set(raw.findall(rule.get(field) or "")) - allowed
                self.assertFalse(hits, f"{rule['id']} {field}: {sorted(hits)}")


if __name__ == "__main__":
    unittest.main()
