"""R8 T-045: catalogue classification keys (``tier``/``card``/``section``) and the validator.

Every family and every artifact type a collector can write must resolve to a tier, a card and a
section (plan r8-redesign §4.2, "미분류 0"); a missing key is a load error. The real-data list below
is type *names* only (IMG-B and the C3 baseline run, read from their case DBs outside Git), never
values from the evidence.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from rapidtriage.core.artifact_taxonomy import discover_artifact_type_literals
from rapidtriage.core.triage_rules.catalog import (
    CARD_IDS,
    CLASS_KEYS,
    CatalogError,
    load_catalog,
    parse_catalog,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# Artifact type names seen in IMG-B (type_counts_imgb.json) and the C3 baseline case DBs.
REAL_DATA_TYPES = (
    'activities-cache-db', 'activities-cache-row-candidate', 'amcache-device-container', 'amcache-device-pnp',
    'amcache-hive', 'amcache-schema-row', 'archive-file-inventory', 'bam-schema-entry',
    'bits-qmgr-transfer-candidate', 'browser-cache-entry', 'browser-cookie', 'browser-extension',
    'browser-history', 'browser-parse-error', 'browser-profile-account', 'browser-session-tab',
    'browser-storage-inventory', 'browser-top-site', 'chat-app-inventory', 'chat-attachment', 'chat-contact',
    'chat-message', 'cloud-sync-account', 'cloud-sync-event', 'cloud-sync-inventory', 'crash-dump-indicators',
    'credential-store-presence', 'defender-support-log', 'desktop-ai-app-artifact', 'desktop-cloud-sync-db',
    'desktop-cloud-sync-row-candidate', 'desktop-wallpaper', 'disk-memory-file-indicators', 'document-lock-owner',
    'document-metadata-risk', 'email-mailbox', 'email-message', 'etl-trace-file', 'eventlog-detection',
    'eventlog-event', 'eventlog-file', 'eventlog-logon-session', 'eventlog-summary', 'execution-feature-usage',
    'execution-pca', 'file-signature-mismatch', 'icon-cache-entry-candidate', 'icon-cache-file',
    'icon-cache-media-candidate', 'indicator-domain', 'indicator-ip', 'indicator-md5', 'indicator-sha1',
    'indicator-sha256', 'indicator-url', 'jumplist-automatic', 'jumplist-custom', 'jumplist-entry',
    'kakaotalk-app-inventory', 'kakaotalk-shared-picture', 'kakaotalk-windows-app-database',
    'kakaotalk-windows-correlation-summary', 'kakaotalk-windows-crypto-material-candidate',
    'kakaotalk-windows-source-candidate', 'kakaotalk-windows-user-id-candidate', 'media-audio', 'media-image',
    'media-image-unreadable', 'media-player-inventory', 'media-player-recent', 'media-video',
    'memory-dump-indicators', 'mft-file', 'mft-record', 'notification-database', 'notification-row-candidate',
    'ntfs-logfile-transaction-candidate', 'ntfs-volume-information', 'prefetch-file', 'prefetch-invalid-content',
    'prefetch-reference', 'recent-shortcut', 'recycle-bin-entry', 'registry-default-browser',
    'registry-deleted-cell-candidate', 'registry-hive', 'registry-hive-strings', 'registry-install-state',
    'registry-key', 'registry-key-recovery-candidate', 'registry-key-tree-node', 'registry-known-dll',
    'registry-network-profile', 'registry-network-share', 'registry-office-mru', 'registry-persistence-entry',
    'registry-summary', 'registry-user-activity', 'registry-value-recovery-candidate', 'shell-shortcut',
    'shellbag-entry', 'shellbag-hive-summary', 'shimcache-schema-entry', 'srum-database-file', 'srum-schema-row',
    'srum-table-candidate', 'startup-item', 'sticky-note', 'sticky-note-recovery-candidate',
    'synthetic-media-image', 'synthetic-media-scan-summary', 'synthetic-media-text', 'task-scheduler-task',
    'third-party-remote-control-artifact', 'thumbnail-cache-entry-candidate', 'thumbnail-cache-file',
    'thumbnail-cache-media-candidate', 'userassist-schema-entry', 'uwp-package', 'web-server-log',
    'webcachev01-ese-file', 'webshell-source-candidate', 'wer-report', 'windows-computer-name',
    'windows-control-set', 'windows-execution-summary', 'windows-installed-program', 'windows-mounted-device',
    'windows-network-interface', 'windows-os-account-summary', 'windows-os-version', 'windows-profile-list-entry',
    'windows-sam-account', 'windows-sam-group', 'windows-search-db', 'windows-search-edb-file',
    'windows-search-edb-page-candidate', 'windows-search-edb-row-candidate', 'windows-search-edb-table-candidate',
    'windows-search-index-summary', 'windows-search-row-candidate', 'windows-service-config', 'windows-timezone',
    'windows-usb-device', 'windows-user-profile', 'wmi-repository-file',
)  # fmt: skip

FAMILY = {"id": "fam", "label": "계열", "tier": 2, "card": "documents", "section": "fam",
          "types": ["fam-row-type"], "core_columns": [{"key": "a", "label": "가"}]}  # fmt: skip


def _doc(families: list[dict[str, object]] | None = None, type_defaults: object = None) -> list[tuple[str, bytes]]:
    document: dict[str, object] = {"families": families if families is not None else [dict(FAMILY)]}
    if type_defaults is not None:
        document["type_defaults"] = type_defaults
    return [("a.yaml", json.dumps(document, ensure_ascii=False).encode("utf-8"))]


class PackagedCatalogClassificationTests(unittest.TestCase):
    def test_every_family_carries_valid_keys(self) -> None:
        catalog = load_catalog()
        self.assertEqual(len(catalog.families), 131)
        for family in catalog.families:
            with self.subTest(family["id"]):
                self.assertIn(family["tier"], (1, 2, 3))
                self.assertTrue(family["card"] is None or family["card"] in CARD_IDS)
                self.assertRegex(family["section"], r"^[a-z][a-z0-9-]*$")

    def test_the_nine_category_cards_each_own_a_tier_one_family(self) -> None:
        catalog = load_catalog()
        tier_one_cards = {f["card"] for f in catalog.families if f["tier"] == 1}
        tier_one_cards |= {e["card"] for e in catalog.type_defaults if e["tier"] == 1}
        for card in ("documents", "email", "messenger", "web", "exfil", "programs", "deleted", "accounts", "ai"):
            self.assertIn(card, tier_one_cards)

    def test_registry_types_all_classify(self) -> None:
        """Every artifact type literal a collector can write (``artifact_taxonomy`` register)."""
        literals = discover_artifact_type_literals(REPO_ROOT)
        self.assertGreater(len(literals), 250)
        self.assertEqual(load_catalog().unclassified(literals), [])

    def test_real_data_types_all_classify(self) -> None:
        self.assertEqual(load_catalog().unclassified(REAL_DATA_TYPES), [])

    def test_resolution_order_and_unknown(self) -> None:
        catalog = load_catalog()
        usb = catalog.classify("windows-usb-device")
        self.assertEqual((usb["tier"], usb["card"], usb["section"], usb["source"]), (1, "exfil", "usb", "family:usb"))
        # A family suffix/type wins over the ``-row`` default suffix.
        self.assertEqual(catalog.classify("amcache-schema-row")["source"], "family:amcache-file")
        # Exact default beats the prefix default.
        self.assertEqual(catalog.classify("indicator-ioc-scanner-hit")["card"], "findings")
        self.assertEqual(catalog.classify("indicator-md5")["tier"], 3)
        self.assertEqual(catalog.classify("hash-row")["section"], "analysis-rows")
        # Unknown type falls back to the kind's family.
        self.assertEqual(catalog.classify("zz-unknown", "windows-execution")["source"], "family:execution")
        unknown = catalog.classify("zz-unknown")
        self.assertEqual(unknown, {"tier": 3, "card": None, "section": "unclassified", "source": "unclassified"})
        unknown["tier"] = 1  # callers get a copy, the cache stays intact
        self.assertEqual(catalog.classify("zz-unknown")["tier"], 3)
        self.assertEqual(catalog.unclassified(["zz-unknown", "sticky-note", "zz-unknown"]), ["zz-unknown"])

    def test_payload_families_carry_keys(self) -> None:
        payload = load_catalog().payload()
        self.assertTrue(all(set(CLASS_KEYS) <= set(family) for family in payload["families"]))
        self.assertEqual(set(payload), {"version", "families", "rules"})  # type defaults stay server-side

    def test_family_for_is_unchanged_by_type_defaults(self) -> None:
        """The existing grid/tree lookup never sees the defaults (기존 화면 동작 변화 0)."""
        catalog = load_catalog()
        self.assertIsNone(catalog.family_for("sticky-note"))
        self.assertEqual(catalog.family_for("windows-usb-device"), "usb")


class ClassificationValidatorTests(unittest.TestCase):
    def test_good_document_parses_and_classifies(self) -> None:
        catalog = parse_catalog(_doc(type_defaults=[{"kinds": ["k"], "tier": 2, "card": None, "section": "ctx"}]))
        self.assertEqual(catalog.classify("fam-row-type")["source"], "family:fam")
        self.assertEqual(catalog.classify("other", "k")["section"], "ctx")
        self.assertEqual(catalog.classify("other", "q")["source"], "unclassified")

    def test_missing_or_bad_family_keys_are_errors(self) -> None:
        cases: dict[str, dict[str, object]] = {"bad-tier": {"tier": 4}, "bool-tier": {"tier": True},
                                               "bad-card": {"card": "nope"}, "tier1-null": {"tier": 1, "card": None},
                                               "tier3-card": {"tier": 3}, "bad-section": {"section": "Has Space"},
                                               "null-section": {"section": None}}  # fmt: skip
        for key in CLASS_KEYS:
            family = dict(FAMILY)
            del family[key]
            with self.subTest(missing=key), self.assertRaises(CatalogError) as caught:
                parse_catalog(_doc([family]))
            self.assertIn(key, str(caught.exception))
        for name, change in cases.items():
            with self.subTest(name), self.assertRaises(CatalogError) as caught:
                parse_catalog(_doc([{**FAMILY, **change}]))
            self.assertRegex(str(caught.exception), "[가-힣]")

    def test_bad_type_defaults_are_errors(self) -> None:
        ok = {"tier": 3, "card": None, "section": "x"}
        cases: dict[str, object] = {
            "not-list": {"types": ["a"], **ok},
            "no-match-key": [dict(ok)],
            "unknown-key": [{"types": ["a"], "colour": "red", **ok}],
            "empty-list": [{"types": [], **ok}],
            "missing-class": [{"types": ["a"], "tier": 3, "card": None}],
            "duplicate": [{"types": ["a"], **ok}, {"types": ["a"], **ok}],
            "shadowed-by-family": [{"types": ["fam-row-type"], **ok}],
        }
        for name, raw in cases.items():
            with self.subTest(name), self.assertRaises(CatalogError):
                parse_catalog(_doc(type_defaults=raw))


if __name__ == "__main__":
    unittest.main()
