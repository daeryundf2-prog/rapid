"""R7 갈래 A 중복 제거 (Nuix R2 item sets): keys, the three modes, ``rapidtriage-dedup.json`` and
``dup=`` on the listings (Q-A3, Q-A4)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.families import FAMILIES_SERVICE, collect_sources, derive
    from rapidtriage.api.app.row_conditions import MATCH_CACHE

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.dedup import (
    compute_dedup,
    dedup_document,
    dedup_index_from_document,
    mail_key,
    minute_utc,
)
from rapidtriage.core.jobs import RunJobStore
from tests import r7_a_fixtures as fx

TOKEN = "r7-a-dedup-token"
E = "artifacts:email:/artifacts/"
C = "files::/candidates/"
CARVE = f"analysis:{fx.CARVE_ID}:/rows/"


class KeyTests(unittest.TestCase):
    def test_mail_key_normalizes_subject_addresses_and_minute(self) -> None:
        base = {"subject": "견적서 송부", "date": "Mon, 26 May 2025 10:15:42 +0900", "from": "Kim <KIM@example.com>", "to": "b@x.com, a@x.com", "cc": "", "body_sha256": fx.B1}
        same = {**base, "subject": "  견적서\t송부 ", "date": "2025-05-26T01:15:05Z", "from": "kim@example.com", "to": "a@x.com", "cc": "B <b@x.com>"}
        self.assertEqual(mail_key(base), mail_key(same))
        self.assertNotEqual(mail_key(base), mail_key({**base, "date": "Mon, 26 May 2025 10:16:00 +0900"}))
        self.assertNotEqual(mail_key(base), mail_key({**base, "body_sha256": fx.B2}))
        # Without a body hash the Message-ID identifies the content; with neither there is no key.
        self.assertTrue(mail_key({**base, "body_sha256": "", "message_id": "<x@y>"}).startswith("mail:"))
        self.assertEqual(mail_key({**base, "body_sha256": ""}), "")
        self.assertEqual(minute_utc("not a date"), "")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class ModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"

    def derived(self):
        outputs = fx.write_run(self.run_dir)
        return derive(collect_sources(outputs, self.run_dir))

    def test_item_mode_groups_in_item_order(self) -> None:
        item = self.derived().dedup.mode("item")
        groups = {group.original: group.duplicates for group in item.groups}
        # The same bytes everywhere (files copies, three attachments, one carved PDF): the first files row is the original.
        self.assertEqual(groups[C + "2"], [C + "10", E + "2", E + "5", E + "8", CARVE + "1"])
        self.assertEqual(groups[E + "1"], [E + "7"])  # the second copy of the same mail
        summary = item.summary()
        # Q-A3: duplicates = items - groups.
        self.assertEqual(summary, {"items": 14, "groups": 8, "originals": 8, "duplicates": 6, "groups_with_duplicates": 2})
        self.assertEqual(summary["duplicates"], summary["items"] - summary["groups"])

    def test_q_a4_family_mode(self) -> None:
        family = self.derived().dedup.mode("family")
        # Two copies of the same mail whose attachments differ are not duplicates as families.
        self.assertEqual(family.status[E + "1"][0], "original")
        self.assertEqual(family.status[E + "7"][0], "original")
        # Descendants follow their top-level item; only top-level items are grouped.
        self.assertEqual(family.status[E + "8"][0], "original")
        self.assertNotIn(E + "2", [ref for group in family.groups for ref in (group.original, *group.duplicates)])
        # The two loose copies of the PDF are identical families.
        self.assertEqual(family.status[C + "10"][0], "duplicate")
        # Carved rows hang under the pagefile, which has no digest: never deduplicated as a family.
        self.assertNotIn(CARVE + "1", family.status)
        # Completely identical families are duplicates: give the third copy the same two attachments.
        rows = [*fx.EMAIL_ROWS, fx.attachment("<m1@example.com>", "Inbox/3", "logo.png", fx.S2, inline=True)]
        with mock.patch.dict(fx.KINDS, {"email": rows}):
            family = self.derived().dedup.mode("family")
        self.assertEqual(family.status[E + "7"][0], "duplicate")
        self.assertEqual(family.status[E + "8"][0], "duplicate")
        self.assertEqual(family.status[E + "9"][0], "duplicate")
        self.assertEqual(family.status[E + "2"][0], "original")

    def test_custodian_mode_ranks_deterministically(self) -> None:
        derived = self.derived()
        self.assertEqual(derived.dedup.mode("custodian").status, derived.dedup.mode("item").status)

        def rank(ref: str) -> tuple[int, str]:  # a custodian assignment that ranks the second copy first
            return (0, "B") if ref == C + "10" else (1, "A")

        first = compute_dedup(derived.dedup.keys, derived.families, custodian_rank=rank).mode("custodian")
        second = compute_dedup(dict(reversed(list(derived.dedup.keys.items()))), derived.families, custodian_rank=rank).mode("custodian")
        group = next(group for group in first.groups if C + "10" in (group.original, *group.duplicates))
        self.assertEqual(group.original, C + "10")
        self.assertEqual([(g.original, g.duplicates) for g in first.groups], [(g.original, g.duplicates) for g in second.groups])

    def test_document_round_trip(self) -> None:
        dedup = self.derived().dedup
        rebuilt = dedup_index_from_document(dedup_document(dedup))
        for name in ("item", "family", "custodian"):
            self.assertEqual(rebuilt.mode(name).status, dedup.mode(name).status, name)
        with self.assertRaises(ValueError):
            dedup_index_from_document({"keys": {}, "modes": {"item": {"groups": [{"original": 1}]}}})


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class DedupApiTests(unittest.TestCase):
    def setUp(self) -> None:
        FAMILIES_SERVICE.clear()
        MATCH_CACHE.clear()
        self.addCleanup(FAMILIES_SERVICE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        fx.write_run(self.run_dir)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, url: str, expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{url}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def test_summary(self) -> None:
        body = self.get("dedup/summary")
        modes = {mode["id"]: mode for mode in body["modes"]}
        self.assertEqual(modes["item"]["label"], "항목별")
        self.assertEqual((modes["item"]["items"], modes["item"]["groups"], modes["item"]["duplicates"]), (14, 8, 6))
        self.assertEqual(modes["custodian"]["duplicates"], 6)
        self.assertFalse(body["custodians_assigned"])

    def test_q_a3_duplicates_of_the_mail_listing(self) -> None:
        duplicates = self.get("artifacts?limit=100&kind=email&dup=duplicate")["artifacts"]["email"]
        self.assertEqual([row["record_index"] for row in duplicates["artifacts"]], [2, 5, 7, 8])
        originals = self.get("artifacts?limit=100&kind=email&dup=original")["artifacts"]["email"]
        self.assertEqual([row["record_index"] for row in originals["artifacts"]], [1, 3, 4, 6])
        # Email items (8) minus the groups whose original is a mail row (4) = 4 duplicates.
        self.assertEqual(len(duplicates["artifacts"]) + len(originals["artifacts"]), 8)
        files = self.get("files?limit=100&dup=duplicate")
        self.assertEqual([row["record_index"] for row in files["candidates"]], [10])
        anywhere = self.get("files?limit=100&dup=any")
        self.assertEqual([row["record_index"] for row in anywhere["candidates"]], [2, 10])
        family_mode = self.get("artifacts?limit=100&kind=email&dup=duplicate&dup_mode=family")["artifacts"]["email"]
        self.assertEqual(family_mode["artifacts"], [])
        timeline = self.get("timeline?limit=100&dup=duplicate")
        self.assertEqual([row["record_index"] for row in timeline["events"]], [1, 3])
        across = self.get("artifacts?limit=100&dup=duplicate&artifact_type=email-attachment")
        self.assertEqual([tuple(item) for item in across["cross_kind"]["order"]], [("email", 2), ("email", 5), ("email", 8)])

    def test_bad_values_are_korean_422(self) -> None:
        self.assertIn("dup 값은", self.get("artifacts?limit=10&dup=maybe", 422)["detail"])
        self.assertIn("dup_mode", self.get("artifacts?limit=10&dup=original&dup_mode=team", 422)["detail"])
        self.assertIn("dup 조건과 함께", self.get("files?limit=10&dup_mode=family", 422)["detail"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/artifacts?dup=original").status_code, 400)


if __name__ == "__main__":
    unittest.main()
