"""R5 console / catalogue review fixes (docs/plans/r5-residual-2026-10-18.md §5).

Startup-folder executables and the StartupApproved/Run double flag, timeline fields of R5 rows,
Korean names of every R5 time kind, content-type parity with the console, catalogue semantics,
P2P error reasons and carved-only URL hosts in 통합 보기.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app import row_conditions
from rapidtriage.core.derived.engine import run_derived
from rapidtriage.core.derived.url_classes import load_url_classes
from rapidtriage.core.timeline import (
    TIMELINE_EXCLUDED_TYPES,
    TIMELINE_FIELD_MAP,
    canonical_label,
    iter_artifact_detail_events,
)
from rapidtriage.core.triage_rules import load_catalog
from rapidtriage.core.triage_rules.base import FlagContext, RowView
from rapidtriage.core.triage_rules.engine import TriageInputs
from rapidtriage.core.triage_rules.execution import StartupUserPath

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend" / "src"

# R5 modules whose rows carry a row-level ``timestamp_kind`` (docs/plans/r5-residual-2026-10-18.md).
R5_MODULES = (
    "rapidtriage/artifacts/p2p.py",
    "rapidtriage/artifacts/mobile/adb_backup.py",
    "rapidtriage/artifacts/windows/browser_analytics.py",
    "rapidtriage/artifacts/windows/phone_link.py",
    "rapidtriage/artifacts/windows/system_extras.py",
    "rapidtriage/artifacts/windows/registry_depth.py",
    "rapidtriage/artifacts/windows/media_players.py",
    "rapidtriage/artifacts/email_clients.py",
)
# Row types of those modules (the canonical timeline label strips a type noun: "transfer-completed"
# of a p2p-transfer row reads "completed").
R5_TYPES = (
    "p2p-torrent",
    "p2p-transfer",
    "p2p-shared-file",
    "p2p-search-term",
    "p2p-client-config",
    "android-backup-member",
    "browser-analytics-cookie",
    "phone-link-message",
    "phone-link-call",
    "phone-link-photo",
    "startup-item",
    "office-backstage-item",
    "vm-config",
    "av-detection-log",
)
KIND_PATTERNS = (
    re.compile(r'"timestamp_kind":\s*"([a-z][a-z0-9-]*)"'),
    re.compile(r'\bkind="([a-z][a-z0-9-]*)"'),
    re.compile(r'kind = "([a-z][a-z0-9-]*)" if isinstance\(.* else "([a-z][a-z0-9-]*)"'),
    re.compile(r'\("[a-z_]+_at", "([a-z][a-z0-9-]*)"\)'),
    re.compile(r'= \w+, "([a-z]+-[a-z-]+)", f?"'),
)


def ts_labels(path: Path) -> set[str]:
    """Keys of a ``Record<string, string>`` literal (``TIMESTAMP_KIND_LABELS``)."""
    text = path.read_text(encoding="utf-8")
    body = text.split("TIMESTAMP_KIND_LABELS", 1)[1].split("};", 1)[0]
    return set(re.findall(r'^\s*"?([a-z0-9_-]+)"?:\s*"', body, flags=re.MULTILINE))


def ts_string_array(text: str, name: str) -> list[str]:
    body = text.split(f"{name} = [", 1)[1].split("]", 1)[0]
    return re.findall(r'"([^"]+)"', body)


def startup_row(**details: object) -> RowView:
    return RowView(kind="windows-system", collection="artifacts", source_kind="windows-system", index=0, row={"artifact_type": "startup-item", "details": details})


class StartupRuleTests(unittest.TestCase):
    def test_user_startup_folder_executable_is_flagged(self) -> None:
        rule = StartupUserPath()
        result = rule.apply(startup_row(item_name="payload.exe", command="payload.exe", item_kind="executable", scope="user", startup_source="startup-folder-file"), FlagContext())
        assert result is not None
        self.assertIn("시작프로그램 폴더의 실행 파일", result.evidence["reasons"])  # type: ignore[operator]
        self.assertIsNone(result.grade)
        machine = startup_row(item_name="tray.exe", command="tray.exe", item_kind="executable", scope="machine", startup_source="startup-folder-file")
        self.assertIsNone(rule.apply(machine, FlagContext()))

    def test_startup_approved_run_row_joined_from_run_is_capped_at_c(self) -> None:
        rule = StartupUserPath()
        command = r"C:\Users\alice\AppData\Roaming\upd\upd.exe /silent"
        joined = rule.apply(startup_row(item_name="Updater", command=command, enabled=True, scope="user", startup_source="startup-approved-run", run_value_found=True), FlagContext())
        assert joined is not None
        self.assertEqual(joined.grade, "C")
        self.assertIn("registry.run_user_path", joined.note or "")
        # A Startup-folder row (no Run value of its own) keeps the catalogue grade B.
        folder = rule.apply(startup_row(item_name="x.lnk", command=command, scope="user", startup_source="startup-approved-startup-folder", run_value_found=None), FlagContext())
        assert folder is not None
        self.assertIsNone(folder.grade)


class TimelineTests(unittest.TestCase):
    def kinds(self, artifact_type: str, details: dict[str, object]) -> list[str]:
        return [str(event["timestamp_kind"]) for event in iter_artifact_detail_events(artifact_type, details)]

    def test_r5_row_fields_are_timeline_events(self) -> None:
        transfer = {"timestamp": "2024-01-02T00:00:00Z", "timestamp_kind": "transfer-completed", "added_at": "2024-01-01T00:00:00Z", "completed_at": "2024-01-02T00:00:00Z", "last_seen_complete_at": "2024-01-03T00:00:00Z"}
        self.assertEqual(sorted(self.kinds("p2p-transfer", transfer)), ["added", "completed", "last-seen-complete"])
        shared = {"timestamp": "2024-02-01T00:00:00Z", "timestamp_kind": "last-shared", "file_date": "2023-12-01T00:00:00Z"}
        self.assertEqual(sorted(self.kinds("p2p-shared-file", shared)), ["file-date", "last-shared"])
        ga = {"timestamp": "2024-01-05T00:00:00Z", "timestamp_kind": "ga-current-visit", "current_visit_at": "2024-01-05T00:00:00Z", "previous_visit_at": "2024-01-04T00:00:00Z", "first_visit_at": "2023-01-01T00:00:00Z", "campaign_set_at": "2023-06-01T00:00:00Z"}
        self.assertEqual(sorted(self.kinds("browser-analytics-cookie", ga)), ["ga-campaign-set", "ga-current-visit", "ga-first-visit", "ga-previous-visit"])
        photo = {"timestamp": "2024-01-02T00:00:00Z", "timestamp_kind": "photo-taken", "taken_at": "2024-01-02T00:00:00Z", "updated_at": "2024-01-09T00:00:00Z"}
        events = list(iter_artifact_detail_events("phone-link-photo", photo))
        self.assertEqual(sorted(str(event["timestamp_kind"]) for event in events), ["synced", "taken"])
        self.assertTrue(all(not event.get("extra_labels") for event in events))  # the row time merges, no "taken" twice

    def test_file_date_keeps_its_head_and_location_candidates_are_excluded(self) -> None:
        self.assertEqual(canonical_label("file-date", "p2p-shared-file"), "file-date")
        self.assertEqual(canonical_label("transfer-completed", "p2p-transfer"), "completed")
        self.assertIn("location-url-candidate", TIMELINE_EXCLUDED_TYPES)

    def test_every_r5_time_kind_has_a_korean_label(self) -> None:
        labels = ts_labels(FRONTEND / "utils" / "timeKinds.ts")
        raw: set[str] = set()
        for module in R5_MODULES:
            text = (ROOT / module).read_text(encoding="utf-8")
            for pattern in KIND_PATTERNS:
                for match in pattern.finditer(text):
                    raw.update(group for group in match.groups() if group)
        from rapidtriage.artifacts.windows.registry_depth import TIMESTAMP_KINDS

        raw.update(TIMESTAMP_KINDS.values())
        for must in ("transfer-completed", "torrent-created", "member-modified", "call-start", "photo-taken", "photo-synced", "ga-first-visit"):
            self.assertIn(must, raw, "the kind scan missed a known R5 kind")
        missing = {kind for kind in raw if kind not in labels}
        self.assertEqual(missing, set(), "raw timestamp_kind without a Korean label")
        canonical = {canonical_label(kind, artifact_type) for kind in raw for artifact_type in R5_TYPES}
        for artifact_type in R5_TYPES:
            canonical.update(canonical_label(field.label, artifact_type) for field in TIMELINE_FIELD_MAP.get(artifact_type, ()))
        missing = {kind for kind in canonical if kind not in labels}
        self.assertEqual(missing, set(), "timeline (canonical) time kind without a Korean label")


class ContentTypeParityTests(unittest.TestCase):
    def test_console_mirrors_server_row_conditions(self) -> None:
        text = (FRONTEND / "features" / "filters" / "contentTypes.ts").read_text(encoding="utf-8")
        self.assertEqual(ts_string_array(text, "TARGET_PATH_KEYS"), list(row_conditions.TARGET_PATH_KEYS))
        self.assertEqual(ts_string_array(text, "PATH_IS_CONTENT_PREFIXES"), list(row_conditions.PATH_IS_CONTENT_PREFIXES))
        self.assertEqual(ts_string_array(text, "PATH_NOT_CONTENT_PREFIXES"), list(row_conditions.PATH_NOT_CONTENT_PREFIXES))
        types = text.split("PATH_IS_CONTENT_TYPES", 1)[1].split("]);", 1)[0]
        self.assertEqual(set(re.findall(r'"([^"]+)"', types)), set(row_conditions.PATH_IS_CONTENT_TYPES))


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()

    def family_of(self, artifact_type: str) -> str:
        return next(str(item["id"]) for item in self.catalog.families if artifact_type in item.get("types", []))

    def column(self, family_id: str, key: str) -> dict:
        family = next(item for item in self.catalog.families if item["id"] == family_id)
        columns = [*family.get("core_columns", []), *family.get("aux_columns", [])]
        return next(dict(column) for column in columns if column["key"] == key)

    def test_candidate_lists_are_not_owner_accounts(self) -> None:
        wallet = self.family_of("crypto-wallet-presence")
        self.assertNotIn("semantic", self.column(wallet, "public_addresses"))
        store = self.family_of("email-client-store")
        self.assertEqual(self.column(store, "address_candidates").get("semantic"), "person")
        self.assertNotIn("semantic", self.column("p2p-torrent", "files"))

    def test_p2p_error_reasons_and_sshd_values_read_in_korean(self) -> None:
        labels = self.column("p2p-error", "reason")["value_labels"]
        text = (ROOT / "rapidtriage" / "artifacts" / "p2p.py").read_text(encoding="utf-8")
        reasons = set(re.findall(r'_error\(path, [^,]+, "([a-z0-9-]+)"', text))
        self.assertGreaterEqual(len(reasons), 10)
        self.assertEqual(reasons - set(labels), set())
        sshd = self.family_of("ssh-server-config")
        self.assertEqual(self.column(sshd, "password_authentication")["value_labels"]["no"], "허용 안 함")

    def test_proton_drive_is_not_webmail(self) -> None:
        classes = load_url_classes()
        self.assertEqual(classes.classify("mail.proton.me"), "webmail")
        self.assertEqual(classes.classify("drive.proton.me"), "cloud")
        self.assertIsNone(classes.classify("vpn.proton.me"))


class CarvedUrlTests(unittest.TestCase):
    def test_hosts_seen_only_in_url_carving_are_marked_and_counted_apart(self) -> None:
        carved = [
            {"artifact_type": "carved-url-candidate", "path": "C:/pagefile.sys", "details": {"url": "https://mail.naver.com/x", "encoding": "ascii", "offset": 10}},
            {"artifact_type": "carved-url-candidate", "path": "C:/pagefile.sys", "details": {"url": "https://mail.google.com/x", "encoding": "ascii", "offset": 90}},
        ]
        visits = [{"artifact_type": "browser-visit", "details": {"url": "https://mail.google.com/mail/u/0", "timestamp": "2026-01-01T00:00:00Z"}}]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            records = base / "browser.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in visits), encoding="utf-8")
            payload = base / "browser.json"
            payload.write_text(json.dumps({"records_path": str(records), "record_count": len(visits), "artifacts": []}), encoding="utf-8")
            rows_path = base / "rows-url.jsonl"
            rows_path.write_text("".join(json.dumps(row) + "\n" for row in carved), encoding="utf-8")
            inputs = TriageInputs(output_dir=base, artifact_payloads={"browser": payload}, analyses=[("u1", "url-carve", rows_path, len(carved))])
            summary = run_derived(inputs, base / "out", source_label="test")
            table = {row["normalized"]: row for row in map(json.loads, (base / "out" / "urls.jsonl").read_text(encoding="utf-8").splitlines())}
        self.assertTrue(table["mail.naver.com"].get("carved_only"))
        self.assertNotIn("carved_only", table["mail.google.com"])  # also visited
        urls = summary["tables"]["urls"]
        self.assertEqual(urls["by_class"], {"webmail": 1})
        self.assertEqual(urls["by_class_carved"], {"webmail": 1})


if __name__ == "__main__":
    unittest.main()
