"""통합 보기 engine (plan axiom-adoption §3.2): semantic tags, normalisation, caps, credential masking, partial sets."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.derived import engine as derived_engine
from rapidtriage.core.derived.engine import (
    SEARCH_TEXT_CHARS,
    TABLES,
    family_plans,
    run_derived,
    search_text,
    url_example,
)
from rapidtriage.core.derived.normalize import (
    clean,
    credential_record,
    device_key,
    mask_secret,
    normalize,
    path_key,
    person_key,
    phone_e164,
    url_host,
)
from rapidtriage.core.derived.stage import DERIVED_ANALYSIS_KIND, run_derived_stage
from rapidtriage.core.derived.url_classes import (
    UrlClassError,
    load_url_classes,
    parse_url_classes,
)
from rapidtriage.core.triage_rules.catalog import (
    SEMANTIC_TAGS,
    CatalogError,
    load_catalog,
    parse_catalog,
)
from rapidtriage.core.triage_rules.engine import TriageInputs

SECRET = "SuperSecretToken-1234567890"
# Families whose catalogue columns carry no identifier (reviewed for the semantic tagging, §3.2).
NO_IDENTIFIER_FAMILIES = frozenset(
    {
        "eventlog-record-candidate",  # header-only record candidates (strings, no parsed fields)
        "synthetic-media",  # scoring rows
        "defender",  # log-file summaries
        "system-log",  # log-file summaries
        "string-candidate",  # non-evidence string pivots
        "summary",  # aggregate rows (would double count)
        "timeline",  # copies of artifact rows
        "indicator",  # copies of row values
        "timezone",  # one registry value
        "web-upload-candidate",  # restates its source row (r2 console fix m3)
        "messenger-error",  # store read failures (r2 console fix m2)
        "email-client-error",  # mail client store read failures (r5 L1)
        "ntfs-logfile-transaction",  # LSN / op codes; file names are bare candidates, not paths (R3 §3.3)
        "logon-banner",  # caption/text of a legal notice (R5 L2)
    }
)


def event(event_id: str, **details: object) -> dict[str, object]:
    return {
        "artifact_type": "eventlog-event",
        "details": {"event_id": event_id, "channel": "Security", "timestamp": "2024-05-01T10:00:00Z", **details},
    }


class NormalizationTests(unittest.TestCase):
    def test_people(self) -> None:
        self.assertEqual(person_key("Alice <Alice.Kim@Example.COM>"), "alice.kim@example.com")
        self.assertEqual(person_key("010-1234-5678"), "+821012345678")
        self.assertEqual(person_key("+1 (555) 010-9999"), "+15550109999")
        self.assertEqual(person_key("0082 10 1234 5678"), "+821012345678")
        self.assertEqual(person_key("s-1-5-21-1-2-3-1001"), "S-1-5-21-1-2-3-1001")
        self.assertEqual(person_key("  CORP\\Alice   Kim "), "corp\\alice kim")
        self.assertIsNone(phone_e164("12-34"))

    def test_paths(self) -> None:
        self.assertEqual(path_key("C:/Users/Alice//Desktop/A.TXT"), "c:\\users\\alice\\desktop\\a.txt")
        self.assertEqual(path_key("\\\\?\\C:\\Temp\\"), "c:\\temp")
        self.assertEqual(path_key("\\\\SERVER\\Share\\x"), "\\\\server\\share\\x")
        self.assertEqual(path_key("file:///C:/Users/a%20b.txt"), "c:\\users\\a b.txt")
        self.assertEqual(path_key("C:\\"), "c:\\")

    def test_urls_and_devices(self) -> None:
        self.assertEqual(url_host("https://User@WWW.Example.com:8443/a?b=1"), "www.example.com")
        self.assertEqual(url_host(".naver.com"), "naver.com")
        self.assertEqual(url_host("mail.naver.com/inbox"), "mail.naver.com")
        self.assertIsNone(url_host("not a host"))
        self.assertEqual(device_key("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(device_key("[fe80:0:0::1]"), "fe80::1")
        self.assertEqual(device_key("{1B2C3D4E-0000-1111-2222-333344445555}"), "1b2c3d4e-0000-1111-2222-333344445555")
        self.assertEqual(normalize("attachments", "C:\\Mail\\Report.PDF"), "report.pdf")

    def test_placeholders_are_dropped(self) -> None:
        for raw in ("", "-", "N/A", "null", "0", None, True, [], {"a": 1}):
            self.assertIsNone(clean(raw), raw)
        self.assertEqual(clean("  value "), "value")

    def test_mask_never_returns_the_clear_value(self) -> None:
        self.assertEqual(mask_secret("short"), "•••••")
        masked = mask_secret(SECRET)
        self.assertNotIn(SECRET[2:-1], masked)
        self.assertTrue(masked.startswith("Su") and masked.endswith("0"))
        # A value its parser already masked is masked again (no pass-through of text containing '*').
        self.assertNotIn("pass*word12", mask_secret("pass*word12345"))
        record = credential_record(SECRET)
        self.assertEqual(record["length"], len(SECRET))
        self.assertEqual(len(str(record["sha256"])), 64)
        own = credential_record("[마스킹됨]", sha256="A" * 64, length=12)
        self.assertEqual((own["sha256"], own["length"]), ("a" * 64, 12))


class NormalizationRegressionTests(unittest.TestCase):
    """Adversarial review of E2 (items 8-10)."""

    def test_phone_needs_a_prefix_or_punctuated_phone_length(self) -> None:
        # Dates and employee numbers are not phone numbers: they stay separate text keys.
        self.assertIsNone(phone_e164("20240501"))
        self.assertIsNone(phone_e164("2024-05-01"))
        self.assertIsNone(phone_e164("1234567"))
        self.assertIsNone(phone_e164("123456789"))
        self.assertEqual(person_key("20240501"), "20240501")
        self.assertNotEqual(person_key("2024-05-01"), person_key("20240501"))
        self.assertEqual(person_key("2024-05-01"), "2024-05-01")
        # Prefixed numbers and punctuated phone-length numbers still are.
        self.assertEqual(phone_e164("1-555-010-9999"), "15550109999")
        self.assertEqual(phone_e164("+82 10 1234 5678"), "+821012345678")
        self.assertEqual(phone_e164("02-123-4567"), "+8221234567")

    def test_posix_paths_keep_slash_and_case(self) -> None:
        self.assertEqual(path_key("/sdcard/DCIM//Camera/IMG_1.jpg/"), "/sdcard/DCIM/Camera/IMG_1.jpg")
        self.assertNotEqual(path_key("/data/A.db"), path_key("/data/a.db"))
        self.assertEqual(path_key("file:///home/Alice/x.TXT"), "/home/Alice/x.TXT")
        self.assertEqual(path_key("/"), "/")
        # Windows paths are unchanged: drive letter, UNC, backslash, or a bare name.
        self.assertEqual(path_key("C:/Users/A.TXT"), "c:\\users\\a.txt")
        self.assertEqual(path_key("Users\\Alice/Doc.TXT"), "users\\alice\\doc.txt")
        self.assertEqual(path_key("Report.PDF"), "report.pdf")

    def test_credential_hash_covers_the_full_value(self) -> None:
        long_secret = "k" * 3000 + "TAIL"
        other = "k" * 3000 + "DIFF"
        self.assertEqual(len(clean(long_secret) or ""), 2048)
        self.assertEqual(clean(long_secret, max_chars=None), long_secret)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            records = base / "kakao.jsonl"
            rows = [
                {"artifact_type": "kakaotalk-windows-crypto-material-candidate", "details": {"candidate_value": value}}
                for value in (long_secret, other)
            ]
            records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload = base / "artifacts_kakao.json"
            payload.write_text(json.dumps({"records_path": str(records), "record_count": 2, "artifacts": []}), encoding="utf-8")
            out = base / "out"
            summary = run_derived(
                TriageInputs(output_dir=base, artifact_payloads={"kakaotalk-windows": payload}), out, source_label="test"
            )
            table = [json.loads(line) for line in (out / "credentials.jsonl").read_text(encoding="utf-8").splitlines()]
        # Two secrets sharing their first 2,048 characters stay two rows; length is the full length.
        self.assertEqual(len(table), 2)
        self.assertEqual({row["length"] for row in table}, {3004})
        self.assertEqual({row["sha256"] for row in table}, {credential_record(long_secret)["sha256"], credential_record(other)["sha256"]})
        self.assertIn("오프라인", str(summary["limitation"]))


class CatalogSemanticTests(unittest.TestCase):
    def test_every_family_is_reviewed(self) -> None:
        catalog = load_catalog()
        # 54 + r2 M1 (3) + r2 M4 (1) + r2 M2 (6) + r2 M3 (2) + console fix (cloud-sync split 2, messenger-error 1)
        # + r3 O1 (10) + r3 O3 (ntfs-timestamp-mismatch, ntfs-logfile-transaction, carved-file)
        # + R5 L3 (11: location-url-candidate, browser-analytics-cookie, carved-url-candidate, 6 p2p, 2 android-backup)
        # + R5 L2 (15: startup, banner, Office x2, SSH x5, VM, wallet, AV, wallpaper, credential stores, NTFS volume)
        # + R6 S2 lane A (1: av-product-presence).
        self.assertEqual(len(catalog.families), 120)
        for family in catalog.families:
            columns = [*family["core_columns"], *(family.get("aux_columns") or [])]
            tagged = [column for column in columns if column.get("semantic")]
            if family["id"] in NO_IDENTIFIER_FAMILIES:
                self.assertEqual(tagged, [], family["id"])
            else:
                self.assertTrue(tagged, f"{family['id']} has no semantic column")
            for column in tagged:
                self.assertIn(column["semantic"], SEMANTIC_TAGS)

    def test_plans_map_tags_to_tables(self) -> None:
        plans = family_plans(load_catalog())
        people = {column.key for column in plans["sam-account"].columns if column.table == "people"}
        self.assertIn("user_name", people)
        autofill = next(column for column in plans["browser-autofill"].columns if column.semantic == "credential")
        self.assertEqual(dict(autofill.when), {"mask_reason": frozenset({"secret-field-name"})})
        self.assertEqual(plans["media-image"].columns[0].table, "")  # geo feeds no table

    def test_validator_rejects_bad_tags(self) -> None:
        def family(column: dict[str, object]) -> list[tuple[str, bytes]]:
            document = {"families": [{"id": "x", "label": "X", "core_columns": [{"key": "a", "label": "A", **column}]}]}
            return [("x.yaml", json.dumps(document).encode("utf-8"))]

        for column, message in (
            ({"semantic": "people"}, "semantic"),
            ({"semantic_when": {"f": ["v"]}}, "semantic_when"),
            ({"semantic": "account", "semantic_when": {"f": "v"}}, "semantic_when"),
            ({"derive": "nope"}, "derive"),
        ):
            with self.assertRaises(CatalogError) as caught:
                parse_catalog(family(column))
            self.assertIn(message, str(caught.exception))
        parse_catalog(family({"semantic": "account", "semantic_when": {"f": ["v"]}, "derive": "auto_logon"}))


class R2ConsoleCatalogTests(unittest.TestCase):
    """r2 console fix m1/m2/m3/m8/M7: family split, column order, meaning tags, value labels."""

    def setUp(self) -> None:
        self.catalog = load_catalog()
        self.families = {family["id"]: family for family in self.catalog.families}

    def column(self, family: str, key: str) -> dict[str, object]:
        family_def = self.families[family]
        return next(column for column in [*family_def["core_columns"], *(family_def.get("aux_columns") or [])] if column["key"] == key)

    def core_labels(self, family: str) -> list[str]:
        return [str(column["label"]) for column in self.families[family]["core_columns"]]

    def test_cloud_sync_is_split_into_account_file_event_and_inventory(self) -> None:
        self.assertEqual(self.catalog.family_for("cloud-sync-account"), "cloud-sync-account")
        self.assertEqual(self.catalog.family_for("cloud-sync-file"), "cloud-sync")
        self.assertEqual(self.catalog.family_for("cloud-sync-event"), "cloud-sync")
        self.assertEqual(self.catalog.family_for("cloud-sync-inventory"), "cloud-sync-inventory")
        self.assertEqual(self.core_labels("cloud-sync-account")[:5], ["클라이언트", "계정", "동기화 폴더", "테넌트", "계정 ID"])
        self.assertEqual(self.column("cloud-sync-account", "account_id")["semantic"], "account")
        self.assertEqual(self.core_labels("cloud-sync-inventory")[:3], ["클라이언트", "상태", "사유"])
        self.assertIn("cloud.sync_folder_outside_user_profile", self.families["cloud-sync-account"]["rules"])
        # m3: the cloud-relative item path is no evidence path; m8: modified time is the timestamp kind.
        self.assertNotIn("semantic", self.column("cloud-sync", "item_path"))
        timestamp = self.column("cloud-sync", "timestamp")
        self.assertEqual(timestamp["ts_kind"], "cloud-modified")
        keys = [column["key"] for column in self.families["cloud-sync"]["aux_columns"]]
        self.assertNotIn("modified_at", keys)

    def test_contact_email_tags_agree(self) -> None:
        self.assertEqual(self.column("contact", "email")["semantic"], self.column("messenger-contact", "email")["semantic"])

    def test_email_core_order_and_pst_time(self) -> None:
        self.assertEqual(self.core_labels("email"), ["시각(제출·배달·Date)", "보낸 사람", "받는 사람", "제목", "첨부", "폴더", "읽음"])
        time = self.families["email"]["core_columns"][0]
        self.assertEqual(time["key"], "submit_time")
        self.assertEqual(time["aliases"][:2], ["delivery_time", "date"])
        aux = [column["key"] for column in self.families["email"]["aux_columns"]]
        for key in ("date", "message_id", "authentication_results", "return_path", "reply_to"):
            self.assertIn(key, aux)
        self.assertEqual(self.column("email", "date")["label"], "Date 헤더(발신 주장)")

    def test_cache_entry_and_upload_candidate_order_and_tags(self) -> None:
        self.assertEqual(self.core_labels("browser-cache-entry")[:8], ["시각", "주소 (URL)", "응답 상태", "콘텐츠 형식 (Content-Type)", "크기", "본문 SHA-256", "호스트", "요청 방식"])
        self.assertEqual(self.column("browser-cache-entry", "url")["semantic_when"], {"method": ["POST"]})
        self.assertEqual(self.core_labels("web-upload-candidate")[:5], ["시각", "서비스", "주소 (URL)", "근거 강도", "관련 파일 이름 후보"])
        family = self.families["web-upload-candidate"]
        self.assertFalse([column for column in [*family["core_columns"], *family["aux_columns"]] if column.get("semantic")])
        self.assertEqual(self.column("web-upload-candidate", "source_artifact_type")["format"], "artifact_type")
        # Cache GET resources stay out of 통합 보기 › URL; POST (upload) entries go in.
        plan = next(column for column in family_plans(self.catalog)["browser-cache-entry"].columns if column.key == "url")
        self.assertEqual(dict(plan.when), {"method": frozenset({"POST"})})

    def test_messenger_error_family_and_attachment_tags(self) -> None:
        self.assertEqual(self.catalog.family_for("chat-parse-error"), "messenger-error")
        self.assertEqual(self.catalog.family_for("chat-app-inventory"), "messenger-app")
        self.assertEqual(self.core_labels("messenger-error")[:3], ["앱", "사유", "앱 폴더"])
        attachment = self.column("messenger", "attachments")
        self.assertEqual((attachment["semantic"], attachment["aliases"][0]), ("attachment", "attachment_name"))
        for key in ("from", "to"):
            self.assertNotIn("semantic", self.column("email-attachment", key))
        self.assertEqual(self.column("kakaotalk-shared-picture", "download_time")["ts_kind"], "saved")

    def test_value_labels_cover_r2_raw_values(self) -> None:
        direction = self.column("messenger", "direction")["value_labels"]
        self.assertEqual({direction[raw] for raw in ("outgoing", "sent", "발신")}, {"발신"})
        self.assertEqual({direction[raw] for raw in ("incoming", "received", "수신")}, {"수신"})
        self.assertEqual(direction["unknown"], "불명")
        self.assertEqual(self.column("messenger-attachment", "direction")["value_labels"], direction)
        self.assertEqual(self.column("messenger", "deleted_state")["value_labels"]["live"], "활성")
        self.assertIn("leveldb-plaintext", self.column("messenger-app", "encryption_state")["value_labels"])
        self.assertIn("executable-trace-only", self.column("cloud-sync-inventory", "inventory_status")["value_labels"])
        self.assertIn("mirror", self.column("cloud-sync", "sync_state")["value_labels"])
        self.assertIn("chromium-simple", self.column("browser-cache-entry", "cache_format")["value_labels"])

    def test_value_labels_validator_is_korean(self) -> None:
        def family(column: dict[str, object]) -> list[tuple[str, bytes]]:
            document = {"families": [{"id": "x", "label": "X", "core_columns": [{"key": "a", "label": "A", **column}]}]}
            return [("x.yaml", json.dumps(document).encode("utf-8"))]

        for labels in ({}, ["a"], {"a": ""}, {"": "가"}, {"a": 1}):
            with self.assertRaises(CatalogError) as caught:
                parse_catalog(family({"value_labels": labels}))
            self.assertIn("value_labels", str(caught.exception))
            self.assertRegex(str(caught.exception), "[가-힣]")
        parse_catalog(family({"value_labels": {"outgoing": "발신"}}))


class UrlClassTests(unittest.TestCase):
    def test_packaged_classes_load_with_sources(self) -> None:
        classes = load_url_classes()
        self.assertEqual(
            set(classes.labels),
            {"search", "social", "cloud", "messenger", "jobs", "finance", "adult", "suspicious", "webmail", "torrent"},
        )
        for urls in classes.sources.values():
            self.assertTrue(urls and all(url.startswith("https://") for url in urls))
        self.assertEqual(classes.classify("www.google.com"), "search")
        self.assertEqual(classes.classify("search.naver.com"), "search")
        # R5 L3: personal / Korean webmail is its own class (longest domain wins over naver.com search hosts).
        self.assertEqual(classes.classify("mail.naver.com"), "webmail")
        self.assertIsNone(classes.classify("www.naver.com"))
        self.assertEqual(classes.classify("x.blog.naver.com"), "social")
        self.assertIsNone(classes.classify("com"))

    def test_bad_class_files_are_korean_errors(self) -> None:
        for text in (b"classes: []", b"classes: [{id: a, label_ko: A, sources: [http://x], domains: [a.com]}]"):
            with self.assertRaises(UrlClassError):
                parse_url_classes(text)
        with self.assertRaises(UrlClassError):
            parse_url_classes(
                b"classes: [{id: a, label_ko: A, sources: [https://x], domains: [a.com]},"
                b" {id: b, label_ko: B, sources: [https://x], domains: [a.com]}]"
            )


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def write_kind(self, kind: str, rows: list[dict[str, object]], *, record_count: int | None = None) -> Path:
        records = self.base / f"{kind}.jsonl"
        records.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        types: dict[str, int] = {}
        for row in rows:
            types[str(row["artifact_type"])] = types.get(str(row["artifact_type"]), 0) + 1
        payload = {
            "records_path": str(records),
            "record_count": len(rows) if record_count is None else record_count,
            "artifacts": [],
            "summary": {"artifact_type_counts": types},
        }
        path = self.base / f"artifacts_{kind}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def inputs(self, **kinds: Path) -> TriageInputs:
        files = self.base / "files.json"
        files.write_text(
            json.dumps({"candidates": [{"path": "C:/Users/Alice/Desktop/Plan.docx", "name": "Plan.docx"}], "inventory": []}),
            encoding="utf-8",
        )
        return TriageInputs(output_dir=self.base, artifact_payloads={name.replace("_", "-"): path for name, path in kinds.items()}, files_path=files)

    def table(self, out: Path, name: str) -> list[dict[str, object]]:
        return [json.loads(line) for line in (out / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_tables_samples_and_first_last_seen(self) -> None:
        eventlog = self.write_kind(
            "eventlog",
            [
                *[event("4624", target_user_name="Alice", source_ip="10.0.0.5", timestamp=f"2024-05-0{day}T10:00:00Z") for day in (1, 2, 3)],
                *[event("4672", subject_user_name="ALICE") for _ in range(30)],
                event("4688", process_name="C:\\Windows\\System32\\cmd.exe"),
            ],
        )
        accounts = self.write_kind(
            "windows_os_account",
            [{"artifact_type": "windows-sam-account", "details": {"user_name": "alice", "last_logon_at": "2023-01-01T00:00:00Z"}}],
        )
        browser = self.write_kind(
            "browser",
            [
                {"artifact_type": "browser-visit", "details": {"url": "https://www.google.com/search?q=x", "timestamp": "2024-01-01T00:00:00Z"}},
                {"artifact_type": "browser-visit", "details": {"url": "https://WWW.google.com:443/maps"}},
            ],
        )
        out = self.base / "out"
        summary = run_derived(self.inputs(eventlog=eventlog, windows_os_account=accounts, browser=browser), out, source_label="test")
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(
            {path.name for path in out.iterdir()},
            {*(f"{table}.jsonl" for table in TABLES), *(f"{table}.index.json" for table in TABLES), "summary.json"},
        )
        # The paging index points at each row's own line.
        raw = (out / "people.jsonl").read_bytes()
        index = json.loads((out / "people.index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["rows"], len(raw.splitlines()))
        for position in range(index["rows"]):
            offset, length = index["offsets"][position], index["lengths"][position]
            row = json.loads(raw[offset : offset + length])
            kinds = index["kind_sets"][index["kinds"][position]]
            self.assertEqual(
                (row["normalized"], row["count"], list(row["kinds"])),
                (index["normalized"][position], index["count"][position], kinds),
            )
        people = self.table(out, "people")
        alice = people[0]
        self.assertEqual((alice["normalized"], alice["count"]), ("alice", 34))
        self.assertEqual(alice["kinds"], {"eventlog": 33, "windows-os-account": 1})
        self.assertEqual(alice["families"], {"eventlog-event": 33, "sam-account": 1})
        self.assertEqual(alice["first_seen"], "2023-01-01T00:00:00+00:00")
        self.assertEqual(alice["last_seen"], "2024-05-03T10:00:00+00:00")
        self.assertEqual(len(alice["samples"]), 20)
        # Round-robin over kinds: the single SAM row is among the samples.
        self.assertIn("windows-os-account", {sample["kind"] for sample in alice["samples"]})
        self.assertEqual(self.table(out, "devices")[0]["normalized"], "10.0.0.5")
        paths = {row["normalized"]: row for row in self.table(out, "paths")}
        self.assertIn("c:\\windows\\system32\\cmd.exe", paths)
        self.assertEqual(paths["c:\\users\\alice\\desktop\\plan.docx"]["kinds"], {"files:candidates": 1})
        urls = self.table(out, "urls")
        self.assertEqual((urls[0]["normalized"], urls[0]["count"], urls[0]["url_class"]), ("www.google.com", 2, "search"))
        self.assertEqual(urls[0]["examples"], ["https://www.google.com/search", "https://www.google.com:443/maps"])  # no query strings
        self.assertEqual(summary["tables"]["people"]["rows"], len(people))

    def test_credentials_are_never_stored_in_clear(self) -> None:
        kakao = self.write_kind(
            "kakaotalk_windows",
            [{"artifact_type": "kakaotalk-windows-crypto-material-candidate", "details": {"candidate_value": SECRET}}],
        )
        browser = self.write_kind(
            "browser",
            [
                {
                    "artifact_type": "browser-autofill",
                    "details": {"value_preview": "[마스킹됨]", "mask_reason": "secret-field-name", "value_sha256": "b" * 64, "value_length": 9},
                },
                {"artifact_type": "browser-autofill", "details": {"value_preview": "[마스킹됨]", "mask_reason": "personal-field-name", "value_sha256": "c" * 64}},
            ],
        )
        out = self.base / "out"
        run_derived(self.inputs(kakaotalk_windows=kakao, browser=browser), out, source_label="test")
        for path in out.iterdir():
            self.assertNotIn(SECRET, path.read_text(encoding="utf-8"), path.name)
            self.assertNotIn(SECRET[2:-1], path.read_text(encoding="utf-8"), path.name)
        rows = {row["normalized"]: row for row in self.table(out, "credentials")}
        self.assertEqual(set(rows), {f"sha256:{'b' * 64}", f"sha256:{credential_record(SECRET)['sha256']}"})
        own = rows[f"sha256:{'b' * 64}"]
        self.assertEqual((own["length"], own["value"]), (9, "•" * len("[마스킹됨]")))
        token = rows[f"sha256:{credential_record(SECRET)['sha256']}"]
        self.assertEqual(token["length"], len(SECRET))
        self.assertNotEqual(token["value"], SECRET)

    def test_value_cap_and_memory_cap(self) -> None:
        eventlog = self.write_kind("eventlog", [event("4624", target_user_name=f"user{index}") for index in range(5)] + [event("4624", target_user_name="user0")])
        out = self.base / "out"
        summary = run_derived(self.inputs(eventlog=eventlog), out, source_label="test", max_values=2)
        table = summary["tables"]["people"]
        self.assertEqual((table["rows"], table["capped"], table["cap_reason"], table["dropped_values"]), (2, True, "values", 3))
        # Known values still count after the cap.
        self.assertEqual(self.table(out, "people")[0]["count"], 2)
        summary = run_derived(self.inputs(eventlog=eventlog), self.base / "out2", source_label="test", memory_cap=1)
        self.assertEqual((summary["tables"]["people"]["rows"], summary["tables"]["people"]["cap_reason"]), (1, "memory"))

    def test_partial_when_a_source_ends_early(self) -> None:
        eventlog = self.write_kind("eventlog", [event("4624", target_user_name="bob")], record_count=3)
        summary = run_derived(self.inputs(eventlog=eventlog), self.base / "out", source_label="test")
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["coverage"]["incomplete"], ["eventlog"])
        missing = self.base / "missing.json"
        summary = run_derived(TriageInputs(output_dir=self.base, artifact_payloads={"browser": missing}), self.base / "out3", source_label="t")
        self.assertEqual(summary["status"], "partial")
        self.assertIn("source:browser", summary["errors"])

    def test_list_values_and_recipient_lists(self) -> None:
        email = self.write_kind(
            "email",
            [
                {
                    "artifact_type": "email-message",
                    "details": {
                        "from": "Kim <KIM@corp.example>",
                        "to": "a@x.example, B@y.example",
                        "attachments": [{"filename": "Q3.xlsx"}, {"name": "photo.jpg"}],
                    },
                }
            ],
        )
        out = self.base / "out"
        run_derived(self.inputs(email=email), out, source_label="test")
        people = {row["normalized"]: row["semantic"] for row in self.table(out, "people")}
        self.assertEqual(people, {"kim@corp.example": "person_sender", "a@x.example": "person_recipient", "b@y.example": "person_recipient"})
        self.assertEqual({row["normalized"] for row in self.table(out, "attachments")}, {"q3.xlsx", "photo.jpg"})


class UrlExampleAndSearchTests(unittest.TestCase):
    """Adversarial review of E2 (items 1, 11)."""

    def test_url_examples_drop_userinfo_query_and_token_segments(self) -> None:
        self.assertEqual(url_example("https://alice:Sup3rSecret@Host.example/share?token=X"), "https://host.example/share")
        self.assertEqual(url_example("https://drive.example:8443/share/AbCdEf0123456789/view#frag"), "https://drive.example:8443/share/…")
        self.assertEqual(url_example("http://[fe80::1]:8080/"), "http://[fe80::1]:8080")
        self.assertIsNone(url_example("https://"))
        self.assertIsNone(url_example("https://host:notaport/x"))

    def test_engine_examples_never_keep_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            records = base / "browser.jsonl"
            row = {"artifact_type": "browser-visit", "details": {"url": "https://alice:Sup3rSecret@host.example/reset/tok123?token=X"}}
            records.write_text(json.dumps(row) + "\n", encoding="utf-8")
            payload = base / "artifacts_browser.json"
            payload.write_text(json.dumps({"records_path": str(records), "record_count": 1, "artifacts": []}), encoding="utf-8")
            out = base / "out"
            run_derived(TriageInputs(output_dir=base, artifact_payloads={"browser": payload}), out, source_label="test")
            for path in out.iterdir():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("Sup3rSecret", text, path.name)
                self.assertNotIn("tok123", text, path.name)
            urls = [json.loads(line) for line in (out / "urls.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(urls[0]["examples"], ["https://host.example/reset/…"])

    def test_search_text_is_bounded(self) -> None:
        text = search_text("A" * 5000, "b" * 5000)
        self.assertLessEqual(len(text), SEARCH_TEXT_CHARS)
        self.assertTrue(text.startswith("a" * 10) and "\nb" in text)
        self.assertEqual(search_text("Alice", "alice"), "alice")


class StageTests(unittest.TestCase):
    def test_stage_writes_a_derived_analysis_and_isolates_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            step = run_derived_stage(run_dir, artifact_outputs={})
            self.assertEqual(step["status"], "completed", step)
            directory = run_dir / "analyses" / str(step["analysis_id"])
            state = json.loads((directory / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual((state["kind"], state["status"], state["options"]), (DERIVED_ANALYSIS_KIND, "completed", {"source": "run-stage"}))
            self.assertTrue((directory / "people.jsonl").is_file())
            second = run_derived_stage(run_dir, artifact_outputs={})
            self.assertFalse(directory.exists())  # older run-stage generation removed
            with patch.object(derived_engine, "load_url_classes", side_effect=RuntimeError("boom")):
                failed = run_derived_stage(run_dir, artifact_outputs={})
            self.assertEqual(failed["status"], "failed_isolated")
            self.assertIn("통합 보기 단계 실패", failed["warning_messages"][0])
            # Only the type and the first 100 characters of the message (it can carry paths / row text).
            secret_tail = "C:\\Evidence\\" + "x" * 200 + "\\row-fragment-SECRET"
            with patch.object(derived_engine, "load_url_classes", side_effect=RuntimeError(secret_tail)):
                failed_long = run_derived_stage(run_dir, artifact_outputs={})
            message = failed_long["warning_messages"][0]
            self.assertEqual(message, f"통합 보기 단계 실패: RuntimeError: {secret_tail[:100]}")
            self.assertNotIn("SECRET", message)
            self.assertFalse((run_dir / "analyses" / str(failed["analysis_id"]) / "analysis.json").exists())
            self.assertTrue((run_dir / "analyses" / str(second["analysis_id"]) / "analysis.json").exists())


if __name__ == "__main__":
    unittest.main()
