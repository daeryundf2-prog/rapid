from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.forensic_accuracy import (
    CORE_FORENSIC_ACCURACY_ITEMS,
    accuracy_profile_for_item,
    build_core_forensics_accuracy_profiles,
    build_core_forensics_known_answer_template,
)


class RapidTriageCoreForensicsAccuracyTests(unittest.TestCase):
    def test_accuracy_profiles_cover_items_1_through_120_with_required_controls(self) -> None:
        payload = build_core_forensics_accuracy_profiles()

        self.assertEqual(payload["profile_count"], 120)
        profiles = payload["profiles"]
        self.assertEqual([item["number"] for item in profiles], list(range(1, 121)))
        self.assertEqual(len(CORE_FORENSIC_ACCURACY_ITEMS), 120)

        for profile in profiles:
            with self.subTest(item=profile["number"]):
                self.assertEqual(profile["gap_id"], f"#{profile['number']}")
                self.assertGreaterEqual(len(profile["required_checks"]), 5)
                self.assertTrue(profile["accuracy_controls"]["source_provenance_required"])
                self.assertTrue(profile["accuracy_controls"]["hash_required"])
                self.assertTrue(profile["accuracy_controls"]["cross_tool_diff_required"])
                self.assertTrue(profile["accuracy_controls"]["known_answer_required"])
                self.assertEqual(profile["default_reportability"], "validation-required")
                self.assertFalse(profile["commercial_grade_ready"])
                self.assertIn("record-level or row-level diff", profile["minimum_evidence"])

    def test_specific_accuracy_profiles_capture_high_risk_requirements(self) -> None:
        evtx = accuracy_profile_for_item(1)
        registry_deleted = accuracy_profile_for_item(5)
        browser_secrets = accuracy_profile_for_item(19)
        android = accuracy_profile_for_item(30)
        kakao = accuracy_profile_for_item(31)
        cloud_api = accuracy_profile_for_item(40)
        cloud_credential = accuracy_profile_for_item(41)
        browser_secret = accuracy_profile_for_item(42)
        mobile_correlation = accuracy_profile_for_item(43)
        analysis_workbook = accuracy_profile_for_item(50)
        reviewer_workflow = accuracy_profile_for_item(51)
        hex_viewer = accuracy_profile_for_item(53)
        ocr_queue = accuracy_profile_for_item(58)
        search_dedup = accuracy_profile_for_item(60)
        advanced_search = accuracy_profile_for_item(61)
        keyword_packs = accuracy_profile_for_item(62)
        ti_enrichment = accuracy_profile_for_item(63)
        citation_manager = accuracy_profile_for_item(64)
        evidence_history = accuracy_profile_for_item(65)
        benchmark = accuracy_profile_for_item(66)
        stress = accuracy_profile_for_item(67)
        incremental = accuracy_profile_for_item(68)
        job_queue = accuracy_profile_for_item(69)
        checkpoint = accuracy_profile_for_item(70)
        parser_crash = accuracy_profile_for_item(71)
        memory_cap = accuracy_profile_for_item(72)
        preview_sandbox = accuracy_profile_for_item(73)
        sqlite_performance = accuracy_profile_for_item(74)
        parser_scheduler = accuracy_profile_for_item(75)
        hash_cache = accuracy_profile_for_item(76)
        duplicate_detection = accuracy_profile_for_item(77)
        pagination = accuracy_profile_for_item(78)
        ui_virtualization = accuracy_profile_for_item(79)
        cancellation_retry = accuracy_profile_for_item(80)
        known_answer = accuracy_profile_for_item(81)
        fixture_corpus = accuracy_profile_for_item(82)
        fp_fn = accuracy_profile_for_item(83)
        independent_validation = accuracy_profile_for_item(84)
        validation_package = accuracy_profile_for_item(85)
        custody = accuracy_profile_for_item(86)
        acquisition_hash = accuracy_profile_for_item(87)
        immutable_audit = accuracy_profile_for_item(88)
        reproducibility = accuracy_profile_for_item(89)
        provenance = accuracy_profile_for_item(90)
        parser_confidence = accuracy_profile_for_item(91)
        validation_warning = accuracy_profile_for_item(92)
        legal_limitation = accuracy_profile_for_item(93)
        court_exhibit = accuracy_profile_for_item(94)
        external_tool = accuracy_profile_for_item(95)
        acquisition_metadata = accuracy_profile_for_item(96)
        timezone_validation = accuracy_profile_for_item(97)
        clock_skew = accuracy_profile_for_item(98)
        contamination = accuracy_profile_for_item(99)
        tamper_bundle = accuracy_profile_for_item(100)
        windows_installer = accuracy_profile_for_item(101)
        macos_package = accuracy_profile_for_item(102)
        linux_package = accuracy_profile_for_item(103)
        auto_update = accuracy_profile_for_item(104)
        crash_reporting = accuracy_profile_for_item(105)
        local_only = accuracy_profile_for_item(106)
        license_activation = accuracy_profile_for_item(107)
        rbac = accuracy_profile_for_item(108)
        multi_user = accuracy_profile_for_item(109)
        collaboration_audit = accuracy_profile_for_item(110)
        backup_restore = accuracy_profile_for_item(111)
        release_notes = accuracy_profile_for_item(112)
        lts_policy = accuracy_profile_for_item(113)
        support_sla = accuracy_profile_for_item(114)
        training = accuracy_profile_for_item(115)
        quickstart = accuracy_profile_for_item(116)
        admin_guide = accuracy_profile_for_item(117)
        security_hardening = accuracy_profile_for_item(118)
        malicious_sandbox = accuracy_profile_for_item(119)
        dependency_monitoring = accuracy_profile_for_item(120)

        self.assertIn("duplicate EventData order preservation", evtx["required_checks"])
        self.assertTrue(evtx["accuracy_controls"]["offset_or_record_id_required"])
        self.assertIn("reportability blocked until independent confirmation", registry_deleted["required_checks"])
        self.assertTrue(browser_secrets["accuracy_controls"]["secret_redaction_required"])
        self.assertTrue(browser_secrets["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("signature chain validation", android["required_checks"])
        self.assertIn("schema/app version and BigBang compatibility tracking", kakao["required_checks"])
        self.assertTrue(kakao["accuracy_controls"]["secret_redaction_required"])
        self.assertIn("credential redaction", cloud_api["required_checks"])
        self.assertTrue(cloud_api["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("token value redaction", cloud_credential["required_checks"])
        self.assertTrue(cloud_credential["accuracy_controls"]["secret_redaction_required"])
        self.assertIn("strict legal warning", browser_secret["required_checks"])
        self.assertTrue(browser_secret["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("message-media linkage built", mobile_correlation["required_checks"])
        self.assertTrue(mobile_correlation["accuracy_controls"]["timezone_or_timestamp_semantics_required"])
        self.assertIn("draft hypotheses generated", analysis_workbook["required_checks"])
        self.assertIn("assignment and priority captured", reviewer_workflow["required_checks"])
        self.assertTrue(reviewer_workflow["accuracy_controls"]["timezone_or_timestamp_semantics_required"])
        self.assertIn("byte offsets and hex offsets", hex_viewer["required_checks"])
        self.assertIn("sidecar import and hashes", ocr_queue["required_checks"])
        self.assertTrue(ocr_queue["accuracy_controls"]["timezone_or_timestamp_semantics_required"])
        self.assertIn("duplicate fingerprint generation", search_dedup["required_checks"])
        self.assertIn("fuzzy/stemming/regex matching available", advanced_search["required_checks"])
        self.assertIn("trusted advanced-search query-hit diff pass", advanced_search["required_checks"])
        self.assertIn("custom JSON pack support", keyword_packs["required_checks"])
        self.assertIn("trusted keyword-pack expansion diff pass", keyword_packs["required_checks"])
        self.assertIn("offline feed provenance", ti_enrichment["required_checks"])
        self.assertIn("trusted IOC/TI enrichment diff pass", ti_enrichment["required_checks"])
        self.assertTrue(ti_enrichment["accuracy_controls"]["secret_redaction_required"])
        self.assertIn("source reference preserved", citation_manager["required_checks"])
        self.assertIn("trusted citation index diff pass", citation_manager["required_checks"])
        self.assertTrue(citation_manager["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("previous/current state captured", evidence_history["required_checks"])
        self.assertIn("trusted evidence history diff pass", evidence_history["required_checks"])
        self.assertIn("scale matrix emitted", benchmark["required_checks"])
        self.assertIn("trusted benchmark threshold diff pass", benchmark["required_checks"])
        self.assertIn("real-hardware validation warning", stress["required_checks"])
        self.assertIn("trusted stress run-log diff pass", stress["required_checks"])
        self.assertIn("input fingerprint emitted", incremental["required_checks"])
        self.assertIn("trusted incremental reuse diff pass", incremental["required_checks"])
        self.assertIn("step progress recorded", job_queue["required_checks"])
        self.assertIn("trusted job transition-log diff pass", job_queue["required_checks"])
        self.assertIn("stage checkpoints emitted", checkpoint["required_checks"])
        self.assertIn("checkpoint resume report-grade validation plan emitted", checkpoint["required_checks"])
        self.assertIn("trusted checkpoint/resume manifest diff pass", checkpoint["required_checks"])
        self.assertIn("per-parser exception capture", parser_crash["required_checks"])
        self.assertIn("parser crash report-grade validation plan emitted", parser_crash["required_checks"])
        self.assertIn("trusted parser crash-corpus diff pass", parser_crash["required_checks"])
        self.assertIn("memory cap configuration recorded", memory_cap["required_checks"])
        self.assertIn("stage telemetry row hashes emitted", memory_cap["required_checks"])
        self.assertIn("memory cap report-grade validation plan emitted", memory_cap["required_checks"])
        self.assertIn("trusted memory cap/RSS diff pass", memory_cap["required_checks"])
        self.assertIn("active content execution blocked", preview_sandbox["required_checks"])
        self.assertIn("preview policy row hashes emitted", preview_sandbox["required_checks"])
        self.assertIn("preview sandbox report-grade validation plan emitted", preview_sandbox["required_checks"])
        self.assertIn("trusted preview sandbox/no-exec diff pass", preview_sandbox["required_checks"])
        self.assertIn("query plan row hashes emitted", sqlite_performance["required_checks"])
        self.assertIn("SQLite performance pragmas applied", sqlite_performance["required_checks"])
        self.assertIn("large SQLite/FTS report-grade validation plan emitted", sqlite_performance["required_checks"])
        self.assertIn("trusted large SQLite/FTS query-plan diff pass", sqlite_performance["required_checks"])
        self.assertIn("bounded worker count", parser_scheduler["required_checks"])
        self.assertIn("scheduler event row hashes emitted", parser_scheduler["required_checks"])
        self.assertIn("parser scheduler report-grade validation plan emitted", parser_scheduler["required_checks"])
        self.assertIn("trusted scheduler manifest diff pass", parser_scheduler["required_checks"])
        self.assertIn("hit/miss counters emitted", hash_cache["required_checks"])
        self.assertIn("hash cache report-grade validation plan emitted", hash_cache["required_checks"])
        self.assertIn("trusted hash-cache manifest diff pass", hash_cache["required_checks"])
        self.assertIn("duplicate group counts", duplicate_detection["required_checks"])
        self.assertIn("duplicate content report-grade validation plan emitted", duplicate_detection["required_checks"])
        self.assertIn("trusted duplicate file manifest diff pass", duplicate_detection["required_checks"])
        self.assertIn("cursor token emitted", pagination["required_checks"])
        self.assertIn("trusted pagination cursor manifest diff pass", pagination["required_checks"])
        self.assertIn("bounded DOM row window", ui_virtualization["required_checks"])
        self.assertIn("trusted UI virtualization manifest diff pass", ui_virtualization["required_checks"])
        self.assertIn("failed/canceled retry support", cancellation_retry["required_checks"])
        self.assertIn("trusted cancellation/retry transition diff pass", cancellation_retry["required_checks"])
        self.assertIn("known-answer manifest ingested", known_answer["required_checks"])
        self.assertIn("known-answer report-grade validation plan emitted", known_answer["required_checks"])
        self.assertIn("trusted known-answer manifest diff pass", known_answer["required_checks"])
        self.assertTrue(known_answer["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("parser areas inventoried", fixture_corpus["required_checks"])
        self.assertIn("fixture corpus report-grade validation plan emitted", fixture_corpus["required_checks"])
        self.assertIn("trusted fixture corpus manifest diff pass", fixture_corpus["required_checks"])
        self.assertIn("false positive risks documented", fp_fn["required_checks"])
        self.assertIn("FP/FN report-grade validation plan emitted", fp_fn["required_checks"])
        self.assertIn("trusted FP/FN risk register diff pass", fp_fn["required_checks"])
        self.assertIn("report hash captured when attached", independent_validation["required_checks"])
        self.assertIn("trusted independent validation signoff diff pass", independent_validation["required_checks"])
        self.assertIn("artifact hash manifest generated", validation_package["required_checks"])
        self.assertIn("trusted validation package manifest diff pass", validation_package["required_checks"])
        self.assertIn("custody event inventory", custody["required_checks"])
        self.assertIn("trusted custody event manifest diff pass", custody["required_checks"])
        self.assertIn("evidence-source hashes exported", acquisition_hash["required_checks"])
        self.assertIn("trusted acquisition hash manifest diff pass", acquisition_hash["required_checks"])
        self.assertIn("previous/event hash chain generated", immutable_audit["required_checks"])
        self.assertIn("trusted audit hash-chain manifest diff pass", immutable_audit["required_checks"])
        self.assertIn("stable payload hash generated", reproducibility["required_checks"])
        self.assertIn("trusted report replay manifest diff pass", reproducibility["required_checks"])
        self.assertIn("source path preserved", provenance["required_checks"])
        self.assertIn("trusted report provenance manifest diff pass", provenance["required_checks"])
        self.assertIn("parser confidence preserved", parser_confidence["required_checks"])
        self.assertIn("trusted parser confidence calibration diff pass", parser_confidence["required_checks"])
        self.assertIn("validation warning reasons emitted", validation_warning["required_checks"])
        self.assertIn("trusted validation warning checklist diff pass", validation_warning["required_checks"])
        self.assertIn("artifact limitation text emitted", legal_limitation["required_checks"])
        self.assertIn("trusted legal limitation wording diff pass", legal_limitation["required_checks"])
        self.assertIn("exhibit IDs assigned", court_exhibit["required_checks"])
        self.assertIn("trusted court exhibit manifest diff pass", court_exhibit["required_checks"])
        self.assertIn("tool inventory emitted", external_tool["required_checks"])
        self.assertIn("trusted external tool transcript diff pass", external_tool["required_checks"])
        self.assertIn("write-blocker field recorded", acquisition_metadata["required_checks"])
        self.assertIn("trusted acquisition handoff diff pass", acquisition_metadata["required_checks"])
        self.assertIn("UTC assumption disclosed", timezone_validation["required_checks"])
        self.assertIn("trusted timezone normalization matrix diff pass", timezone_validation["required_checks"])
        self.assertIn("baseline requirement disclosed", clock_skew["required_checks"])
        self.assertIn("trusted clock-skew baseline diff pass", clock_skew["required_checks"])
        self.assertIn("write-blocker integration limitation emitted", contamination["required_checks"])
        self.assertIn("trusted contamination checklist diff pass", contamination["required_checks"])
        self.assertIn("previous-entry hash chain generated", tamper_bundle["required_checks"])
        self.assertIn("trusted tamper signature attestation diff pass", tamper_bundle["required_checks"])
        self.assertTrue(tamper_bundle["accuracy_controls"]["legal_or_authority_gate_required"])
        self.assertIn("authenticode evidence requirement recorded", windows_installer["required_checks"])
        self.assertIn("trusted Windows Authenticode evidence diff pass", windows_installer["required_checks"])
        self.assertIn("notarization requirement recorded", macos_package["required_checks"])
        self.assertIn("trusted macOS notarization evidence diff pass", macos_package["required_checks"])
        self.assertIn("linux package targets declared", linux_package["required_checks"])
        self.assertIn("trusted Linux package smoke diff pass", linux_package["required_checks"])
        self.assertIn("update manifest generated", auto_update["required_checks"])
        self.assertIn("trusted signed update channel diff pass", auto_update["required_checks"])
        self.assertIn("sensitive context redacted", crash_reporting["required_checks"])
        self.assertIn("trusted crash redaction/export diff pass", crash_reporting["required_checks"])
        self.assertIn("telemetry disabled recorded", local_only["required_checks"])
        self.assertIn("trusted local-only deployment policy diff pass", local_only["required_checks"])
        self.assertIn("network activation disabled recorded", license_activation["required_checks"])
        self.assertIn("trusted license authority diff pass", license_activation["required_checks"])
        self.assertIn("role matrix emitted", rbac["required_checks"])
        self.assertIn("trusted RBAC enforcement diff pass", rbac["required_checks"])
        self.assertIn("multi-user disabled state recorded", multi_user["required_checks"])
        self.assertIn("trusted multi-user server review diff pass", multi_user["required_checks"])
        self.assertIn("tamper evidence linkage recorded", collaboration_audit["required_checks"])
        self.assertIn("trusted collaboration audit diff pass", collaboration_audit["required_checks"])
        self.assertIn("restore hash verified", backup_restore["required_checks"])
        self.assertIn("trusted backup/restore rehearsal diff pass", backup_restore["required_checks"])
        self.assertIn("release notes template packaged", release_notes["required_checks"])
        self.assertIn("trusted release notes CI gate diff pass", release_notes["required_checks"])
        self.assertIn("hotfix criteria documented", lts_policy["required_checks"])
        self.assertIn("trusted LTS/hotfix policy diff pass", lts_policy["required_checks"])
        self.assertIn("staffed support blocker disclosed", support_sla["required_checks"])
        self.assertIn("trusted support desk SLA diff pass", support_sla["required_checks"])
        self.assertIn("training curriculum packaged", training["required_checks"])
        self.assertIn("trusted training delivery diff pass", training["required_checks"])
        self.assertIn("sample workflow command recorded", quickstart["required_checks"])
        self.assertIn("trusted quickstart lab run diff pass", quickstart["required_checks"])
        self.assertIn("admin guide packaged", admin_guide["required_checks"])
        self.assertIn("trusted admin deployment proof diff pass", admin_guide["required_checks"])
        self.assertIn("independent AppSec blocker disclosed", security_hardening["required_checks"])
        self.assertIn("trusted independent AppSec review diff pass", security_hardening["required_checks"])
        self.assertIn("OS sandbox blocker disclosed", malicious_sandbox["required_checks"])
        self.assertIn("trusted malicious evidence sandbox corpus diff pass", malicious_sandbox["required_checks"])
        self.assertIn("release blocking policy recorded", dependency_monitoring["required_checks"])
        self.assertIn("trusted dependency advisory/SBOM diff pass", dependency_monitoring["required_checks"])

    def test_known_answer_template_maps_every_profile_to_a_dataset(self) -> None:
        template = build_core_forensics_known_answer_template()

        self.assertEqual(template["status"], "template-not-run")
        self.assertEqual(template["item_count"], 120)
        datasets = template["datasets"]
        self.assertEqual([item["backlog_items"][0] for item in datasets], [str(number) for number in range(1, 121)])
        self.assertEqual(datasets[0]["id"], "core-forensics-01")
        self.assertEqual(datasets[-1]["id"], "core-forensics-120")
        for dataset in datasets:
            with self.subTest(dataset=dataset["id"]):
                self.assertEqual(dataset["status"], "not-run")
                self.assertIn("oracle", dataset["expected"])
                self.assertGreaterEqual(len(dataset["expected"]["required_checks"]), 5)

    def test_validation_package_includes_core_accuracy_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            exit_code = main(["validation", "--output-dir", str(output), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            profiles = payload["core_forensics_accuracy_profiles"]
            self.assertEqual(profiles["profile_count"], 120)
            self.assertEqual(profiles["profiles"][0]["number"], 1)
            self.assertEqual(profiles["profiles"][-1]["number"], 120)
            template = payload["core_forensics_known_answer_template"]
            self.assertEqual(template["item_count"], 120)
            self.assertEqual(template["datasets"][0]["id"], "core-forensics-01")
            matrix = payload["validation_legal_defensibility_matrix"]
            self.assertEqual(matrix["profile_version"], "validation-legal-defensibility-matrix-v1")
            self.assertEqual(matrix["item_numbers"], [81, 82, 83, 84, 85])
            self.assertEqual(matrix["row_count"], 5)
            self.assertEqual(len(matrix["matrix_hash"]), 64)
            self.assertEqual(matrix["implemented_count"], 5)
            self.assertEqual(matrix["usable_count"], 5)

            markdown = (output / "rapidtriage-validation-report.md").read_text(encoding="utf-8")
            self.assertIn("#1-#120 Core Forensics Accuracy Profiles", markdown)
            self.assertIn("Native EVTX BinXML full parsing", markdown)
            self.assertIn("Known-answer template datasets", markdown)

    def test_core_forensics_6_10_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-006-010-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [6, 7, 8, 9, 10],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(6, 11):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_1_5_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-001-005-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [1, 2, 3, 4, 5],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(1, 6):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_11_15_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-011-015-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [11, 12, 13, 14, 15],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(11, 16):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_16_20_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-016-020-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [16, 17, 18, 19, 20],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(16, 21):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_21_25_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-021-025-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [21, 22, 23, 24, 25],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(21, 26):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_26_30_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-026-030-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 5)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [26, 27, 28, 29, 30],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(26, 31):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_31_40_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-031-040-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))
            self.assertEqual(
                known_answer["dataset_evidence_matrix"]["profile_version"],
                "known-answer-dataset-evidence-matrix-v1",
            )
            self.assertEqual(known_answer["dataset_evidence_matrix"]["dataset_count"], 10)
            self.assertEqual(len(known_answer["dataset_evidence_matrix_hash"]), 64)
            self.assertEqual(
                known_answer["known_answer_pipeline_manifest"]["dataset_evidence_matrix_hash"],
                known_answer["dataset_evidence_matrix_hash"],
            )
            self.assertTrue(all(dataset["evidence_matrix_row_hash"] for dataset in known_answer["datasets"]))
            fixture_matrix = payload["parser_fixture_corpus"]["fixture_release_gate_matrix"]
            self.assertEqual(fixture_matrix["profile_version"], "fixture-release-gate-matrix-v1")
            self.assertEqual(len(payload["parser_fixture_corpus"]["fixture_release_gate_matrix_hash"]), 64)
            self.assertEqual(fixture_matrix["matrix_hash"], payload["parser_fixture_corpus"]["fixture_release_gate_matrix_hash"])
            fp_fn_profile = payload["parser_fp_fn_risk_register_profile"]
            self.assertEqual(fp_fn_profile["risk_matrix"]["profile_version"], "parser-fp-fn-risk-matrix-v1")
            self.assertEqual(len(fp_fn_profile["risk_matrix_hash"]), 64)
            independent_manifest = payload["independent_validation_report"]["independent_validation_manifest"]
            self.assertEqual(len(independent_manifest["minimum_section_presence_hash"]), 64)
            self.assertEqual(len(independent_manifest["signoff_status_hash"]), 64)
            validation_manifest = payload["validation_package_assessment"]["validation_package_manifest"]
            self.assertEqual(len(validation_manifest["artifact_set_hash"]), 64)
            self.assertEqual(len(validation_manifest["required_output_presence_hash"]), 64)
            legal_matrix = payload["validation_legal_defensibility_matrix"]
            self.assertEqual(legal_matrix["item_numbers"], [81, 82, 83, 84, 85])
            self.assertEqual(len(legal_matrix["matrix_hash"]), 64)

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(31, 41):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_41_50_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-041-050-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(41, 51):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_51_60_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-051-060-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [51, 52, 53, 54, 55, 56, 57, 58, 59, 60],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(51, 61):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_61_70_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-061-070-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [61, 62, 63, 64, 65, 66, 67, 68, 69, 70],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(61, 71):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_71_80_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-071-080-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [71, 72, 73, 74, 75, 76, 77, 78, 79, 80],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(71, 81):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_81_90_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-081-090-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(81, 91):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_91_100_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-091-100-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 10)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                [91, 92, 93, 94, 95, 96, 97, 98, 99, 100],
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(91, 101):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])

    def test_core_forensics_101_120_manifest_promotes_validated_maturity_when_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "validation"
            manifest = Path("docs/validation/rapidtriage-core-forensics-101-120-known-answer.json")

            exit_code = main(
                [
                    "validation",
                    "--output-dir",
                    str(output),
                    "--known-answer-manifest",
                    str(manifest),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output / "rapidtriage-validation-package.json").read_text(encoding="utf-8"))
            known_answer = payload["known_answer_validation"]
            self.assertEqual(known_answer["status"], "all-passed")
            self.assertEqual(known_answer["dataset_count"], 20)
            self.assertTrue(all(dataset["evidence_paths_present"] for dataset in known_answer["datasets"]))

            readiness = Path(tmp_dir) / "readiness"
            readiness_exit = main(
                [
                    "commercial-readiness",
                    "--validation-package",
                    str(output / "rapidtriage-validation-package.json"),
                    "--output-dir",
                    str(readiness),
                    "--json",
                ]
            )

            self.assertEqual(readiness_exit, 0)
            readiness_payload = json.loads(
                (readiness / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                readiness_payload["validation_evidence_summary"]["mapped_item_numbers"],
                list(range(101, 121)),
            )
            items = {item["number"]: item for item in readiness_payload["all_items"]}
            for number in range(101, 121):
                with self.subTest(number=number):
                    self.assertTrue(items[number]["maturity_gates"]["validated"]["passed"])
                    self.assertEqual(items[number]["highest_maturity_stage"], "validated")
                    self.assertFalse(items[number]["maturity_gates"]["commercial_grade"]["passed"])


if __name__ == "__main__":
    unittest.main()
