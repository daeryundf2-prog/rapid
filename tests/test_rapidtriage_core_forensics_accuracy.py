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
    def test_accuracy_profiles_cover_items_1_through_40_with_required_controls(self) -> None:
        payload = build_core_forensics_accuracy_profiles()

        self.assertEqual(payload["profile_count"], 40)
        profiles = payload["profiles"]
        self.assertEqual([item["number"] for item in profiles], list(range(1, 41)))
        self.assertEqual(len(CORE_FORENSIC_ACCURACY_ITEMS), 40)

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

    def test_known_answer_template_maps_every_profile_to_a_dataset(self) -> None:
        template = build_core_forensics_known_answer_template()

        self.assertEqual(template["status"], "template-not-run")
        self.assertEqual(template["item_count"], 40)
        datasets = template["datasets"]
        self.assertEqual([item["backlog_items"][0] for item in datasets], [str(number) for number in range(1, 41)])
        self.assertEqual(datasets[0]["id"], "core-forensics-01")
        self.assertEqual(datasets[-1]["id"], "core-forensics-40")
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
            self.assertEqual(profiles["profile_count"], 40)
            self.assertEqual(profiles["profiles"][0]["number"], 1)
            self.assertEqual(profiles["profiles"][-1]["number"], 40)
            template = payload["core_forensics_known_answer_template"]
            self.assertEqual(template["item_count"], 40)
            self.assertEqual(template["datasets"][0]["id"], "core-forensics-01")

            markdown = (output / "rapidtriage-validation-report.md").read_text(encoding="utf-8")
            self.assertIn("#1-#40 Core Forensics Accuracy Profiles", markdown)
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


if __name__ == "__main__":
    unittest.main()
