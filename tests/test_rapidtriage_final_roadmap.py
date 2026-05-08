from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.bundle import (
    build_court_exhibit_trusted_diff,
    build_tamper_evident_trusted_diff,
    court_exhibit_core_accuracy_gates,
    tamper_evident_bundle_core_accuracy_gates,
)
from rapidtriage.core.normalize import normalize_artifacts
from rapidtriage.core.sample_case import run_sample_workflow


class RapidTriageFinalRoadmapTests(unittest.TestCase):
    def test_parser_exposes_final_roadmap_commands(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("timeline-export", commands)
        self.assertIn("--event-type", commands["timeline-export"].format_help())
        self.assertIn("normalize", commands)
        self.assertIn("bundle", commands)
        self.assertIn("--allowed-root", commands["bundle"].format_help())
        self.assertIn("plugins", commands)
        self.assertIn("validation", commands)
        self.assertIn("--output-dir", commands["validation"].format_help())
        self.assertIn("--known-answer-manifest", commands["validation"].format_help())

    def test_validation_package_separates_internal_and_commercial_scores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["validation", "--output-dir", tmp_dir, "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["internal_roadmap_score"], 100)
            self.assertLess(payload["commercial_readiness_score"], payload["internal_roadmap_score"])
            gaps = payload["commercial_gap_assessment"]
            self.assertTrue(any(item["area"] == "native-evidence-acquisition" for item in gaps))
            report = Path(tmp_dir) / "rapidtriage-validation-report.md"
            self.assertIn("Commercial Gap Assessment", report.read_text(encoding="utf-8"))
            self.assertTrue(Path(payload["outputs"]["artifact_manifest"]).is_file())

    def test_validation_package_accepts_known_answer_and_independent_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            known_answer = root / "known-answer.json"
            independent = root / "independent-validation.md"
            evidence = root / "observed-output.json"
            output_dir = root / "validation"
            evidence.write_text('{"ok": true}\n', encoding="utf-8")
            independent.write_text("# Independent validation\n\nSigned review placeholder.\n", encoding="utf-8")
            known_answer.write_text(
                json.dumps(
                    {
                        "datasets": [
                            {
                                "id": "cfreds-sample-001",
                                "source": "NIST CFReDS",
                                "corpus_family": "disk-image",
                                "status": "pass",
                                "expected": {"eventlog_records_min": 1},
                                "evidence_paths": [str(evidence)],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "validation",
                        "--output-dir",
                        str(output_dir),
                        "--known-answer-manifest",
                        str(known_answer),
                        "--independent-report",
                        str(independent),
                        "--fixture-root",
                        str(Path.cwd()),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["known_answer_validation"]["status"], "all-passed")
            self.assertEqual(payload["known_answer_validation"]["dataset_count"], 1)
            self.assertTrue(payload["known_answer_validation"]["datasets"][0]["evidence_paths_present"])
            self.assertEqual(payload["independent_validation_report"]["status"], "attached")
            self.assertTrue(payload["external_tool_versions"])
            self.assertGreater(payload["parser_fixture_corpus"]["fixture_backed_count"], 0)
            artifact_manifest = json.loads(Path(payload["outputs"]["artifact_manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(artifact_manifest["artifact_count"], 2)
            self.assertTrue(all(item["sha256"] for item in artifact_manifest["artifacts"]))

    def test_timeline_export_and_normalize_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            run_output = Path(sample["run"]["output_dir"])
            timeline_output = root / "timeline-export.json"
            normalize_output = root / "normalized.json"

            timeline_exit = main(
                [
                    "timeline-export",
                    str(run_output),
                    "--output",
                    str(timeline_output),
                    "--limit",
                    "10",
                ]
            )
            normalize_exit = main(
                [
                    "normalize",
                    str(run_output),
                    "--case-id",
                    "CASE-NORMALIZED",
                    "--output",
                    str(normalize_output),
                ]
            )

            self.assertEqual(timeline_exit, 0)
            self.assertEqual(normalize_exit, 0)
            timeline_payload = json.loads(timeline_output.read_text(encoding="utf-8"))
            normalized_payload = json.loads(normalize_output.read_text(encoding="utf-8"))
            self.assertEqual(timeline_payload["command"], "timeline-export")
            self.assertLessEqual(timeline_payload["summary"]["event_count"], 10)
            self.assertTrue(timeline_payload["events"][0]["event_id"].startswith("evt-"))
            self.assertEqual(normalized_payload["command"], "normalize")
            self.assertEqual(normalized_payload["case"]["case_id"], "CASE-NORMALIZED")
            self.assertGreaterEqual(normalized_payload["summary"]["file_record_count"], 1)
            self.assertIn("artifacts", normalized_payload["models"])

    def test_normalize_artifacts_promotes_parser_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            artifacts_path = Path(tmp_dir) / "artifacts-media.json"
            artifacts_path.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "provider": "media-image-artifacts",
                                "artifact_type": "media-image",
                                "path": "/case/screen.png",
                                "details": {
                                    "parser": "media-image",
                                    "parser_version": "media-image-v3",
                                    "parser_confidence": 0.86,
                                    "entry_name": "screen.png",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            rows = normalize_artifacts({"artifacts_media": str(artifacts_path)})

            self.assertEqual(rows[0]["parser"], "media-image")
            self.assertEqual(rows[0]["parser_version"], "media-image-v3")
            self.assertEqual(rows[0]["confidence"], 0.86)

    def test_bundle_command_builds_submission_archive_with_integrity_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            run_output = Path(sample["run"]["output_dir"])
            files_json = run_output / "rapidtriage-files.json"
            case_json = root / "case.json"
            bundle_dir = root / "bundle"

            self.assertEqual(
                main(
                    [
                        "case",
                        str(case_json),
                        "--source",
                        str(files_json),
                        "--pointer",
                        "/candidates/0",
                        "--tag",
                        "report",
                        "--note",
                        "Include <script>alert(1)</script> in final bundle.",
                        "--include-in-report",
                    ]
                ),
                0,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                bundle_exit = main(
                    [
                        "bundle",
                        str(case_json),
                        "--allowed-root",
                        str(sample["evidence_root"]),
                        "--output-dir",
                        str(bundle_dir),
                        "--json",
                    ]
                )

            self.assertEqual(bundle_exit, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "bundle")
            self.assertTrue((bundle_dir / "rapidtriage-submission-manifest.json").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-selected-evidence.json").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-case-report.md").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-case-report.html").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-case-report.docx").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-case-report.pdf").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-case-report.exports.json").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-reviewer.html").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-bundle-manifest.json").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-court-exhibit-index.json").is_file())
            self.assertTrue((bundle_dir / "rapidtriage-tamper-evident-audit-bundle.json").is_file())
            report_html = (bundle_dir / "rapidtriage-case-report.html").read_text(encoding="utf-8")
            reviewer_html = (bundle_dir / "rapidtriage-reviewer.html").read_text(encoding="utf-8")
            export_manifest = json.loads((bundle_dir / "rapidtriage-case-report.exports.json").read_text(encoding="utf-8"))
            court_exhibit = json.loads((bundle_dir / "rapidtriage-court-exhibit-index.json").read_text(encoding="utf-8"))
            tamper_bundle = json.loads((bundle_dir / "rapidtriage-tamper-evident-audit-bundle.json").read_text(encoding="utf-8"))
            self.assertIn("Reviewer Bundle", reviewer_html)
            self.assertIn("rapidtriage-bundle-manifest.json", reviewer_html)
            self.assertIn("Reviewer Checklist", reviewer_html)
            self.assertIn("Quick Preview", reviewer_html)
            self.assertIn("Status:", reviewer_html)
            self.assertIn("Content-Security-Policy", report_html)
            self.assertIn("Content-Security-Policy", reviewer_html)
            self.assertNotIn("<script>alert(1)</script>", report_html)
            self.assertNotIn("<script>alert(1)</script>", reviewer_html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report_html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", reviewer_html)
            self.assertTrue(export_manifest["security"]["html_escaped"])
            self.assertIn("default-src 'none'", export_manifest["security"]["content_security_policy"])
            with zipfile.ZipFile(bundle_dir / "rapidtriage-case-report.docx") as report_docx:
                self.assertIn("word/document.xml", report_docx.namelist())
            self.assertEqual((bundle_dir / "rapidtriage-case-report.pdf").read_bytes()[:5], b"%PDF-")
            with zipfile.ZipFile(payload["archive"]) as bundle_zip:
                self.assertIn("rapidtriage-case-report.html", bundle_zip.namelist())
                self.assertIn("rapidtriage-case-report.docx", bundle_zip.namelist())
                self.assertIn("rapidtriage-case-report.pdf", bundle_zip.namelist())
                self.assertIn("rapidtriage-case-report.exports.json", bundle_zip.namelist())
                self.assertIn("rapidtriage-court-exhibit-index.json", bundle_zip.namelist())
                self.assertIn("rapidtriage-tamper-evident-audit-bundle.json", bundle_zip.namelist())
                self.assertIn("rapidtriage-bundle-manifest.json", bundle_zip.namelist())
            self.assertTrue(Path(payload["archive"]).is_file())
            self.assertIn("sha256", payload["archive_hashes"])
            self.assertIn("report_html", payload["outputs"])
            self.assertIn("report_docx", payload["outputs"])
            self.assertIn("report_pdf", payload["outputs"])
            self.assertIn("report_export_manifest", payload["outputs"])
            self.assertIn("bundle_manifest", payload["outputs"])
            self.assertIn("court_exhibit_index", payload["outputs"])
            self.assertIn("tamper_evident_audit_bundle", payload["outputs"])
            self.assertEqual(court_exhibit["command"], "court-exhibit-index")
            self.assertIn("#94", court_exhibit["commercial_gap_ids"])
            self.assertEqual(court_exhibit["core_accuracy_gates"][0]["gap_id"], "#94")
            self.assertTrue(court_exhibit["output_hashes"])
            self.assertEqual(court_exhibit["court_exhibit_manifest"]["profile_version"], "court-exhibit-package-manifest-v1")
            self.assertEqual(len(court_exhibit["court_exhibit_manifest_hash"]), 64)
            self.assertTrue(court_exhibit["court_exhibit_manifest"]["selected_evidence_manifest_hash"])
            self.assertTrue(all(len(item["exhibit_row_hash"]) == 64 for item in court_exhibit["exhibits"]))
            self.assertIn("external_signature", court_exhibit["signing_slots"])
            self.assertEqual(court_exhibit["trusted_court_exhibit_diff"]["status"], "missing")
            self.assertIn("trusted-court-exhibit-manifest-diff-missing", court_exhibit["blockers"])
            court_diff = build_court_exhibit_trusted_diff(court_exhibit, court_exhibit)
            court_gates = court_exhibit_core_accuracy_gates(
                exhibits=court_exhibit["exhibits"],
                output_hashes=court_exhibit["output_hashes"],
                exhibit_manifest=court_exhibit["court_exhibit_manifest"],
                trusted_diff=court_diff,
            )
            self.assertEqual(court_diff["status"], "pass")
            self.assertIn("court_exhibit_manifest_hash", court_diff["compared_fields"])
            self.assertIn("court exhibit package manifest hash emitted", court_gates[0]["satisfied_checks"])
            self.assertIn("external signing slot emitted", court_gates[0]["satisfied_checks"])
            self.assertIn("trusted court exhibit manifest diff pass", court_gates[0]["satisfied_checks"])
            self.assertIn("#100", tamper_bundle["commercial_gap_ids"])
            self.assertIn("#100", tamper_bundle["summary"]["commercial_gap_ids"])
            self.assertEqual(tamper_bundle["core_accuracy_gates"][0]["gap_id"], "#100")
            self.assertTrue(tamper_bundle["summary"]["head_hash"])
            self.assertEqual(tamper_bundle["tamper_evident_manifest"]["profile_version"], "tamper-evident-audit-manifest-v1")
            self.assertEqual(len(tamper_bundle["tamper_evident_manifest_hash"]), 64)
            self.assertEqual(len(tamper_bundle["verification_matrix_hash"]), 64)
            self.assertEqual(
                tamper_bundle["verification_matrix_hash"],
                tamper_bundle["tamper_evident_manifest"]["verification_matrix_hash"],
            )
            self.assertEqual(
                tamper_bundle["tamper_evident_manifest"]["verification_matrix"]["profile_version"],
                "tamper-verification-matrix-v1",
            )
            self.assertIn("external_signature", tamper_bundle["signing_slots"])
            self.assertEqual(tamper_bundle["trusted_tamper_evident_diff"]["status"], "missing")
            self.assertIn("trusted-tamper-signature-attestation-diff-missing", tamper_bundle["blockers"])
            tamper_diff = build_tamper_evident_trusted_diff(tamper_bundle, tamper_bundle)
            tamper_gates = tamper_evident_bundle_core_accuracy_gates(
                entries=tamper_bundle["entries"],
                head_hash=tamper_bundle["summary"]["head_hash"],
                tamper_manifest=tamper_bundle["tamper_evident_manifest"],
                trusted_diff=tamper_diff,
            )
            self.assertEqual(tamper_diff["status"], "pass")
            self.assertIn("tamper_evident_manifest_hash", tamper_diff["compared_fields"])
            self.assertIn("verification_matrix_hash", tamper_diff["compared_fields"])
            self.assertIn("tamper-evident manifest hash emitted", tamper_gates[0]["satisfied_checks"])
            self.assertIn("tamper verification matrix hash emitted", tamper_gates[0]["satisfied_checks"])
            self.assertIn("external signing slot emitted", tamper_gates[0]["satisfied_checks"])
            self.assertIn("trusted tamper signature attestation diff pass", tamper_gates[0]["satisfied_checks"])
            self.assertIn("reviewer", payload["outputs"])
            selected = json.loads((bundle_dir / "rapidtriage-selected-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(selected["items"][0]["hash_status"], "hashed")
            self.assertIn("note", selected["items"][0])

    def test_plugins_command_lists_builtins_and_validates_external_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin_dir = root / "plugins" / "sample"
            plugin_dir.mkdir(parents=True)
            manifest = plugin_dir / "plugin.json"
            manifest.write_text(
                json.dumps(
                    {
                        "id": "sample.parser",
                        "name": "Sample Parser",
                        "version": "0.1",
                        "kind": "parser",
                        "entrypoint": "sample.parser:parse",
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["plugins", "--plugin-dir", str(root / "plugins"), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            plugin_ids = {plugin["id"] for plugin in payload["plugins"]}
            self.assertIn("rapidtriage.files", plugin_ids)
            self.assertIn("rapidtriage.local-ioc-enrichment", plugin_ids)
            self.assertIn("sample.parser", plugin_ids)
            enrichment = next(plugin for plugin in payload["plugins"] if plugin["id"] == "rapidtriage.local-ioc-enrichment")
            self.assertEqual(enrichment["kind"], "ti-enrichment")
            self.assertFalse(enrichment["enabled"])
            self.assertEqual(payload["summary"]["error_count"], 0)


if __name__ == "__main__":
    unittest.main()
