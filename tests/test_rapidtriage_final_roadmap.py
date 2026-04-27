from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import build_parser, main
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
            report_html = (bundle_dir / "rapidtriage-case-report.html").read_text(encoding="utf-8")
            reviewer_html = (bundle_dir / "rapidtriage-reviewer.html").read_text(encoding="utf-8")
            export_manifest = json.loads((bundle_dir / "rapidtriage-case-report.exports.json").read_text(encoding="utf-8"))
            self.assertIn("Reviewer Bundle", reviewer_html)
            self.assertIn("rapidtriage-bundle-manifest.json", reviewer_html)
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
                self.assertIn("rapidtriage-bundle-manifest.json", bundle_zip.namelist())
            self.assertTrue(Path(payload["archive"]).is_file())
            self.assertIn("sha256", payload["archive_hashes"])
            self.assertIn("report_html", payload["outputs"])
            self.assertIn("report_docx", payload["outputs"])
            self.assertIn("report_pdf", payload["outputs"])
            self.assertIn("report_export_manifest", payload["outputs"])
            self.assertIn("bundle_manifest", payload["outputs"])
            self.assertIn("reviewer", payload["outputs"])

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
