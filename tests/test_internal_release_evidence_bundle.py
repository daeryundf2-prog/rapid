from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_internal_bundle_module():
    module_path = (
        Path(__file__).resolve().parent.parent
        / "scripts"
        / "internal-release-evidence-bundle.py"
    )
    spec = importlib.util.spec_from_file_location(
        "rapidtriage_internal_release_evidence_bundle_test",
        module_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalReleaseEvidenceBundleTests(unittest.TestCase):
    def test_synthetic_hostile_corpus_records_expected_safety_boundaries(self) -> None:
        module = load_internal_bundle_module()
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            payload = module.build_synthetic_hostile_corpus(output_dir)
            archive_path = output_dir / "synthetic-hostile-corpus" / "zip-slip-candidate.zip"

            self.assertEqual(payload["profile_version"], "synthetic-hostile-corpus-v1")
            self.assertFalse(payload["commercial_claim_allowed"])
            self.assertEqual(payload["item_number"], 119)
            self.assertEqual(len(payload["corpus_hash"]), 64)
            self.assertGreaterEqual(payload["active_content_file_count"], 2)
            self.assertEqual(payload["unsafe_archive_entry_count"], 1)
            self.assertIn("trusted-malicious-evidence-sandbox-corpus", payload["external_blockers"])
            self.assertTrue(archive_path.exists())
            with zipfile.ZipFile(archive_path) as archive:
                self.assertIn("../escape.txt", archive.namelist())

    def test_bundle_generates_all_internal_outputs_without_commercial_claim(self) -> None:
        module = load_internal_bundle_module()
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "bundle"
            manifest = module.build_internal_evidence_bundle(output_dir, overwrite=True)

            self.assertEqual(manifest["profile_version"], "internal-release-evidence-bundle-v1")
            self.assertEqual(manifest["item_numbers"], [116, 117, 118, 119, 120])
            self.assertFalse(manifest["commercial_claim_allowed"])
            self.assertTrue(manifest["all_internal_checks_passed"])
            self.assertEqual(len(manifest["bundle_hash"]), 64)
            self.assertIn("trusted-quickstart-lab-run-log", manifest["external_blockers"])
            self.assertIn("trusted-admin-deployment-proof", manifest["external_blockers"])
            self.assertIn("independent-appsec-review", manifest["external_blockers"])
            self.assertIn("trusted-malicious-evidence-sandbox-corpus", manifest["external_blockers"])
            self.assertIn(
                "scheduled-ci-advisory-scan-and-sbom-publication",
                manifest["external_blockers"],
            )
            expected_outputs = {
                "quickstart-lab-run.json",
                "admin-deployment-smoke.json",
                "security-hardening-review.json",
                "synthetic-hostile-corpus-manifest.json",
                "parser-sandbox-smoke.json",
                "dependency-monitoring.json",
                "dependency-release-linkage.json",
                "SHA256SUMS",
            }
            generated_paths = {entry["path"] for entry in manifest["generated_files"]}
            self.assertTrue(expected_outputs.issubset(generated_paths))
            written_manifest = json.loads(
                (output_dir / "internal-release-evidence-bundle.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(written_manifest["bundle_hash"], manifest["bundle_hash"])
