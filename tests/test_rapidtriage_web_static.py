from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class RapidTriageWebStaticTests(unittest.TestCase):
    def test_web_artifact_workbench_exposes_ntfs_replay_review_cards(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("ntfsArtifactPreviewText", app_js)
        self.assertIn("renderNtfsReplayPreviewArtifactCard", app_js)
        self.assertIn("usn_replay_inventory_profile", app_js)
        self.assertIn("bounded_mft_replay_preview", app_js)
        self.assertIn("mft_bounded_path_cache_profile", app_js)
        self.assertIn("MFT cache quality", app_js)
        self.assertIn("MFT partial path warnings", app_js)
        self.assertIn("usn_path_reliability_profile", app_js)
        self.assertIn("Path reliability", app_js)
        self.assertIn("Reliability wording", app_js)
        self.assertIn("rename_pair_preview", app_js)
        self.assertIn("delete_lifecycle_preview", app_js)
        self.assertIn("bounded_state_replay_preview", app_js)
        self.assertIn("usn_state_replay_validation_profile", app_js)
        self.assertIn("State replay validation", app_js)
        self.assertIn("State validation wording", app_js)
        self.assertIn("Delete lifecycle", app_js)
        self.assertIn("State transitions", app_js)
        self.assertIn("Bounded state replay", app_js)
        self.assertIn("STATE paired OLD", app_js)
        self.assertIn("USN replay preview", app_js)
        self.assertIn("renderNtfsSourceLocatorLinks", app_js)
        self.assertIn("Source locators", app_js)
        self.assertIn("source-hex-range", app_js)
        self.assertIn("include_hashes=true", app_js)
        self.assertIn("errorMessageFromDetail", app_js)
        self.assertIn("renderSourceResolutionDiagnostics", app_js)
        self.assertIn("source_path_resolution", app_js)
        self.assertIn("Source path resolution diagnostics", app_js)
        self.assertIn("Court-grade rename/delete replay still requires full-journal ordering", app_js)

    def test_web_workbench_exposes_run_validation_diff_inventory_panel(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("data-testid=\"run-validation-diff-panel\"", app_js)
        self.assertIn("loadRunValidationPackageSummary", app_js)
        self.assertIn("renderRunValidationPackageSummary", app_js)
        self.assertIn("diff_inventory", app_js)
        self.assertIn("usn_state_replay_diff_attached", app_js)
        self.assertIn("usn_state_replay_diff_pass_count", app_js)
        self.assertIn("usn_state_replay_status", app_js)
        self.assertIn("Run validation diff inventory", app_js)
        self.assertIn("run-validation-diff-panel", styles)
        self.assertIn("validation-diff-card", styles)
        self.assertIn("validation-diff-list", styles)
        self.assertIn("compact-dl", styles)


if __name__ == "__main__":
    unittest.main()
