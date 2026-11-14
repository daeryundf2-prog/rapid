"""``rapidtriage run --artifact-kinds`` (R7 Q-AI9): a kind-only run collects only the listed kinds,
skips the tree-walking stages, samples the input fingerprint and records the restriction."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from rapidtriage.cli import main as cli_main
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.plan import (
    PLAN_FILE_NAME,
    PlanTargetError,
    build_run_plan,
    find_task,
)
from tests.fixtures.ai_agents import make_fixtures as mf


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ArtifactKindsPlanTests(unittest.TestCase):
    def test_plan_skips_other_providers_and_tree_walking_stages(self) -> None:
        plan = build_run_plan(mode="seizure", artifact_kinds=["ai-agent"])
        self.assertEqual(plan["options"]["artifact_kinds"], ["ai-agent"])
        self.assertEqual(find_task(plan, "ai-agent")["status"], "queued")
        for task_id in ("browser", "eventlog", "windows-registry", "docs", "files", "carve", "docs-extract", "files-extract"):
            task = find_task(plan, task_id)
            self.assertEqual(task["status"], "skipped", task_id)
            self.assertEqual(task["reason"], "종류 제한 실행(--artifact-kinds)", task_id)
        for task_id in ("fingerprint", "manifest", "timeline", "report"):
            self.assertEqual(find_task(plan, task_id)["status"], "queued", task_id)
        self.assertEqual(build_run_plan(mode="seizure")["options"]["artifact_kinds"], [])

    def test_unknown_kind_is_rejected(self) -> None:
        with self.assertRaises(PlanTargetError) as caught:
            build_run_plan(mode="seizure", artifact_kinds=["no-such-kind"])
        self.assertIn("no-such-kind", str(caught.exception))


class ArtifactKindsRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "evidence"
        mf.build_all(self.root, only=("claude_code", "codex"))
        # bulk that a full run would walk / fingerprint
        bulk = self.root / "Users" / "u1" / "Documents" / "bulk"
        bulk.mkdir(parents=True)
        for index in range(1500):
            (bulk / f"f{index:04d}.txt").write_text("x", encoding="utf-8")
        self.output_dir = Path(self._tmp.name) / "run-out"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kind_only_run(self) -> None:
        started = time.monotonic()
        summary = run_triage_mode(self.root, mode="seizure", output_dir=self.output_dir, artifact_kinds=["ai-agent"], case_db=False)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 60.0)
        self.assertEqual(summary["run_scope"]["artifact_kinds"], ["ai-agent"])
        self.assertTrue(summary["run_scope"]["kinds_only"])
        self.assertEqual(summary["fingerprint_mode"], "sampled")
        self.assertEqual(summary["run_scope"]["skipped_stage_groups"], ["docs", "files", "carve", "extract"])
        notes = summary["disclosures"]["collection_notes"]["run-scope"]
        self.assertIn("fingerprint_mode: sampled", notes[0])
        fingerprint = _load(self.output_dir / "rapidtriage-run-fingerprint.json")
        self.assertEqual(fingerprint["fingerprint_mode"], "sampled")
        self.assertEqual(fingerprint["summary"]["content_hashed_file_count"], 0)
        self.assertLessEqual(fingerprint["summary"]["scanned_file_count"], 1000)
        self.assertTrue(fingerprint["summary"]["truncated"])
        artifacts = sorted(path.name for path in (self.output_dir / "artifacts").glob("rapidtriage-artifacts-*.json"))
        self.assertEqual(artifacts, ["rapidtriage-artifacts-ai-agent.json"])
        self.assertIn("artifacts_ai-agent", summary["outputs"])
        plan = _load(self.output_dir / PLAN_FILE_NAME)
        self.assertEqual(plan["outcome"], "complete")
        self.assertEqual(find_task(plan, "ai-agent")["status"], "completed")
        self.assertEqual(find_task(plan, "browser")["status"], "skipped")
        self.assertEqual(find_task(plan, "docs")["status"], "skipped")
        audit = _load(self.output_dir / "rapidtriage-run-audit.json")
        self.assertEqual(audit["provenance"]["options"]["artifact_kinds"], ["ai-agent"])
        self.assertEqual(audit["provenance"]["options"]["fingerprint_mode"], "sampled")
        report = (self.output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")
        self.assertIn("종류 제한 실행", report)
        payload = _load(self.output_dir / "artifacts" / "rapidtriage-artifacts-ai-agent.json")
        self.assertGreater(int(payload.get("record_count") or payload.get("summary", {}).get("artifact_count") or 0), 0)

    def test_cli_artifact_kinds(self) -> None:
        stdout = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stdout(stdout):
            code = cli_main(
                [
                    "run",
                    str(self.root),
                    "--mode",
                    "seizure",
                    "--output-dir",
                    str(self.output_dir),
                    "--no-case-db",
                    "--artifact-kinds",
                    "ai-agent",
                    "--ai-read-mb",
                    "64",
                ]
            )
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 60.0)
        summary = _load(self.output_dir / "rapidtriage-run-summary.json")
        self.assertEqual(summary["run_scope"]["artifact_kinds"], ["ai-agent"])
        self.assertEqual(summary["fingerprint_mode"], "sampled")

    def test_full_run_records_metadata_fingerprint_mode(self) -> None:
        summary = run_triage_mode(self.root, mode="seizure", output_dir=self.output_dir, case_db=False, skip_groups=["docs", "files"])
        self.assertEqual(summary["fingerprint_mode"], "metadata")
        self.assertFalse(summary["run_scope"]["kinds_only"])
        self.assertNotIn("run-scope", summary["disclosures"]["collection_notes"])


if __name__ == "__main__":
    unittest.main()
