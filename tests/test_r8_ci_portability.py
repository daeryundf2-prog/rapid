"""R8 CI-green: product fixes for failures that only showed up on some CI hosts.

* Processing decisions in the markdown report were cut at 30 rows with no disclosure, and step
  skip decisions sat behind a long tail of notices (an extra skipped optional step on a host
  without ``deepfake_lens`` pushed ``docs-extract status=skipped`` out of the report).
* The artifact summary fallback used ``Path(...).name``, which keeps a Windows evidence path whole
  on a POSIX analysis host.
* AI-agent profile discovery listed every home twice on a case-insensitive file system because
  ``Users`` and ``users`` were de-duplicated by spelling, not by directory identity.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.ai_agents.adapters._common import (
    iter_profiles,
    profile_homes,
)
from rapidtriage.core.reporting import (
    PROCESSING_DECISION_REPORT_LIMIT,
    build_processing_decision_rows,
    format_processing_decision_lines,
)
from rapidtriage.core.timeline import build_artifact_summary


class ProcessingDecisionTests(unittest.TestCase):
    def test_skip_decisions_come_before_warnings_and_notices(self) -> None:
        steps: list[dict[str, object]] = [
            {"name": f"artifacts-n{index}", "status": "completed", "warning_level": "notice", "warning_messages": ["no rows"]}
            for index in range(40)
        ]
        steps.insert(3, {"name": "artifacts-b", "status": "failed_isolated", "warning_level": "failed", "warning_messages": ["parser error"]})
        steps.append(
            {
                "name": "docs-extract",
                "status": "skipped",
                "output": "x.json",
                "skip_reasons": {"read-only": 4},
                "warning_level": "notice",
                "warning_messages": ["Selected items were not extracted"],
            }
        )
        rows = build_processing_decision_rows(steps, {"read_only": True})
        self.assertTrue(rows[0].startswith("Read-only mode was enabled"))
        self.assertEqual(rows[1], "`docs-extract` status=`skipped` output=`x.json`.")
        self.assertEqual(rows[2], "`docs-extract` skip reasons: read-only=4.")
        self.assertEqual(rows[3], "`artifacts-b` failed: parser error")
        self.assertEqual(len(rows), 4 + 41)

        lines = format_processing_decision_lines(rows)
        self.assertEqual(len(lines), PROCESSING_DECISION_REPORT_LIMIT + 1)
        self.assertIn("docs-extract` status=`skipped", "\n".join(lines))
        self.assertEqual(
            lines[-1],
            f"- +{len(rows) - PROCESSING_DECISION_REPORT_LIMIT} more processing decision(s) not shown here; "
            "see each step's warning_messages in the run summary JSON.",
        )

    def test_no_overflow_line_within_limit(self) -> None:
        self.assertEqual(format_processing_decision_lines(["a", "b"]), ["- a", "- b"])
        self.assertEqual(format_processing_decision_lines(None), [])


class ArtifactSummaryBasenameTests(unittest.TestCase):
    def test_fallback_label_is_the_last_component_on_any_separator(self) -> None:
        self.assertEqual(build_artifact_summary("wer-report", "C:\\x\\Report.wer", {}), "wer-report Report.wer")
        self.assertEqual(build_artifact_summary("wer-report", "/a/b/Report.wer", {}), "wer-report Report.wer")
        self.assertEqual(build_artifact_summary("wer-report", "C:\\x/y\\Report.wer\\", {}), "wer-report Report.wer")
        self.assertEqual(build_artifact_summary("wer-report", "Report.wer", {}), "wer-report Report.wer")
        self.assertEqual(build_artifact_summary("wer-report", "", {}), "wer-report wer-report")


class ProfileIdentityTests(unittest.TestCase):
    def test_alias_of_the_users_folder_does_not_duplicate_profiles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ai-alias-") as tmp_name:
            tmp = Path(tmp_name)
            for user in ("u1", "u2"):
                (tmp / "Users" / user).mkdir(parents=True)
            alias = tmp / "users"
            if not alias.exists():
                # Case-sensitive host: model the case-insensitive spelling with a directory alias.
                try:
                    os.symlink(tmp / "Users", alias, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"directory symlinks unavailable: {exc}")
            homes = [user for home, user in profile_homes([tmp]) if home != tmp]
            self.assertEqual(sorted(homes), ["u1", "u2"])
            profiles = iter_profiles([tmp, tmp / "users" / "u1"], "windows")
            self.assertEqual(sorted(p.user for p in profiles if p.home != tmp), ["u1", "u2"])


if __name__ == "__main__":
    unittest.main()
