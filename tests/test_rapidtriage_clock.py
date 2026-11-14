"""T-132: output and audit timestamps carry their UTC offset; old offset-less outputs still read."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.triage_flags import _moment
from rapidtriage.core.audit import audit_timestamps
from rapidtriage.core.clock import now_local, now_local_iso
from rapidtriage.core.timeline import run_timeline

REPO = Path(__file__).resolve().parents[1]
OFFSET = re.compile(r"([+-]\d\d:\d\d|Z)$")


class ClockTests(unittest.TestCase):
    def test_now_local_iso_has_offset_and_names_now(self) -> None:
        text = now_local_iso()
        self.assertRegex(text, OFFSET)
        moment = dt.datetime.fromisoformat(text)
        self.assertIsNotNone(moment.tzinfo)
        self.assertLess(abs((dt.datetime.now(dt.timezone.utc) - moment).total_seconds()), 5)

    def test_now_local_is_aware_and_keeps_naive_strftime(self) -> None:
        aware = now_local()
        self.assertIsNotNone(aware.utcoffset())
        naive = dt.datetime.now()
        # File-name stamps (`%Y%m%d_%H%M%S`) read the same local wall clock as before.
        self.assertLess(abs((aware.replace(tzinfo=None) - naive).total_seconds()), 5)

    def test_same_rule_as_export_audit(self) -> None:
        instant = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.timezone.utc)
        stamps = audit_timestamps(instant)
        self.assertEqual(dt.datetime.fromisoformat(stamps["generated_at"]), instant)

    def test_no_naive_now_left_in_package(self) -> None:
        hits = [
            f"{path.relative_to(REPO)}:{number}"
            for path in (REPO / "rapidtriage").rglob("*.py")
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if "datetime.now()" in line
        ]
        self.assertEqual(hits, [])

    def test_output_generated_at_has_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = run_timeline(root=Path(tmp))
        self.assertRegex(str(payload["generated_at"]), OFFSET)

    def test_old_offsetless_timestamps_still_read(self) -> None:
        old = _moment("2026-01-02T03:04:05.123456")
        new = _moment("2026-01-02T12:04:05.123456+09:00")
        self.assertIsNotNone(old.tzinfo)
        self.assertEqual(old, new)  # naive values are read as UTC, as before
        self.assertEqual(
            sorted([new, _moment("2026-01-01T00:00:00")]), [_moment("2026-01-01T00:00:00"), new]
        )

    def test_utc_and_new_york_name_the_same_instant(self) -> None:
        code = (
            "import json, pathlib, sys, tempfile\n"
            "from rapidtriage.core.timeline import run_timeline\n"
            "with tempfile.TemporaryDirectory() as t:\n"
            "    print(json.dumps(run_timeline(root=pathlib.Path(t))['generated_at']))\n"
        )
        moments = {}
        # POSIX TZ strings: honoured by the C runtime on Windows and by tzset elsewhere.
        for zone in ("UTC0", "EST5EDT"):
            env = {**os.environ, "TZ": zone, "RAPIDTRIAGE_NO_BROWSER": "1"}
            out = subprocess.run(
                [sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True, check=True
            ).stdout.strip().splitlines()[-1]
            text = json.loads(out)
            self.assertRegex(text, OFFSET)
            moments[zone] = dt.datetime.fromisoformat(text)
        self.assertNotEqual(moments["UTC0"].utcoffset(), moments["EST5EDT"].utcoffset())
        self.assertLess(abs((moments["UTC0"] - moments["EST5EDT"]).total_seconds()), 60)


if __name__ == "__main__":
    unittest.main()
