"""Exercise the run-profile collector kinds, expanded schemas and timeline together."""

import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.windows.registry_depth import EXPLORER
from rapidtriage.core.artifact_profiles import iter_payload_records
from rapidtriage.core.artifact_store import artifact_record_with_fields
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.run.profiles import RUN_PROFILES
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    extract_artifact_events,
)
from tests.test_linux_login_accounting import lastlog, utmp
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    HiveWriter,
    Key,
    dword,
    write_hive,
)
from tests.test_taskband_featureusage import TICKS, make_export, taskband_values


class TaskbarLoginIntegrationTests(unittest.TestCase):
    def test_collectors_are_enabled_in_each_profile(self):
        for profile in RUN_PROFILES.values():
            with self.subTest(mode=profile.mode):
                self.assertIn("windows-registry", profile.artifacts_kinds)
                self.assertIn("linux-system", profile.artifacts_kinds)

    def test_streamed_records_validate_and_key_times_collapse(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            root = output / "evidence"
            log = root / "var/log"
            log.mkdir(parents=True)
            (root / "run").mkdir()
            (root / "run/utmp").write_bytes(utmp())
            (log / "wtmp").write_bytes(utmp(2) + utmp(8))
            (log / "btmp").write_bytes(utmp())
            (log / "lastlog").write_bytes(lastlog())
            hive = Key("ROOT")
            explorer = hive.path(EXPLORER)
            counter = explorer.path("FeatureUsage").key("AppLaunch", stamp=TICKS)
            for name in ("하나", "둘"):
                counter.value(name, REG_DWORD, dword(1))
            taskband = explorer.key("Taskband", stamp=TICKS)
            for name, data in taskband_values().items():
                taskband.value(name, REG_BINARY, data)
            write_hive(root, "Users/시험/NTUSER.DAT", HiveWriter().build(hive))
            (root / "synthetic.reg").write_text(make_export("HKCU"), encoding="utf-16")

            stats = TimelineStats()
            builder = TimelineBuilder(stats)
            schemas = {
                "registry-taskband-pin": "registry-taskband-pin",
                "registry-taskband-summary": "registry-taskband-summary",
                "execution-feature-usage": "execution-feature-usage",
                "linux-login-accounting-summary": "linux-login-accounting-summary",
                **{f"linux-{name}": "linux-login-accounting" for name in ("utmp", "wtmp", "btmp", "lastlog")},
            }
            row_counts = Counter()
            for kind in ("windows-registry", "linux-system"):
                stream = output / f"{kind}.jsonl"
                payload = run_artifact_collection(root, kind=kind, records_path=stream, preview_limit=1)
                for row in iter_payload_records(payload):
                    artifact_type = row["artifact_type"]
                    if artifact_type not in schemas:
                        continue
                    record = artifact_record_with_fields(row)
                    validate(record, load_schema("artifact-record-v1.schema.json"))
                    fields = record["fields"]["details"]
                    validate(fields, load_schema(f"details/{schemas[artifact_type]}.schema.json"))
                    if "record_sha256" in fields:
                        self.assertEqual(record["source"]["length"], fields["source_length"])
                    row_counts[artifact_type] += 1
                builder.extend(extract_artifact_events(payload, output / f"{kind}.json", stats=stats))

            self.assertEqual(row_counts, {
                "registry-taskband-pin": 8, "registry-taskband-summary": 4, "execution-feature-usage": 7,
                "linux-utmp": 1, "linux-wtmp": 2, "linux-btmp": 1, "linux-lastlog": 1,
                "linux-login-accounting-summary": 4,
            })
            events = [e for e in builder.events() if e["details"]["artifact_type"] in schemas]
            labels = Counter((e["details"]["artifact_type"], e["timestamp_kind"]) for e in events)
            self.assertEqual(labels, {
                ("execution-feature-usage", "last-written"): 1, ("registry-taskband-pin", "last-written"): 1,
                ("linux-utmp", "session-record"): 1, ("linux-wtmp", "session-record"): 2,
                ("linux-btmp", "failed-login"): 1, ("linux-lastlog", "last-login"): 1,
            })
            self.assertFalse(any(e["path"].endswith(".reg") for e in events))
