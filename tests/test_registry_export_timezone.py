"""F9: ``TimeZoneInformation`` from a ``.reg`` export feeds the timeline's evidence time zone.

A live acquisition without administrator rights has no SYSTEM hive copy, only
``reg export HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation``. All values
below are synthetic.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.timeline import build_timeline_report, run_timeline

KST_EXPORT = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation]
"ActiveTimeBias"=dword:fffffde4
"Bias"=dword:fffffde4
"DaylightBias"=dword:ffffffc4
"DaylightName"="@tzres.dll,-621"
"DaylightStart"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"DynamicDaylightTimeDisabled"=dword:00000000
"StandardBias"=dword:00000000
"StandardName"="@tzres.dll,-622"
"StandardStart"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"TimeZoneKeyName"="Korea Standard Time"

"""

# Recurring US rule: DST from the 2nd Sunday of March 02:00, standard from the 1st Sunday of November 02:00.
PACIFIC_EXPORT = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\Select]
"Current"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\TimeZoneInformation]
"Bias"=dword:00000000
"TimeZoneKeyName"="UTC"

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\TimeZoneInformation]
"ActiveTimeBias"=dword:000001a4
"Bias"=dword:000001e0
"DaylightBias"=dword:ffffffc4
"DaylightName"="@tzres.dll,-211"
"DaylightStart"=hex:00,00,03,00,00,00,02,00,02,00,00,00,00,00,00,00
"DynamicDaylightTimeDisabled"=dword:00000000
"StandardBias"=dword:00000000
"StandardName"="@tzres.dll,-212"
"StandardStart"=hex:00,00,0b,00,00,00,01,00,02,00,00,00,00,00,00,00
"TimeZoneKeyName"="Pacific Standard Time"

"""


def write_reg_export(path: Path, text: str) -> Path:
    """UTF-16 LE with BOM and CRLF, as ``reg export`` writes it."""
    path.write_bytes(b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le"))
    return path


def timezone_rows(root: Path) -> list:
    return [record for record in WindowsRegistryProvider().collect(root) if record.artifact_type == "windows-timezone"]


class RegExportTimezoneTests(unittest.TestCase):
    def test_reg_export_yields_timezone_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reg_export(root / "SYSTEM_TimeZoneInformation.reg", KST_EXPORT)
            records = list(WindowsRegistryProvider().collect(root))

        rows = [record for record in records if record.artifact_type == "windows-timezone"]
        self.assertEqual(len(rows), 1)
        details = rows[0].details
        self.assertEqual(details["time_zone_key_name"], "Korea Standard Time")
        self.assertEqual(details["time_zone_label_ko"], "대한민국 표준시(KST)")
        self.assertEqual(details["bias_minutes"], -540)
        self.assertEqual(details["active_time_bias_minutes"], -540)
        self.assertEqual(details["daylight_bias_minutes"], -60)
        self.assertEqual(details["utc_offset"], "+09:00")
        self.assertEqual(details["utc_offset_minutes"], 540)
        self.assertEqual(details["standard_name"], "@tzres.dll,-622")
        self.assertEqual(details["dynamic_daylight_time_disabled"], 0)
        self.assertIsNone(details["standard_start"])
        self.assertIsNone(details["daylight_start"])
        self.assertEqual(details["source_format"], "reg")
        self.assertEqual(details["control_set"], "CurrentControlSet")
        self.assertEqual(details["key_path"], r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
        self.assertEqual(details["source_offset"], 3)
        summary = next(record for record in records if record.artifact_type == "registry-summary")
        self.assertEqual(summary.details["timezone"]["time_zone_key_name"], "Korea Standard Time")
        self.assertEqual(summary.details["timezone"]["utc_offset"], "+09:00")

    def test_select_current_control_set_and_dst_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reg_export(root / "SYSTEM.reg", PACIFIC_EXPORT)
            rows = timezone_rows(root)

        self.assertEqual(len(rows), 1)
        details = rows[0].details
        self.assertEqual(details["control_set"], "ControlSet002")
        self.assertEqual(details["time_zone_key_name"], "Pacific Standard Time")
        self.assertEqual(details["bias_minutes"], 480)
        # ActiveTimeBias 420 = PDT in effect at export time.
        self.assertEqual(details["utc_offset"], "-07:00")
        self.assertEqual(
            details["daylight_start"],
            {"year": 0, "month": 3, "day_of_week": 0, "day": 2, "day_semantics": "week-of-month (5 = last)", "hour": 2, "minute": 0},
        )
        self.assertEqual(details["standard_start"]["month"], 11)
        self.assertEqual(details["standard_start"]["day"], 1)

    def test_key_name_without_bias_has_no_invented_offset(self) -> None:
        text = (
            "Windows Registry Editor Version 5.00\n\n"
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation]\n"
            '"TimeZoneKeyName"="Korea Standard Time"\n\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reg_export(root / "tz.reg", text)
            rows = timezone_rows(root)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].details["utc_offset"], "")
        self.assertIsNone(rows[0].details["utc_offset_minutes"])

    def test_timeline_reports_evidence_zone_from_reg_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "live"
            root.mkdir()
            write_reg_export(root / "SYSTEM_TimeZoneInformation.reg", KST_EXPORT)
            artifacts = Path(tmp) / "rapidtriage-artifacts-windows-registry.json"
            artifacts.write_text(
                json.dumps(run_artifact_collection(root, kind="windows-registry", use_cache=False), ensure_ascii=False),
                encoding="utf-8",
            )
            payload = run_timeline(root=root, artifacts_inputs=[artifacts])

        disclosure = payload["summary"]["timezone"]
        self.assertEqual(disclosure["evidence_timezone_status"], "registry-reported")
        self.assertEqual(disclosure["evidence_timezone"]["name"], "Korea Standard Time")
        self.assertEqual(disclosure["evidence_timezone"]["utc_offset"], "+09:00")
        self.assertEqual(disclosure["evidence_timezone"]["bias_minutes"], -540)
        report = build_timeline_report(payload)
        self.assertIn("- 증거 시스템 시간대: `Korea Standard Time` (UTC+09:00, bias -540 min, 레지스트리 보고)", report)
        self.assertNotIn("보고되지 않음", report)


if __name__ == "__main__":
    unittest.main()
