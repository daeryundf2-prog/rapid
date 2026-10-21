"""scripts/rule-validation.py on synthetic runs / ntfs-meta analyses with planted positives and negatives (R6 S4 Q-S4-1)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rapidtriage.core.triage_rules.stage import run_triage_stage
from tests.triage_cases.eventlog import CASES as EVENTLOG_CASES
from tests.triage_cases.ntfs import CASES as NTFS_CASES
from tests.triage_cases.rdp import CASES as RDP_CASES

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "rule-validation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("rapidtriage_rule_validation_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rule_validation = _load_module()

LOG_CLEARED = "eventlog.log_cleared"
RDP_LOGON = "eventlog.rdp_external_ip"
RDP_ADDRESS = "rdp.external_ip"
ADS = "ntfs.ads_executable"
SI_FN = "ntfs.si_before_fn"


def case_rows(cases: Mapping[str, Mapping[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    """Positive then negative rows of one rule's fixture (the planted positives / negatives)."""
    return [*cases[rule_id]["positive"]["rows"], *cases[rule_id]["negative"]["rows"]]


def snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {str(path.relative_to(root)): (path.stat().st_size, path.stat().st_mtime_ns) for path in root.rglob("*") if path.is_file()}


def write_run(root: Path, specs: list[dict[str, Any]], *, indicators: list[dict[str, Any]] | None = None, triage: bool = True) -> Path:
    """A run output folder (summary + per-kind outputs) of row specs; the run-stage flag set unless ``triage=False``."""
    run = root / "run"
    run.mkdir()
    kinds: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        kinds.setdefault(str(spec["kind"]), []).append(dict(spec["row"]))
    outputs: dict[str, str] = {}
    artifact_outputs: dict[str, Path] = {}
    for kind, rows in kinds.items():
        types: dict[str, int] = {}
        for row in rows:
            types[row["artifact_type"]] = types.get(row["artifact_type"], 0) + 1
        payload: dict[str, Any] = {"record_count": len(rows), "summary": {"artifact_count": len(rows), "artifact_type_counts": types}}
        if kind == "eventlog":  # JSONL records stream, like large kinds
            records = run / f"{kind}.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload.update({"records_path": str(records), "artifacts": []})
        else:
            payload["artifacts"] = rows
        path = run / f"artifacts_{kind}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        outputs[f"artifacts_{kind}"] = str(path)
        artifact_outputs[kind] = path
    if indicators is not None:
        path = run / "rapidtriage-indicators.json"
        path.write_text(json.dumps({"summary": {"indicator_count": len(indicators)}, "indicators": indicators}), encoding="utf-8")
        outputs["indicators"] = str(path)
    summary = run / "rapidtriage-run-summary.json"
    outputs["summary"] = str(summary)
    summary.write_text(json.dumps({"output_dir": str(run), "outputs": outputs}), encoding="utf-8")
    if triage:
        step = run_triage_stage(run, artifact_outputs=artifact_outputs)
        assert step["status"] == "completed", step
    return run


def write_ntfs_analysis(run: Path, specs: list[dict[str, Any]], *, reason_counts: Mapping[str, int] | None = None, kind: str = "ntfs-meta") -> Path:
    directory = run / "analyses" / "ntfs-mft-1"
    directory.mkdir(parents=True)
    rows = [spec["row"] for spec in specs]
    (directory / "rows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary: dict[str, Any] = {"source": "mft", "parse_status": "parsed", "mft_record_count": len(rows)}
    if reason_counts is not None:
        summary.update({"timestamp_mismatch_status": "parsed", "timestamp_mismatch_reason_counts_all": dict(reason_counts)})
    (directory / "analysis.json").write_text(
        json.dumps({"analysis_id": "ntfs-mft-1", "kind": kind, "status": "completed", "row_count": len(rows), "summary": summary}),
        encoding="utf-8",
    )
    return directory


class RuleValidationScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_script(self, *args: str) -> tuple[int, dict[str, Any] | None, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rule_validation.main(list(args))
        text = out.getvalue()
        try:
            report = json.loads(text) if text.strip().startswith("{") else None
        except ValueError:
            report = None
        return code, report, err.getvalue()

    def expect(self, payload: Mapping[str, Any]) -> str:
        path = self.root / "expected.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def standard_run(self, **kwargs) -> Path:
        specs = [
            *case_rows(EVENTLOG_CASES, LOG_CLEARED),  # 1102 Security (+) · 104 Kernel-Cache (−)
            *case_rows(EVENTLOG_CASES, RDP_LOGON),  # 4624/10 from 8.8.8.8 (+) · from 10.8.0.15 (−)
            *case_rows(RDP_CASES, RDP_ADDRESS),  # 1149 / 131 public (+2) · private (−2)
            *case_rows(NTFS_CASES, ADS),  # PE streams (+2) · tag / Zone.Identifier streams (−2)
        ]
        return write_run(self.root, specs, **kwargs)

    @staticmethod
    def by_id(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        return {item["id"]: item for item in report["rules"]}

    # -- run mode ------------------------------------------------------------------------------

    def test_run_mode_counts_planted_positives_and_passes_expectations(self) -> None:
        run = self.standard_run()
        expected = self.expect({LOG_CLEARED: {"min": 1, "max": 1}, RDP_LOGON: {"min": 1, "max": 1}, RDP_ADDRESS: {"min": 2}, ADS: {"min": 2, "max": 2}})
        code, report, _err = self.run_script("--run", str(run), "--rules", "A", "--expect", expected, "--json")
        self.assertEqual(code, 0, report)
        rules = self.by_id(report)
        self.assertEqual(len(rules), 7)  # every A-grade rule
        self.assertEqual(report["flag_source"]["status"], "joined")
        self.assertEqual(report["flag_source"]["source"], "run-stage")
        self.assertEqual({rule_id: rules[rule_id]["hits"] for rule_id in (LOG_CLEARED, RDP_LOGON, RDP_ADDRESS, ADS)},
                         {LOG_CLEARED: 1, RDP_LOGON: 1, RDP_ADDRESS: 2, ADS: 2})
        self.assertEqual(rules[LOG_CLEARED]["result"], "pass")
        self.assertEqual(rules[LOG_CLEARED]["grades"], {"A": 1})
        self.assertEqual(rules[LOG_CLEARED]["hits_by_kind"], {"eventlog": 1})
        self.assertTrue(rules[LOG_CLEARED]["validation_synthetic_only"])
        # Eligible rows: 8 event-log rows for the event-log rules, 4 ADS rows for ntfs.ads_executable.
        self.assertEqual(rules[LOG_CLEARED]["eligible_rows"], 8)
        self.assertEqual(rules[ADS]["eligible_rows"], 4)
        # Rules with no input in this run are not applicable (0 hits is not a negative result).
        self.assertEqual(rules[SI_FN]["result"], "not_applicable")
        self.assertEqual(rules[SI_FN]["eligible_rows"], 0)
        self.assertEqual(rules["cloud.bulk_upload"]["result"], "not_applicable")

    def test_samples_carry_type_path_tail_time_and_scrubbed_evidence(self) -> None:
        run = self.standard_run()
        code, report, _err = self.run_script("--run", str(run), "--rules", f"{LOG_CLEARED},{ADS}", "--json")
        self.assertEqual(code, 0)
        rules = self.by_id(report)
        cleared = rules[LOG_CLEARED]["samples"][0]
        self.assertEqual(cleared["artifact_type"], "eventlog-event")
        self.assertEqual(cleared["path_tail"], "Security.evtx")
        self.assertEqual(cleared["timestamp"], "2024-05-01T10:00:00Z")
        self.assertEqual((cleared["kind"], cleared["record_index"]), ("eventlog", 0))
        ads = rules[ADS]["samples"]
        self.assertEqual([sample["path_tail"] for sample in ads], ["notes.txt:svc.bin", "readme.txt:cfg"])
        self.assertEqual(ads[0]["artifact_type"], "ads-stream-candidate")
        # Full host paths never leave the report: only their tail.
        self.assertEqual(ads[1]["evidence"]["host"], "…\\readme.txt")
        text = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("Users\\\\Public", text)
        self.assertNotIn("Users\\\\analyst", text)
        # --samples caps the list.
        code, report, _err = self.run_script("--run", str(run), "--rules", ADS, "--samples", "1", "--json")
        self.assertEqual(len(self.by_id(report)[ADS]["samples"]), 1)

    def test_negative_control_mismatch_and_no_input_mismatch(self) -> None:
        run = self.standard_run()
        expected = self.expect({LOG_CLEARED: {"max": 0}, SI_FN: {"max": 0}, RDP_LOGON: {"max": 1}})
        code, report, _err = self.run_script("--run", str(run), "--rules", RDP_LOGON, "--expect", expected, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(report["verdict"], "mismatch")
        rules = self.by_id(report)
        self.assertEqual(set(rules), {RDP_LOGON, LOG_CLEARED, SI_FN})  # rules named in --expect are added
        self.assertEqual(rules[LOG_CLEARED]["result"], "mismatch")
        self.assertIn("기대 최대 0건", rules[LOG_CLEARED]["reason_ko"])
        self.assertEqual(rules[SI_FN]["result"], "mismatch")
        self.assertIn("음성 대조 불성립", rules[SI_FN]["reason_ko"])
        self.assertEqual(rules[RDP_LOGON]["result"], "pass")
        self.assertEqual(report["totals"], {"pass": 1, "mismatch": 2})

    def test_negative_only_run_passes_zero_hit_expectations(self) -> None:
        negatives = [*EVENTLOG_CASES[LOG_CLEARED]["negative"]["rows"], *EVENTLOG_CASES[RDP_LOGON]["negative"]["rows"], *RDP_CASES[RDP_ADDRESS]["negative"]["rows"]]
        run = write_run(self.root, negatives)
        expected = self.expect({LOG_CLEARED: {"max": 0}, RDP_LOGON: {"max": 0}, RDP_ADDRESS: {"max": 0}})
        code, report, _err = self.run_script("--run", str(run), "--expect", expected, "--json")
        self.assertEqual(code, 0, report)
        rules = self.by_id(report)
        for rule_id in (LOG_CLEARED, RDP_LOGON, RDP_ADDRESS):
            self.assertEqual((rules[rule_id]["hits"], rules[rule_id]["result"]), (0, "pass"), rule_id)
            self.assertGreater(rules[rule_id]["eligible_rows"], 0)

    def test_recompute_matches_the_joined_set_and_needs_no_flag_set(self) -> None:
        run = self.standard_run(triage=False)
        code, _report, err = self.run_script("--run", str(run), "--json")
        self.assertEqual(code, 2)
        self.assertIn("no completed triage-flags set", err)
        code, report, _err = self.run_script("--run", str(run), "--recompute", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(report["flag_source"]["status"], "recomputed")
        rules = self.by_id(report)
        self.assertEqual((rules[LOG_CLEARED]["hits"], rules[RDP_ADDRESS]["hits"], rules[ADS]["hits"]), (1, 2, 2))
        self.assertEqual(rules[ADS]["samples"][0]["path_tail"], "notes.txt:svc.bin")

    def test_run_and_output_folders_are_read_only(self) -> None:
        run = self.standard_run()
        before = snapshot(run)
        out = self.root / "reports" / "rule-validation.json"
        for extra in ([], ["--recompute"]):
            code, _report, _err = self.run_script("--run", str(run), "--output", str(out), *extra)
            self.assertEqual(code, 0)
        self.assertEqual(snapshot(run), before)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], "rapidtriage-rule-validation-v1")

    def test_indicator_ips_split_public_and_non_public(self) -> None:
        indicators = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "10.8.0.15"},
            {"type": "ip", "value": "192.168.0.7"},
            {"type": "ip", "value": "100.64.1.1"},  # CGNAT: not public
            {"type": "domain", "value": "example.org"},
        ]
        run = self.standard_run(indicators=indicators)
        code, report, _err = self.run_script("--run", str(run), "--rules", LOG_CLEARED, "--json")
        self.assertEqual(code, 0)
        block = report["indicators"]
        self.assertEqual(block["indicator_count"], 5)
        self.assertEqual(block["type_counts"], {"domain": 1, "ip": 4})
        self.assertEqual((block["ip"]["total"], block["ip"]["public"], block["ip"]["non_public"]), (4, 1, 3))
        self.assertEqual(block["ip"]["non_public_samples"], ["10.8.0.15", "192.168.0.7", "100.64.1.1"])

    def test_input_errors_exit_2(self) -> None:
        run = self.standard_run()
        cases = {
            "missing run": ["--run", str(self.root / "nope")],
            "unknown rule": ["--run", str(run), "--rules", "nope.rule"],
            "bad expect shape": ["--run", str(run), "--expect", self.expect({LOG_CLEARED: 1})],
            "bad expect key": ["--run", str(run), "--expect", self.expect({LOG_CLEARED: {"atleast": 1}})],
            "expect unknown rule": ["--run", str(run), "--expect", self.expect({"x.y": {"min": 1}})],
            "min above max": ["--run", str(run), "--expect", self.expect({LOG_CLEARED: {"min": 2, "max": 1}})],
        }
        for name, args in cases.items():
            with self.subTest(name):
                code, _report, err = self.run_script(*args)
                self.assertEqual(code, 2)
                self.assertIn("input error", err)

    def test_text_report(self) -> None:
        run = self.standard_run()
        code, _report, _err = self.run_script("--run", str(run), "--rules", LOG_CLEARED)
        self.assertEqual(code, 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rule_validation.main(["--run", str(run), "--rules", LOG_CLEARED])
        self.assertIn("eventlog.log_cleared", out.getvalue())
        self.assertIn("Security.evtx", out.getvalue())

    # -- ntfs-meta analysis mode ---------------------------------------------------------------

    def test_ntfs_analysis_mode_runs_the_engine_over_mft_rows(self) -> None:
        run = self.root / "ntfs-run"
        run.mkdir()
        rows = case_rows(NTFS_CASES, SI_FN)  # timestomped (+1) · plain copy (−1)
        analysis = write_ntfs_analysis(run, rows, reason_counts={"si_created_before_fn": 1, "zero_subsecond": 0})
        before = snapshot(run)
        code, report, _err = self.run_script("--ntfs-analysis", str(analysis), "--expect", self.expect({SI_FN: {"min": 1, "max": 1}}), "--json")
        self.assertEqual(code, 0, report)
        self.assertEqual(snapshot(run), before)  # read-only
        self.assertEqual(report["mode"], "ntfs-analysis")
        self.assertEqual(report["input"]["row_count"], 2)
        rules = self.by_id(report)
        self.assertEqual(set(rules), {SI_FN, ADS})  # default rule pair
        si = rules[SI_FN]
        self.assertEqual((si["hits"], si["eligible_rows"], si["result"]), (1, 2, "pass"))
        self.assertEqual(si["hits_by_kind"], {"analysis:ntfs-mft-1": 1})
        self.assertEqual(si["analysis_cross_check"], {"reason": "si_created_before_fn", "analysis_count": 1, "engine_hits": 1, "agree": True})
        sample = si["samples"][0]
        self.assertEqual((sample["artifact_type"], sample["path_tail"]), ("ntfs-meta-row", "svc-helper.exe"))
        self.assertEqual(sample["evidence"]["path"], "…\\svc-helper.exe")
        self.assertEqual(sample["evidence"]["delta_seconds"], si["samples"][0]["evidence"]["delta_seconds"])
        self.assertGreater(sample["evidence"]["delta_seconds"], 0)
        # The MFT analysis has no ADS rows: never a silent 0-hit pass.
        ads = rules[ADS]
        self.assertEqual((ads["hits"], ads["eligible_rows"], ads["result"]), (0, 0, "not_applicable"))
        self.assertIn("ads-stream-candidate", ads["reason_ko"])

    def test_ntfs_analysis_negative_expectation_on_ads_is_a_mismatch(self) -> None:
        run = self.root / "ntfs-run"
        run.mkdir()
        analysis = write_ntfs_analysis(run, case_rows(NTFS_CASES, SI_FN))
        code, report, _err = self.run_script("--ntfs-analysis", str(analysis), "--expect", self.expect({ADS: {"max": 0}}), "--json")
        self.assertEqual(code, 1)
        ads = self.by_id(report)[ADS]
        self.assertEqual(ads["result"], "mismatch")
        self.assertIn("음성 대조 불성립", ads["reason_ko"])
        self.assertNotIn("analysis_cross_check", self.by_id(report)[SI_FN])  # no mismatch counts in the summary

    def test_ntfs_analysis_negative_only_and_input_errors(self) -> None:
        run = self.root / "ntfs-run"
        run.mkdir()
        analysis = write_ntfs_analysis(run, NTFS_CASES[SI_FN]["negative"]["rows"])
        code, report, _err = self.run_script("--ntfs-analysis", str(analysis), "--rules", SI_FN, "--expect", self.expect({SI_FN: {"max": 0}}), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(self.by_id(report)[SI_FN]["hits"], 0)
        wrong = self.root / "other"
        wrong.mkdir()
        other = write_ntfs_analysis(wrong, NTFS_CASES[SI_FN]["negative"]["rows"], kind="triage-flags")
        for args in (["--ntfs-analysis", str(other)], ["--ntfs-analysis", str(self.root / "missing")]):
            code, _report, err = self.run_script(*args)
            self.assertEqual(code, 2, args)
            self.assertIn("input error", err)
        shutil.rmtree(wrong)


if __name__ == "__main__":
    unittest.main()
