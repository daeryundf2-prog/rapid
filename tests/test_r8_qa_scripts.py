"""R8 T-003 QA scripts on synthetic folders: evidence snapshot, log scan, report audit, trace audit."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"r8_{name.replace('-', '_')}_test", SCRIPTS / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


snapshot_mod = _load("r8-evidence-snapshot")
log_scan = _load("r8-log-scan")
report_audit = _load("r8-report-audit")
trace_audit = _load("r8-trace-audit")


def _quiet(fn, *args):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = fn(*args)
    return code, out.getvalue()


class EvidenceSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.root = base / "case_q7"
        self.out = base / "qa"
        (self.root / "sub").mkdir(parents=True)
        (self.root / "a.bin").write_bytes(b"0123456789")
        (self.root / "sub" / "b.txt").write_bytes(b"hello")
        (self.root / "gone.txt").write_bytes(b"x")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snap(self, name: str, *extra: str) -> Path:
        path = self.out / name
        code, _ = _quiet(
            snapshot_mod.main, ["--root", str(self.root), "--output", str(path), *extra]
        )
        self.assertEqual(code, 0)
        return path

    def test_identical_snapshots_compare_clean(self) -> None:
        a, b = self._snap("a.json"), self._snap("b.json")
        code, out = _quiet(snapshot_mod.main, ["--compare", str(a), str(b)])
        self.assertEqual(code, 0, out)
        self.assertIn("IDENTICAL", out)

    def test_one_byte_change_new_and_deleted_file_detected(self) -> None:
        before = self._snap("before.json")
        data = (self.root / "a.bin").read_bytes()
        st = (self.root / "a.bin").stat()
        (self.root / "a.bin").write_bytes(
            data[:3] + b"X" + data[4:]
        )  # same size, 1 byte differs
        os.utime(
            self.root / "a.bin", ns=(st.st_atime_ns, st.st_mtime_ns)
        )  # even with mtime restored
        (self.root / "sub" / "new.txt").write_bytes(b"n")
        (self.root / "gone.txt").unlink()
        after = self._snap("after.json")
        result = snapshot_mod.compare(
            *(json.loads(p.read_text(encoding="utf-8")) for p in (before, after))
        )
        self.assertEqual([c["path"] for c in result["changed"]], ["0/a.bin"])
        self.assertEqual(result["changed"][0]["fields"], ["sha256"])
        self.assertEqual(result["new"], ["0/sub/new.txt"])
        self.assertEqual(result["deleted"], ["0/gone.txt"])
        code, _ = _quiet(snapshot_mod.main, ["--compare", str(before), str(after)])
        self.assertEqual(code, 1)

    def test_redacted_names_hide_paths_but_still_compare(self) -> None:
        before = self._snap("r1.json", "--redact-names")
        text = before.read_text(encoding="utf-8")
        self.assertNotIn("a.bin", text)
        self.assertNotIn(str(self.root.name), text)
        (self.root / "sub" / "b.txt").write_bytes(b"hellO")
        after = self._snap("r2.json", "--redact-names")
        result = snapshot_mod.compare(
            *(json.loads(p.read_text(encoding="utf-8")) for p in (before, after))
        )
        self.assertEqual(len(result["changed"]), 1)
        self.assertTrue(result["changed"][0]["path"].startswith("sha256:"))

    def test_refuses_output_inside_evidence_root(self) -> None:
        with self.assertRaises(SystemExit):
            _quiet(
                snapshot_mod.main,
                ["--root", str(self.root), "--output", str(self.root / "snap.json")],
            )
        self.assertFalse((self.root / "snap.json").exists())

    def test_before_after_diff_shorthand(self) -> None:
        state = self.out / "state"
        common = ["--root", str(self.root), "--state-dir", str(state)]
        self.assertEqual(_quiet(snapshot_mod.main, [*common, "--before"])[0], 0)
        self.assertEqual(
            _quiet(snapshot_mod.main, [*common, "--after", "--diff"])[0], 0
        )
        (self.root / "extra.txt").write_bytes(b"e")
        self.assertEqual(
            _quiet(snapshot_mod.main, [*common, "--after", "--diff"])[0], 1
        )
        self.assertTrue((state / "evid_diff.json").exists())


class LogScanTests(unittest.TestCase):
    # Fake values only: assembled at runtime so no secret-shaped literal sits in the repo.
    FAKE_SECRETS = (
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "gh" + "p_" + "a" * 36,
        "api_key=" + "Z" * 24,
    )
    FAKE_PATHS = (
        "C:" + "\\Users\\" + "examiner\\AppData\\Local\\x.db",
        "/home/" + "analyst/.config/app",
    )

    def test_fake_secrets_and_paths_detected_counts_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "server.log"
            log.write_text(
                "\n".join(f"line {v}" for v in self.FAKE_SECRETS + self.FAKE_PATHS),
                encoding="utf-8",
            )
            report = log_scan.scan_paths([Path(tmp)])
            self.assertEqual(report["by_pattern"].get("aws_access_key"), 1)
            self.assertEqual(report["by_pattern"].get("github_token"), 1)
            self.assertEqual(report["by_pattern"].get("secret_assignment"), 1)
            self.assertEqual(report["by_pattern"].get("windows_user_path"), 1)
            self.assertEqual(report["by_pattern"].get("posix_home_path"), 1)
            code, out = _quiet(log_scan.main, [str(log), "--json"])
            self.assertEqual(code, 1)
            for value in self.FAKE_SECRETS + self.FAKE_PATHS:
                self.assertNotIn(value, out)  # counts only, never the matched text

    def test_identifiers_detected_with_validation(self) -> None:
        hits = log_scan.scan_text(
            "rrn 900101-1234567 card 4111 1111 1111 1111 order 1234 5678 9012 3456"
        )
        self.assertEqual(hits.get("kr_resident_number"), 1)
        self.assertEqual(
            hits.get("card_number"), 1
        )  # second number fails the Luhn check

    def test_clean_log_has_zero_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "clean.log"
            log.write_text(
                "2026-11-12T10:00:00Z INFO run started run_id=ab12 kind=registry rows=1200\n"
                "GET /api/runs/ab12/files 200 12ms\nPOST /api/cases 409 conflict code=CASE_EXISTS\n",
                encoding="utf-8",
            )
            code, _ = _quiet(log_scan.main, [str(log)])
            self.assertEqual(code, 0)
            self.assertEqual(log_scan.scan_paths([log])["total_hits"], 0)


FULL_REPORT_LINES = [
    "# 사건 보고서",
    "도구 버전: RapidTriage 0.9.1",
    "카탈로그 버전: 2026.11",
    "증거 해시: SHA-256 " + "ab" * 32,
    "처리 범위: 할당 파일 전체",
    "실패·부분 단계: 없음",
    "시간대: UTC+09:00",
    "조건: 태그=관련 있음",
]


class ReportAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_complete_markdown_passes(self) -> None:
        path = self.dir / "r.md"
        path.write_text("\n".join(FULL_REPORT_LINES), encoding="utf-8")
        self.assertTrue(report_audit.audit_file(path)["ok"])

    def test_each_missing_field_fails(self) -> None:
        for idx, field in enumerate(report_audit.REQUIRED_FIELDS, start=1):
            with self.subTest(field=field):
                lines = [line for i, line in enumerate(FULL_REPORT_LINES) if i != idx]
                path = self.dir / f"missing-{field}.md"
                path.write_text("\n".join(lines), encoding="utf-8")
                result = report_audit.audit_file(path)
                self.assertFalse(result["ok"])
                self.assertEqual(result["missing_fields"], [field])

    def test_forbidden_strings_fail(self) -> None:
        path = self.dir / "bad.html"
        body = "".join(f"<p>{line}</p>" for line in FULL_REPORT_LINES)
        path.write_text(
            f"<h2>Findings</h2>{body}<p>status=ok</p><p>명백히 삭제했다</p>",
            encoding="utf-8",
        )
        result = report_audit.audit_file(path)
        self.assertEqual(
            set(result["forbidden"]),
            {"english_title", "raw_status_token", "assertive_wording"},
        )
        code, _ = _quiet(report_audit.main, [str(path)])
        self.assertEqual(code, 1)

    def test_docx_json_and_pdf_extraction(self) -> None:
        docx = self.dir / "r.docx"
        paras = "".join(
            f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in FULL_REPORT_LINES
        )
        with zipfile.ZipFile(docx, "w") as zf:
            zf.writestr(
                "word/document.xml",
                f'<w:document xmlns:w="x"><w:body>{paras}</w:body></w:document>',
            )
        self.assertTrue(report_audit.audit_file(docx)["ok"])

        js = self.dir / "r.json"
        js.write_text(
            json.dumps(
                {
                    "tool_version": "0.9.1",
                    "catalog_version": "2026.11",
                    "evidence_hash": "ab" * 32,
                    "processing_scope": "allocated",
                    "failed_stages": [],
                    "timezone": "UTC+09:00",
                    "conditions": {},
                }
            ),
            encoding="utf-8",
        )
        self.assertTrue(report_audit.audit_file(js)["ok"])

        pdf = self.dir / "r.pdf"
        ops = b"".join(
            b"<" + ("﻿" + line).encode("utf-16-be").hex().encode() + b"> Tj\n"
            for line in FULL_REPORT_LINES[1:6]
        )
        stream = zlib.compress(b"BT\n" + ops + b"ET")
        pdf.write_bytes(
            b"%PDF-1.4\n1 0 obj<<>>stream\n" + stream + b"\nendstream\nendobj\n%%EOF"
        )
        result = report_audit.audit_file(pdf)
        self.assertEqual(result["missing_fields"], ["time_zone", "conditions"])


# ---------------------------------------------------------------- trace audit

PLAN_A = """# A
| ID | 이상적 상태 | 왜 | 사용자 |
|---|---|---|---|
| IS-001 | a | b | c |
| IS-002 | a | b | c |
| IS-003 | a | b | c |
"""
PLAN_B = """# B
| GAP | IS | 현재(증거) | 심각도 | 이유 |
|---|---|---|---|---|
| GAP-001 | 001 | x | S1 | y |
| GAP-002 | 002 | x | S2 | y |
"""
PLAN_E = """# E
### E.3.1
| QA | IS | 데이터 | 절차 | 기대 | 판정 | 증거 | 자동화 |
|---|---|---|---|---|---|---|---|
| QA-001 | 001 | C1 | p | e | — | e | PY |
| QA-002 | 002 | C1 | p | e | — | e | PY |
"""
TASK_HEADER = "| ID | 제목 | 파일 | 의존 | h | 동작·수용 | GAP/IS | QA | 모델 | 검증 |\n|---|---|---|---|---|---|---|---|---|---|\n"
PLAN_G = """# G
## G.1 IS → GAP → 과제 → QA
| IS | GAP | 과제 | QA | 판정 |
|---|---|---|---|---|
| IS-001 | GAP-001 | T-001 | QA-001 | — |
| IS-002 | GAP-002 | T-002 | QA-002 | — |
| IS-003 | — | — | — | — |
## G.3 QA가 없는 과제와 그 이유
| 과제 | 물결 | 제목 | 이유 |
|---|---|---|---|
"""


def _task(
    tid: str,
    files: str,
    deps: str,
    accept: str,
    gap_is: str,
    qa: str,
    verify: str = "V-PY",
    h: str = "2",
) -> str:
    return f"| {tid} | title | {files} | {deps} | {h} | {accept} | {gap_is} | {qa} | Opus | {verify} |\n"


class TraceAuditTests(unittest.TestCase):
    def _plan(
        self, tasks_md: str, b: str = PLAN_B, e: str = PLAN_E, g: str = PLAN_G
    ) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        for name, text in {
            "r8-ideal-state.md": PLAN_A,
            "r8-gaps.md": b,
            "r8-qa-scenarios.md": e,
            "r8-tasks.md": tasks_md,
            "r8-traceability.md": g,
        }.items():
            (d / name).write_text(text, encoding="utf-8")
        return d

    def _run(self, tasks_md: str, **kw) -> dict:
        plan = trace_audit.Plan(self._plan(tasks_md, **kw))
        checks, _ = trace_audit.run_checks(plan, Path(__file__).resolve().parent.parent)
        return checks

    def _tasks(self, *rows: str, bundles: tuple[str, ...] = ("WA-1",)) -> str:
        md = "# F\n## F.3 과제표\n"
        for bundle, chunk in zip(bundles, rows):
            md += f"### {bundle} — t ({chunk.count('| T-')})\n\n{TASK_HEADER}{chunk}\n"
        return (
            md
            + "## F.4 폐기\n| ID | v2 제목 | 사유 |\n|---|---|---|\n| T-099 | x | y |\n"
        )

    def _clean_rows(self) -> str:
        return _task(
            "T-001", "`scripts/a.py`", "—", "ok", "GAP-001 / IS-001", "QA-001"
        ) + _task(
            "T-002", "`scripts/b.py`", "—", "ok", "GAP-002 / IS-002·003", "QA-002"
        )

    def test_orphans_reported(self) -> None:
        checks = self._run(self._tasks(self._clean_rows()))
        self.assertEqual(checks["is_without_gap"], ["IS-003"])
        self.assertEqual(checks["is_without_qa"], ["IS-003"])
        self.assertEqual(checks["gap_without_task"], [])
        self.assertEqual(checks["g1_drift"], ["IS-003 tasks: +T-002 / --"])

    def test_gap_without_task_and_missing_qa(self) -> None:
        rows = _task(
            "T-001", "`scripts/a.py`", "—", "ok", "GAP-001 / IS-001", "QA-001"
        ) + _task("T-003", "`scripts/c.py`", "—", "ok", "IS-002", "—")
        checks = self._run(self._tasks(rows))
        self.assertEqual(checks["gap_without_task"], ["GAP-002"])
        self.assertEqual(checks["task_without_qa"], ["T-003"])
        self.assertEqual(checks["qa_without_task"], ["QA-002"])

    def test_file_overlap_within_bundle_including_globs(self) -> None:
        rows = _task(
            "T-001", "`frontend/e2e/*.spec.ts`", "—", "ok", "GAP-001 / IS-001", "QA-001"
        ) + _task(
            "T-002",
            "`frontend/e2e/grid.spec.ts`(블록만)",
            "—",
            "ok",
            "GAP-002 / IS-002",
            "QA-002",
        )
        checks = self._run(self._tasks(rows))
        self.assertEqual(len(checks["file_overlap_in_bundle"]), 1)
        # the same files in different bundles do not conflict
        split = self._tasks(
            rows.splitlines(True)[0], rows.splitlines(True)[1], bundles=("WA-1", "WA-2")
        )
        self.assertEqual(self._run(split)["file_overlap_in_bundle"], [])

    def test_wave_and_dependency_contradictions(self) -> None:
        early = _task("T-001", "`a/x.py`", "T-002", "ok", "GAP-001 / IS-001", "QA-001")
        late = _task("T-002", "`a/y.py`", "—", "ok", "GAP-002 / IS-002", "QA-002")
        checks = self._run(self._tasks(early, late, bundles=("WA-1", "WB-1")))
        self.assertEqual(len(checks["wave_dependency"]), 1)
        self.assertIn("later wave WB", checks["wave_dependency"][0])
        same_bundle = self._run(self._tasks(early + late))
        self.assertIn("not earlier", same_bundle["wave_dependency"][0])
        screen_on_engine = self._run(
            self._tasks(late, early, bundles=("WP1-1", "WF-1"))
        )
        self.assertIn("engine lane", screen_on_engine["wave_dependency"][0])
        ok = self._run(self._tasks(late, early, bundles=("WA-1", "WB-1")))
        self.assertEqual(ok["wave_dependency"], [])

    def test_verification_target_must_exist_or_be_listed(self) -> None:
        rows = _task(
            "T-001",
            "`tests/test_new_thing.py`",
            "—",
            "ok",
            "GAP-001 / IS-001",
            "QA-001",
            "`python -m unittest tests.test_new_thing`<br>V-PY",
        ) + _task(
            "T-002",
            "`scripts/b.py`",
            "—",
            "ok",
            "GAP-002 / IS-002",
            "QA-002",
            "`python -m unittest tests.test_r8_qa_scripts tests.test_nope_missing`",
        )
        checks = self._run(self._tasks(rows))
        self.assertEqual(
            checks["verification_target_missing"],
            [
                "T-002: unittest `tests/test_nope_missing.py` not in files column or repo"
            ],
        )

    def test_same_as_wording_and_parse_issue(self) -> None:
        rows = (
            _task("T-001", "`a/x.py`", "—", "v2와 같음", "GAP-001 / IS-001", "QA-001")
            + _task(
                "T-002",
                "`a/y.py`",
                "—",
                '검사: 동작에 "같음"이 없는가',
                "GAP-002 / IS-002",
                "QA-002",
            )
            + "| T-004 | broken row | `a/z.py` |\n"
        )
        checks = self._run(self._tasks(rows))
        self.assertEqual([x.split()[0] for x in checks["same_as_wording"]], ["T-001"])
        self.assertEqual(len(checks["table_parse"]), 1)

    def test_parse_ids_and_code_spans(self) -> None:
        self.assertEqual(
            trace_audit.parse_ids("GAP-373·204 / IS-067·074"),
            ["GAP-373", "GAP-204", "IS-067", "IS-074"],
        )
        self.assertEqual(
            trace_audit.parse_ids("QA-001~003", "QA"), ["QA-001", "QA-002", "QA-003"]
        )
        self.assertEqual(trace_audit.parse_ids("`f.py:123` 067", "IS"), ["IS-067"])
        self.assertEqual(len(trace_audit.split_row("| a | `x|y` and `` ` `` | c |")), 3)

    def test_cli_check_exit_code(self) -> None:
        d = self._plan(self._tasks(self._clean_rows()))
        code, out = _quiet(trace_audit.main, ["--plan-dir", str(d), "--check"])
        self.assertEqual(code, 1)
        self.assertIn("is_without_gap: 1", out)
        code, _ = _quiet(trace_audit.main, ["--plan-dir", str(d)])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
