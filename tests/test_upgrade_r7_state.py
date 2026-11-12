"""R8 T-355 / QA-206: state written by the R7 build still opens on this build.

Synthetic R7 state only (``tests/fixtures/upgrade/r7-state.json``: DDL of commit 1da1b1e + 10 marks,
2 notes, 3 tags, 2 saved searches, 4 export audit records, 3 browser keys) and a sample run made
R7-shaped (summary without ``run_scope`` / ``fingerprint_mode``, ``runs.json`` without
``readonly_reason``, an old bookmark JSON, output folder inside the evidence).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.case_db.schema import SCHEMA_VERSION
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.readonly_runs import may_persist, unregister_readonly_folder
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.sample_case import build_sample_evidence

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "r8-upgrade-check.py"
TOKEN = "r7-upgrade-token"


def _load():
    spec = importlib.util.spec_from_file_location("r8_upgrade_check_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upgrade = _load()
FIXTURE = upgrade.load_fixture()
EXPECTED = FIXTURE["expected"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): "<dir>" if path.is_dir() else sha256(path) for path in sorted(root.rglob("*"))
    }


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()


class FixtureTests(unittest.TestCase):
    def test_fixture_is_synthetic_r7_state(self) -> None:
        self.assertTrue(FIXTURE["synthetic"])
        self.assertEqual(FIXTURE["schema_source_commit"], "1da1b1e")
        self.assertEqual(FIXTURE["schema_version"], SCHEMA_VERSION)
        self.assertEqual(len(FIXTURE["review_marks"]), EXPECTED["review_marks"])
        self.assertEqual(EXPECTED["review_marks"], 10)
        self.assertEqual(len(FIXTURE["case_notes"]), 2)
        self.assertEqual(len(FIXTURE["tags"]), 3)
        self.assertEqual(len(FIXTURE["saved_searches"]), 2)
        self.assertEqual(len(FIXTURE["export_audit_records"]), 4)
        self.assertEqual([entry["label"] for entry in FIXTURE["browser_storage"]], ["역할", "담당자 이름", "테마"])
        for record in FIXTURE["export_audit_records"]:
            for output in record["integrity"]["generated_outputs"]:
                self.assertTrue(output["path"].startswith("C:/synthetic/"), output["path"])


class CaseDbUpgradeTests(TempCase):
    def test_r7_db_opens_with_zero_difference(self) -> None:
        database = upgrade.build_r7_case_db(FIXTURE, self.base / "case" / "rapidtriage-case.db")
        hash_before = sha256(database)
        result = upgrade.check_case_db(database, write=True, backup_dir=self.base / "backup", expected=EXPECTED)
        self.assertEqual(result["problems"], [])
        self.assertEqual(result["schema_errors"], [])
        self.assertEqual(result["diff"], dict.fromkeys(upgrade.COUNT_KEYS, 0))
        for key in upgrade.COUNT_KEYS:
            self.assertEqual(result["counts_after"][key], EXPECTED[key], key)
        self.assertEqual(result["backup"]["files"], 1)
        self.assertTrue(result["backup"]["taken_before_open"])
        backups = sorted(path.name for path in (self.base / "backup").glob("*.db"))
        self.assertEqual(backups, ["rapidtriage-case.db"])
        self.assertEqual(sha256(self.base / "backup" / "rapidtriage-case.db"), hash_before)

    def test_tags_and_marks_read_by_current_code(self) -> None:
        database = upgrade.build_r7_case_db(FIXTURE, self.base / "rapidtriage-case.db")
        upgrade.check_case_db(database, write=True, backup_dir=self.base / "backup")
        db = upgrade.CaseDatabase(database)
        marks = db.list_review_marks("r7-case")
        tags = sorted({tag for mark in marks for tag in mark["tags"]})
        self.assertEqual(tags, sorted(FIXTURE["tags"]))
        self.assertEqual(sum(1 for mark in marks if mark["include_in_report"]), EXPECTED["include_in_report_marks"])
        self.assertEqual({item["name"] for item in db.list_saved_searches("r7-case")}, {"송금 키워드", "반출 흔적"})

    def test_migration_path_takes_the_backup_first(self) -> None:
        database = upgrade.build_r7_case_db(FIXTURE, self.base / "rapidtriage-case.db", before_tag_table=True)
        before = upgrade.inspect_case_db(database)
        self.assertTrue(before["migration_needed"])
        self.assertIn("review_mark.tag_ids_json", before["missing"])
        result = upgrade.check_case_db(database, write=True, backup_dir=self.base / "backup", expected=EXPECTED)
        self.assertEqual(result["problems"], [])
        self.assertEqual(result["diff"], dict.fromkeys(upgrade.COUNT_KEYS, 0))
        self.assertEqual(result["backup"]["files"], 1)
        self.assertTrue(result["backup"]["migration_needed"])
        # The backup copy is the DB as it was before the migration (no tag table yet).
        copy = upgrade.inspect_case_db(self.base / "backup" / "rapidtriage-case.db")
        self.assertIn("table:case_tag", copy["missing"])
        self.assertFalse(upgrade.inspect_case_db(database)["migration_needed"])

    def test_read_only_check_never_writes(self) -> None:
        database = upgrade.build_r7_case_db(FIXTURE, self.base / "run" / "rapidtriage-case.db", before_tag_table=True)
        before = snapshot(self.base / "run")
        result = upgrade.check_case_db(database, expected=EXPECTED)
        self.assertEqual(result["problems"], [])
        self.assertTrue(result["unchanged"])
        self.assertIn("백업 후 이관", result["notice"])
        self.assertEqual(snapshot(self.base / "run"), before)

    def test_unsupported_schema_gets_a_korean_message_and_no_write(self) -> None:
        database = upgrade.build_r7_case_db(FIXTURE, self.base / "rapidtriage-case.db")
        connection = sqlite3.connect(database)
        connection.execute("UPDATE schema_info SET value = '99' WHERE key = 'schema_version'")
        connection.commit()
        connection.close()
        hash_before = sha256(database)
        result = upgrade.check_case_db(database, write=True, backup_dir=self.base / "backup")
        self.assertEqual(len(result["problems"]), 1)
        self.assertIn("스키마 버전(99)", result["problems"][0])
        self.assertIn("열 수 없습니다", result["problems"][0])
        self.assertTrue(result["unchanged"])
        self.assertEqual(sha256(database), hash_before)
        self.assertFalse((self.base / "backup").exists())

    def test_cli_synthetic_run_passes(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = upgrade.main(["--synthetic", str(self.base / "work"), "--json"])
        report = json.loads(out.getvalue())
        self.assertEqual(code, 0, report["problems"])
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["synthetic"]["storage"]["label"], "R7 저장 키 읽기 3/3")


class AuditTests(TempCase):
    def test_r7_records_are_pre_chain_not_broken(self) -> None:
        paths = upgrade.write_r7_audit(FIXTURE, self.base / "audit")
        for name, path in paths.items():
            with self.subTest(name):
                result = upgrade.check_audit([path])
                self.assertEqual((result["records"], result["pre_chain"], result["broken"]), (4, 4, 0))
                self.assertEqual(result["label"], "사슬 이전 4줄")

    def _chained(self) -> Path:
        path = upgrade.write_r7_audit(FIXTURE, self.base / "audit")["lines"]
        lines = path.read_text(encoding="utf-8").splitlines()
        for index in range(2):
            record = {"command": "case-report", "n": index, upgrade.CHAIN_FIELD: hashlib.sha256(lines[-1].encode()).hexdigest()}
            lines.append(json.dumps(record))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        return path

    def test_chained_lines_after_old_lines_verify(self) -> None:
        result = upgrade.check_audit([self._chained()])
        self.assertEqual((result["pre_chain"], result["chained"], result["broken"]), (4, 2, 0))

    def test_tampered_line_is_named(self) -> None:
        path = self._chained()
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[4] = lines[4].replace('"n": 0', '"n": 7')  # changes line 5 -> line 6's hash no longer matches
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        result = upgrade.check_audit([path])
        self.assertEqual(result["broken"], 1)
        self.assertEqual(result["broken_lines"][0]["line"], 6)
        self.assertIn("감사 깨짐 1줄", upgrade.collect_problems({"audit": result}))


class StorageKeyTests(unittest.TestCase):
    def test_three_r7_keys_read(self) -> None:
        result = upgrade.check_storage_keys(FIXTURE["browser_storage"])
        self.assertEqual((result["read"], result["total"]), (3, 3), result["items"])
        self.assertEqual(result["label"], "R7 저장 키 읽기 3/3")

    def test_unknown_key_is_reported_in_korean(self) -> None:
        result = upgrade.check_storage_keys([{"item": "x", "label": "x", "key": "rapidtriage.gone", "r7_value": "1"}])
        self.assertEqual(result["read"], 0)
        self.assertIn("키가 없어", result["items"][0]["how"])


class _Run:
    """One sample run (built once), copied per test into its evidence as an R7-era output."""

    _tmp: tempfile.TemporaryDirectory | None = None

    @classmethod
    def build(cls) -> tuple[Path, Path]:
        if cls._tmp is None:
            cls._tmp = tempfile.TemporaryDirectory()
            base = Path(cls._tmp.name).resolve()
            build_sample_evidence(base / "evidence")
            run_triage_mode(base / "evidence", mode="fraud", output_dir=base / "out", read_only=True)
        base = Path(cls._tmp.name).resolve()
        return base / "evidence", base / "out"


def tearDownModule() -> None:
    if _Run._tmp is not None:
        _Run._tmp.cleanup()


class R7RunTests(TempCase):
    def setUp(self) -> None:
        super().setUp()
        source_evidence, source_out = _Run.build()
        self.evidence = self.base / "evidence"
        shutil.copytree(source_evidence, self.evidence)
        self.folder = self.evidence / "out"  # pre-guard: the output was written inside the evidence
        shutil.copytree(source_out, self.folder)
        summary_path = self.folder / upgrade.SUMMARY_NAME
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for key in FIXTURE["run"]["summary_keys_absent_in_r7"]:
            summary.pop(key, None)
        summary["root"] = str(self.evidence)
        summary["output_dir"] = str(self.folder)
        summary["outputs"] = {
            name: str(self.folder / Path(value).relative_to(source_out)) for name, value in summary["outputs"].items()
        }
        summary_path.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        self.summary = summary
        case_json = {"command": "case", "case_id": "r7-run", "bookmarks": FIXTURE["run"]["bookmarks"]}
        (self.folder / upgrade.CASE_JSON_NAME).write_text(json.dumps(case_json, ensure_ascii=False), encoding="utf-8")
        self._add_r7_marks(self.folder / upgrade.CASE_DB_NAME)
        self.expected_candidates = EXPECTED["include_in_report_bookmarks"] + EXPECTED["include_in_report_marks"]
        self.addCleanup(unregister_readonly_folder, self.folder)

    @staticmethod
    def _add_r7_marks(database: Path) -> None:
        connection = sqlite3.connect(database)
        try:
            case_id = connection.execute("SELECT case_id FROM case_record WHERE case_id = 'run-out'").fetchone()[0]
            assert connection.execute("SELECT COUNT(*) FROM review_mark").fetchone()[0] == 0
            for index, mark in enumerate(FIXTURE["review_marks"], start=1):
                connection.execute(
                    "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, status, note, include_in_report, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, '2026-10-01T09:00:00', '2026-10-01T09:00:00')",
                    (f"R7-RM-{index:04d}", case_id, mark["target_type"], mark["target_id"], mark["status"], mark["note"],
                     int(mark["include_in_report"])),
                )
            connection.commit()
        finally:
            connection.close()

    def test_script_reads_an_old_run_without_writing(self) -> None:
        before = snapshot(self.evidence)
        result = upgrade.check_run_folder(self.folder)
        self.assertEqual(result["problems"], [])
        self.assertEqual(result["r7_summary"], ["run_scope", "fingerprint_mode"])
        self.assertEqual(result["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertEqual(result["review_marks"], EXPECTED["review_marks"])
        self.assertEqual(result["report_candidates"]["count"], self.expected_candidates)
        self.assertEqual(result["writes"], 0)
        self.assertEqual(snapshot(self.evidence), before)

    def test_r7_runs_json_opens_read_only_with_one_candidate_count(self) -> None:
        record = {
            "run_id": "r7run000001",
            "status": "completed",
            "origin": "web",
            "created_at": "2026-10-01T09:00:00+09:00",
            "updated_at": "2026-10-01T09:30:00+09:00",
            "completed_at": "2026-10-01T09:30:00+09:00",
            "request": {"root": str(self.evidence), "mode": "fraud", "output_dir": str(self.folder)},
            "summary": self.summary,
        }
        for key in FIXTURE["run"]["runs_json_keys_absent_in_r7"]:
            self.assertNotIn(key, record)
        state = self.base / "state" / "runs.json"
        state.parent.mkdir()
        state.write_text(json.dumps({"version": 1, "runs": [record]}, ensure_ascii=False), encoding="utf-8")
        before = snapshot(self.evidence)
        store = RunJobStore(state_path=state)
        self.assertEqual(store.get("r7run000001").readonly_reason, "OUTPUT_INSIDE_EVIDENCE")
        self.assertFalse(may_persist(self.folder / "rapidtriage-lazy.json"))
        with TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}) as client:
            counts = client.get("/api/runs/r7run000001/review-counts")
            self.assertEqual(counts.status_code, 200, counts.text)
            self.assertIsNone(counts.json()["error"])
            self.assertEqual(counts.json()["report_candidates"], self.expected_candidates)
            self.assertEqual(counts.json()["report_candidates"], upgrade.check_run_folder(self.folder)["report_candidates"]["count"])
            review_map = client.get("/api/runs/r7run000001/review-map")
            self.assertEqual(review_map.status_code, 200, review_map.text)
            self.assertEqual(len(review_map.json()["marks"]), EXPECTED["review_marks"])
            refused = client.post("/api/runs/r7run000001/bookmarks", json={"source": "files", "pointer": "/candidates/0"})
            self.assertEqual(refused.status_code, 409, refused.text)
            self.assertEqual(refused.json()["detail"]["code"], "RUN_READ_ONLY")
            self.assertIn("읽기 전용", refused.json()["detail"]["message"])
        self.assertEqual(snapshot(self.evidence), before)
        saved = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(saved["runs"][0]["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")

    def test_import_of_an_r7_folder_works_read_only(self) -> None:
        store = RunJobStore()
        before = snapshot(self.evidence)
        with TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}) as client:
            response = client.post("/api/runs/import", json={"output_dir": str(self.folder)})
            self.assertEqual(response.status_code, 201, response.text)
            self.assertEqual(response.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
            run_id = response.json()["run_id"]
            counts = client.get(f"/api/runs/{run_id}/review-counts").json()
            self.assertEqual(counts["report_candidates"], self.expected_candidates)
        self.assertEqual(snapshot(self.evidence), before)

    def test_unsupported_summary_gets_a_korean_message(self) -> None:
        summary_path = self.folder / upgrade.SUMMARY_NAME
        summary_path.write_text(json.dumps({"root": str(self.evidence)}), encoding="utf-8")
        result = upgrade.check_run_folder(self.folder)
        self.assertEqual(len(result["problems"]), 1)
        self.assertIn("지원하지 않는 형식", result["problems"][0])


if __name__ == "__main__":
    unittest.main()
