"""R8 T-166 corpus audit (QA-201) on synthetic temp folders: fields, hashes, runs, leaks."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "r8-corpus-audit.py"


def _load():
    spec = importlib.util.spec_from_file_location("r8_corpus_audit_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit_mod = _load()


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = audit_mod.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write_run(folder: Path, kinds: dict[str, dict[str, int]]) -> Path:
    (folder / "artifacts").mkdir(parents=True)
    (folder / "rapidtriage-run-summary.json").write_text("{}", encoding="utf-8")
    for kind, counts in kinds.items():
        payload = {"summary": {"artifact_type_counts": counts}}
        (folder / "artifacts" / f"rapidtriage-artifacts-{kind}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    return folder


class CorpusAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "corpus"
        for cid in audit_mod.CORPORA:
            self._manifest(cid)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _manifest(self, cid: str, *, drop: str | None = None, **extra) -> Path:
        folder = self.root / cid
        (folder / "img").mkdir(parents=True, exist_ok=True)
        seg = folder / "img" / f"SYNTH-{cid}.E01"
        seg.write_bytes(f"segment-{cid}".encode() * 10)
        (folder / "answer-key.json").write_text("{}", encoding="utf-8")
        st = seg.stat()
        manifest = {
            "corpus": cid,
            "status": "available",
            "source": f"synthetic source {cid}",
            "license": "synthetic-test-licence",
            "created": "2026-11-12",
            "answer_key": "answer-key.json",
            "size_bytes": st.st_size,
            "items": [{
                "path": f"img/SYNTH-{cid}.E01", "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                "sha256": hashlib.sha256(seg.read_bytes()).hexdigest(),
            }],
            "expected_tier1": [],
        }
        manifest.update(extra)
        if drop == "size":
            manifest.pop("size_bytes")
        elif drop == "hash":
            manifest["items"][0].pop("sha256")
        elif drop:
            manifest.pop(drop)
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return folder

    def _report(self, *extra: str) -> tuple[int, dict]:
        code, out, err = _run(["--corpus-root", str(self.root), "--json", *extra])
        self.assertEqual(err, "")
        return code, json.loads(out)

    def _entry(self, report: dict, cid: str) -> dict:
        return next(e for e in report["corpora"] if e["corpus"] == cid)

    def test_complete_manifests_pass(self) -> None:
        code, report = self._report()
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["totals"]["manifests_present"], 6)
        self.assertEqual(report["totals"]["items_present"], 6)

    def test_each_of_six_missing_fields_is_detected(self) -> None:
        for cid, field in zip(audit_mod.CORPORA, audit_mod.REQUIRED_FIELDS):
            self._manifest(cid, drop=field)
        code, report = self._report()
        self.assertEqual(code, 1)
        for cid, field in zip(audit_mod.CORPORA, audit_mod.REQUIRED_FIELDS):
            entry = self._entry(report, cid)
            self.assertEqual(entry["fields_missing"], [field], cid)
            self.assertIn(f"field_missing:{field}", entry["issues"])

    def test_malformed_date_and_hash_count_as_missing(self) -> None:
        folder = self._manifest("C2", created="yesterday")
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        manifest["items"][0]["sha256"] = "abc"
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        _code, report = self._report()
        self.assertEqual(self._entry(report, "C2")["fields_missing"], ["hash", "created"])

    def test_missing_manifest_fails_and_unavailable_with_reason_passes(self) -> None:
        (self.root / "C5" / "manifest.json").unlink()
        self._manifest("C6", status="unavailable", unavailable_reason="D32 승인 대기")
        code, report = self._report()
        self.assertEqual(code, 1)
        self.assertEqual(self._entry(report, "C5")["issues"], ["manifest_missing"])
        c6 = self._entry(report, "C6")
        self.assertEqual((c6["status"], c6["issues"]), ("unavailable", []))
        self._manifest("C6", status="unavailable")
        _code, report = self._report()
        self.assertIn("unavailable_without_reason", self._entry(report, "C6")["issues"])

    def test_quick_mode_flags_missing_resized_and_touched_items(self) -> None:
        (self.root / "C1" / "img" / "SYNTH-C1.E01").unlink()
        seg2 = self.root / "C2" / "img" / "SYNTH-C2.E01"
        seg2.write_bytes(b"shorter")
        code, report = self._report()
        self.assertEqual(code, 1)
        self.assertIn("item_missing", self._entry(report, "C1")["issues"])
        c2 = self._entry(report, "C2")
        self.assertIn("item_size_mismatch", c2["issues"])
        self.assertEqual(c2["items"]["sha256_unverified"], 1)

    def test_full_mode_detects_same_size_tamper(self) -> None:
        seg = self.root / "C3" / "img" / "SYNTH-C3.E01"
        st = seg.stat()
        data = bytearray(seg.read_bytes())
        data[0] ^= 0xFF
        seg.write_bytes(bytes(data))
        os.utime(seg, ns=(st.st_atime_ns, st.st_mtime_ns))
        code, report = self._report()
        self.assertEqual(code, 0, "quick mode cannot see a same-size, same-mtime change")
        code, report = self._report("--full")
        self.assertEqual(code, 1)
        c3 = self._entry(report, "C3")
        self.assertEqual((c3["items"]["sha256_mismatch"], c3["items"]["mode"]), (1, "full_sha256"))
        self.assertEqual(self._entry(report, "C1")["items"]["sha256_ok"], 1)

    def test_tier1_rows_from_processed_run_and_gaps(self) -> None:
        run = _write_run(self.base / "runs" / "c3", {
            "browser": {"browser-history": 5, "browser-ai-usage": 1},
            "windows-registry": {"windows-usb-device": 2, "registry-summary": 1},
            "kakaotalk-windows": {"kakaotalk-app-inventory": 1},
            "windows-prefetch": {"prefetch-file": 3},
        })
        self._manifest("C3", expected_tier1=["web", "exfil", "messenger", "email"], runs=[str(run)])
        code, report = self._report()
        self.assertEqual(code, 0)
        c3 = self._entry(report, "C3")
        self.assertEqual(c3["runs"], {"declared": 1, "found": 1})
        self.assertEqual(c3["tier1_rows"]["web"], 5)
        self.assertEqual(c3["tier1_rows"]["ai_usage"], 1)
        self.assertEqual(c3["tier1_rows"]["messenger"], 0, "inventory rows are not messages")
        self.assertEqual(c3["coverage_gaps"], ["messenger", "email"])
        self.assertIn("messenger", report["tier1_gaps"])
        self.assertNotIn("execution", report["tier1_gaps"])
        code, _report = self._report("--strict-coverage")
        self.assertEqual(code, 1)

    def test_run_override_and_missing_run(self) -> None:
        run = _write_run(self.base / "runs" / "c4", {"ai-agent": {"ai-agent-session": 2}})
        self._manifest("C4", expected_tier1=["ai_usage"], runs=["no-such-run"])
        _code, report = self._report("--run", f"C4={run}")
        c4 = self._entry(report, "C4")
        self.assertEqual(c4["runs"], {"declared": 2, "found": 1})
        self.assertIn("run_not_found", c4["issues"])
        self.assertEqual(c4["coverage_gaps"], [])

    def test_default_expected_cards_and_no_run(self) -> None:
        manifest_path = self.root / "C2" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("expected_tier1")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        _code, report = self._report()
        c2 = self._entry(report, "C2")
        self.assertEqual(c2["expected_tier1"], list(audit_mod.DEFAULT_EXPECTED["C2"]))
        self.assertIsNone(c2["tier1_rows"])
        self.assertEqual(c2["coverage_gaps"], c2["expected_tier1"])

    def test_report_holds_no_identifiers(self) -> None:
        _code, out, _err = _run(["--corpus-root", str(self.root), "--json", "--full"])
        self.assertEqual(audit_mod.identifier_hits(out), {})
        for needle in ("SYNTH-", "synthetic source", "synthetic-test-licence", str(self.base), ".E01"):
            self.assertNotIn(needle, out)

    def test_identifier_hits_patterns(self) -> None:
        cases = {
            "windows_path": "C:\\Users\\x", "long_hex": "a" * 64, "email": "a.b@corp.co.kr",
            "windows_sid": "S-1-5-21-123", "evidence_file": "IMG-B.E01", "posix_home_path": "/home/kim",
        }
        for name, sample in cases.items():
            self.assertIn(name, audit_mod.identifier_hits(f"x {sample} y"), name)
        self.assertEqual(audit_mod.identifier_hits("C1 6건 · 미확보 — 사유 1"), {})
        self.assertEqual(audit_mod.identifier_hits("from Secret Lab", {"Secret Lab"}), {"manifest_literal": 1})

    def test_check_summary_fails_on_identifier(self) -> None:
        clean = self.base / "clean.md"
        clean.write_text("| C1 | 1 | 있음 |\n", encoding="utf-8")
        leaky = self.base / "leaky.md"
        leaky.write_text("C2 원본 synthetic source C2\n", encoding="utf-8")
        code, _out, _err = _run(["--corpus-root", str(self.root), "--check-summary", str(clean)])
        self.assertEqual(code, 0)
        code, _out, err = _run(["--corpus-root", str(self.root), "--check-summary", str(leaky)])
        self.assertEqual(code, 2)
        self.assertIn("manifest_literal", err)
        self.assertNotIn("synthetic source", err)

    def test_output_written_outside_and_refused_inside_corpus(self) -> None:
        before = {p: p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_file()}
        report_path = self.base / "qa" / "corpus-audit.json"
        code, _out, _err = _run(["--corpus-root", str(self.root), "--full", "--output", str(report_path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["schema"], audit_mod.SCHEMA)
        with self.assertRaises(SystemExit) as ctx:
            _run(["--corpus-root", str(self.root), "--output", str(self.root / "C1" / "audit.json")])
        self.assertIn("OUTPUT_INSIDE_EVIDENCE", str(ctx.exception))
        self.assertFalse((self.root / "C1" / "audit.json").exists())
        after = {p: p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_card_mapping(self) -> None:
        self.assertEqual(audit_mod.card_for("email", "email-message"), "email")
        self.assertEqual(audit_mod.card_for("windows-filesystem", "deleted-mft-entry"), "deleted")
        self.assertEqual(audit_mod.card_for("eventlog", "eventlog-logon-session"), "accounts_logon")
        self.assertEqual(audit_mod.card_for("cloud-sync", "cloud-sync-file"), "exfil")
        self.assertEqual(audit_mod.card_for("ai-agent", "ai-agent-message"), "ai_usage")
        self.assertEqual(audit_mod.card_for("recent-files", "lnk-file"), "documents")
        self.assertIsNone(audit_mod.card_for("eventlog", "eventlog-event"))
        self.assertIsNone(audit_mod.card_for("cloud-sync", "cloud-sync-inventory"))
        self.assertIsNone(audit_mod.card_for("kakaotalk-windows", "kakaotalk-windows-source-candidate"))


if __name__ == "__main__":
    unittest.main()
