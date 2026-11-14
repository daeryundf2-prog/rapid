"""Tests for scripts/check-glossary-terms.py (R8 T-005 terminology lint)."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-glossary-terms.py"

_spec = importlib.util.spec_from_file_location("check_glossary_terms", SCRIPT)
lint = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lint  # dataclasses resolve annotations via sys.modules
_spec.loader.exec_module(lint)


def _terms(hits):
    return sorted(hit.term for hit in hits)


class EightTermsTest(unittest.TestCase):
    def test_exactly_eight_forbidden_terms(self):
        self.assertEqual(len(lint.TERMS), 8)
        self.assertEqual(set(lint.TERMS), set(lint.BASELINE))

    def test_each_term_matches(self):
        src = "\n".join(
            [
                'const a = "이 런은 끝났습니다";',
                'const b = "IOC/위험";',
                'const c = { reviewer: "web-ui" };',
                "const d = <dt>검사관</dt>;",
                'const e = "리뷰보드";',
                'const f = "리뷰 보드";',
                "const g = `소요 알 수 없음초`;",
                'const h = "Failed to fetch";',
                'const i = "Request failed";',
            ]
        )
        hits = lint.scan_text("x.tsx", src)
        self.assertEqual(
            _terms(hits),
            sorted(
                [
                    "run-ko",
                    "ioc",
                    "web-ui",
                    "examiner-ko",
                    "review-board",
                    "review-board",
                    "unknown-seconds",
                    "failed-to-fetch",
                    "request-failed",
                ]
            ),
        )
        self.assertEqual([h.line for h in hits if h.term == "web-ui"], [3])

    def test_allowed_forms_do_not_match(self):
        src = "\n".join(
            [
                'const a = "프런트 · 브런치 · 런타임 · 런던";',
                'const b = "지표(IOC)";',
                "const iocCount = IOC_TYPES.length;",
                'const c = "분석 담당 · 검토 목록 · 처리 2차";',
            ]
        )
        self.assertEqual(lint.scan_text("x.ts", src), [])


class CommentStrippingTest(unittest.TestCase):
    def test_comments_are_ignored(self):
        src = "\n".join(
            [
                "// 검사관 in a line comment",
                "/* 리뷰보드",
                "   IOC */ const x = 1;",
                'const url = "http://host/검사관"; // trailing 런',
            ]
        )
        hits = lint.scan_text("x.ts", src)
        self.assertEqual([(h.term, h.line) for h in hits], [("examiner-ko", 4)])

    def test_template_literal_with_nested_code(self):
        src = "const s = `${ok ? `런 ${n}` : \"\"} // not a comment 검사관`;\n// 리뷰보드"
        hits = lint.scan_text("x.tsx", src)
        self.assertEqual(_terms(hits), ["examiner-ko", "run-ko"])

    def test_line_numbers_survive_block_comments(self):
        src = "/*\n\n*/\nconst a = 'IOC';"
        self.assertEqual([h.line for h in lint.scan_text("x.ts", src)], [4])


class ScanAndRatchetTest(unittest.TestCase):
    def _tree(self, files: dict[str, str]) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def test_scan_skips_tests_and_alias_contract(self):
        root = self._tree(
            {
                "frontend/src/a.tsx": 'const a = "검사관";\n',
                "frontend/src/a.test.tsx": 'const a = "검사관";\n',
                "frontend/src/b.spec.ts": 'const a = "검사관";\n',
                "frontend/src/testSetup.ts": 'const a = "검사관";\n',
                "frontend/src/contracts/uiContract.ts": 'const a = "검사관";\n',
                "frontend/src/notes.md": "검사관\n",
            }
        )
        hits = lint.scan(root)
        self.assertEqual([(h.path, h.line) for h in hits], [("frontend/src/a.tsx", 1)])

    def test_ratchet(self):
        hits = [lint.Hit("ioc", "f.ts", 1, "IOC"), lint.Hit("ioc", "f.ts", 2, "IOC")]
        base = {term: 0 for term in lint.TERMS}
        base["ioc"] = 2
        self.assertTrue(lint.summarize(hits, base, strict=False)["ok"])
        self.assertFalse(lint.summarize(hits, base, strict=True)["ok"])
        base["ioc"] = 1
        report = lint.summarize(hits, base, strict=False)
        self.assertFalse(report["ok"])
        self.assertEqual(next(r for r in report["terms"] if r["term"] == "ioc")["status"], "fail")
        base["ioc"] = 3
        report = lint.summarize(hits, base, strict=False)
        self.assertEqual(next(r for r in report["terms"] if r["term"] == "ioc")["status"], "below-baseline")

    def test_main_exit_codes(self):
        root = self._tree({"frontend/src/a.ts": 'const a = "알 수 없음초";\n'})
        clean = self._tree({"frontend/src/a.ts": 'const a = "처리 1차";\n'})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lint.main(["--root", str(root), "--quiet"]), 1)
            self.assertEqual(lint.main(["--root", str(clean), "--quiet"]), 0)

    def test_current_tree_within_baseline(self):
        report = lint.summarize(lint.scan(REPO_ROOT), lint.BASELINE, strict=False)
        over = [r for r in report["terms"] if r["status"] == "fail"]
        self.assertEqual(over, [], "new forbidden terms in frontend/src")


if __name__ == "__main__":
    unittest.main()
