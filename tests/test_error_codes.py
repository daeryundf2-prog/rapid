"""T-162: one error code table for server and CLI, and the generated document stays in sync."""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from rapidtriage.core import error_codes
from rapidtriage.core.error_codes import CATEGORIES, ERROR_CODES, STATUS_DEFAULT_CODES

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "rapidtriage"
DOC = REPO / "docs" / "api-error-codes.md"
REGISTRY = PACKAGE / "core" / "error_codes.py"

CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
SELF_NAMED_RE = re.compile(rb"^\s*([A-Z][A-Z0-9_]+) = \"\1\"", re.MULTILINE)
#: Cheap pre-filter: a file can only use a code via a "code" key, ``code=`` or ``code: str =``.
CODE_HINT_RE = re.compile(rb"[\"']code[\"']|(?<![A-Za-z0-9_])code\s*[=:]")
HANGUL_RE = re.compile(r"[가-힣]")

#: Every code ever registered. Codes are append-only (r8-contracts D.8): add new codes here,
#: never remove one.
SHIPPED = frozenset({
    "OUTPUT_INSIDE_EVIDENCE", "EVIDENCE_INSIDE_OUTPUT", "OUTPUT_DIR_REQUIRED", "OUTPUT_DIR_BUSY",
    "PATH_OUTSIDE_ALLOWED_ROOT", "CREDENTIAL_FILE_WITHHELD", "SERVER_READ_ONLY",
    "SAMPLE_DIR_NOT_EMPTY", "SAMPLE_DIR_NOT_SAMPLE", "SAMPLE_DIR_HAS_OTHER_FILES", "SAMPLE_CASE_FAILED",
    "IMPORT_SUMMARY_INVALID", "IMPORT_OUTPUT_OUTSIDE_FOLDER", "IMPORT_SOURCE_ROOT_UNVERIFIED",
    "RUN_READ_ONLY", "RUN_NOT_FOUND", "RUN_NOT_FINISHED",
    "EXPORT_NOT_WRITTEN",
    "CASE_DB_UNREADABLE", "CASE_JSON_UNREADABLE", "CASE_NOT_FOUND", "REVIEW_CONFLICT",
    "SCAN_BUDGET_STOPPED", "TOTAL_NOT_COUNTED",
    "BAD_REQUEST", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "CONFLICT", "UNSUPPORTED_MEDIA",
    "VALIDATION_FAILED", "INTERNAL_ERROR", "USAGE_ERROR",
    "NETWORK_UNREACHABLE", "REQUEST_TIMEOUT", "REQUEST_ABORTED",
    # T-007: status defaults for the other statuses the server answers with
    "METHOD_NOT_ALLOWED", "TIME_BUDGET_EXCEEDED", "PAYLOAD_TOO_LARGE", "RANGE_NOT_SATISFIABLE",
    "TOO_MANY_REQUESTS", "SERVICE_UNAVAILABLE",
    # T-131 review: a case-DB write refused by another window's lock
    "CASE_DB_LOCKED",
})


def _str_value(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and CODE_RE.match(node.value):
        return node.value
    return None


def scan_code_literals(root: Path = PACKAGE) -> dict[str, list[str]]:
    """Return ``{code: [file:line, ...]}`` for every error-code literal used under ``root``.

    A literal counts as a code when it is (a) a self-named module constant
    (``RUN_READ_ONLY = "RUN_READ_ONLY"``), (b) the value of a ``"code"`` key in a dict literal,
    (c) a ``code=`` keyword argument, or (d) the default of a parameter named ``code``.
    """
    found: dict[str, list[str]] = {}

    def add(code: str | None, path: Path, node: ast.AST) -> None:
        if code:
            found.setdefault(code, []).append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}")

    for path in sorted(root.rglob("*.py")):
        if path == REGISTRY:
            continue
        source = path.read_bytes()
        if not CODE_HINT_RE.search(source) and not SELF_NAMED_RE.search(source):
            continue
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                value = _str_value(node.value)
                if isinstance(target, ast.Name) and value == target.id:
                    add(value, path, node)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == "code":
                        add(_str_value(value), path, value)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "code":
                        add(_str_value(keyword.value), path, keyword.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                positional = args.posonlyargs + args.args
                pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
                pairs += [(arg, default) for arg, default in zip(args.kwonlyargs, args.kw_defaults) if default]
                for arg, default in pairs:
                    if arg.arg == "code":
                        add(_str_value(default), path, default)
    return found


class ErrorCodeTableTests(unittest.TestCase):
    def test_table_size_and_shape(self) -> None:
        self.assertGreaterEqual(len(ERROR_CODES), 30)
        self.assertEqual(len(ERROR_CODES), len(error_codes._ROWS), "duplicate code in the table")
        for code, row in ERROR_CODES.items():
            with self.subTest(code=code):
                self.assertRegex(code, CODE_RE)
                self.assertIn(row.category, CATEGORIES)
                self.assertIn(row.state, ("active", "reserved"))
                self.assertIn(row.surface, ("http", "body", "notice", "readonly_reason", "cli", "frontend"))
                self.assertRegex(row.message_ko, HANGUL_RE)
                self.assertRegex(row.hint_ko, HANGUL_RE)
                self.assertTrue(row.short_en.strip())
                self.assertNotRegex(row.short_en, HANGUL_RE)
                self.assertIn(row.exit_code, (None, 1, 2, 3, 4))
                if row.surface == "http":
                    self.assertIsNotNone(row.http_status)
                if row.http_status is not None:
                    self.assertTrue(400 <= row.http_status <= 599, row.http_status)
                if row.state == "reserved":
                    self.assertTrue(row.owner, "a reserved code names the task that wires it")

    def test_codes_are_append_only(self) -> None:
        missing = sorted(SHIPPED - set(ERROR_CODES))
        self.assertEqual(missing, [], "a shipped code was removed or renamed")
        unlisted = sorted(set(ERROR_CODES) - SHIPPED)
        self.assertEqual(unlisted, [], "add the new code to SHIPPED in this test")

    def test_status_defaults_are_registered(self) -> None:
        for status, code in STATUS_DEFAULT_CODES.items():
            with self.subTest(status=status):
                self.assertEqual(ERROR_CODES[code].http_status, status)
                self.assertEqual(error_codes.default_code_for_status(status), code)
        self.assertEqual(error_codes.default_code_for_status(418), "BAD_REQUEST")
        self.assertEqual(error_codes.default_code_for_status(503), "INTERNAL_ERROR")
        self.assertIs(error_codes.get("RUN_READ_ONLY"), ERROR_CODES["RUN_READ_ONLY"])
        with self.assertRaises(KeyError):
            error_codes.get("NO_SUCH_CODE")


class ErrorCodeUsageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.used = scan_code_literals()

    def test_every_used_code_is_registered(self) -> None:
        unregistered = {code: sites for code, sites in self.used.items() if code not in ERROR_CODES}
        self.assertEqual(unregistered, {}, "register these codes in rapidtriage/core/error_codes.py")

    def test_every_active_code_is_used(self) -> None:
        unused = sorted(code for code, row in ERROR_CODES.items() if row.state == "active" and code not in self.used)
        self.assertEqual(unused, [], "active codes not emitted anywhere: mark them reserved (with owner)")

    def test_scanner_sees_known_sites(self) -> None:
        # Guards the scanner itself: one site per detection rule.
        self.assertIn("RUN_READ_ONLY", self.used)  # self-named constant
        self.assertTrue(any("routes_runs.py" in site for site in self.used["EXPORT_NOT_WRITTEN"]))  # "code" key
        self.assertIn("SAMPLE_CASE_FAILED", self.used)  # parameter default


class ErrorCodeDocTests(unittest.TestCase):
    def test_document_is_generated_from_table(self) -> None:
        self.assertTrue(DOC.is_file(), "run: python -m rapidtriage.core.error_codes --write docs/api-error-codes.md")
        current = DOC.read_bytes()
        self.assertNotIn(b"\r\n", current)
        self.assertEqual(
            current.decode("utf-8"),
            error_codes.render_markdown(),
            "docs/api-error-codes.md is stale: python -m rapidtriage.core.error_codes --write docs/api-error-codes.md",
        )

    def test_document_lists_every_code(self) -> None:
        text = error_codes.render_markdown()
        for code in ERROR_CODES:
            self.assertIn(f"| `{code}` |", text)

    def test_cli_check_mode(self) -> None:
        self.assertEqual(error_codes.main(["--check", str(DOC)]), 0)


if __name__ == "__main__":
    unittest.main()
