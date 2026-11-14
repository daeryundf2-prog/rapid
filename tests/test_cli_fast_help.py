"""``rapidtriage --help`` must not load the forensic engine (T-161b)."""

from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path

from rapidtriage.cli.parsers.lazy_choices import LazyChoices, set_lazy_choices
from rapidtriage.core import cli_constants

REPO_ROOT = Path(__file__).resolve().parents[1]
HEAVY_MODULES = ("cv2", "numpy", "rapidtriage.artifacts")


def _imported_modules(*args: str) -> set[str]:
    proc = subprocess.run(
        [sys.executable, "-X", "importtime", "-m", "rapidtriage", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    names = set()
    for line in proc.stderr.splitlines():
        if line.startswith("import time:") and line.count("|") == 2:
            names.add(line.rsplit("|", 1)[1].strip())
    return names


class FastHelpTests(unittest.TestCase):
    def test_help_does_not_import_engine(self) -> None:
        modules = _imported_modules("--help")
        self.assertIn("rapidtriage.cli.parser", modules)
        heavy = sorted(
            name for name in modules if any(name == root or name.startswith(root + ".") for root in HEAVY_MODULES)
        )
        self.assertEqual(heavy, [])

    def test_cli_constants_imports_nothing_from_the_project(self) -> None:
        source = Path(cli_constants.__file__).read_text(encoding="utf-8")
        import_lines = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
        self.assertEqual(import_lines, ["from __future__ import annotations", "from pathlib import Path"])

    def test_engine_modules_re_export_moved_constants(self) -> None:
        from rapidtriage.artifacts import kakaotalk_macos
        from rapidtriage.core import (
            benchmark,
            benchmark_fts,
            browser_stress,
            carving,
            case,
            case_catalog,
            cloud_api,
            collect_plan,
            commercial_readiness,
            extract,
            forensic_validation_plan,
            input_root,
            kakaotalk,
            large_case_readiness,
            macos_live_smoke,
            run,
            sample_case,
            validation_diff_runners,
        )

        owners = {
            extract: ("SUPPORTED_DOC_KINDS", "DEFAULT_EXTRACT_MANIFEST_NAME"),
            run: ("SUPPORTED_RUN_MODES", "SUPPORTED_DOC_KINDS"),
            input_root: ("SUPPORTED_INPUT_ROOT_KINDS",),
            case: ("REVIEW_STATUSES",),
            sample_case: ("DEFAULT_SAMPLE_DIR", "DEFAULT_SAMPLE_MODE"),
            cloud_api: (
                "DEFAULT_CLOUD_BEARER_TOKEN_ENV",
                "DEFAULT_CLOUD_API_TIMEOUT_SECONDS",
                "DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES",
            ),
            collect_plan: ("DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT", "DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES"),
            carving: ("DEFAULT_MAX_SCAN_BYTES", "DEFAULT_MAX_CARVE_BYTES", "DEFAULT_MAX_CANDIDATES"),
            kakaotalk: (
                "DEFAULT_MEMORY_SQLITE_MAX_HITS",
                "DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES",
                "DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT",
                "DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT",
            ),
            kakaotalk_macos: ("DEFAULT_MACOS_REPORT_MAX_MESSAGES", "DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS"),
            benchmark: ("DEFAULT_BENCHMARK_FILE_COUNT", "DEFAULT_BENCHMARK_KEYWORD"),
            benchmark_fts: (
                "SQLITE_FTS_DEFAULT_RECORD_COUNT",
                "SQLITE_FTS_DEFAULT_QUERY_ITERATIONS",
                "SQLITE_FTS_DEFAULT_HIT_EVERY",
            ),
            browser_stress: ("DEFAULT_BROWSER_STRESS_RECORD_COUNT",),
            commercial_readiness: ("MATURITY_GATE_ORDER",),
            forensic_validation_plan: ("DEFAULT_FORENSIC_VALIDATION_ITEMS", "DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS"),
            large_case_readiness: ("DEFAULT_LARGE_CASE_P95_THRESHOLD_MS",),
            macos_live_smoke: ("DEFAULT_MACOS_SMOKE_BENCHMARK_FILES", "DEFAULT_MACOS_SMOKE_FTS_RECORDS"),
            validation_diff_runners: ("VERSION_PROBE_TIMEOUT_SECONDS",),
            case_catalog: ("default_case_catalog_path",),
        }
        for module, names in owners.items():
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertIs(getattr(module, name), getattr(cli_constants, name))

    def test_lazy_choices_match_engine_registries(self) -> None:
        from rapidtriage.cli.parser import build_parser
        from rapidtriage.core.artifacts import SUPPORTED_ARTIFACT_KINDS
        from rapidtriage.core.collect_plan import supported_collect_profiles
        from rapidtriage.core.files import ALL_FILE_CATEGORIES

        parser = build_parser()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))

        def choices(command: str, dest: str) -> list[str]:
            action = next(a for a in sub.choices[command]._actions if a.dest == dest)
            self.assertIsInstance(action.choices, LazyChoices)
            return list(action.choices)

        self.assertEqual(choices("artifacts", "kind"), sorted(SUPPORTED_ARTIFACT_KINDS))
        self.assertEqual(choices("files", "category"), sorted(ALL_FILE_CATEGORIES))
        self.assertEqual(choices("extract", "category"), sorted(ALL_FILE_CATEGORIES))
        self.assertEqual(choices("collect-plan", "profile"), sorted(supported_collect_profiles()))
        self.assertEqual(choices("collect-export", "profile"), sorted(supported_collect_profiles()))

    def test_lazy_choices_validate_like_static_choices(self) -> None:
        parser = argparse.ArgumentParser(prog="demo")
        calls: list[int] = []

        def loader() -> list[str]:
            calls.append(1)
            return ["alpha", "beta"]

        set_lazy_choices(parser.add_argument("--kind"), loader)
        self.assertEqual(calls, [])
        self.assertEqual(parser.parse_args(["--kind", "beta"]).kind, "beta")
        self.assertIn("{alpha,beta}", parser.format_help())
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            parser.parse_args(["--kind", "gamma"])
        self.assertIn("invalid choice: 'gamma'", stderr.getvalue())
        self.assertEqual(calls, [1])


if __name__ == "__main__":
    unittest.main()
