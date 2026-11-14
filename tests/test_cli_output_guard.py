"""T-033 (IS-068, QA-004): a default single-file ``--output`` never lands in the evidence.

Single-file commands default ``--output`` to a file in the current folder. Run from inside
the evidence folder (or beside an evidence image) without ``--output`` they exit 2 with
``OUTPUT_INSIDE_EVIDENCE`` and leave the evidence byte-identical; run from elsewhere they
keep writing the same default file name as before.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.cli.helpers import (
    DefaultOutput,
    default_output_name,
    guard_default_output,
    resolve_output_path,
)
from rapidtriage.cli.parser import build_parser
from rapidtriage.core.error_codes import ERROR_CODES
from rapidtriage.core.output_guard import (
    OUTPUT_INSIDE_EVIDENCE,
    OutputInsideEvidenceError,
)

# Commands whose positional input names the evidence -> argv that points it at ".".
EVIDENCE_INPUT_ARGV = {
    "docs": ["docs", ".", "-k", "secret"],
    "manifest": ["manifest", "."],
    "artifacts": ["artifacts", ".", "--kind", "browser"],
    "kakaotalk-decrypt": ["kakaotalk-decrypt", "."],
    "kakaotalk-memory-carve": ["kakaotalk-memory-carve", "."],
    "kakaotalk-sqlcipher-probe": ["kakaotalk-sqlcipher-probe", "."],
    "kakaotalk-key-store-inspect": ["kakaotalk-key-store-inspect", "."],
    "kakaotalk-userdir-bruteforce": ["kakaotalk-userdir-bruteforce", "."],
    "files": ["files", "."],
    "collect-plan": ["collect-plan", "."],
    "vsc-compare": ["vsc-compare", ".", "."],
    "vsc-discover": ["vsc-discover", "."],
    "compare": ["compare", "."],
    "timeline": ["timeline"],
    "ocr-queue": ["ocr-queue", "."],
}
# Commands that read a run folder: the evidence is the ``root`` of its run summary.
RUN_INPUT_ARGV = {
    "search": ["search", "{run}", "-k", "secret"],
    "source-read": ["source-read", "{run}", "--path", "x.txt"],
    "source-search": ["source-search", "{run}", "--path", "x.txt", "-k", "secret"],
    "indicators": ["indicators", "{run}"],
    "timeline-export": ["timeline-export", "{run}"],
    "normalize": ["normalize", "{run}"],
}
# Inputs that are neither evidence nor a run folder (an index, a hash feed, nothing).
OTHER_INPUT_ARGV = {
    "docs-index-search": ["docs-index-search", "index.json", "secret"],
    "taxonomy-audit": ["taxonomy-audit"],
    "known-good-index": ["known-good-index", "feed.txt"],
}


def snapshot(root: Path) -> dict[str, str]:
    """Relative path -> SHA-256 (``<dir>`` for folders) of everything under ``root``."""
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        result[rel] = "<dir>" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def subcommands() -> dict[str, argparse.ArgumentParser]:
    parser = build_parser()
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return dict(action.choices)


class _Refused(Exception):
    pass


class _ErrorParser:
    """Stand-in for ``parser.error``: records the message instead of exiting."""

    def __init__(self) -> None:
        self.message = ""

    def error(self, message: str) -> None:
        self.message = message
        raise _Refused(message)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.evidence = self.base / "evidence"
        (self.evidence / "Users" / "kim").mkdir(parents=True)
        (self.evidence / "Users" / "kim" / "note.txt").write_text("secret invoice\n", encoding="utf-8")
        (self.evidence / "report.docx").write_bytes(b"PK\x03\x04 not really a docx")
        self.work = self.base / "work"
        self.work.mkdir()
        self.run_folder = self.base / "run"
        self.run_folder.mkdir()
        (self.run_folder / "rapidtriage-run-summary.json").write_text(
            json.dumps({"root": str(self.evidence)}), encoding="utf-8"
        )
        self.before = snapshot(self.evidence)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)

    def assertEvidenceUntouched(self) -> None:
        self.assertEqual(snapshot(self.evidence), self.before)

    def run_cli(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            try:
                code = main(argv)
            except SystemExit as exc:
                code = int(exc.code or 0)
        return code, stderr.getvalue()

    def argv_for(self, template: list[str]) -> list[str]:
        return [item.replace("{run}", str(self.run_folder)) for item in template]

    def guard(self, argv: list[str]) -> tuple[str | None, str]:
        """Parse ``argv`` and run the guard alone: (refusal message or None, stderr)."""
        args = build_parser().parse_args(argv)
        stand_in = _ErrorParser()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            try:
                guard_default_output(stand_in, args)  # type: ignore[arg-type]
            except _Refused:
                return stand_in.message, stderr.getvalue()
        return None, stderr.getvalue()


class ParserCoverageTests(unittest.TestCase):
    def test_every_cwd_default_output_is_marked(self) -> None:
        """Every ``--output`` with a file-name default is a :class:`DefaultOutput` and is covered here."""
        marked: set[str] = set()
        for name, sub in subcommands().items():
            for action in sub._actions:
                if action.dest != "output" or action.default is None:
                    continue
                with self.subTest(command=name):
                    self.assertIsInstance(action.default, DefaultOutput)
                marked.add(name)
        covered = set(EVIDENCE_INPUT_ARGV) | set(RUN_INPUT_ARGV) | set(OTHER_INPUT_ARGV)
        self.assertEqual(marked | {"artifacts"}, covered)

    def test_marker_keeps_the_old_default_value(self) -> None:
        args = build_parser().parse_args(["files", "x"])
        self.assertEqual(args.output, "rapidtriage-files.json")
        self.assertIsInstance(args.output, DefaultOutput)
        explicit = build_parser().parse_args(["files", "x", "--output", "rapidtriage-files.json"])
        self.assertNotIsInstance(explicit.output, DefaultOutput)
        self.assertIsNone(default_output_name(explicit))

    def test_commands_without_a_cwd_default_file(self) -> None:
        """QA-004 ``evidence`` / ``doctor`` / ``bundle`` write no default file in the current folder."""
        for argv in (
            ["evidence", "case.E01"],
            ["doctor"],
            ["bundle", "case.json", "--allowed-root", "x", "--output-dir", "out"],
        ):
            with self.subTest(command=argv[0]):
                self.assertIsNone(default_output_name(build_parser().parse_args(argv)))

    def test_output_inside_evidence_code_is_registered_with_exit_2(self) -> None:
        self.assertEqual(ERROR_CODES[OUTPUT_INSIDE_EVIDENCE].exit_code, 2)


class RefusalTests(Base):
    def test_qa004_commands_refuse_inside_the_evidence_folder(self) -> None:
        """QA-004: run from the evidence folder without --output -> exit 2, evidence byte-identical."""
        os.chdir(self.evidence)
        commands = [
            EVIDENCE_INPUT_ARGV["docs"],
            EVIDENCE_INPUT_ARGV["files"],
            EVIDENCE_INPUT_ARGV["artifacts"],
            EVIDENCE_INPUT_ARGV["timeline"],
            EVIDENCE_INPUT_ARGV["manifest"],
            EVIDENCE_INPUT_ARGV["compare"],
            RUN_INPUT_ARGV["search"],
            RUN_INPUT_ARGV["indicators"],
            RUN_INPUT_ARGV["normalize"],
        ]
        for template in commands:
            argv = self.argv_for(template)
            with self.subTest(command=argv[0]):
                code, err = self.run_cli(argv)
                self.assertEqual(code, 2, err)
                self.assertIn(OUTPUT_INSIDE_EVIDENCE, err)
                self.assertIn("증거", err)
                self.assertIn("--output", err)
                self.assertEvidenceUntouched()

    def test_every_marked_command_refuses_from_a_subfolder_of_the_evidence(self) -> None:
        os.chdir(self.evidence / "Users" / "kim")
        for template in {**EVIDENCE_INPUT_ARGV, **RUN_INPUT_ARGV}.values():
            argv = [str(self.evidence) if item == "." else item for item in self.argv_for(template)]
            if argv == ["timeline"]:
                argv = ["timeline", str(self.evidence)]
            with self.subTest(command=argv[0]):
                message, _ = self.guard(argv)
                self.assertIsNotNone(message)
                self.assertIn(OUTPUT_INSIDE_EVIDENCE, message or "")
        self.assertEvidenceUntouched()

    def test_beside_an_evidence_image_is_refused(self) -> None:
        image = self.evidence / "case.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
        self.before = snapshot(self.evidence)
        os.chdir(self.evidence)
        message, _ = self.guard(["files", "case.E01"])
        self.assertIn(OUTPUT_INSIDE_EVIDENCE, message or "")
        code, err = self.run_cli(["files", "case.E01"])
        self.assertEqual(code, 2, err)
        self.assertEvidenceUntouched()

    def test_resolve_output_path_raises_with_the_stable_code(self) -> None:
        os.chdir(self.evidence)
        args = build_parser().parse_args(["manifest", "."])
        with self.assertRaises(OutputInsideEvidenceError) as caught:
            resolve_output_path(args, self.evidence)
        self.assertEqual(caught.exception.code, OUTPUT_INSIDE_EVIDENCE)


class CompatibilityTests(Base):
    def test_defaults_outside_the_evidence_still_work(self) -> None:
        os.chdir(self.work)
        for argv, name in (
            (["manifest", str(self.evidence)], "rapidtriage-manifest.json"),
            (["files", str(self.evidence)], "rapidtriage-files.json"),
        ):
            with self.subTest(command=argv[0]):
                code, err = self.run_cli(argv)
                self.assertEqual(code, 0, err)
                self.assertTrue((self.work / name).is_file())
        self.assertEqual(
            resolve_output_path(build_parser().parse_args(["docs", str(self.evidence), "-k", "x"]), self.evidence),
            self.work / "rapidtriage-docs.json",
        )
        self.assertEvidenceUntouched()

    def test_every_marked_command_passes_the_guard_outside_the_evidence(self) -> None:
        os.chdir(self.work)
        for template in {**EVIDENCE_INPUT_ARGV, **RUN_INPUT_ARGV, **OTHER_INPUT_ARGV}.values():
            argv = [str(self.evidence) if item == "." else item for item in self.argv_for(template)]
            with self.subTest(command=argv[0]):
                message, err = self.guard(argv if argv != ["timeline"] else ["timeline", str(self.evidence)])
                self.assertIsNone(message)
                self.assertEqual(err, "")

    def test_explicit_output_outside_the_evidence_works_from_inside_it(self) -> None:
        os.chdir(self.evidence)
        output = self.work / "manifest.json"
        code, err = self.run_cli(["manifest", ".", "--output", str(output)])
        self.assertEqual(code, 0, err)
        self.assertTrue(output.is_file())
        self.assertEvidenceUntouched()

    def test_run_folder_commands_keep_writing_into_the_run_folder(self) -> None:
        """indicators / search read a run folder; running them there is legitimate."""
        os.chdir(self.run_folder)
        for template in RUN_INPUT_ARGV.values():
            argv = self.argv_for(template)
            with self.subTest(command=argv[0]):
                message, err = self.guard(argv)
                self.assertIsNone(message)
                self.assertEqual(err, "")

    def test_no_evidence_input_only_warns_when_the_folder_holds_evidence_files(self) -> None:
        (self.evidence / "disk.E01").write_bytes(b"EVF")
        self.before = snapshot(self.evidence)
        os.chdir(self.evidence)
        for template in OTHER_INPUT_ARGV.values():
            with self.subTest(command=template[0]):
                message, err = self.guard(template)
                self.assertIsNone(message)
                self.assertIn("warning", err)
                self.assertIn("--output", err)
        os.chdir(self.work)
        self.assertEqual(self.guard(OTHER_INPUT_ARGV["taxonomy-audit"]), (None, ""))


class VendorSuggestionTests(unittest.TestCase):
    def test_suggested_validation_outputs_are_beside_the_export_folder(self) -> None:
        from rapidtriage.artifacts.mobile.vendor import (
            build_mobile_vendor_export_report_grade_validation_plan,
        )

        with tempfile.TemporaryDirectory() as tmp:
            export_dir = Path(tmp) / "cellebrite-export"
            export_dir.mkdir()
            export = export_dir / "messages.csv"
            export.write_text("a,b\n", encoding="utf-8")
            plan = build_mobile_vendor_export_report_grade_validation_plan(
                path=export,
                source_format="csv",
                source_tool="cellebrite",
                source_hashes={},
                rows=[],
                detected_type_counts={},
                source_profile={},
                vendor_manifest_profile={},
                mapper_manifest={},
            )
        text = json.dumps(plan, ensure_ascii=False)
        output_root = Path(plan["output_root"])
        self.assertEqual(output_root.parent, export_dir.parent)
        self.assertNotIn(str(export_dir / "messages-rapidtriage-validation"), text)


if __name__ == "__main__":
    unittest.main()
