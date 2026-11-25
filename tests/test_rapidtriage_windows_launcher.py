from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "scripts" / "windows" / "start-rapidtriage.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

# Dot-sources one helper function of a launcher script and reports what it
# returns for children that print a line and exit with 0 or 3.
FUNCTION_HARNESS = r"""
param([string]$Launcher, [string]$FunctionName, [string]$Interpreter)
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Launcher, [ref]$tokens, [ref]$parseErrors)
$definition = $tree.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $FunctionName
}, $true)
. ([scriptblock]::Create($definition.Extent.Text))
$VenvPython = $Interpreter
$results = @()
foreach ($exitCode in @(0, 3)) {
    $returned = Invoke-VenvPython @("-c", "import sys; print('child output line'); sys.exit($exitCode)")
    $results += [pscustomobject]@{ expected = $exitCode; returned = $returned; is_int = ($returned -is [int]) }
}
Write-Output ("RESULT " + (ConvertTo-Json -Compress -InputObject $results))
"""

# Dot-sources Find-SystemPython and prints the interpreter it picks.
FIND_PYTHON_HARNESS = r"""
param([string]$Launcher)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$tokens = $null
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Launcher, [ref]$tokens, [ref]$parseErrors)
$definition = $tree.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Find-SystemPython"
}, $true)
. ([scriptblock]::Create($definition.Extent.Text))
$found = Find-SystemPython
Write-Output ("RESULT " + (ConvertTo-Json -Compress -InputObject @{ exe = $found.Exe; args = @($found.Args) }))
"""

FAKE_VENV_PYTHON = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_CALL_LOG"
echo "child output: completed"
case "$*" in
  *doctor*) exit "${FAKE_DOCTOR_EXIT:-0}" ;;
esac
exit 0
"""


def run_powershell(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1", **(env or {})},
    )


@unittest.skipIf(POWERSHELL is None, "PowerShell (pwsh/powershell) is not installed")
class RapidTriageWindowsLauncherExitCodeTests(unittest.TestCase):
    """D12: a child that writes to stdout must not turn the exit code into an array."""

    def test_venv_helper_returns_only_the_child_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = Path(tmp) / "harness.ps1"
            harness.write_text(FUNCTION_HARNESS, encoding="utf-8")
            result = run_powershell(str(harness), str(LAUNCHER), "Invoke-VenvPython", sys.executable)
        self.assertEqual(result.returncode, 0, result.stderr)
        line = next(line for line in result.stdout.splitlines() if line.startswith("RESULT "))
        outcomes = json.loads(line.removeprefix("RESULT "))
        self.assertEqual([(item["expected"], item["returned"], item["is_int"]) for item in outcomes], [(0, 0, True), (3, 3, True)])
        self.assertIn("child output line", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Store alias and per-user python.org layout are Windows-only")
    def test_system_python_skips_store_alias_and_finds_per_user_install(self) -> None:
        for scripts_name in ("start-rapidtriage.ps1", "smoke-test-rapidtriage.ps1"):
            with self.subTest(script=scripts_name), tempfile.TemporaryDirectory() as tmp:
                # Long form: the runner TEMP can be an 8.3 short path, Get-ChildItem reports the long one.
                local = Path(tmp).resolve() / "AppData Local 한글"
                alias = local / "Microsoft" / "WindowsApps" / "python.exe"
                installed = local / "Programs" / "Python" / "Python312" / "python.exe"
                older = local / "Programs" / "Python" / "Python39" / "python.exe"
                # "Python311-32" has more digits than "Python312"; the minor version decides.
                x86 = local / "Programs" / "Python" / "Python311-32" / "python.exe"
                for path in (alias, installed, older, x86):
                    path.parent.mkdir(parents=True)
                    path.write_bytes(b"")
                harness = Path(tmp) / "harness.ps1"
                harness.write_text(FIND_PYTHON_HARNESS, encoding="utf-8")
                env = {"LOCALAPPDATA": str(local), "PATH": str(alias.parent) + os.pathsep + os.environ.get("SystemRoot", r"C:\Windows") + r"\System32"}

                result = run_powershell(str(harness), str(REPO_ROOT / "scripts" / "windows" / scripts_name), env=env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                found = json.loads(next(line for line in result.stdout.splitlines() if line.startswith("RESULT ")).removeprefix("RESULT "))
                self.assertEqual((found["exe"], found["args"]), (str(installed), []))

                launcher = local / "Programs" / "Python" / "Launcher" / "py.exe"
                launcher.parent.mkdir(parents=True)
                launcher.write_bytes(b"")
                result = run_powershell(str(harness), str(REPO_ROOT / "scripts" / "windows" / scripts_name), env=env)
                found = json.loads(next(line for line in result.stdout.splitlines() if line.startswith("RESULT ")).removeprefix("RESULT "))
                self.assertEqual((found["exe"], found["args"]), (str(launcher), ["-3"]))

    @unittest.skipIf(os.name == "nt", "the stand-in .venv python is a POSIX shell script")
    def test_launcher_runs_every_install_step_and_propagates_doctor_failure(self) -> None:
        for doctor_exit in (0, 7):
            with self.subTest(doctor_exit=doctor_exit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "install dir 한글"
                script = root / "scripts" / "windows" / "start-rapidtriage.ps1"
                script.parent.mkdir(parents=True)
                shutil.copyfile(LAUNCHER, script)
                fake_python = root / ".venv" / "Scripts" / "python.exe"
                fake_python.parent.mkdir(parents=True)
                fake_python.write_text(FAKE_VENV_PYTHON, encoding="utf-8")
                fake_python.chmod(0o755)
                call_log = Path(tmp) / "calls.txt"

                result = run_powershell(
                    str(script),
                    "-DoctorOnly",
                    env={"FAKE_CALL_LOG": str(call_log), "FAKE_DOCTOR_EXIT": str(doctor_exit)},
                )

                self.assertEqual(result.returncode, doctor_exit, result.stdout + result.stderr)
                self.assertEqual(
                    call_log.read_text(encoding="utf-8").splitlines(),
                    [
                        "-m pip install -U pip",
                        "-m pip install -e .[web]",
                        "-m rapidtriage doctor --host 127.0.0.1 --port 8765",
                    ],
                )


class RapidTriageWindowsLauncherTests(unittest.TestCase):
    def test_windows_launchers_exist_and_call_doctor_before_web(self) -> None:
        ps1 = REPO_ROOT / "scripts" / "windows" / "start-rapidtriage.ps1"
        bat = REPO_ROOT / "scripts" / "windows" / "start-rapidtriage.bat"

        self.assertTrue(ps1.is_file())
        self.assertTrue(bat.is_file())

        ps1_text = ps1.read_text(encoding="utf-8")
        bat_text = bat.read_text(encoding="utf-8")

        self.assertIn("Python virtual environment", ps1_text)
        self.assertIn("rapidtriage\", \"doctor", ps1_text)
        self.assertIn("rapidtriage\", \"web", ps1_text)
        self.assertLess(ps1_text.index("rapidtriage\", \"doctor"), ps1_text.index("rapidtriage\", \"web"))
        self.assertIn("ExecutionPolicy Bypass", bat_text)
        self.assertIn("start-rapidtriage.ps1", bat_text)

    def test_windows_quickstart_documents_launcher_and_fallbacks(self) -> None:
        doc = REPO_ROOT / "docs" / "rapidtriage-windows-quickstart.md"
        readme = REPO_ROOT / "README.md"

        self.assertTrue(doc.is_file())
        doc_text = doc.read_text(encoding="utf-8")
        readme_text = readme.read_text(encoding="utf-8")

        self.assertIn(".\\scripts\\windows\\start-rapidtriage.ps1", doc_text)
        self.assertIn("rapidtriage doctor", doc_text)
        self.assertIn("mounted/extracted folder", doc_text)
        self.assertIn("docs/rapidtriage-windows-quickstart.md", readme_text)
