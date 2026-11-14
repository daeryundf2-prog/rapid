"""Structure ratchet: layer boundaries and file sizes (T-155).

Two guards, both compared against ``tests/fixtures/architecture-baseline.json``:

1. Layers. ``rapidtriage.core`` must not import ``rapidtriage.api``. The
   existing imports are allow-listed one entry per import statement
   (``<file>::<module>``). Any import outside the list fails, and the list
   itself may never exceed ``MAX_CORE_API_ALLOWLIST`` entries.
2. File sizes. New Python files are capped at 800 lines and new ``.tsx``
   files at 400 lines. Files already over the cap are listed in the baseline
   with their recorded line count and fail once they grow more than 5% past
   it. Files that shrink pass and print a hint to lower the baseline.

Lower the baseline after a shrink with::

    python tests/test_architecture.py --lower-baseline

That command only lowers counts and drops entries; it never adds a file or
raises a count.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "tests" / "fixtures" / "architecture-baseline.json"

CORE_DIR = REPO_ROOT / "rapidtriage" / "core"
CORE_PACKAGE = "rapidtriage.core"
API_PACKAGE = "rapidtriage.api"
MAX_CORE_API_ALLOWLIST = 4

PYTHON_ROOTS = ("rapidtriage", "scripts", "tests")
TSX_ROOTS = ("frontend/src",)
PYTHON_CAP = 800
TSX_CAP = 400
GROWTH_TOLERANCE = 0.05
SKIP_DIRS = {"__pycache__", "node_modules", "dist", "build", ".git"}
_API_TOKEN = re.compile(rb"\bapi\b")


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _iter_files(roots: tuple[str, ...], suffix: str):
    for root in roots:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(suffix):
                    yield Path(dirpath) / name


def _line_count(path: Path) -> int:
    return len(path.read_bytes().splitlines())


def measure_sizes() -> dict[str, dict[str, int]]:
    """Return ``{"python": {file: lines}, "tsx": {file: lines}}`` over the caps."""
    out: dict[str, dict[str, int]] = {"python": {}, "tsx": {}}
    for kind, roots, suffix, cap in (
        ("python", PYTHON_ROOTS, ".py", PYTHON_CAP),
        ("tsx", TSX_ROOTS, ".tsx", TSX_CAP),
    ):
        for path in _iter_files(roots, suffix):
            lines = _line_count(path)
            if lines > cap:
                out[kind][_rel(path)] = lines
    return out


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(REPO_ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(node: ast.ImportFrom, path: Path) -> str:
    if node.level == 0:
        return node.module or ""
    package = _module_name(path)
    if path.name != "__init__.py":
        package = package.rpartition(".")[0]
    base = package.split(".")
    if node.level > 1:
        base = base[: len(base) - (node.level - 1)]
    return ".".join([*base, node.module] if node.module else base)


def _is_api(module: str) -> bool:
    return module == API_PACKAGE or module.startswith(API_PACKAGE + ".")


def measure_core_api_imports() -> Counter[str]:
    """Return a multiset of ``<file>::<module>`` for every core -> api import."""
    found: Counter[str] = Counter()
    for path in _iter_files(("rapidtriage/core",), ".py"):
        source = path.read_bytes()
        # Every api import names the token ``api``; skip the parse otherwise
        # (keeps the whole run well under the 3 s budget).
        if not _API_TOKEN.search(source):
            continue
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = _resolve(node, path)
                if _is_api(module):
                    targets = [module]
                else:
                    targets = [f"{module}.{alias.name}" for alias in node.names]
            hits = sorted({t for t in targets if _is_api(t)})
            if hits:
                found[f"{_rel(path)}::{hits[0]}"] += 1
    return found


def load_baseline() -> dict:
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _limit(recorded: int) -> int:
    return int(recorded * (1 + GROWTH_TOLERANCE))


def check_sizes(baseline: dict, current: dict[str, dict[str, int]]):
    """Return ``(failures, hints)`` for the file-size ratchet."""
    failures: list[str] = []
    hints: list[str] = []
    caps = {"python": PYTHON_CAP, "tsx": TSX_CAP}
    for kind, cap in caps.items():
        recorded: dict[str, int] = baseline["file_lines"][kind]
        for name, lines in sorted(current[kind].items()):
            if name not in recorded:
                failures.append(f"new {kind} file over {cap} lines: {name} ({lines})")
            elif lines > _limit(recorded[name]):
                failures.append(
                    f"{name} grew to {lines} lines; baseline {recorded[name]}, "
                    f"limit {_limit(recorded[name])} (+{GROWTH_TOLERANCE:.0%})"
                )
            elif lines < recorded[name]:
                hints.append(f"{name} shrank {recorded[name]} -> {lines}")
        for name in sorted(set(recorded) - set(current[kind])):
            hints.append(f"{name} is gone or now under {cap} lines; drop it")
    return failures, hints


def check_layers(baseline: dict, current: Counter[str]):
    """Return ``(failures, hints)`` for the core -> api layer ratchet."""
    allowed = Counter(baseline["core_api_imports"])
    failures: list[str] = []
    if len(baseline["core_api_imports"]) > MAX_CORE_API_ALLOWLIST:
        failures.append(
            f"core->api allowlist has {len(baseline['core_api_imports'])} entries; "
            f"max {MAX_CORE_API_ALLOWLIST}. Remove the import instead."
        )
    extra = current - allowed
    failures.extend(
        f"core imports api (not allow-listed): {key}"
        for key in sorted(extra.elements())
    )
    stale = allowed - current
    hints = [
        f"core->api import removed, drop from allowlist: {key}"
        for key in sorted(stale.elements())
    ]
    return failures, hints


def _print_hints(hints: list[str]) -> None:
    if hints:
        print(
            "\narchitecture ratchet can tighten; run "
            "`python tests/test_architecture.py --lower-baseline`:",
            file=sys.stderr,
        )
        for hint in hints:
            print(f"  - {hint}", file=sys.stderr)


class ArchitectureRatchetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = load_baseline()

    def test_core_does_not_import_api_beyond_allowlist(self) -> None:
        failures, hints = check_layers(self.baseline, measure_core_api_imports())
        _print_hints(hints)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_file_sizes_do_not_grow(self) -> None:
        failures, hints = check_sizes(self.baseline, measure_sizes())
        _print_hints(hints)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_checker_flags_violations(self) -> None:
        baseline = {
            "core_api_imports": ["a.py::rapidtriage.api.x"],
            "file_lines": {"python": {"big.py": 1000}, "tsx": {}},
        }
        current = {"python": {"big.py": 1051, "new.py": 801}, "tsx": {"n.tsx": 401}}
        failures, _ = check_sizes(baseline, current)
        self.assertEqual(len(failures), 3)
        failures, _ = check_sizes(baseline, {"python": {"big.py": 1050}, "tsx": {}})
        self.assertEqual(failures, [])
        failures, hints = check_sizes(baseline, {"python": {"big.py": 990}, "tsx": {}})
        self.assertEqual(failures, [])
        self.assertEqual(len(hints), 1)
        failures, _ = check_layers(
            baseline, Counter(["a.py::rapidtriage.api.x", "b.py::rapidtriage.api.y"])
        )
        self.assertEqual(
            failures, ["core imports api (not allow-listed): b.py::rapidtriage.api.y"]
        )
        baseline["core_api_imports"] = [f"f{i}.py::rapidtriage.api" for i in range(5)]
        failures, _ = check_layers(baseline, Counter(baseline["core_api_imports"]))
        self.assertEqual(len(failures), 1)

    def test_relative_import_resolution(self) -> None:
        path = CORE_DIR / "run" / "persist.py"
        node = ast.parse("from ...api.app import x").body[0]
        self.assertIsInstance(node, ast.ImportFrom)
        self.assertEqual(_resolve(node, path), "rapidtriage.api.app")
        init = CORE_DIR / "run" / "__init__.py"
        node = ast.parse("from .. import api").body[0]
        self.assertEqual(_resolve(node, init), CORE_PACKAGE)


def lower_baseline() -> None:
    baseline = load_baseline()
    sizes = measure_sizes()
    for kind, recorded in baseline["file_lines"].items():
        baseline["file_lines"][kind] = {
            name: min(lines, sizes[kind][name])
            for name, lines in sorted(recorded.items())
            if name in sizes[kind]
        }
    allowed = Counter(baseline["core_api_imports"])
    kept = allowed & measure_core_api_imports()
    baseline["core_api_imports"] = sorted(kept.elements())
    BASELINE_PATH.write_bytes((json.dumps(baseline, indent=2) + "\n").encode("utf-8"))
    print(f"lowered {_rel(BASELINE_PATH)}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--lower-baseline"]:
        lower_baseline()
    else:
        unittest.main()
