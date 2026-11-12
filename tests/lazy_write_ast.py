"""AST walk behind the R8 T-133 / T-134 lazy-write checks (shared by both test modules).

A *write site* is a call that changes the file system: ``write_text`` / ``write_bytes`` /
``mkdir`` / ``touch`` / ``unlink`` / ``rmdir`` / ``rename``, ``os.replace`` / ``os.remove`` /
``os.makedirs`` …, ``shutil`` copies and moves, ``open`` / ``.open`` with a writing mode, a
``sqlite3.connect`` that is not ``?mode=ro`` and any call passing ``write=True`` (the case-DB
connection helper). Each site belongs to its *unit*: the module-level function or class method it
is written in (nested functions and lambdas count as their outer unit), except that a route
handler nested in a ``build_*_router`` function is a unit of its own.

A unit is *safe* when

* it asks a persist guard itself (``may_persist`` / ``index_persist_enabled``), or
* it is a state-changing route handler (``@router.post/put/patch/delete``): the read-only gate
  answers ``409 RUN_READ_ONLY`` before it runs, or
* it is a run-completion step (written while a run fills its own new folder) referenced only
  from ``rapidtriage/core/run``, or
* it is referenced somewhere in ``rapidtriage`` and every unit referencing it is safe.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from rapidtriage.api.app.index_cache import PERSIST_GUARD_NAMES

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "rapidtriage"
API_APP = PACKAGE / "api" / "app"
RUN_PIPELINE = PACKAGE / "core" / "run"

WRITE_METHODS = frozenset(
    {"write_text", "write_bytes", "mkdir", "makedirs", "touch", "unlink", "rmdir", "rename", "symlink_to", "hardlink_to"}
)
OS_WRITES = frozenset({"replace", "rename", "remove", "unlink", "makedirs", "mkdir", "rmdir", "truncate", "link", "symlink"})
SHUTIL_WRITES = frozenset({"copy", "copy2", "copyfile", "copytree", "copyfileobj", "move", "rmtree", "make_archive"})
GATED_DECORATORS = frozenset({"post", "put", "patch", "delete"})
MODE = re.compile(r"[rwaxbtU+]{1,4}")
#: Writers that run while a run fills its own new output folder (``core/run``), never from the API.
RUN_COMPLETION_WRITERS = frozenset({"write_run_families", "write_run_geo_index", "write_timeline_index"})
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass(frozen=True)
class Site:
    module: str
    unit: str | None
    line: int
    call: str


@dataclass
class Unit:
    path: Path
    name: str | None  # ``None``: module-level code
    node: ast.AST
    skip: frozenset[int] = field(default_factory=frozenset)  # ids of nested handlers (units of their own)

    def nodes(self) -> Iterator[ast.AST]:
        stack = [self.node]
        while stack:
            current = stack.pop()
            yield current
            stack.extend(child for child in ast.iter_child_nodes(current) if id(child) not in self.skip)


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _owner(func: ast.expr) -> str | None:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _text(node: ast.expr) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_text(part) for part in node.values if isinstance(part, ast.Constant))
    return ""


def _opens_for_writing(call: ast.Call) -> bool:
    mode = next((keyword.value for keyword in call.keywords if keyword.arg == "mode"), None)
    if mode is not None:
        text = _text(mode)
        return not text or any(char in text for char in "wax+")  # a computed mode counts as a write
    for argument in call.args:
        text = _text(argument)
        if text and MODE.fullmatch(text):
            return any(char in text for char in "wax+")
    return False  # default mode "r"


def is_write(call: ast.Call) -> str | None:
    """The write a call makes (``None`` for anything else)."""
    name = _call_name(call.func)
    owner = _owner(call.func)
    for keyword in call.keywords:
        if keyword.arg == "write" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return f"{name}(write=True)"
    if name is None:
        return None
    if owner == "os":
        return f"os.{name}" if name in OS_WRITES else None
    if owner == "shutil":
        return f"shutil.{name}" if name in SHUTIL_WRITES else None
    if owner == "sqlite3" and name == "connect":
        return None if call.args and "mode=ro" in _text(call.args[0]) else "sqlite3.connect"
    if isinstance(call.func, ast.Attribute) and name in WRITE_METHODS:
        return name
    if name == "open" and _opens_for_writing(call):
        return "open(write)"
    return None


def _is_gated(node: ast.AST) -> bool:
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in GATED_DECORATORS:
            return True
    return False


def units_of(path: Path, tree: ast.Module) -> list[Unit]:
    units: list[Unit] = []

    def add_function(name: str, node: ast.AST) -> None:
        handlers = [inner for inner in ast.walk(node) if inner is not node and isinstance(inner, FUNCTIONS) and _is_gated(inner)]
        units.extend(Unit(path, handler.name, handler) for handler in handlers)
        units.append(Unit(path, name, node, frozenset(id(handler) for handler in handlers)))

    for node in tree.body:
        if isinstance(node, FUNCTIONS):
            add_function(node.name, node)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, FUNCTIONS):
                    add_function(item.name, item)
                else:
                    units.append(Unit(path, None, item))
        else:
            units.append(Unit(path, None, node))
    return units


class Package:
    """Parsed ``rapidtriage`` modules with the reference index the safety check needs."""

    def __init__(self) -> None:
        self.units: dict[Path, list[Unit]] = {}
        # referenced name -> units whose code names it (``Name`` or ``.attr``)
        self.references: dict[str, list[Unit]] = {}
        for path in sorted(PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            self.units[path] = units_of(path, tree)
            for unit in self.units[path]:
                names = set()
                for inner in unit.nodes():
                    if isinstance(inner, ast.Name):
                        names.add(inner.id)
                    elif isinstance(inner, ast.Attribute):
                        names.add(inner.attr)
                names.discard(unit.name)
                for name in names:
                    self.references.setdefault(name, []).append(unit)

    def write_sites(self, path: Path) -> list[tuple[Site, Unit]]:
        sites: list[tuple[Site, Unit]] = []
        for unit in self.units[path]:
            for inner in unit.nodes():
                if isinstance(inner, ast.Call):
                    call = is_write(inner)
                    if call is not None:
                        sites.append((Site(path.name, unit.name, inner.lineno, call), unit))
        return sites

    def unsafe_reason(self, unit: Unit, seen: frozenset[str] = frozenset()) -> str | None:
        """``None`` when the unit is safe (see the module doc), else why not."""
        label = f"{unit.path.relative_to(ROOT).as_posix()}:{unit.name}"
        if unit.name is None:
            return f"{label}: module-level code (no guard possible)"
        if _is_gated(unit.node):
            return None
        if any(isinstance(inner, ast.Call) and _call_name(inner.func) in PERSIST_GUARD_NAMES for inner in unit.nodes()):
            return None
        if unit.name in seen:
            return None  # a cycle: the other references decide
        refs = self.references.get(unit.name, [])
        if unit.name in RUN_COMPLETION_WRITERS:
            outside = [f"{ref.path.name}:{ref.name}" for ref in refs if not ref.path.is_relative_to(RUN_PIPELINE)]
            return f"{label}: run-completion writer also used by {outside}" if outside else None
        if not refs:
            return f"{label}: writes without asking a persist guard and nothing calls it"
        for ref in refs:
            reason = self.unsafe_reason(ref, seen | {unit.name})
            if reason is not None:
                return f"{label} <- {reason}"
        return None

    def unguarded(self, path: Path) -> tuple[list[Site], list[str]]:
        """Write sites of ``path`` and the reasons of the unsafe ones."""
        sites = self.write_sites(path)
        problems = []
        for site, unit in sites:
            reason = self.unsafe_reason(unit)
            if reason is not None:
                problems.append(f"{site.module}:{site.line} {site.call}: {reason}")
        return [site for site, _unit in sites], problems
