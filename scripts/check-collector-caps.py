#!/usr/bin/env python3
"""Inventory hard caps in collectors and core, and whether each one is disclosed when hit (T-165).

Read-only static analysis over ``rapidtriage/artifacts/**`` and ``rapidtriage/core/**``. Nothing is
imported or executed; every file is parsed with :mod:`ast`. Caps are reported, never changed.

What counts as a cap
    * constants (module or class level) whose UPPER_CASE name carries a cap token (``MAX``,
      ``LIMIT``, ``BUDGET``, ``CAP``) or ends in ``_SCAN_BYTES`` / ``_READ_MB``, with a numeric value;
    * function parameters with a cap-like name (``max_items``, ``limit`` ...) and a literal default >= 100;
    * literals used as limits inside code: ``if len(rows) >= N: break/return`` and
      ``while len(rows) < N`` loop caps (N >= 100), ``f(limit=N)`` keyword arguments (N >= 100) and SQL
      ``LIMIT N`` strings (N >= 100). Slices (``text[:N]``) are value previews, not caps, and are skipped.
    Time-range bounds (``MIN_UNIX``, ``*_MAX_MS`` ...), version pins and env-var names are excluded.

What counts as disclosed
    Disclosure is looked for near each use of the cap: in the same function, within
    ``PROXIMITY_LINES`` lines of the reference (the constant, the parameter's uses, or the literal).
    * ``full``  -- a truncation flag (``*_truncated``, ``capped``, ``limit_reached`` ...) together with a
      total key (``*_total`` / ``total_*``), or a human-readable warning sentence ("safety cap",
      "cap reached", Korean ``상한`` / ``잘림``). This is the T-301..T-307 contract
      (``<name>_truncated`` + ``<name>_total`` or a processing-problem line).
    * ``flag``  -- a truncation flag only: the reader learns that rows are missing, not how many.
    * ``none``  -- nothing; stating the limit (``"scan_limit": LIMIT``) is not a disclosure.
    ``disclosed`` is true only for ``full``.

Usage::

    python scripts/check-collector-caps.py --json        # full inventory + undisclosed list
    python scripts/check-collector-caps.py               # markdown table (file:line, name, value, unit, disclosed)
    python scripts/check-collector-caps.py --undisclosed-only

Exit status is 0; the ratchet lives in ``tests/test_collector_caps_inventory.py``.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOTS = ("rapidtriage/artifacts", "rapidtriage/core")

CAP_NAME_RE = re.compile(r"(?:^|_)(?:MAX|LIMIT|LIMITS|BUDGET|CAP)(?:_|$)|_SCAN_BYTES$|_READ_MB$")
EXCLUDED_NAME_RE = re.compile(r"(?:^|_)(?:MIN|UNIX|MS|MICROS|FILETIME|EPOCH|PLAUSIBLE|VERSION|ENV)(?:_|$)")
CAP_PARAM_RE = re.compile(r"(?:^|_)(?:max|limit|budget|cap)(?:_|$)")
SQL_LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\b")
FLAG_KEY_RE = re.compile(r"truncat|\bcapped\b|_capped\b|limit_(?:reached|hit)|cap_(?:reached|hit)", re.IGNORECASE)
TOTAL_KEY_RE = re.compile(r"(?:^|_)total(?:_|$)", re.IGNORECASE)
WARNING_RE = re.compile(
    r"truncat|safety cap|\b(?:cap|limit) (?:was )?(?:reached|hit)|\bhit the\b.*\b(?:cap|limit)\b|상한|잘림",
    re.IGNORECASE,
)

PROXIMITY_LINES = 50
MIN_PARAMETER = 100
MIN_LEN_COMPARE = 100
MIN_KEYWORD = 100
MIN_SQL_LIMIT = 100

FUNCTION_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class Cap:
    """One cap site."""

    id: str
    file: str
    line: int
    name: str
    kind: str  # constant | parameter | literal
    value: float | int | None
    expr: str
    unit: str
    disclosure: str = "none"  # full | flag | none
    disclosed: bool = False
    disclosure_keys: list[str] = field(default_factory=list)
    used_in: list[str] = field(default_factory=list)


def _unit_for(name: str, expr: str) -> str:
    upper = name.upper()
    if re.search(r"(?:^|_)(?:SECONDS|TIMEOUT)(?:_|$)", upper):
        return "seconds"
    if re.search(r"(?:^|_)MB(?:_|$)", upper):
        return "MiB"
    if re.search(r"(?:^|_)(?:BYTES|BYTE|KB|MIB)(?:_|$)", upper) or "1024" in expr:
        return "bytes"
    if re.search(r"(?:^|_)CHARS?(?:_|$)", upper):
        return "chars"
    if re.search(r"(?:^|_)DEPTH(?:_|$)", upper):
        return "depth"
    return "count"


def _eval_numeric(node: ast.AST, known: dict[str, float | int]) -> float | int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name):
        return known.get(node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _eval_numeric(node.operand, known)
        return None if inner is None else -inner
    if not isinstance(node, ast.BinOp):
        return None
    left = _eval_numeric(node.left, known)
    right = _eval_numeric(node.right, known)
    if left is None or right is None:
        return None
    operators = {
        ast.Mult: lambda a, b: a * b,
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Pow: lambda a, b: a**b,
        ast.LShift: lambda a, b: a << b,
    }
    operation = operators.get(type(node.op))
    if operation is None:
        return None
    try:
        return operation(left, right)
    except (ArithmeticError, TypeError, ValueError):
        return None


def _int_literal(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _is_len_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"


class _ModuleInfo:
    """One parsed source file: node list, parent map, imports and per-scope disclosure strings."""

    def __init__(self, rel: str, tree: ast.Module) -> None:
        self.rel = rel
        self.tree = tree
        parts = rel[:-3].split("/")
        self.is_package = parts[-1] == "__init__"
        self.module_name = ".".join(parts[:-1] if self.is_package else parts)
        self.parents: dict[ast.AST, ast.AST] = {}
        self.nodes: list[ast.AST] = [tree]
        stack: list[ast.AST] = [tree]
        while stack:
            parent = stack.pop()
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
                self.nodes.append(child)
                stack.append(child)
        self.imports: dict[str, tuple[str, str]] = {}  # local name -> (module, original name)
        self._strings: dict[ast.AST, list[tuple[int, str]]] = {}

    def resolve_from(self, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        package = self.module_name.split(".") if self.is_package else self.module_name.split(".")[:-1]
        if node.level > 1:
            package = package[: len(package) - (node.level - 1)]
        return ".".join([*package, node.module] if node.module else package)

    def scope_of(self, node: ast.AST) -> ast.AST:
        """Innermost enclosing function, else the top-level statement holding ``node``."""
        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, FUNCTION_TYPES):
                return parent
            if isinstance(parent, ast.Module):
                return current
            current = parent
        return current

    def scope_label(self, scope: ast.AST) -> str:
        if isinstance(scope, FUNCTION_TYPES):
            return f"{self.rel}:{scope.name}"
        return f"{self.rel}:<module>"

    def strings(self, scope: ast.AST) -> list[tuple[int, str]]:
        if scope not in self._strings:
            found: list[tuple[int, str]] = []
            for child in ast.walk(scope):
                if isinstance(child, ast.JoinedStr):
                    # f-string: judge the whole sentence, placeholders as "{}"
                    text = "".join(
                        part.value if isinstance(part, ast.Constant) and isinstance(part.value, str) else "{}"
                        for part in child.values
                    )
                elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                    if isinstance(self.parents.get(child), ast.JoinedStr):
                        continue
                    text = child.value
                else:
                    continue
                if len(text) <= 400 and (FLAG_KEY_RE.search(text) or TOTAL_KEY_RE.search(text) or WARNING_RE.search(text)):
                    found.append((child.lineno, text))
            self._strings[scope] = found
        return self._strings[scope]


def _classify(texts: list[str]) -> tuple[str, list[str]]:
    flags = [text for text in texts if FLAG_KEY_RE.search(text)]
    totals = [text for text in texts if TOTAL_KEY_RE.search(text) and " " not in text.strip()]
    warnings = [text for text in texts if " " in text.strip() and WARNING_RE.search(text)]
    keys = sorted({text.strip()[:80] for text in [*flags, *totals, *warnings]})
    if warnings or (flags and totals):
        return "full", keys
    if flags:
        return "flag", keys
    return "none", keys


def _returned(info: _ModuleInfo, node: ast.AST, scope: ast.AST) -> bool:
    """True when ``scope`` hands the cap out as its scalar return value (``return CAP``,
    ``return int(env or CAP)``, ``return CAP * MIB``) -- not when the cap is one field of a returned dict."""
    current = node
    while current in info.parents and current is not scope:
        current = info.parents[current]
        if isinstance(current, ast.Return):
            return True
        if not isinstance(current, (ast.Call, ast.BinOp, ast.BoolOp, ast.IfExp, ast.UnaryOp, ast.keyword)):
            return False
    return False


def _stops_collection(info: _ModuleInfo, compare: ast.Compare) -> bool:
    """``while len(rows) < N`` or ``if len(rows) >= N: break/return`` -- a collection loop cap,
    as opposed to a string-length check that only shortens a value."""
    parent = info.parents.get(compare)
    if isinstance(parent, ast.While) and parent.test is compare:
        return True
    if isinstance(parent, ast.If) and parent.test is compare:
        return any(isinstance(stmt, (ast.Break, ast.Return)) for stmt in parent.body)
    return False


def _near(info: _ModuleInfo, scope: ast.AST, lines: list[int]) -> list[str]:
    return [text for line, text in info.strings(scope) if any(abs(line - ref) <= PROXIMITY_LINES for ref in lines)]


def _collect_constants(info: _ModuleInfo) -> list[tuple[str, ast.Name, ast.AST, float | int | None]]:
    """(qualified name, target, value node, value) for cap constants in module and class bodies."""
    known: dict[str, float | int] = {}
    caps: list[tuple[str, ast.Name, ast.AST, float | int | None]] = []

    def visit_body(body: list[ast.stmt], prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, ast.ClassDef):
                visit_body(stmt.body, f"{prefix}{stmt.name}.")
                continue
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                target, value_node = stmt.targets[0], stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                target, value_node = stmt.target, stmt.value
            else:
                continue
            name = target.id
            value = _eval_numeric(value_node, known)
            if value is not None and not prefix:
                known[name] = value
            if not name.isupper() or not CAP_NAME_RE.search(name) or EXCLUDED_NAME_RE.search(name):
                continue
            if value is None and not isinstance(value_node, (ast.BinOp, ast.Name)):
                continue
            if value is not None and value <= 0:
                continue
            caps.append((f"{prefix}{name}", target, value_node, value))

    visit_body(info.tree.body, "")
    return caps


def _load_modules(repo_root: Path) -> tuple[list[_ModuleInfo], list[str]]:
    modules: list[_ModuleInfo] = []
    errors: list[str] = []
    for root in SCAN_ROOTS:
        base = repo_root / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(repo_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            except (SyntaxError, UnicodeDecodeError) as exc:
                errors.append(f"{rel}: {exc}")
                continue
            modules.append(_ModuleInfo(rel, tree))
    return modules, errors


def _constant_caps(modules: list[_ModuleInfo]) -> list[Cap]:
    by_module_name = {info.module_name: info for info in modules}
    defs: dict[tuple[str, str], Cap] = {}
    caps: list[Cap] = []
    for info in modules:
        for node in info.nodes:
            if isinstance(node, ast.ImportFrom):
                source = info.resolve_from(node)
                for alias in node.names:
                    info.imports[alias.asname or alias.name] = (source, alias.name)
        for qualified, target, value_node, value in _collect_constants(info):
            expr = ast.unparse(value_node)
            bare = qualified.rsplit(".", 1)[-1]
            cap = Cap(
                id=f"{info.rel}::{qualified}",
                file=info.rel,
                line=target.lineno,
                name=qualified,
                kind="constant",
                value=value,
                expr=expr,
                unit=_unit_for(bare, expr),
            )
            caps.append(cap)
            defs[(info.module_name, bare)] = cap

    attr_owner: dict[str, list[Cap]] = defaultdict(list)
    for (_module, bare), cap in defs.items():
        attr_owner[bare].append(cap)

    # cap id -> {(module info, scope): [reference lines]}
    refs: dict[str, dict[tuple[int, ast.AST], list[int]]] = defaultdict(lambda: defaultdict(list))
    accessors: dict[tuple[str, str], Cap] = {}  # (module, function) returning a cap constant
    infos_by_id: dict[int, _ModuleInfo] = {id(info): info for info in modules}
    for info in modules:
        for node in info.nodes:
            cap: Cap | None = None
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                cap = defs.get((info.module_name, node.id))
                if cap is None and node.id in info.imports:
                    source, original = info.imports[node.id]
                    cap = defs.get((source, original))
                    if cap is None and source in by_module_name:
                        reexport = by_module_name[source].imports.get(original)
                        if reexport:
                            cap = defs.get(reexport)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                owners = attr_owner.get(node.attr, [])
                if len(owners) == 1:
                    cap = owners[0]
            if cap is None:
                continue
            scope = info.scope_of(node)
            if isinstance(scope, (ast.Assign, ast.AnnAssign)):
                continue  # a constant derived from another constant is not a use site
            refs[cap.id][(id(info), scope)].append(node.lineno)
            if isinstance(scope, FUNCTION_TYPES) and _returned(info, node, scope):
                accessors[(info.module_name, scope.name)] = cap

    # One hop through accessors such as ``def native_extract_file_limit(): return MAX_...``:
    # their call sites are uses of the cap as well.
    accessor_attr: dict[str, list[Cap]] = defaultdict(list)
    for (_module, function_name), cap in accessors.items():
        accessor_attr[function_name].append(cap)
    for info in modules:
        for node in info.nodes:
            if not isinstance(node, ast.Call):
                continue
            cap = None
            if isinstance(node.func, ast.Name):
                cap = accessors.get((info.module_name, node.func.id))
                if cap is None and node.func.id in info.imports:
                    cap = accessors.get(info.imports[node.func.id])
            elif isinstance(node.func, ast.Attribute) and len(accessor_attr.get(node.func.attr, [])) == 1:
                cap = accessor_attr[node.func.attr][0]
            if cap is None:
                continue
            scope = info.scope_of(node)
            if not isinstance(scope, (ast.Assign, ast.AnnAssign)):
                refs[cap.id][(id(info), scope)].append(node.lineno)

    for cap in caps:
        texts: list[str] = []
        labels: set[str] = set()
        for (info_id, scope), lines in refs.get(cap.id, {}).items():
            info = infos_by_id[info_id]
            labels.add(info.scope_label(scope))
            texts.extend(_near(info, scope, lines))
        cap.used_in = sorted(labels)
        cap.disclosure, cap.disclosure_keys = _classify(texts)
        cap.disclosure_keys = cap.disclosure_keys[:6]
        cap.disclosed = cap.disclosure == "full"
    return caps


def _inline_caps(info: _ModuleInfo) -> list[Cap]:
    caps: list[Cap] = []
    counters: dict[str, int] = defaultdict(int)

    def add(name: str, node: ast.AST, value: int, unit: str, scope: ast.AST, kind: str, lines: list[int]) -> None:
        counters[name] += 1
        suffix = f"#{counters[name]}" if counters[name] > 1 else ""
        disclosure, keys = _classify(_near(info, scope, lines))
        caps.append(
            Cap(
                id=f"{info.rel}::{name}{suffix}",
                file=info.rel,
                line=getattr(node, "lineno", 0),
                name=name,
                kind=kind,
                value=value,
                expr=ast.unparse(node) if isinstance(node, ast.expr) else str(value),
                unit=unit,
                disclosure=disclosure,
                disclosed=disclosure == "full",
                disclosure_keys=keys[:6],
                used_in=[info.scope_label(scope)],
            )
        )

    for node in info.nodes:
        if isinstance(node, FUNCTION_TYPES):
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            pairs = list(zip(positional[len(positional) - len(args.defaults) :], args.defaults))
            pairs += [(arg, default) for arg, default in zip(args.kwonlyargs, args.kw_defaults) if default is not None]
            for arg, default in pairs:
                literal = _int_literal(default)
                if literal is None or literal < MIN_PARAMETER or not CAP_PARAM_RE.search(arg.arg):
                    continue
                uses = [
                    child.lineno
                    for child in ast.walk(node)
                    if isinstance(child, ast.Name) and child.id == arg.arg and isinstance(child.ctx, ast.Load)
                ]
                add(f"{node.name}({arg.arg})", default, literal, _unit_for(arg.arg, ""), node, "parameter", uses)
            continue
        literal: int | None = None
        label = ""
        unit = "count"
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = node.left, node.comparators[0]
            if isinstance(node.ops[0], (ast.Gt, ast.GtE)) and _is_len_call(left):
                literal = _int_literal(right)
            elif isinstance(node.ops[0], (ast.Lt, ast.LtE)) and _is_len_call(right):
                literal = _int_literal(left)
            if literal is not None and literal >= MIN_LEN_COMPARE and _stops_collection(info, node):
                label = f"len>={literal}"
        elif isinstance(node, ast.keyword) and node.arg and CAP_PARAM_RE.search(node.arg):
            literal = _int_literal(node.value)
            if literal is not None and literal >= MIN_KEYWORD:
                label = f"{node.arg}={literal}"
                unit = _unit_for(node.arg, "")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "LIMIT" in node.value:
            for match in SQL_LIMIT_RE.finditer(node.value):
                value = int(match.group(1))
                if value >= MIN_SQL_LIMIT:
                    literal, label, unit = value, f"SQL LIMIT {value}", "rows"
                    break
        if not label or literal is None:
            continue
        scope = info.scope_of(node)
        function = scope.name if isinstance(scope, FUNCTION_TYPES) else "<module>"
        anchor = node.value if isinstance(node, ast.keyword) else node
        add(f"{function}:{label}", anchor, literal, unit, scope, "literal", [getattr(anchor, "lineno", 0)])
    return caps


def build_inventory(repo_root: Path = REPO_ROOT) -> dict[str, object]:
    """Scan ``SCAN_ROOTS`` under ``repo_root`` and return the caps inventory."""
    modules, parse_errors = _load_modules(repo_root)
    caps = _constant_caps(modules)
    for info in modules:
        caps.extend(_inline_caps(info))
    caps.sort(key=lambda cap: (cap.file, cap.line, cap.name))

    undisclosed = [cap for cap in caps if not cap.disclosed]
    per_file: dict[str, int] = defaultdict(int)
    for cap in undisclosed:
        per_file[cap.file] += 1
    by_kind: dict[str, int] = defaultdict(int)
    by_disclosure: dict[str, int] = defaultdict(int)
    for cap in caps:
        by_kind[cap.kind] += 1
        by_disclosure[cap.disclosure] += 1
    return {
        "schema": "rapidtriage.collector-caps.v1",
        "scan_roots": list(SCAN_ROOTS),
        "summary": {
            "files_scanned": len(modules),
            "caps": len(caps),
            "disclosed": len(caps) - len(undisclosed),
            "undisclosed": len(undisclosed),
            "by_kind": dict(sorted(by_kind.items())),
            "by_disclosure": dict(sorted(by_disclosure.items())),
        },
        "undisclosed_per_file": dict(sorted(per_file.items())),
        "undisclosed": [cap.id for cap in undisclosed],
        "caps": [asdict(cap) for cap in caps],
        "parse_errors": parse_errors,
    }


def _format_value(value: float | None, unit: str) -> str:
    if value is None:
        return "?"
    if unit == "bytes" and isinstance(value, int) and value >= 1024 * 1024 and value % (1024 * 1024) == 0:
        return f"{value // (1024 * 1024):,} MiB"
    if isinstance(value, int):
        return f"{value:,}"
    return f"{value:g}"


def render_markdown(inventory: dict[str, object], *, undisclosed_only: bool = False) -> str:
    summary = inventory["summary"]
    caps = inventory["caps"]
    roots = inventory["scan_roots"]
    assert isinstance(summary, dict) and isinstance(caps, list) and isinstance(roots, list)
    lines = [
        "# Collector caps inventory",
        "",
        f"Scanned {summary['files_scanned']} files under {', '.join(roots)}: {summary['caps']} caps, "
        f"{summary['disclosed']} disclosed, {summary['undisclosed']} undisclosed "
        f"(flag only: {summary['by_disclosure'].get('flag', 0)}).",
        "",
        "| file:line | name | value | unit | kind | disclosed |",
        "| --- | --- | ---: | --- | --- | --- |",
    ]
    for cap in caps:
        if undisclosed_only and cap["disclosed"]:
            continue
        name = str(cap["name"]).replace("|", "\\|")
        disclosed = "yes" if cap["disclosed"] else ("no (flag only)" if cap["disclosure"] == "flag" else "no")
        lines.append(
            f"| {cap['file']}:{cap['line']} | `{name}` | {_format_value(cap['value'], cap['unit'])} "
            f"| {cap['unit']} | {cap['kind']} | {disclosed} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory collector/core hard caps and their disclosure (T-165).")
    parser.add_argument("--json", action="store_true", help="emit the full inventory as JSON")
    parser.add_argument("--undisclosed-only", action="store_true", help="markdown: list only undisclosed caps")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root (default: this checkout)")
    args = parser.parse_args(argv)
    inventory = build_inventory(args.root)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.json:
        json.dump(inventory, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(inventory, undisclosed_only=args.undisclosed_only))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
