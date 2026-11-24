"""Python-vs-Rust registry engine comparison helpers (differential tests and scripts).

``api_trace`` exercises every ``NativeRegistryHive`` entry point the collectors use (tree walk,
key/value fields, last-write ticks, value bytes/decoded data/allocation state, case-insensitive
lookups, ``open_key``, raw offset probes, free-cell candidates, the string pivot) and snapshots
the ``errors`` Counter (order included) after each step. ``collect_rows`` runs the collectors
that read hives over an evidence tree under one engine. Both engines must produce identical
traces and rows; ``count_fields`` reports how many leaf fields a comparison covered.
"""

from __future__ import annotations

import json
import os
import random
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from itertools import islice
from pathlib import Path

from rapidtriage.artifacts.windows.registry import (
    MAX_HIVE_STRING_SCAN_BYTES,
    NativeRegistryHive,
    RustRegistryHive,
    iter_registry_free_cell_candidates,
)
from rapidtriage.artifacts.windows.registry_engine import (
    REGISTRY_ENGINE_ENV,
    load_registry_extension,
)

# Provenance fields that name the engine on registry-hive rows (present only when a non-default
# engine was requested); everything else must be identical.
ENGINE_PROVENANCE_FIELDS = frozenset(
    {"native_registry_engine", "native_registry_engine_requested", "native_registry_engine_notice_ko"}
)
KEY_FIELDS = (
    "offset", "name", "name_encoding", "flags", "last_written_filetime", "last_written_at", "parent_offset",
    "subkey_count", "subkey_list_offset", "value_count", "value_list_offset", "allocated",
)
VALUE_FIELDS = ("offset", "name", "name_encoding", "value_type", "data_size", "data_offset", "inline", "flags", "allocated")


def rust_module() -> object | None:
    return load_registry_extension()[0]


def open_engine(blob: bytes, engine: str) -> NativeRegistryHive:
    """The hive on an explicit engine (independent of the environment switch)."""
    if engine == "rust":
        module = rust_module()
        if module is None:
            raise RuntimeError("rapid_registry_native is not built")
        return RustRegistryHive(blob, native=module)
    return NativeRegistryHive(blob)


@contextmanager
def registry_engine(engine: str) -> Iterator[None]:
    previous = os.environ.get(REGISTRY_ENGINE_ENV)
    os.environ[REGISTRY_ENGINE_ENV] = engine
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(REGISTRY_ENGINE_ENV, None)
        else:
            os.environ[REGISTRY_ENGINE_ENV] = previous


def _fields(item: object, names: tuple[str, ...]) -> tuple[object, ...] | None:
    if item is None:
        return None
    return tuple((name, getattr(item, name), type(getattr(item, name)).__name__) for name in names)


def _typed(value: object) -> tuple[str, object]:
    return type(value).__name__, value


def _call(trace: list[object], label: str, function: Callable[[], object]) -> object:
    try:
        result = function()
    except Exception as exc:  # the engines must also fail identically
        trace.append((label, "raised", type(exc).__name__))
        return None
    return result


def _variants(name: str) -> list[str]:
    return list(dict.fromkeys([name, name.upper(), name.lower(), name.casefold(), name.swapcase(), name + "x"]))


def api_trace(hive: NativeRegistryHive, *, seed: int = 0, probe_count: int = 400) -> list[object]:
    rng = random.Random(seed)
    trace: list[object] = []
    errors = lambda: list(hive.errors.items())
    root = hive.root
    trace.append(("root", _fields(root, KEY_FIELDS), errors()))
    paths: list[str] = []
    for index, (parts, key) in enumerate(hive.iter_keys()):
        values = hive.values(key)
        trace.append(("key", parts, _fields(key, KEY_FIELDS), [_fields(value, VALUE_FIELDS) for value in values]))
        if index % 7 == 0 and len(paths) < 60:
            paths.append("\\".join(parts))
        for value in values:
            trace.append(
                (
                    "data",
                    _typed(hive.value_bytes(value)),
                    _typed(hive.value_data(value)),
                    _typed(hive.value_data_allocated(value)),
                    hive.cell_allocated(int(value.data_offset or 0)),
                )
            )
        trace.append(("values_dict", [(name, _typed(data)) for name, data in hive.values_dict(key).items()]))
        children = hive.subkeys(key)
        trace.append(("subkeys", [_fields(child, KEY_FIELDS) for child in children]))
        if index % 5 == 0:  # case-insensitive lookups on a sample of keys
            for value in values[:2]:
                for variant in _variants(str(value.name)):
                    trace.append(("value", variant, _fields(hive.value(key, variant), VALUE_FIELDS)))
            for child in children[:2]:
                for variant in _variants(str(child.name)):
                    trace.append(("subkey", variant, _fields(hive.subkey(key, variant), KEY_FIELDS)))
        trace.append(("errors", errors()))
    walk_errors = errors()
    for path in paths:
        for variant in (path, path.upper(), path.replace("\\", "/"), "\\" + path.lower() + "\\", path + "\\missing"):
            trace.append(("open_key", variant, _fields(hive.open_key(variant), KEY_FIELDS)))
    if root is not None:
        for parts, key in islice(hive.iter_keys(), 20):
            relative = "\\".join(parts[1:])
            start = hive.open_key(parts[0]) if parts else root
            trace.append(("open_key_start", relative, _fields(hive.open_key(relative, start=start), KEY_FIELDS)))
            trace.append(("iter_from", [(sub_parts, sub.offset) for sub_parts, sub in islice(hive.iter_keys(key, ("X",)), 50)]))
    limit = max(8, min(hive.size, 1 << 20) - 4096)
    probes = [0, 3, 8, 0xFFFFFFFF, 0xFFFFFFF8, 0x7FFFFFF8, 1 << 33, (1 << 33) + 3, limit - 8, limit]
    probes += [rng.randrange(0, limit) for _ in range(probe_count)]
    probes += [rng.randrange(0, limit // 8) * 8 for _ in range(probe_count)]
    for offset in probes:
        trace.append(
            (
                "probe",
                offset,
                _fields(_call(trace, "key_at", lambda o=offset: hive.key_at(o)), KEY_FIELDS),
                _fields(_call(trace, "value_at", lambda o=offset: hive.value_at(o)), VALUE_FIELDS),
                _call(trace, "cell_allocated", lambda o=offset: hive.cell_allocated(o)),
            )
        )
    candidates, stats = iter_registry_free_cell_candidates(hive)
    trace.append(("free_cells", [list(candidate.items()) for candidate in candidates], list(stats.items())))
    trace.append(("strings", hive.utf16le_strings(min(hive.size, MAX_HIVE_STRING_SCAN_BYTES))))
    trace.append(("walk_errors", walk_errors, "final_errors", errors()))
    return trace


def record_rows(records: object) -> list[dict[str, object]]:
    rows = []
    for record in records:  # type: ignore[attr-defined]
        row = record.to_dict()
        details = row.get("details")
        if isinstance(details, Mapping):
            row["details"] = {key: value for key, value in details.items() if key not in ENGINE_PROVENANCE_FIELDS}
        rows.append(row)
    return rows


def collect_rows(root: Path) -> dict[str, list[dict[str, object]]]:
    """Rows of every collector that reads hives through the native reader, over ``root``."""
    from rapidtriage.artifacts.windows.execution import WindowsExecutionProvider
    from rapidtriage.artifacts.windows.media_players import WindowsMediaPlayersProvider
    from rapidtriage.artifacts.windows.os_account import WindowsOsAccountProvider
    from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider
    from rapidtriage.artifacts.windows.shellbags import WindowsShellbagsProvider

    providers = {
        "registry": WindowsRegistryProvider(),
        "shellbags": WindowsShellbagsProvider(),
        "execution": WindowsExecutionProvider(),
        "os-account": WindowsOsAccountProvider(),
        "media-players": WindowsMediaPlayersProvider(),
    }
    return {name: record_rows(provider.collect(root)) for name, provider in providers.items()}


def canonical(value: object) -> str:
    """Order-sensitive JSON (dict order included) so even key-order drift counts as a difference."""
    return json.dumps(value, ensure_ascii=False, default=lambda item: f"<{type(item).__name__}>{item!r}")


def count_fields(value: object) -> int:
    if isinstance(value, Mapping):
        return sum(count_fields(item) for item in value.values()) or 1
    if isinstance(value, (list, tuple)):
        return sum(count_fields(item) for item in value) or 1
    return 1


def diff_paths(left: object, right: object, path: str = "", limit: int = 20) -> list[str]:
    """Up to ``limit`` locations where two structures differ (types included)."""
    found: list[str] = []
    if type(left) is not type(right):
        return [f"{path}: {type(left).__name__} != {type(right).__name__}"]
    if isinstance(left, Mapping):
        if list(left) != list(right):  # type: ignore[arg-type]
            found.append(f"{path}: keys {list(left)[:8]} != {list(right)[:8]}")  # type: ignore[arg-type]
        for key in left:
            if key in right and len(found) < limit:  # type: ignore[operator]
                found += diff_paths(left[key], right[key], f"{path}.{key}", limit - len(found))  # type: ignore[index]
    elif isinstance(left, (list, tuple)):
        if len(left) != len(right):  # type: ignore[arg-type]
            found.append(f"{path}: len {len(left)} != {len(right)}")  # type: ignore[arg-type]
        for index, (a, b) in enumerate(zip(left, right)):  # type: ignore[call-overload]
            if len(found) >= limit:
                break
            found += diff_paths(a, b, f"{path}[{index}]", limit - len(found))
    elif left != right:
        found.append(f"{path}: {str(left)[:120]!r} != {str(right)[:120]!r}")
    return found[:limit]
