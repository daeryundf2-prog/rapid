#!/usr/bin/env python3
"""Compare seven registry artifact families in a Rapid run with python-registry.

Point --hive-root at the corresponding filesystem tree. Only live machine hives
in Windows/System32/config and NTUSER.DAT in immediate user profile directories
are in scope. The output contains aggregate counts and no recovered values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter, defaultdict
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rapidtriage.core.artifact_profiles import expand_profile, iter_payload_records

VERSION = r"Microsoft\Windows\CurrentVersion"
EXPLORER = "Software\\" + VERSION + r"\Explorer"
RUN_KEYS = (
    "Run",
    "RunOnce",
    "RunOnceEx",
    "RunServices",
    "RunServicesOnce",
    r"Policies\Explorer\Run",
)
FAMILIES = {
    "accounts": ("sam",),
    "installed_programs": ("software", "ntuser.dat"),
    "usb_storage_devices": ("system",),
    "recent_docs_mru": ("ntuser.dat",),
    "run_keys": ("software", "ntuser.dat"),
    "timezone": ("system",),
    "computer_name": ("system",),
}
# The value tuples use this order. Key paths and value names are case-insensitive.
PROJECTIONS = {
    "windows-sam-account": ("accounts", ("user_name",)),
    "windows-installed-program": (
        "installed_programs",
        ("display_name", "display_version", "publisher"),
    ),
    "windows-usb-device": (
        "usb_storage_devices",
        ("device_class_id", "serial_number", "friendly_name", "driver"),
    ),
    "registry-user-activity": ("recent_docs_mru", ("activity_value", "mru_position")),
    "registry-persistence-entry": ("run_keys", ("command",)),
    "windows-timezone": (
        "timezone",
        (
            "time_zone_key_name",
            "standard_name",
            "bias_minutes",
            "active_time_bias_minutes",
        ),
    ),
    "windows-computer-name": ("computer_name", ("computer_name",)),
}


def key_at(hive, path):
    from Registry import Registry

    try:
        return hive.open(path)
    except Registry.RegistryKeyNotFoundException:
        return None


def field(key, name, default=""):
    from Registry import Registry

    try:
        return key.value(name).value()
    except Registry.RegistryValueNotFoundException:
        return default


def signed_bias(value):
    return (
        struct.unpack("<i", struct.pack("<I", value))[0] if value is not None else None
    )


def text_prefix(raw):
    # RecentDocs may append a binary shell item, so only decode the leading name.
    for offset in range(0, len(raw) - 1, 2):
        if raw[offset : offset + 2] == b"\0\0":
            return raw[:offset].decode("utf-16-le")
    raise ValueError("unterminated RecentDocs string")


def live_uninstall_offsets(data, parent, index):
    """Read the referenced lf/lh cells and reconcile them to the parent nk's child count.

    parent/index are absolute record offsets (immediately after their cell sizes).
    The returned offsets are absolute cell offsets. No transaction replay or carving.
    """
    slots = struct.unpack_from("<H", data, index + 2)[0]
    list_size = -struct.unpack_from("<i", data, index - 4)[0]
    if (
        data[index:index + 2] not in (b"lf", b"lh")
        or list_size < 8 + 8 * slots
        or list_size % 8
        or index - 4 + list_size > len(data)
    ):
        raise ValueError("invalid direct uninstall index")
    live = set()
    free = 0
    for slot in range(slots):
        relative = struct.unpack_from("<I", data, index + 4 + 8 * slot)[0]
        offset = 4096 + relative
        size = struct.unpack_from("<i", data, offset)[0]
        if relative % 8 or abs(size) < 8 or size % 8 or offset + abs(size) > len(data):
            raise ValueError("invalid uninstall child cell extent")
        if size > 0:
            free += 1
            continue
        if size > -80 or data[offset + 4:offset + 6] != b"nk" or offset in live:
            raise ValueError("invalid allocated uninstall child")
        backlink = struct.unpack_from("<I", data, offset + 4 + 16)[0]
        if 4096 + backlink + 4 != parent:
            raise ValueError("uninstall child with different parent")
        live.add(offset)
    declared = struct.unpack_from("<I", data, parent + 20)[0]
    if not free or len(live) != declared:
        raise ValueError("unreconciled uninstall index")
    return sorted(live), free


def uninstall_children(key, diagnostics):
    from Registry import Registry, RegistryParse

    parent = key._nkrecord
    try:
        children = key.subkeys()
        if len(children) == parent.subkey_number() and all(
            struct.unpack_from("<i", parent._buf, k._nkrecord.offset() - 4)[0] < 0 for k in children
        ):
            return children
    except RegistryParse.ParseException:
        pass
    index = parent.subkey_list()
    offsets, free = live_uninstall_offsets(parent._buf, parent.offset(), index.offset())
    children = [Registry.RegistryKey(RegistryParse.HBINCell(parent._buf, offset, index).child()) for offset in offsets]
    diagnostics["free_uninstall_index_entries"] += free
    return children


def reference_rows(hive, family, leaf, diagnostics):
    """Yield (relative key, value name, fields) from the independent live tree."""
    if family == "accounts":
        names = key_at(hive, r"SAM\Domains\Account\Users\Names")
        for user in names.subkeys() if names is not None else []:
            # Each Names subkey stores the RID in its default value's TYPE.
            yield str(user.value("(default)").value_type()), "", (user.name(),)
    elif leaf == "system":
        current = hive.open("Select").value("Current").value()
        control = f"ControlSet{current:03d}"
        hive.open(
            control
        )  # An invalid selector cannot establish an active control set.
        if family == "timezone":
            path = control + r"\Control\TimeZoneInformation"
            key = key_at(hive, path)
            if key is not None:
                yield (
                    path,
                    "",
                    (
                        field(key, "TimeZoneKeyName"),
                        field(key, "StandardName"),
                        signed_bias(field(key, "Bias", None)),
                        signed_bias(field(key, "ActiveTimeBias", None)),
                    ),
                )
        elif family == "computer_name":
            path = control + r"\Control\ComputerName\ComputerName"
            key = key_at(hive, path)
            if key is not None:
                yield path, "", (field(key, "ComputerName"),)
        else:
            path = control + r"\Enum\USBSTOR"
            key = key_at(hive, path)
            for model in key.subkeys() if key is not None else []:
                for device in model.subkeys():
                    yield (
                        "\\".join((path, model.name(), device.name())),
                        "",
                        (
                            model.name(),
                            device.name(),
                            field(device, "FriendlyName"),
                            field(device, "Driver"),
                        ),
                    )
    elif family == "recent_docs_mru":
        path = EXPLORER + r"\RecentDocs"
        key = key_at(hive, path)
        if key is not None:
            for node_path, node in [
                (path, key),
                *((path + "\\" + sub.name(), sub) for sub in key.subkeys()),
            ]:
                order = {}
                for index, (slot,) in enumerate(
                    struct.iter_unpack("<I", field(node, "MRUListEx", b""))
                ):
                    if slot == 0xFFFFFFFF:
                        break
                    order.setdefault(str(slot), index)
                for entry in node.values():
                    if entry.name().isdecimal():
                        yield (
                            node_path,
                            entry.name(),
                            (text_prefix(entry.raw_data()), order.get(entry.name())),
                        )
    else:
        prefix = "Software\\" if leaf == "ntuser.dat" else ""
        if family == "installed_programs":
            bases = (VERSION,) if prefix else (VERSION, "Wow6432Node\\" + VERSION)
            for base in bases:
                path = prefix + base + r"\Uninstall"
                key = key_at(hive, path)
                for program in uninstall_children(key, diagnostics) if key is not None else []:
                    yield (
                        path + "\\" + program.name(),
                        "",
                        tuple(
                            field(program, name)
                            for name in ("DisplayName", "DisplayVersion", "Publisher")
                        ),
                    )
        else:
            for view, suffixes in (
                ("", RUN_KEYS),
                ("Wow6432Node\\", ("Run", "RunOnce")),
            ):
                for suffix in suffixes:
                    path = prefix + view + VERSION + "\\" + suffix
                    key = key_at(hive, path)
                    for value in key.values() if key is not None else []:
                        yield path, value.name(), (value.value(),)


def project(row):
    typ = row["artifact_type"]
    family, fields = PROJECTIONS[typ]
    details = row["details"]
    if (
        typ == "registry-user-activity"
        and details.get("user_activity_category") != "recent-document"
    ):
        return None
    if typ == "registry-persistence-entry" and details.get(
        "persistence_category"
    ) not in {suffix.split("\\")[-1] for suffix in RUN_KEYS}:
        return None
    if family == "accounts":
        path = str(details["rid"])
    else:
        mount = details["hive_mount"] + "\\"
        if not details["key_path"].casefold().startswith(mount.casefold()):
            raise ValueError("unexpected registry mount")
        path = details["key_path"][len(mount) :]
    name = details["value_name"] if family in {"recent_docs_mru", "run_keys"} else ""
    return family, path, name, tuple(details.get(key) for key in fields)


def add(table, path, name, values):
    # JSON preserves data types and supplies a hashable token for a multiset.
    table[path.casefold(), name.casefold()][json.dumps(values, ensure_ascii=True)] += 1


def summarize(left, right):
    counts = dict(matched=0, differing=0, rapid_only=0, reference_only=0)
    for key in left.keys() | right.keys():
        rapid, reference = left.get(key, Counter()), right.get(key, Counter())
        matches = (rapid & reference).total()
        pairs = min(rapid.total(), reference.total())
        counts["matched"] += matches
        counts["differing"] += pairs - matches
        counts["rapid_only"] += rapid.total() - pairs
        counts["reference_only"] += reference.total() - pairs
    return counts


def is_hive(parts):
    return (
        len(parts) == 4
        and parts[0] in {"windows", "winnt"}
        and parts[1:3] == ("system32", "config")
        and parts[-1] in {"system", "software", "sam"}
    ) or (
        len(parts) == 3
        and parts[0] in {"users", "documents and settings"}
        and parts[-1] == "ntuser.dat"
    )


def directories(parent, names=()):
    for entry in parent.iterdir():
        if (
            (not names or entry.name.casefold() in names)
            and not entry.is_symlink()
            and entry.is_dir()
        ):
            yield entry


def discover(root):
    # Search both case spellings without relying on case-insensitive host paths.
    files = {}
    for top in directories(
        root, {"windows", "winnt", "users", "documents and settings"}
    ):
        if top.name.casefold() in {"windows", "winnt"}:
            folders = (
                config
                for sysdir in directories(top, {"system32"})
                for config in directories(sysdir, {"config"})
            )
        else:
            folders = directories(top)
        candidates = (entry for folder in folders for entry in folder.iterdir())
        for p in candidates:
            parts = tuple(c.casefold() for c in p.relative_to(root).parts)
            if (
                is_hive(parts)
                and p.is_file()
                and not p.is_symlink()
                and p.resolve().is_relative_to(root)
            ):
                if parts in files:
                    raise ValueError("ambiguous case-insensitive hive path")
                files[parts] = p
    return files


def rapid_tables(run):
    tables = defaultdict(lambda: defaultdict(Counter))
    digests = defaultdict(set)
    parser_errors = {}
    statuses = {}
    for provider in ("windows-os-account", "windows-registry"):
        head = run / "artifacts" / f"rapidtriage-artifacts-{provider}.json"
        payload = json.loads(head.read_text(encoding="utf-8"))
        source_root = Path(payload["root"])
        parser_errors[provider] = payload["summary"]["parser_error_count"]
        statuses[provider] = payload["summary"].get("collection_status", "unknown")
        count = 0
        for row in iter_payload_records(payload, payload_path=head, expand=False):
            count += 1
            if (
                row["artifact_type"] not in PROJECTIONS
                and row["artifact_type"] != "registry-hive"
            ):
                continue
            path = Path(row["path"])
            if not path.is_relative_to(source_root):
                raise ValueError(f"row outside the {provider} source root")
            parts = tuple(c.casefold() for c in path.relative_to(source_root).parts)
            if not is_hive(parts):
                continue
            if row.get("profile_ref"):
                row = expand_profile(
                    row, payload["artifact_type_profiles"], copy_templates=False
                )
            digests[parts].add(row["details"].get("source_hashes", {}).get("sha256"))
            if (
                row["artifact_type"] != "registry-hive"
                and (result := project(row)) is not None
            ):
                family, key, name, values = result
                add(tables[parts, family], key, name, values)
        if count != payload["summary"]["artifact_count"] or count != payload.get(
            "record_count", count
        ):
            raise ValueError(f"incomplete {provider} row stream")
    return tables, digests, parser_errors, statuses


def compare(run, root):
    from Registry import Registry

    rapid, digests, parser_errors, statuses = rapid_tables(run)
    hives = discover(root.resolve())
    results = {
        f: Counter(
            matched=0,
            differing=0,
            rapid_only=0,
            reference_only=0,
            compared_hives=0,
            unavailable_hives=0,
        )
        for f in FAMILIES
    }
    errors = Counter()
    diagnostics = Counter()
    for parts in sorted(hives.keys() | digests.keys()):
        families = [f for f, leaves in FAMILIES.items() if parts[-1] in leaves]
        try:
            if parts not in hives:
                raise ValueError("missing reference hive")
            data = hives[parts].read_bytes()
            if parts in digests and digests[parts] != {
                hashlib.sha256(data).hexdigest()
            }:
                raise ValueError("source digest mismatch")
            reader = Registry.Registry(BytesIO(data))
        except Exception as error:
            errors[type(error).__name__] += 1
            for family in families:
                results[family]["unavailable_hives"] += 1
            continue
        for family in families:
            reference = defaultdict(Counter)
            try:
                for key, name, values in reference_rows(reader, family, parts[-1], diagnostics):
                    add(reference, key, name, values)
            except Exception as error:
                errors[type(error).__name__] += 1
                results[family]["unavailable_hives"] += 1
                continue
            results[family].update(summarize(rapid[parts, family], reference))
            results[family]["compared_hives"] += 1
    leaves = {parts[-1] for parts in hives.keys() | digests.keys()}
    for family, counts in results.items():
        counts["missing_hive_types"] = len(set(FAMILIES[family]) - leaves)
        provider = "windows-os-account" if family == "accounts" else "windows-registry"
        counts["provider_parser_errors"] = parser_errors[provider]
        if not counts["compared_hives"]:
            status = "unassessed"
        elif (counts["unavailable_hives"] or counts["missing_hive_types"]
              or counts["provider_parser_errors"] or statuses[provider] != "completed"):
            status = "partial"
        elif not any(
            counts[k] for k in ("matched", "differing", "rapid_only", "reference_only")
        ):
            status = "no-rows"
        else:
            status = "compared"
        results[family] = {**counts, "status": status}
    return {
        "families": results,
        "reference_errors": errors,
        "reference_diagnostics": diagnostics,
        "rapid_parser_errors": parser_errors,
        "rapid_collector_status": statuses,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--hive-root", required=True, type=Path)
    args = parser.parse_args()
    report = compare(args.run, args.hive_root)
    print(json.dumps(report, indent=2))
    incomplete = any(
        row["status"] in {"partial", "unassessed"}
        for row in report["families"].values()
    )
    sys.exit(int(incomplete or any(report["rapid_parser_errors"].values())))
