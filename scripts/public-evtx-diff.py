"""Compare retained event collector rows with python-evtx on selected Windows channels."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rapidtriage.core.artifact_profiles import (
    iter_payload_records,
    payload_record_count,
)

LOGS = Path("Windows/System32/winevt/Logs")
CHANNELS = {
    "security",
    "system",
    "windows powershell",
    "microsoft-windows-powershell%4operational",
    "microsoft-windows-partition%4diagnostic",
    "microsoft-windows-kernel-pnp%4configuration",
    "microsoft-windows-driverframeworks-usermode%4operational",
}
FAMILIES = ("logon", "logoff", "service-install", "powershell", "usb", "other")
SYSTEM_FIELDS = (
    "record_id",
    "event_id",
    "provider_name",
    "channel",
    "computer",
    "timestamp",
)
PAYLOAD_FIELDS = {
    "logon": ("TargetUserName", "TargetLogonId", "LogonType"),
    "logoff": ("TargetUserName", "TargetLogonId", "LogonType", "SubjectLogonId"),
    "service-install": ("ServiceName", "ImagePath", "ServiceFileName"),
    "powershell": ("ScriptBlockText", "Payload"),
    "usb": ("DeviceInstanceId", "InstanceId", "DeviceId", "ParentId", "BusType"),
}
USB_FIELDS = ("DeviceInstanceId", "InstanceId", "DeviceId", "ParentId")
DATA_KEYS = {key for keys in PAYLOAD_FIELDS.values() for key in keys}


def selected(path):
    stem = path.stem.casefold()
    return path.suffix.casefold() == ".evtx" and (
        stem in CHANNELS or stem.startswith("microsoft-windows-usb-")
    )


def family(fields):
    channel = fields.get("channel", "").casefold()
    provider = fields.get("provider_name", "").casefold()
    event = fields.get("event_id", "")
    if channel == "security" and provider == "microsoft-windows-security-auditing":
        if event in {"4624", "4625"}:
            return "logon"
        if event in {"4634", "4647"}:
            return "logoff"
        if event == "4697":
            return "service-install"
    if (
        channel == "system"
        and provider == "service control manager"
        and event == "7045"
    ):
        return "service-install"
    if channel in {"windows powershell", "microsoft-windows-powershell/operational"}:
        return "powershell"
    if channel.startswith("microsoft-windows-usb-") or provider.startswith(
        "microsoft-windows-usb-"
    ):
        return "usb"
    if channel in {
        "microsoft-windows-partition/diagnostic",
        "microsoft-windows-kernel-pnp/configuration",
        "microsoft-windows-driverframeworks-usermode/operational",
        "security",
        "system",
    }:
        if fields.get("BusType") == ("7",) or any(
            value.upper().startswith(("USB\\", "USBSTOR\\"))
            for k in USB_FIELDS
            for value in fields.get(k, ())
        ):
            return "usb"
    return "other"


def timestamp(value):
    if not value:
        return ""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("EVTX timestamp has no offset")
    return parsed.astimezone(timezone.utc)


def xml_fields(record):
    system = record.find("{*}System")
    if system is None:
        raise ValueError("missing event System")
    fields = {
        "record_id": system.findtext("{*}EventRecordID", ""),
        "event_id": system.findtext("{*}EventID", ""),
        "channel": system.findtext("{*}Channel", ""),
        "computer": system.findtext("{*}Computer", ""),
    }
    provider = system.find("{*}Provider")
    fields["provider_name"] = provider.get("Name", "") if provider is not None else ""
    created = system.find("{*}TimeCreated")
    fields["timestamp"] = (
        timestamp(created.get("SystemTime")) if created is not None else ""
    )
    data = defaultdict(list)
    for element in record.findall("{*}EventData/{*}Data"):
        key = element.get("Name")
        if key in DATA_KEYS:
            data[key].append(element.text or "")
    for element in record.iterfind("{*}UserData//*"):
        key = element.tag.rsplit("}", 1)[-1]
        if key in DATA_KEYS and not len(element):
            data[key].append(element.text or "")
    fields.update({key: tuple(values) for key, values in data.items()})
    return fields


def rapid_fields(details):
    fields = {key: str(details.get(key) if details.get(key) is not None else "") for key in SYSTEM_FIELDS}
    fields["timestamp"] = timestamp(fields["timestamp"])
    fields["record_state"] = details.get("evtx_record_state") or "unknown"
    data = details.get("event_data", details.get("binxml_event_data_fields", {}))
    for key in DATA_KEYS.intersection(data):
        value = data[key]
        fields[key] = (
            tuple(map(str, value)) if isinstance(value, list) else (str(value),)
        )
    return fields


def compare(rows, references, counts):
    for offset in rows.keys() | references.keys():
        left, right = rows.get(offset, []), references.get(offset, [])
        if len(left) > 1 or len(right) > 1 or not (left and right):
            for side, entries in (("rapid", left), ("reference", right)):
                status = "ambiguous" if left and right else "only"
                for fields in entries:
                    counter = counts[family(fields)]
                    counter[f"{side}_{status}"] += 1
                    if side == "rapid" and status == "only":
                        counter[f"rapid_only_state.{fields['record_state']}"] += 1
            continue
        actual, expected = left[0], right[0]
        group = family(expected)
        counter = counts[group]
        counter["paired"] += 1
        matched = True
        for key in (*SYSTEM_FIELDS, *PAYLOAD_FIELDS.get(group, ())):
            if key in SYSTEM_FIELDS:
                status = (
                    "missing" if not actual[key] or not expected[key] else "compared"
                )
            else:
                status = (
                    "compared" if key in actual or key in expected else "absent_both"
                )
            if status == "compared":
                left_value, right_value = actual.get(key), expected.get(key)
                if key == "timestamp":
                    delta_us = abs(left_value - right_value) // timedelta(microseconds=1)
                    if 0 < delta_us < 1000:
                        counter["timestamp.sub_ms_difference"] += 1
                    left_value = left_value.isoformat(timespec="milliseconds")
                    right_value = right_value.isoformat(timespec="milliseconds")
                    if left_value != right_value:
                        counter["timestamp.max_mismatch_delta_us"] = max(counter["timestamp.max_mismatch_delta_us"], delta_us)
                status = "match" if left_value == right_value else "mismatch"
                if status == "mismatch" and key in {"ScriptBlockText", "Payload"} and left_value and right_value:
                    xml_text = tuple(s.replace("\r\n", "\n").replace("\r", "\n") for s in left_value)
                    if xml_text == right_value:
                        counter[f"{key}.same_after_xml_newline_normalization"] += 1
                if (status == "mismatch" and key in {"TargetLogonId", "SubjectLogonId"}
                        and left_value and right_value):
                    try:
                        a = tuple(int(text, 0) for text in left_value)
                        b = tuple(int(text, 0) for text in right_value)
                    except ValueError:
                        pass
                    else:
                        if a == b:
                            counter[f"{key}.same_integer_different_text"] += 1
            counter[f"{key}.{status}"] += 1
            matched &= status in {"match", "absent_both"}
        counter["matched" if matched else "mismatched_or_missing"] += 1


def reference_rows(path, errors):
    from Evtx.Evtx import Evtx

    rows = defaultdict(list)
    unreadable = set()
    with Evtx(str(path)) as log:
        header = log.get_file_header()
        if not header.check_magic():
            raise ValueError("invalid EVTX file signature")
        chunks_read = 0
        for chunk in log.chunks():
            chunks_read += 1
            if not chunk.check_magic():
                errors["invalid_chunk_header"] += 1
                continue
            # The upstream iterator can end early on an invalid record size.
            # Compare its final cursor with the chunk's declared end of data.
            cursor = chunk.offset() + 512
            for record in chunk.records():
                cursor = record.offset() + record.length()
                try:
                    if record.magic() != 0x2A2A or not record.verify():
                        raise ValueError("invalid record header or length")
                    fields = xml_fields(ET.fromstring(record.xml()))
                except Exception as exc:
                    errors[type(exc).__name__] += 1
                    unreadable.add(record.offset())
                else:
                    rows[record.offset()].append(fields)
            if cursor != chunk.offset() + chunk.next_record_offset():
                errors["chunk_end_disagreement"] += 1
        if chunks_read != header.chunk_count():
            errors["missing_declared_chunks"] += header.chunk_count() - chunks_read
    return rows, unreadable


def compare_run(run, reference_logs=None):
    head = run / "artifacts/rapidtriage-artifacts-eventlog.json"
    payload = json.loads(head.read_text(encoding="utf-8"))
    logs = Path(payload["root"]) / LOGS
    ref_dir = reference_logs or logs
    paths = [p for p in ref_dir.iterdir() if p.is_file() and selected(p)]
    sources = {p.name.casefold(): p for p in paths}
    if len(sources) != len(paths):
        raise ValueError("ambiguous reference filenames")
    rapid = defaultdict(lambda: defaultdict(list))
    hashes = {}
    audit = Counter()
    for row in iter_payload_records(payload, payload_path=head):
        audit["collector_rows_read"] += 1
        path = Path(row["path"])
        if (
            not selected(path)
            or path.parent.as_posix().casefold() != logs.as_posix().casefold()
        ):
            continue
        name = path.name.casefold()
        details = row["details"]
        if row["artifact_type"] == "eventlog-file":
            if name in hashes:
                raise ValueError("duplicate EVTX file inventory")
            hashes[name] = details["source_hashes"]["sha256"]
        elif row["artifact_type"] == "eventlog-event":
            offset = details.get("evtx_record_offset")
            if type(offset) is not int or offset < 0:
                audit["rapid_unlocatable_events"] += 1
            else:
                rapid[name][offset].append(rapid_fields(details))
        else:
            audit[f"excluded_{row['artifact_type']}"] += 1
    expected_rows = payload_record_count(payload)
    if (
        audit["collector_rows_read"] != expected_rows
        or payload["summary"].get("artifact_count", expected_rows) != expected_rows
    ):
        raise ValueError("incomplete eventlog collector stream")
    counts = {kind: Counter() for kind in FAMILIES}
    files = {}
    for name in sorted(sources.keys() | hashes.keys() | rapid.keys()):
        rows = rapid[name]
        ref = {}
        errors = Counter()
        info = {
            "rapid_events": sum(map(len, rows.values())),
            "reference_errors": errors,
        }
        files[name] = info
        if name not in sources:
            info["file_status"] = "rapid-only-file"
        else:
            with sources[name].open("rb") as source:
                digest = hashlib.sha256()
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            info["reference_sha256"] = digest.hexdigest()
            if name in hashes and digest.hexdigest() != hashes[name]:
                raise ValueError(
                    f"EVTX reference bytes differ from Rapid file inventory for {name}"
                )
            if rows and name not in hashes:
                raise ValueError(f"missing source digest for retained events in {name}")
            info["file_status"] = (
                "verified" if name in hashes else "reference-only-file"
            )
            try:
                ref, unreadable = reference_rows(sources[name], errors)
            except ImportError:
                raise
            except Exception as exc:
                errors[f"file.{type(exc).__name__}"] += 1
                info["file_status"] = "reference-unreadable"
                info["reference_file_error"] = str(exc)[:300]
                continue
            info["rapid_rows_at_unreadable_reference_offsets"] = sum(
                len(rows.pop(offset, [])) for offset in unreadable
            )
        info["reference_decoded"] = sum(map(len, ref.values()))
        compare(rows, ref, counts)
    issues = []
    if not sources:
        issues.append("no selected reference log files")
    if any(info["reference_errors"] for info in files.values()):
        issues.append("reference parser errors (see files)")
    if payload["summary"]["collection_status"] != "completed" or payload["summary"]["parser_error_count"]:
        issues.append("incomplete Rapid collector (see collector status and parser errors)")
    if audit["rapid_unlocatable_events"]:
        issues.append("Rapid event rows lack a usable byte offset")
    return {
        "engineering_check_only": True,
        "comparison_status": "incomplete" if issues else "completed",
        "issues": issues,
        "collector_status": payload["summary"]["collection_status"],
        "collector_parser_errors": payload["summary"]["parser_error_count"],
        "audit": audit,
        "files": files,
        "families": counts,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument(
        "--reference-logs",
        type=Path,
        help="canonical Logs directory independently exported from the image",
    )
    args = parser.parse_args(argv)
    try:
        report = compare_run(args.run, args.reference_logs)
    except (OSError, ImportError, KeyError, TypeError, ValueError) as exc:
        report = {
            "engineering_check_only": True,
            "comparison_status": "incomplete",
            "issues": [f"{type(exc).__name__}: {exc}"],
        }
    print(json.dumps(report, indent=2))
    return int(report["comparison_status"] != "completed")


if __name__ == "__main__":
    raise SystemExit(main())
