"""Synthetic run output for the search index tests (no real evidence).

The run has two event log kinds (Security 4624 x2 + System 7045), registry
(key nodes, time zone, a SanDisk USB device), ShellBags (one entry with two
timeline times), a document with metadata, files candidates + inventory,
indicators, the timeline output, and one completed carve analysis.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

DOC_TEXT = "2024년 급여대장 정리본\n직원 급여 지급 내역과 공제 내역을 기록한다.\n급여 대장 원본은 금고에 보관.\n"
EXE_BYTES = b"MZ" + b"\x00" * 62 + b"tool"


def sha(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def write_kind(run_dir: Path, kind: str, rows: list[dict[str, object]], *, profiles: dict[str, object] | None = None) -> Path:
    artifacts = run_dir / "artifacts"
    artifacts.mkdir(exist_ok=True)
    records = artifacts / f"rapidtriage-artifacts-{kind}.jsonl"
    _jsonl(records, rows)
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["artifact_type"])] = counts.get(str(row["artifact_type"]), 0) + 1
    payload: dict[str, object] = {
        "command": "artifacts",
        "kind": kind,
        "summary": {"artifact_count": len(rows), "artifact_type_counts": counts},
        "artifacts": [],
        "record_count": len(rows),
        "records_path": str(records),
        "records_file": records.name,
    }
    if profiles:
        payload["artifact_type_profiles"] = profiles
    path = artifacts / f"rapidtriage-artifacts-{kind}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def build_fixture_run(base: Path, name: str = "run") -> dict[str, object]:
    """Write the run; return ``{run_dir, summary_path, evidence, hashes, ...}``."""
    evidence = base / f"{name}-evidence"
    (evidence / "Users" / "bsh" / "Desktop").mkdir(parents=True)
    (evidence / "Users" / "bsh" / "Downloads").mkdir(parents=True)
    doc_path = evidence / "Users" / "bsh" / "Desktop" / "급여대장.txt"
    doc_path.write_text(DOC_TEXT, encoding="utf-8")
    exe_path = evidence / "Users" / "bsh" / "Downloads" / "AnyDesk.exe"
    exe_path.write_bytes(EXE_BYTES)
    deleted_path = evidence / "Users" / "bsh" / "Desktop" / "old.docx"
    mismatch_path = evidence / "Users" / "bsh" / "Desktop" / "photo.jpg"
    evtx_path = evidence / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    system_evtx = evidence / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx"
    hive = evidence / "Windows" / "System32" / "config" / "SYSTEM"
    usrclass = evidence / "Users" / "bsh" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    doc_hashes = sha(doc_path.read_bytes())
    exe_hashes = sha(EXE_BYTES)
    run_dir = base / name
    run_dir.mkdir()
    outputs: dict[str, str] = {}

    files = {
        "command": "files",
        "candidates": [
            {"path": str(doc_path), "name": doc_path.name, "extension": ".txt", "size": len(doc_path.read_bytes()), "categories": ["documents"], "hashes": doc_hashes},
            {"path": str(exe_path), "name": "AnyDesk.exe", "extension": ".exe", "size": len(EXE_BYTES), "categories": ["executables"], "hashes": exe_hashes,
             "file_signature": {"detected": "windows-pe", "mismatch": False}, "fs_created_at": "2025-05-28T11:00:00+00:00"},
            {"path": str(deleted_path), "name": "old.docx", "extension": ".docx", "size": 2048, "categories": ["documents"], "deletion_state": "deleted"},
            {"path": str(mismatch_path), "name": "photo.jpg", "extension": ".jpg", "size": 5000000, "categories": ["images"],
             "file_signature": {"detected": "windows-pe", "mismatch": True}},
        ],
        "inventory": [
            {"path": str(evtx_path), "name": "Security.evtx", "extension": ".evtx", "size": 69632, "categories": ["other"], "inventory_only": True},
        ],
    }
    outputs["files"] = str(run_dir / "rapidtriage-files.json")
    Path(outputs["files"]).write_text(json.dumps(files, ensure_ascii=False), encoding="utf-8")

    docs = {"command": "docs", "candidates": [{"path": str(doc_path), "kind": "txt", "size": len(doc_path.read_bytes()), "text_status": "ok", "matched": True}], "results": []}
    outputs["docs"] = str(run_dir / "rapidtriage-docs.json")
    Path(outputs["docs"]).write_text(json.dumps(docs, ensure_ascii=False), encoding="utf-8")

    profile = {"eventlog-event": {"details": {"provider_name": "Microsoft-Windows-Security-Auditing", "parser": "windows-eventlog-evtx-native"}}}
    eventlog_rows = [
        {
            "provider": "windows-eventlog", "artifact_type": "eventlog-event", "path": str(evtx_path), "profile_ref": "eventlog-event",
            "details": {"event_id": "4624", "record_id": "11", "channel": "Security", "computer": "진료실1", "user_name": "bsh",
                        "target_user_name": "bsh", "target_user_sid": "S-1-5-21-1-2-3-1001", "event_message": "An account successfully logged on.",
                        "event_data": {"TargetUserName": "bsh", "LogonType": "10", "IpAddress": "10.1.2.3", "WorkstationName": "-"}},
        },
        {
            "provider": "windows-eventlog", "artifact_type": "eventlog-event", "path": str(evtx_path), "profile_ref": "eventlog-event",
            "details": {"event_id": "4624", "record_id": "12", "channel": "Security", "computer": "진료실1", "user_name": "SYSTEM",
                        "target_user_name": "SYSTEM", "event_message": "An account successfully logged on.",
                        "event_data": {"TargetUserName": "SYSTEM", "LogonType": "5"}},
        },
        {
            "provider": "windows-eventlog", "artifact_type": "eventlog-event", "path": str(system_evtx),
            "details": {"event_id": "7045", "record_id": "3", "channel": "System", "provider_name": "Service Control Manager", "computer": "진료실1",
                        "event_message": "A service was installed in the system.", "event_data": {"ServiceName": "AnyDeskSvc", "ImagePath": "C:\\Program Files\\AnyDesk\\AnyDesk.exe"}},
        },
        {
            "provider": "windows-eventlog", "artifact_type": "eventlog-detection", "path": str(evtx_path),
            "details": {"event_id": "4624", "detection": "remote-logon", "event_message": "원격 로그온 탐지"},
        },
    ]
    outputs["artifacts_eventlog"] = str(write_kind(run_dir, "eventlog", eventlog_rows, profiles=profile))

    registry_rows = [
        {"provider": "windows-registry", "artifact_type": "registry-key-tree-node", "path": str(hive),
         "details": {"key_path": "HKLM\\SYSTEM\\ControlSet001\\Services\\AnyDeskSvc", "name": "AnyDeskSvc", "value_names": ["ImagePath", "Start"]}},
        {"provider": "windows-registry", "artifact_type": "windows-timezone", "path": str(hive),
         "details": {"key_path": "HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation", "time_zone_key_name": "Korea Standard Time", "utc_offset": "+09:00", "utc_offset_minutes": 540}},
        {"provider": "windows-registry", "artifact_type": "windows-usb-device", "path": str(hive),
         "details": {"key_path": "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra", "vendor": "SanDisk", "product": "Ultra", "serial_number": "4C530001231231109142"}},
    ]
    outputs["artifacts_windows-registry"] = str(write_kind(run_dir, "windows-registry", registry_rows))

    shellbag_rows = [
        {"provider": "windows-shellbags", "artifact_type": "shellbag-entry", "path": str(usrclass),
         "details": {"shell_path": "C:\\Users\\bsh\\Desktop\\급여대장", "key_path": "HKU\\S-1-5-21-1-2-3-1001_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0", "user_sid": "S-1-5-21-1-2-3-1001"}},
    ]
    outputs["artifacts_windows-shellbags"] = str(write_kind(run_dir, "windows-shellbags", shellbag_rows))

    doc_rows = [
        {"provider": "generic-documents", "artifact_type": "document-metadata-risk", "path": str(doc_path),
         "details": {"source_path": str(doc_path), "author": "김경리", "last_modified_by": "박원장", "template": "Normal.dotm", "source_hashes": doc_hashes}},
    ]
    outputs["artifacts_generic-documents"] = str(write_kind(run_dir, "generic-documents", doc_rows))

    timeline_events = [
        {"timestamp": "2025-05-28T10:30:00+00:00", "timestamp_kind": "event", "source": "artifacts", "details": {"source_record": {"output": "artifacts_eventlog", "row_index": 0}}},
        {"timestamp": "2025-05-28T15:00:00+00:00", "timestamp_kind": "event", "source": "artifacts", "details": {"source_record": {"output": "artifacts_eventlog", "row_index": 1}}},
        {"timestamp": "2025-05-28T11:05:00+00:00", "timestamp_kind": "event", "source": "artifacts", "details": {"source_record": {"output": "artifacts_eventlog", "row_index": 2}}},
        {"timestamp": "2025-05-20T01:00:00+00:00", "timestamp_kind": "last-written", "source": "artifacts", "details": {"source_record": {"output": "artifacts_windows-registry", "row_index": 0}}},
        {"timestamp": "2025-05-26T12:48:04+00:00", "timestamp_kind": "last-arrival", "labels": ["last-arrival", "last-written"], "source": "artifacts",
         "details": {"source_record": {"output": "artifacts_windows-registry", "row_index": 2}}},
        {"timestamp": "2025-05-27T00:10:00+00:00", "timestamp_kind": "item-created", "source": "artifacts", "details": {"source_record": {"output": "artifacts_windows-shellbags", "row_index": 0}}},
        {"timestamp": "2025-05-28T10:40:00+00:00", "timestamp_kind": "item-accessed", "source": "artifacts", "details": {"source_record": {"output": "artifacts_windows-shellbags", "row_index": 0}}},
    ]
    outputs["timeline"] = str(run_dir / "rapidtriage-timeline.json")
    Path(outputs["timeline"]).write_text(
        json.dumps({"command": "timeline", "summary": {"timezone": {"evidence_timezone": {"name": "Korea Standard Time", "bias_minutes": -540}}}, "events": timeline_events}, ensure_ascii=False),
        encoding="utf-8",
    )

    indicators = {"command": "indicators", "indicators": [{"type": "sha256", "value": exe_hashes["sha256"], "count": 1, "classification": "hash"}, {"type": "url", "value": "https://download.anydesk.com/AnyDesk.exe", "count": 1}]}
    outputs["indicators"] = str(run_dir / "rapidtriage-indicators.json")
    Path(outputs["indicators"]).write_text(json.dumps(indicators, ensure_ascii=False), encoding="utf-8")

    carve_hash = hashlib.sha256(b"carved-jpeg").hexdigest()
    write_analysis(run_dir, "20251013T000000-aaaaaaaa", "carve", [
        {"artifact_type": "carve-row", "path": str(evidence / "blob.bin"), "details": {"signature_kind": "jpeg", "offset": 100, "sha256": carve_hash, "source_path": str(evidence / "blob.bin")}},
        {"artifact_type": "carve-row", "path": str(evidence / "blob.bin"), "details": {"signature_kind": "png", "offset": 900, "sha256": hashlib.sha256(b"carved-png").hexdigest()}},
    ])

    summary_path = run_dir / "rapidtriage-run-summary.json"
    summary = {
        "profile_version": "rapidtriage-run-summary-v1",
        "mode": "hacking",
        "root": str(evidence),
        "scan_scope_root": str(evidence),
        "output_dir": str(run_dir),
        "source": {"type": "folder", "source_path": str(evidence), "analysis_root": str(evidence)},
        "outputs": outputs,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    return {
        "run_dir": run_dir,
        "summary_path": summary_path,
        "summary": summary,
        "evidence": evidence,
        "doc_hashes": doc_hashes,
        "exe_hashes": exe_hashes,
        "carve_hash": carve_hash,
    }


def write_analysis(run_dir: Path, analysis_id: str, kind: str, rows: list[dict[str, object]], *, status: str = "completed") -> Path:
    directory = run_dir / "analyses" / analysis_id
    directory.mkdir(parents=True)
    _jsonl(directory / "rows.jsonl", rows)
    state = {
        "version": "analysis-state-v1",
        "analysis_id": analysis_id,
        "kind": kind,
        "status": status,
        "row_count": len(rows),
        "created_at": "2025-10-13T00:00:00+00:00",
        "finished_at": "2025-10-13T00:00:01+00:00",
        "summary": {},
    }
    (directory / "analysis.json").write_text(json.dumps(state), encoding="utf-8")
    return directory


# Primary documents of the fixture: docs 1 + files 4 + inventory 1 + eventlog 4 + registry 3
# + shellbags 1 + generic-documents 1 + indicators 2 + carve rows 2.
EXPECTED_DOCS = 19
