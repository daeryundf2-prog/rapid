from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.eventlog import (
    binxml_value_field_map,
    build_evtx_message_rendering_diff,
    build_evtx_recovery_corpus_diff,
    build_evtx_trusted_tool_record_diff,
    event_semantics_profile,
    NativeEvtxRecordCandidate,
    native_evtx_commercial_uplift_evidence,
    native_evtx_core_accuracy_gates,
    native_evtx_promoted_fields,
    native_evtx_record_candidate_record,
    parse_native_evtx_binxml,
    render_event_message,
)
from rapidtriage.artifacts.windows.execution import (
    build_execution_artifact_trusted_diff,
    collect_amcache_candidate_clusters,
    collect_bam_dam_candidate_clusters,
    collect_shimcache_candidate_clusters,
    iter_registry_like_string_occurrences,
)
from rapidtriage.artifacts.windows.registry import (
    build_registry_deleted_cell_diff,
    build_registry_key_tree_diff,
    collect_reg_export,
    collect_registry_hive,
    registry_analyst_review_profile,
)
from rapidtriage.artifacts.windows.filesystem import (
    build_mft_bounded_path_cache,
    build_native_mft_record,
    build_native_usn_record,
    mft_bounded_path_cache_profile,
    build_mft_trusted_diff,
    build_usn_state_replay_trusted_diff,
    build_usn_trusted_diff,
    decode_mft_runlist,
    ntfs_core_accuracy_gates,
    parse_mft_attribute,
    parse_usn_record_at,
    parse_usn_record_scan,
    usn_bounded_mft_replay_preview,
    usn_bounded_state_replay_preview,
    usn_delete_lifecycle_preview,
    usn_path_reliability_profile,
    usn_rename_pair_preview,
    usn_replay_inventory_profile,
    usn_state_replay_validation_profile,
    usn_timeline_review_candidates,
)
from rapidtriage.artifacts.windows.browser import (
    ai_transcript_core_accuracy_gates,
    ai_transcript_commercial_uplift_evidence,
    browser_core_accuracy_gates,
    build_ai_transcript_trusted_diff,
    build_browser_storage_trusted_diff,
    build_browser_timeline_trusted_diff,
)
from rapidtriage.artifacts.windows.prefetch import (
    build_prefetch_trusted_diff,
    prefetch_core_accuracy_gates,
    prefetch_header_hints,
)
from rapidtriage.artifacts.windows.recent_files import (
    build_jumplist_trusted_diff,
    build_lnk_trusted_diff,
    jumplist_core_accuracy_gates,
    lnk_core_accuracy_gates,
    parse_destlist_metadata,
    parse_lnk_extra_data,
)
from rapidtriage.artifacts.windows.search_index import (
    build_search_row_candidates,
    build_windows_edb_trusted_diff,
    windows_search_core_accuracy_gates,
)
from rapidtriage.artifacts.windows.srum_ese import build_srum_row_candidates
from rapidtriage.artifacts.windows.os_account import decode_sam_binary_field
from rapidtriage.artifacts.windows.os_account import build_os_account_trusted_diff
from rapidtriage.artifacts.windows.shellbags import (
    WindowsShellbagsProvider,
    build_shellbag_trusted_diff,
    shellbag_core_accuracy_gates,
)
from rapidtriage.artifacts.windows.system import build_system_trusted_diff, system_core_accuracy_gates
from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_minimal_registry_hive, build_minimal_shellbags_registry_hive

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


class RapidTriageWindowsArtifactsCollectorTests(unittest.TestCase):
    def test_native_evtx_binxml_decodes_misc_text_tokens(self) -> None:
        def counted_utf16(text: str) -> bytes:
            return len(text).to_bytes(2, "little") + text.encode("utf-16le")

        payload = (
            b"\x0f\x01\x01\x00"
            + b"\x07"
            + counted_utf16("literal")
            + b"\x08"
            + ord("&").to_bytes(2, "little")
            + b"\x0b"
            + counted_utf16("pi-data")
            + b"\x00"
        )

        parsed = parse_native_evtx_binxml(payload)

        self.assertEqual(parsed["status"], "basic-rendered")
        values = {item["value_type"]: item for item in parsed["value_fields"]}
        self.assertEqual(values["CDataSection"]["text"], "literal")
        self.assertEqual(values["CharacterReference"]["text"], "&")
        self.assertEqual(values["ProcessingInstructionData"]["text"], "pi-data")
        self.assertIn("CDataSectionToken", {item["value"] for item in parsed["token_counts"]})
        self.assertEqual(parsed["unsupported_token_count"], 0)

    def test_evtx_message_catalog_renders_positional_manifest_placeholders(self) -> None:
        rendering = render_event_message(
            provider_name="Microsoft-Windows-Security-Auditing",
            event_id="4624",
            category="logon-success",
            data={
                "binxml_event_data_sequence": [
                    {"name": "TargetUserName", "value": "alice"},
                    {"name": "IpAddress", "value": "10.0.0.5"},
                ]
            },
            raw_preview="",
            is_native_evtx=True,
            message_catalog={
                "microsoftwindowssecurityauditing": {
                    "4624": {
                        "message": "User %1 logged on from %2.",
                        "source_type": "windows-event-manifest",
                    }
                }
            },
        )

        self.assertEqual(rendering["message"], "User alice logged on from 10.0.0.5.")
        self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
        self.assertEqual(rendering["missing_fields"], [])
        self.assertEqual(
            [item["field"] for item in rendering["used_fields"]],
            ["positional[1]", "positional[2]"],
        )
        self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])

    def test_event_semantics_profile_preserves_analyst_pivots_and_validation_steps(self) -> None:
        profile = event_semantics_profile(
            event_id="4688",
            provider_name="Microsoft-Windows-Security-Auditing",
            channel="Security",
            category="process-created",
            event_family="execution",
            channel_family_value="security",
            data={
                "NewProcessName": r"C:\Windows\System32\certutil.exe",
                "CommandLine": "certutil -urlcache -split -f http://example.invalid/a.exe a.exe",
                "ParentProcessName": r"C:\Windows\explorer.exe",
            },
            normalized_fields={
                "new_process_name": r"C:\Windows\System32\certutil.exe",
                "command_line": "certutil -urlcache -split -f http://example.invalid/a.exe a.exe",
                "parent_process_name": r"C:\Windows\explorer.exe",
                "user_name": "alice",
            },
            detected_terms=["certutil"],
            risk_flags=["suspicious-term:certutil"],
            is_native_evtx=True,
        )

        self.assertEqual(profile["profile_version"], "eventlog-analyst-semantics-v1")
        self.assertEqual(profile["severity"], "medium")
        self.assertIn("Prefetch", " ".join(profile["analyst_questions"]))
        self.assertIn("mft-usn", profile["correlation_targets"])
        self.assertEqual(profile["source_field_values"]["command_line"], "certutil -urlcache -split -f http://example.invalid/a.exe a.exe")
        self.assertIn("content-risk-term", profile["risk_tags"])
        self.assertIn("attach trusted EVTX parser diff", profile["validation_requirements"][0])

    def test_native_evtx_recovery_candidate_emits_report_citation_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "Security.evtx"
            path.write_bytes(b"fixture")
            record_blob = (
                b"**\x00\x00"
                + (80).to_bytes(4, "little")
                + (42).to_bytes(8, "little")
                + (0).to_bytes(8, "little")
                + b"A" * 20
                + (64).to_bytes(4, "little")
            )
            candidate = NativeEvtxRecordCandidate(
                offset=0x2000,
                declared_size=80,
                record_blob=record_blob,
                parseable=False,
                reason="record-size-exceeds-available",
                available_size=len(record_blob),
            )

            artifact = native_evtx_record_candidate_record(
                path,
                0,
                {"sha256": "a" * 64},
                b"\x00" * 0x3000,
                candidate,
            )

        manifest = artifact.details["evtx_recovery_report_citation_manifest"]
        self.assertEqual(manifest["manifest_version"], "evtx-recovery-report-citation-manifest-v1")
        self.assertEqual(manifest["artifact_type"], "eventlog-record-candidate")
        self.assertEqual(manifest["row_identity"]["record_offset"], 0x2000)
        self.assertEqual(manifest["row_identity"]["candidate_reason"], "record-size-exceeds-available")
        self.assertEqual(manifest["reportability"]["allowed_use"], "evtx-recovery-triage-pivot-only")
        self.assertFalse(manifest["reportability"]["ready_for_court_report"])
        self.assertIn("known-answer-corpus-validation-required", manifest["reportability"]["blockers"])
        self.assertEqual(artifact.details["evtx_recovery_report_citation_manifest_hash"], manifest["manifest_sha256"])
        locator = manifest["citation_refs"][0]["source_viewer_locator"]
        self.assertEqual(locator["mode"], "evtx-recovery-record-candidate")
        self.assertEqual(locator["offset"], 0x2000)

    def test_mft_nonresident_runlist_preview_decodes_runs_and_sparse_segments(self) -> None:
        runlist = bytes([0x11, 0x03, 0x05, 0x21, 0x02, 0x01, 0x00, 0x01, 0x04, 0x00])

        decoded = decode_mft_runlist(runlist)

        self.assertEqual(decoded["status"], "decoded-preview")
        self.assertEqual(decoded["run_count"], 3)
        self.assertEqual(decoded["terminator_offset"], 9)
        self.assertEqual(decoded["runs"][0]["cluster_count"], 3)
        self.assertEqual(decoded["runs"][0]["absolute_lcn"], 5)
        self.assertEqual(decoded["runs"][1]["absolute_lcn"], 6)
        self.assertTrue(decoded["runs"][2]["sparse"])

        attribute = bytearray(0x40 + len(runlist))
        attribute[0:4] = (0x80).to_bytes(4, "little")
        attribute[4:8] = len(attribute).to_bytes(4, "little")
        attribute[8] = 1
        attribute[14:16] = (7).to_bytes(2, "little")
        attribute[24:32] = (8).to_bytes(8, "little")
        attribute[32:34] = (0x40).to_bytes(2, "little")
        attribute[40:48] = (4096 * 9).to_bytes(8, "little")
        attribute[48:56] = (4096 * 9).to_bytes(8, "little")
        attribute[56:64] = (4096 * 9).to_bytes(8, "little")
        attribute[0x40:] = runlist

        parsed = parse_mft_attribute(bytes(attribute), 0)

        self.assertEqual(parsed["nonresident_metadata"]["runlist_decode_status"], "decoded-preview")
        self.assertEqual(parsed["data"]["runlist_decode_status"], "decoded-preview")
        self.assertEqual(parsed["data"]["runlist_preview"][0]["absolute_lcn"], 5)
        self.assertTrue(parsed["data"]["runlist_preview"][2]["sparse"])

    def test_mft_attribute_list_decodes_extension_reference_without_claiming_resolution(self) -> None:
        entry = bytearray(32)
        entry[0:4] = (0x80).to_bytes(4, "little")
        entry[4:6] = (32).to_bytes(2, "little")
        entry[8:16] = (4).to_bytes(8, "little")
        entry[16:24] = ((9 << 48) | 321).to_bytes(8, "little")
        entry[24:26] = (7).to_bytes(2, "little")
        attribute = bytearray(0x18 + len(entry))
        attribute[0:4] = (0x20).to_bytes(4, "little")
        attribute[4:8] = len(attribute).to_bytes(4, "little")
        attribute[14:16] = (4).to_bytes(2, "little")
        attribute[16:20] = len(entry).to_bytes(4, "little")
        attribute[20:22] = (0x18).to_bytes(2, "little")
        attribute[0x18:] = entry

        parsed = parse_mft_attribute(bytes(attribute), 0)

        self.assertEqual(parsed["attribute_list"]["status"], "decoded")
        self.assertFalse(parsed["attribute_list"]["resolved"])
        self.assertEqual(parsed["attribute_list"]["entries"][0]["attribute_type_name"], "$DATA")
        self.assertEqual(parsed["attribute_list"]["entries"][0]["lowest_vcn"], 4)
        self.assertEqual(parsed["attribute_list"]["entries"][0]["extension_reference_decoded"]["record_number"], 321)
        self.assertEqual(parsed["attribute_list"]["entries"][0]["extension_reference_decoded"]["sequence_number"], 9)

    def test_usn_v4_extent_record_preserves_extent_cursor_evidence(self) -> None:
        record = bytearray(80)
        record[0:4] = (80).to_bytes(4, "little")
        record[4:6] = (4).to_bytes(2, "little")
        record[6:8] = (0).to_bytes(2, "little")
        record[8:24] = (0x1234).to_bytes(16, "little")
        record[24:40] = (0x1200).to_bytes(16, "little")
        record[40:48] = (9001).to_bytes(8, "little")
        record[48:52] = (0x00000002 | 0x80000000).to_bytes(4, "little")
        record[52:56] = (0).to_bytes(4, "little")
        record[56:60] = (0).to_bytes(4, "little")
        record[60:62] = (1).to_bytes(2, "little")
        record[62:64] = (16).to_bytes(2, "little")
        record[64:72] = (4096).to_bytes(8, "little")
        record[72:80] = (8192).to_bytes(8, "little")

        parsed = parse_usn_record_at(bytes(record), 0)

        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["major_version"], 4)
        self.assertEqual(parsed["next_record_cursor"], 80)
        self.assertEqual(parsed["file_name_decode_status"], "not-present-usn-v4")
        self.assertEqual(parsed["v4_extent_count"], 1)
        self.assertEqual(parsed["v4_extents"][0]["file_offset"], 4096)
        self.assertEqual(parsed["v4_extents"][0]["byte_length"], 8192)
        self.assertTrue(parsed["validation_checks"]["v4_extent_bounds_valid"])
        self.assertTrue(parsed["validation_checks"]["v4_no_filename_by_design"])

        scan = parse_usn_record_scan(b"\x00\x00" + bytes(record))
        self.assertEqual(scan["first_record_offset"], 2)
        self.assertEqual(scan["records"][0]["major_version"], 4)
        self.assertFalse(scan["next_cursor_available"])

    def test_ntfs_native_records_emit_report_citation_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            mft_path = root / "$MFT"
            usn_path = root / "$J"
            mft_path.write_bytes(b"FILE" + b"\x00" * 4092)
            usn_path.write_bytes(b"\x50\x00\x00\x00" + b"\x00" * 76)
            mft_record = build_native_mft_record(
                mft_path,
                {
                    "record_number_candidate": 42,
                    "record_offset": 4096,
                    "sequence_number": 7,
                    "in_use": True,
                    "attribute_count": 3,
                    "attribute_types": ["$STANDARD_INFORMATION", "$FILE_NAME", "$DATA", "$ATTRIBUTE_LIST"],
                    "standard_information": {"timestamps": {"modified_at": "2026-01-02T03:04:05+00:00"}},
                    "file_name_entries": [
                        {
                            "file_name": "case.txt",
                            "parent_reference_raw": 5,
                            "parent_reference": {"record_number": 5, "sequence_number": 1},
                        }
                    ],
                    "data_attributes": [
                        {
                            "resident": True,
                            "resident_data_hashes": {"sha256": "a" * 64},
                        }
                    ],
                    "attribute_list_entries": [{"attribute_type_name": "$DATA"}],
                    "validation_checks": {
                        "magic_valid": True,
                        "sequence_fixup_valid": True,
                        "has_file_name_attribute": True,
                        "attribute_list_resolution_available": False,
                    },
                },
                0,
            )
            usn_record = build_native_usn_record(
                usn_path,
                {
                    "file_reference_number": 42,
                    "parent_file_reference_number": 5,
                    "file_name": "case.txt",
                    "timestamp": "2026-01-02T03:04:05+00:00",
                    "deleted_hint": True,
                    "rename_hint": "delete",
                    "reason": "FILE_DELETE|CLOSE",
                    "reason_raw": 0x80000200,
                    "reason_flags": ["FILE_DELETE", "CLOSE"],
                    "usn": 9001,
                    "record_cursor": 128,
                    "next_record_cursor": 208,
                    "record_length": 80,
                    "record_offset": 128,
                    "major_version": 4,
                    "v4_extents": [{"file_offset": 4096, "byte_length": 8192}],
                    "validation_checks": {
                        "record_length_aligned": True,
                        "record_cursor_progresses": True,
                        "version_supported": True,
                        "v4_extent_bounds_valid": True,
                    },
                },
                1,
            )

        mft_manifest = mft_record.details["ntfs_report_citation_manifest"]
        usn_manifest = usn_record.details["ntfs_report_citation_manifest"]
        mft_kinds = {item["kind"] for item in mft_manifest["citation_refs"]}
        usn_kinds = {item["kind"] for item in usn_manifest["citation_refs"]}
        self.assertEqual(mft_manifest["manifest_version"], "ntfs-report-citation-manifest-v1")
        self.assertEqual(usn_manifest["manifest_version"], "ntfs-report-citation-manifest-v1")
        self.assertEqual(len(mft_manifest["manifest_sha256"]), 64)
        self.assertEqual(len(usn_manifest["manifest_sha256"]), 64)
        self.assertIn("mft-record-offset", mft_kinds)
        self.assertIn("mft-file-name-attribute", mft_kinds)
        self.assertIn("mft-data-attribute", mft_kinds)
        self.assertIn("mft-attribute-list", mft_kinds)
        self.assertIn("usn-record-cursor", usn_kinds)
        self.assertIn("usn-reason-flags", usn_kinds)
        self.assertIn("usn-rename-delete-timeline-hint", usn_kinds)
        self.assertIn("usn-v4-extent-preview", usn_kinds)
        self.assertEqual(mft_record.details["ntfs_report_citation_manifest_hash"], mft_manifest["manifest_sha256"])
        self.assertEqual(usn_record.details["ntfs_report_citation_manifest_hash"], usn_manifest["manifest_sha256"])
        self.assertFalse(mft_manifest["reportability"]["commercial_grade_ready"])
        self.assertFalse(usn_manifest["reportability"]["commercial_grade_ready"])
        mft_depth = mft_record.details["mft_parser_depth_manifest"]
        self.assertEqual(mft_depth["manifest_version"], "mft-parser-depth-manifest-v1")
        self.assertEqual(mft_depth["gap_id"], "#12")
        self.assertEqual(mft_depth["record_identity"]["record_number"], "42")
        self.assertTrue(mft_depth["usa_validation"]["magic_valid"])
        self.assertTrue(mft_depth["usa_validation"]["sequence_fixup_valid"])
        self.assertTrue(mft_depth["attribute_decoding"]["has_attribute_list"])
        self.assertFalse(mft_depth["attribute_decoding"]["attribute_list_resolution_available"])
        self.assertEqual(
            mft_depth["attribute_decoding"]["attribute_list_resolution_status"],
            "extension-record-resolution-not-implemented",
        )
        self.assertEqual(mft_depth["data_run_decoding"]["resident_data_attribute_count"], 1)
        self.assertFalse(mft_depth["data_run_decoding"]["full_nonresident_runlist_decode_available"])
        self.assertEqual(mft_depth["path_reconstruction"]["parent_record_number"], 5)
        self.assertFalse(mft_depth["path_reconstruction"]["full_volume_path_reconstruction_complete"])
        self.assertEqual(
            mft_depth["reportability"]["allowed_use"],
            "mft-record-structure-and-timestamp-pivot",
        )
        self.assertFalse(mft_depth["reportability"]["commercial_grade_ready"])
        self.assertEqual(
            mft_record.details["mft_parser_depth_manifest_hash"],
            mft_depth["manifest_sha256"],
        )
        usn_depth = usn_record.details["usn_timeline_depth_manifest"]
        self.assertEqual(usn_depth["manifest_version"], "usn-timeline-depth-manifest-v1")
        self.assertEqual(usn_depth["gap_id"], "#13")
        self.assertEqual(usn_depth["record_identity"]["usn"], 9001)
        self.assertTrue(usn_depth["record_layout_validation"]["record_cursor_progresses"])
        self.assertTrue(usn_depth["record_layout_validation"]["version_supported"])
        self.assertIn("FILE_DELETE", usn_depth["change_semantics"]["reason_flags"])
        self.assertEqual(usn_depth["change_semantics"]["transition_class"], "delete")
        self.assertFalse(usn_depth["change_semantics"]["standalone_timeline_fact"])
        self.assertFalse(usn_depth["path_correlation"]["full_frn_path_cache_replay_done"])
        self.assertTrue(usn_depth["cursor_pagination"]["safe_for_cursor_api"])
        self.assertFalse(usn_depth["cursor_pagination"]["large_journal_pagination_validated"])
        self.assertFalse(usn_depth["replay_state"]["full_journal_replay_available"])
        self.assertEqual(
            usn_depth["reportability"]["allowed_use"],
            "usn-change-record-triage-pivot",
        )
        self.assertFalse(usn_depth["reportability"]["commercial_grade_ready"])
        self.assertEqual(
            usn_record.details["usn_timeline_depth_manifest_hash"],
            usn_depth["manifest_sha256"],
        )

    def test_mft_bounded_parent_path_cache_reconstructs_scanned_chain(self) -> None:
        records = [
            {
                "record_number_candidate": 5,
                "sequence_number": 1,
                "directory": True,
                "in_use": True,
                "file_name_entries": [
                    {
                        "file_name": ".",
                        "namespace": "WIN32",
                        "parent_reference": {"record_number": 5, "sequence_number": 1},
                    }
                ],
            },
            {
                "record_number_candidate": 40,
                "sequence_number": 3,
                "directory": True,
                "in_use": True,
                "file_name_entries": [
                    {
                        "file_name": "Users",
                        "namespace": "WIN32",
                        "parent_reference": {"record_number": 5, "sequence_number": 1},
                    }
                ],
            },
            {
                "record_number_candidate": 41,
                "sequence_number": 9,
                "directory": False,
                "in_use": True,
                "file_name_entries": [
                    {
                        "file_name": "case.txt",
                        "namespace": "WIN32",
                        "parent_reference": {"record_number": 40, "sequence_number": 3},
                    }
                ],
            },
            {
                "record_number_candidate": 42,
                "sequence_number": 4,
                "directory": False,
                "in_use": True,
                "file_name_entries": [
                    {
                        "file_name": "outside.txt",
                        "namespace": "WIN32",
                        "parent_reference": {"record_number": 999, "sequence_number": 1},
                    }
                ],
            },
        ]

        cache = build_mft_bounded_path_cache(records)

        self.assertEqual(cache[41]["status"], "reconstructed-bounded-parent-cache")
        self.assertEqual(cache[41]["path"], "\\Users\\case.txt")
        self.assertTrue(cache[41]["complete_within_bounded_scan"])
        self.assertEqual(cache[42]["status"], "partial-parent-outside-bounded-scan")
        self.assertIn("parent-not-in-cache:999", cache[42]["warnings"])
        profile = mft_bounded_path_cache_profile(cache)
        self.assertEqual(profile["profile_version"], "mft-bounded-path-cache-profile-v1")
        self.assertEqual(profile["cache_entry_count"], 4)
        self.assertEqual(profile["complete_path_count"], 3)
        self.assertEqual(profile["partial_path_count"], 1)
        self.assertIn("\\Users\\case.txt", profile["sample_complete_paths"])
        self.assertEqual(profile["sample_partial_paths"][0]["record_number"], 42)
        self.assertEqual(profile["reportability"], "bounded-mft-path-cache-quality-profile")
        self.assertIn("mft-trusted-path-diff-required", profile["blockers"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            mft_path = Path(tmp_dir) / "$MFT"
            mft_path.write_bytes(b"FILE" + b"\x00" * 4092)
            artifact = build_native_mft_record(mft_path, records[2], 2, cache)

        path_profile = artifact.details["mft_path_reconstruction_profile"]
        self.assertEqual(path_profile["source_mode"], "bounded-scan-parent-cache")
        self.assertEqual(path_profile["best_available_path"], "\\Users\\case.txt")
        self.assertTrue(path_profile["bounded_parent_path"]["complete_within_bounded_scan"])
        self.assertTrue(artifact.details["mft_full_parser_profile"]["decoded_components"]["bounded_parent_path_cache"])
        self.assertEqual(artifact.details["mft_full_parser_profile"]["item_number"], 12)
        self.assertFalse(path_profile["commercial_grade_ready"])

    def test_mft_bounded_path_cache_profile_surfaces_partial_chain_quality(self) -> None:
        cache = {
            10: {
                "record_number": 10,
                "path": "\\Users",
                "status": "reconstructed-bounded-parent-cache",
                "depth": 2,
                "complete_within_bounded_scan": True,
                "warnings": [],
            },
            99: {
                "record_number": 99,
                "path": "\\outside.txt",
                "status": "partial-parent-outside-bounded-scan",
                "depth": 1,
                "complete_within_bounded_scan": False,
                "warnings": ["parent-not-in-cache:9999"],
            },
        }

        profile = mft_bounded_path_cache_profile(cache)

        self.assertEqual(profile["cache_entry_count"], 2)
        self.assertEqual(profile["complete_path_count"], 1)
        self.assertEqual(profile["partial_path_count"], 1)
        self.assertEqual(profile["complete_path_ratio"], 0.5)
        self.assertEqual(profile["warning_count"], 1)
        self.assertEqual(profile["max_chain_depth"], 2)
        self.assertEqual(profile["sample_partial_paths"][0]["record_number"], 99)
        self.assertEqual(profile["sample_partial_paths"][0]["warnings"], ["parent-not-in-cache:9999"])

    def test_usn_record_correlates_bounded_mft_path_cache(self) -> None:
        mft_cache = {
            40: {
                "profile_version": "mft-bounded-parent-path-v1",
                "status": "reconstructed-bounded-parent-cache",
                "path": "\\Users",
                "record_number": 40,
                "complete_within_bounded_scan": True,
            },
            41: {
                "profile_version": "mft-bounded-parent-path-v1",
                "status": "reconstructed-bounded-parent-cache",
                "path": "\\Users\\case.txt",
                "record_number": 41,
                "complete_within_bounded_scan": True,
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            usn_path = Path(tmp_dir) / "$J"
            usn_path.write_bytes(b"\x50\x00\x00\x00" + b"\x00" * 76)
            artifact = build_native_usn_record(
                usn_path,
                {
                    "file_reference_number": 41,
                    "parent_file_reference_number": 40,
                    "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                    "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                    "file_name": "case.txt",
                    "timestamp": "2026-01-02T03:04:05+00:00",
                    "reason": "FILE_DELETE|CLOSE",
                    "reason_raw": 0x80000200,
                    "reason_flags": ["FILE_DELETE", "CLOSE"],
                    "deleted_hint": True,
                    "usn": 9001,
                    "record_cursor": 128,
                    "next_record_cursor": 208,
                    "record_length": 80,
                    "major_version": 3,
                    "validation_checks": {
                        "record_length_aligned": True,
                        "record_cursor_progresses": True,
                        "filename_utf16_valid": True,
                        "version_supported": True,
                    },
                },
                0,
                mft_cache,
            )

        bounded = artifact.details["usn_bounded_mft_path"]
        self.assertEqual(bounded["status"], "matched-file-reference-cache")
        self.assertEqual(bounded["path_candidate"], "\\Users\\case.txt")
        self.assertTrue(bounded["complete_within_bounded_mft_cache"])
        self.assertEqual(
            artifact.details["usn_replay_transition_profile"]["path_candidate"],
            "\\Users\\case.txt",
        )
        self.assertTrue(
            artifact.details["usn_journal_replay_profile"]["decoded_components"]["bounded_mft_path_correlation"]
        )
        self.assertTrue(
            artifact.details["ntfs_native_depth_readiness_profile"]["decoded_components"]["bounded_mft_path_correlation"]
        )
        citation_kinds = {
            item["kind"]
            for item in artifact.details["ntfs_report_citation_manifest"]["citation_refs"]
        }
        self.assertIn("usn-bounded-mft-path-candidate", citation_kinds)

    def test_usn_bounded_mft_replay_preview_summarizes_correlated_journal_paths(self) -> None:
        records = [
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "case.txt",
                "timestamp": "2026-01-02T03:04:05+00:00",
                "reason_flags": ["FILE_DELETE", "CLOSE"],
                "deleted_hint": True,
                "usn": 9001,
                "record_cursor": 128,
            },
            {
                "file_reference_number": 99,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 99, "sequence_number": 1},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "new.txt",
                "timestamp": "2026-01-02T03:05:05+00:00",
                "reason_flags": ["FILE_CREATE"],
                "usn": 9002,
                "record_cursor": 208,
            },
            {
                "file_reference_number": 1234,
                "parent_file_reference_number": 9999,
                "file_name": "outside.txt",
                "reason_flags": ["DATA_EXTEND"],
                "usn": 9003,
                "record_cursor": 288,
            },
        ]
        mft_cache = {
            40: {"path": "\\Users", "status": "reconstructed-bounded-parent-cache"},
            41: {"path": "\\Users\\case.txt", "status": "reconstructed-bounded-parent-cache"},
        }

        preview = usn_bounded_mft_replay_preview(records, mft_cache)

        self.assertEqual(preview["profile_version"], "usn-bounded-mft-replay-preview-v1")
        self.assertEqual(preview["cache_entry_count"], 2)
        self.assertEqual(preview["record_count"], 3)
        self.assertEqual(preview["correlated_record_count"], 2)
        self.assertEqual(preview["uncorrelated_record_count"], 1)
        self.assertEqual(preview["file_reference_cache_hit_count"], 1)
        self.assertEqual(preview["parent_reference_cache_hit_count"], 2)
        self.assertIn(
            {"value": "matched-file-reference-cache", "count": 1},
            preview["correlation_status_counts"],
        )
        self.assertIn(
            {"value": "combined-parent-cache-and-usn-name", "count": 1},
            preview["correlation_status_counts"],
        )
        self.assertEqual(preview["path_samples"][0]["path_candidate"], "\\Users\\case.txt")
        self.assertEqual(preview["path_samples"][1]["path_candidate"], "\\Users\\new.txt")
        self.assertFalse(preview["complete_journal_replay"])
        self.assertFalse(preview["commercial_grade_ready"])

        reliability = usn_path_reliability_profile(
            records=records,
            bounded_replay_preview=preview,
            path_cache_profile={
                "cache_entry_count": 2,
                "complete_path_ratio": 1.0,
                "warning_count": 0,
            },
        )
        self.assertEqual(reliability["profile_version"], "usn-path-reliability-profile-v1")
        self.assertEqual(reliability["correlated_record_count"], 2)
        self.assertEqual(reliability["correlation_ratio"], 0.666667)
        self.assertEqual(reliability["reliability"], "medium-bounded-review-confidence")
        self.assertEqual(reliability["review_priority"], "review-correlated-paths-first")
        self.assertFalse(reliability["commercial_grade_ready"])
        self.assertIn("usn-full-frn-path-cache-required", reliability["blockers"])

    def test_usn_path_reliability_profile_marks_uncorrelated_scan_low_value(self) -> None:
        reliability = usn_path_reliability_profile(
            records=[{"file_name": "a.txt"}, {"file_name": "b.txt"}],
            bounded_replay_preview={
                "record_count": 2,
                "correlated_record_count": 0,
            },
            path_cache_profile={
                "cache_entry_count": 0,
                "complete_path_ratio": 0,
                "warning_count": 0,
            },
        )

        self.assertEqual(reliability["reliability"], "no-path-correlation")
        self.assertEqual(reliability["review_priority"], "review-usn-records-without-path-assumption")
        self.assertIn("No reliable bounded MFT path correlation", reliability["safe_report_wording"])

    def test_usn_state_replay_validation_profile_separates_record_diff_from_state_diff(self) -> None:
        trusted_diff = {
            "status": "pass",
            "trusted_tool": "UsnJrnl2Csv",
            "trusted_tool_recognized": True,
            "matched_count": 4,
        }
        profile = usn_state_replay_validation_profile(
            state_replay_preview={
                "transition_count": 4,
                "transitions": [{"transition": "create"}, {"transition": "delete"}],
            },
            trusted_diff=trusted_diff,
            path_reliability_profile={"reliability": "medium-bounded-review-confidence"},
        )

        self.assertEqual(profile["profile_version"], "usn-state-replay-validation-profile-v1")
        self.assertTrue(profile["record_level_trusted_diff_passed"])
        self.assertFalse(profile["state_replay_diff_passed"])
        self.assertEqual(profile["validation_status"], "record-level-diff-passed-state-replay-validation-required")
        self.assertEqual(profile["trusted_tool"], "UsnJrnl2Csv")
        self.assertEqual(profile["trusted_diff_matched_count"], 4)
        self.assertIn("usn-trusted-state-replay-diff-required", profile["blockers"])
        self.assertNotIn("usn-trusted-timeline-diff-required", profile["blockers"])
        self.assertIn("bounded review aid", profile["safe_report_wording"])

    def test_usn_state_replay_validation_profile_blocks_missing_record_diff(self) -> None:
        profile = usn_state_replay_validation_profile(
            state_replay_preview={"transition_count": 0},
            trusted_diff={},
            path_reliability_profile={"reliability": "no-path-correlation"},
        )

        self.assertFalse(profile["record_level_trusted_diff_passed"])
        self.assertEqual(profile["validation_status"], "trusted-diff-and-state-replay-validation-required")
        self.assertIn("usn-trusted-timeline-diff-required", profile["blockers"])
        self.assertIn("usn-state-replay-transition-corpus-required", profile["blockers"])
        self.assertIn("usn-path-reliability-validation-required", profile["blockers"])

    def test_usn_state_replay_trusted_diff_accepts_nested_transition_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "usn-journal-inventory",
                "details": {
                    "usn_replay_inventory_profile": {
                        "bounded_state_replay_preview": {
                            "transitions": [
                                {
                                    "usn": 9004,
                                    "file_reference_number": 41,
                                    "record_cursor": 408,
                                    "transition": "delete",
                                    "timestamp": "2026-01-02T03:05:00Z",
                                    "previous_path": r"C:\Users\new.txt",
                                    "new_path": "",
                                    "file_name": "new.txt",
                                    "state_effect": "remove-current-path",
                                }
                            ]
                        }
                    }
                },
            }
        ]
        trusted_rows = [
            {
                "USN": "9004",
                "FRN": "41",
                "RecordCursor": "408",
                "Transition": "delete",
                "Timestamp": "2026-01-02T03:05:00Z",
                "PreviousPath": r"C:\Users\new.txt",
                "NewPath": "",
                "FileName": "new.txt",
                "StateEffect": "remove-current-path",
            }
        ]

        diff = build_usn_state_replay_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="known-answer-state-replay",
        )

        self.assertEqual(diff["mode"], "usn-trusted-state-replay-diff-v1")
        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_usn_state_replay_trusted_diff_reports_transition_mismatch(self) -> None:
        rapid_rows = [
            {
                "usn": 9004,
                "file_reference_number": 41,
                "transition": "delete",
                "previous_path": r"C:\Users\new.txt",
            }
        ]
        trusted_rows = [
            {
                "USN": "9004",
                "FRN": "41",
                "Transition": "rename-new-name",
                "PreviousPath": r"C:\Users\new.txt",
            }
        ]

        diff = build_usn_state_replay_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="known-answer-state-replay",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["missing_in_trusted_count"], 1)
        self.assertEqual(diff["extra_in_trusted_count"], 1)

    def test_usn_state_replay_validation_profile_accepts_state_replay_diff_pass(self) -> None:
        profile = usn_state_replay_validation_profile(
            state_replay_preview={"transition_count": 1},
            trusted_diff={"status": "pass", "trusted_tool": "UsnJrnl2Csv", "trusted_tool_recognized": True, "matched_count": 1},
            state_replay_diff={
                "status": "pass",
                "trusted_tool": "known-answer-state-replay",
                "trusted_tool_recognized": True,
                "matched_count": 1,
            },
            path_reliability_profile={"reliability": "medium-bounded-review-confidence"},
        )

        self.assertEqual(profile["validation_status"], "record-and-state-replay-diffs-passed")
        self.assertTrue(profile["state_replay_diff_passed"])
        self.assertTrue(profile["commercial_grade_ready"])
        self.assertEqual(profile["blockers"], [])

    def test_usn_replay_inventory_embeds_state_replay_validation_gate(self) -> None:
        records = [
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "case.txt",
                "timestamp": "2026-01-02T03:04:00+00:00",
                "reason_flags": ["FILE_CREATE"],
                "usn": 9001,
                "record_cursor": 128,
            }
        ]
        mft_cache = {
            40: {"path": "\\Users", "status": "reconstructed-bounded-parent-cache", "complete_within_bounded_scan": True},
            41: {"path": "\\Users\\case.txt", "status": "reconstructed-bounded-parent-cache", "complete_within_bounded_scan": True},
        }

        inventory = usn_replay_inventory_profile(
            records,
            {"record_limit_reached": False},
            mft_cache,
            trusted_diff={
                "status": "pass",
                "trusted_tool": "UsnJrnl2Csv",
                "trusted_tool_recognized": True,
                "matched_count": 1,
            },
        )

        validation = inventory["usn_state_replay_validation_profile"]
        self.assertEqual(validation["trusted_diff_status"], "pass")
        self.assertTrue(validation["record_level_trusted_diff_passed"])
        self.assertFalse(validation["state_replay_diff_passed"])
        self.assertIn("usn-trusted-state-replay-diff-required", validation["blockers"])
        self.assertIn("usn_path_reliability_profile", inventory)
        self.assertIn("bounded_state_replay_preview", inventory)

    def test_usn_rename_pair_preview_pairs_old_and_new_names_with_caveats(self) -> None:
        records = [
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "old.txt",
                "timestamp": "2026-01-02T03:04:05+00:00",
                "reason_flags": ["RENAME_OLD_NAME"],
                "usn": 9001,
                "record_cursor": 128,
            },
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "new.txt",
                "timestamp": "2026-01-02T03:04:06+00:00",
                "reason_flags": ["RENAME_NEW_NAME"],
                "usn": 9002,
                "record_cursor": 208,
            },
            {
                "file_reference_number": 99,
                "parent_file_reference_number": 40,
                "file_name": "orphan-old.txt",
                "reason_flags": ["RENAME_OLD_NAME"],
                "usn": 9003,
                "record_cursor": 288,
            },
        ]
        mft_cache = {
            40: {"path": "\\Users", "status": "reconstructed-bounded-parent-cache"},
            41: {"path": "\\Users\\new.txt", "status": "reconstructed-bounded-parent-cache"},
        }

        preview = usn_rename_pair_preview(records, mft_cache)

        self.assertEqual(preview["profile_version"], "usn-rename-pair-preview-v1")
        self.assertEqual(preview["rename_old_count"], 2)
        self.assertEqual(preview["rename_new_count"], 1)
        self.assertEqual(preview["candidate_pair_count"], 1)
        self.assertEqual(preview["unmatched_old_count"], 1)
        self.assertEqual(preview["pair_balance"], "requires-full-journal-context")
        pair = preview["pairs"][0]
        self.assertEqual(pair["confidence"], "high")
        self.assertEqual(pair["old_name"], "old.txt")
        self.assertEqual(pair["new_name"], "new.txt")
        self.assertEqual(pair["file_reference_number"], 41)
        self.assertTrue(pair["same_parent_reference"])
        self.assertEqual(pair["old_path_candidate"], "\\Users\\old.txt")
        self.assertEqual(pair["new_path_candidate"], "\\Users\\new.txt")
        self.assertEqual(pair["old_path_candidate_source"], "parent-cache-plus-usn-name")
        self.assertEqual(pair["new_path_candidate_source"], "parent-cache-plus-usn-name")
        self.assertEqual(pair["old_frn_path_correlation"]["path_candidate"], "\\Users\\new.txt")
        self.assertFalse(preview["complete_journal_replay"])
        self.assertFalse(preview["commercial_grade_ready"])

    def test_usn_delete_lifecycle_preview_pairs_create_and_delete_with_caveats(self) -> None:
        records = [
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "case.txt",
                "timestamp": "2026-01-02T03:04:05+00:00",
                "reason_flags": ["FILE_CREATE"],
                "usn": 9001,
                "record_cursor": 128,
            },
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "case.txt",
                "timestamp": "2026-01-02T03:04:06+00:00",
                "reason_flags": ["FILE_DELETE", "CLOSE"],
                "deleted_hint": True,
                "usn": 9002,
                "record_cursor": 208,
            },
            {
                "file_reference_number": 99,
                "parent_file_reference_number": 40,
                "file_name": "orphan-delete.txt",
                "reason_flags": ["FILE_DELETE"],
                "usn": 9003,
                "record_cursor": 288,
            },
        ]
        mft_cache = {
            40: {"path": "\\Users", "status": "reconstructed-bounded-parent-cache"},
            41: {"path": "\\Users\\case.txt", "status": "reconstructed-bounded-parent-cache"},
        }

        preview = usn_delete_lifecycle_preview(records, mft_cache)

        self.assertEqual(preview["profile_version"], "usn-delete-lifecycle-preview-v1")
        self.assertEqual(preview["create_count"], 1)
        self.assertEqual(preview["delete_count"], 2)
        self.assertEqual(preview["candidate_lifecycle_count"], 2)
        self.assertEqual(preview["paired_create_delete_count"], 1)
        self.assertEqual(preview["delete_without_prior_create_count"], 1)
        paired = preview["candidates"][0]
        self.assertEqual(paired["lifecycle_status"], "create-delete-paired-within-bounded-window")
        self.assertEqual(paired["confidence"], "high")
        self.assertEqual(paired["file_reference_number"], 41)
        self.assertEqual(paired["create_record_cursor"], 128)
        self.assertEqual(paired["delete_record_cursor"], 208)
        self.assertEqual(paired["delete_path_candidate"], "\\Users\\case.txt")
        self.assertFalse(preview["complete_journal_replay"])
        self.assertFalse(preview["commercial_grade_ready"])

    def test_usn_timeline_review_candidates_promote_rename_and_delete_pivots(self) -> None:
        rename_preview = {
            "pairs": [
                {
                    "old_name": "old.txt",
                    "new_name": "new.txt",
                    "old_timestamp": "2026-01-02T03:04:05+00:00",
                    "new_timestamp": "2026-01-02T03:04:06+00:00",
                    "old_record_cursor": 128,
                    "new_record_cursor": 208,
                    "old_path_candidate": "\\Users\\old.txt",
                    "new_path_candidate": "\\Users\\new.txt",
                    "file_reference_number": 41,
                    "confidence": "high",
                }
            ]
        }
        delete_preview = {
            "candidates": [
                {
                    "file_name": "gone.txt",
                    "create_timestamp": "2026-01-02T03:05:00+00:00",
                    "delete_timestamp": "2026-01-02T03:05:30+00:00",
                    "create_record_cursor": 308,
                    "delete_record_cursor": 408,
                    "create_path_candidate": "\\Users\\gone.txt",
                    "delete_path_candidate": "\\Users\\gone.txt",
                    "file_reference_number": 42,
                    "confidence": "high",
                }
            ]
        }

        candidates = usn_timeline_review_candidates(
            rename_pair_preview=rename_preview,
            delete_lifecycle_preview=delete_preview,
        )

        self.assertEqual(len(candidates), 4)
        self.assertEqual(candidates[0]["timeline_type"], "usn-rename-old-name")
        self.assertEqual(candidates[1]["timeline_type"], "usn-rename-new-name")
        self.assertEqual(candidates[2]["timeline_type"], "usn-file-create")
        self.assertEqual(candidates[3]["timeline_type"], "usn-file-delete")
        self.assertEqual(candidates[3]["record_cursor"], 408)
        self.assertEqual(candidates[3]["reportability"], "bounded-usn-timeline-review-candidate")
        self.assertTrue(candidates[3]["validation_required"])
        self.assertIn("usn-trusted-timeline-diff-required", candidates[3]["blockers"])

    def test_usn_bounded_state_replay_preview_applies_create_rename_delete_in_order(self) -> None:
        records = [
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "old.txt",
                "timestamp": "2026-01-02T03:04:05+00:00",
                "reason_flags": ["RENAME_OLD_NAME"],
                "usn": 9002,
                "record_cursor": 208,
            },
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "case.txt",
                "timestamp": "2026-01-02T03:04:00+00:00",
                "reason_flags": ["FILE_CREATE"],
                "usn": 9001,
                "record_cursor": 128,
            },
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "new.txt",
                "timestamp": "2026-01-02T03:04:06+00:00",
                "reason_flags": ["RENAME_NEW_NAME"],
                "usn": 9003,
                "record_cursor": 308,
            },
            {
                "file_reference_number": 41,
                "parent_file_reference_number": 40,
                "file_reference_number_decoded": {"record_number": 41, "sequence_number": 7},
                "parent_file_reference_number_decoded": {"record_number": 40, "sequence_number": 3},
                "file_name": "new.txt",
                "timestamp": "2026-01-02T03:05:00+00:00",
                "reason_flags": ["FILE_DELETE"],
                "usn": 9004,
                "record_cursor": 408,
            },
        ]
        mft_cache = {
            40: {"path": "\\Users", "status": "reconstructed-bounded-parent-cache"},
            41: {"path": "\\Users\\new.txt", "status": "reconstructed-bounded-parent-cache"},
        }

        preview = usn_bounded_state_replay_preview(records, mft_cache)

        self.assertEqual(preview["profile_version"], "usn-bounded-state-replay-preview-v1")
        self.assertEqual(preview["transition_count"], 4)
        transition_counts = {
            item["value"]: item["count"]
            for item in preview["transition_counts"]
        }
        self.assertEqual(transition_counts["create"], 1)
        self.assertEqual(transition_counts["rename-old-name"], 1)
        self.assertEqual(transition_counts["rename-new-name"], 1)
        self.assertEqual(transition_counts["delete"], 1)
        transitions = preview["transitions"]
        self.assertEqual([item["transition"] for item in transitions], ["create", "rename-old-name", "rename-new-name", "delete"])
        self.assertEqual(transitions[0]["new_path"], "\\Users\\case.txt")
        self.assertEqual(transitions[1]["previous_path"], "\\Users\\old.txt")
        self.assertEqual(transitions[2]["previous_path"], "\\Users\\old.txt")
        self.assertEqual(transitions[2]["new_path"], "\\Users\\new.txt")
        self.assertEqual(transitions[3]["previous_path"], "\\Users\\new.txt")
        self.assertEqual(transitions[3]["timeline_type"], "usn-state-delete")
        self.assertEqual(transitions[3]["event_label"], "USN state delete")
        self.assertEqual(transitions[3]["path_candidate"], "\\Users\\new.txt")
        self.assertEqual(transitions[3]["reportability"], "bounded-usn-state-replay-transition")
        self.assertTrue(transitions[3]["validation_required"])
        self.assertIn("usn-trusted-state-replay-diff-required", transitions[3]["blockers"])
        self.assertEqual(preview["final_path_state_count"], 1)
        self.assertFalse(preview["complete_journal_replay"])
        self.assertFalse(preview["commercial_grade_ready"])
        self.assertIn("usn-trusted-state-replay-diff-required", preview["blockers"])

    def test_jumplist_destlist_marks_unlinked_entries_as_review_only_candidates(self) -> None:
        path = r"C:\Users\alice\Documents\missing.docx"
        encoded_path = path.encode("utf-16le")
        entry = bytearray(114 + len(encoded_path))
        entry[112:114] = len(path).to_bytes(2, "little")
        entry[114:] = encoded_path
        destlist = bytearray(32)
        destlist[0:4] = (1).to_bytes(4, "little")
        destlist[4:8] = (1).to_bytes(4, "little")
        destlist.extend(entry)

        metadata = parse_destlist_metadata(
            [
                {
                    "name": "DestList",
                    "path": "Root Entry/DestList",
                    "index": 1,
                    "size": len(destlist),
                    "start_sector": 3,
                    "data": bytes(destlist),
                }
            ]
        )

        self.assertEqual(metadata["destlist_parse_status"], "parsed-candidate")
        self.assertEqual(metadata["destlist_entry_candidate_count"], 1)
        self.assertEqual(metadata["destlist_unlinked_entry_candidate_count"], 1)
        self.assertEqual(metadata["destlist_deleted_or_unlinked_entry_review_status"], "candidate-review-only-not-recovered")
        self.assertEqual(metadata["destlist_unlinked_entry_candidates"][0]["path_candidate"], path)
        self.assertTrue(metadata["destlist_validation_checks"]["deleted_or_unlinked_entry_review_available"])

    def test_prefetch_mam_compression_status_is_detected_without_false_scca_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            pf = Path(tmp_dir) / "COMPRESSED.EXE-12345678.pf"
            blob = bytearray(128)
            blob[0:4] = b"MAM\x04"
            blob[4:8] = (4096).to_bytes(4, "little")
            pf.write_bytes(bytes(blob))

            hints = prefetch_header_hints(pf)

            self.assertFalse(hints["binary_format_detected"])
            self.assertEqual(hints["prefetch_compression"]["format"], "windows-prefetch-mam")
            self.assertEqual(hints["prefetch_compression"]["declared_uncompressed_size"], 4096)
            self.assertTrue(hints["prefetch_validation_checks"]["compressed_prefetch_detected"])
            self.assertTrue(hints["prefetch_validation_checks"]["compressed_prefetch_status_recorded"])
            gate = prefetch_core_accuracy_gates(
                {
                    "source_path": str(pf),
                    "validation_checks": hints["prefetch_validation_checks"],
                    **hints,
                }
            )[0]
            self.assertIn("compressed PF handling", gate["satisfied_checks"])

    def test_core_filesystem_and_activity_trusted_diffs_gate_commercial_claims(self) -> None:
        edb_diff = build_windows_edb_trusted_diff(
            [
                {
                    "item_path": r"C:\Users\alice\Documents\case.txt",
                    "content_snippet": "incident timeline",
                    "deleted_state": "false",
                }
            ],
            [
                {
                    "System.ItemPathDisplay": r"C:\Users\alice\Documents\case.txt",
                    "System.Search.Contents": "incident timeline",
                    "IsDeleted": "false",
                }
            ],
            trusted_tool="libesedb",
        )
        self.assertEqual(edb_diff["status"], "pass")
        edb_gate = windows_search_core_accuracy_gates(
            "windows-search-edb-row-candidate",
            {
                "item_path": r"C:\Users\alice\Documents\case.txt",
                "content_snippet": "incident timeline",
                "deleted_state": "candidate-marker-present",
                "page_offset": 4096,
                "windows_edb_trusted_diff": edb_diff,
            },
        )[0]
        self.assertIn("trusted Windows.edb parser diff pass", edb_gate["satisfied_checks"])
        self.assertNotIn("trusted Windows.edb parser diff pass", edb_gate["missing_required_checks"])

        mft_diff = build_mft_trusted_diff(
            [
                {
                    "record_number": "42",
                    "parent_reference": "5",
                    "file_path": r"C:\Users\alice\case.txt",
                    "timestamp": "2024-01-02T03:04:05Z",
                }
            ],
            [
                {
                    "EntryNumber": "42",
                    "ParentEntryNumber": "5",
                    "FullPath": r"C:\Users\alice\case.txt",
                    "Created0x10": "2024-01-02T03:04:05Z",
                }
            ],
            trusted_tool="MFTECmd",
        )
        self.assertEqual(mft_diff["status"], "pass")
        mft_gate = ntfs_core_accuracy_gates(
            "mft-record",
            {
                "sequence_validation": {"status": "valid"},
                "file_path": r"C:\Users\alice\case.txt",
                "timestamp": "2024-01-02T03:04:05Z",
                "mft_trusted_diff": mft_diff,
            },
        )[0]
        self.assertIn("trusted MFT parser record diff pass", mft_gate["satisfied_checks"])

        usn_diff = build_usn_trusted_diff(
            [
                {
                    "usn": "9001",
                    "file_reference_number": "42",
                    "parent_file_reference_number": "5",
                    "file_name": "case.txt",
                    "reason": "FILE_CREATE|CLOSE",
                }
            ],
            [
                {
                    "USN": "9001",
                    "FRN": "42",
                    "ParentFRN": "5",
                    "FileName": "case.txt",
                    "Reason": "FILE_CREATE|CLOSE",
                }
            ],
            trusted_tool="UsnJrnl2Csv",
        )
        self.assertEqual(usn_diff["status"], "pass")
        usn_gate = ntfs_core_accuracy_gates(
            "usn-record",
            {
                "reason_flags": ["FILE_CREATE", "CLOSE"],
                "file_reference_number_decoded": True,
                "record_cursor": 128,
                "usn_trusted_diff": usn_diff,
            },
        )[0]
        self.assertIn("trusted USN parser timeline diff pass", usn_gate["satisfied_checks"])

        jumplist_diff = build_jumplist_trusted_diff(
            [
                {
                    "application_id_hash": "a1b2",
                    "stream_path": "1",
                    "target_path": r"C:\Users\alice\case.txt",
                }
            ],
            [
                {
                    "AppID": "a1b2",
                    "EntryNumber": "1",
                    "TargetPath": r"C:\Users\alice\case.txt",
                }
            ],
            trusted_tool="JLECmd",
        )
        self.assertEqual(jumplist_diff["status"], "pass")
        jumplist_gate = jumplist_core_accuracy_gates(
            {
                "application_id_hash": "a1b2",
                "ole_streams": [{"name": "DestList"}],
                "destlist_metadata": {"destlist_header_candidates": [{}]},
                "destinations": [{"stream_path": "1", "target_path": r"C:\Users\alice\case.txt"}],
                "jumplist_trusted_diff": jumplist_diff,
            }
        )[0]
        self.assertIn("trusted JumpList DestList diff pass", jumplist_gate["satisfied_checks"])

        shellbag_diff = build_shellbag_trusted_diff(
            [
                {
                    "source_key_path": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                    "bag_id": "42",
                    "node_id": "0",
                    "key_last_written_at": "2024-01-02T03:04:05Z",
                }
            ],
            [
                {
                    "KeyPath": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                    "Bag": "42",
                    "Node": "0",
                    "LastWriteTime": "2024-01-02T03:04:05Z",
                }
            ],
            trusted_tool="ShellBagsExplorer",
        )
        self.assertEqual(shellbag_diff["status"], "pass")
        shellbag_gate = shellbag_core_accuracy_gates(
            {
                "shellbag_section": "bagmru",
                "bag_id_candidates": ["42"],
                "node_id_candidates": ["0"],
                "timestamp_candidates": [{"timestamp": "2024-01-02T03:04:05Z"}],
                "hive_name": "NTUSER.DAT",
                "shellbag_trusted_diff": shellbag_diff,
            }
        )[0]
        self.assertIn("trusted ShellBags parser diff pass", shellbag_gate["satisfied_checks"])

    def test_core_filesystem_and_activity_trusted_diffs_block_mismatches(self) -> None:
        edb_diff = build_windows_edb_trusted_diff(
            [{"item_path": r"C:\a.txt", "content_snippet": "rapid"}],
            [{"System.ItemPathDisplay": r"C:\a.txt", "System.Search.Contents": "trusted"}],
            trusted_tool="libesedb",
        )
        self.assertEqual(edb_diff["status"], "diffs-present")
        self.assertFalse(edb_diff["commercial_grade_evidence"])
        self.assertEqual(edb_diff["mismatch_count"], 1)

        mft_diff = build_mft_trusted_diff(
            [{"record_number": "42", "file_path": r"C:\a.txt"}],
            [{"EntryNumber": "43", "FullPath": r"C:\a.txt"}],
            trusted_tool="unknown-tool",
        )
        self.assertEqual(mft_diff["status"], "diffs-present")
        self.assertFalse(mft_diff["trusted_tool_recognized"])
        self.assertIn("mft-trusted-record-diff-required", mft_diff["reportability_decision"]["blockers"])

    def test_windows_edb_trusted_diff_accepts_nested_page_row_candidates(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "windows-search-edb-row-candidate",
                "details": {
                    "item_path": r"C:\Users\alice\Documents\Case Notes.docx",
                    "url": "https://example.test/case",
                    "content_snippet": "encoded powershell investigation notes",
                    "deleted_state": False,
                    "table_family_candidates": ["property-store", "content-index"],
                    "page_index": 7,
                    "page_offset": 28672,
                    "page_sha256": "a" * 64,
                    "source_format": "ese-edb",
                },
            }
        ]
        trusted_rows = [
            {
                "System.ItemPathDisplay": r"C:\Users\alice\Documents\Case Notes.docx",
                "System.ItemUrl": "https://example.test/case",
                "System.Search.Contents": "encoded powershell investigation notes",
                "IsDeleted": "0",
                "TableFamilies": "content-index; property-store",
                "PageIndex": "7",
                "PageOffset": "0x7000",
                "PageSHA256": "a" * 64,
                "SourceFormat": "ese-edb",
            }
        ]

        diff = build_windows_edb_trusted_diff(rapid_rows, trusted_rows, trusted_tool="WinSearchDBAnalyzer")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_windows_edb_trusted_diff_reports_page_and_deleted_state_mismatches(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "windows-search-edb-row-candidate",
                "details": {
                    "item_path": r"C:\Users\alice\Documents\Case Notes.docx",
                    "deleted_state": False,
                    "table_family_candidates": ["property-store"],
                    "page_offset": 28672,
                    "page_sha256": "b" * 64,
                },
            }
        ]
        trusted_rows = [
            {
                "System.ItemPathDisplay": r"C:\Users\alice\Documents\Case Notes.docx",
                "IsDeleted": "true",
                "TableFamilies": "property-store",
                "PageOffset": 28672,
                "PageSHA256": "b" * 64,
            }
        ]

        diff = build_windows_edb_trusted_diff(rapid_rows, trusted_rows, trusted_tool="WinSearchDBAnalyzer")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "deleted_state")

    def test_mft_trusted_diff_accepts_nested_native_rows_with_attributes(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "mft-record",
                "details": {
                    "record_number": 42,
                    "sequence_number": 7,
                    "parent_reference": 5,
                    "file_path": r"C:\Users\alice\Documents\case.txt",
                    "deleted_hint": False,
                    "timestamp": "2024-01-02T03:04:05Z",
                    "record_offset": 43008,
                    "attribute_types": ["$STANDARD_INFORMATION", "$FILE_NAME", "$DATA"],
                    "data_attributes": [
                        {
                            "resident": False,
                            "runlist_decode_status": "decoded-preview",
                        }
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "EntryNumber": "42",
                "SequenceNumber": "7",
                "ParentEntryNumber": "5",
                "FullPath": r"C:\Users\alice\Documents\case.txt",
                "Deleted": "false",
                "Created0x10": "2024-01-02T03:04:05Z",
                "Offset": "0xa800",
                "Attributes": "$DATA; $FILE_NAME; $STANDARD_INFORMATION",
                "DataRunStatus": "decoded-preview",
            }
        ]

        diff = build_mft_trusted_diff(rapid_rows, trusted_rows, trusted_tool="MFTECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_mft_trusted_diff_reports_sequence_and_parent_mismatches(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "mft-record",
                "details": {
                    "record_number": "42",
                    "sequence_number": "7",
                    "parent_reference": "5",
                    "file_path": r"C:\Users\alice\Documents\case.txt",
                },
            }
        ]
        trusted_rows = [
            {
                "EntryNumber": "42",
                "SequenceNumber": "9",
                "ParentEntryNumber": "5",
                "FullPath": r"C:\Users\alice\Documents\case.txt",
            }
        ]

        diff = build_mft_trusted_diff(rapid_rows, trusted_rows, trusted_tool="MFTECmd")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "sequence_number")

    def test_usn_trusted_diff_accepts_nested_v4_extent_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "usn-record",
                "details": {
                    "usn": 9001,
                    "file_reference_number": 42,
                    "parent_file_reference_number": 5,
                    "major_version": 4,
                    "record_cursor": 128,
                    "reason_flags": ["DATA_EXTEND", "CLOSE"],
                    "source_info_flags": ["DATA_MANAGEMENT"],
                    "file_attribute_names": ["ARCHIVE"],
                    "usn_record_evidence": {
                        "change_evidence": {
                            "v4_extent_evidence": {
                                "extent_count": 2,
                            }
                        }
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "USN": "9001",
                "FRN": "42",
                "ParentFRN": "5",
                "MajorVersion": "4",
                "RecordOffset": "0x80",
                "Reason": "CLOSE|DATA_EXTEND",
                "SourceInfo": "DATA_MANAGEMENT",
                "FileAttributes": "ARCHIVE",
                "ExtentCount": "2",
            }
        ]

        diff = build_usn_trusted_diff(rapid_rows, trusted_rows, trusted_tool="UsnJrnl2Csv")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_usn_trusted_diff_reports_reason_flag_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "usn-record",
                "details": {
                    "usn": "9001",
                    "file_reference_number": "42",
                    "file_name": "case.txt",
                    "reason_flags": ["FILE_CREATE", "CLOSE"],
                },
            }
        ]
        trusted_rows = [
            {
                "USN": "9001",
                "FRN": "42",
                "FileName": "case.txt",
                "Reason": "FILE_DELETE|CLOSE",
            }
        ]

        diff = build_usn_trusted_diff(rapid_rows, trusted_rows, trusted_tool="UsnJrnl2Csv")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "reason")

    def test_jumplist_trusted_diff_accepts_nested_destinations_and_destlist_fields(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "jumplist-automatic",
                "details": {
                    "application_id_hash": "a1b2",
                    "destinations": [
                        {
                            "stream_path": "7",
                            "target_path": r"C:\Users\alice\Documents\case.txt",
                            "destlist_entry_index_candidate": 3,
                            "destlist_entry_offset_candidate": 4096,
                            "destlist_hostname_candidates": [{"hostname_candidate": "ALICE-PC"}],
                            "destlist_validation_status": "candidate-linked-lnk-stream",
                            "timestamp": "2024-01-02T03:04:05Z",
                        }
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "AppID": "a1b2",
                "EntryNumber": "3",
                "StreamPath": "7",
                "TargetPath": r"C:\Users\alice\Documents\case.txt",
                "EntryOffset": "0x1000",
                "Hostname": "ALICE-PC",
                "ValidationStatus": "candidate-linked-lnk-stream",
                "LastAccessed": "2024-01-02T03:04:05Z",
            }
        ]

        diff = build_jumplist_trusted_diff(rapid_rows, trusted_rows, trusted_tool="JLECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_jumplist_trusted_diff_reports_destlist_offset_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "jumplist-automatic",
                "details": {
                    "application_id_hash": "a1b2",
                    "destlist_metadata": {
                        "destlist_entry_candidates": [
                            {
                                "index": 3,
                                "entry_offset": 4096,
                                "path_candidate": r"C:\Users\alice\Documents\case.txt",
                                "hostname_candidates": [{"hostname_candidate": "ALICE-PC"}],
                            }
                        ]
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "AppID": "a1b2",
                "EntryNumber": "3",
                "TargetPath": r"C:\Users\alice\Documents\case.txt",
                "EntryOffset": "0x1200",
                "Hostname": "ALICE-PC",
            }
        ]

        diff = build_jumplist_trusted_diff(rapid_rows, trusted_rows, trusted_tool="JLECmd")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "entry_offset")

    def test_shellbag_trusted_diff_accepts_nested_native_evidence_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "shellbag-native-candidate",
                "details": {
                    "hive_name": "NTUSER.DAT",
                    "shellbag_evidence": {
                        "key_evidence": {
                            "source_key_path": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                            "shellbag_section": "bagmru",
                            "allocation_status": "allocated",
                            "cell_offset": 4096,
                            "hbin_offset": 8192,
                            "transaction_log_status": "not-present",
                        },
                        "relationship_evidence": {
                            "bag_id_candidates": ["42"],
                            "node_id_candidates": ["0"],
                        },
                        "activity_evidence": {
                            "path_candidates": [r"C:\Users\alice\Documents"],
                            "primary_timestamp": "2024-01-02T03:04:05Z",
                        },
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "Hive": "NTUSER.DAT",
                "KeyPath": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                "Section": "bagmru",
                "Bag": "42",
                "Node": "0",
                "FolderPath": r"C:\Users\alice\Documents",
                "LastWriteTime": "2024-01-02T03:04:05Z",
                "CellOffset": "0x1000",
                "HbinOffset": "0x2000",
                "AllocationStatus": "allocated",
                "TransactionStatus": "not-present",
            }
        ]

        diff = build_shellbag_trusted_diff(rapid_rows, trusted_rows, trusted_tool="ShellBagsExplorer")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_shellbag_trusted_diff_reports_cell_offset_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "shellbag-native-candidate",
                "details": {
                    "source_key_path": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                    "bag_id_candidates": ["42"],
                    "node_id_candidates": ["0"],
                    "cell_offset": 4096,
                },
            }
        ]
        trusted_rows = [
            {
                "KeyPath": r"Software\Microsoft\Windows\Shell\BagMRU\0",
                "Bag": "42",
                "Node": "0",
                "CellOffset": "0x1200",
            }
        ]

        diff = build_shellbag_trusted_diff(rapid_rows, trusted_rows, trusted_tool="ShellBagsExplorer")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "cell_offset")

    def test_prefetch_trusted_diff_accepts_nested_version_and_metric_fields(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "prefetch-file",
                "details": {
                    "executable_hint": "POWERSHELL.EXE",
                    "prefetch_hash": "12345678",
                    "run_count": 3,
                    "last_run_at": "2024-04-01T09:10:11+00:00",
                    "last_run_times": ["2024-04-01T09:10:11+00:00", "2024-03-31T08:00:00+00:00"],
                    "prefetch_version": 30,
                    "prefetch_version_metadata": {"layout_name": "windows-10"},
                    "declared_file_size": 4096,
                    "referenced_paths": [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"],
                    "volume_candidates": [{"volume_device_path": r"\DEVICE\HARDDISKVOLUME3"}],
                    "file_reference_candidates": [{"file_reference": "42-7"}],
                    "prefetch_compression": {
                        "format": "plain-or-unknown",
                        "decompression_status": "not-needed",
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "Executable": "POWERSHELL.EXE",
                "Hash": "12345678",
                "RunCount": "3",
                "LastRun": "2024-04-01T09:10:11+00:00",
                "PreviousRunTimes": "2024-03-31T08:00:00+00:00;2024-04-01T09:10:11+00:00",
                "Version": "30",
                "LayoutName": "windows-10",
                "DeclaredFileSize": "0x1000",
                "ReferencedPaths": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "VolumeDevicePath": r"\DEVICE\HARDDISKVOLUME3",
                "FileReference": "42-7",
                "CompressionFormat": "plain-or-unknown",
                "DecompressionStatus": "not-needed",
            }
        ]

        diff = build_prefetch_trusted_diff(rapid_rows, trusted_rows, trusted_tool="PECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_prefetch_trusted_diff_reports_version_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "prefetch-file",
                "details": {
                    "executable_hint": "POWERSHELL.EXE",
                    "prefetch_hash": "12345678",
                    "prefetch_version": 30,
                },
            }
        ]
        trusted_rows = [
            {
                "Executable": "POWERSHELL.EXE",
                "Hash": "12345678",
                "Version": "23",
            }
        ]

        diff = build_prefetch_trusted_diff(rapid_rows, trusted_rows, trusted_tool="PECmd")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "prefetch_version")

    def test_lnk_trusted_diff_accepts_nested_linkinfo_tracker_property_store(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "recent-shortcut",
                "details": {
                    "target_path": r"C:\Users\alice\Documents\case.txt",
                    "working_dir": r"C:\Users\alice\Documents",
                    "command_line_arguments": "/safe",
                    "target_created_at": "2024-01-02T03:04:05+00:00",
                    "target_accessed_at": "2024-01-03T03:04:05+00:00",
                    "target_modified_at": "2024-01-04T03:04:05+00:00",
                    "description": "Case shortcut",
                    "relative_path": r"..\Documents\case.txt",
                    "icon_location": r"C:\Windows\System32\shell32.dll,1",
                    "link_flag_names": ["HasLinkInfo", "IsUnicode"],
                    "file_attribute_names": ["ARCHIVE"],
                    "target_file_size": 1234,
                    "show_command": 1,
                    "hot_key": 0,
                    "link_info": {
                        "local_base_path": r"C:\Users\alice\Documents\case.txt",
                        "common_path_suffix": r"case.txt",
                    },
                    "tracker_data": {
                        "machine_id": "ALICE-PC",
                        "droid_file_identifier": "11111111-2222-3333-4444-555555555555",
                        "birth_droid_file_identifier": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    },
                    "property_store_blocks": [
                        {
                            "embedded_paths": [r"C:\Users\alice\Documents\case.txt"],
                            "string_candidates": ["Case shortcut"],
                        }
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "TargetPath": r"C:\Users\alice\Documents\case.txt",
                "WorkingDirectory": r"C:\Users\alice\Documents",
                "Arguments": "/safe",
                "CreationTime": "2024-01-02T03:04:05+00:00",
                "AccessTime": "2024-01-03T03:04:05+00:00",
                "ModifiedTime": "2024-01-04T03:04:05+00:00",
                "Description": "Case shortcut",
                "RelativePath": r"..\Documents\case.txt",
                "IconLocation": r"C:\Windows\System32\shell32.dll,1",
                "Flags": "HasLinkInfo;IsUnicode",
                "Attributes": "ARCHIVE",
                "FileSize": "1234",
                "ShowCommand": "1",
                "HotKey": "0",
                "LocalBasePath": r"C:\Users\alice\Documents\case.txt",
                "CommonPathSuffix": r"case.txt",
                "MachineID": "ALICE-PC",
                "DroidFileIdentifier": "11111111-2222-3333-4444-555555555555",
                "BirthDroidFileIdentifier": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "PropertyStorePaths": r"C:\Users\alice\Documents\case.txt",
                "PropertyStoreStrings": "Case shortcut",
            }
        ]

        diff = build_lnk_trusted_diff(rapid_rows, trusted_rows, trusted_tool="LECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_lnk_trusted_diff_reports_tracker_guid_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "recent-shortcut",
                "details": {
                    "target_path": r"C:\Users\alice\Documents\case.txt",
                    "tracker_data": {
                        "droid_file_identifier": "11111111-2222-3333-4444-555555555555",
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "TargetPath": r"C:\Users\alice\Documents\case.txt",
                "DroidFileIdentifier": "99999999-2222-3333-4444-555555555555",
            }
        ]

        diff = build_lnk_trusted_diff(rapid_rows, trusted_rows, trusted_tool="LECmd")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "tracker_droid_file")

    def test_system_trusted_diff_accepts_nested_family_specific_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "task-scheduler-task",
                "details": {
                    "task_uri": r"\SecurityUpdater",
                    "command": "powershell.exe",
                    "arguments": "-EncodedCommand AAA",
                    "working_directory": r"C:\Users\alice",
                    "user_id": "S-1-5-21-1000",
                    "run_level": "HighestAvailable",
                    "hidden": True,
                    "trigger_types": ["CalendarTrigger"],
                    "risk_flags": ["task-string:powershell"],
                },
            },
            {
                "artifact_type": "defender-support-log",
                "details": {
                    "source_path": r"C:\ProgramData\Microsoft\Windows Defender\Support\MPLog.log",
                    "interesting_entry_count": 1,
                    "interesting_entries": ["Threat detected: Trojan Test"],
                    "risk_flags": ["defender:threat"],
                },
            },
            {
                "artifact_type": "firewall-log-row",
                "details": {
                    "timestamp": "2024-01-02T03:04:05+00:00",
                    "action": "DROP",
                    "protocol": "TCP",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "203.0.113.8",
                    "dst_port": "443",
                    "direction": "outbound",
                },
            },
            {
                "artifact_type": "wer-report",
                "details": {
                    "application_name": "bad.exe",
                    "event_name": "APPCRASH",
                    "exception_code": "0xc0000005",
                    "event_time": "2024-01-02T03:04:05+00:00",
                    "bucket_id": "abc",
                },
            },
            {
                "artifact_type": "wmi-repository-inventory",
                "details": {
                    "source_path": r"C:\Windows\System32\wbem\Repository\OBJECTS.DATA",
                    "wmi_persistence_terms": ["commandlineeventconsumer"],
                    "path_pivots": [r"C:\Users\alice\evil.ps1"],
                    "risk_flags": ["wmi-string:commandlineeventconsumer"],
                },
            },
        ]
        trusted_rows = [
            {
                "Family": "Task Scheduler",
                "TaskURI": r"\SecurityUpdater",
                "Command": "powershell.exe",
                "Arguments": "-EncodedCommand AAA",
                "WorkingDirectory": r"C:\Users\alice",
                "UserID": "S-1-5-21-1000",
                "RunLevel": "HighestAvailable",
                "Hidden": "true",
                "TriggerTypes": "CalendarTrigger",
            },
            {
                "Family": "Defender",
                "SourcePath": r"C:\ProgramData\Microsoft\Windows Defender\Support\MPLog.log",
                "InterestingEntryCount": "1",
                "InterestingEntries": "Threat detected: Trojan Test",
                "RiskFlags": "defender:threat",
            },
            {
                "Family": "Firewall",
                "Timestamp": "2024-01-02T03:04:05+00:00",
                "Action": "DROP",
                "Protocol": "TCP",
                "SrcIP": "10.0.0.5",
                "DstIP": "203.0.113.8",
                "DstPort": 443,
                "Direction": "outbound",
            },
            {
                "Family": "WER",
                "Application": "bad.exe",
                "EventName": "APPCRASH",
                "ExceptionCode": "0xc0000005",
                "EventTime": "2024-01-02T03:04:05+00:00",
                "BucketId": "abc",
            },
            {
                "Family": "WMI",
                "SourcePath": r"C:\Windows\System32\wbem\Repository\OBJECTS.DATA",
                "PersistenceTerms": "commandlineeventconsumer",
                "PathPivots": r"C:\Users\alice\evil.ps1",
                "RiskFlags": "wmi-string:commandlineeventconsumer",
            },
        ]

        diff = build_system_trusted_diff(rapid_rows, trusted_rows, trusted_tool="Velociraptor")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 5)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_system_trusted_diff_blocks_family_specific_mismatches(self) -> None:
        diff = build_system_trusted_diff(
            [
                {
                    "artifact_type": "wer-report",
                    "details": {
                        "application_name": "bad.exe",
                        "event_name": "APPCRASH",
                        "event_time": "2024-01-02T03:04:05+00:00",
                        "bucket_id": "abc",
                        "exception_code": "0xc0000005",
                    },
                }
            ],
            [
                {
                    "Family": "WER",
                    "Application": "bad.exe",
                    "EventName": "APPCRASH",
                    "EventTime": "2024-01-02T03:04:05+00:00",
                    "BucketId": "abc",
                    "ExceptionCode": "0xe0434352",
                }
            ],
            trusted_tool="Velociraptor",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "exception_code")

    def test_browser_storage_trusted_diff_accepts_nested_inventory_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "browser-storage-inventory",
                "details": {
                    "browser": "chrome",
                    "profile": "Default",
                    "storage_inventory": [
                        {
                            "storage_type": "cache",
                            "storage_name": "cache-data",
                            "relative_path": r"Cache\Cache_Data",
                            "artifact_hint": "browser-cache-inventory",
                            "file_count": 2,
                            "total_bytes": 4096,
                            "is_file": False,
                            "sensitive": False,
                            "sample_files": [{"hashes": {"sha256": "a" * 64}}],
                            "inventory_truncated": False,
                        },
                        {
                            "storage_type": "extension",
                            "storage_name": "extensions",
                            "relative_path": "Extensions",
                            "artifact_hint": "browser-extension-inventory",
                            "file_count": 1,
                            "total_bytes": 2048,
                            "is_file": False,
                            "sensitive": False,
                            "sample_files": [{"hashes": {"sha256": "b" * 64}}],
                            "inventory_truncated": False,
                        },
                        {
                            "storage_type": "cookie",
                            "storage_name": "network-cookies",
                            "relative_path": r"Network\Cookies",
                            "artifact_hint": "browser-cookie-store-inventory",
                            "file_count": 1,
                            "total_bytes": 8192,
                            "is_file": True,
                            "sensitive": True,
                            "sample_files": [{"hashes": {"sha256": "c" * 64}}],
                            "inventory_truncated": False,
                        },
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "Browser": "Chrome",
                "Profile": "Default",
                "Type": "cache",
                "Name": "cache-data",
                "RelativePath": r"Cache\Cache_Data",
                "ArtifactHint": "browser-cache-inventory",
                "FileCount": "2",
                "TotalBytes": "4096",
                "IsFile": "false",
                "Sensitive": "false",
                "SampleHashes": "a" * 64,
                "InventoryTruncated": "false",
            },
            {
                "Browser": "Chrome",
                "Profile": "Default",
                "Type": "extension",
                "Name": "extensions",
                "RelativePath": "Extensions",
                "ArtifactHint": "browser-extension-inventory",
                "FileCount": "1",
                "TotalBytes": "2048",
                "IsFile": "false",
                "Sensitive": "false",
                "SampleHashes": "b" * 64,
                "InventoryTruncated": "false",
            },
            {
                "Browser": "Chrome",
                "Profile": "Default",
                "Type": "cookie",
                "Name": "network-cookies",
                "RelativePath": r"Network\Cookies",
                "ArtifactHint": "browser-cookie-store-inventory",
                "FileCount": "1",
                "TotalBytes": "8192",
                "IsFile": "true",
                "Sensitive": "true",
                "SampleHashes": "c" * 64,
                "InventoryTruncated": "false",
            },
        ]

        diff = build_browser_storage_trusted_diff(rapid_rows, trusted_rows, trusted_tool="Hindsight")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 3)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_browser_storage_trusted_diff_blocks_inventory_field_mismatches(self) -> None:
        diff = build_browser_storage_trusted_diff(
            [
                {
                    "artifact_type": "browser-storage-inventory",
                    "details": {
                        "browser": "chrome",
                        "profile": "Default",
                        "storage_inventory": [
                            {
                                "storage_type": "cache",
                                "storage_name": "cache-data",
                                "relative_path": r"Cache\Cache_Data",
                                "file_count": 2,
                            }
                        ],
                    },
                }
            ],
            [
                {
                    "Browser": "chrome",
                    "Profile": "Default",
                    "Type": "cache",
                    "Name": "cache-data",
                    "RelativePath": r"Cache\Cache_Data",
                    "FileCount": 9,
                }
            ],
            trusted_tool="Hindsight",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "file_count")

    def test_browser_timeline_trusted_diff_accepts_nested_unified_timeline_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "browser-summary",
                "details": {
                    "browser": "chrome",
                    "profile": "Default",
                    "unified_timeline": [
                        {
                            "timeline_type": "visit",
                            "timestamp": "2024-04-01T09:10:11+00:00",
                            "url": "https://example.test/search?q=rapid",
                            "title": "Example Search",
                            "domain": "example.test",
                            "transition": "typed",
                            "visit_count": 3,
                            "typed_count": 1,
                            "ai_service": "",
                            "source_table": "history",
                            "source_index": 0,
                        },
                        {
                            "timeline_type": "download",
                            "timestamp": "2024-04-01T09:09:00+00:00",
                            "url": "https://example.test/a.zip",
                            "domain": "example.test",
                            "target_path": r"C:\Users\alice\Downloads\a.zip",
                            "total_bytes": 12345,
                            "state": 1,
                            "ended_at": "2024-04-01T09:09:05+00:00",
                            "source_table": "downloads",
                            "source_index": 0,
                        },
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "Browser": "Chrome",
                "Profile": "Default",
                "Type": "visit",
                "VisitTime": "2024-04-01T09:10:11+00:00",
                "URL": "https://example.test/search?q=rapid",
                "Title": "Example Search",
                "Domain": "example.test",
                "Transition": "typed",
                "VisitCount": "3",
                "TypedCount": "1",
                "SourceTable": "history",
                "SourceIndex": "0",
            },
            {
                "Browser": "Chrome",
                "Profile": "Default",
                "Type": "download",
                "StartTime": "2024-04-01T09:09:00+00:00",
                "URL": "https://example.test/a.zip",
                "Domain": "example.test",
                "DownloadPath": r"C:\Users\alice\Downloads\a.zip",
                "TotalBytes": "12345",
                "State": "1",
                "EndTime": "2024-04-01T09:09:05+00:00",
                "SourceTable": "downloads",
                "SourceIndex": "0",
            },
        ]

        diff = build_browser_timeline_trusted_diff(rapid_rows, trusted_rows, trusted_tool="BrowserHistoryView")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 2)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_browser_timeline_trusted_diff_blocks_nested_timeline_mismatches(self) -> None:
        diff = build_browser_timeline_trusted_diff(
            [
                {
                    "artifact_type": "browser-summary",
                    "details": {
                        "browser": "chrome",
                        "profile": "Default",
                        "unified_timeline": [
                            {
                                "timeline_type": "visit",
                                "timestamp": "2024-04-01T09:10:11+00:00",
                                "url": "https://example.test/",
                                "transition": "typed",
                            }
                        ],
                    },
                }
            ],
            [
                {
                    "Browser": "chrome",
                    "Profile": "Default",
                    "Type": "visit",
                    "VisitTime": "2024-04-01T09:10:11+00:00",
                    "URL": "https://example.test/",
                    "Transition": "link",
                }
            ],
            trusted_tool="BrowserHistoryView",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "transition")

    def test_prefetch_lnk_system_and_browser_trusted_diffs_gate_commercial_claims(self) -> None:
        prefetch_diff = build_prefetch_trusted_diff(
            [{"executable_hint": "POWERSHELL.EXE", "prefetch_hash": "12345678", "run_count": "3"}],
            [{"Executable": "POWERSHELL.EXE", "Hash": "12345678", "RunCount": "3"}],
            trusted_tool="PECmd",
        )
        self.assertEqual(prefetch_diff["status"], "pass")
        prefetch_gate = prefetch_core_accuracy_gates(
            {
                "binary_format_detected": True,
                "prefetch_version_metadata": {"supported_common_layout": True},
                "last_run_times": ["2024-04-01T09:10:11+00:00"],
                "volume_candidates": [{"volume_device_path": r"\DEVICE\HARDDISKVOLUME3"}],
                "prefetch_trusted_diff": prefetch_diff,
            }
        )[0]
        self.assertIn("trusted Prefetch parser diff pass", prefetch_gate["satisfied_checks"])

        lnk_diff = build_lnk_trusted_diff(
            [{"target_path": r"C:\Users\alice\case.txt", "working_dir": r"C:\Users\alice"}],
            [{"TargetPath": r"C:\Users\alice\case.txt", "WorkingDirectory": r"C:\Users\alice"}],
            trusted_tool="LECmd",
        )
        self.assertEqual(lnk_diff["status"], "pass")
        lnk_gate = lnk_core_accuracy_gates(
            {
                "validation_checks": {"has_valid_header": True},
                "link_flag_names": ["IsUnicode"],
                "target_path": r"C:\Users\alice\case.txt",
                "working_dir": r"C:\Users\alice",
                "target_modified_at": "2024-04-01T09:10:11+00:00",
                "lnk_trusted_diff": lnk_diff,
            }
        )[0]
        self.assertIn("trusted LNK parser diff pass", lnk_gate["satisfied_checks"])

        system_diff = build_system_trusted_diff(
            [{"artifact_family": "task-scheduler", "task_uri": r"\SecurityUpdater", "command": "powershell.exe"}],
            [{"Family": "task-scheduler", "TaskURI": r"\SecurityUpdater", "Command": "powershell.exe"}],
            trusted_tool="Velociraptor",
        )
        self.assertEqual(system_diff["status"], "pass")
        system_gate = system_core_accuracy_gates(
            "task-scheduler",
            {
                "risk_flags": ["task-string:powershell"],
                "validation_checks": {"taskcache_registry_validated": True},
                "system_trusted_diff": system_diff,
            },
        )[0]
        self.assertIn("trusted system artifact diff pass", system_gate["satisfied_checks"])

        storage_diff = build_browser_storage_trusted_diff(
            [{"browser": "chrome", "profile": "Default", "storage_type": "cache", "storage_name": "Cache_Data"}],
            [{"Browser": "chrome", "Profile": "Default", "Type": "cache", "Name": "Cache_Data"}],
            trusted_tool="Hindsight",
        )
        timeline_diff = build_browser_timeline_trusted_diff(
            [{"browser": "chrome", "profile": "Default", "timestamp": "2024-04-01T09:10:11+00:00", "url": "https://example.test"}],
            [{"Browser": "chrome", "Profile": "Default", "VisitTime": "2024-04-01T09:10:11+00:00", "URL": "https://example.test"}],
            trusted_tool="BrowserHistoryView",
        )
        self.assertEqual(storage_diff["status"], "pass")
        self.assertEqual(timeline_diff["status"], "pass")
        browser_gates = {
            gate["gap_id"]: gate
            for gate in browser_core_accuracy_gates(
                {
                    "browser": "chrome",
                    "profile": "Default",
                    "storage_inventory": [{"storage_type": "cache", "storage_name": "Cache_Data"}],
                    "unified_timeline": [{"timestamp": "2024-04-01T09:10:11+00:00", "url": "https://example.test", "transition": "typed"}],
                    "download_rows": [{"target_path": r"C:\Users\alice\Downloads\a.zip", "source_url": "https://example.test/a.zip"}],
                    "browser_storage_trusted_diff": storage_diff,
                    "browser_timeline_trusted_diff": timeline_diff,
                }
            )
        }
        self.assertIn("trusted browser storage diff pass", browser_gates["#19"]["satisfied_checks"])
        self.assertIn("trusted browser timeline diff pass", browser_gates["#20"]["satisfied_checks"])

    def test_ai_transcript_trusted_export_diff_gates_report_grade_claims(self) -> None:
        rapid_rows = [
            {
                "ai_service": "ChatGPT",
                "question": "Summarize this timeline",
                "answer": "The login happened before the download.",
                "timestamp": "2024-04-01T09:10:11+00:00",
                "source_path": "Local Storage/leveldb/000003.log",
                "source_sha256": "a" * 64,
            }
        ]
        trusted_rows = [
            {
                "Service": "ChatGPT",
                "Question": "Summarize this timeline",
                "Answer": "The login happened before the download.",
                "CreatedAt": "2024-04-01T09:10:11+00:00",
                "Source": "Local Storage/leveldb/000003.log",
            }
        ]

        transcript_diff = build_ai_transcript_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="ChatGPT export",
        )
        candidate_manifest = {
            "manifest_sha256": "b" * 64,
            "candidate_citation_count": 2,
            "pair_citations": [{"pair_id": "pair-1"}],
        }

        self.assertEqual(transcript_diff["status"], "pass")
        self.assertTrue(transcript_diff["commercial_grade_evidence"])
        gate = ai_transcript_core_accuracy_gates(
            {
                "source_path": r"C:\Users\alice",
                "browser": "chrome",
                "profile": "Default",
                "conversation_rows": rapid_rows,
                "transcript": {
                    "pair_count": 1,
                    "complete_pair_count": 1,
                    "orphan_question_count": 0,
                    "orphan_answer_count": 0,
                },
                "source_summary": {"source_sha256s": ["a" * 64]},
                "ai_transcript_trusted_diff": transcript_diff,
                "ai_transcript_candidate_manifest": candidate_manifest,
            }
        )[0]
        self.assertIn("trusted AI transcript export diff pass", gate["satisfied_checks"])
        self.assertIn("AI transcript candidate manifest", gate["satisfied_checks"])
        self.assertNotIn("trusted AI transcript export diff pass", gate["missing_required_checks"])
        uplift = ai_transcript_commercial_uplift_evidence(
            {
                "source_path": r"C:\Users\alice",
                "browser": "chrome",
                "profile": "Default",
                "conversation_rows": [
                    {"direction": "question", "ai_service": "ChatGPT", "text": "Q", "source_sha256": "a" * 64},
                    {"direction": "answer", "ai_service": "ChatGPT", "text": "A", "source_sha256": "a" * 64},
                ],
                "transcript": {
                    "complete_pair_count": 1,
                    "question_count": 1,
                    "answer_count": 1,
                    "completeness_score": 1.0,
                },
                "source_summary": {"source_file_count": 1, "service_counts": {"ChatGPT": 2}},
                "ai_transcript_candidate_manifest": candidate_manifest,
                "transcript_validation_checks": {
                    "has_candidate_transcript_rows": True,
                    "service_side_export_validated": False,
                },
                "ai_transcript_trusted_diff": transcript_diff,
            }
        )
        self.assertEqual(uplift["functional_priority_profile"]["item_number"], 48)
        self.assertEqual(
            uplift["functional_priority_profile"]["implemented_controls"]["candidate_manifest_hash"],
            "b" * 64,
        )
        self.assertIn(
            "ai-transcript-candidate-manifest-emitted",
            uplift["functional_priority_profile"]["passed_validation_check_ids"],
        )
        self.assertIn(
            "service-side-ai-export-not-validated",
            uplift["functional_priority_profile"]["failed_validation_check_ids"],
        )

    def test_ai_transcript_trusted_diff_accepts_nested_transcript_pairs(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "ai-conversation-candidate",
                "details": {
                    "ai_service": "Claude",
                    "browser": "chrome",
                    "profile": "Default",
                    "transcript_pairs": [
                        {
                            "pair_id": "pair-1",
                            "ai_service": "Claude",
                            "question": "What happened before the download?",
                            "answer": "The login event happened first.",
                            "source_sha256s": ["a" * 64],
                            "question_source_path": "IndexedDB/000001.ldb",
                            "answer_source_path": "IndexedDB/000001.ldb",
                            "pairing_evidence": {
                                "question_source_offset": 128,
                                "answer_source_offset": 256,
                                "storage_area": "IndexedDB",
                            },
                            "pairing_confidence": "high-candidate",
                            "confidence": 0.92,
                        }
                    ],
                },
            }
        ]
        trusted_rows = [
            {
                "Service": "Claude",
                "Question": "What happened before the download?",
                "Answer": "The login event happened first.",
                "SourceSha256": "a" * 64,
                "QuestionSourcePath": "IndexedDB/000001.ldb",
                "AnswerSourcePath": "IndexedDB/000001.ldb",
                "QuestionSourceOffset": "128",
                "AnswerSourceOffset": "256",
                "StorageArea": "IndexedDB",
                "PairingConfidence": "high-candidate",
                "Confidence": "0.92",
                "PairId": "pair-1",
            }
        ]

        diff = build_ai_transcript_trusted_diff(rapid_rows, trusted_rows, trusted_tool="Claude export")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_ai_transcript_trusted_diff_accepts_nested_conversation_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "ai-conversation-candidate",
                "details": {
                    "conversation_rows": [
                        {
                            "direction": "question",
                            "ai_service": "Gemini",
                            "text": "Find suspicious URLs.",
                            "source_path": "Local Storage/leveldb/000003.log",
                            "source_sha256": "b" * 64,
                            "source_offset": 32,
                            "storage_area": "Local Storage",
                            "confidence": 0.91,
                        },
                        {
                            "direction": "answer",
                            "ai_service": "Gemini",
                            "text": "The suspicious URL is https://bad.example/.",
                            "source_path": "Local Storage/leveldb/000003.log",
                            "source_sha256": "b" * 64,
                            "source_offset": 96,
                            "storage_area": "Local Storage",
                            "confidence": 0.9,
                        },
                    ]
                },
            }
        ]
        trusted_rows = [
            {
                "Service": "Gemini",
                "Question": "Find suspicious URLs.",
                "Answer": "The suspicious URL is https://bad.example/.",
                "SourceSha256": "b" * 64,
                "QuestionSourcePath": "Local Storage/leveldb/000003.log",
                "AnswerSourcePath": "Local Storage/leveldb/000003.log",
                "QuestionSourceOffset": "32",
                "AnswerSourceOffset": "96",
                "StorageArea": "Local Storage",
                "PairingConfidence": "high-candidate",
            }
        ]

        diff = build_ai_transcript_trusted_diff(rapid_rows, trusted_rows, trusted_tool="Gemini export")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_ai_transcript_trusted_diff_blocks_nested_pair_mismatches(self) -> None:
        diff = build_ai_transcript_trusted_diff(
            [
                {
                    "artifact_type": "ai-conversation-candidate",
                    "details": {
                        "transcript_pairs": [
                            {
                                "ai_service": "Perplexity",
                                "question": "Q",
                                "answer": "A",
                                "source_sha256s": ["c" * 64],
                            }
                        ]
                    },
                }
            ],
            [
                {
                    "Service": "Perplexity",
                    "Question": "Q",
                    "Answer": "A",
                    "SourceSha256": "d" * 64,
                }
            ],
            trusted_tool="Perplexity export",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "source_sha256s")

    def test_lnk_property_store_extra_data_preserves_review_candidates(self) -> None:
        payload = (
            b"\x05\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae"
            + r"C:\Users\alice\Documents\Case Notes.docx".encode("utf-16le")
        )
        block = (
            (len(payload) + 8).to_bytes(4, "little")
            + (0xA0000009).to_bytes(4, "little")
            + payload
            + b"\x00\x00\x00\x00"
        )

        blocks, tracker = parse_lnk_extra_data(block, 0)

        self.assertEqual(tracker, {})
        self.assertEqual(blocks[0]["type"], "PropertyStoreDataBlock")
        property_store = blocks[0]["property_store_data"]
        self.assertEqual(property_store["parse_status"], "parsed-candidate")
        self.assertIn(r"C:\Users\alice\Documents\Case Notes.docx", property_store["embedded_paths"])
        self.assertTrue(property_store["guid_candidates"])
        self.assertEqual(property_store["reportability"], "review-only")

    def test_prefetch_lnk_system_and_browser_trusted_diffs_block_mismatches(self) -> None:
        prefetch_diff = build_prefetch_trusted_diff(
            [{"executable_hint": "POWERSHELL.EXE", "prefetch_hash": "12345678", "run_count": "3"}],
            [{"Executable": "POWERSHELL.EXE", "Hash": "12345678", "RunCount": "99"}],
            trusted_tool="PECmd",
        )
        self.assertEqual(prefetch_diff["status"], "diffs-present")
        self.assertFalse(prefetch_diff["commercial_grade_evidence"])
        self.assertEqual(prefetch_diff["mismatch_count"], 1)

        browser_diff = build_browser_timeline_trusted_diff(
            [{"browser": "chrome", "profile": "Default", "timestamp": "2024-04-01T09:10:11+00:00", "url": "https://example.test"}],
            [{"Browser": "chrome", "Profile": "Default", "VisitTime": "2024-04-01T09:10:11+00:00", "URL": "https://example.test"}],
            trusted_tool="unknown-browser-tool",
        )
        self.assertEqual(browser_diff["status"], "diffs-present")
        self.assertFalse(browser_diff["trusted_tool_recognized"])
        self.assertIn("browser-timeline-trusted-diff-required", browser_diff["reportability_decision"]["blockers"])

        ai_diff = build_ai_transcript_trusted_diff(
            [{"ai_service": "Claude", "question": "Q", "answer": "rapid"}],
            [{"Service": "Claude", "Question": "Q", "Answer": "trusted"}],
            trusted_tool="unknown-ai-tool",
        )
        self.assertEqual(ai_diff["status"], "diffs-present")
        self.assertFalse(ai_diff["trusted_tool_recognized"])
        self.assertIn("ai-transcript-trusted-export-diff-required", ai_diff["reportability_decision"]["blockers"])

    def test_native_amcache_clusters_path_hash_timestamp_and_metadata(self) -> None:
        payload = (
            "C:\\Program Files\\Example\\app.exe\x00"
            "0123456789abcdef0123456789abcdef01234567\x00"
            "Example Publisher\x00"
            "2024-04-01T02:03:04Z\x00"
        ).encode("utf-16le")
        occurrences = list(iter_registry_like_string_occurrences(b"\x00" * 64 + payload))

        clusters = collect_amcache_candidate_clusters(occurrences)

        self.assertEqual(len(clusters), 1)
        cluster = clusters[0]
        self.assertEqual(cluster["executable_path"], r"C:\Program Files\Example\app.exe")
        self.assertEqual(cluster["sha1_candidates"], ["0123456789abcdef0123456789abcdef01234567"])
        self.assertEqual(cluster["timestamp_candidates"], ["2024-04-01T02:03:04+00:00"])
        self.assertIn("Example Publisher", cluster["metadata_candidates"])
        self.assertGreater(cluster["source_offset"], 0)
        self.assertGreaterEqual(cluster["parser_confidence"], 0.6)

    def test_amcache_trusted_diff_accepts_nested_artifact_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "amcache-entry",
                "details": {
                    "source_format": "reg",
                    "executable_path": r"C:\Program Files\Example\app.exe",
                    "timestamp": "2024-04-01T02:03:04Z",
                    "timestamp_source": "InventoryApplicationFile.LastModified",
                    "program_name": "Example App",
                    "publisher": "Example Publisher",
                    "sha1": "0123456789abcdef0123456789abcdef01234567",
                    "file_description": "Example Application Binary",
                    "product_name": "Example Suite",
                    "execution_caveat": "Amcache is not standalone proof of execution.",
                },
            }
        ]
        trusted_rows = [
            {
                "SourceFormat": "reg",
                "Path": r"C:\Program Files\Example\app.exe",
                "LastModified": "2024-04-01T02:03:04+00:00",
                "TimestampSource": "inventoryapplicationfile.lastmodified",
                "Name": "Example App",
                "Publisher": "Example Publisher",
                "SHA1": "0123456789abcdef0123456789abcdef01234567",
                "FileDescription": "Example Application Binary",
                "ProductName": "Example Suite",
                "Warning": "Amcache is not standalone proof of execution.",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="AmcacheParser",
            artifact_family="amcache",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertIn("publisher", diff["compare_fields"])

    def test_amcache_trusted_diff_blocks_metadata_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "amcache-entry",
                "details": {
                    "executable_path": r"C:\Program Files\Example\app.exe",
                    "timestamp": "2024-04-01T02:03:04+00:00",
                    "sha1": "0123456789abcdef0123456789abcdef01234567",
                    "publisher": "Example Publisher",
                },
            }
        ]
        trusted_rows = [
            {
                "Path": r"C:\Program Files\Example\app.exe",
                "LastModified": "2024-04-01T02:03:04+00:00",
                "SHA1": "0123456789abcdef0123456789abcdef01234567",
                "Publisher": "Different Publisher",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="AmcacheParser",
            artifact_family="amcache",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field_diffs"][0]["field"], "publisher")

    def test_native_shimcache_clusters_preserve_order_offsets_and_caveat_metadata(self) -> None:
        payload = (
            "ControlSet001\\Control\\Session Manager\\AppCompatCache\x00"
            "C:\\Users\\alice\\AppData\\Roaming\\legacy.exe\x00"
            "LastModified=2024-04-01T03:04:05Z\x00"
            "C:\\Windows\\System32\\cleanmgr.exe\x00"
        ).encode("utf-16le")
        occurrences = list(iter_registry_like_string_occurrences(b"\x00" * 64 + payload))

        clusters = collect_shimcache_candidate_clusters(occurrences)

        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0]["cache_order"], 0)
        self.assertTrue(clusters[0]["executable_path"].endswith("legacy.exe"))
        self.assertGreater(clusters[0]["source_offset"], 0)
        self.assertEqual(clusters[0]["timestamp_candidates"], ["2024-04-01T03:04:05+00:00"])
        self.assertIn("AppCompatCache", " ".join(clusters[0]["nearby_metadata_candidates"]))
        self.assertTrue(clusters[1]["executable_path"].endswith("cleanmgr.exe"))

    def test_shimcache_trusted_diff_accepts_nested_artifact_rows_with_order_and_offset(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "shimcache-entry",
                "details": {
                    "source_format": "system-hive-native-shimcache-scan",
                    "source_key": r"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
                    "source_offset": 8192,
                    "cache_order": 0,
                    "executable_path": r"C:\Users\alice\AppData\Roaming\legacy.exe",
                    "timestamp": "2024-04-01T03:04:05Z",
                    "timestamp_source": "native-shimcache-nearby-string-timestamp-candidate",
                    "os_build": "22631",
                    "shimcache_evidence": {
                        "execution_caveat": "ShimCache/AppCompatCache can show program presence/order, but it is not standalone proof of execution.",
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "SourceFormat": "system-hive-native-shimcache-scan",
                "SourceKey": r"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
                "SourceOffset": "0x2000",
                "CacheOrder": "0",
                "Path": r"C:\Users\alice\AppData\Roaming\legacy.exe",
                "LastModified": "2024-04-01T03:04:05+00:00",
                "TimestampSource": "native-shimcache-nearby-string-timestamp-candidate",
                "OSBuild": "22631",
                "Warning": "ShimCache/AppCompatCache can show program presence/order, but it is not standalone proof of execution.",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="AppCompatCacheParser",
            artifact_family="shimcache-appcompatcache",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertIn("cache_order", diff["compare_fields"])

    def test_shimcache_trusted_diff_blocks_order_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "shimcache-entry",
                "details": {
                    "source_offset": 8192,
                    "cache_order": 0,
                    "executable_path": r"C:\Users\alice\AppData\Roaming\legacy.exe",
                    "timestamp": "2024-04-01T03:04:05+00:00",
                },
            }
        ]
        trusted_rows = [
            {
                "SourceOffset": 8192,
                "CacheOrder": 1,
                "Path": r"C:\Users\alice\AppData\Roaming\legacy.exe",
                "LastModified": "2024-04-01T03:04:05+00:00",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="AppCompatCacheParser",
            artifact_family="shimcache-appcompatcache",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field_diffs"][0]["field"], "cache_order")

    def test_native_bam_dam_clusters_preserve_sid_path_timestamp_and_source(self) -> None:
        payload = (
            "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1000\x00"
            "\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Roaming\\evil.exe\x00"
            "LastExecution=2024-04-01T06:07:08Z\x00"
        ).encode("utf-16le")
        occurrences = list(iter_registry_like_string_occurrences(b"\x00" * 64 + payload))

        clusters = collect_bam_dam_candidate_clusters(occurrences)

        self.assertEqual(len(clusters), 1)
        cluster = clusters[0]
        self.assertEqual(cluster["user_sid"], "S-1-5-21-1000")
        self.assertTrue(cluster["executable_path"].endswith("evil.exe"))
        self.assertGreater(cluster["source_offset"], 0)
        self.assertEqual(cluster["timestamp_candidates"], ["2024-04-01T06:07:08+00:00"])
        self.assertIn("Services\\bam", " ".join(cluster["nearby_metadata_candidates"]))
        self.assertGreaterEqual(cluster["parser_confidence"], 0.6)

    def test_bam_dam_trusted_diff_accepts_nested_artifact_rows_with_sid_and_device_path(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "bam-entry",
                "details": {
                    "source_format": "system-hive-native-bam-dam-scan",
                    "source_key": r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1000",
                    "source_offset": 12288,
                    "device_path": r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evil.exe",
                    "user_sid": "S-1-5-21-1000",
                    "timestamp": "2024-04-01T06:07:08Z",
                    "timestamp_source": "native-bam-dam-nearby-string-timestamp-candidate",
                    "bam_dam_evidence": {
                        "execution_caveat": "BAM/DAM is a strong recent-execution pivot but should be correlated with Prefetch, SRUM, UserAssist, and event logs.",
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "SourceFormat": "system-hive-native-bam-dam-scan",
                "SourceKey": r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1000",
                "SourceOffset": "0x3000",
                "DevicePath": r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evil.exe",
                "UserSid": "S-1-5-21-1000",
                "LastExecution": "2024-04-01T06:07:08+00:00",
                "TimestampSource": "native-bam-dam-nearby-string-timestamp-candidate",
                "Warning": "BAM/DAM is a strong recent-execution pivot but should be correlated with Prefetch, SRUM, UserAssist, and event logs.",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="RECmd BAM parser",
            artifact_family="bam-dam",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertIn("device_path", diff["compare_fields"])

    def test_bam_dam_trusted_diff_blocks_sid_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "bam-entry",
                "details": {
                    "device_path": r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evil.exe",
                    "user_sid": "S-1-5-21-1000",
                    "timestamp": "2024-04-01T06:07:08+00:00",
                },
            }
        ]
        trusted_rows = [
            {
                "DevicePath": r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evil.exe",
                "UserSid": "S-1-5-21-2000",
                "LastExecution": "2024-04-01T06:07:08+00:00",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="RECmd",
            artifact_family="bam-dam",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field_diffs"][0]["field"], "user_sid")

    def test_native_srum_row_candidates_merge_nearby_split_strings(self) -> None:
        hits = [
            {"value": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "offset": 4096, "encoding": "utf-16le"},
            {"value": "SruDbTable=NetworkUsage", "offset": 4200, "encoding": "utf-16le"},
            {"value": "UserSid=S-1-5-21-1000 Timestamp=2024-04-01T05:06:07Z", "offset": 4300, "encoding": "utf-16le"},
            {"value": "BytesSent=512 BytesReceived=2048 InterfaceLuid=12 NetworkProfile=CorpWiFi", "offset": 4400, "encoding": "utf-16le"},
        ]

        candidates = build_srum_row_candidates(hits)

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["table_family"], "network-usage")
        self.assertTrue(candidate["app_id"].endswith("powershell.exe"))
        self.assertEqual(candidate["user_sid"], "S-1-5-21-1000")
        self.assertEqual(candidate["timestamp"], "2024-04-01T05:06:07+00:00")
        self.assertEqual(candidate["bytes_received"], 2048)
        self.assertEqual(candidate["nearby_string_count"], 4)
        self.assertTrue(candidate["field_presence_profile"]["network_counters"])
        self.assertGreaterEqual(candidate["candidate_confidence"], 0.6)

    def test_srum_trusted_diff_accepts_nested_network_usage_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "srum-network-usage",
                "details": {
                    "source_format": "csv",
                    "app_id": "powershell.exe",
                    "user": "alice",
                    "timestamp": "2024-04-01T05:06:07Z",
                    "timestamp_source": "srum-export-row",
                    "srum_table_family": "network-usage",
                    "bytes_sent": 512,
                    "bytes_received": 2048,
                    "interface_luid": "12",
                    "network_profile": "CorpWiFi",
                    "srum_usage_evidence": {
                        "table_family": "network-usage",
                        "app_id": "powershell.exe",
                        "user": "alice",
                        "timestamp": "2024-04-01T05:06:07+00:00",
                        "counter_values": {
                            "bytes_sent": 512,
                            "bytes_received": 2048,
                            "interface_luid": "12",
                            "network_profile": "CorpWiFi",
                        },
                    },
                },
            }
        ]
        trusted_rows = [
            {
                "SourceFormat": "csv",
                "AppId": "powershell.exe",
                "User": "alice",
                "Timestamp": "2024-04-01T05:06:07+00:00",
                "TimestampSource": "srum-export-row",
                "TableFamily": "network-usage",
                "BytesSent": "512.0",
                "BytesReceived": "2048",
                "InterfaceLuid": "12",
                "NetworkProfile": "CorpWiFi",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="SrumECmd",
            artifact_family="srum",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertIn("bytes_received", diff["compare_fields"])

    def test_srum_trusted_diff_reports_counter_field_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "srum-row-candidate",
                "details": {
                    "app_id": "powershell.exe",
                    "timestamp": "2024-04-01T05:06:07+00:00",
                    "table_family": "network-usage",
                    "bytes_received": 2048,
                    "counter_candidates": {"bytes_received": 2048},
                },
            }
        ]
        trusted_rows = [
            {
                "AppId": "powershell.exe",
                "Timestamp": "2024-04-01T05:06:07+00:00",
                "TableFamily": "network-usage",
                "BytesReceived": 1024,
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid_rows,
            trusted_rows,
            trusted_tool="SrumECmd",
            artifact_family="srum",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        fields = [item["field"] for item in diff["mismatches"][0]["field_diffs"]]
        self.assertIn("bytes_received", fields)

    def test_windows_edb_row_candidates_prefer_page_local_source_citation(self) -> None:
        rows = build_search_row_candidates(
            {
                "path_candidates": [r"C:\Users\alice\Documents\Case Notes.docx"],
                "url_candidates": ["https://example.com/browser-history"],
                "content_candidates": ["encoded powershell investigation notes"],
                "ese_page_map": {
                    "page_samples": [
                        {
                            "page_index": 7,
                            "page_offset": 28672,
                            "page_sha256": "a" * 64,
                            "path_candidates": [r"C:\Users\alice\Documents\Case Notes.docx"],
                            "url_candidates": ["https://example.com/browser-history"],
                            "content_candidates": ["encoded powershell investigation notes"],
                            "table_marker_hits": {
                                "property-store": ["system.itempathdisplay"],
                                "content-index": ["system.search.contents"],
                                "deleted-state": ["isdeleted"],
                            },
                        }
                    ]
                },
            }
        )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["correlation_method"], "page-local-path-url-content-correlation")
        self.assertEqual(row["page_offset"], 28672)
        self.assertEqual(row["page_sha256"], "a" * 64)
        self.assertTrue(row["field_presence_profile"]["item_path"])
        self.assertTrue(row["field_presence_profile"]["content_index_marker"])
        self.assertTrue(row["field_presence_profile"]["deleted_state_marker"])
        self.assertGreaterEqual(row["parser_confidence"], 0.7)

    def test_native_evtx_binxml_promotes_duplicate_event_data_without_losing_order(self) -> None:
        value_fields = [
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "TargetUserName",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "alice",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "IpAddress",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "10.0.0.5",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "IpAddress",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "10.0.0.6",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
        ]

        promoted = native_evtx_promoted_fields({"value_fields": value_fields})

        self.assertEqual(promoted["event_data_fields"]["TargetUserName"], "alice")
        self.assertEqual(promoted["event_data_fields"]["IpAddress"], "10.0.0.5")
        self.assertEqual(promoted["event_data_values_by_name"]["IpAddress"], ["10.0.0.5", "10.0.0.6"])
        self.assertEqual(
            [item["name"] for item in promoted["event_data_sequence"]],
            ["TargetUserName", "IpAddress", "IpAddress"],
        )
        self.assertEqual(
            [item["value"] for item in promoted["event_data_sequence"]],
            ["alice", "10.0.0.5", "10.0.0.6"],
        )
        self.assertEqual(
            binxml_value_field_map(value_fields)["Event/EventData/Data"],
            ["alice", "10.0.0.5", "10.0.0.6"],
        )

    def test_native_evtx_core_accuracy_gates_track_report_grade_blockers(self) -> None:
        gates = native_evtx_core_accuracy_gates(
            {
                "source_path": "Security.evtx",
                "record_id": "42",
                "event_id": "4624",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "host01",
                "evtx_record_offset": 8192,
                "evtx_record_sha256": "a" * 64,
                "binxml_status": "partial-tokenized",
                "binxml_event_data_sequence": [
                    {"name": "TargetUserName", "value": "alice"},
                    {"name": "IpAddress", "value": "10.0.0.5"},
                ],
                "binxml_event_data_values_by_name": {"IpAddress": ["10.0.0.5"]},
                "evtx_validation_checks": {
                    "declared_size_valid": True,
                    "decoded_value_type_counts": {"StringType": 2},
                },
                "evtx_validation_matrix": [
                    {"id": "chunk-context", "passed": True},
                    {"id": "declared-size-and-offset", "passed": True},
                    {"id": "integrity-hash", "passed": True},
                ],
                "evtx_record_integrity": {"record_hash": "a" * 64},
                "evtx_trusted_tool_record_diff": {
                    "status": "pass",
                    "trusted_tool": "EvtxECmd",
                    "matched_count": 1,
                    "mismatch_count": 0,
                    "missing_in_trusted_count": 0,
                    "extra_in_trusted_count": 0,
                    "commercial_grade_evidence": True,
                },
                "evtx_recovery_context": {"validation_required": True},
                "evtx_recovery_evidence": {"caution_labels": ["slack-record-candidate"]},
                "message_rendering": {
                    "event_message": "An account was successfully logged on.",
                    "message": "An account was successfully logged on.",
                    "normalized_template_preview": "%1 logged on from %2",
                    "parameter_candidates": ["alice", "10.0.0.5"],
                    "limitations": ["provider-resource-dll-not-resolved"],
                },
                "evtx_message_rendering_diff": {
                    "status": "pass",
                    "trusted_tool": "Windows Event Viewer",
                    "matched_count": 1,
                    "mismatch_count": 0,
                    "missing_in_trusted_count": 0,
                    "extra_in_trusted_count": 0,
                    "commercial_grade_evidence": True,
                },
                "evtx_validation_guidance": {"message": "Compare against Event Viewer rendering."},
                "evtx_recovery_corpus_diff": {
                    "status": "pass",
                    "oracle": "hand-labeled deleted EVTX fixture",
                    "matched_count": 1,
                    "mismatch_count": 0,
                    "missing_in_oracle_count": 0,
                    "extra_in_oracle_count": 0,
                    "commercial_grade_evidence": True,
                },
            }
        )

        by_gap = {gate["gap_id"]: gate for gate in gates}
        self.assertEqual(set(by_gap), {"#1", "#2", "#3"})
        self.assertIn("duplicate EventData order preservation", by_gap["#1"]["satisfied_checks"])
        self.assertIn("trusted-tool record-level diff pass", by_gap["#1"]["satisfied_checks"])
        self.assertIn("message text normalization", by_gap["#2"]["satisfied_checks"])
        self.assertIn("inserted parameter mapping", by_gap["#2"]["satisfied_checks"])
        self.assertIn("provider/template/source provenance", by_gap["#2"]["satisfied_checks"])
        self.assertIn("trusted rendered-message diff pass", by_gap["#2"]["satisfied_checks"])
        self.assertIn("chunk-boundary containment", by_gap["#3"]["satisfied_checks"])
        self.assertIn("trusted recovery offset diff pass", by_gap["#3"]["satisfied_checks"])
        self.assertEqual(by_gap["#1"]["missing_required_checks"], [])
        self.assertIn("expected-answer manifest", by_gap["#1"]["minimum_evidence"])
        self.assertFalse(by_gap["#1"]["commercial_grade_ready"])
        uplift = native_evtx_commercial_uplift_evidence(
            {
                "source_path": "Security.evtx",
                "record_id": "42",
                "evtx_record_offset": 8192,
                "evtx_record_sha256": "a" * 64,
                "evtx_report_grade_assessment": {
                    "status": "validation-required",
                    "blockers": [
                        "full-binxml-field-decoding-required",
                        "broad-deleted-corrupt-record-corpus-validation-required",
                    ],
                },
            }
        )
        blocker_categories = {row["blocker"]: row["category"] for row in uplift["commercial_blocker_analysis"]}
        self.assertEqual(blocker_categories["full-binxml-field-decoding-required"], "internal_implementation")
        self.assertEqual(
            blocker_categories["broad-deleted-corrupt-record-corpus-validation-required"],
            "external_validation",
        )

    def test_evtx_trusted_tool_record_diff_requires_record_level_equality(self) -> None:
        rapid = [
            {
                "record_id": "42",
                "event_id": "4624",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "host01",
                "timestamp": "2024-01-02T03:04:05Z",
                "event_message": "Alice logged on from 10.0.0.5",
            }
        ]
        trusted = [
            {
                "event_record_id": "42",
                "eventid": "4624",
                "provider": "Microsoft-Windows-Security-Auditing",
                "log_name": "Security",
                "hostname": "host01",
                "time_created": "2024-01-02T03:04:05+00:00",
                "message": "Alice logged on from 10.0.0.5",
            }
        ]

        diff = build_evtx_trusted_tool_record_diff(rapid, trusted, trusted_tool="EvtxECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["mismatch_count"], 0)
        self.assertEqual(diff["reportability_decision"]["decision"], "record-diff-passed")

    def test_evtx_diffs_accept_nested_rapidtriage_artifact_rows(self) -> None:
        rapid_artifact = {
            "artifact_type": "eventlog-event",
            "details": {
                "record_id": "42",
                "event_id": "4624",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "host01",
                "event_created_at": "2024-01-02T03:04:05+00:00",
                "event_message": "Alice logged on from 10.0.0.5",
                "message_rendering": {"message": "Alice logged on from 10.0.0.5"},
                "evtx_record_offset": 8192,
                "evtx_record_sha256": "b" * 64,
                "evtx_declared_size": 256,
                "evtx_allocation_status": "allocated-or-live-record",
                "evtx_recovery_status": "recoverable-record",
            },
        }
        trusted = [
            {
                "event_record_id": "42",
                "eventid": "4624",
                "provider": "Microsoft-Windows-Security-Auditing",
                "log_name": "Security",
                "hostname": "host01",
                "time_created": "2024-01-02T03:04:05+00:00",
                "message": "Alice logged on from 10.0.0.5",
            }
        ]
        oracle = [
            {
                "record_offset": 8192,
                "record_sha256": "b" * 64,
                "declared_size": 256,
                "allocation_status": "allocated-or-live-record",
                "recovery_status": "recoverable-record",
            }
        ]

        record_diff = build_evtx_trusted_tool_record_diff([rapid_artifact], trusted, trusted_tool="EvtxECmd")
        message_diff = build_evtx_message_rendering_diff(
            [rapid_artifact],
            [{"event_record_id": "42", "rendered_message": "Alice logged on from 10.0.0.5"}],
            trusted_tool="Windows Event Viewer",
        )
        recovery_diff = build_evtx_recovery_corpus_diff(
            [rapid_artifact],
            oracle,
            oracle="hand-labeled deleted EVTX fixture",
        )

        self.assertEqual(record_diff["status"], "pass")
        self.assertEqual(message_diff["status"], "pass")
        self.assertEqual(recovery_diff["status"], "pass")
        self.assertTrue(record_diff["commercial_grade_evidence"])
        self.assertTrue(message_diff["commercial_grade_evidence"])
        self.assertTrue(recovery_diff["commercial_grade_evidence"])

    def test_evtx_trusted_tool_record_diff_blocks_mismatches_and_gaps(self) -> None:
        rapid = [
            {"record_id": "1", "event_id": "4624", "provider_name": "Security", "channel": "Security"},
            {"record_id": "2", "event_id": "4625", "provider_name": "Security", "channel": "Security"},
        ]
        trusted = [
            {"record_id": "1", "event_id": "4625", "provider_name": "Security", "channel": "Security"},
            {"record_id": "3", "event_id": "1102", "provider_name": "Security", "channel": "Security"},
        ]

        diff = build_evtx_trusted_tool_record_diff(rapid, trusted, trusted_tool="Hayabusa")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["missing_in_trusted_count"], 1)
        self.assertEqual(diff["extra_in_trusted_count"], 1)
        self.assertEqual(diff["mismatches"][0]["record_key"], "1")
        self.assertEqual(diff["reportability_decision"]["decision"], "do-not-use-native-evtx-as-final")

    def test_evtx_message_rendering_diff_normalizes_and_compares_rendered_text(self) -> None:
        rapid = [
            {
                "record_id": "42",
                "message_rendering": {
                    "message": "An account was successfully logged on.\n\nSubject: Alice",
                },
            }
        ]
        trusted = [
            {
                "event_record_id": "42",
                "rendered_message": "An account was successfully logged on. Subject: Alice",
            }
        ]

        diff = build_evtx_message_rendering_diff(rapid, trusted, trusted_tool="Windows Event Viewer")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["reportability_decision"]["decision"], "rendered-message-diff-passed")

    def test_evtx_message_rendering_diff_blocks_message_wording_mismatch(self) -> None:
        rapid = [{"record_id": "42", "event_message": "Rapid fallback wording"}]
        trusted = [{"record_id": "42", "message": "Windows provider-rendered wording"}]

        diff = build_evtx_message_rendering_diff(rapid, trusted, trusted_tool="EvtxECmd")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("trusted-rendered-message-diff-required", diff["reportability_decision"]["blockers"])

    def test_evtx_recovery_corpus_diff_requires_offset_and_hash_equality(self) -> None:
        rapid = [
            {
                "evtx_record_offset": "0x2000",
                "evtx_record_sha256": "b" * 64,
                "evtx_declared_size": 256,
                "evtx_allocation_status": "slack-record-candidate",
                "evtx_recovery_status": "candidate-validation-required",
            }
        ]
        oracle = [
            {
                "record_offset": 8192,
                "record_sha256": "b" * 64,
                "declared_size": "256",
                "allocation_status": "slack-record-candidate",
                "recovery_status": "candidate-validation-required",
            }
        ]

        diff = build_evtx_recovery_corpus_diff(rapid, oracle, oracle="hand-labeled deleted EVTX fixture")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["oracle_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["reportability_decision"]["decision"], "recovery-corpus-diff-passed")

    def test_evtx_recovery_corpus_diff_blocks_unmatched_recovery_candidates(self) -> None:
        rapid = [{"evtx_record_offset": 8192, "evtx_record_sha256": "b" * 64}]
        oracle = [{"record_offset": 12288, "record_sha256": "c" * 64}]

        diff = build_evtx_recovery_corpus_diff(rapid, oracle, oracle="Hayabusa recovery export")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["missing_in_oracle_count"], 1)
        self.assertEqual(diff["extra_in_oracle_count"], 1)
        self.assertIn("deleted-corrupt-recovery-corpus-diff-required", diff["reportability_decision"]["blockers"])

    def test_shellbags_provider_emits_native_hive_candidate_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hive_path = Path(tmp_dir) / "Users" / "alice" / "UsrClass.dat"
            hive_path.parent.mkdir(parents=True, exist_ok=True)
            hive_path.write_bytes(
                build_minimal_shellbags_registry_hive(
                    datetime(2024, 4, 2, 3, 4, 5, tzinfo=timezone.utc),
                    "UsrClass.dat",
                )
            )
            transaction_log = bytearray(512)
            transaction_log[0:4] = b"HvLE"
            transaction_log[4:8] = (8).to_bytes(4, "little")
            transaction_log[8:12] = (7).to_bytes(4, "little")
            transaction_log[12:16] = (1).to_bytes(4, "little")
            (hive_path.parent / "UsrClass.dat.LOG1").write_bytes(bytes(transaction_log))

            records = list(WindowsShellbagsProvider().collect(Path(tmp_dir)))
            native = [record for record in records if record.artifact_type == "shellbag-native-candidate"]

            self.assertTrue(native)
            key_tree = next(record for record in native if record.details["candidate_source"] == "native-key-tree")
            self.assertEqual(key_tree.details["shellbag_section"], "bagmru")
            self.assertIn("0", key_tree.details["node_id_candidates"])
            self.assertIn("42", key_tree.details["bag_id_candidates"])
            self.assertTrue(key_tree.details["timestamp_candidates"])
            self.assertEqual(key_tree.details["shellbag_evidence"]["key_evidence"]["shellbag_section"], "bagmru")
            self.assertEqual(
                key_tree.details["shellbag_evidence"]["relationship_evidence"]["bag_node_relationship_status"],
                "candidate-from-key-path-and-values",
            )
            self.assertIn("42", key_tree.details["shellbag_evidence"]["relationship_evidence"]["bag_id_candidates"])
            self.assertIn("0", key_tree.details["shellbag_evidence"]["relationship_evidence"]["node_id_candidates"])
            self.assertEqual(
                key_tree.details["shellbag_evidence"]["activity_evidence"]["primary_timestamp"],
                "2024-04-02T03:04:05+00:00",
            )
            self.assertEqual(key_tree.details["forensic_review"]["gap_id"], "#15")
            self.assertIn("ShellBags", key_tree.details["forensic_review"]["artifact_goal"])
            self.assertTrue(key_tree.details["validation_checks"]["regf_header_valid"])
            self.assertFalse(key_tree.details["validation_checks"]["binary_shell_item_decoding_available"])
            self.assertTrue(key_tree.details["validation_checks"]["transaction_log_context_recorded"])
            self.assertTrue(key_tree.details["validation_checks"]["transaction_log_input_present"])
            self.assertEqual(key_tree.details["registry_transaction_log_evidence"]["recognized_log_count"], 1)
            self.assertEqual(
                key_tree.details["registry_transaction_replay_profile"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertEqual(
                key_tree.details["shellbag_evidence"]["key_evidence"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertFalse(key_tree.details["commercial_grade_ready"])
            self.assertIn("#15", key_tree.details["shellbag_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(key_tree.details["shellbag_native_capabilities"]["binary_shell_item_decode"])
            self.assertIn("requires_dedicated_shellbags_parser", key_tree.details["validation_checks"])
            shellbag_gate = key_tree.details["core_accuracy_gates"][0]
            self.assertEqual(shellbag_gate["gap_id"], "#15")
            self.assertIn("BagMRU/Bags relationship", shellbag_gate["satisfied_checks"])
            self.assertIn("timestamp source labeling", shellbag_gate["satisfied_checks"])
            self.assertIn("UsrClass/NTUSER correlation", shellbag_gate["satisfied_checks"])
            self.assertIn("transaction log context recorded", shellbag_gate["satisfied_checks"])
            self.assertIn("deleted/slack validation warning", shellbag_gate["satisfied_checks"])
            self.assertIn("shell item binary decoding", shellbag_gate["missing_required_checks"])
            shellbag_uplift = key_tree.details["commercial_uplift_evidence"]
            self.assertEqual(shellbag_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(shellbag_uplift["item_numbers"], [15])
            self.assertEqual(
                shellbag_uplift["reportability_decision"]["decision"],
                "do-not-report-folder-access-as-final",
            )
            self.assertEqual(
                shellbag_uplift["reportability_decision"]["allowed_use"],
                "folder-view-history-triage-pivot",
            )
            self.assertIn("regf-header-valid", shellbag_uplift["passed_validation_matrix_ids"])
            self.assertIn("binary-shell-item-decoding-available", shellbag_uplift["failed_validation_matrix_ids"])
            self.assertTrue(
                shellbag_uplift["large_data_controls"]["transaction_log_replay_required_for_commercial_claims"]
            )
            shellbag_manifest = key_tree.details["shellbag_depth_manifest"]
            self.assertEqual(shellbag_manifest["manifest_version"], "shellbag-depth-manifest-v1")
            self.assertEqual(shellbag_manifest["gap_id"], "#15")
            self.assertEqual(shellbag_manifest["source"]["user_hive_scope"], "usrclass")
            self.assertEqual(shellbag_manifest["row_identity"]["shellbag_section"], "bagmru")
            self.assertIn("42", shellbag_manifest["bag_relationship"]["bag_id_candidates"])
            self.assertFalse(shellbag_manifest["bag_relationship"]["bag_node_relationship_validated"])
            self.assertEqual(
                shellbag_manifest["activity_timestamps"]["primary_timestamp"],
                "2024-04-02T03:04:05+00:00",
            )
            self.assertFalse(shellbag_manifest["binary_payload"]["binary_shell_item_decode_capability"])
            self.assertEqual(
                shellbag_manifest["transaction_and_deleted_state"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertFalse(
                shellbag_manifest["transaction_and_deleted_state"]["deleted_slack_validation_available"],
            )
            self.assertEqual(
                shellbag_manifest["reportability"]["allowed_use"],
                "folder-view-history-triage-pivot",
            )
            shellbag_review_profile = key_tree.details["shellbag_analyst_review_profile"]
            self.assertEqual(shellbag_review_profile["profile_version"], "shellbag-analyst-review-profile-v1")
            self.assertEqual(shellbag_review_profile["source_field_values"]["shellbag_section"], "bagmru")
            self.assertEqual(shellbag_review_profile["source_field_values"]["user_hive_scope"], "usrclass")
            self.assertIn("ShellBagsExplorer/SBECmd", shellbag_review_profile["correlation_targets"])
            self.assertIn("final shell-item path semantics", shellbag_review_profile["not_proof_of"])
            self.assertIn("trusted ShellBags parser diff is required", shellbag_review_profile["commercial_blockers"])
            self.assertFalse(shellbag_manifest["reportability"]["folder_access_final"])
            self.assertEqual(
                key_tree.details["shellbag_depth_manifest_hash"],
                shellbag_manifest["manifest_sha256"],
            )

    def test_registry_hive_reconstructs_native_key_and_value_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hive_path = Path(tmp_dir) / "NTUSER.DAT"
            hive_path.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
                    "NTUSER.DAT",
                    [
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe",
                    ],
                )
            )
            transaction_log = bytearray(512)
            transaction_log[0:4] = b"HvLE"
            transaction_log[4:8] = (8).to_bytes(4, "little")
            transaction_log[8:12] = (7).to_bytes(4, "little")
            transaction_log[12:16] = (1).to_bytes(4, "little")
            (hive_path.parent / "NTUSER.DAT.LOG1").write_bytes(bytes(transaction_log))

            records = list(collect_registry_hive(hive_path))

            hive_inventory = next(record for record in records if record.artifact_type == "registry-hive")
            key_tree_nodes = [record for record in records if record.artifact_type == "registry-key-tree-node"]
            run_key = next(record for record in key_tree_nodes if record.details["name"] == "Run")
            self.assertEqual(run_key.details["key_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(run_key.details["key_path_confidence"], "parent-chain")
            self.assertEqual(run_key.details["key_path_components"], ["Software", "Run"])
            self.assertEqual(run_key.details["key_depth"], 2)
            self.assertEqual(run_key.details["key_tree_path_evidence"]["full_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(run_key.details["key_tree_path_evidence"]["path_confidence"], "parent-chain")
            self.assertTrue(run_key.details["key_tree_path_evidence"]["root_reachable"])
            self.assertTrue(run_key.details["root_reachable"])
            self.assertFalse(run_key.details["is_root_key"])
            self.assertTrue(run_key.details["parent_link_consistency"])
            self.assertEqual(
                run_key.details["registry_key_tree_relationships"]["ancestor_cell_offsets"],
                run_key.details["key_ancestry_cell_offsets"],
            )
            self.assertFalse(run_key.details["key_tree_path_evidence"]["cycle_detected"])
            self.assertEqual(len(run_key.details["key_ancestry_cell_offsets"]), 2)
            self.assertEqual(run_key.details["value_names"], ["SecurityUpdater"])
            self.assertEqual(run_key.details["linked_value_count"], 1)
            self.assertEqual(run_key.details["missing_value_cell_offsets"], [])
            self.assertEqual(
                run_key.details["registry_subkey_list_profile"]["profile_version"],
                "registry-subkey-list-profile-v1",
            )
            self.assertEqual(run_key.details["registry_subkey_list_profile"]["list_validation_status"], "resolved")
            self.assertEqual(run_key.details["registry_subkey_list_profile"]["stable"]["status"], "not-declared")
            self.assertEqual(run_key.details["registry_value_list_profile"]["status"], "resolved")
            self.assertEqual(run_key.details["registry_value_list_profile"]["declared_value_count"], 1)
            self.assertEqual(run_key.details["registry_value_list_profile"]["decoded_value_count"], 1)
            self.assertEqual(len(run_key.details["registry_value_list_profile"]["cell_sha256"]), 64)
            reconstruction = run_key.details["registry_key_tree_reconstruction_profile"]
            self.assertEqual(
                reconstruction["profile_version"],
                "registry-key-tree-reconstruction-profile-v1",
            )
            self.assertEqual(reconstruction["reconstruction_status"], "bounded-node-reconstructed")
            self.assertTrue(reconstruction["root_reachable"])
            self.assertTrue(reconstruction["parent_child_backlinks_consistent"])
            self.assertTrue(reconstruction["subkey_lists_resolved"])
            self.assertTrue(reconstruction["value_list_resolved"])
            self.assertFalse(reconstruction["validation_required"])
            self.assertFalse(run_key.details["validation_required"])
            self.assertFalse(run_key.details["commercial_grade_ready"])
            self.assertEqual(
                run_key.details["registry_report_grade_assessment"]["status"],
                "triage-validated-report-grade-blocked",
            )
            self.assertIn("#4", run_key.details["registry_report_grade_assessment"]["commercial_gap_ids"])
            self.assertTrue(run_key.details["registry_native_capabilities"]["parent_chain_path_reconstruction"])
            self.assertFalse(run_key.details["registry_native_capabilities"]["transaction_log_replay"])
            self.assertEqual(
                hive_inventory.details["registry_transaction_log_evidence"]["status"],
                "present-not-replayed",
            )
            self.assertEqual(
                hive_inventory.details["registry_transaction_replay_profile"]["profile_version"],
                "registry-transaction-replay-profile-v1",
            )
            self.assertEqual(
                hive_inventory.details["registry_transaction_replay_profile"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertTrue(
                hive_inventory.details["registry_transaction_replay_profile"]["replay_required_for_report_grade"]
            )
            self.assertIn(
                "transaction-log-replay-or-second-parser-diff-required",
                hive_inventory.details["registry_transaction_replay_profile"]["blockers"],
            )
            self.assertEqual(run_key.details["registry_transaction_log_evidence"]["present_count"], 1)
            self.assertEqual(run_key.details["registry_transaction_log_evidence"]["recognized_log_count"], 1)
            self.assertEqual(run_key.details["registry_transaction_log_evidence"]["unrecognized_log_count"], 0)
            self.assertFalse(run_key.details["registry_transaction_log_evidence"]["transaction_log_replay_applied"])
            self.assertEqual(run_key.details["registry_transaction_log_evidence"]["replay_policy"], "detect-and-disclose-only")
            self.assertIn("NTUSER.DAT.LOG1", run_key.details["registry_transaction_log_evidence"]["expected_log_names"])
            self.assertIn("not replayed", run_key.details["registry_transaction_log_evidence"]["impact_statement"])
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["present_logs"][0]["header"]["signature"],
                "HvLE",
            )
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["present_logs"][0]["signature_status"],
                "recognized-transaction-log",
            )
            self.assertTrue(
                run_key.details["registry_transaction_log_evidence"]["present_logs"][0]["replay_readiness"][
                    "candidate_for_future_replay"
                ]
            )
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["replay_inputs"][
                    "recognized_replay_input_count"
                ],
                1,
            )
            self.assertTrue(
                run_key.details["registry_transaction_log_evidence"]["replay_inputs"][
                    "ready_for_future_internal_replay"
                ]
            )
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["transaction_context_quality"]["level"],
                "recognized-logs-present",
            )
            self.assertEqual(
                run_key.details["registry_transaction_replay_profile"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertEqual(run_key.details["registry_transaction_replay_profile"]["recognized_replay_input_count"], 1)
            self.assertFalse(run_key.details["registry_transaction_replay_profile"]["complete_log_pair_present"])
            self.assertEqual(
                run_key.details["registry_transaction_replay_profile"]["transaction_context_quality"],
                "recognized-logs-present",
            )
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["present_logs"][0]["name"],
                "NTUSER.DAT.LOG1",
            )
            validation_matrix = {item["id"]: item for item in run_key.details["registry_validation_matrix"]}
            self.assertTrue(validation_matrix["regf-header"]["passed"])
            self.assertTrue(validation_matrix["parent-chain"]["passed"])
            self.assertTrue(validation_matrix["root-reachability"]["passed"])
            self.assertTrue(validation_matrix["child-parent-backlinks"]["passed"])
            self.assertTrue(validation_matrix["value-list-resolution"]["passed"])
            self.assertTrue(validation_matrix["transaction-log-context-recorded"]["passed"])
            self.assertEqual(validation_matrix["transaction-log-context-recorded"]["detail"], "present-not-replayed")
            key_gate = run_key.details["core_accuracy_gates"][0]
            self.assertEqual(key_gate["gap_id"], "#4")
            self.assertIn("root-cell reachability", key_gate["satisfied_checks"])
            self.assertIn("parent-child backlink consistency", key_gate["satisfied_checks"])
            self.assertIn("transaction-log replay disclosure", key_gate["satisfied_checks"])
            self.assertEqual(key_gate["missing_required_checks"], ["trusted registry key-tree diff pass"])
            self.assertIn("source file or export hash", key_gate["minimum_evidence"])
            self.assertFalse(key_gate["commercial_grade_ready"])
            key_uplift = run_key.details["commercial_uplift_evidence"]
            self.assertEqual(key_uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(key_uplift["item_numbers"], [4])
            self.assertEqual(key_uplift["implementation_track"], "native-parser-depth")
            self.assertIn("root-reachability", key_uplift["passed_validation_matrix_ids"])
            key_blocker_categories = {
                row["blocker"]: row["category"] for row in key_uplift["commercial_blocker_analysis"]
            }
            self.assertEqual(
                key_blocker_categories["transaction-log-replay-not-implemented"],
                "internal_implementation",
            )
            self.assertEqual(
                key_blocker_categories["deleted-cell-known-answer-corpus-validation-required"],
                "external_validation",
            )
            self.assertEqual(key_uplift["large_data_controls"]["reader"], "bounded-hbin-cell-scan")
            self.assertTrue(
                key_uplift["large_data_controls"]["transaction_log_replay_required_for_commercial_claims"]
            )
            self.assertEqual(key_uplift["key_tree_diff"]["status"], "not-attached")
            key_depth = run_key.details["registry_native_depth_readiness_profile"]
            self.assertEqual(key_depth["profile_version"], "registry-native-depth-readiness-v1")
            self.assertEqual(key_depth["family"], "key-tree")
            self.assertEqual(key_depth["artifact_scope"], "key-tree-node")
            self.assertFalse(key_depth["commercial_grade_ready"])
            self.assertTrue(key_depth["decoded_components"]["parent_chain_path_reconstruction"])
            self.assertTrue(key_depth["decoded_components"]["value_list_linking"])
            self.assertFalse(key_depth["decoded_components"]["transaction_log_replay"])
            self.assertEqual(key_depth["validation_summary"]["transaction_log_status"], "present-not-replayed")
            self.assertEqual(
                key_depth["registry_key_tree_reconstruction_profile"]["reconstruction_status"],
                "bounded-node-reconstructed",
            )
            self.assertIn("source_sha256", key_depth["source_citation_requirements"])
            key_manifest = run_key.details["registry_report_citation_manifest"]
            self.assertEqual(key_manifest["manifest_version"], "registry-report-citation-manifest-v1")
            self.assertEqual(key_manifest["artifact_type"], "registry-key-tree-node")
            self.assertEqual(key_manifest["row_identity"]["key_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(key_manifest["validation_summary"]["transaction_log_status"], "present-not-replayed")
            self.assertEqual(
                key_manifest["reportability"]["allowed_use"],
                "registry-native-triage-review-pivot",
            )
            self.assertFalse(key_manifest["reportability"]["ready_for_court_report"])
            self.assertEqual(len(key_manifest["manifest_sha256"]), 64)
            key_citation_kinds = {item["kind"] for item in key_manifest["citation_refs"]}
            self.assertIn("registry-hive-source", key_citation_kinds)
            self.assertIn("registry-cell-offset", key_citation_kinds)
            self.assertIn("registry-key-path", key_citation_kinds)
            self.assertIn("registry-transaction-log-context", key_citation_kinds)
            key_review = run_key.details["registry_analyst_review_profile"]
            self.assertEqual(key_review["profile_version"], "registry-analyst-review-profile-v1")
            self.assertEqual(key_review["catalog_key"], "persistence")
            self.assertEqual(key_review["source_field_values"]["key_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertIn("prefetch", key_review["correlation_targets"])
            self.assertIn("transaction-log-present-not-replayed", key_review["commercial_blockers"])

            value_recovery = next(
                record
                for record in records
                if record.artifact_type == "registry-value-recovery-candidate"
                and record.details["name"] == "SecurityUpdater"
            )
            self.assertEqual(value_recovery.details["parent_key_path_candidate"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(value_recovery.details["parent_key_confidence"], "key-value-list")
            self.assertGreater(value_recovery.details["parent_key_cell_offset"], 0)
            self.assertEqual(value_recovery.details["decoded_data_preview"], "1")
            self.assertEqual(
                value_recovery.details["registry_report_grade_assessment"]["status"],
                "recovery-candidate-validation-required",
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_evidence"]["candidate_kind"],
                "deleted-or-free-value-cell",
            )
            self.assertTrue(value_recovery.details["registry_recovery_evidence"]["positive_size_free_cell"])
            self.assertEqual(
                value_recovery.details["registry_recovery_evidence"]["allocator_context"]["validation_status"],
                "free-cell-candidate-validation-required",
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_evidence"]["allocator_neighbor_context"][
                    "profile_version"
                ],
                "registry-allocator-neighbor-context-v1",
            )
            self.assertGreaterEqual(
                value_recovery.details["registry_recovery_evidence"]["allocator_neighbor_context"][
                    "ordered_cell_index"
                ],
                0,
            )
            self.assertIn(
                "allocator:neighbor-context-recorded",
                value_recovery.details["registry_recovery_evidence"]["evidence_reasons"],
            )
            self.assertEqual(value_recovery.details["registry_recovery_evidence"]["parent_confidence"], "key-value-list")
            self.assertIn(
                "parent:key-value-list",
                value_recovery.details["registry_recovery_evidence"]["evidence_reasons"],
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_validation_profile"]["candidate_class"],
                "deleted-value-cell",
            )
            self.assertFalse(
                value_recovery.details["registry_recovery_validation_profile"][
                    "reportable_without_secondary_validation"
                ]
            )
            self.assertIn(
                "parent-key-link-confirmation",
                value_recovery.details["registry_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_validation_profile"]["independent_validation_status"],
                "required",
            )
            self.assertIn(
                "known-answer-deleted-cell-corpus",
                value_recovery.details["registry_recovery_validation_profile"]["false_positive_controls"],
            )
            self.assertTrue(
                value_recovery.details["registry_recovery_validation_profile"][
                    "allocator_neighbor_context_present"
                ]
            )
            self.assertIn(
                "allocator-neighbor-context-review",
                value_recovery.details["registry_recovery_validation_profile"]["false_positive_controls"],
            )
            self.assertIn(
                "candidate only",
                value_recovery.details["registry_recovery_validation_profile"]["analyst_wording"],
            )
            value_reportability = value_recovery.details["registry_recovery_reportability_decision"]
            self.assertEqual(value_reportability["decision"], "do-not-report-as-fact")
            self.assertEqual(value_reportability["allowed_use"], "triage-pivot-only")
            self.assertEqual(value_reportability["transaction_log_status"], "present-not-replayed")
            self.assertIn("transaction-log-present-not-replayed", value_reportability["blockers"])
            self.assertIn("hive-allocator-state-validation-required", value_reportability["blockers"])
            self.assertEqual(
                value_recovery.details["registry_transaction_log_evidence"]["status"],
                "present-not-replayed",
            )
            self.assertIn("#5", value_recovery.details["registry_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn(
                "deleted-or-free-cell-independent-validation-required",
                value_recovery.details["registry_report_grade_assessment"]["blockers"],
            )
            value_matrix = {item["id"]: item for item in value_recovery.details["registry_validation_matrix"]}
            self.assertTrue(value_matrix["deleted-value-cell"]["passed"])
            self.assertTrue(value_matrix["parent-key-link"]["passed"])
            value_gate = value_recovery.details["core_accuracy_gates"][0]
            self.assertEqual(value_gate["gap_id"], "#5")
            self.assertIn("positive-size free-cell validation", value_gate["satisfied_checks"])
            self.assertIn("parent-key confirmation", value_gate["satisfied_checks"])
            self.assertIn("allocator reportability context", value_gate["satisfied_checks"])
            self.assertIn("allocator neighbor context", value_gate["satisfied_checks"])
            self.assertIn("transaction-log context disclosure", value_gate["satisfied_checks"])
            self.assertIn("reportability blocked until independent confirmation", value_gate["satisfied_checks"])
            self.assertEqual(value_gate["missing_required_checks"], ["trusted deleted-cell offset diff pass"])
            self.assertIn("expected-answer manifest", value_gate["minimum_evidence"])
            self.assertFalse(value_gate["commercial_grade_ready"])
            value_uplift = value_recovery.details["commercial_uplift_evidence"]
            self.assertEqual(value_uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(value_uplift["item_numbers"], [5])
            self.assertIn("deleted-value-cell", value_uplift["passed_validation_matrix_ids"])
            self.assertEqual(
                value_uplift["recovery_profile_version"],
                "registry-deleted-cell-validation-v1",
            )
            self.assertEqual(value_uplift["transaction_log_status"], "present-not-replayed")
            self.assertEqual(
                value_uplift["recovery_reportability_decision"]["allowed_use"],
                "triage-pivot-only",
            )
            self.assertEqual(value_uplift["deleted_cell_diff"]["status"], "not-attached")
            self.assertTrue(value_uplift["external_evidence_required"])
            value_depth = value_recovery.details["registry_native_depth_readiness_profile"]
            self.assertEqual(value_depth["profile_version"], "registry-native-depth-readiness-v1")
            self.assertEqual(value_depth["family"], "deleted-cell")
            self.assertEqual(value_depth["artifact_scope"], "value-recovery-candidate")
            self.assertFalse(value_depth["commercial_grade_ready"])
            self.assertTrue(value_depth["decoded_components"]["deleted_free_cell_candidate_labeling"])
            self.assertTrue(value_depth["decoded_components"]["inline_value_preview"])
            self.assertFalse(value_depth["decoded_components"]["trusted_deleted_cell_diff"])
            self.assertEqual(value_depth["validation_summary"]["recovery_validation_status"], "required")
            self.assertIn("cell_offset", value_depth["source_citation_requirements"])
            value_manifest = value_recovery.details["registry_report_citation_manifest"]
            self.assertEqual(value_manifest["artifact_type"], "registry-value-recovery-candidate")
            self.assertEqual(value_manifest["citation_scope"], "deleted-value-recovery")
            self.assertEqual(value_manifest["row_identity"]["name"], "SecurityUpdater")
            self.assertEqual(
                value_manifest["row_identity"]["parent_key_path_candidate"],
                "HKEY_CURRENT_USER\\Software\\Run",
            )
            value_citation_kinds = {item["kind"] for item in value_manifest["citation_refs"]}
            self.assertIn("registry-value-or-name", value_citation_kinds)
            self.assertIn("registry-recovery-validation", value_citation_kinds)
            self.assertIn("deleted-value-cell", value_manifest["validation_summary"]["passed_matrix_ids"])
            self.assertIn("registry-deleted-cell-cross-tool-diff-required", value_manifest["reportability"]["blockers"])
            value_review = value_recovery.details["registry_analyst_review_profile"]
            self.assertEqual(value_review["catalog_key"], "deleted-cell")
            self.assertEqual(value_review["source_field_values"]["parent_key_path_candidate"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertIn("registry-explorer-diff", value_review["correlation_targets"])
            self.assertTrue(value_review["validation_required"])
            key_recovery = next(
                record
                for record in records
                if record.artifact_type == "registry-key-recovery-candidate"
                and record.details["name"] == "DeletedRun"
            )
            self.assertEqual(
                key_recovery.details["registry_recovery_validation_profile"]["candidate_class"],
                "deleted-key-cell",
            )
            self.assertIn(
                "parent-chain-and-root-reachability-review",
                key_recovery.details["registry_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertEqual(
                key_recovery.details["registry_recovery_reportability_decision"]["transaction_log_status"],
                "present-not-replayed",
            )
            self.assertIn(
                "transaction-log-present-not-replayed",
                key_recovery.details["registry_recovery_reportability_decision"]["blockers"],
            )
            self.assertEqual(key_recovery.details["commercial_uplift_evidence"]["item_numbers"], [5])
            key_recovery_manifest = key_recovery.details["registry_report_citation_manifest"]
            self.assertEqual(key_recovery_manifest["artifact_type"], "registry-key-recovery-candidate")
            self.assertEqual(key_recovery_manifest["citation_scope"], "deleted-key-recovery")
            self.assertEqual(key_recovery_manifest["row_identity"]["candidate_kind"], "deleted-or-free-key-cell")
            self.assertIn(
                "registry-recovery-validation",
                {item["kind"] for item in key_recovery_manifest["citation_refs"]},
            )

    def test_registry_key_tree_diff_compares_trusted_key_paths_and_values(self) -> None:
        rapid = [
            {
                "key_path": r"HKEY_CURRENT_USER\Software\Run",
                "value_names": ["SecurityUpdater"],
                "last_written_at": "2024-04-01T04:05:06+00:00",
                "root_reachable": True,
            }
        ]
        trusted = [
            {
                "key": r"HKCU\Software\Run",
                "value_names": "SecurityUpdater",
                "last_write_time": "2024-04-01T04:05:06+00:00",
                "root_reachable": True,
            }
        ]

        diff = build_registry_key_tree_diff(rapid, trusted, trusted_tool="Registry Explorer")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["reportability_decision"]["decision"], "key-tree-diff-passed")

    def test_registry_diffs_accept_nested_rapidtriage_artifact_rows(self) -> None:
        rapid_key_artifact = {
            "artifact_type": "registry-key-tree-node",
            "details": {
                "key_path": r"HKEY_CURRENT_USER\Software\Run",
                "value_names": ["SecurityUpdater"],
                "last_written_at": "2024-04-01T04:05:06+00:00",
                "root_reachable": True,
            },
        }
        trusted_key = [
            {
                "key": r"HKCU\Software\Run",
                "value_names": "SecurityUpdater",
                "last_write_time": "2024-04-01T04:05:06+00:00",
                "root_reachable": True,
            }
        ]
        rapid_deleted_artifact = {
            "artifact_type": "registry-value-recovery-candidate",
            "details": {
                "cell_offset": "0x3000",
                "candidate_class": "deleted-value-cell",
                "name": "SecurityUpdater",
                "decoded_data_preview": "1",
                "parent_key_path_candidate": r"HKCU\Software\Run",
            },
        }
        oracle_deleted = [
            {
                "offset": 12288,
                "candidate_class": "deleted-value-cell",
                "value_name": "SecurityUpdater",
                "data_preview": "1",
                "parent_key_path": r"HKEY_CURRENT_USER\Software\Run",
            }
        ]

        key_diff = build_registry_key_tree_diff(
            [rapid_key_artifact],
            trusted_key,
            trusted_tool="Registry Explorer",
        )
        deleted_diff = build_registry_deleted_cell_diff(
            [rapid_deleted_artifact],
            oracle_deleted,
            oracle="hand-labeled deleted registry fixture",
        )

        self.assertEqual(key_diff["status"], "pass")
        self.assertEqual(deleted_diff["status"], "pass")
        self.assertTrue(key_diff["commercial_grade_evidence"])
        self.assertTrue(deleted_diff["commercial_grade_evidence"])

    def test_registry_key_tree_diff_blocks_value_and_path_mismatches(self) -> None:
        rapid = [{"key_path": r"HKCU\Software\Run", "value_names": ["SecurityUpdater"]}]
        trusted = [{"key_path": r"HKCU\Software\Run", "value_names": ["OtherValue"]}]

        diff = build_registry_key_tree_diff(rapid, trusted, trusted_tool="RegRipper")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("registry-key-tree-cross-tool-diff-required", diff["reportability_decision"]["blockers"])

    def test_registry_deleted_cell_diff_compares_offset_class_and_data(self) -> None:
        rapid = [
            {
                "cell_offset": "0x3000",
                "candidate_class": "deleted-value-cell",
                "name": "SecurityUpdater",
                "decoded_data_preview": "1",
                "parent_key_path_candidate": r"HKCU\Software\Run",
            }
        ]
        oracle = [
            {
                "offset": 12288,
                "candidate_class": "deleted-value-cell",
                "value_name": "SecurityUpdater",
                "data_preview": "1",
                "parent_key_path": r"HKEY_CURRENT_USER\Software\Run",
            }
        ]

        diff = build_registry_deleted_cell_diff(rapid, oracle, oracle="hand-labeled deleted registry fixture")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["oracle_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["reportability_decision"]["decision"], "deleted-cell-diff-passed")

    def test_registry_deleted_cell_diff_blocks_offset_or_data_mismatch(self) -> None:
        rapid = [{"cell_offset": 12288, "candidate_class": "deleted-value-cell", "decoded_data_preview": "1"}]
        oracle = [{"cell_offset": 12288, "candidate_class": "deleted-value-cell", "decoded_data_preview": "2"}]

        diff = build_registry_deleted_cell_diff(rapid, oracle, oracle="Registry Explorer deleted-cell review")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("registry-deleted-cell-cross-tool-diff-required", diff["reportability_decision"]["blockers"])

    def test_registry_user_activity_normalizes_mru_dialog_network_and_device_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            reg_path = Path(tmp_dir) / "NTUSER-activity.reg"
            recent_doc = ",".join(f"{byte:02x}" for byte in "report.docx\x00".encode("utf-16le"))
            reg_path.write_text(
                f"""Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU]
"a"="notepad.exe C:\\\\Users\\\\alice\\\\notes.txt"
"MRUList"="a"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.docx]
"0"=hex:{recent_doc}
"MRUListEx"=hex:00,00,00,00,ff,ff,ff,ff

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\docx]
"0"=hex:{recent_doc}

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##USBSTOR#Disk&Ven_Test&Prod_Flash#123456]
"LabelFromReg"="CASEUSB"

[HKEY_CURRENT_USER\\Network\\Z]
"RemotePath"="\\\\\\\\fileserver\\\\cases"
""",
                encoding="utf-16",
            )

            records = [record for record in collect_reg_export(reg_path) if record.artifact_type == "registry-user-activity"]

            categories = {record.details["user_activity_category"] for record in records}
            self.assertIn("run-dialog-mru", categories)
            self.assertIn("recent-document", categories)
            self.assertIn("file-dialog-mru", categories)
            self.assertIn("mounted-device", categories)
            self.assertIn("network-share", categories)
            run_mru = next(record for record in records if record.details["user_activity_category"] == "run-dialog-mru")
            run_mru_command = next(row for row in run_mru.details["normalized_activity_rows"] if row["value_name"] == "a")
            self.assertEqual(run_mru_command["display_value"], r"notepad.exe C:\\Users\\alice\\notes.txt")
            recent = next(record for record in records if record.details["user_activity_category"] == "recent-document")
            recent_row = next(row for row in recent.details["normalized_activity_rows"] if row["value_name"] == "0")
            self.assertEqual(recent.details["decoded_values"]["0"]["recent_document_hint"], "report.docx")
            self.assertEqual(recent_row["display_value"], "report.docx")
            self.assertEqual(len(recent_row["binary_payload_sha256"]), 64)
            file_dialog = next(record for record in records if record.details["user_activity_category"] == "file-dialog-mru")
            self.assertIn("OpenSavePidlMRU", file_dialog.details["registry_user_activity_profile"]["target_artifact_coverage"]["matched_targets"])
            mounted = next(record for record in records if record.details["user_activity_category"] == "mounted-device")
            self.assertIn("MountPoints2", mounted.details["registry_user_activity_profile"]["target_artifact_coverage"]["matched_targets"])
            network = next(record for record in records if record.details["user_activity_category"] == "network-share")
            self.assertEqual(network.details["decoded_values"]["RemotePath"]["network_share_hint"], "Z")
            network_review = network.details["registry_analyst_review_profile"]
            self.assertEqual(network_review["catalog_key"], "network-share")
            self.assertFalse(network_review["validation_required"])
            self.assertIn("eventlog-share-access", network_review["correlation_targets"])
            self.assertTrue(
                all(record.details["registry_user_activity_profile"]["normalized_activity_schema"]["safe_for_search_index"] for record in records)
            )

    def test_registry_analyst_review_profile_bounds_large_decoded_values(self) -> None:
        profile = registry_analyst_review_profile(
            artifact_type="registry-user-activity",
            category="recent-document",
            source_format="reg",
            hive_hint="HKEY_CURRENT_USER",
            key_path=r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            decoded_values={"0": {"value": "A" * 3000}},
            normalized_rows=[{"display_value": "report.docx"}],
            risk_flags=["recent-document"],
            validation_required=False,
        )

        self.assertEqual(profile["profile_version"], "registry-analyst-review-profile-v1")
        self.assertEqual(profile["catalog_key"], "recent-document")
        self.assertIn("mft-usn", profile["correlation_targets"])
        self.assertIn("decoded_values", profile["source_field_values"])
        self.assertIn("truncated_json_preview", profile["source_field_values"]["decoded_values"])

    def test_sam_v_value_decodes_layout_string_candidates_without_secret_output(self) -> None:
        def put_descriptor(raw: bytearray, descriptor_offset: int, relative_offset: int, text: str) -> int:
            encoded = text.encode("utf-16le")
            raw[descriptor_offset : descriptor_offset + 4] = relative_offset.to_bytes(4, "little")
            raw[descriptor_offset + 4 : descriptor_offset + 8] = len(encoded).to_bytes(4, "little")
            raw[descriptor_offset + 8 : descriptor_offset + 12] = len(encoded).to_bytes(4, "little")
            absolute = 0xCC + relative_offset
            raw[absolute : absolute + len(encoded)] = encoded
            return relative_offset + len(encoded)

        raw = bytearray(0xCC + 256)
        cursor = put_descriptor(raw, 0x0C, 0, "alice")
        cursor = put_descriptor(raw, 0x18, cursor, "Alice Example")
        put_descriptor(raw, 0x60, cursor, r"C:\Users\alice")
        reg_hex = ",".join(f"{byte:02x}" for byte in raw)

        decoded = decode_sam_binary_field("V", f"hex:{reg_hex}")

        self.assertTrue(decoded["decoded"])
        self.assertEqual(decoded["layout_validation_status"], "layout-string-candidates-present")
        self.assertEqual(decoded["layout_string_fields"]["user_name"], "alice")
        self.assertEqual(decoded["layout_string_fields"]["full_name"], "Alice Example")
        self.assertEqual(decoded["layout_string_fields"]["profile_path"], r"C:\Users\alice")
        self.assertTrue(all("decoded_text" in item for item in decoded["layout_field_candidates"]))
        self.assertIn("trusted SAM parser", decoded["reportability_warning"])

    def test_os_account_trusted_diff_accepts_nested_artifact_rows(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "windows-account-lifecycle",
                "details": {
                    "user_name": "alice",
                    "rid": "0x3e8",
                    "admin_hint": True,
                    "account_disabled_hint": False,
                },
            },
            {
                "artifact_type": "windows-group-membership",
                "details": {
                    "group_name": "Administrators",
                    "member_sids": ["S-1-5-21-1000"],
                    "member_names": ["alice"],
                    "privileged_group": True,
                },
            },
            {
                "artifact_type": "windows-privilege-assignment",
                "details": {
                    "privilege": "SeRemoteInteractiveLogonRight",
                    "assigned_sids": ["S-1-5-32-544"],
                },
            },
        ]
        trusted_rows = [
            {"account_name": "alice", "account_rid": "1000", "is_admin": True, "disabled": False},
            {
                "group_name": "Administrators",
                "member_sids": "S-1-5-21-1000",
                "member_names": "alice",
                "privileged_group": True,
            },
            {"right": "SeRemoteInteractiveLogonRight", "assigned_principal_sids": ["S-1-5-32-544"]},
        ]

        diff = build_os_account_trusted_diff(rapid_rows, trusted_rows, trusted_tool="RECmd")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 3)
        self.assertEqual(diff["mismatch_count"], 0)
        self.assertEqual(diff["reportability_decision"]["decision"], "os-account-diff-passed")

    def test_os_account_trusted_diff_blocks_group_membership_mismatch(self) -> None:
        rapid_rows = [
            {
                "artifact_type": "windows-group-membership",
                "details": {
                    "group_name": "Administrators",
                    "member_sids": ["S-1-5-21-1000"],
                    "member_names": ["alice"],
                    "privileged_group": True,
                },
            }
        ]
        trusted_rows = [
            {
                "group_name": "Administrators",
                "member_sids": ["S-1-5-21-2000"],
                "member_names": ["bob"],
                "privileged_group": True,
            }
        ]

        diff = build_os_account_trusted_diff(rapid_rows, trusted_rows, trusted_tool="Registry Explorer")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("sam-security-system-trusted-diff-required", diff["reportability_decision"]["blockers"])

    def test_manifest_collects_browser_and_recent_file_artifacts_from_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "windows_artifacts"
            shutil.copytree(FIXTURE_ROOT, root)
            ntuser = root / "Users" / "alice" / "NTUSER.DAT"
            ntuser.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
                    "NTUSER.DAT",
                    [
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe",
                    ],
                )
            )
            usrclass = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            usrclass.parent.mkdir(parents=True, exist_ok=True)
            usrclass.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 5, 6, 7, tzinfo=timezone.utc),
                    "UsrClass.dat",
                    [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"],
                )
            )
            ntuser_activity = root / "Users" / "alice" / "NTUSER-activity.reg"
            ntuser_activity.write_text(
                """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count]
"P:\\Hfref\\nyvpr\\NccQngn\\Ebnzvat\\rivy.rkr"=hex:01,00,00,00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs]
"url1"="https://example.test/login"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths]
"url1"="C:\\\\Users\\\\alice\\\\Documents"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce]
"OneShot"="C:\\\\Users\\\\alice\\\\AppData\\\\Roaming\\\\oneshot.exe"
""",
                encoding="utf-16",
            )
            amcache = root / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"
            amcache.parent.mkdir(parents=True, exist_ok=True)
            amcache.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 2, 3, 4, tzinfo=timezone.utc),
                    "Amcache.hve",
                    [
                        r"C:\Program Files\Example\app.exe",
                        "0123456789abcdef0123456789abcdef01234567",
                        "Example Publisher",
                        "2024-04-01T02:03:04Z",
                    ],
                )
            )
            output = Path(tmp_dir) / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            providers = {item["name"]: item for item in payload["providers"]}

            browser_provider = providers["windows-browser-artifacts"]
            self.assertEqual(len(browser_provider["artifacts"]), 3)
            browser_keys = {
                (artifact["details"]["browser"], artifact["details"]["profile"]): artifact
                for artifact in browser_provider["artifacts"]
            }
            chrome = browser_keys[("chrome", "Default")]
            self.assertEqual(chrome["details"]["history_count"], 2)
            self.assertEqual(chrome["details"]["download_count"], 1)
            self.assertEqual(chrome["details"]["downloads"][0]["source_url"], "https://download.example.com/report.zip")
            self.assertEqual(chrome["details"]["downloads"][0]["target_path"], r"C:\Users\alice\Downloads\report.zip")
            functional_profiles = {
                item["item_number"]: item
                for item in chrome["details"]["commercial_uplift_evidence"]["functional_priority_profiles"]
            }
            self.assertEqual(functional_profiles[46]["batch_id"], "commercial-uplift-046-050")
            self.assertEqual(functional_profiles[46]["implemented_controls"]["history_count"], 2)
            self.assertEqual(len(functional_profiles[46]["implemented_controls"]["row_citation_manifest_hash"]), 64)
            self.assertEqual(functional_profiles[46]["implemented_controls"]["row_citation_count"], 3)
            self.assertEqual(functional_profiles[46]["implemented_controls"]["row_locator_count"], 3)
            self.assertIn(
                "browser-row-citation-manifest-emitted",
                functional_profiles[46]["passed_validation_check_ids"],
            )
            self.assertIn(
                "sqlite-source-viewer-locators-emitted",
                functional_profiles[46]["passed_validation_check_ids"],
            )
            self.assertIn(
                "trusted-browser-timeline-diff-required",
                functional_profiles[46]["failed_validation_check_ids"],
            )
            citation_manifest = chrome["details"]["browser_history_download_citation_manifest"]
            self.assertEqual(citation_manifest["download_citations"][0]["source_table"], "downloads")
            self.assertEqual(citation_manifest["download_citations"][0]["source_row_id"], 1)
            self.assertEqual(citation_manifest["download_citations"][0]["source_viewer_locator"]["viewer"], "sqlite")
            self.assertEqual(
                chrome["details"]["commercial_uplift_evidence"]["large_data_controls"]["row_citation_manifest_hash"],
                citation_manifest["manifest_sha256"],
            )
            self.assertEqual(functional_profiles[47]["item_number"], 47)
            self.assertEqual(len(functional_profiles[47]["implemented_controls"]["storage_citation_manifest_hash"]), 64)
            self.assertEqual(
                functional_profiles[47]["implemented_controls"]["storage_citation_count"],
                chrome["details"]["browser_storage_inventory_count"],
            )
            self.assertIn(
                "browser-storage-citation-manifest-emitted",
                functional_profiles[47]["passed_validation_check_ids"],
            )
            storage_citation_manifest = chrome["details"]["browser_storage_citation_manifest"]
            self.assertEqual(storage_citation_manifest["manifest_version"], "browser-storage-citation-manifest-v1")
            self.assertEqual(storage_citation_manifest["item_number"], 47)
            self.assertEqual(len(storage_citation_manifest["manifest_sha256"]), 64)
            self.assertEqual(storage_citation_manifest["citation_row_count"], chrome["details"]["browser_storage_inventory_count"])

            firefox = browser_keys[("firefox", "default-release")]
            self.assertEqual(firefox["artifact_type"], "browser-history")
            self.assertEqual(firefox["details"]["history"][0]["url"], "https://support.mozilla.org/kb/download-firefox")
            self.assertEqual(firefox["details"]["download_count"], 0)

            recent_provider = providers["windows-recent-files"]
            recent_types = {artifact["artifact_type"] for artifact in recent_provider["artifacts"]}
            self.assertEqual(recent_types, {"recent-shortcut", "jumplist-automatic", "jumplist-custom"})
            shortcut = next(artifact for artifact in recent_provider["artifacts"] if artifact["artifact_type"] == "recent-shortcut")
            self.assertEqual(shortcut["details"]["entry_name"], "Case Notes.lnk")
            self.assertEqual(shortcut["details"]["user"], "alice")

            event_provider = providers["windows-eventlog"]
            self.assertEqual(event_provider["artifacts"][0]["artifact_type"], "eventlog-event")
            self.assertEqual(event_provider["artifacts"][0]["details"]["event_id"], "4624")
            self.assertEqual(event_provider["artifacts"][0]["details"]["data"]["TargetUserName"], "alice")
            self.assertEqual(event_provider["artifacts"][0]["details"]["source_format"], "xml")

            registry_provider = providers["windows-registry"]
            registry_types = {artifact["artifact_type"] for artifact in registry_provider["artifacts"]}
            self.assertIn("registry-hive", registry_types)
            self.assertIn("registry-hive-cell", registry_types)
            self.assertIn("registry-key-tree-node", registry_types)
            self.assertIn("registry-key-recovery-candidate", registry_types)
            self.assertIn("registry-deleted-cell-candidate", registry_types)
            self.assertIn("registry-value-recovery-candidate", registry_types)
            self.assertIn("registry-hive-strings", registry_types)
            self.assertIn("registry-run-key", registry_types)
            self.assertIn("registry-usb", registry_types)
            self.assertIn("registry-user-activity", registry_types)
            self.assertIn("registry-summary", registry_types)
            hive = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-hive")
            self.assertEqual(hive["details"]["native_header"]["regf_valid"], True)
            self.assertEqual(hive["details"]["native_header"]["dirty"], False)
            self.assertEqual(hive["details"]["hive_hint"], "HKEY_CURRENT_USER")
            hive_strings = next(
                artifact
                for artifact in registry_provider["artifacts"]
                if artifact["artifact_type"] == "registry-hive-strings" and artifact["details"]["risk_flags"]
            )
            self.assertIn("hive-pivot:currentversion\\run", hive_strings["details"]["risk_flags"])
            self.assertIn(r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe", hive_strings["details"]["path_candidates"])
            hive_cells = [artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-hive-cell"]
            self.assertGreaterEqual(len(hive_cells), 4)
            self.assertTrue(any(artifact["details"]["cell_kind"] == "key-node" for artifact in hive_cells))
            updater_value = next(artifact for artifact in hive_cells if artifact["details"]["name"] == "SecurityUpdater")
            self.assertEqual(updater_value["details"]["allocation_status"], "free-or-deleted-candidate")
            self.assertEqual(updater_value["details"]["cell_scan_method"], "hbin-walk")
            self.assertGreater(updater_value["details"]["hbin_offset"], 0)
            self.assertIn("deleted-or-free-cell-candidate", updater_value["details"]["risk_flags"])
            key_tree_nodes = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-key-tree-node"
            ]
            self.assertTrue(any(artifact["details"]["key_path"].endswith("\\Run") for artifact in key_tree_nodes))
            self.assertTrue(all("cell_offset" in artifact["details"] for artifact in key_tree_nodes))
            deleted_cells = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-deleted-cell-candidate"
            ]
            self.assertGreaterEqual(len(deleted_cells), 2)
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in deleted_cells))
            self.assertTrue(all(artifact["details"]["registry_recovery_evidence"]["validation_required"] for artifact in deleted_cells))
            self.assertTrue(
                all(
                    not artifact["details"]["registry_recovery_validation_profile"][
                        "reportable_without_secondary_validation"
                    ]
                    for artifact in deleted_cells
                )
            )
            self.assertTrue(any(artifact["details"]["name"] == "SecurityUpdater" for artifact in deleted_cells))
            key_recovery = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-key-recovery-candidate"
            ]
            self.assertTrue(any(artifact["details"]["name"] == "DeletedRun" for artifact in key_recovery))
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in key_recovery))
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_validation_profile"]["candidate_class"]
                    == "deleted-key-cell"
                    for artifact in key_recovery
                )
            )
            self.assertTrue(
                any(
                    "allocator:positive-size-free-cell" in artifact["details"]["registry_recovery_evidence"]["evidence_reasons"]
                    for artifact in key_recovery
                )
            )
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_reportability_decision"]["allowed_use"]
                    == "triage-pivot-only"
                    for artifact in key_recovery
                )
            )
            value_recovery = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-value-recovery-candidate"
            ]
            self.assertTrue(any(artifact["details"]["name"] == "SecurityUpdater" for artifact in value_recovery))
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in value_recovery))
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_validation_profile"]["candidate_class"]
                    == "deleted-value-cell"
                    for artifact in value_recovery
                )
            )
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_evidence"]["allocator_context"]["positive_size_free_cell"]
                    for artifact in value_recovery
                )
            )
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_reportability_decision"]["decision"]
                    == "do-not-report-as-fact"
                    for artifact in value_recovery
                )
            )
            run_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-run-key")
            self.assertIn("SecurityUpdater", run_key["details"]["values"])
            self.assertEqual(run_key["details"]["persistence_values"][0]["value_name"], "SecurityUpdater")
            self.assertIn("suspicious-value:appdata", run_key["details"]["risk_flags"])
            user_activity = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-user-activity"
            ]
            categories = {artifact["details"]["user_activity_category"] for artifact in user_activity}
            self.assertIn("execution", categories)
            self.assertIn("browser-typed-url", categories)
            self.assertIn("typed-path", categories)
            self.assertIn("persistence", categories)
            self.assertIn("shellbag", categories)
            userassist = next(artifact for artifact in user_activity if artifact["details"]["user_activity_category"] == "execution")
            self.assertEqual(userassist["details"]["registry_user_activity_profile"]["item_number"], 11)
            self.assertEqual(
                userassist["details"]["registry_user_activity_profile"]["reportability_decision"]["allowed_use"],
                "searchable-user-activity-row",
            )
            self.assertFalse(userassist["details"]["registry_user_activity_profile"]["commercial_grade_ready"])
            self.assertEqual(
                userassist["details"]["decoded_values"][r"P:\Hfref\nyvpr\NccQngn\Ebnzvat\rivy.rkr"]["decoded_name"],
                r"C:\Users\alice\AppData\Roaming\evil.exe",
            )
            self.assertEqual(
                userassist["details"]["normalized_activity_rows"][0]["display_value"],
                r"C:\Users\alice\AppData\Roaming\evil.exe",
            )
            self.assertTrue(userassist["details"]["registry_user_activity_profile"]["normalized_activity_schema"]["safe_for_search_index"])
            typed_url = next(artifact for artifact in user_activity if artifact["details"]["user_activity_category"] == "browser-typed-url")
            self.assertEqual(typed_url["details"]["decoded_values"]["url1"]["typed_value"], "https://example.test/login")
            hive_shellbag = next(
                artifact
                for artifact in user_activity
                if artifact["details"]["coverage_status"] == "native-hive-string-pivot"
                and artifact["details"]["user_activity_category"] == "shellbag"
            )
            self.assertTrue(hive_shellbag["details"]["validation_required"])
            self.assertEqual(hive_shellbag["details"]["registry_user_activity_profile"]["current_decode_level"], "native-hive-string-pivot")
            self.assertEqual(
                hive_shellbag["details"]["registry_user_activity_profile"]["reportability_decision"]["decision"],
                "do-not-report-as-final-user-activity",
            )
            usb_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-usb")
            self.assertEqual(usb_key["details"]["usb_device"]["serial_hint"], "1234567890")
            summary = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-summary")
            self.assertEqual(summary["details"]["key_count"], 7)
            self.assertEqual(summary["details"]["hive_file_count"], 2)
            self.assertEqual(summary["details"]["hive_string_row_count"], 2)
            self.assertGreaterEqual(summary["details"]["hive_cell_row_count"], 4)
            self.assertGreaterEqual(summary["details"]["key_tree_node_count"], 2)
            self.assertGreaterEqual(summary["details"]["deleted_cell_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["key_recovery_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["value_recovery_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["user_activity_count"], 5)
            self.assertEqual(summary["details"]["persistence_entries"][0]["value_name"], "SecurityUpdater")
            self.assertEqual(summary["details"]["usb_devices"][0]["friendly_name"], "Test USB Device")
            self.assertTrue(summary["details"]["hive_string_hits"])
            self.assertTrue(summary["details"]["hive_cell_hits"])
            self.assertTrue(summary["details"]["key_tree_nodes"])
            self.assertTrue(summary["details"]["deleted_cell_candidates"])
            self.assertTrue(summary["details"]["key_recovery_candidates"])
            self.assertTrue(summary["details"]["value_recovery_candidates"])
            self.assertTrue(summary["details"]["user_activity_entries"])
            self.assertFalse(summary["details"]["native_capabilities"]["transaction_log_replay"])
            status_counts = {
                item["value"]: item["count"] for item in summary["details"]["native_report_grade_status_counts"]
            }
            self.assertGreaterEqual(
                status_counts["triage-validated-report-grade-blocked"],
                2,
            )
            self.assertIn(
                {"value": "recovery-candidate-validation-required", "count": 4},
                summary["details"]["native_report_grade_status_counts"],
            )

            shellbags_provider = providers["windows-shellbags"]
            self.assertEqual(shellbags_provider["artifacts"][0]["artifact_type"], "shellbag-key")
            self.assertIn("BagMRU", shellbags_provider["artifacts"][0]["details"]["key"])

            prefetch_provider = providers["windows-prefetch"]
            self.assertEqual(prefetch_provider["artifacts"][0]["artifact_type"], "prefetch-file")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["executable_hint"], "POWERSHELL.EXE")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["prefetch_hash"], "12345678")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["coverage_status"], "detected")
            self.assertEqual(len(prefetch_provider["artifacts"][0]["details"]["source_hashes"]["sha256"]), 64)

            execution_provider = providers["windows-execution"]
            execution_types = {artifact["artifact_type"] for artifact in execution_provider["artifacts"]}
            self.assertIn("amcache-hive", execution_types)
            self.assertIn("amcache-entry", execution_types)
            native_amcache = next(
                artifact
                for artifact in execution_provider["artifacts"]
                if artifact["artifact_type"] == "amcache-entry"
                and artifact["details"]["source_format"] == "amcache-hive"
            )
            self.assertEqual(native_amcache["details"]["amcache_row_cluster_evidence"]["cluster_status"], "bounded-nearby-string-cluster")
            self.assertGreaterEqual(native_amcache["details"]["source_offset"], 0)
            self.assertIn("bounded Amcache row-cluster provenance", native_amcache["details"]["core_accuracy_gates"][0]["satisfied_checks"])
            hive_amcache = next(artifact for artifact in execution_provider["artifacts"] if artifact["artifact_type"] == "amcache-hive")
            self.assertGreaterEqual(hive_amcache["details"]["amcache_candidate_cluster_count"], 1)

            system_provider = providers["windows-system-artifacts"]
            system_types = {artifact["artifact_type"] for artifact in system_provider["artifacts"]}
            self.assertEqual(
                system_types,
                {
                    "task-scheduler-task",
                    "defender-support-log",
                    "firewall-log",
                    "wer-report",
                    "zone-identifier",
                    "web-server-log",
                },
            )
            task = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "task-scheduler-task")
            self.assertEqual(task["details"]["command"], "powershell.exe")
            self.assertIn("Bypass", task["details"]["arguments"])
            defender = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "defender-support-log")
            self.assertEqual(defender["details"]["interesting_entry_count"], 3)
            self.assertIn("#18", defender["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(defender["details"]["forensic_review"]["gap_id"], "#18")
            self.assertFalse(defender["details"]["system_native_capabilities"]["defender_event_mpcmdrun_correlation"])
            defender_review_profile = defender["details"]["system_analyst_review_profile"]
            self.assertEqual(defender_review_profile["profile_version"], "windows-system-analyst-review-profile-v1")
            self.assertEqual(defender_review_profile["artifact_family"], "defender")
            self.assertIn("Defender EVTX", defender_review_profile["correlation_targets"])
            self.assertIn("final malware verdict", defender_review_profile["not_proof_of"])
            self.assertEqual(defender["details"]["system_deep_parser_manifest"]["artifact_family"], "defender")
            self.assertIn(
                "defender-report-grade-correlation",
                defender["details"]["system_deep_parser_manifest"]["validation"]["failed_validation_matrix_ids"],
            )
            firewall = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "firewall-log")
            self.assertEqual(firewall["details"]["blocked_count"], 1)
            self.assertIn("#18", firewall["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(firewall["details"]["forensic_review"]["gap_id"], "#18")
            self.assertFalse(firewall["details"]["system_native_capabilities"]["firewall_rule_store_correlation"])
            firewall_review_profile = firewall["details"]["system_analyst_review_profile"]
            self.assertEqual(firewall_review_profile["artifact_family"], "firewall")
            self.assertIn("Firewall policy store", firewall_review_profile["correlation_targets"])
            self.assertEqual(firewall["details"]["system_deep_parser_manifest"]["artifact_family"], "firewall")
            self.assertIn(
                "firewall-report-grade-correlation",
                firewall["details"]["system_deep_parser_manifest"]["validation"]["failed_validation_matrix_ids"],
            )
            wer = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "wer-report")
            self.assertEqual(wer["details"]["application"], "powershell.exe")
            self.assertEqual(wer["details"]["coverage_status"], "wer-key-value-normalized")
            self.assertEqual(wer["details"]["application_path"], r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            self.assertEqual(wer["details"]["fault_module_path"], r"C:\Users\alice\AppData\Roaming\evil.dll")
            self.assertEqual(wer["details"]["exception_code"], "c0000005")
            self.assertEqual(wer["details"]["event_time"], "2026-04-26T01:04:05+00:00")
            self.assertEqual(wer["details"]["report_id"], "11111111-2222-3333-4444-555555555555")
            self.assertTrue(wer["details"]["validation_checks"]["has_exception_code"])
            self.assertFalse(wer["details"]["commercial_grade_ready"])
            self.assertIn("#18", wer["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(wer["details"]["system_deep_parser_manifest"]["artifact_family"], "wer")
            wer_review_profile = wer["details"]["system_analyst_review_profile"]
            self.assertEqual(wer_review_profile["artifact_family"], "wer")
            self.assertIn("WER dump/CAB", wer_review_profile["correlation_targets"])
            self.assertIn("dump/CAB contents without linkage validation", wer_review_profile["not_proof_of"])
            self.assertIn(
                "wer-report-grade-correlation",
                wer["details"]["system_deep_parser_manifest"]["validation"]["failed_validation_matrix_ids"],
            )
            self.assertEqual(wer["details"]["forensic_review"]["gap_id"], "#18")
            self.assertIn("wer-dump-file-correlation-not-implemented", wer["details"]["commercial_grade_blockers"])
            self.assertEqual(len(wer["details"]["source_hashes"]["sha256"]), 64)
            zone = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "zone-identifier")
            self.assertEqual(zone["details"]["zone_id"], "3")
            self.assertEqual(zone["details"]["host_url"], "https://download.example.com/report.zip")


if __name__ == "__main__":
    unittest.main()
