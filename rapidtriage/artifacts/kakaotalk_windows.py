from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .memory import MEMORY_DUMP_SCAN_LIMIT, build_scan_ranges, is_memory_dump_candidate
from .windows.common import build_forensic_review
from .windows.ese import build_ese_page_map, build_ese_string_pivots
from .windows.registry import REGISTRY_HIVE_NAMES
from .windows.registry import parse_registry_vk_cell, registry_value_data_preview
from .windows.search_index import WINDOWS_SEARCH_TABLE_MARKERS

PARSER_VERSION = "kakaotalk-windows-correlation-v1"
KAKAO_SCAN_LIMIT = 256 * 1024 * 1024
KAKAO_CHUNK_SIZE = 1024 * 1024
KAKAO_OVERLAP = 512
KAKAO_CANDIDATE_LIMIT = 200
KAKAO_APP_DB_LIMIT = 500
KAKAO_APP_DB_NAMES = {
    "actionlogdb.edb",
    "appstate.dat",
    "bg_v2.edb",
    "calendardb.edb",
    "carouselposition.edb",
    "chatlistinfo.edb",
    "chatlinkinfo.edb",
    "chatfolder.edb",
    "cli_http_v2.edb",
    "emoticon.edb",
    "etm_v2.edb",
    "fci_v2.edb",
    "floatinglist.edb",
    "gfve_t_v2.edb",
    "img_v2.edb",
    "labcf.dat",
    "last_pc_login.dat",
    "login_list.dat",
    "mci_v2.edb",
    "mpi_v2.edb",
    "mss.dat",
    "multiprofiledb.edb",
    "oci_v2.edb",
    "ocii_v2.edb",
    "ocrfar.edb",
    "openlinklistinfo.edb",
    "profile.dat",
    "pvi_v2.edb",
    "settings.dat",
    "tagpreset.edb",
    "throttle_store.dat",
    "talk_u~2.edb",
    "talkfile.edb",
    "talkmedia.edb",
    "talkuserdb.edb",
    "talk_user_prf.edb",
    "url_image_v2.edb",
    "wpi_v2.edb",
}
KAKAO_APP_DB_PREFIXES = ("chatlogs_",)
KAKAO_TERMS = (
    "deviceinfo",
    "hdd_model",
    "hdd_serial",
    "kakaotalk.exe",
    "kakaotalk",
    "kakao talk",
    "kakao",
    "login_list.dat",
    "sys_uuid",
    "talk_user",
    "talkuser",
    "chatlogs",
    "chatlog",
    "appdata\\local\\kakao",
    "appdata\\roaming\\kakao",
    "\\kakao\\kakaotalk",
    "kakao.com",
    "kakaocdn",
)
KAKAO_DEVICEINFO_FIELDS = ("sys_uuid", "hdd_model", "hdd_serial")
KAKAO_USER_ID_FIELD_NAMES = (
    "talk_user_id",
    "user_id",
    "userid",
    "userId",
    "tuid",
    "tuidb",
    "uuid",
    "uuidR",
    "login_id",
    "last_login_id",
)
KAKAO_HIGH_VALUE_TERMS = (
    "kakaotalk.exe",
    "talk_user",
    "talkuser",
    "chatlogs",
    "chatlog",
    "\\kakao\\kakaotalk",
)
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\x00\r\n\t\"'<>|]{4,320}")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")


class KakaoTalkWindowsProvider:
    collector_kind = "kakaotalk-windows"
    name = "kakaotalk-windows-correlation"
    description = "KakaoTalk Windows correlation across Windows.edb, Registry, and memory dumps"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        for db_path in find_kakaotalk_app_databases(root):
            records.append(collect_kakaotalk_app_database(db_path))
        for edb_path in find_windows_edb_files(root):
            records.extend(collect_edb_kakao_candidates(edb_path))
        for registry_path in find_registry_sources(root):
            records.extend(collect_registry_crypto_material(registry_path))
            records.extend(collect_registry_user_id_candidates(registry_path))
            records.extend(collect_registry_kakao_candidates(registry_path))
        for memory_path in find_memory_sources(root):
            records.extend(collect_memory_kakao_candidates(memory_path))
        yield from records
        summary = build_kakaotalk_windows_summary(root, records)
        if summary is not None:
            yield summary


def find_windows_edb_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("Windows.edb"), key=lambda item: str(item).lower()):
        if path.is_file():
            yield path


def find_kakaotalk_app_databases(root: Path) -> Iterable[Path]:
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        if not is_kakaotalk_path(path):
            continue
        if path.suffix.lower() not in {".edb", ".db", ".dat"}:
            continue
        if path.name.lower().endswith(("-wal", "-shm", ".copy0", ".copy1", ".copy2")):
            continue
        yield path
        count += 1
        if count >= KAKAO_APP_DB_LIMIT:
            return


def is_kakaotalk_path(path: Path) -> bool:
    lowered_path = str(path).lower()
    name = path.name.lower()
    parent = path.parent.name.lower()
    if "kakaotalk" in lowered_path or "/kakao/" in lowered_path or "\\kakao\\" in lowered_path:
        return True
    if name in KAKAO_APP_DB_NAMES or name.startswith(KAKAO_APP_DB_PREFIXES):
        return True
    return parent == "chat_data" and name.startswith(("chatlogs_", "chatlist"))


def find_registry_sources(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        if path.suffix.lower() == ".reg" or path.name.upper() in REGISTRY_HIVE_NAMES:
            yield path


def find_memory_sources(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if path.is_file() and is_memory_dump_candidate(path):
            yield path


def collect_kakaotalk_app_database(path: Path) -> ArtifactRecord:
    source_hashes = compute_hashes(path)
    role = classify_kakaotalk_db_role(path)
    sqlite_meta = inspect_sqlite_database(path)
    companions = companion_files(path)
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    report_grade = {
        "report_grade_ready": False,
        "status": "database-inventory-validation-required",
        "blockers": [
            "kakaotalk-db-schema-version-validation-required",
            "kakaotalk-db-decryption-or-codec-validation-required",
            "kakaotalk-deleted-record-validation-required",
        ],
        "validated_strengths": [
            "source-hash-preserved",
            "database-role-classified",
            "wal-shm-companions-recorded",
        ],
        "commercial_gap_ids": ["#31"],
        "next_validation_step": "Validate KakaoTalk DB role, encryption/codec state, WAL/SHM replay needs, schema version, and row semantics against a known-answer KakaoTalk corpus before reporting message content.",
    }
    return ArtifactRecord(
        provider=KakaoTalkWindowsProvider.name,
        artifact_type="kakaotalk-windows-app-database",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "kakaotalk-windows-app-db-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "kakaotalk-app-db-inventory",
            "reportability": "inventory-triage",
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "source_family": "kakaotalk-app-db",
            "source_subtype": role["subtype"],
            "database_role": role["role"],
            "profile_id_hint": profile_id_hint(path),
            "source_size": size,
            "sqlite_access": sqlite_meta,
            "companion_files": companions,
            "has_wal": any(item["kind"] == "wal" for item in companions),
            "has_shm": any(item["kind"] == "shm" for item in companions),
            "has_copy_companion": any(item["kind"].startswith("copy") for item in companions),
            "kakaotalk_decryption_readiness": build_decryption_readiness(path, role, sqlite_meta, size),
            "parser_confidence": app_database_confidence(role, sqlite_meta, companions),
            "evidence_strength": "kakaotalk-application-database-presence",
            "validation_required": True,
            "validation_guidance": "This row inventories a KakaoTalk application database or store. It records role, hashes, schema access, and WAL/SHM companions but does not decrypt or testify message content.",
            "kakaotalk_windows_analysis": {
                "method": "kakaotalk-app-db-inventory",
                "source_family": "kakaotalk-app-db",
                "message_content_status": "not-decrypted-inventory-only",
                "wal_replay_needed": any(item["kind"] == "wal" for item in companions),
                "copy_companions_preserved": [item for item in companions if str(item.get("kind", "")).startswith("copy")],
                "post_bigbang_caveat": "Post-2025-08 KakaoTalk database layouts and encryption assumptions require known-answer validation.",
            },
            "forensic_review": build_forensic_review(
                gap_id="#31",
                artifact_goal="KakaoTalk application database inventory",
                primary_evidence=[
                    f"role={role['role']}",
                    f"size={size}",
                    f"sqlite={sqlite_meta['sqlite_header']}",
                    f"wal={any(item['kind'] == 'wal' for item in companions)}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                commercial_grade_ready=False,
                caveats=[
                    "Application DB inventory only; encrypted/custom-codec stores are not decoded.",
                    "WAL/SHM companions may contain important recent state and must be preserved with the DB.",
                ],
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "privacy_legal_warning": "KakaoTalk DB files may contain private communications. Preserve hashes and validate legal authority before decoding or reporting content.",
            "risk_flags": build_app_db_flags(role, sqlite_meta, companions),
            "risk_score": app_database_risk(role, sqlite_meta, companions),
            "raw_preview": "",
        },
    )


def collect_edb_kakao_candidates(path: Path) -> list[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    pivots = build_ese_string_pivots(path, max_strings=500)
    page_map = build_ese_page_map(path, table_markers=WINDOWS_SEARCH_TABLE_MARKERS)
    records: list[ArtifactRecord] = []
    seen: set[tuple[str, str, int]] = set()

    values: list[tuple[str, str, dict[str, object]]] = []
    for field, kind in (
        ("path_candidates", "path"),
        ("url_candidates", "url"),
        ("content_candidates", "content"),
        ("suspicious_strings", "text"),
        ("extracted_strings", "text"),
    ):
        for value in pivots.get(field) or []:
            values.append((kind, str(value), {"pivot_field": field}))
    for page in page_map.get("page_samples") or []:
        if not isinstance(page, Mapping):
            continue
        page_meta = {
            "page_index": int(page.get("page_index") or 0),
            "page_offset": int(page.get("page_offset") or 0),
            "page_sha256": str(page.get("page_sha256") or ""),
            "page_marker_hits": dict(page.get("table_marker_hits") or {}),
        }
        for field, kind in (
            ("path_candidates", "path"),
            ("url_candidates", "url"),
            ("content_candidates", "content"),
            ("suspicious_strings", "text"),
            ("strings", "text"),
        ):
            for value in page.get(field) or []:
                values.append((kind, str(value), {**page_meta, "pivot_field": f"page.{field}"}))

    for index, (candidate_kind, value, metadata) in enumerate(values):
        matched = matched_kakao_terms(value)
        if not matched:
            continue
        key = ("edb", normalize_candidate_value(value), int(metadata.get("page_offset") or -1))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            build_kakao_candidate_record(
                path,
                source_hashes,
                source_family="windows-edb",
                source_subtype="windows-search-index",
                source_index=index,
                candidate_kind=candidate_kind,
                candidate_value=value,
                matched_terms=matched,
                source_offset=int(metadata.get("page_offset") or -1),
                metadata=metadata,
            )
        )
        if len(records) >= KAKAO_CANDIDATE_LIMIT:
            break
    return records


def collect_registry_kakao_candidates(path: Path) -> list[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    records: list[ArtifactRecord] = []
    if path.suffix.lower() == ".reg":
        lines = read_registry_export_lines(path)
        for index, line in enumerate(lines):
            matched = matched_kakao_terms(line)
            if not matched:
                continue
            records.append(
                build_kakao_candidate_record(
                    path,
                    source_hashes,
                    source_family="registry",
                    source_subtype="reg-export",
                    source_index=index,
                    candidate_kind=classify_candidate(line),
                    candidate_value=line.strip()[:1000],
                    matched_terms=matched,
                    source_offset=-1,
                    metadata={"line_number": index + 1},
                )
            )
            if len(records) >= KAKAO_CANDIDATE_LIMIT:
                break
        return records

    for index, hit in enumerate(scan_binary_kakao_hits(path, limit=min(KAKAO_SCAN_LIMIT, 32 * 1024 * 1024))):
        records.append(
            build_kakao_candidate_record(
                path,
                source_hashes,
                source_family="registry",
                source_subtype="native-hive-string",
                source_index=index,
                candidate_kind=classify_candidate(str(hit.get("value") or "")),
                candidate_value=str(hit.get("value") or ""),
                matched_terms=[str(hit.get("matched_term") or "")],
                source_offset=int(hit.get("offset") or -1),
                metadata={"encoding": hit.get("encoding", ""), "scan_status": "bounded-native-hive-string-scan"},
            )
        )
        if len(records) >= KAKAO_CANDIDATE_LIMIT:
            break
    return records


def collect_registry_crypto_material(path: Path) -> list[ArtifactRecord]:
    if path.suffix.lower() != ".reg":
        return collect_native_hive_crypto_material(path)
    lines = read_registry_export_lines(path)
    values = extract_deviceinfo_values(lines)
    if not values:
        return []
    source_hashes = compute_hashes(path)
    present = sorted(values)
    missing = [field for field in KAKAO_DEVICEINFO_FIELDS if field not in values]
    return [
        ArtifactRecord(
            provider=KakaoTalkWindowsProvider.name,
            artifact_type="kakaotalk-windows-crypto-material-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "kakaotalk-windows-deviceinfo-context",
                "parser_version": PARSER_VERSION,
                "coverage_status": "kakaotalk-deviceinfo-context",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "source_family": "registry",
                "source_subtype": "reg-export-deviceinfo",
                "candidate_kind": "crypto-material-context",
                "deviceinfo_path": r"HKCU\Software\Kakao\KakaoTalk\DeviceInfo",
                "present_fields": present,
                "missing_fields": missing,
                "field_hashes": {field: hashlib.sha256(values[field].encode("utf-8", errors="ignore")).hexdigest() for field in present},
                "values_redacted": True,
                "kakaotalk_decryption_context": {
                    "research_alignment": "DeviceInfo sys_uuid, hdd_model, and hdd_serial are commonly cited as pragma input material for legacy Windows KakaoTalk DB research.",
                    "pragma_input_fields_complete": not missing,
                    "user_id_required": True,
                    "hardcoded_application_key_required": True,
                    "hardcoded_application_key_included": False,
                    "decrypts_content": False,
                    "post_bigbang_caveat": "Post-2025-08 KakaoTalk layouts and encryption assumptions require separate known-answer validation.",
                },
                "parser_confidence": 0.72 if not missing else 0.56,
                "evidence_strength": "kakaotalk-deviceinfo-context-preserved",
                "validation_required": True,
                "validation_guidance": "Use as a preserved decryption-context inventory item only. It does not contain the proprietary app key and does not prove message content.",
                "forensic_review": build_forensic_review(
                    gap_id="#31",
                    artifact_goal="KakaoTalk Windows DeviceInfo decryption-context inventory",
                    primary_evidence=[
                        "source=registry",
                        f"present_fields={len(present)}",
                        f"missing_fields={len(missing)}",
                    ],
                    validation_required=True,
                    report_grade_assessment={
                        "report_grade_ready": False,
                        "status": "decryption-context-inventory-only",
                        "blockers": [
                            "kakaotalk-user-id-validation-required",
                            "kakaotalk-proprietary-key-not-included",
                            "post-bigbang-known-answer-validation-required",
                        ],
                        "validated_strengths": [
                            "deviceinfo-field-presence-recorded",
                            "source-hash-preserved",
                            "sensitive-values-redacted",
                        ],
                        "commercial_gap_ids": ["#31"],
                        "next_validation_step": "Correlate DeviceInfo with userId evidence, authorized app data, and known-answer decrypted SQLite headers.",
                    },
                    commercial_grade_ready=False,
                    caveats=[
                        "Sensitive device identifiers are hashed/redacted in this row.",
                        "This row is not a decryption result and should not be reported as chat content.",
                    ],
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "kakaotalk-user-id-validation-required",
                    "kakaotalk-proprietary-key-not-included",
                    "post-bigbang-known-answer-validation-required",
                ],
                "privacy_legal_warning": "Device identifiers can be sensitive. Use only within authorized forensic scope.",
                "risk_flags": ["kakaotalk-deviceinfo-context", "sensitive-device-identifier-redacted"],
                "risk_score": 64 if not missing else 48,
                "raw_preview": "",
            },
        )
    ]


def collect_registry_user_id_candidates(path: Path) -> list[ArtifactRecord]:
    if path.suffix.lower() == ".reg":
        return collect_reg_export_user_id_candidates(path)
    return collect_native_hive_user_id_candidates(path)


def collect_reg_export_user_id_candidates(path: Path) -> list[ArtifactRecord]:
    lines = read_registry_export_lines(path)
    values = extract_user_id_values_from_reg_export(lines)
    if not values:
        return []
    return [build_user_id_candidate_record(path, "reg-export-user-id", values)]


def collect_native_hive_user_id_candidates(path: Path) -> list[ArtifactRecord]:
    values = extract_native_hive_user_id_values(path)
    if not values:
        return []
    normalized = {
        name: {
            "value": str(item.get("value") or ""),
            "offset": int(item.get("offset") or -1),
            "value_type": str(item.get("value_type") or ""),
            "value_size": int(item.get("value_size") or 0),
        }
        for name, item in values.items()
    }
    return [build_user_id_candidate_record(path, "native-hive-user-id-value", normalized)]


def build_user_id_candidate_record(
    path: Path,
    source_subtype: str,
    values: Mapping[str, Mapping[str, object]],
) -> ArtifactRecord:
    source_hashes = compute_hashes(path)
    field_names = sorted(values)
    value_hashes = {
        field: hashlib.sha256(str(values[field].get("value") or "").encode("utf-8", errors="ignore")).hexdigest()
        for field in field_names
    }
    value_shapes = {field: classify_user_id_shape(str(values[field].get("value") or "")) for field in field_names}
    field_offsets = {
        field: int(values[field].get("offset") or -1)
        for field in field_names
        if int(values[field].get("offset") or -1) >= 0
    }
    report_grade = {
        "report_grade_ready": False,
        "status": "user-id-candidate-validation-required",
        "blockers": [
            "kakaotalk-user-id-source-validation-required",
            "kakaotalk-decryption-header-validation-required",
            "kakaotalk-proprietary-key-not-included",
        ],
        "validated_strengths": [
            "source-hash-preserved",
            "candidate-name-recorded",
            "candidate-value-redacted-and-hashed",
        ],
        "commercial_gap_ids": ["#31"],
        "next_validation_step": "Use the candidate only inside an authorized decryption workflow, then validate the resulting SQLite header and message row counts.",
    }
    return ArtifactRecord(
        provider=KakaoTalkWindowsProvider.name,
        artifact_type="kakaotalk-windows-user-id-candidate",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "kakaotalk-windows-user-id-context",
            "parser_version": PARSER_VERSION,
            "coverage_status": "kakaotalk-user-id-candidate",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "source_family": "registry",
            "source_subtype": source_subtype,
            "candidate_kind": "account-identifier-context",
            "field_names": field_names,
            "field_hashes": value_hashes,
            "field_shapes": value_shapes,
            "field_offsets": field_offsets,
            "values_redacted": True,
            "auto_decrypt_eligible": len({value_hashes[field] for field in field_names}) == 1
            and any(value_shapes[field] in {"numeric-id", "opaque-token", "structured-token", "uuid-like"} for field in field_names),
            "kakaotalk_decryption_context": {
                "user_id_candidate_present": True,
                "deviceinfo_required": True,
                "hardcoded_application_key_required": True,
                "hardcoded_application_key_included": False,
                "decrypts_content": False,
                "post_bigbang_caveat": "Post-2025-08 KakaoTalk layouts and encryption assumptions require separate known-answer validation.",
            },
            "parser_confidence": 0.7 if source_subtype == "native-hive-user-id-value" else 0.66,
            "evidence_strength": "kakaotalk-user-id-context-preserved",
            "validation_required": True,
            "validation_guidance": "This row preserves KakaoTalk account identifier candidates needed by legacy PC KakaoTalk research workflows. Values are redacted and must be validated by successful SQLite-header decryption.",
            "forensic_review": build_forensic_review(
                gap_id="#31",
                artifact_goal="KakaoTalk Windows userId decryption-context inventory",
                primary_evidence=[
                    f"source={source_subtype}",
                    f"field_count={len(field_names)}",
                    f"auto_decrypt_eligible={len({value_hashes[field] for field in field_names}) == 1}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                commercial_grade_ready=False,
                caveats=[
                    "Account identifiers are sensitive and are redacted in output.",
                    "A userId candidate is not chat content; report message content only after successful authorized decryption and known-answer validation.",
                ],
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "privacy_legal_warning": "KakaoTalk account identifiers can be sensitive. Use only inside an authorized forensic workflow.",
            "risk_flags": ["kakaotalk-user-id-context", "sensitive-account-identifier-redacted"],
            "risk_score": 62 if source_subtype == "native-hive-user-id-value" else 58,
            "raw_preview": "",
        },
    )


def collect_native_hive_crypto_material(path: Path) -> list[ArtifactRecord]:
    values = extract_native_hive_deviceinfo_values(path)
    if values:
        source_hashes = compute_hashes(path)
        present = sorted(values)
        missing = [field for field in KAKAO_DEVICEINFO_FIELDS if field not in values]
        return [
            ArtifactRecord(
                provider=KakaoTalkWindowsProvider.name,
                artifact_type="kakaotalk-windows-crypto-material-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "kakaotalk-windows-deviceinfo-context",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-hive-deviceinfo-value-candidate",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_hashes": dict(source_hashes),
                    "source_family": "registry",
                    "source_subtype": "native-hive-deviceinfo-value",
                    "candidate_kind": "crypto-material-context",
                    "deviceinfo_path": r"HKCU\Software\Kakao\KakaoTalk\DeviceInfo",
                    "present_fields": present,
                    "missing_fields": missing,
                    "field_hashes": {
                        field: hashlib.sha256(str(values[field]["value"]).encode("utf-8", errors="ignore")).hexdigest()
                        for field in present
                    },
                    "field_offsets": {field: values[field]["offset"] for field in present},
                    "values_redacted": True,
                    "kakaotalk_decryption_context": {
                        "research_alignment": "DeviceInfo sys_uuid, hdd_model, and hdd_serial are pragma input material for legacy Windows KakaoTalk DB research.",
                        "pragma_input_fields_complete": not missing,
                        "user_id_required": True,
                        "hardcoded_application_key_required": True,
                        "hardcoded_application_key_included": False,
                        "decrypts_content": False,
                        "post_bigbang_caveat": "Post-2025-08 KakaoTalk layouts and encryption assumptions require separate known-answer validation.",
                    },
                    "parser_confidence": 0.78 if not missing else 0.6,
                    "evidence_strength": "native-hive-deviceinfo-values-preserved",
                    "validation_required": True,
                    "validation_guidance": "DeviceInfo values were decoded from native vk cells and redacted in output. They are pragma input material, not final chat content or the proprietary app key.",
                    "forensic_review": build_forensic_review(
                        gap_id="#31",
                        artifact_goal="KakaoTalk Windows native DeviceInfo value inventory",
                        primary_evidence=[
                            "source=native-registry-hive",
                            f"present_fields={len(present)}",
                            f"missing_fields={len(missing)}",
                        ],
                        validation_required=True,
                        report_grade_assessment={
                            "report_grade_ready": False,
                            "status": "decryption-context-inventory-only",
                            "blockers": [
                                "kakaotalk-user-id-validation-required",
                                "kakaotalk-proprietary-key-not-included",
                                "known-answer-decryption-validation-required",
                            ],
                            "validated_strengths": [
                                "native-vk-value-decoded",
                                "source-hash-preserved",
                                "sensitive-values-redacted",
                            ],
                            "commercial_gap_ids": ["#31"],
                            "next_validation_step": "Use decoded DeviceInfo values with authorized app-key workflow to derive pragma and validate decrypted SQLite headers.",
                        },
                        commercial_grade_ready=False,
                        caveats=[
                            "DeviceInfo values are redacted from output because they contain sensitive device identifiers.",
                            "This row is not a decryption result and should not be reported as chat content.",
                        ],
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": [
                        "kakaotalk-user-id-validation-required",
                        "kakaotalk-proprietary-key-not-included",
                        "known-answer-decryption-validation-required",
                    ],
                    "privacy_legal_warning": "Device identifiers can be sensitive. Values are decoded for workflow readiness but redacted in output.",
                    "risk_flags": ["kakaotalk-deviceinfo-context", "native-vk-deviceinfo-decoded", "sensitive-device-identifier-redacted"],
                    "risk_score": 68 if not missing else 52,
                    "raw_preview": "",
                },
            )
        ]
    hits = [
        hit
        for hit in scan_binary_kakao_hits(path, limit=min(KAKAO_SCAN_LIMIT, 32 * 1024 * 1024))
        if str(hit.get("matched_term") or "") in KAKAO_DEVICEINFO_FIELDS or str(hit.get("matched_term") or "") == "deviceinfo"
    ]
    if not hits:
        return []
    source_hashes = compute_hashes(path)
    matched = sorted({str(hit.get("matched_term") or "") for hit in hits if hit.get("matched_term")})
    return [
        ArtifactRecord(
            provider=KakaoTalkWindowsProvider.name,
            artifact_type="kakaotalk-windows-crypto-material-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "kakaotalk-windows-deviceinfo-context",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-hive-deviceinfo-string-candidate",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "source_family": "registry",
                "source_subtype": "native-hive-deviceinfo-string",
                "candidate_kind": "crypto-material-context",
                "matched_terms": matched,
                "source_offsets": [int(hit.get("offset") or -1) for hit in hits[:20]],
                "values_redacted": True,
                "kakaotalk_decryption_context": {
                    "pragma_input_fields_complete": False,
                    "user_id_required": True,
                    "hardcoded_application_key_required": True,
                    "hardcoded_application_key_included": False,
                    "decrypts_content": False,
                },
                "parser_confidence": 0.48,
                "evidence_strength": "native-hive-deviceinfo-string-presence-candidate",
                "validation_required": True,
                "validation_guidance": "Native hive string hits need full registry cell parsing before use as decryption context.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": ["native-registry-deviceinfo-cell-parser-required"],
                "privacy_legal_warning": "Device identifiers can be sensitive. This row redacts values.",
                "risk_flags": ["kakaotalk-deviceinfo-context", "native-hive-validation-required"],
                "risk_score": 42,
                "raw_preview": "",
            },
        )
    ]


def collect_memory_kakao_candidates(path: Path) -> list[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    records: list[ArtifactRecord] = []
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0
    ranges = build_scan_ranges(file_size)
    for index, hit in enumerate(scan_binary_kakao_hits(path, ranges=ranges, limit=MEMORY_DUMP_SCAN_LIMIT)):
        value = str(hit.get("value") or "")
        records.append(
            build_kakao_candidate_record(
                path,
                source_hashes,
                source_family="memory-dump",
                source_subtype="bounded-memory-string",
                source_index=index,
                candidate_kind=classify_candidate(value),
                candidate_value=value,
                matched_terms=[str(hit.get("matched_term") or "")],
                source_offset=int(hit.get("offset") or -1),
                metadata={
                    "encoding": hit.get("encoding", ""),
                    "scan_ranges": [{"start": start, "end": end} for start, end in ranges],
                    "scan_truncated": sum(max(0, end - start) for start, end in ranges) < file_size,
                    "scan_status": "bounded-direct-memory-kakaotalk-string-scan",
                },
            )
        )
        if len(records) >= KAKAO_CANDIDATE_LIMIT:
            break
    return records


def build_kakao_candidate_record(
    path: Path,
    source_hashes: Mapping[str, str],
    *,
    source_family: str,
    source_subtype: str,
    source_index: int,
    candidate_kind: str,
    candidate_value: str,
    matched_terms: Sequence[str],
    source_offset: int,
    metadata: Mapping[str, object],
) -> ArtifactRecord:
    confidence = candidate_confidence(source_family, candidate_kind, candidate_value, matched_terms, metadata)
    report_grade = {
        "report_grade_ready": False,
        "status": "triage-correlation-validation-required",
        "blockers": [
            "kakaotalk-source-artifact-validation-required",
            "kakaotalk-message-db-decryption-not-implemented",
            "kakaotalk-post-bigbang-known-answer-validation-required",
        ],
        "validated_strengths": [
            "source-hash-preserved",
            "source-family-labeled",
            "candidate-string-preserved",
        ],
        "commercial_gap_ids": ["#31"],
        "next_validation_step": "Validate KakaoTalk candidates against known-good Windows KakaoTalk artifacts, process lists, user profile paths, and authorized application data exports before reporting message content.",
    }
    return ArtifactRecord(
        provider=KakaoTalkWindowsProvider.name,
        artifact_type="kakaotalk-windows-source-candidate",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "kakaotalk-windows-correlation",
            "parser_version": PARSER_VERSION,
            "coverage_status": "cross-source-kakaotalk-candidate",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "source_family": source_family,
            "source_subtype": source_subtype,
            "source_index": source_index,
            "source_offset": source_offset if source_offset >= 0 else "",
            "candidate_kind": candidate_kind,
            "candidate_value": candidate_value[:1000],
            "candidate_value_sha256": hashlib.sha256(candidate_value.encode("utf-8", errors="ignore")).hexdigest(),
            "matched_terms": sorted({term for term in matched_terms if term}),
            "path_candidates": extract_paths(candidate_value),
            "url_candidates": extract_urls(candidate_value),
            "page_index": metadata.get("page_index", ""),
            "page_offset": metadata.get("page_offset", ""),
            "page_sha256": metadata.get("page_sha256", ""),
            "page_marker_hits": metadata.get("page_marker_hits", {}),
            "metadata": dict(metadata),
            "parser_confidence": confidence,
            "evidence_strength": "kakaotalk-cross-source-presence-candidate",
            "validation_required": True,
            "validation_guidance": "This candidate indicates KakaoTalk-related Windows evidence in EDB, Registry, or memory. It is not decrypted chat testimony by itself.",
            "kakaotalk_windows_analysis": {
                "method": "edb-registry-memory-correlation",
                "source_family": source_family,
                "supports_pc_kakaotalk_triage": True,
                "message_content_status": "candidate-only-not-decrypted",
                "post_bigbang_caveat": "KakaoTalk 25.7.2 / 2025-08-13+ compatibility must be validated with a known-answer corpus.",
            },
            "forensic_review": build_forensic_review(
                gap_id="#31",
                artifact_goal="KakaoTalk Windows EDB/Registry/Memory correlation",
                primary_evidence=[
                    f"source={source_family}",
                    f"kind={candidate_kind}",
                    f"terms={len(matched_terms)}",
                    f"offset={source_offset}" if source_offset >= 0 else "",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                commercial_grade_ready=False,
                caveats=[
                    "Cross-source candidate only; validate with app data, process timeline, and known-answer KakaoTalk corpus.",
                    "Memory strings may include volatile or stale data and are not proof of sent/received message state.",
                ],
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "privacy_legal_warning": "KakaoTalk artifacts may contain private communications. Review only within authorized legal scope and avoid reporting raw content until validated.",
            "risk_flags": build_candidate_flags(source_family, candidate_kind, matched_terms),
            "risk_score": min(100, int(confidence * 100)),
            "raw_preview": candidate_value[:500],
        },
    )


def build_kakaotalk_windows_summary(root: Path, records: Sequence[ArtifactRecord]) -> ArtifactRecord | None:
    summary_artifact_types = {
        "kakaotalk-windows-source-candidate",
        "kakaotalk-windows-app-database",
        "kakaotalk-windows-crypto-material-candidate",
        "kakaotalk-windows-user-id-candidate",
    }
    candidates = [
        record
        for record in records
        if record.artifact_type in summary_artifact_types
    ]
    if not candidates:
        return None
    family_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    source_files: set[str] = set()
    confidence_scores: list[float] = []
    for record in candidates:
        details = record.details
        source_family = str(details.get("source_family") or "")
        candidate_kind = str(details.get("candidate_kind") or details.get("database_role") or "")
        source_path = str(details.get("source_path") or record.path)
        if source_family:
            family_counts[source_family] = family_counts.get(source_family, 0) + 1
        if candidate_kind:
            kind_counts[candidate_kind] = kind_counts.get(candidate_kind, 0) + 1
        source_files.add(source_path)
        try:
            confidence_scores.append(float(details.get("parser_confidence") or 0.0))
        except (TypeError, ValueError):
            pass
    source_family_set = set(family_counts)
    correlation_strength = "strong" if len(source_family_set) >= 3 else "moderate" if len(source_family_set) == 2 else "single-source"
    return ArtifactRecord(
        provider=KakaoTalkWindowsProvider.name,
        artifact_type="kakaotalk-windows-correlation-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "kakaotalk-windows-correlation-summary",
            "parser_version": PARSER_VERSION,
            "coverage_status": "summarized",
            "reportability": "triage",
            "source_path": str(root.resolve()),
            "candidate_count": len(candidates),
            "app_database_count": sum(1 for record in candidates if record.artifact_type == "kakaotalk-windows-app-database"),
            "crypto_material_candidate_count": sum(
                1 for record in candidates if record.artifact_type == "kakaotalk-windows-crypto-material-candidate"
            ),
            "user_id_candidate_count": sum(
                1 for record in candidates if record.artifact_type == "kakaotalk-windows-user-id-candidate"
            ),
            "source_family_counts": sorted_counts(family_counts),
            "candidate_kind_counts": sorted_counts(kind_counts),
            "source_files": sorted(source_files),
            "correlation_strength": correlation_strength,
            "average_confidence": round(sum(confidence_scores) / len(confidence_scores), 2) if confidence_scores else 0.0,
            "analysis_workflow": [
                "Inventory KakaoTalk application DB files first, preserving DB/WAL/SHM hashes and role classification.",
                "Use Windows.edb candidates to find indexed KakaoTalk paths/content hints.",
                "Use Registry candidates to confirm user profile, execution, MRU, install, or persistence-adjacent traces.",
                "Use memory candidates to find volatile KakaoTalk process/path/string hints.",
                "Validate all candidates against authorized KakaoTalk application data exports and known-answer fixtures before reporting chat content.",
            ],
            "validation_required": True,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "kakaotalk-message-db-decryption-not-implemented",
                "kakaotalk-known-answer-corpus-validation-required",
                "cross-source-timeline-correlation-required",
            ],
            "privacy_legal_warning": "KakaoTalk cross-source analysis can expose private communications and account identifiers. Treat output as authorized triage evidence only until validated.",
        },
    )


def scan_binary_kakao_hits(
    path: Path,
    *,
    ranges: Sequence[tuple[int, int]] | None = None,
    limit: int,
) -> Iterable[dict[str, object]]:
    try:
        file_size = path.stat().st_size
    except OSError:
        return []
    scan_ranges = list(ranges or [(0, min(file_size, limit))])
    hits: list[dict[str, object]] = []
    seen: set[tuple[str, int, str]] = set()
    try:
        with path.open("rb") as handle:
            for start, end in scan_ranges:
                handle.seek(start)
                previous_tail = b""
                current_offset = start
                remaining = max(0, end - start)
                while remaining > 0 and len(hits) < KAKAO_CANDIDATE_LIMIT:
                    chunk = handle.read(min(KAKAO_CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    data = previous_tail + chunk
                    data_offset = current_offset - len(previous_tail)
                    hits.extend(binary_hits_from_chunk(data, data_offset, seen))
                    previous_tail = data[-KAKAO_OVERLAP:]
                    current_offset += len(chunk)
                    remaining -= len(chunk)
    except OSError:
        return []
    return hits[:KAKAO_CANDIDATE_LIMIT]


def classify_kakaotalk_db_role(path: Path) -> dict[str, str]:
    name = path.name.lower()
    parent = path.parent.name.lower()
    if name.startswith("chatlogs_"):
        return {"role": "chat-log", "subtype": "chatlogs"}
    if name == "chatlistinfo.edb":
        return {"role": "chat-list", "subtype": "chat-list-info"}
    if name in {"talkuserdb.edb", "talk_u~2.edb"}:
        return {"role": "talk-user", "subtype": "talk-user-db"}
    if name == "talk_user_prf.edb":
        return {"role": "user-profile", "subtype": "talk-user-profile"}
    if name in {"pvi_v2.edb", "profile.dat", "multiprofiledb.edb"}:
        return {"role": "profile-index", "subtype": name.rsplit(".", 1)[0]}
    if name == "talkmedia.edb":
        return {"role": "media-index", "subtype": "talk-media"}
    if name == "talkfile.edb":
        return {"role": "file-index", "subtype": "talk-file"}
    if name == "actionlogdb.edb":
        return {"role": "action-log", "subtype": "action-log"}
    if name in {"appstate.dat", "last_pc_login.dat", "login_list.dat"}:
        return {"role": "account-login-state", "subtype": name.rsplit(".", 1)[0]}
    if name in {"calendardb.edb", "chatfolder.edb", "tagpreset.edb"}:
        return {"role": "user-organization-state", "subtype": name.rsplit(".", 1)[0]}
    if name in {"mci_v2.edb", "fci_v2.edb", "mpi_v2.edb", "wpi_v2.edb"} or parent in {"contacts", "mci_v2", "fpi_v2"}:
        return {"role": "contact-or-profile-index", "subtype": name.rsplit(".", 1)[0]}
    if name in {"url_image_v2.edb", "cli_http_v2.edb", "chatlinkinfo.edb", "openlinklistinfo.edb", "img_v2.edb"}:
        return {"role": "link-url-media-index", "subtype": name.rsplit(".", 1)[0]}
    if name in {"bg_v2.edb", "emoticon.edb", "etm_v2.edb", "carouselposition.edb"} or parent.lower() in {"balloonfactory", "och", "x2.0"}:
        return {"role": "ui-media-cache", "subtype": name.rsplit(".", 1)[0]}
    if name in {"gfve_t_v2.edb", "oci_v2.edb", "ocii_v2.edb", "ocrfar.edb"}:
        return {"role": "chat-adjacent-index", "subtype": name.rsplit(".", 1)[0]}
    if name in {"labcf.dat", "mss.dat", "floatinglist.edb"}:
        return {"role": "client-settings-state", "subtype": name.rsplit(".", 1)[0]}
    if parent.lower() == "crashpad" or name in {"settings.dat", "throttle_store.dat"}:
        return {"role": "crashpad-state", "subtype": name.rsplit(".", 1)[0]}
    if name.endswith(".db"):
        return {"role": "sqlite-ui-or-cache", "subtype": name.rsplit(".", 1)[0]}
    return {"role": "kakaotalk-store", "subtype": name.rsplit(".", 1)[0]}


def inspect_sqlite_database(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        header = b""
    sqlite_header = header.startswith(b"SQLite format 3")
    result: dict[str, object] = {
        "sqlite_header": sqlite_header,
        "open_status": "not-sqlite-header",
        "header_hex": header[:16].hex(),
        "table_names": [],
        "table_count": 0,
        "row_counts": [],
        "error": "",
    }
    if not sqlite_header:
        return result
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            table_names = [str(row[0]) for row in rows]
            result["table_names"] = table_names[:50]
            result["table_count"] = len(table_names)
            result["row_counts"] = sqlite_row_counts(connection, table_names[:20])
            result["open_status"] = "opened-read-only"
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        result["open_status"] = "sqlite-open-failed"
        result["error"] = str(exc)[:200]
    except OSError as exc:
        result["open_status"] = "sqlite-file-read-failed"
        result["error"] = str(exc)[:200]
    return result


def build_decryption_readiness(
    path: Path,
    role: Mapping[str, str],
    sqlite_meta: Mapping[str, object],
    size: int,
) -> dict[str, object]:
    encrypted_candidate = not bool(sqlite_meta.get("sqlite_header")) and path.suffix.lower() == ".edb"
    page_aligned = size > 0 and size % 4096 == 0
    return {
        "status": "plain-sqlite" if sqlite_meta.get("sqlite_header") else "encrypted-or-custom-store-validation-required",
        "legacy_research_model": "AES-128-CBC-4096-byte-pages",
        "encrypted_page_model_candidate": encrypted_candidate,
        "size_multiple_of_4096": page_aligned,
        "expected_success_indicator": "SQLite format 3 header after authorized decryption",
        "requires_deviceinfo_fields": list(KAKAO_DEVICEINFO_FIELDS),
        "requires_user_id": role.get("role") in {"chat-log", "chat-list", "talk-user", "profile-index", "user-profile"},
        "requires_authorized_key_material": encrypted_candidate,
        "hardcoded_application_key_included": False,
        "decrypt_attempted": False,
        "safe_next_step": "Preserve DB/WAL/SHM/copy files, correlate DeviceInfo and userId hints, then validate any authorized decoder against known-answer SQLite headers and row counts.",
    }


def extract_native_hive_deviceinfo_values(path: Path) -> dict[str, dict[str, object]]:
    try:
        blob = path.read_bytes()
    except OSError:
        return {}
    values: dict[str, dict[str, object]] = {}
    for field in KAKAO_DEVICEINFO_FIELDS:
        field_bytes = field.encode("ascii")
        start = 0
        while True:
            index = blob.find(field_bytes, start)
            if index < 0:
                break
            candidate = decode_vk_value_at_name_offset(blob, index)
            if candidate and str(candidate.get("name") or "").lower() == field:
                preview = registry_value_data_preview(blob, candidate)
                if preview:
                    values[field] = {
                        "value": preview,
                        "offset": int(candidate.get("cell_offset") or max(0, index - 24)),
                        "value_type": candidate.get("value_type", ""),
                        "value_size": candidate.get("value_data_size", 0),
                    }
                    break
            start = index + len(field_bytes)
    return values


def extract_native_hive_user_id_values(path: Path) -> dict[str, dict[str, object]]:
    try:
        blob = path.read_bytes()
    except OSError:
        return {}
    values: dict[str, dict[str, object]] = {}
    for field in KAKAO_USER_ID_FIELD_NAMES:
        candidates = [field.encode("ascii", errors="ignore")]
        if any(ch.isupper() for ch in field):
            candidates.append(field.lower().encode("ascii", errors="ignore"))
        for field_bytes in candidates:
            if not field_bytes:
                continue
            start = 0
            while True:
                index = blob.find(field_bytes, start)
                if index < 0:
                    break
                candidate = decode_vk_value_at_name_offset(blob, index)
                if candidate and str(candidate.get("name") or "").lower() == field.lower():
                    preview = registry_value_data_preview(blob, candidate)
                    normalized_preview = normalize_kakaotalk_user_id_value(preview)
                    if preview and looks_like_kakaotalk_user_id(normalized_preview):
                        values[field] = {
                            "value": normalized_preview,
                            "offset": int(candidate.get("cell_offset") or max(0, index - 24)),
                            "value_type": candidate.get("value_type", ""),
                            "value_size": candidate.get("value_data_size", 0),
                        }
                        break
                start = index + len(field_bytes)
            if field in values:
                break
    return values


def decode_vk_value_at_name_offset(blob: bytes, name_offset: int) -> dict[str, object] | None:
    # In a vk cell, the value name starts 20 bytes after the "vk" signature and
    # the allocated cell size starts 4 bytes before the signature.
    signature_offset = name_offset - 20
    cell_offset = signature_offset - 4
    if cell_offset < 0 or blob[signature_offset : signature_offset + 2] != b"vk":
        return None
    cell_size_raw = int.from_bytes(blob[cell_offset:signature_offset], "little", signed=True)
    cell_size = abs(cell_size_raw)
    if cell_size <= 0 or cell_size > 4096:
        return None
    return parse_registry_vk_cell(blob, cell_offset, signature_offset, cell_size, cell_size_raw)


def sqlite_row_counts(connection: sqlite3.Connection, table_names: Sequence[str]) -> list[dict[str, object]]:
    counts: list[dict[str, object]] = []
    for table_name in table_names:
        if not re.fullmatch(r"[A-Za-z0-9_.$-]{1,128}", table_name):
            continue
        try:
            value = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()
        except sqlite3.DatabaseError:
            continue
        counts.append({"table": table_name, "count": int(value[0]) if value else 0})
    return counts


def companion_files(path: Path) -> list[dict[str, object]]:
    companions: list[dict[str, object]] = []
    suffixes = [
        (f"{path.name}-wal", "wal"),
        (f"{path.name}-shm", "shm"),
        (f"{path.name}.copy0", "copy0"),
        (f"{path.name}.copy1", "copy1"),
        (f"{path.name}.copy2", "copy2"),
    ]
    for suffix, kind in suffixes:
        candidate = path.with_name(suffix)
        if not candidate.is_file():
            continue
        try:
            size = candidate.stat().st_size
        except OSError:
            size = 0
        companions.append(
            {
                "kind": kind,
                "path": str(candidate.resolve()),
                "size": size,
                "sha256": compute_hashes(candidate).get("sha256", ""),
            }
        )
    return companions


def profile_id_hint(path: Path) -> str:
    for part in reversed(path.parts):
        lowered = part.lower()
        if re.fullmatch(r"[a-f0-9]{32,64}", lowered):
            return part
    return ""


def app_database_confidence(
    role: Mapping[str, str],
    sqlite_meta: Mapping[str, object],
    companions: Sequence[Mapping[str, object]],
) -> float:
    score = 0.46
    if role.get("role") in {"chat-log", "chat-list", "talk-user", "action-log"}:
        score += 0.18
    if sqlite_meta.get("sqlite_header"):
        score += 0.08
    if companions:
        score += 0.06
    return round(min(score, 0.82), 2)


def build_app_db_flags(
    role: Mapping[str, str],
    sqlite_meta: Mapping[str, object],
    companions: Sequence[Mapping[str, object]],
) -> list[str]:
    flags = ["kakaotalk-windows-candidate", "kakaotalk-source:kakaotalk-app-db", f"kakaotalk-db-role:{role['role']}"]
    if role.get("role") in {"chat-log", "chat-list"}:
        flags.append("high-value-kakaotalk-artifact")
    if not sqlite_meta.get("sqlite_header"):
        flags.append("kakaotalk-custom-or-encrypted-db")
    if companions:
        flags.append("kakaotalk-db-companion-files-present")
    return sorted(set(flags))


def app_database_risk(
    role: Mapping[str, str],
    sqlite_meta: Mapping[str, object],
    companions: Sequence[Mapping[str, object]],
) -> int:
    score = 25
    if role.get("role") in {"chat-log", "chat-list"}:
        score += 35
    if not sqlite_meta.get("sqlite_header"):
        score += 10
    if companions:
        score += 10
    return min(score, 100)


def binary_hits_from_chunk(data: bytes, data_offset: int, seen: set[tuple[str, int, str]]) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for term in KAKAO_TERMS:
        utf16_needles = {
            term.encode("utf-16le"),
            term.replace("kakao", "Kakao").replace("talk", "Talk").encode("utf-16le"),
            term.replace("kakaotalk", "KakaoTalk").encode("utf-16le"),
        }
        encoded_terms = [("ascii", term.encode("ascii", errors="ignore"))]
        encoded_terms.extend(("utf-16le", needle) for needle in sorted(utf16_needles))
        for encoding, needle in encoded_terms:
            if not needle:
                continue
            start = 0
            lowered = data.lower() if encoding == "ascii" else data
            search_needle = needle.lower() if encoding == "ascii" else needle
            while True:
                index = lowered.find(search_needle, start)
                if index < 0:
                    break
                offset = data_offset + index
                context = decode_binary_context(data, index, encoding)
                key = (term, offset, normalize_candidate_value(context))
                if key not in seen:
                    seen.add(key)
                    hits.append(
                        {
                            "matched_term": term,
                            "offset": offset,
                            "encoding": encoding,
                            "value": context,
                        }
                    )
                start = index + max(1, len(search_needle))
                if len(hits) >= KAKAO_CANDIDATE_LIMIT:
                    return hits
    return hits


def decode_binary_context(data: bytes, index: int, encoding: str) -> str:
    if encoding == "utf-16le":
        start = max(0, index - 160)
        if start % 2:
            start -= 1
        end = min(len(data), index + 400)
        if end % 2:
            end -= 1
        text = data[start:end].decode("utf-16le", errors="ignore")
    else:
        start = max(0, index - 120)
        end = min(len(data), index + 300)
        text = data[start:end].decode("latin-1", errors="ignore")
    return " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())[:1000]


def read_registry_export_lines(path: Path) -> list[str]:
    for encoding in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            return path.read_text(encoding=encoding).splitlines()
        except (OSError, UnicodeError):
            continue
    return []


def extract_deviceinfo_values(lines: Sequence[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    in_deviceinfo = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deviceinfo = stripped.lower().endswith(r"\software\kakao\kakaotalk\deviceinfo]") or (
                r"\software\kakao\kakaotalk\deviceinfo" in stripped.lower()
            )
            continue
        if not in_deviceinfo:
            continue
        match = re.match(r'"(?P<name>[^"]+)"=(?:"(?P<string>.*)"|(?P<raw>.+))$', stripped)
        if not match:
            continue
        name = match.group("name").lower()
        if name not in KAKAO_DEVICEINFO_FIELDS:
            continue
        value = match.group("string") if match.group("string") is not None else match.group("raw") or ""
        values[name] = value
    return values


def extract_user_id_values_from_reg_export(lines: Sequence[str]) -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    in_kakaotalk = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            lowered = stripped.lower()
            in_kakaotalk = r"\software\kakao\kakaotalk" in lowered
            continue
        if not in_kakaotalk:
            continue
        match = re.match(r'"(?P<name>[^"]+)"=(?:"(?P<string>.*)"|(?P<raw>.+))$', stripped)
        if not match:
            continue
        name = match.group("name")
        normalized_name = canonical_user_id_field_name(name)
        if not normalized_name:
            continue
        value = normalize_kakaotalk_user_id_value(
            match.group("string") if match.group("string") is not None else match.group("raw") or ""
        )
        if not looks_like_kakaotalk_user_id(value):
            continue
        values[normalized_name] = {
            "value": value,
            "offset": -1,
            "value_type": "REG_EXPORT",
            "value_size": len(value),
            "line_number": index + 1,
        }
    return values


def canonical_user_id_field_name(name: str) -> str:
    lowered = name.lower()
    for field in KAKAO_USER_ID_FIELD_NAMES:
        if lowered == field.lower():
            return field
    return ""


def looks_like_kakaotalk_user_id(value: str) -> bool:
    stripped = value.strip().strip('"')
    if not stripped or len(stripped) > 160:
        return False
    if stripped.lower().startswith("hex:"):
        return False
    if re.fullmatch(r"[0-9]{3,20}", stripped):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,128}", stripped):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_.:-]{8,160}", stripped):
        return True
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", stripped):
        return True
    return False


def normalize_kakaotalk_user_id_value(value: str) -> str:
    stripped = value.strip().strip('"')
    allowed = re.findall(r"[A-Za-z0-9+/=_.:-]+", stripped)
    if not allowed:
        return stripped
    return max(allowed, key=len)


def classify_user_id_shape(value: str) -> str:
    stripped = value.strip().strip('"')
    if re.fullmatch(r"[0-9]{3,20}", stripped):
        return "numeric-id"
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", stripped):
        return "uuid-like"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,128}", stripped):
        return "opaque-token"
    if re.fullmatch(r"[A-Za-z0-9+/=_.:-]{8,160}", stripped):
        return "structured-token"
    return "unknown"


def matched_kakao_terms(value: str) -> list[str]:
    lowered = value.lower()
    return [term for term in KAKAO_TERMS if term in lowered]


def classify_candidate(value: str) -> str:
    lowered = value.lower()
    if WINDOWS_PATH_RE.search(value):
        return "path"
    if URL_RE.search(value):
        return "url"
    if "kakaotalk.exe" in lowered or "kakaotalk" in lowered and ".exe" in lowered:
        return "process"
    if any(term in lowered for term in ("chatlog", "chatlogs", "talk_user", "talkuser")):
        return "chat-store"
    return "text"


def candidate_confidence(
    source_family: str,
    candidate_kind: str,
    candidate_value: str,
    matched_terms: Sequence[str],
    metadata: Mapping[str, object],
) -> float:
    score = 0.34
    if source_family in {"windows-edb", "registry", "memory-dump"}:
        score += 0.08
    if candidate_kind in {"path", "process", "chat-store"}:
        score += 0.14
    if any(term in matched_terms for term in KAKAO_HIGH_VALUE_TERMS):
        score += 0.14
    if extract_paths(candidate_value):
        score += 0.08
    if metadata.get("page_sha256") or metadata.get("line_number") or metadata.get("encoding"):
        score += 0.04
    return round(min(score, 0.82), 2)


def build_candidate_flags(source_family: str, candidate_kind: str, matched_terms: Sequence[str]) -> list[str]:
    flags = ["kakaotalk-windows-candidate", f"kakaotalk-source:{source_family}", f"kakaotalk-kind:{candidate_kind}"]
    if source_family == "memory-dump":
        flags.append("volatile-memory-kakaotalk-string")
    if candidate_kind == "chat-store" or any(term in KAKAO_HIGH_VALUE_TERMS for term in matched_terms):
        flags.append("high-value-kakaotalk-artifact")
    return sorted(set(flags))


def extract_paths(value: str) -> list[str]:
    return list(dict.fromkeys(match.group(0).rstrip(".,);]") for match in WINDOWS_PATH_RE.finditer(value)))[:10]


def extract_urls(value: str) -> list[str]:
    return list(dict.fromkeys(match.group(0).rstrip(".,);]") for match in URL_RE.finditer(value)))[:10]


def normalize_candidate_value(value: str) -> str:
    return " ".join(value.lower().split())[:500]


def sorted_counts(counts: Mapping[str, int]) -> list[dict[str, object]]:
    return [{"value": value, "count": count} for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
