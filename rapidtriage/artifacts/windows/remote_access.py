from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .._walk import iter_evidence_paths
from .common import isoformat_from_timestamp, iter_windows_user_homes
from .prefetch import prefetch_header_hints
from .recent_files import parse_lnk_metadata_from_bytes
from .system import (
    IP_RE,
    REMOTE_CONTROL_SCAN_LIMIT,
    URL_RE,
    extract_ascii_strings,
    extract_utf16_strings,
    read_prefix,
    regex_candidates,
    remote_control_product_for_path,
    remote_control_risk_flags,
    remote_control_session_profile,
    unique_strings,
)

PARSER_VERSION = "windows-remote-access-v4"
RDP_CACHE_ROOT = ("AppData", "Local", "Microsoft", "Terminal Server Client", "Cache")
RDP_DESTINATION_RE = re.compile(r"(?i)\\terminal server client\\(?:default|servers)\\(?P<destination>[^\\\]\"]+)")
RDP_CACHE_SCAN_LIMIT = 4 * 1024 * 1024
IMAGE_SIGNATURES = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("bmp", b"BM"),
)


class WindowsRemoteAccessProvider:
    name = "windows-remote-access"
    collector_kind = "windows-remote-access"
    description = "Windows RDP configuration, cache, and exported destination artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_rdp_config_files(root)
        yield from collect_rdp_cache_files(root)
        yield from collect_rdp_registry_exports(root)
        yield from collect_third_party_remote_control_artifacts(root)


def collect_rdp_config_files(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        documents = user_root / "Documents"
        candidates = list(documents.glob("*.rdp")) if documents.is_dir() else []
        default_rdp = user_root / "Documents" / "Default.rdp"
        if default_rdp.is_file() and default_rdp not in candidates:
            candidates.append(default_rdp)
        for path in sorted((item for item in candidates if item.is_file()), key=lambda item: item.name.lower()):
            fields = parse_rdp_file(path)
            stat_result = path.stat()
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-config",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "rdp"),
                    "user": user_root.name,
                    "destination": fields.get("full address", ""),
                    "username_hint": fields.get("username", ""),
                    "screen_mode": fields.get("screen mode id", ""),
                    "gateway_hostname": fields.get("gatewayhostname", ""),
                    "fields": fields,
                    "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": "",
                    "timestamp_source": "none-rdp-file-modified-at-is-acquisition-copy-time",
                },
            )


def collect_rdp_cache_files(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        cache_root = user_root.joinpath(*RDP_CACHE_ROOT)
        if not cache_root.is_dir():
            continue
        for path in sorted((item for item in iter_evidence_paths(cache_root, "*") if item.is_file()), key=lambda item: str(item).lower()):
            stat_result = path.stat()
            thumbnail_candidates = scan_thumbnail_candidates(path)
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-cache-file",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "rdp-cache"),
                    "user": user_root.name,
                    "entry_name": path.name,
                    "size": stat_result.st_size,
                    "cache_parse_status": "image-signature-pivots",
                    "thumbnail_candidate_count": len(thumbnail_candidates),
                    "thumbnail_candidates": thumbnail_candidates,
                    "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": "",
                    "timestamp_source": "none-rdp-cache-modified-at-is-acquisition-copy-time",
                    "note": "RDP cache file inventoried with bounded image signature pivots for remote-access thumbnail review; validate important screenshots with a dedicated RDP cache decoder.",
                },
            )


def collect_rdp_registry_exports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*.reg"), key=lambda item: str(item).lower()):
        text = read_text(path)
        if "Terminal Server Client" not in text:
            continue
        destinations = sorted(set(match.group("destination") for match in RDP_DESTINATION_RE.finditer(text)))
        for destination in destinations:
            yield ArtifactRecord(
                provider=WindowsRemoteAccessProvider.name,
                artifact_type="rdp-destination",
                path=str(path.resolve()),
                supported=True,
                details={
                    **source_details(path, "reg-export"),
                    "destination": destination,
                    "evidence_strength": "remote-access-destination",
                    "raw_preview": text[:1000],
                },
            )


REMOTE_CONTROL_TEXT_SUFFIXES = {".log", ".txt", ".trace", ".toml", ".conf", ".ini", ".cfg", ".json", ".xml", ".csv"}
TEMPLATE_PROFILE_PARTS = {"default", "default user"}


def collect_third_party_remote_control_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    """Third-party remote-control pivots (single owner: windows-remote-access).

    The row time comes from the artifact itself: Prefetch run times, LNK
    target times, or a timestamp written inside a text log. The acquired
    copy's host mtime is kept only as ``source_file_mtime``. Session
    candidates are only extracted from text logs; shortcuts and Prefetch
    files show installation/execution, not sessions.
    """
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        product = remote_control_product_for_path(path)
        if not product:
            continue
        stat_result = path.stat()
        suffix = path.suffix.lower()
        lowered_parts = {part.lower() for part in path.parts}
        profile_template = bool(lowered_parts & TEMPLATE_PROFILE_PARTS) and "users" in lowered_parts
        details: dict[str, object] = {
            **source_details(path, "third-party-remote-control"),
            "product": product,
            "size": stat_result.st_size,
            "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
            "profile_template": profile_template,
            "reportability": "triage",
            "validation_required": True,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "full-product-specific-session-state-decoder-required",
                "remote-peer-attribution-validation-required",
                "file-transfer-log-validation-required",
            ],
        }
        risk_flags = [f"remote-control:{product}"]
        empty_profile = remote_control_session_profile(product, [], [], [])
        if suffix == ".pf":
            header = prefetch_header_hints(path)
            if header.get("binary_format_detected"):
                run_times = list(header.get("last_run_times") or [])
                details.update(
                    {
                        "artifact_role": "execution-prefetch",
                        "coverage_status": "remote-control-execution-evidence",
                        "parser_confidence": "high",
                        "executable_name": header.get("header_executable_name", ""),
                        "run_count": header.get("run_count", 0),
                        "last_run_times": run_times,
                        "timestamp": run_times[0] if run_times else "",
                        "timestamp_source": "prefetch_last_run_time" if run_times else "missing_prefetch_run_time",
                        "timestamp_kind": "run",
                    }
                )
                risk_flags.append("remote-control-executed")
            else:
                details.update(
                    {
                        "artifact_role": "prefetch-invalid-content",
                        "coverage_status": "remote-control-file-inventory",
                        "parser_confidence": "low",
                        "timestamp": "",
                        "timestamp_source": "none-prefetch-invalid-content",
                    }
                )
            session_profile = empty_profile
        elif suffix == ".lnk":
            lnk = parse_lnk_metadata_from_bytes(read_prefix(path, REMOTE_CONTROL_SCAN_LIMIT))
            times = {key: lnk.get(key, "") for key in ("target_created_at", "target_accessed_at", "target_modified_at")}
            stamp_key = next((key for key in ("target_accessed_at", "target_modified_at", "target_created_at") if times[key]), "")
            details.update(
                {
                    "artifact_role": "shortcut-template" if profile_template else "shortcut",
                    "coverage_status": "remote-control-installation-shortcut",
                    "parser_confidence": "medium",
                    "lnk_parse_status": lnk.get("lnk_parse_status", ""),
                    "target_path": lnk.get("target_path", ""),
                    **times,
                    "timestamp": times[stamp_key] if stamp_key else "",
                    "timestamp_source": stamp_key or "missing_lnk_target_times",
                    "timestamp_kind": f"lnk-target-{stamp_key.split('_')[1]}" if stamp_key else "",
                }
            )
            risk_flags.append("remote-control-installed-shortcut")
            if profile_template:
                risk_flags.append("default-profile-template")
            session_profile = empty_profile
        else:
            blob = read_prefix(path, REMOTE_CONTROL_SCAN_LIMIT)
            strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
            urls = regex_candidates(strings, URL_RE)[:20]
            ips = sorted(set(IP_RE.findall(" ".join(strings))))[:20]
            is_text = suffix in REMOTE_CONTROL_TEXT_SUFFIXES
            session_profile = remote_control_session_profile(product, strings, urls, ips) if is_text else empty_profile
            log_times = list(session_profile.get("timestamp_candidates") or [])
            details.update(
                {
                    "artifact_role": "log" if is_text else "binary-file",
                    "coverage_status": "remote-control-session-pivot-inventory"
                    if session_profile["session_candidates"]
                    else "remote-control-file-inventory",
                    "parser_confidence": "medium",
                    "scan_bytes": len(blob),
                    "extracted_string_count": len(strings),
                    "string_samples": strings[:40],
                    "url_candidates": urls,
                    "ip_candidates": ips,
                    # Log text timestamps carry no offset: kept as written, timezone unknown.
                    "timestamp": log_times[0] if log_times else "",
                    "timestamp_source": "remote_control_log_text" if log_times else "none-no-artifact-time",
                    "timestamp_kind": "event" if log_times else "",
                    "timezone": "unknown" if log_times else "",
                }
            )
        details.update(
            {
                "remote_control_session_profile": session_profile,
                "session_candidates": session_profile["session_candidates"],
                "remote_id_candidates": session_profile["remote_id_candidates"],
                "file_transfer_indicators": session_profile["file_transfer_indicators"],
                "risk_flags": [*risk_flags, *remote_control_risk_flags(product, session_profile)[1:]],
                "validation_guidance": (
                    "원격 제어 도구 흔적입니다. Prefetch는 실행, 바로가기는 설치 흔적이며 세션 근거가 아닙니다. "
                    "세션 시작/종료·상대방·파일 전송은 제품별 로그 파서로 확인한 뒤 보고서에 사용하십시오."
                ),
            }
        )
        yield ArtifactRecord(
            provider=WindowsRemoteAccessProvider.name,
            artifact_type="third-party-remote-control-artifact",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


def parse_rdp_file(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in read_text(path).splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) != 3:
            continue
        key, _value_type, value = parts
        fields[key.strip().lower()] = value.strip()
    return fields


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return data.decode(encoding, errors="replace")


def scan_thumbnail_candidates(path: Path, *, scan_limit: int = RDP_CACHE_SCAN_LIMIT) -> list[dict[str, object]]:
    try:
        with path.open("rb") as handle:
            blob = handle.read(scan_limit)
    except OSError:
        return []
    candidates: list[dict[str, object]] = []
    for image_type, signature in IMAGE_SIGNATURES:
        start = 0
        while True:
            offset = blob.find(signature, start)
            if offset < 0:
                break
            candidate = {"type": image_type, "offset": offset, "signature": signature.hex()}
            candidate.update(image_dimensions(blob, image_type, offset))
            candidates.append(candidate)
            if len(candidates) >= 20:
                return candidates
            start = offset + max(1, len(signature))
    candidates.extend(scan_dib_candidates(blob, existing_offsets={int(item["offset"]) for item in candidates}))
    return candidates[:20]


def image_dimensions(blob: bytes, image_type: str, offset: int) -> dict[str, int]:
    if image_type == "png" and len(blob) >= offset + 24:
        return {
            "width": int.from_bytes(blob[offset + 16 : offset + 20], "big", signed=False),
            "height": int.from_bytes(blob[offset + 20 : offset + 24], "big", signed=False),
        }
    if image_type == "bmp" and len(blob) >= offset + 26:
        return {
            "width": int.from_bytes(blob[offset + 18 : offset + 22], "little", signed=True),
            "height": int.from_bytes(blob[offset + 22 : offset + 26], "little", signed=True),
        }
    return {}


def scan_dib_candidates(blob: bytes, *, existing_offsets: set[int]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for offset in range(0, max(0, len(blob) - 16), 4):
        if offset in existing_offsets:
            continue
        header_size = int.from_bytes(blob[offset : offset + 4], "little", signed=False)
        if header_size not in {40, 108, 124}:
            continue
        width = int.from_bytes(blob[offset + 4 : offset + 8], "little", signed=True)
        height = int.from_bytes(blob[offset + 8 : offset + 12], "little", signed=True)
        planes = int.from_bytes(blob[offset + 12 : offset + 14], "little", signed=False)
        bits_per_pixel = int.from_bytes(blob[offset + 14 : offset + 16], "little", signed=False)
        if planes != 1 or bits_per_pixel not in {1, 4, 8, 16, 24, 32}:
            continue
        if not (0 < abs(width) <= 10000 and 0 < abs(height) <= 10000):
            continue
        candidates.append(
            {
                "type": "dib",
                "offset": offset,
                "signature": f"dib-header-{header_size}",
                "width": width,
                "height": height,
                "bits_per_pixel": bits_per_pixel,
            }
        )
        if len(candidates) >= 20:
            break
    return candidates


def source_details(path: Path, source_format: str) -> dict[str, object]:
    return {
        "parser": "windows-remote-access",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_hashes": {"sha256": compute_sha256(path)},
    }
