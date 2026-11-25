"""KakaoTalk memory analyses inside the main run.

Finds KakaoTalk process dumps anywhere in the evidence tree (renamed,
moved to Desktop/Downloads/Temp, or written by ``kakaotalk-collect-windows``)
plus hiberfil.sys/pagefile.sys/swapfile.sys residue, then runs the
memory carve, SQLCipher key-residue probe and key-store residency check on
them and emits rows for the report and timeline.

Discovery is bounded: files under ``DISCOVERY_MIN_BYTES`` are ignored, only
the first 4 bytes are read to spot a minidump, a minidump is confirmed from
its module list (process image ``KakaoTalk.exe``) and stream directory
without reading memory ranges, and a header-less raw dump is accepted only
next to KakaoTalk evidence or when a bounded sample holds KakaoTalk
markers. Nothing is read in full before a dump is confirmed.

The analyses hold a whole dump in memory, so a confirmed dump larger than
``MAX_IN_MEMORY_DUMP_BYTES`` is scanned like hiberfil/pagefile residue, as
bounded overlapping segments; the analyses that need the dump's virtual
address map are not applied to it, and its record says so.
"""

from __future__ import annotations

import datetime as dt
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ..core.kakaotalk_residue_memory import RESIDUE_SOURCE_KINDS
from ..core.models import ArtifactRecord
from ._walk import iter_evidence_paths
from .memory import parse_minidump, safe_memory_source_hashes

PARSER_VERSION = "kakaotalk-memory-auto-v1"
COLLECTOR_KIND = "kakaotalk-memory"
DISCOVERY_MIN_BYTES = 64 * 1024
RAW_SAMPLE_BYTES = 1024 * 1024
MAX_ANALYSED_DUMPS = 64
MAX_IN_MEMORY_DUMP_BYTES = 1024 * 1024 * 1024
SEGMENTED_NOT_APPLIED = ("runtime-key-store-nodes", "postpatch-ikm", "postpatch-v2-dek-derivation")
MAX_MESSAGE_ROWS = 1000
KAKAO_PROCESS_IMAGE = "kakaotalk.exe"
KAKAO_COLLECT_NAME = re.compile(r"^kakaotalk_\d+\.dmp$", re.IGNORECASE)
RAW_DUMP_SUFFIXES = (".dmp", ".dump", ".raw", ".mem")
RAW_KAKAO_MARKERS = (
    b"KakaoTalk",
    "KakaoTalk".encode("utf-16le"),
    b'{"chatId"',
    b"TalkChatDB",
)
TRIAGE_NOTE = (
    "메모리 잔존 데이터(검증 필요): 실제 송수신 여부는 원본 대화 DB로 확인해야 합니다."
)


class KakaoTalkMemoryProvider:
    collector_kind = COLLECTOR_KIND
    name = "kakaotalk-memory-analysis"
    description = "KakaoTalk process dumps anywhere in the evidence tree plus hiberfil/pagefile residue"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        dumps, residue_sources = discover_kakaotalk_memory_sources(root)
        confirmed = [dump for dump in dumps if dump["confirmed"]]
        analysed = confirmed[:MAX_ANALYSED_DUMPS]
        for dump in dumps:
            if not dump["confirmed"]:
                yield build_dump_record(dump, analysis_counts={})
        for dump in confirmed[MAX_ANALYSED_DUMPS:]:
            yield build_dump_record(dump, analysis_counts={}, skip_reason="analysis-limit")
        if not analysed and not residue_sources:
            return
        whole = [Path(str(dump["path"])) for dump in analysed if not is_segmented(dump)]
        segmented = [Path(str(dump["path"])) for dump in analysed if is_segmented(dump)]
        analyses = run_kakaotalk_memory_analyses(root, whole, [*residue_sources, *segmented])
        carve = analyses["carve"]
        for dump in analysed:
            yield build_dump_record(
                dump, analysis_counts=count_hits_for_source(carve, str(dump["path"]))
            )
        yield from build_analysis_rows(analyses)


def is_segmented(dump: Mapping[str, object]) -> bool:
    return int(dump.get("size") or 0) > MAX_IN_MEMORY_DUMP_BYTES


def discover_kakaotalk_memory_sources(
    root: Path,
) -> tuple[list[dict[str, object]], list[Path]]:
    dumps: list[dict[str, object]] = []
    residue: list[Path] = []
    for path in sorted(
        iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()
    ):
        if not path.is_file():
            continue
        if path.name.lower() in RESIDUE_SOURCE_KINDS:
            residue.append(path.resolve())
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < DISCOVERY_MIN_BYTES:
            continue
        try:
            with path.open("rb") as handle:
                signature = handle.read(4)
        except OSError:
            continue
        if signature == b"MDMP":
            dumps.append(classify_minidump(path, size))
        elif path.suffix.lower() in RAW_DUMP_SUFFIXES:
            dumps.append(classify_raw_dump(path, size, root))
    return dumps, residue


def module_basename(name: str) -> str:
    return re.split(r"[\\/]", name)[-1]


def classify_minidump(path: Path, size: int) -> dict[str, object]:
    minidump = parse_minidump(path) or {}
    modules = (
        minidump.get("modules") if isinstance(minidump.get("modules"), list) else []
    )
    module_names = [
        module_basename(str(module.get("name") or ""))
        for module in modules
        if isinstance(module, Mapping)
    ]
    misc = (
        minidump.get("misc_info")
        if isinstance(minidump.get("misc_info"), Mapping)
        else {}
    )
    reasons = ["minidump-signature"]
    process_image = module_names[0] if module_names else ""
    confirmed = False
    if process_image.lower() == KAKAO_PROCESS_IMAGE:
        reasons.append("process-image:KakaoTalk.exe")
        confirmed = True
    elif any(name.lower() == KAKAO_PROCESS_IMAGE for name in module_names):
        reasons.append("module-list:KakaoTalk.exe")
        confirmed = True
    if KAKAO_COLLECT_NAME.match(path.name):
        reasons.append("kakaotalk-collect-file-name")
        confirmed = confirmed or not module_names
    return {
        "path": str(path.resolve()),
        "size": size,
        "dump_format": "minidump",
        "confirmed": confirmed,
        "process_name": process_image,
        "process_id": misc.get("process_id", ""),
        "process_create_time": misc.get("process_create_time", ""),
        "dump_time": minidump.get("dump_time", ""),
        "module_count": len(module_names),
        "identification_reasons": reasons,
    }


def classify_raw_dump(path: Path, size: int, root: Path) -> dict[str, object]:
    reasons = [f"suffix:{path.suffix.lower()}"]
    if is_near_kakaotalk_evidence(path, root):
        reasons.append("next-to-kakaotalk-evidence")
    else:
        try:
            with path.open("rb") as handle:
                sample = handle.read(RAW_SAMPLE_BYTES)
        except OSError:
            sample = b""
        markers = [
            marker.decode("utf-16le") if b"\x00" in marker else marker.decode()
            for marker in RAW_KAKAO_MARKERS
            if marker in sample
        ]
        if markers:
            reasons.append("sample-markers:" + ",".join(sorted(set(markers))))
    return {
        "path": str(path.resolve()),
        "size": size,
        "dump_format": "raw",
        "confirmed": len(reasons) > 1,
        "process_name": "",
        "process_id": "",
        "process_create_time": "",
        "dump_time": "",
        "module_count": 0,
        "identification_reasons": reasons,
    }


def is_near_kakaotalk_evidence(path: Path, root: Path) -> bool:
    try:
        inside_root = path.parent.relative_to(root)
    except ValueError:
        inside_root = Path(path.parent.name)
    if "kakao" in str(inside_root).lower():
        return True
    try:
        siblings = [
            child.name.lower() for _, child in zip(range(256), path.parent.iterdir())
        ]
    except OSError:
        return False
    return any("kakao" in name for name in siblings if name != path.name.lower())


def run_kakaotalk_memory_analyses(
    root: Path, dumps: Sequence[Path], residue_sources: Sequence[Path]
) -> dict[str, dict[str, object]]:
    # core.kakaotalk -> core.docs -> artifacts would be circular at module import time.
    from ..core.kakaotalk import (
        DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
        DEFAULT_MEMORY_SQLITE_MAX_HITS,
        build_kakaotalk_memory_carve_payload,
        run_kakaotalk_key_store_inspect,
        run_kakaotalk_sqlcipher_probe,
    )

    with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-memory-") as temp_dir:
        output_dir = Path(temp_dir)
        carve = build_kakaotalk_memory_carve_payload(
            root=root,
            output=output_dir / "carve.json",
            carve_dir=None,
            max_hits=DEFAULT_MEMORY_SQLITE_MAX_HITS,
            max_carve_bytes=DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
            include_row_preview=False,
            max_rows_per_table=0,
            max_message_residues=MAX_MESSAGE_ROWS,
            include_message_preview=True,
            write_carves=False,
            command="run-kakaotalk-memory",
            sources=dumps,
            residue_sources=residue_sources,
        )
        probe = run_kakaotalk_sqlcipher_probe(
            root,
            output=output_dir / "probe.json",
            max_message_residues=1,
            memory_sources=dumps,
            residue_sources=residue_sources,
        )
        key_store = run_kakaotalk_key_store_inspect(
            root,
            output=output_dir / "key-store.json",
            max_memory_sources=len(dumps) or 1,
            memory_sources=dumps,
            residue_sources=residue_sources,
        )
    return {"carve": carve, "probe": probe, "key_store": key_store}


def count_hits_for_source(
    carve: Mapping[str, object], source_path: str
) -> dict[str, int]:
    counts: dict[str, int] = {}
    residue = (
        carve.get("residue_memory")
        if isinstance(carve.get("residue_memory"), Mapping)
        else {}
    )
    for key in (
        "entries",
        "chat_message_residues",
        "reverse_indicators",
        "sqlcipher_key_residues",
    ):
        items = [
            *(carve.get(key) if isinstance(carve.get(key), list) else []),
            *list_of(residue, key),
        ]
        counts[key] = sum(
            1
            for item in items
            if isinstance(item, Mapping) and item.get("source_path") == source_path
        )
    return counts


def file_times(path: Path) -> dict[str, str]:
    try:
        stat = path.stat()
    except OSError:
        return {}

    def iso(value: float) -> str:
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).isoformat()

    return {
        "modified_at": iso(stat.st_mtime),
        "accessed_at": iso(stat.st_atime),
        "changed_at": iso(stat.st_ctime),
    }


def build_dump_record(
    dump: Mapping[str, object],
    *,
    analysis_counts: Mapping[str, int],
    skip_reason: str = "",
) -> ArtifactRecord:
    path = Path(str(dump["path"]))
    size = int(dump.get("size") or 0)
    analysed = bool(dump.get("confirmed")) and not skip_reason
    details: dict[str, object] = {
        "parser": COLLECTOR_KIND,
        "parser_version": PARSER_VERSION,
        "source_path": str(path),
        "source_size": size,
        "dump_format": dump.get("dump_format", ""),
        "process_name": dump.get("process_name", ""),
        "pid": dump.get("process_id", ""),
        "dump_time": dump.get("dump_time", ""),
        "process_create_time": dump.get("process_create_time", ""),
        "module_count": dump.get("module_count", 0),
        "identification_reasons": list(dump.get("identification_reasons") or []),
        "file_times": file_times(path),
        "file_times_source": "extracted-file-stat",
        "reportability": "triage",
    }
    if analysed:
        details["source_hashes"] = safe_memory_source_hashes(path, file_size=size)
        details["analysis_counts"] = dict(analysis_counts)
        details["display_label"] = "카카오톡 프로세스 메모리 덤프"
        details["timestamp"] = dump.get("dump_time", "")
        if is_segmented(dump):
            details["analysis_mode"] = "segmented"
            details["analysis_mode_reason"] = (
                f"larger than the {MAX_IN_MEMORY_DUMP_BYTES}-byte in-memory cap: scanned as bounded "
                "overlapping segments like hiberfil/pagefile residue"
            )
            details["not_applied"] = list(SEGMENTED_NOT_APPLIED)
        else:
            details["analysis_mode"] = "whole-file"
    elif skip_reason:
        details["skip_reason"] = skip_reason
        details["display_label"] = (
            f"카카오톡 프로세스 메모리 덤프(분석 한도 {MAX_ANALYSED_DUMPS}개 초과, 미분석)"
        )
    else:
        details["skip_reason"] = (
            "other-process-dump"
            if dump.get("dump_format") == "minidump"
            else "no-kakaotalk-evidence"
        )
        details["display_label"] = "다른 프로세스 덤프(카카오톡 분석 제외)"
    return ArtifactRecord(
        provider=KakaoTalkMemoryProvider.name,
        artifact_type="kakaotalk-memory-dump"
        if analysed
        else "kakaotalk-memory-dump-skipped",
        path=str(path),
        supported=True,
        details=details,
    )


def residue_fields(item: Mapping[str, object]) -> dict[str, object]:
    fields = {
        "source_path": item.get("source_path", ""),
        "source_offset": item.get("source_offset", ""),
        "evidence_class": item.get("evidence_class", "process-memory"),
        "confidence": item.get("confidence", "needs-validation"),
    }
    for key in ("source_kind", "page_number", "page_offset"):
        if key in item:
            fields[key] = item[key]
    return fields


def build_analysis_rows(
    analyses: Mapping[str, Mapping[str, object]],
) -> Iterable[ArtifactRecord]:
    carve = analyses["carve"]
    probe = analyses["probe"]
    key_store = analyses["key_store"]
    residue = (
        carve.get("residue_memory")
        if isinstance(carve.get("residue_memory"), Mapping)
        else {}
    )
    messages = [
        *list_of(carve, "chat_message_residues"),
        *list_of(residue, "chat_message_residues"),
    ]
    for item in messages[:MAX_MESSAGE_ROWS]:
        yield ArtifactRecord(
            provider=KakaoTalkMemoryProvider.name,
            artifact_type="kakaotalk-memory-message-residue",
            path=str(item.get("source_path") or ""),
            supported=True,
            details={
                "parser": COLLECTOR_KIND,
                "parser_version": PARSER_VERSION,
                **residue_fields(item),
                "chat_id": item.get("chat_id", 0),
                "log_id": item.get("log_id", 0),
                "author_id": item.get("author_id", 0),
                "message_type": item.get("type", 0),
                "deleted": item.get("deleted", False),
                "message": item.get("message_text", ""),
                "message_text_sha256": item.get("message_text_sha256", ""),
                "timestamp": item.get("send_at_utc", ""),
                "reportability": "triage",
                "validation_guidance": TRIAGE_NOTE,
            },
        )
    for item in [
        *list_of(carve, "sqlcipher_key_residues"),
        *list_of(residue, "sqlcipher_key_residues"),
    ]:
        yield ArtifactRecord(
            provider=KakaoTalkMemoryProvider.name,
            artifact_type="kakaotalk-memory-key-residue",
            path=str(item.get("source_path") or ""),
            supported=True,
            details={
                "parser": COLLECTOR_KIND,
                "parser_version": PARSER_VERSION,
                **residue_fields(item),
                "byte_length": item.get("byte_length", 0),
                "candidate_sha256": item.get("candidate_sha256", ""),
                "raw_key_sha256": item.get("raw_key_sha256", ""),
                "context_terms": item.get("context_terms", []),
                "raw_key_redacted": True,
                "reportability": "triage",
            },
        )
    for item in [*list_of(carve, "entries"), *list_of(residue, "entries")]:
        yield ArtifactRecord(
            provider=KakaoTalkMemoryProvider.name,
            artifact_type="kakaotalk-memory-sqlite-carve",
            path=str(item.get("source_path") or ""),
            supported=True,
            details={
                "parser": COLLECTOR_KIND,
                "parser_version": PARSER_VERSION,
                **residue_fields(item),
                "sqlite_status": item.get("sqlite_status", ""),
                "carved_size": item.get("carved_size", 0),
                "truncated": item.get("truncated", False),
                "tables": [
                    {
                        key: table.get(key)
                        for key in ("name", "row_count", "chat_relevant")
                    }
                    for table in item.get("tables") or []
                    if isinstance(table, Mapping)
                ],
                "reportability": "triage",
            },
        )
    for source in list_of(residue, "sources"):
        yield ArtifactRecord(
            provider=KakaoTalkMemoryProvider.name,
            artifact_type="kakaotalk-memory-residue-source",
            path=str(source.get("source_path") or ""),
            supported=source.get("status") in {"read", "partial"},
            details={
                "parser": COLLECTOR_KIND,
                "parser_version": PARSER_VERSION,
                **source,
            },
        )
    yield ArtifactRecord(
        provider=KakaoTalkMemoryProvider.name,
        artifact_type="kakaotalk-memory-analysis-summary",
        path="",
        supported=True,
        details={
            "parser": COLLECTOR_KIND,
            "parser_version": PARSER_VERSION,
            "memory_carve": carve.get("summary", {}),
            "sqlcipher_probe": probe.get("summary", {}),
            "sqlcipher_probe_openable_edbs": probe.get("openable_edbs", []),
            "sqlcipher_probe_matches": [
                {
                    key: match.get(key)
                    for key in (
                        "database",
                        "variant",
                        "compatibility",
                        "evidence_class",
                        "confidence",
                    )
                }
                for match in list_of(probe, "matches")
            ],
            "key_store": key_store.get("summary", {}),
            "key_store_residue_hits": [
                hit
                for entry in list_of(key_store, "key_stores")
                for hit in entry.get("residue_memory_hits") or []
            ],
        },
    )


def list_of(payload: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    value = payload.get(key)
    return (
        [item for item in value if isinstance(item, Mapping)]
        if isinstance(value, list)
        else []
    )
