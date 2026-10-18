"""Program Compatibility Assistant text files (Windows 11 22H2+) -> ``execution-pca`` rows.

``C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt``: one ``<path>|<UTC time>`` line per
executable (last launch through Explorer). ``PcaGeneralDb0.txt`` / ``PcaGeneralDb1.txt``:
``<UTC time>|<record type>|<path>|<product>|<vendor>|<version>|<program id>|<message>``
(abnormal exits, compatibility events). The registry side (``Compatibility Assistant\\Store``)
is decoded by :mod:`.registry_depth`.

Bounded: files over :data:`MAX_PCA_FILE_BYTES` are skipped, at most
:data:`MAX_PCA_LINES` lines are read per file; malformed lines are counted on
the rows of the same file (``malformed_line_count``), never raised.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

from ...core.models import ArtifactRecord
from .._walk import iter_evidence_paths

PCA_PARSER = "windows-pca-text"
PCA_PARSER_VERSION = "pca-text-v1"
MAX_PCA_FILE_BYTES = 64 * 1024 * 1024
MAX_PCA_LINES = 200_000
PCA_FILE_NAMES = re.compile(r"^(pcaapplaunchdic\.txt|pcageneraldb\d\.txt)$", re.IGNORECASE)
PCA_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?$")
PCA_RECORD_TYPES = {"0": "실행", "1": "설치 관련", "2": "비정상 종료", "3": "호환성 문제"}


def pca_time(text: str) -> str:
    """``YYYY-MM-DD HH:MM:SS.fff`` (UTC) -> ISO-8601 with ``+00:00``; ``""`` when malformed."""
    match = PCA_TIME.match(text.strip())
    if not match:
        return ""
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = match.group(7) or ""
    try:
        moment = dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)
    except ValueError:
        return ""
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{fraction}+00:00" if fraction else f"{stamp}+00:00"


def decode_pca_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(data) > 1 and data[1:2] == b"\x00"):
        return data.decode("utf-16", errors="replace") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp949", errors="replace")


def parse_pca_file(path: Path) -> tuple[list[dict[str, object]], int, bool]:
    """``(entries, malformed line count, truncated)`` of one PCA text file."""
    data = path.read_bytes()
    lines = decode_pca_text(data).splitlines()
    truncated = len(lines) > MAX_PCA_LINES
    entries: list[dict[str, object]] = []
    malformed = 0
    general = path.name.lower().startswith("pcageneraldb")
    for number, line in enumerate(lines[:MAX_PCA_LINES], start=1):
        stripped = line.strip().strip("\x00")
        if not stripped:
            continue
        parts = stripped.split("|")
        if general:
            if len(parts) < 3 or not pca_time(parts[0]):
                malformed += 1
                continue
            padded = parts + [""] * (8 - len(parts))
            entries.append(
                {
                    "source_kind": "pca-general-db",
                    "event_at": pca_time(padded[0]),
                    "record_type": padded[1].strip(),
                    "record_type_label": PCA_RECORD_TYPES.get(padded[1].strip(), ""),
                    "executable_path": padded[2].strip(),
                    "product_name": padded[3].strip(),
                    "vendor": padded[4].strip(),
                    "product_version": padded[5].strip(),
                    "program_id": padded[6].strip(),
                    "message": "|".join(padded[7:]).strip()[:1000],
                    "source_line": number,
                }
            )
        else:
            if len(parts) < 2 or not pca_time(parts[-1]):
                malformed += 1
                continue
            entries.append(
                {
                    "source_kind": "pca-app-launch-dic",
                    "last_run_at": pca_time(parts[-1]),
                    "executable_path": "|".join(parts[:-1]).strip(),
                    "source_line": number,
                }
            )
    return entries, malformed, truncated


def collect_pca_text_files(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not PCA_FILE_NAMES.match(path.name) or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_PCA_FILE_BYTES:
                continue
            entries, malformed, truncated = parse_pca_file(path)
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError, UnicodeError):
            continue
        resolved = str(path.resolve())
        for entry in entries:
            executable = str(entry.get("executable_path") or "")
            moment = str(entry.get("last_run_at") or entry.get("event_at") or "")
            kind = str(entry["source_kind"])
            yield ArtifactRecord(
                provider=provider,
                artifact_type="execution-pca",
                path=resolved,
                supported=True,
                details={
                    "parser": PCA_PARSER,
                    "parser_version": PCA_PARSER_VERSION,
                    "recovery_method": "parsed",
                    "source_path": resolved,
                    "source_format": "pca-text",
                    "source_hashes": {"sha256": sha256},
                    "source_offset": entry.get("source_line"),
                    "source_offset_unit": "line",
                    "label": "프로그램 호환성 도우미(PCA 기록 파일)",
                    "source_kind_label": "PcaAppLaunchDic.txt(실행 기록)" if kind == "pca-app-launch-dic" else "PcaGeneralDb(호환성 이벤트)",
                    **entry,
                    "executable_name": executable.replace("/", "\\").rsplit("\\", 1)[-1],
                    "timestamp": moment,
                    "timestamp_label": "last_run" if kind == "pca-app-launch-dic" else "pca_event",
                    "timestamp_timezone": "UTC" if moment else "",
                    "malformed_line_count": malformed,
                    "line_cap_reached": truncated,
                    "raw_preview": f"{executable}|{moment}",
                    "evidence_note": "PCA 기록은 탐색기를 통한 실행·호환성 이벤트 흔적입니다(Windows 11 22H2 이상).",
                },
            )
