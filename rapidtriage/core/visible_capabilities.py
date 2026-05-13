from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence


PROFILE_VERSION = "visible-forensic-capabilities-v1"

STATUS_LABELS = {
    "usable": "사용 가능",
    "partial": "부분 구현",
    "inventory": "목록화",
    "validation-required": "검증 필요",
    "external-required": "외부 자료 필요",
}

CAPABILITY_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "id": "evidence-image-input",
        "catalog_id": "evidence-input",
        "label": "이미지 / 증거 입력",
        "capabilities": (
            {"id": "image-e01-ex01", "label": "E01/Ex01 선택", "status": "usable", "terms": ("e01", "ex01", "ewf", "image")},
            {"id": "image-raw-split", "label": "RAW/split image", "status": "partial", "terms": ("raw", "dd", "001", "split")},
            {"id": "image-vm-disk", "label": "VHD/VHDX/VMDK/VDI/QCOW", "status": "inventory", "terms": ("vhd", "vhdx", "vmdk", "vdi", "qcow")},
            {"id": "image-export-only", "label": "AD1/L01/AFF/XVA export workflow", "status": "external-required", "terms": ("ad1", "l01", "aff", "aff4", "xva")},
        ),
    },
    {
        "id": "windows-eventlog",
        "catalog_id": "windows-core",
        "label": "EVTX / 이벤트 로그",
        "capabilities": (
            {"id": "eventlog-chunk", "label": "EVTX chunk/record", "status": "partial", "terms": ("evtx", "eventlog", "record", "chunk")},
            {"id": "eventlog-provider-message-rendering", "label": "Provider message rendering", "status": "validation-required", "terms": ("provider", "manifest", "message", "template")},
            {"id": "eventlog-corrupt-recovery", "label": "Corrupt/deleted record recovery", "status": "validation-required", "terms": ("deleted", "corrupt", "slack", "recovery")},
        ),
    },
    {
        "id": "windows-registry-account",
        "catalog_id": "windows-core",
        "label": "Registry / 계정",
        "capabilities": (
            {"id": "registry-hive-tree", "label": "Registry hive tree", "status": "partial", "terms": ("registry", "hive", "regf", "hbin", "nk", "vk")},
            {"id": "registry-user-activity", "label": "NTUSER/UsrClass 사용자 활동", "status": "partial", "terms": ("ntuser", "usrclass", "shellbag", "recentdocs", "typedpaths")},
            {"id": "registry-deleted-candidate", "label": "Deleted key/value 후보", "status": "validation-required", "terms": ("deleted", "free cell", "allocator")},
            {"id": "windows-account-sam-security-system", "label": "SAM/SECURITY/SYSTEM 계정/권한", "status": "partial", "terms": ("sam", "security", "system", "controlset", "privilege")},
        ),
    },
    {
        "id": "windows-execution-filesystem",
        "catalog_id": "windows-core",
        "label": "실행 / 파일시스템",
        "capabilities": (
            {"id": "windows-execution-amcache", "label": "Amcache", "status": "partial", "terms": ("amcache", "execution", "install")},
            {"id": "windows-execution-shimcache", "label": "ShimCache/AppCompatCache", "status": "partial", "terms": ("shimcache", "appcompatcache")},
            {"id": "windows-execution-bam-dam", "label": "BAM/DAM", "status": "partial", "terms": ("bam", "dam", "sid", "execution")},
            {"id": "windows-search-edb-row-candidate", "label": "Windows.edb row 후보", "status": "inventory", "terms": ("windows.edb", "edb", "ese", "search index")},
            {"id": "ntfs-mft-usn-path-replay", "label": "MFT/USN 경로 재구성", "status": "partial", "terms": ("mft", "usn", "frn", "rename", "delete")},
        ),
    },
    {
        "id": "browser-internet",
        "catalog_id": "web-ai",
        "label": "인터넷 사용 기록",
        "capabilities": (
            {"id": "browser-history", "label": "브라우저 방문 기록", "status": "usable", "terms": ("browser", "history", "visit", "url")},
            {"id": "browser-downloads", "label": "브라우저 다운로드 기록", "status": "usable", "terms": ("download", "target path", "referrer")},
            {"id": "browser-cache-session-extension-cookie", "label": "Cache/session/extension/cookie", "status": "partial", "terms": ("cache", "session", "extension", "cookie")},
            {"id": "browser-storage-inventory", "label": "LocalStorage/IndexedDB 저장소", "status": "inventory", "terms": ("localstorage", "indexeddb", "storage")},
            {"id": "browser-unified-timeline", "label": "브라우저 통합 타임라인", "status": "partial", "terms": ("chrome", "edge", "firefox", "safari", "timeline")},
        ),
    },
    {
        "id": "ai-service-usage",
        "catalog_id": "web-ai",
        "label": "AI 사용 기록",
        "capabilities": (
            {"id": "browser-ai-usage", "label": "AI 서비스 방문 기록", "status": "usable", "terms": ("chatgpt", "claude", "gemini", "perplexity", "copilot")},
            {"id": "browser-ai-conversation", "label": "AI 질문/답변 후보", "status": "partial", "terms": ("prompt", "answer", "conversation", "transcript")},
            {"id": "browser-ai-export-parser", "label": "AI export parser", "status": "inventory", "terms": ("export", "json", "chatgpt", "claude")},
        ),
    },
    {
        "id": "documents-email-database",
        "catalog_id": "documents-db",
        "label": "문서 / 이메일 / DB",
        "capabilities": (
            {"id": "document-content-search", "label": "PDF/Office/text 본문 검색", "status": "usable", "terms": ("pdf", "office", "docx", "xlsx", "pptx", "txt")},
            {"id": "sqlite-table-viewer", "label": "SQLite table viewer", "status": "usable", "terms": ("sqlite", "database", "table", "row")},
            {"id": "email-eml-mbox", "label": "EML/MBOX 메일", "status": "partial", "terms": ("email", "eml", "mbox", "attachment")},
            {"id": "email-pst-ost-import", "label": "PST/OST mailbox", "status": "external-required", "terms": ("pst", "ost", "libpff", "mailbox")},
        ),
    },
    {
        "id": "messenger-mobile",
        "catalog_id": "communications",
        "label": "메신저 / 모바일",
        "capabilities": (
            {"id": "kakaotalk-windows-app-database", "label": "PC KakaoTalk Windows DB", "status": "partial", "terms": ("kakao", "kakaotalk", "chatlogs", "edb")},
            {"id": "kakaotalk-macos-inventory", "label": "macOS KakaoTalk inventory", "status": "inventory", "terms": ("kakao", "macos", "container", "group container")},
            {"id": "mobile-message", "label": "모바일 메시지/SMS/통화", "status": "partial", "terms": ("mobile", "sms", "call", "contact", "message")},
            {"id": "messenger-whatsapp-telegram-signal-line", "label": "WhatsApp/Telegram/Signal/LINE", "status": "inventory", "terms": ("whatsapp", "telegram", "signal", "line", "discord")},
        ),
    },
    {
        "id": "cloud-exports",
        "catalog_id": "mobile-cloud",
        "label": "클라우드 export",
        "capabilities": (
            {"id": "cloud-google-takeout", "label": "Google Takeout", "status": "partial", "terms": ("takeout", "gmail", "drive", "photos", "location")},
            {"id": "cloud-icloud-export", "label": "iCloud export", "status": "inventory", "terms": ("icloud", "photos", "apple")},
            {"id": "cloud-message", "label": "M365/Teams/OneDrive", "status": "inventory", "terms": ("m365", "teams", "onedrive", "sharepoint")},
        ),
    },
    {
        "id": "media-ocr-review",
        "catalog_id": "media-ocr",
        "label": "미디어 / OCR",
        "capabilities": (
            {"id": "media-image", "label": "이미지 gallery/review", "status": "usable", "terms": ("jpg", "jpeg", "png", "heic", "thumbnail")},
            {"id": "media-video", "label": "영상 preview", "status": "partial", "terms": ("mp4", "mov", "avi", "video")},
            {"id": "media-audio", "label": "음성/Transcript", "status": "inventory", "terms": ("mp3", "wav", "m4a", "audio", "transcript")},
            {"id": "media-ocr-queue", "label": "OCR Queue/번역", "status": "partial", "terms": ("ocr", "korean", "translation")},
        ),
    },
    {
        "id": "dfir-memory-threat",
        "catalog_id": "timeline-ioc",
        "label": "DFIR / 메모리 / 위협",
        "capabilities": (
            {"id": "memory-dump-indicators", "label": "Memory dump indicators", "status": "inventory", "terms": ("memory", "ram", "process", "bitlocker")},
            {"id": "dfir-powershell-lol", "label": "PowerShell/LoL/Fileless", "status": "partial", "terms": ("powershell", "wmi", "wmic", "lol", "fileless")},
            {"id": "dfir-webshell-log", "label": "WebShell/웹서버 로그", "status": "inventory", "terms": ("webshell", "iis", "apache", "nginx", "domain")},
        ),
    },
    {
        "id": "review-report-citation",
        "catalog_id": "review-report",
        "label": "리뷰 / 보고서",
        "capabilities": (
            {"id": "unified-search-source-viewer", "label": "통합 검색 + source viewer", "status": "usable", "terms": ("search", "keyword", "regex", "source")},
            {"id": "review-evidence-tray", "label": "Evidence tray/review status", "status": "usable", "terms": ("relevant", "excluded", "include", "tag", "note")},
            {"id": "report-citation-bundle", "label": "Citation/report bundle", "status": "partial", "terms": ("report", "citation", "hash", "bundle", "exhibit")},
            {"id": "audit-hash-chain", "label": "Audit hash chain", "status": "partial", "terms": ("audit", "hash", "custody", "validation")},
        ),
    },
)


def build_visible_capability_response(
    *,
    run_summary: Mapping[str, Any] | None = None,
    artifacts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the forensic capability model, optionally annotated with run signals."""
    rendered_groups: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    total_signals = 0
    capability_count = 0
    for group in CAPABILITY_GROUPS:
        rendered_capabilities: list[dict[str, Any]] = []
        for capability in group["capabilities"]:
            signal_count = capability_signal_count(capability["terms"], run_summary=run_summary, artifacts=artifacts)
            status = str(capability["status"])
            status_counts[status] += 1
            total_signals += signal_count
            capability_count += 1
            rendered_capabilities.append(
                {
                    "id": capability["id"],
                    "label": capability["label"],
                    "status": status,
                    "status_label": STATUS_LABELS.get(status, status),
                    "terms": list(capability["terms"]),
                    "signal_count": signal_count,
                    "has_signals": signal_count > 0,
                }
            )
        rendered_groups.append(
            {
                "id": group["id"],
                "catalog_id": group["catalog_id"],
                "label": group["label"],
                "capability_count": len(rendered_capabilities),
                "signal_count": sum(int(item["signal_count"]) for item in rendered_capabilities),
                "capabilities": rendered_capabilities,
            }
        )
    return {
        "profile_version": PROFILE_VERSION,
        "status_labels": STATUS_LABELS,
        "summary": {
            "group_count": len(rendered_groups),
            "capability_count": capability_count,
            "signal_count": total_signals,
            "status_counts": dict(status_counts),
            "run_bound": run_summary is not None or artifacts is not None,
        },
        "groups": rendered_groups,
    }


def capability_signal_count(
    terms: Sequence[str],
    *,
    run_summary: Mapping[str, Any] | None = None,
    artifacts: Mapping[str, Any] | None = None,
) -> int:
    lower_terms = tuple(str(term).lower() for term in terms)
    if not lower_terms:
        return 0
    count = 0
    if run_summary:
        count += text_signal_count(run_summary, lower_terms)
    if artifacts:
        for name, payload in artifacts.items():
            if any(term in str(name).lower() for term in lower_terms):
                count += artifact_payload_size(payload)
                continue
            for row in artifact_rows(payload):
                if any(term in compact_text(row).lower() for term in lower_terms):
                    count += 1
    return count


def text_signal_count(payload: Mapping[str, Any], lower_terms: Sequence[str]) -> int:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    count = 0
    for key, value in summary.items():
        text = f"{key} {value}".lower()
        if any(term in text for term in lower_terms):
            count += int(value) if isinstance(value, int) and value > 0 else 1
    for key in ("mode", "root", "source", "scan_scope_root"):
        value = payload.get(key)
        if value and any(term in str(value).lower() for term in lower_terms):
            count += 1
    return count


def artifact_payload_size(payload: Any) -> int:
    if isinstance(payload, Mapping):
        pagination = payload.get("pagination")
        if isinstance(pagination, Mapping) and isinstance(pagination.get("total"), int):
            return max(0, int(pagination["total"]))
        rows = payload.get("artifacts") or payload.get("items") or payload.get("rows")
        if isinstance(rows, Sequence) and not isinstance(rows, (str, bytes, bytearray)):
            return len(rows)
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        return len(payload)
    return 1 if payload else 0


def artifact_rows(payload: Any) -> list[Any]:
    if isinstance(payload, Mapping):
        for key in ("artifacts", "items", "rows", "matches"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return rows
        return [payload]
    if isinstance(payload, list):
        return payload
    return []


def compact_text(value: Any, *, depth: int = 0) -> str:
    if value is None or depth > 2:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:500]
    if isinstance(value, Mapping):
        parts = []
        for key, item in list(value.items())[:20]:
            parts.append(str(key))
            parts.append(compact_text(item, depth=depth + 1))
        return " ".join(parts)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return " ".join(compact_text(item, depth=depth + 1) for item in list(value)[:12])
    return ""
