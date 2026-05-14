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
CATALOG_TABS = {
    "evidence-input": "summary",
    "windows-core": "artifacts",
    "web-ai": "artifacts",
    "communications": "artifacts",
    "documents-db": "docs",
    "media-ocr": "files",
    "timeline-ioc": "timeline",
    "mobile-cloud": "artifacts",
    "review-report": "review",
}
CATALOG_WORKFLOW_STAGES = {
    "evidence-input": "ingest-extract",
    "windows-core": "parse-review",
    "web-ai": "parse-search",
    "communications": "parse-search",
    "documents-db": "parse-search-view",
    "media-ocr": "preview-ocr-review",
    "timeline-ioc": "correlate-detect",
    "mobile-cloud": "import-parse",
    "review-report": "review-report",
}
CATALOG_VIEWERS = {
    "evidence-input": "Evidence intake",
    "windows-core": "Artifact workbench",
    "web-ai": "Web and AI timeline",
    "communications": "Messenger and mail viewer",
    "documents-db": "Document and database viewer",
    "media-ocr": "Media and OCR viewer",
    "timeline-ioc": "Timeline and IOC viewer",
    "mobile-cloud": "Mobile and cloud import viewer",
    "review-report": "Review and report workspace",
}
STATUS_NEXT_ACTIONS = {
    "usable": "Open the mapped tab, filter matching evidence, verify source provenance, then review or report.",
    "partial": "Use as triage evidence only until source viewer, correlation, and validation blockers are checked.",
    "inventory": "Use to locate candidate sources; deeper row parsing or validation is still required.",
    "validation-required": "Do not report as fact until trusted-tool diff, fixture, or known-answer validation is attached.",
    "external-required": "Requires authorized external data, tool output, credential, or lab evidence before full use.",
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
            {"id": "memory-dump-indicators", "label": "Memory dump indicators", "status": "partial", "terms": ("memory", "ram", "process", "bitlocker", "memory-dump-indicators", "web_recovery_profile")},
            {"id": "dfir-powershell-lol", "label": "PowerShell/LoL/Fileless", "status": "partial", "terms": ("powershell", "wmi", "wmic", "lol", "fileless")},
            {"id": "dfir-webshell-log", "label": "WebShell/웹서버 로그", "status": "inventory", "terms": ("webshell", "iis", "apache", "nginx", "domain")},
        ),
    },
    {
        "id": "evidence-recovery-unlock",
        "catalog_id": "evidence-input",
        "label": "복원 / 암호화 해제",
        "capabilities": (
            {"id": "evidence-vss-apfs-snapshot", "label": "VSS/APFS 스냅샷", "status": "inventory", "terms": ("vss", "shadow copy", "apfs snapshot", "snapshot")},
            {"id": "evidence-fde-unlock", "label": "BitLocker/FileVault/LUKS unlock", "status": "external-required", "terms": ("bitlocker", "filevault", "luks", "fde", "unlock")},
            {"id": "evidence-unallocated-carving", "label": "비할당 영역 카빙", "status": "inventory", "terms": ("unallocated", "carving", "deleted file", "sqlite carving")},
        ),
    },
    {
        "id": "filesystem-antiforensics",
        "catalog_id": "windows-core",
        "label": "파일시스템 / 안티포렌식",
        "capabilities": (
            {"id": "ntfs-logfile-transactions", "label": "$LogFile transaction", "status": "partial", "terms": ("$logfile", "transaction", "ntfs log", "redo", "undo", "ntfs-logfile-transaction-candidate")},
            {"id": "recycle-bin-ir-map", "label": "Recycle Bin $I/$R 매핑", "status": "partial", "terms": ("recycle bin", "recycle-bin-entry", "$i", "$r", "deleted time", "original path")},
            {"id": "timestamp-stomping-detection", "label": "Time stomping 탐지", "status": "partial", "terms": ("timestamp", "stomping", "$sia", "$fna", "time mismatch", "timestamp_stomping_analysis", "mft-sia-fna-timestamp-mismatch")},
            {"id": "signature-mismatch-detection", "label": "확장자 변조 탐지", "status": "partial", "terms": ("signature mismatch", "file-signature-mismatch", "magic", "extension mismatch", "file header", "file_signature_profile")},
        ),
    },
    {
        "id": "windows-eventlog-dfir",
        "catalog_id": "windows-core",
        "label": "이벤트 로그 DFIR",
        "capabilities": (
            {"id": "etl-trace-parser", "label": "ETW/ETL trace", "status": "partial", "terms": ("etl", "etw", "trace", "wmi trace", "usb trace", "etl-trace-file")},
            {"id": "eventlog-clearing-alert", "label": "로그 삭제 High-Risk", "status": "partial", "terms": ("event id 1102", "event id 104", "log clear", "audit log cleared")},
            {"id": "logon-session-timeline", "label": "로그온 세션 통합 뷰", "status": "partial", "terms": ("4624", "4634", "4647", "logon session", "logoff", "eventlog-logon-session")},
        ),
    },
    {
        "id": "usb-persistence-network",
        "catalog_id": "windows-core",
        "label": "USB / 지속성 / 네트워크",
        "capabilities": (
            {"id": "usb-external-device-history", "label": "USB 및 외장매체 연결 이력", "status": "partial", "terms": ("usbstor", "mounteddevices", "setupapi.dev.log", "usb serial", "drive letter", "usb-setupapi-device-install-candidate")},
            {"id": "autoruns-persistence-view", "label": "Persistence/Autoruns 통합 뷰", "status": "partial", "terms": ("autoruns", "run key", "service", "scheduled task", "wmi consumer")},
            {"id": "wifi-network-profile-history", "label": "Wi-Fi/네트워크 프로필", "status": "partial", "terms": ("wifi", "ssid", "wlan", "network profile", "connection", "wifi-profile")},
        ),
    },
    {
        "id": "execution-user-activity",
        "catalog_id": "windows-core",
        "label": "사용자 실행 / 활동",
        "capabilities": (
            {"id": "lnk-jumplist-analysis", "label": "LNK 및 JumpList", "status": "partial", "terms": ("lnk", "jumplist", "destlist", "automaticdestinations", "customdestinations")},
            {"id": "windows-timeline-activities", "label": "Windows Timeline ActivitiesCache", "status": "partial", "terms": ("activitiescache.db", "activities-cache-db", "windows timeline", "activity", "app activity")},
            {"id": "bits-qmgr-transfer", "label": "BITS qmgr.dat 전송", "status": "partial", "terms": ("bits", "qmgr", "bits-qmgr-transfer-candidate", "background transfer", "download", "exfil")},
            {"id": "recentdocs-clipboard-muicache", "label": "RecentDocs/Clipboard/MUICache", "status": "partial", "terms": ("recentfilecache", "recentdocs", "clipboard", "muicache", "registry-user-activity", "clipboard-history")},
        ),
    },
    {
        "id": "browser-deep-recovery",
        "catalog_id": "web-ai",
        "label": "브라우저 심화 복원",
        "capabilities": (
            {"id": "incognito-memory-pagefile-carving", "label": "시크릿 모드 URL 카빙", "status": "partial", "terms": ("incognito", "inprivate", "pagefile", "hiberfil", "url carving", "private-browsing-url-candidate", "search-query-url-candidate")},
            {"id": "webcachev01-ese-parser", "label": "WebCacheV01.dat", "status": "partial", "terms": ("webcachev01.dat", "webcachev01-ese-file", "webcachev01_review_profile", "ese_page_map", "url candidate", "domain candidate", "ese", "webcache", "wininet", "webview")},
            {"id": "desktop-cloud-sync-db", "label": "OneDrive/Google Drive sync DB", "status": "partial", "terms": ("onedrive", "sync_engine.db", "desktop-cloud-sync-db", "desktop-cloud-sync-row-candidate", "cloud_sync_row_review_profile", "google drive", "drivefs", "sync")},
        ),
    },
    {
        "id": "ai-local-desktop-recall",
        "catalog_id": "web-ai",
        "label": "로컬/데스크톱 AI",
        "capabilities": (
            {"id": "local-llm-ollama-lmstudio-gpt4all", "label": "Ollama/LM Studio/GPT4All", "status": "partial", "terms": ("ollama", "lm studio", "gpt4all", "local llm", "model", "local-llm-artifact", "local-llm-prompt-candidate", "local_llm_review_profile")},
            {"id": "ai-desktop-app-db", "label": "ChatGPT/Copilot 데스크톱 앱 DB", "status": "partial", "terms": ("chatgpt desktop", "copilot", "desktop app", "sqlite", "desktop-ai-app-artifact", "desktop-ai-conversation-candidate", "desktop_ai_conversation_review_profile")},
            {"id": "windows-copilot-recall", "label": "Windows Copilot Recall", "status": "partial", "terms": ("recall", "copilot recall", "screenray", "windows 11 24h2", "ukg.db", "coreaiplatform", "windows-recall-database", "windows-recall-snapshot-file")},
        ),
    },
    {
        "id": "docs-leakage-artifacts",
        "catalog_id": "documents-db",
        "label": "문서 유출 보조 아티팩트",
        "capabilities": (
            {"id": "print-spooler-spl-shd", "label": "Print Spooler SPL/SHD", "status": "partial", "terms": ("print spooler", "print-spooler-job", "print_spooler_job_profile", ".spl", ".shd", "printed", "printer")},
            {"id": "document-metadata-macro-risk", "label": "문서 메타데이터/매크로 위험", "status": "partial", "terms": ("metadata", "vba", "macro", "ole", "ooxml", "author", "document-metadata-risk", "metadata_profile", "macro_profile", "external_reference_candidates")},
            {"id": "sticky-notes-plum", "label": "Sticky Notes plum.sqlite", "status": "partial", "terms": ("sticky notes", "plum.sqlite", "stickynotes", "note", "sticky-note", "sticky-note-recovery-candidate", "sticky_note_schema_profile", "sticky_note_review_profile")},
        ),
    },
    {
        "id": "mobile-location-behavior",
        "catalog_id": "communications",
        "label": "모바일 위치 / 생활 패턴",
        "capabilities": (
            {"id": "geo-location-map-viewer", "label": "위치 정보/동선 지도", "status": "partial", "terms": ("gps", "latitude", "longitude", "cell tower", "wifi location", "map", "mobile-location", "map_review_profile")},
            {"id": "health-fitness-activity", "label": "Health/Fitness 활동", "status": "partial", "terms": ("health", "fitness", "steps", "heart rate", "sleep", "mobile-health", "health_review_profile")},
            {"id": "screen-time-digital-wellbeing", "label": "Screen Time/Digital Wellbeing", "status": "partial", "terms": ("screen time", "digital wellbeing", "app usage", "screen on", "mobile-screen-time", "screen_time_review_profile")},
        ),
    },
    {
        "id": "cloud-iaas-audit",
        "catalog_id": "mobile-cloud",
        "label": "IaaS 보안 로그",
        "capabilities": (
            {"id": "aws-cloudtrail-parser", "label": "AWS CloudTrail", "status": "partial", "terms": ("cloudtrail", "aws", "iam", "s3", "ec2", "cloud-iaas-audit")},
            {"id": "azure-activity-log-parser", "label": "Azure Activity Log", "status": "partial", "terms": ("azure activity", "entra", "azuread", "microsoft graph", "cloud-iaas-audit")},
            {"id": "gcp-audit-log-parser", "label": "GCP Audit Logs", "status": "partial", "terms": ("gcp", "google cloud", "audit log", "iam", "cloud-iaas-audit")},
        ),
    },
    {
        "id": "media-advanced-forensics",
        "catalog_id": "media-ocr",
        "label": "미디어 심화 포렌식",
        "capabilities": (
            {"id": "exif-gps-map", "label": "사진 EXIF GPS 지도", "status": "partial", "terms": ("exif", "gps", "geotag", "map", "photo location")},
            {"id": "steganography-suspicion-scan", "label": "Steganography 의심 스캔", "status": "inventory", "terms": ("steganography", "hidden data", "lsb", "entropy")},
            {"id": "deepfake-manipulation-scan", "label": "Deepfake/조작 의심", "status": "inventory", "terms": ("deepfake", "ai generated", "manipulated", "media authenticity")},
        ),
    },
    {
        "id": "memory-disk-artifacts",
        "catalog_id": "timeline-ioc",
        "label": "디스크 내 메모리 파일",
        "capabilities": (
            {"id": "hiberfil-pagefile-carving", "label": "hiberfil/pagefile 통합 카빙", "status": "partial", "terms": ("hiberfil.sys", "pagefile.sys", "swapfile.sys", "memory carving", "disk-memory-file-indicators")},
            {"id": "crash-dump-minidump-analysis", "label": "MEMORY.DMP/Minidump", "status": "partial", "terms": ("memory.dmp", "minidump", "crash dump", ".dmp", "crash-dump-indicators")},
        ),
    },
    {
        "id": "incident-remote-tampering",
        "catalog_id": "timeline-ioc",
        "label": "원격접속 / Tampering",
        "capabilities": (
            {"id": "remote-control-anydesk-teamviewer-rustdesk", "label": "AnyDesk/TeamViewer/RustDesk", "status": "partial", "terms": ("anydesk", "teamviewer", "rustdesk", "chrome remote desktop", "remote control", "third-party-remote-control-artifact", "remote_control_session_profile")},
            {"id": "defender-edr-tampering", "label": "Defender/EDR 무력화", "status": "partial", "terms": ("defender", "tamper", "exclusion", "edr", "service stopped")},
        ),
    },
    {
        "id": "review-search-advanced",
        "catalog_id": "review-report",
        "label": "검색 / 타임라인 고급",
        "capabilities": (
            {"id": "super-timeline-plaso-style", "label": "Super Timeline", "status": "partial", "terms": ("super timeline", "plaso", "log2timeline", "timeline correlation")},
            {"id": "denisting-nsrl-whitelist", "label": "De-NISTing/Whitelisting", "status": "partial", "terms": ("nsrl", "denist", "whitelist", "known file", "known_good_suppression_profile")},
            {"id": "yara-ioc-scanner", "label": "YARA / IOC 스캐너", "status": "partial", "terms": ("yara", "ioc", "hash list", "malware scan", "ioc_scanner_hits", "local-rule-ioc-hit")},
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
            rendered = render_capability(group, capability)
            status = str(rendered["status"])
            status_counts[status] += 1
            total_signals += signal_count
            capability_count += 1
            rendered["signal_count"] = signal_count
            rendered["has_signals"] = signal_count > 0
            rendered_capabilities.append(rendered)
        rendered_groups.append(
            {
                "id": group["id"],
                "catalog_id": group["catalog_id"],
                "tab": CATALOG_TABS.get(str(group["catalog_id"]), "artifacts"),
                "workflow_stage": CATALOG_WORKFLOW_STAGES.get(str(group["catalog_id"]), "parse-review"),
                "label": group["label"],
                "capability_count": len(rendered_capabilities),
                "signal_count": sum(int(item["signal_count"]) for item in rendered_capabilities),
                "capabilities": rendered_capabilities,
            }
        )
    contract_issues = validate_visible_capability_contract()
    return {
        "profile_version": PROFILE_VERSION,
        "status_labels": STATUS_LABELS,
        "summary": {
            "group_count": len(rendered_groups),
            "capability_count": capability_count,
            "signal_count": total_signals,
            "status_counts": dict(status_counts),
            "run_bound": run_summary is not None or artifacts is not None,
            "gui_contract_pass": not contract_issues,
            "gui_contract_issue_count": len(contract_issues),
        },
        "gui_contract": {
            "profile_version": "visible-capability-gui-contract-v1",
            "required_fields": [
                "id",
                "label",
                "status",
                "terms",
                "tab",
                "viewer",
                "artifact_types",
                "workflow_stage",
                "next_action",
                "gui_surfaces",
            ],
            "issue_count": len(contract_issues),
            "issues": contract_issues,
        },
        "groups": rendered_groups,
    }


def render_capability(group: Mapping[str, Any], capability: Mapping[str, Any]) -> dict[str, Any]:
    catalog_id = str(group.get("catalog_id") or "")
    status = str(capability.get("status") or "partial")
    terms = tuple(str(term) for term in capability.get("terms") or ())
    tab = str(capability.get("tab") or CATALOG_TABS.get(catalog_id, "artifacts"))
    viewer = str(capability.get("viewer") or CATALOG_VIEWERS.get(catalog_id, "Artifact workbench"))
    workflow_stage = str(
        capability.get("workflow_stage") or CATALOG_WORKFLOW_STAGES.get(catalog_id, "parse-review")
    )
    artifact_types = tuple(
        str(item)
        for item in (
            capability.get("artifact_types")
            or capability.get("artifactTypes")
            or infer_artifact_types(str(capability.get("id") or ""), terms)
        )
        if str(item)
    )
    gui_surfaces = tuple(
        str(item)
        for item in (
            capability.get("gui_surfaces")
            or capability.get("guiSurfaces")
            or ("feature-catalog", "capability-chip", tab, viewer)
        )
        if str(item)
    )
    next_action = str(
        capability.get("next_action")
        or capability.get("nextAction")
        or STATUS_NEXT_ACTIONS.get(status, "Review source evidence before reporting.")
    )
    return {
        "id": str(capability.get("id") or ""),
        "label": str(capability.get("label") or ""),
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "terms": list(terms),
        "tab": tab,
        "viewer": viewer,
        "artifact_types": list(artifact_types),
        "workflow_stage": workflow_stage,
        "next_action": next_action,
        "gui_surfaces": list(gui_surfaces),
        "gui_contract": {
            "exposed": True,
            "primary_tab": tab,
            "primary_viewer": viewer,
            "required_surfaces": list(gui_surfaces),
        },
    }


def infer_artifact_types(capability_id: str, terms: Sequence[str]) -> tuple[str, ...]:
    normalized_terms = tuple(term.replace(" ", "-").lower() for term in terms if term)
    candidates = [capability_id]
    candidates.extend(term for term in normalized_terms[:3] if term not in candidates)
    return tuple(item for item in candidates if item)


def validate_visible_capability_contract(
    groups: Sequence[Mapping[str, Any]] = CAPABILITY_GROUPS,
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    required = (
        "id",
        "label",
        "status",
        "terms",
        "tab",
        "viewer",
        "artifact_types",
        "workflow_stage",
        "next_action",
        "gui_surfaces",
    )
    for group in groups:
        group_id = str(group.get("id") or "")
        catalog_id = str(group.get("catalog_id") or "")
        if not group_id:
            issues.append({"scope": "group", "id": "<missing>", "field": "id", "reason": "group id is required"})
        if catalog_id not in CATALOG_TABS:
            issues.append({"scope": "group", "id": group_id, "field": "catalog_id", "reason": "catalog must map to a GUI tab"})
        for capability in group.get("capabilities") or ():
            rendered = render_capability(group, capability)
            capability_id = str(rendered["id"])
            if capability_id in seen_ids:
                issues.append(
                    {"scope": "capability", "id": capability_id, "field": "id", "reason": "duplicate capability id"}
                )
            seen_ids.add(capability_id)
            if rendered["status"] not in STATUS_LABELS:
                issues.append({"scope": "capability", "id": capability_id, "field": "status", "reason": "unknown status"})
            for field in required:
                value = rendered.get(field)
                if value is None or value == "" or value == []:
                    issues.append(
                        {
                            "scope": "capability",
                            "id": capability_id or "<missing>",
                            "field": field,
                            "reason": "required GUI contract field is empty",
                        }
                    )
    return issues


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
