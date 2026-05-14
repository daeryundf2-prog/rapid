from __future__ import annotations

import datetime as dt
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping

from ..artifacts import artifact_collectors

TAXONOMY_VERSION = "forensic-artifact-taxonomy-v1"
KNOWN_DYNAMIC_ARTIFACT_TYPES = {
    "activities-cache-db",
    "browser-cache-inventory",
    "browser-cookie-store-inventory",
    "browser-credential-store-inventory",
    "browser-extension-inventory",
    "browser-session-storage-inventory",
    "browser-sync-inventory",
    "icon-cache-file",
    "jumplist-automatic",
    "jumplist-custom",
    "media-audio",
    "media-video",
    "memory-artifact",
    "memory-cmdline",
    "memory-dump-indicators",
    "crash-dump-indicators",
    "disk-memory-file-indicators",
    "memory-malfind",
    "memory-network",
    "memory-process",
    "notification-database",
    "thumbnail-cache-file",
    "uwp-package",
}


@dataclass(frozen=True)
class TaxonomyTarget:
    id: str
    category: str
    title: str
    expectation: str
    required_collectors: tuple[str, ...] = ()
    expected_artifact_types: tuple[str, ...] = ()
    required_viewer_markers: tuple[str, ...] = ()
    required_test_markers: tuple[str, ...] = ()
    required_doc_markers: tuple[str, ...] = ()
    external_blockers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


TAXONOMY_TARGETS: tuple[TaxonomyTarget, ...] = (
    TaxonomyTarget(
        id="e01-partition-workflow",
        category="image-workflow",
        title="E01/Ex01 partition selection workflow",
        expectation="GUI and CLI expose preflight, dependency, partition selection, extraction, and provenance evidence.",
        required_doc_markers=("E01", "partition"),
        required_test_markers=("e01",),
    ),
    TaxonomyTarget(
        id="vsc-direct-workflow",
        category="image-workflow",
        title="Volume Shadow Copy direct discovery and extraction",
        expectation="Discover, mount, compare, and extract VSC snapshots from an image workflow, not only already-mounted folders.",
        required_doc_markers=("Volume Shadow", "VSC"),
        required_test_markers=("vsc",),
    ),
    TaxonomyTarget(
        id="filesystem-inventory",
        category="windows-core",
        title="Windows file-system inventory",
        expectation="Extract file rows with metadata, source path, hashes, deleted/recovery hints, and report citations.",
        required_collectors=("windows-filesystem",),
        expected_artifact_types=("mft-file", "mft-record"),
        required_test_markers=("windows-filesystem", "mft"),
    ),
    TaxonomyTarget(
        id="mft-deep-parser",
        category="windows-core",
        title="$MFT deep parser",
        expectation="Decode record headers, attributes, runlists, parent path reconstruction, deleted state, and trusted diff evidence.",
        required_collectors=("windows-filesystem",),
        expected_artifact_types=("mft-file", "mft-record"),
        required_test_markers=("mft",),
        required_doc_markers=("MFT",),
    ),
    TaxonomyTarget(
        id="usn-journal-replay",
        category="windows-core",
        title="$UsnJrnl replay",
        expectation="Decode USN v2/v3/v4 records, replay rename/delete events, maintain FRN path cache, and support large journals.",
        required_collectors=("windows-filesystem",),
        expected_artifact_types=("usn-journal-file", "usn-record"),
        required_test_markers=("usn",),
        required_doc_markers=("USN",),
    ),
    TaxonomyTarget(
        id="evtx-native-binxml",
        category="windows-core",
        title="EVTX native BinXML parser",
        expectation="Native EVTX parsing covers file/chunk/record/BinXML structures, message rendering, recovery, and trusted diffs.",
        required_collectors=("eventlog",),
        expected_artifact_types=("eventlog-file", "eventlog-event", "eventlog-detection", "eventlog-summary"),
        required_viewer_markers=("eventlog",),
        required_test_markers=("eventlog", "evtx"),
        required_doc_markers=("EVTX",),
    ),
    TaxonomyTarget(
        id="registry-transaction-replay",
        category="windows-core",
        title="Registry transaction replay and key tree",
        expectation="Reconstruct hives with LOG1/LOG2 replay, full key tree, user activity pivots, and source offsets.",
        required_collectors=("windows-registry",),
        expected_artifact_types=("registry-hive", "registry-key", "registry-key-tree-node", "registry-user-activity"),
        required_viewer_markers=("registry"),
        required_test_markers=("registry",),
        required_doc_markers=("Registry",),
    ),
    TaxonomyTarget(
        id="registry-deleted-recovery",
        category="windows-core",
        title="Registry deleted key/value recovery",
        expectation="Recover and score deleted keys/values with allocator false-positive controls and report limitations.",
        required_collectors=("windows-registry",),
        expected_artifact_types=("registry-key-recovery-candidate", "registry-value-recovery-candidate"),
        required_test_markers=("deleted", "registry"),
        required_doc_markers=("deleted key"),
    ),
    TaxonomyTarget(
        id="sam-security-system",
        category="windows-core",
        title="SAM/SECURITY/SYSTEM account and privilege parser",
        expectation="Parse users, groups, aliases, LSA policy, privileges, mounted devices, services, and control sets.",
        required_collectors=("windows-os-account", "windows-registry"),
        expected_artifact_types=(
            "windows-sam-account-candidate",
            "windows-sam-group-candidate",
            "windows-privilege-assignment",
            "windows-lsa-policy-location",
        ),
        required_test_markers=("sam", "windows-os-account"),
    ),
    TaxonomyTarget(
        id="execution-artifacts",
        category="windows-core",
        title="Windows execution artifacts",
        expectation="Parse Amcache, ShimCache, BAM/DAM, UserAssist, Tasks, WMI, WER, Defender, Firewall, and service evidence.",
        required_collectors=("windows-execution",),
        expected_artifact_types=(
            "amcache-entry",
            "shimcache-entry",
            "bam-entry",
            "userassist-entry",
            "task-scheduler-task",
            "wmi-repository-file",
            "wer-report",
            "defender-support-log",
            "firewall-log",
        ),
        required_test_markers=("windows-execution", "amcache", "shimcache"),
    ),
    TaxonomyTarget(
        id="prefetch-parser",
        category="windows-core",
        title="Prefetch parser",
        expectation="Decode Prefetch versions and compressed PF metadata with execution metrics and referenced files.",
        required_collectors=("windows-prefetch",),
        expected_artifact_types=("prefetch-file", "prefetch-reference"),
        required_test_markers=("prefetch",),
    ),
    TaxonomyTarget(
        id="shellbags-parser",
        category="windows-core",
        title="ShellBags parser",
        expectation="Decode NTUSER/UsrClass ShellBags, BagMRU/Bags relationships, timestamps, deleted/slack evidence, and source cells.",
        required_collectors=("windows-shellbags",),
        expected_artifact_types=("shellbag-key", "shellbag-native-candidate"),
        required_test_markers=("shellbags",),
    ),
    TaxonomyTarget(
        id="lnk-jumplist-parser",
        category="windows-core",
        title="LNK and JumpList parser",
        expectation="Decode ShellLink and DestList structures, targets, tracker GUIDs, AppID, deleted entries, and MRU state.",
        required_collectors=("recent-files",),
        expected_artifact_types=("recent-shortcut", "jumplist-automatic", "jumplist-custom"),
        required_test_markers=("recent-files", "jumplist"),
    ),
    TaxonomyTarget(
        id="usb-timeline",
        category="windows-core",
        title="USB and removable device timeline",
        expectation="Correlate registry USB traces, mounted devices, users, volume GUIDs, and file activity into a timeline.",
        required_collectors=("windows-registry", "windows-system"),
        expected_artifact_types=("registry-usb", "windows-mounted-device"),
        required_doc_markers=("USB",),
    ),
    TaxonomyTarget(
        id="recycle-bin-parser",
        category="windows-core",
        title="Recycle Bin parser",
        expectation="Parse $I/$R entries with original path, deletion time, SID/user mapping, hashes, and source citations.",
        required_test_markers=("recycle",),
        required_doc_markers=("Recycle",),
    ),
    TaxonomyTarget(
        id="thumbnail-icon-cache",
        category="windows-core",
        title="Thumbnail and icon cache parser",
        expectation="Parse Windows thumbnail/icon cache entries, image hashes, source locators, and review thumbnails.",
        required_collectors=("windows-system",),
        expected_artifact_types=("thumbnail-cache-file", "icon-cache-file"),
        required_test_markers=("thumbnail", "icon-cache"),
        required_doc_markers=("thumbnail",),
    ),
    TaxonomyTarget(
        id="activities-notifications-uwp",
        category="windows-core",
        title="Activities, notifications, clipboard, and UWP artifacts",
        expectation="Parse ActivitiesCache, notifications, clipboard-like residues, ConnectedDevicesPlatform, and UWP app traces.",
        required_collectors=("windows-system",),
        expected_artifact_types=("activities-cache-db", "notification-database", "uwp-package"),
        required_test_markers=("activities", "uwp"),
        required_doc_markers=("ActivitiesCache", "UWP"),
    ),
    TaxonomyTarget(
        id="browser-history-downloads",
        category="web-ai",
        title="Browser history and downloads",
        expectation="Parse Chrome/Edge/Firefox/Safari history/downloads with unified timestamp semantics and source citations.",
        required_collectors=("browser",),
        expected_artifact_types=("browser-history", "browser-history-downloads"),
        required_viewer_markers=("browser",),
        required_test_markers=("browser",),
    ),
    TaxonomyTarget(
        id="browser-cache-session-extension",
        category="web-ai",
        title="Browser cache, session, extension, sync, cookie, and credential stores",
        expectation="Inventory and legally gate sensitive browser stores, with deep decoders where safe and validated.",
        required_collectors=("browser",),
        expected_artifact_types=(
            "browser-cache-inventory",
            "browser-session-storage-inventory",
            "browser-extension-inventory",
            "browser-cookie-store-inventory",
            "browser-credential-store-inventory",
        ),
        required_test_markers=("browser", "cookie", "session"),
    ),
    TaxonomyTarget(
        id="ai-service-transcripts",
        category="web-ai",
        title="AI service transcript parser",
        expectation="Parse ChatGPT, Claude, Gemini, Perplexity, Copilot, and other AI Q/A from exports and browser stores.",
        required_collectors=("browser", "macos-system"),
        expected_artifact_types=("macos-browser-ai-usage", "macos-browser-ai-conversation"),
        required_test_markers=("ai", "browser"),
        required_doc_markers=("AI", "ChatGPT"),
    ),
    TaxonomyTarget(
        id="email-pst-ost-mbox-msg",
        category="mail-cloud-chat",
        title="Email parser",
        expectation="Parse PST/OST/MBOX/MSG/EML with folders, threads, deleted items, attachments, and header graph.",
        required_collectors=("email",),
        expected_artifact_types=("email-mailbox", "email-message"),
        required_viewer_markers=("email",),
        required_test_markers=("email",),
        required_doc_markers=("PST", "OST", "email"),
    ),
    TaxonomyTarget(
        id="cloud-export-google",
        category="mail-cloud-chat",
        title="Google Takeout and Google cloud export parser",
        expectation="Parse Gmail, Drive, Photos, Activity, Location, and account/device context from Takeout exports.",
        required_collectors=("cloud-export",),
        expected_artifact_types=("cloud-account", "cloud-file", "cloud-activity", "cloud-location", "cloud-mail"),
        required_test_markers=("cloud", "google"),
    ),
    TaxonomyTarget(
        id="cloud-export-icloud",
        category="mail-cloud-chat",
        title="iCloud export parser",
        expectation="Parse iCloud Photos, albums, shares, devices, account metadata, and EXIF context.",
        required_collectors=("cloud-export",),
        expected_artifact_types=("cloud-account", "cloud-file"),
        required_test_markers=("cloud", "icloud"),
    ),
    TaxonomyTarget(
        id="cloud-export-m365-teams",
        category="mail-cloud-chat",
        title="Microsoft 365, OneDrive, Teams, SharePoint export parser",
        expectation="Parse Graph/eDiscovery exports, Teams messages/reactions/attachments, OneDrive files, and SharePoint permissions.",
        required_collectors=("cloud-export",),
        expected_artifact_types=("cloud-account", "cloud-message", "cloud-file", "cloud-audit"),
        required_test_markers=("cloud", "teams"),
    ),
    TaxonomyTarget(
        id="cloud-api-acquisition",
        category="mail-cloud-chat",
        title="Cloud API acquisition",
        expectation="Collect authorized cloud API data with OAuth/device flow, pagination, backoff, redaction, and audit.",
        required_doc_markers=("cloud API", "OAuth"),
        required_test_markers=("cloud-collect",),
        external_blockers=("authorized-provider-credentials-required",),
    ),
    TaxonomyTarget(
        id="kakaotalk-windows",
        category="mail-cloud-chat",
        title="PC KakaoTalk parser",
        expectation="Analyze legacy and post-patch PC KakaoTalk data, rooms, messages, media, key-store metadata, and memory-assisted residues.",
        required_collectors=("kakaotalk-windows",),
        expected_artifact_types=(
            "kakaotalk-windows-app-database",
            "kakaotalk-windows-user-id-candidate",
            "kakaotalk-windows-crypto-material-candidate",
        ),
        required_test_markers=("kakaotalk",),
        required_doc_markers=("KakaoTalk",),
    ),
    TaxonomyTarget(
        id="mobile-ios-backup",
        category="mobile",
        title="iOS backup parser",
        expectation="Parse Manifest.db, domains, media, SMS, app DBs, keychain inventory, and encrypted-backup legal workflow.",
        required_collectors=("mobile-export",),
        expected_artifact_types=("ios-backup-source", "ios-backup-metadata", "ios-backup-file", "ios-keychain-inventory"),
        required_test_markers=("ios", "mobile"),
    ),
    TaxonomyTarget(
        id="mobile-android-artifacts",
        category="mobile",
        title="Android artifact parser",
        expectation="Parse Android SMS, call log, contacts, browser, media, app DBs, packages, signatures, and permissions.",
        required_collectors=("mobile-export", "android-apk"),
        expected_artifact_types=("android-apk", "android-app-data", "mobile-message", "mobile-chat-database"),
        required_test_markers=("android", "mobile"),
    ),
    TaxonomyTarget(
        id="messenger-matrix",
        category="mobile",
        title="Messenger schema matrix",
        expectation="Support KakaoTalk, WhatsApp, Telegram, Signal, LINE, WeChat, Discord, Instagram, and export/native schema versions.",
        required_collectors=("mobile-export", "kakaotalk-windows", "cloud-export"),
        expected_artifact_types=("mobile-message", "mobile-chat-database", "cloud-message"),
        required_test_markers=("mobile", "chat"),
        required_doc_markers=("WhatsApp", "Telegram", "Signal", "LINE", "Discord"),
    ),
    TaxonomyTarget(
        id="mobile-correlation-view",
        category="mobile",
        title="Mobile unified contact/call/SMS/message view",
        expectation="Correlate contacts, calls, SMS, messages, media, and file-system artifacts with entity resolution.",
        required_collectors=("mobile-export",),
        expected_artifact_types=("mobile-correlation-summary", "mobile-message"),
        required_viewer_markers=("mobile",),
    ),
    TaxonomyTarget(
        id="media-image-gallery",
        category="media-ocr-docdb",
        title="Image gallery and metadata review",
        expectation="Review images with EXIF, metadata, thumbnails, tagging, hash/citation, and gallery navigation.",
        required_collectors=("media-image",),
        expected_artifact_types=("media-image", "media-image-unreadable"),
        required_viewer_markers=("image",),
        required_test_markers=("media",),
    ),
    TaxonomyTarget(
        id="media-video-audio-transcript",
        category="media-ocr-docdb",
        title="Video/audio preview and transcript",
        expectation="Preview video/audio safely with thumbnails, waveform, transcript cues, hashes, and report citations.",
        required_collectors=("media-image",),
        expected_artifact_types=("media-video", "media-audio"),
        required_test_markers=("media", "transcript"),
        required_doc_markers=("video", "audio", "transcript"),
    ),
    TaxonomyTarget(
        id="ocr-native-pipeline",
        category="media-ocr-docdb",
        title="OCR pipeline",
        expectation="Run OCR queue, retry, Korean OCR calibration, translation sidecar, confidence, and searchable results.",
        required_test_markers=("ocr",),
        required_doc_markers=("OCR",),
        required_viewer_markers=("ocr",),
    ),
    TaxonomyTarget(
        id="document-db-sqlite-viewer",
        category="media-ocr-docdb",
        title="Document and database viewer",
        expectation="Search and review Office/PDF/text/SQLite/DB files with table paging, deleted rows, and citations.",
        expected_artifact_types=("document-pattern",),
        required_viewer_markers=("sqlite", "document"),
        required_test_markers=("docs",),
    ),
    TaxonomyTarget(
        id="archive-encrypted-workflow",
        category="media-ocr-docdb",
        title="Archive and encrypted-file workflow",
        expectation="Detect archives/encrypted files, safely recurse, manage password candidates, and sandbox previews.",
        required_test_markers=("archive", "extract"),
        required_doc_markers=("archive", "encrypted"),
    ),
    TaxonomyTarget(
        id="bounded-carving",
        category="media-ocr-docdb",
        title="File carving",
        expectation="Carve bounded signature candidates with offsets, hashes, recovery caveats, and large-case queue controls.",
        required_test_markers=("carving",),
        required_doc_markers=("carving",),
    ),
    TaxonomyTarget(
        id="memory-volatility",
        category="dfir-threat-memory",
        title="Memory analysis",
        expectation="Inventory memory dumps and parse process/network/module/handle/credential-yielding artifacts where authorized.",
        required_collectors=("memory-volatility",),
        expected_artifact_types=("memory-dump-indicators",),
        required_test_markers=("memory",),
    ),
    TaxonomyTarget(
        id="lotl-fileless",
        category="dfir-threat-memory",
        title="LotL and fileless activity",
        expectation="Correlate PowerShell, WMI, WMIC, scheduled tasks, registry, event logs, services, and script evidence.",
        required_collectors=("windows-execution", "eventlog", "windows-registry"),
        expected_artifact_types=("powershell-history-command", "wmi-repository-file", "task-scheduler-task"),
        required_test_markers=("powershell", "wmi"),
    ),
    TaxonomyTarget(
        id="webshell-server-logs",
        category="dfir-threat-memory",
        title="WebShell and server log analysis",
        expectation="Parse web roots, IIS/Apache/Nginx logs, suspicious source files, webshell rule hits, and source viewers.",
        required_collectors=("windows-system",),
        expected_artifact_types=("webshell-source-candidate", "web-server-log"),
        required_test_markers=("webshell", "server-log"),
        required_doc_markers=("webshell", "IIS", "Apache", "Nginx"),
    ),
    TaxonomyTarget(
        id="ioc-ti-enrichment",
        category="dfir-threat-memory",
        title="IOC and threat-intelligence enrichment",
        expectation="Extract indicators and enrich with local signed feeds, STIX/TAXII, confidence decay, and no-network policy.",
        required_test_markers=("indicators", "rule"),
        required_doc_markers=("STIX", "TAXII", "IOC"),
    ),
    TaxonomyTarget(
        id="external-tool-import-diff",
        category="validation",
        title="External tool import and trusted diff",
        expectation="Import and compare EvtxECmd, Hayabusa, RECmd, MFTECmd, JLECmd, PECmd, ShellBagsExplorer, and SRUM/ESE outputs.",
        required_test_markers=("cross-tool",),
        required_doc_markers=("EvtxECmd", "Hayabusa", "RECmd", "MFTECmd"),
        external_blockers=("trusted-external-tool-exports-required",),
    ),
    TaxonomyTarget(
        id="source-viewers",
        category="ux-review-report",
        title="Source viewers",
        expectation="Provide source-backed EVTX, registry, hex, SQLite, email, image/video, OCR, timeline, and text viewers.",
        required_viewer_markers=("source", "hex", "sqlite", "email", "image", "timeline"),
        required_test_markers=("source-read",),
    ),
    TaxonomyTarget(
        id="unified-search",
        category="ux-review-report",
        title="Unified search",
        expectation="Search files, docs, browser, AI, EVTX, registry, OCR, email, messenger, cloud, and timeline with source verification.",
        required_test_markers=("search",),
        required_doc_markers=("search",),
        required_viewer_markers=("search",),
    ),
    TaxonomyTarget(
        id="review-workflow",
        category="ux-review-report",
        title="Review workflow",
        expectation="Support relevant, needs-review, excluded, include-in-report, tags, notes, evidence tray, compare, shortcuts, and history.",
        required_test_markers=("case-review", "case_db"),
        required_viewer_markers=("review", "evidence"),
    ),
    TaxonomyTarget(
        id="timeline-correlation",
        category="ux-review-report",
        title="Unified timeline correlation",
        expectation="Merge all artifacts into a cursor-friendly timeline with timezone, skew, and citation overlays.",
        required_test_markers=("timeline",),
        required_viewer_markers=("timeline",),
    ),
    TaxonomyTarget(
        id="report-exhibit-bundle",
        category="ux-review-report",
        title="Report and court exhibit bundle",
        expectation="Export selected evidence, citations, hashes, parser versions, limitations, audit chain, and exhibit package.",
        required_test_markers=("bundle", "case-db-report"),
        required_doc_markers=("exhibit", "report"),
    ),
    TaxonomyTarget(
        id="large-case-performance",
        category="performance",
        title="Large-case performance",
        expectation="Handle 100k/1M/10M rows with cursor APIs, checkpoint/resume, parser crash isolation, memory caps, and benchmarks.",
        required_test_markers=("benchmark", "columnar", "run"),
        required_doc_markers=("benchmark", "large"),
    ),
    TaxonomyTarget(
        id="taxonomy-audit-guardrail",
        category="validation",
        title="Taxonomy audit guardrail",
        expectation="Fail when a target forensic artifact has no collector, artifact type, viewer, test, or documentation mapping.",
        required_test_markers=("taxonomy",),
        required_doc_markers=("Omission Audit",),
    ),
)


def build_taxonomy_audit(repo_root: Path | None = None) -> dict[str, object]:
    root = (repo_root or Path.cwd()).resolve()
    collectors = set(artifact_collectors())
    artifact_types = discover_artifact_type_literals(root)
    test_index = build_text_index(root / "tests")
    doc_index = build_text_index(root / "docs")
    viewer_index = build_text_index(root / "rapidtriage" / "web") + "\n" + build_text_index(root / "rapidtriage" / "core")

    target_results = [
        evaluate_target(
            target,
            collectors=collectors,
            artifact_types=artifact_types,
            test_index=test_index,
            doc_index=doc_index,
            viewer_index=viewer_index,
        )
        for target in TAXONOMY_TARGETS
    ]
    status_counts: dict[str, int] = {}
    category_counts: dict[str, dict[str, int]] = {}
    for result in target_results:
        status = str(result["status"])
        category = str(result["category"])
        status_counts[status] = status_counts.get(status, 0) + 1
        category_counts.setdefault(category, {})
        category_counts[category][status] = category_counts[category].get(status, 0) + 1

    incomplete = [result for result in target_results if result["status"] != "covered"]
    missing = [result for result in target_results if result["status"] == "missing"]
    partial = [result for result in target_results if result["status"] == "partial"]
    external = [result for result in target_results if result.get("external_blockers")]
    return {
        "command": "taxonomy-audit",
        "taxonomy_version": TAXONOMY_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "repo_root": str(root),
        "summary": {
            "target_count": len(target_results),
            "covered_count": status_counts.get("covered", 0),
            "partial_count": status_counts.get("partial", 0),
            "missing_count": status_counts.get("missing", 0),
            "incomplete_count": len(incomplete),
            "external_blocker_count": len(external),
            "collector_count": len(collectors),
            "artifact_type_literal_count": len(artifact_types),
            "status_counts": status_counts,
            "category_status_counts": category_counts,
            "strict_pass": not incomplete,
        },
        "available": {
            "collectors": sorted(collectors),
            "artifact_types": sorted(artifact_types),
        },
        "targets": target_results,
        "priority_missing": summarize_priority(missing),
        "priority_partial": summarize_priority(partial),
    }


def evaluate_target(
    target: TaxonomyTarget,
    *,
    collectors: set[str],
    artifact_types: set[str],
    test_index: str,
    doc_index: str,
    viewer_index: str,
) -> dict[str, object]:
    missing_collectors = [name for name in target.required_collectors if name not in collectors]
    missing_artifact_types = [name for name in target.expected_artifact_types if name not in artifact_types]
    missing_tests = [marker for marker in target.required_test_markers if marker.lower() not in test_index]
    missing_docs = [marker for marker in target.required_doc_markers if marker.lower() not in doc_index]
    missing_viewers = [marker for marker in target.required_viewer_markers if marker.lower() not in viewer_index]
    missing_bindings = {
        "collectors": missing_collectors,
        "artifact_types": missing_artifact_types,
        "viewer_markers": missing_viewers,
        "test_markers": missing_tests,
        "doc_markers": missing_docs,
    }
    concrete_required = (
        len(target.required_collectors)
        + len(target.expected_artifact_types)
        + len(target.required_viewer_markers)
        + len(target.required_test_markers)
    )
    concrete_missing = (
        len(missing_collectors) + len(missing_artifact_types) + len(missing_viewers) + len(missing_tests)
    )
    total_required = concrete_required + len(target.required_doc_markers)
    total_missing = sum(len(items) for items in missing_bindings.values())
    matched_signal = total_required > total_missing
    if total_missing == 0 and concrete_required > 0 and concrete_missing == 0:
        status = "covered"
    elif concrete_required == 0:
        status = "missing"
    elif matched_signal:
        status = "partial"
    else:
        status = "missing"
    result = target.to_dict()
    result.update(
        {
            "status": status,
            "missing_bindings": missing_bindings,
            "present_bindings": {
                "collectors": [name for name in target.required_collectors if name in collectors],
                "artifact_types": [name for name in target.expected_artifact_types if name in artifact_types],
                "viewer_markers": [
                    marker for marker in target.required_viewer_markers if marker.lower() in viewer_index
                ],
                "test_markers": [marker for marker in target.required_test_markers if marker.lower() in test_index],
                "doc_markers": [marker for marker in target.required_doc_markers if marker.lower() in doc_index],
            },
            "reportability": "commercial-blocked" if status != "covered" or target.external_blockers else "internally-covered",
        }
    )
    return result


def discover_artifact_type_literals(repo_root: Path) -> set[str]:
    values: set[str] = set(KNOWN_DYNAMIC_ARTIFACT_TYPES)
    source_root = repo_root / "rapidtriage"
    if not source_root.exists():
        return values
    for path in source_root.rglob("*.py"):
        text = read_text(path)
        values.update(re.findall(r"artifact_type[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']", text))
    return values


def build_text_index(root: Path) -> str:
    if not root.exists():
        return ""
    parts: list[str] = []
    for path in iter_text_files(root):
        parts.append(str(path).lower())
        parts.append(read_text(path).lower())
    return "\n".join(parts)


def iter_text_files(root: Path) -> Iterable[Path]:
    suffixes = {".py", ".js", ".ts", ".tsx", ".html", ".css", ".md", ".json", ".yaml", ".yml"}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in suffixes:
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def summarize_priority(results: list[Mapping[str, object]], *, limit: int = 12) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for item in results[:limit]:
        missing = item.get("missing_bindings")
        missing_total = 0
        if isinstance(missing, Mapping):
            missing_total = sum(len(value) for value in missing.values() if isinstance(value, list))
        summary.append(
            {
                "id": item.get("id"),
                "category": item.get("category"),
                "title": item.get("title"),
                "missing_binding_count": missing_total,
                "external_blockers": item.get("external_blockers", []),
            }
        )
    return summary
