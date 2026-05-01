from __future__ import annotations

import datetime as dt
from typing import Mapping


CORE_FORENSIC_ACCURACY_VERSION = "core-forensics-accuracy-v1"


CORE_FORENSIC_ACCURACY_ITEMS: tuple[dict[str, object], ...] = (
    {
        "number": 1,
        "title": "Native EVTX BinXML full parsing",
        "surface": "native EVTX records, BinXML values, promoted Event/System/EventData/UserData fields",
        "corpus": "EVTX files with Security, System, PowerShell, Sysmon, malformed chunks, duplicate EventData names, and provider-specific TemplateInstance records",
        "oracle": "EvtxECmd/Hayabusa/Windows Event Viewer XML export record-level diff",
        "required_checks": (
            "record-id and file-offset stability",
            "timestamp/EventID/provider/channel/computer equality",
            "duplicate EventData order preservation",
            "BinXML scalar type decoding diff",
            "unsupported grammar warning coverage",
        ),
    },
    {
        "number": 2,
        "title": "EVTX event template/message rendering",
        "surface": "rendered message, provider/template metadata, unresolved-template warnings",
        "corpus": "provider manifests/resource-DLL exports plus high-value Windows/Sysmon/Defender events",
        "oracle": "Windows Event Viewer rendered message and trusted EVTX export tools",
        "required_checks": (
            "message text normalization",
            "inserted parameter mapping",
            "provider/template/source provenance",
            "unresolved template warning",
            "fallback-message limitation disclosure",
        ),
    },
    {
        "number": 3,
        "title": "EVTX deleted/corrupt record recovery validation",
        "surface": "slack/deleted/corrupt record candidates with offsets and confidence",
        "corpus": "known-answer EVTX slack, truncated chunks, corrupt checksums, and carved record headers",
        "oracle": "hand-labeled offsets plus second-parser recovery output",
        "required_checks": (
            "chunk-boundary containment",
            "record-size plausibility",
            "checksum/integrity status",
            "candidate reason and confidence",
            "non-reportable default for unvalidated recovery",
        ),
    },
    {
        "number": 4,
        "title": "Registry hive full key tree reconstruction",
        "surface": "regf/hbin/nk/vk/sk/lf/lh/ri tree rows and parent/value links",
        "corpus": "NTUSER/SOFTWARE/SYSTEM hives with nested keys, value lists, dirty sequence numbers, and transaction logs",
        "oracle": "regripper/RegRipper, python-registry, exported .reg, and hand-labeled offsets",
        "required_checks": (
            "root-cell reachability",
            "parent-child backlink consistency",
            "value-list ownership",
            "last-write timestamp preservation",
            "transaction-log replay disclosure",
        ),
    },
    {
        "number": 5,
        "title": "Registry deleted key/value recovery",
        "surface": "free-cell nk/vk candidates, allocator state, parent confidence, data previews",
        "corpus": "hives with deleted keys/values, allocator reuse, transaction logs, and false-positive free cells",
        "oracle": "hand-labeled deleted-cell corpus and second-parser comparison",
        "required_checks": (
            "positive-size free-cell validation",
            "parent-key confirmation",
            "data-type and data-length plausibility",
            "allocator-state evidence",
            "reportability blocked until independent confirmation",
        ),
    },
    {
        "number": 6,
        "title": "SAM/SECURITY/SYSTEM account and permission deep parser",
        "surface": "SAM F/V, aliases, SECURITY policy/LSA metadata, ControlSet, privileges",
        "corpus": "Windows version matrix with local/admin/deleted/disabled accounts and group aliases",
        "oracle": "Windows API/Registry exports, RegRipper, and known account lifecycle assertions",
        "required_checks": (
            "RID/name/SID consistency",
            "UAC flag decoding",
            "group alias membership reconstruction",
            "privilege assignment attribution",
            "secret-value redaction and authority gate",
        ),
    },
    {
        "number": 7,
        "title": "Amcache parser",
        "surface": "Amcache.hve execution/install path, hash, publisher, timestamp semantics",
        "corpus": "Windows 7/8/10/11 Amcache schema variants and installer/execution fixtures",
        "oracle": "AmcacheParser/RegRipper export and hand-labeled timestamp semantics",
        "required_checks": (
            "schema-version detection",
            "path/hash/publisher extraction",
            "timestamp source labeling",
            "execution caveat wording",
            "deleted/legacy schema fallback warnings",
        ),
    },
    {
        "number": 8,
        "title": "ShimCache/AppCompatCache parser",
        "surface": "SYSTEM AppCompatCache binary entries by OS version",
        "corpus": "Windows XP through Windows 11 cache layouts with non-executed references",
        "oracle": "AppCompatCacheParser/ShimCacheParser and OS-version known-answer data",
        "required_checks": (
            "OS layout selection",
            "path/timestamp/flag decoding",
            "entry order preservation",
            "not-proof-of-execution warning",
            "malformed binary bounds checks",
        ),
    },
    {
        "number": 9,
        "title": "BAM/DAM execution parser",
        "surface": "SYSTEM BAM/DAM SID/path/FILETIME records",
        "corpus": "Windows 10/11 BAM/DAM hives with multiple SIDs and device paths",
        "oracle": "RegRipper/BAM parser output plus known execution timeline",
        "required_checks": (
            "SID extraction",
            "device path normalization",
            "FILETIME validity",
            "ControlSet attribution",
            "execution-semantics warning",
        ),
    },
    {
        "number": 10,
        "title": "SRUM full ESE table parser",
        "surface": "SRUDB ESE catalog/pages/tables/rows for app/network/resource usage",
        "corpus": "SRUDB.dat fixtures with network bytes, energy, app resources, and damaged pages",
        "oracle": "srum-dump/SrumECmd export and hand-labeled ESE page assertions",
        "required_checks": (
            "ESE page checksum validation",
            "catalog/table mapping",
            "tagged column decoding",
            "counter/timestamp semantics",
            "native-row confidence scoring",
        ),
    },
    {
        "number": 11,
        "title": "Windows.edb full ESE parser",
        "surface": "Windows Search ESE tables, properties, content snippets, deleted/index state",
        "corpus": "Windows.edb fixtures with files, URLs, content, deleted-state markers, and damaged pages",
        "oracle": "esentutl/export utilities, ESE parser exports, and known document/property assertions",
        "required_checks": (
            "catalog/table/page mapping",
            "property ID/name mapping",
            "path/URL/content correlation",
            "deleted/index-state validation",
            "page-level source citation",
        ),
    },
    {
        "number": 12,
        "title": "$MFT full attribute parser",
        "surface": "FILE records, attributes, resident/nonresident data, paths, timestamps, deleted state",
        "corpus": "NTFS volumes with attribute lists, hard links, deleted records, USA repairs, and nonresident runlists",
        "oracle": "MFTECmd/TSK output and byte-level FILE record assertions",
        "required_checks": (
            "USA validation",
            "attribute-list extension resolution",
            "parent path reconstruction",
            "runlist decoding",
            "timestamp/source field provenance",
        ),
    },
    {
        "number": 13,
        "title": "$UsnJrnl large-scale timeline parser",
        "surface": "USN v2/v3/v4 records, FRN/parent replay, rename/delete timeline",
        "corpus": "large USN journals with renames, deletes, truncation, v3 FILE_ID_128, and cursor pagination",
        "oracle": "MFTECmd/USN parser output plus replayed filesystem known-answer timeline",
        "required_checks": (
            "record-size bounds",
            "reason flag decoding",
            "FRN path cache replay",
            "rename/delete ordering",
            "cursor determinism at scale",
        ),
    },
    {
        "number": 14,
        "title": "JumpList DestList deep parser",
        "surface": "Automatic/Custom Destinations OLE streams, DestList entries, embedded LNKs",
        "corpus": "JumpList fixtures across OS versions with deleted streams and known AppIDs",
        "oracle": "JLECmd/LNK parser output and known application mapping",
        "required_checks": (
            "CFB stream inventory",
            "DestList header/entry layout",
            "embedded LNK linkage",
            "AppID mapping provenance",
            "deleted-entry warning",
        ),
    },
    {
        "number": 15,
        "title": "ShellBags native hive parser",
        "surface": "BagMRU/Bags relationships, shell item binary payloads, NTUSER/UsrClass transaction context",
        "corpus": "ShellBag hives with nested folders, network paths, deleted bags, and transaction logs",
        "oracle": "ShellBagsExplorer/SBECmd output and hand-labeled shell item paths",
        "required_checks": (
            "BagMRU/Bags relationship",
            "shell item binary decoding",
            "timestamp source labeling",
            "UsrClass/NTUSER correlation",
            "deleted/slack validation warning",
        ),
    },
    {
        "number": 16,
        "title": "Prefetch full version parser",
        "surface": "PF versions 17/23/26/30/31 sections, run counts, volumes, file metrics",
        "corpus": "compressed and uncompressed Prefetch files across Windows versions",
        "oracle": "PECmd/WinPrefetchView output and known run-count fixtures",
        "required_checks": (
            "SCCA/header validation",
            "version-specific section offsets",
            "run count and last-run timestamps",
            "volume/file metrics",
            "compressed PF handling",
        ),
    },
    {
        "number": 17,
        "title": "LNK full metadata parser",
        "surface": "ShellLinkHeader, LinkInfo, StringData, ExtraData, tracker GUID metadata",
        "corpus": "LNK fixtures for local, removable, network, Unicode, arguments, and tracker metadata",
        "oracle": "LECmd/Windows shell properties and hand-labeled link fields",
        "required_checks": (
            "header flag consistency",
            "target/working-dir/arguments extraction",
            "drive/network metadata",
            "tracker GUID validation",
            "timestamp/source field provenance",
        ),
    },
    {
        "number": 18,
        "title": "WER/Defender/Firewall/Task Scheduler/WMI deep parser",
        "surface": "WER reports/dumps, Defender logs, Firewall logs, Task XML/TaskCache, WMI repository pivots",
        "corpus": "Windows IR fixtures with malware detections, scheduled tasks, WMI persistence, and crash reports",
        "oracle": "Windows native exports, Chainsaw/Hayabusa/Velociraptor, and hand-labeled IR assertions",
        "required_checks": (
            "event semantics and risk rules",
            "Task XML/TaskCache correlation",
            "Defender/Firewall field normalization",
            "WER dump/cab linkage",
            "WMI consumer/filter binding validation",
        ),
    },
    {
        "number": 19,
        "title": "Browser cache/session/extension/sync artifacts",
        "surface": "Chromium/Firefox/Safari cache, sessions, extensions, cookies, sync, credential stores",
        "corpus": "multi-browser profiles with cache entries, session restore, extensions, cookies, and cleared history",
        "oracle": "browser DB queries, BrowserHistoryView/Hindsight exports, and known browsing sessions",
        "required_checks": (
            "profile/source attribution",
            "cache/session schema validation",
            "extension ID/source mapping",
            "secret/cookie opt-in legal gate",
            "deleted/synced content warning",
        ),
    },
    {
        "number": 20,
        "title": "Chrome/Edge/Firefox/Safari unified browser timeline",
        "surface": "cross-browser visit/download/search timeline with transition and profile metadata",
        "corpus": "Windows/macOS profiles with multiple browsers, downloads, typed URLs, and timezone edge cases",
        "oracle": "browser-native SQLite queries and trusted browser forensic exports",
        "required_checks": (
            "timestamp normalization",
            "transition semantics",
            "download target/source URL linkage",
            "multi-profile deduplication",
            "Safari scope limitation disclosure",
        ),
    },
    {
        "number": 21,
        "title": "AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity",
        "surface": "browser storage/export prompt-answer candidates with service labels and pairing confidence",
        "corpus": "service exports and browser storage fixtures for ChatGPT, Claude, Gemini, Perplexity, and schema changes",
        "oracle": "service export JSON/HTML and hand-labeled Q/A pairs",
        "required_checks": (
            "service/schema version detection",
            "question/answer pairing confidence",
            "orphan prompt/answer tracking",
            "source offset/storage provenance",
            "privacy and completeness warnings",
        ),
    },
    {
        "number": 22,
        "title": "E01/Ex01 fully integrated workflow",
        "surface": "libewf/Sleuth Kit mount/extract, partition selection, progress, hashes, resume",
        "corpus": "E01/Ex01 images with partitions, corrupt segments, encryption warnings, and known file hashes",
        "oracle": "ewfverify, mmls/fls/tsk_recover output, and known-answer image manifest",
        "required_checks": (
            "source hash and segment integrity",
            "tool version/command capture",
            "partition offset correctness",
            "read-only extraction provenance",
            "corrupt/encrypted limitation reporting",
        ),
    },
    {
        "number": 23,
        "title": "RAW/split image robust partition/filesystem handling",
        "surface": "DD/RAW/IMG/001 split detection, partition/filesystem extraction, gap warnings",
        "corpus": "raw and split images with missing segments, multiple filesystems, deleted files, and encrypted volumes",
        "oracle": "TSK output plus known-answer recovered file/hash manifest",
        "required_checks": (
            "split-set order and gap validation",
            "partition table parsing",
            "filesystem extraction audit",
            "deleted-file recovery expectations",
            "encrypted volume limitation warning",
        ),
    },
    {
        "number": 24,
        "title": "VHD/VHDX/VMDK/VDI/QCOW direct handling polish",
        "surface": "virtual disk conversion/extraction with snapshot and provenance handling",
        "corpus": "VM disks with differencing chains, snapshots, compression, corruption, and known recovered hashes",
        "oracle": "qemu-img info/convert, TSK extraction, and hypervisor metadata manifest",
        "required_checks": (
            "qemu-img version/command capture",
            "snapshot/differencing-chain detection",
            "converted raw hash/provenance",
            "nested partition extraction",
            "unsupported/encrypted VM warning",
        ),
    },
    {
        "number": 25,
        "title": "AD1/L01/Lx01/AFF/AFF4/XVA support",
        "surface": "forensic container detection, export-first workflow, source integrity, and native parser gates",
        "corpus": "AD1/L01/Lx01/AFF/AFF4/XVA samples or vendor exports with known file manifests",
        "oracle": "vendor export logs, afflib where available, and known-answer file/hash manifest",
        "required_checks": (
            "container type detection",
            "source integrity capture",
            "native-vs-export workflow disclosure",
            "metadata/deleted-entry validation",
            "encrypted/compressed limitation warning",
        ),
    },
    {
        "number": 26,
        "title": "Cellebrite/XRY/GrayKey/AXIOM export deep import",
        "surface": "vendor export messages, contacts, calls, files, apps, accounts, browser/media rows",
        "corpus": "versioned vendor exports with deleted-record and duplicate-message edge cases",
        "oracle": "source vendor tool report, acquisition hash manifest, and hand-labeled row counts",
        "required_checks": (
            "source tool/version/profile detection",
            "row count and source ID preservation",
            "duplicate/deleted semantics",
            "source hash and acquisition linkage",
            "schema version compatibility warning",
        ),
    },
    {
        "number": 27,
        "title": "iOS backup parser",
        "surface": "Manifest.db, domains, Info/Status plist, app DB/media/message inventory",
        "corpus": "encrypted and unencrypted iOS backups with messages, media, app domains, and deleted records",
        "oracle": "iTunes/idevicebackup metadata, iLEAPP exports, and known backup manifest assertions",
        "required_checks": (
            "Manifest.db domain/fileID mapping",
            "Info/Status plist consistency",
            "encrypted backup authority gate",
            "app database schema detection",
            "deleted-record limitation warning",
        ),
    },
    {
        "number": 28,
        "title": "iOS keychain/artifact parser",
        "surface": "keychain inventory, protected-data metadata, redacted secret handling",
        "corpus": "authorized keychain exports with generic/password/certificate records and protected data states",
        "oracle": "iLEAPP/keychain-dumper style inventory and legal authority manifest",
        "required_checks": (
            "secret values redacted by default",
            "protected-data class labeling",
            "authority gate before reveal/decrypt",
            "record count/table inventory",
            "audit log for any controlled reveal",
        ),
    },
    {
        "number": 29,
        "title": "Android backup/artifact parser",
        "surface": "Android backup/export SMS, calls, contacts, browser, media, app DB/file artifacts",
        "corpus": "Android logical/backup exports with schema variants, media links, and encrypted stores",
        "oracle": "ALEAPP/vendor export plus known app/table assertions",
        "required_checks": (
            "package/path attribution",
            "SMS/call/contact row validation",
            "browser/media source linkage",
            "encrypted-store limitation",
            "app-specific schema version tracking",
        ),
    },
    {
        "number": 30,
        "title": "Android app package/data parser",
        "surface": "APK manifest/permissions/components/DEX strings/native libraries plus app data inventory",
        "corpus": "benign and malicious APKs with binary manifests, signatures, native code, and app databases",
        "oracle": "apkanalyzer/aapt/jadx/MobSF exports and known malware triage labels",
        "required_checks": (
            "binary manifest decode or limitation",
            "permission/component normalization",
            "signature chain validation",
            "DEX/native string pivot bounds",
            "app-data schema and secret-handling warnings",
        ),
    },
    {
        "number": 31,
        "title": "KakaoTalk parser",
        "surface": "authorized KakaoTalk exports, PC inventory/decrypt workflows, chat/message/media pivots",
        "corpus": "pre/post-2025-08 KakaoTalk exports and Windows PC stores with known chat/message/media counts",
        "oracle": "authorized KakaoTalk export, validated decrypted SQLite, vendor tool output, and hand-labeled message assertions",
        "required_checks": (
            "KakaoTalk service/profile detection",
            "chat/message participant/media normalization",
            "schema/app version and BigBang compatibility tracking",
            "encrypted/deleted limitation warning",
            "source hash and legal provenance",
        ),
    },
    {
        "number": 32,
        "title": "WhatsApp parser",
        "surface": "authorized WhatsApp exports, msgstore/contact/media/call database inventory",
        "corpus": "WhatsApp exports and msgstore/contact fixtures across schema and crypt variants",
        "oracle": "WhatsApp export text, validated msgstore.db decode, vendor tool output, and hand-labeled media/message counts",
        "required_checks": (
            "WhatsApp service/profile detection",
            "chat/contact/media normalization",
            "crypt backup authority workflow warning",
            "deleted-row limitation warning",
            "source hash and app-version provenance",
        ),
    },
    {
        "number": 33,
        "title": "Telegram parser",
        "surface": "Telegram desktop/mobile export rows, cache/media/account attribution, database inventory",
        "corpus": "Telegram JSON/HTML exports and desktop/mobile cache/database fixtures",
        "oracle": "Telegram native export, vendor tool output, and hand-labeled chat/media/account assertions",
        "required_checks": (
            "Telegram service/profile detection",
            "chat/user/media attribution",
            "account/cache provenance",
            "encrypted local store warning",
            "deleted/cache recovery limitation",
        ),
    },
    {
        "number": 34,
        "title": "Signal parser",
        "surface": "authorized Signal exports/backups, SQLCipher-safe inventory, thread/message/recipient pivots",
        "corpus": "Signal exports/backups with thread, recipient, attachment, deleted, and encrypted-store variants",
        "oracle": "authorized Signal export, validated SQLCipher decode where legally supplied, and hand-labeled assertions",
        "required_checks": (
            "Signal service/profile detection",
            "thread/recipient/message inventory",
            "SQLCipher/key authority gate",
            "attachment/deleted limitation warning",
            "secret-safe legal provenance",
        ),
    },
    {
        "number": 35,
        "title": "Extended messenger parser",
        "surface": "WeChat/LINE/Discord/Instagram and extended messenger authorized exports/databases",
        "corpus": "service-specific exports covering media, reactions, read-state, edits, deletes, and ephemeral modes",
        "oracle": "native service export, vendor tool output, and hand-labeled message/media/reaction assertions",
        "required_checks": (
            "extended service/profile detection",
            "message/media/reaction normalization",
            "schema/app version registry",
            "encrypted/ephemeral limitation warning",
            "source hash and legal provenance",
        ),
    },
    {
        "number": 36,
        "title": "Email PST/OST full mailbox parser",
        "surface": "EML/MBOX/Maildir parsing and PST/OST/MSG mailbox inventory with attachment/thread pivots",
        "corpus": "mailboxes with folder trees, duplicate threads, attachments, deleted items, PST/OST/MSG variants",
        "oracle": "libpff/readpst/Outlook exports, MBOX/EML ground truth, and hand-labeled folder/message assertions",
        "required_checks": (
            "mailbox/message source profile detection",
            "message header/body/attachment inventory",
            "PST/OST native limitation warning",
            "threading/dedup validation warning",
            "legal privilege boundary",
        ),
    },
    {
        "number": 37,
        "title": "Gmail/Google Takeout deep parser",
        "surface": "Gmail, Drive, Photos, Activity, Location, and account Takeout exports",
        "corpus": "Google Takeout exports with selected products, split archives, sidecars, Gmail threads, and location/activity variants",
        "oracle": "Google Takeout index/native views, provider API spot-checks, and hand-labeled product assertions",
        "required_checks": (
            "Google service/profile detection",
            "Gmail/Drive/Activity/Location normalization",
            "source hash and export-scope warning",
            "sidecar/media/linkage limitation",
            "provider schema/timezone warning",
        ),
    },
    {
        "number": 38,
        "title": "Apple iCloud export parser",
        "surface": "iCloud/Apple privacy export account, file, photos, mail, and shared metadata rows",
        "corpus": "Apple privacy exports and iCloud copies with photos, shared albums, files, accounts, and ADP limitations",
        "oracle": "Apple export index/iCloud web view, EXIF/sidecar assertions, and hand-labeled account/file metadata",
        "required_checks": (
            "Apple/iCloud service profile detection",
            "account/file/photo metadata normalization",
            "source hash and export-scope warning",
            "ADP/shared-album limitation warning",
            "provider retention/schema warning",
        ),
    },
    {
        "number": 39,
        "title": "Microsoft 365/OneDrive/Teams export parser",
        "surface": "Microsoft 365, OneDrive, SharePoint, Teams, Exchange, and audit exports",
        "corpus": "Purview/eDiscovery/Graph exports with Teams messages, reactions, OneDrive files, audit and permission states",
        "oracle": "Purview/eDiscovery export, Graph API spot-checks, and hand-labeled Teams/OneDrive/Audit assertions",
        "required_checks": (
            "Microsoft 365 service profile detection",
            "mail/file/message/audit normalization",
            "source hash and eDiscovery/export warning",
            "permissions/retention/deleted limitation",
            "provider schema/timestamp warning",
        ),
    },
    {
        "number": 40,
        "title": "Cloud API acquisition workflow",
        "surface": "manifest-driven cloud API collection, credential redaction, response hashing, and import workflow",
        "corpus": "authorized provider API fixtures covering pagination, retries, scope, OAuth, delta, and error handling",
        "oracle": "provider API/native export diff, request/response hash manifest, and reviewer-signed authorization metadata",
        "required_checks": (
            "manifest request validation",
            "credential redaction",
            "response hash/provenance",
            "pagination/backoff limitation warning",
            "provider OAuth/scope/legal warning",
        ),
    },
)


def build_core_forensics_accuracy_profiles() -> dict[str, object]:
    profiles = [build_accuracy_profile(item) for item in CORE_FORENSIC_ACCURACY_ITEMS]
    return {
        "version": CORE_FORENSIC_ACCURACY_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "#1-#40 validation and accuracy reinforcement",
        "profile_count": len(profiles),
        "commercial_gap_ids": [f"#{item['number']}" for item in profiles],
        "status": "accuracy-profiles-ready",
        "release_gate": "Each #1-#40 parser claim must attach pass/fail evidence against its profile before report-grade wording.",
        "profiles": profiles,
    }


def build_core_forensics_known_answer_template() -> dict[str, object]:
    profiles = [build_accuracy_profile(item) for item in CORE_FORENSIC_ACCURACY_ITEMS]
    return {
        "version": CORE_FORENSIC_ACCURACY_VERSION,
        "status": "template-not-run",
        "item_count": len(profiles),
        "instructions": [
            "Replace source/evidence_paths with real corpora before using this as validation evidence.",
            "Keep status as not-run/open/fail until every required check has observed evidence.",
            "Only status=pass datasets with present evidence paths can satisfy commercial-readiness validation gates.",
        ],
        "datasets": [known_answer_dataset_for_profile(profile) for profile in profiles],
    }


def build_accuracy_profile(item: Mapping[str, object]) -> dict[str, object]:
    number = int(item["number"])
    required_checks = list(item["required_checks"])
    return {
        "number": number,
        "gap_id": f"#{number}",
        "title": str(item["title"]),
        "surface": str(item["surface"]),
        "known_answer_corpus_requirement": str(item["corpus"]),
        "oracle": str(item["oracle"]),
        "required_checks": required_checks,
        "minimum_evidence": [
            "source file or export hash",
            "tool/parser version and command",
            "expected-answer manifest",
            "observed RapidTriage output",
            "record-level or row-level diff",
            "reviewer sign-off and limitation note",
        ],
        "accuracy_controls": {
            "source_provenance_required": True,
            "offset_or_record_id_required": number <= 25,
            "hash_required": True,
            "timezone_or_timestamp_semantics_required": number in {
                1, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 20, 22, 23, 24, 26, 27, 29, 31, 32,
                33, 34, 35, 36, 37, 38, 39, 40,
            },
            "secret_redaction_required": number in {19, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 40},
            "legal_or_authority_gate_required": number in {19, 22, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 37, 38, 39, 40},
            "cross_tool_diff_required": True,
            "known_answer_required": True,
        },
        "pass_fail_rules": [
            "pass only when every required_check has explicit observed evidence",
            "fail when parser output loses record order, source path/hash, record ID, offset/source index, or timestamp semantics required by the profile",
            "fail when a recovered/deleted/native-candidate artifact is reportable without secondary validation",
            "open when fixture evidence exists but broad corpus or cross-tool validation is not attached",
        ],
        "default_reportability": "validation-required",
        "commercial_grade_ready": False,
    }


def known_answer_dataset_for_profile(profile: Mapping[str, object]) -> dict[str, object]:
    number = int(profile["number"])
    return {
        "id": f"core-forensics-{number:02d}",
        "name": f"#{number} {profile['title']} known-answer validation",
        "source": str(profile["known_answer_corpus_requirement"]),
        "corpus_family": "core-forensics",
        "status": "not-run",
        "backlog_items": [str(number)],
        "evidence_paths": [],
        "expected": {
            "oracle": profile["oracle"],
            "required_checks": list(profile["required_checks"]),
            "minimum_evidence": list(profile["minimum_evidence"]),
            "pass_fail_rules": list(profile["pass_fail_rules"]),
        },
        "notes": "Attach source hashes, RapidTriage output, oracle output, diff, and reviewer sign-off.",
    }


def build_accuracy_gate(
    number: int,
    *,
    satisfied_checks: list[str] | tuple[str, ...] | None = None,
    evidence_refs: list[str] | tuple[str, ...] | None = None,
    status: str = "validation-required",
) -> dict[str, object]:
    profile = accuracy_profile_for_item(number)
    satisfied = [str(item) for item in (satisfied_checks or []) if str(item)]
    required = [str(item) for item in profile["required_checks"]]
    missing = [item for item in required if item not in satisfied]
    return {
        "profile_version": CORE_FORENSIC_ACCURACY_VERSION,
        "gap_id": profile["gap_id"],
        "title": profile["title"],
        "status": status,
        "required_checks": required,
        "satisfied_checks": satisfied,
        "missing_required_checks": missing,
        "minimum_evidence": list(profile["minimum_evidence"]),
        "accuracy_controls": dict(profile["accuracy_controls"]),
        "evidence_refs": [str(item) for item in (evidence_refs or []) if str(item)],
        "default_reportability": profile["default_reportability"],
        "commercial_grade_ready": False,
        "next_validation_step": (
            "Attach known-answer corpus output, cross-tool diff, and reviewer sign-off before report-grade claims."
        ),
    }


def accuracy_profile_for_item(number: int) -> dict[str, object]:
    for item in CORE_FORENSIC_ACCURACY_ITEMS:
        if int(item["number"]) == number:
            return build_accuracy_profile(item)
    raise KeyError(f"unknown #1-#40 forensic accuracy item: {number}")
