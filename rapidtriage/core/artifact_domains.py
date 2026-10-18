"""Evidence-tree domains of artifact kinds/types (one table for the API tree and the search index).

Aligned with frontend/src/features/tree/domains.ts. Lives in core so the
search index build (``core.search_index``) and the CLI need not import the API.
"""

from __future__ import annotations

# Evidence-tree domains, aligned with frontend/src/features/tree/domains.ts
# (one table): (domain id, Korean label, artifact kind, artifact types).
# ``None`` types = the kind's default domain; a row with types routes those
# types of the kind to another domain (the kind then appears in both, the
# secondary node id is ``artifacts:<kind>@<domain>``).
DOMAIN_LABELS: dict[str, str] = {
    "os": "운영체제·계정",
    "execution": "실행 흔적",
    "filesystem": "파일시스템",
    "registry": "레지스트리",
    "eventlog": "이벤트 로그",
    "web": "웹·브라우저",
    "messaging": "메신저·메일",
    "cloud": "클라우드",
    "media": "미디어·문서",
    "mobile": "모바일",
    "devices": "연결 장치·원격",
    "anti-forensics": "안티 포렌식",
    "incident": "침해사고",
    "memory": "메모리",
    "location": "위치·여행",
}
ARTIFACT_DOMAIN_TABLE: tuple[tuple[str, str, tuple[str, ...] | None], ...] = (
    # --- kind defaults ----------------------------------------------------
    ("os", "windows-os-account", None),
    ("os", "windows-system", None),
    ("os", "linux-system", None),
    ("os", "macos-system", None),
    ("execution", "windows-prefetch", None),
    ("execution", "windows-execution", None),
    ("execution", "windows-search-index", None),
    ("execution", "recent-files", None),
    ("filesystem", "windows-filesystem", None),
    ("registry", "windows-registry", None),
    ("registry", "windows-shellbags", None),
    ("eventlog", "eventlog", None),
    ("web", "browser", None),
    ("messaging", "email", None),
    ("messaging", "kakaotalk-windows", None),
    ("messaging", "kakaotalk-macos", None),
    ("messaging", "windows-messenger", None),
    ("cloud", "cloud-export", None),
    ("cloud", "cloud-sync", None),
    ("media", "media-image", None),
    ("media", "synthetic-media", None),
    ("media", "generic-documents", None),
    ("mobile", "mobile-export", None),
    ("mobile", "android-apk", None),
    ("devices", "windows-remote-access", None),
    ("memory", "memory-volatility", None),
    # --- type routing -----------------------------------------------------
    ("devices", "windows-os-account", ("windows-mounted-device", "windows-usb-device")),
    ("devices", "windows-registry", ("windows-mounted-device", "windows-usb-device")),
    (
        "devices",
        "windows-system",
        ("usb-setupapi-device-install-candidate", "third-party-remote-control-artifact", "wifi-profile"),
    ),
    (
        "os",
        "windows-registry",
        (
            "windows-service-config",
            "windows-timezone",
            "windows-computer-name",
            "windows-control-set",
            "windows-os-version",
            "windows-profile-list-entry",
            "windows-installed-program",
            "windows-sam-account",
            "windows-sam-group",
            # Network interface configuration is OS configuration (frontend
            # domains.ts "os-sysinfo"), not a connected device.
            "windows-network-interface",
        ),
    ),
    # Amcache extended inventory (parser-quality r2): devices/drivers.
    ("devices", "windows-execution", ("amcache-device-pnp", "amcache-device-container")),
    ("os", "windows-execution", ("amcache-device-census",)),
    ("eventlog", "windows-system", ("firewall-log",)),
    (
        "incident",
        "windows-system",
        ("web-server-log", "webshell-source-candidate", "bits-qmgr-transfer-candidate", "bits-qmgr-sqlite-job-candidate"),
    ),
    ("anti-forensics", "windows-system", ("defender-policy-artifact", "defender-support-log", "bitlocker-recovery-key-file")),
    # Registry-depth execution rows (r3 O1): PCA Store / FeatureUsage live in NTUSER.
    ("execution", "windows-registry", ("execution-pca", "execution-feature-usage")),
    ("anti-forensics", "windows-filesystem", ("ads-stream-candidate", "zone-identifier")),
    ("messaging", "mobile-export", ("mobile-message", "mobile-chat-database")),
    ("location", "mobile-export", ("mobile-location",)),
    ("location", "cloud-export", ("cloud-location",)),
    ("web", "macos-system", ("macos-browser-history-downloads",)),
    # --- R5 L1: communication and media apps --------------------------------
    ("messaging", "email-clients", None),
    ("media", "media-player", None),
    ("mobile", "windows-phone-link", None),
    ("messaging", "windows-phone-link", ("phone-link-message",)),
    # --- R5 L3 (web · URL classes · archives · P2P · recovery) -------------
    ("web", "p2p", None),
)


def artifact_type_domain(kind: str, artifact_type: str) -> str:
    """Domain of one artifact type of a kind (routing rows win over defaults)."""
    default = "other"
    for domain, row_kind, types in ARTIFACT_DOMAIN_TABLE:
        if row_kind != kind:
            continue
        if types is None:
            if default == "other":
                default = domain
        elif artifact_type in types:
            return domain
    return default
