"""Unified timeline from files/docs/artifact outputs (parser-quality r1/r2).

Events come only from timestamps the evidence itself records, through the
explicit :data:`TIMELINE_FIELD_MAP` (``artifact_type -> [(field, label)]``).
Host times of an extracted copy (``files.json`` ``source_file_*``, artifact
``modified_at``/``timestamp`` taken from ``stat``) are acquisition-copy
times and never become events. Every event carries a semantic
``timestamp_kind`` label and ``timezone`` (storage is UTC; ``local-unknown``
values keep their wall-clock text without an offset).

Dedupe (r2): one event per ``(source record, timestamp)``. Label variants of
the same instant (``run``/``run-1``, ``created``/``cookie-created``,
``last-access``/``destlist-last-modified``, ``*-at``/plain, accessed ==
modified) collapse into one event whose ``labels`` lists every label.
Key-level registry times (ShimCache/UserAssist/BAM key LastWrite) are one
event per key, aggregate rows that only re-copy per-row times are not
emitted, and PE link/compile times (TimeDateStamp; reproducible-build
hashes) stay row fields. Values before 1980-01-01, the DOS-zero sentinel
1980-01-01T00:00:00 and values after the reference time (run start or
acquisition) + 1 day are excluded and counted, not dropped silently.

Adding a field is one line in :data:`TIMELINE_FIELD_MAP`. A path is a dotted
key path; ``name[]`` iterates a list of objects and ``name[*]`` a list of
timestamps (numbered labels: ``run-1`` ... ``run-8``).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

from .artifact_profiles import iter_payload_records
from .artifacts import SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .docs import scan_document_candidates
from .files import run_files_scan
from .filetime import MIN_PLAUSIBLE, parse_iso_utc
from .input_root import resolve_input_root
from .rules import RuleSet, annotate_timeline_payload


class TimelineError(ValueError):
    """Raised when timeline inputs are missing or invalid."""


class TimelineField(NamedTuple):
    """One artifact field that is a timeline event.

    ``label`` is the semantic kind (created/modified/accessed/event/run/
    last-written/visited/...); ``event_type`` overrides the default
    ``artifact-<type>-<label>``; ``timezone`` describes the source value
    (``UTC`` unless the format is local wall-clock time, e.g. EXIF).
    ``scope="key"`` marks a registry key time shared by every entry of the
    key (ShimCache/UserAssist/BAM value lists): one event per key.
    ``scope="inventory"`` marks per-subkey LastWrite times that an inventory
    rewrite sets in bulk (Amcache InventoryDriverBinary/DevicePnp/...): one
    event per (hive, section) at the dominant rewrite time; the per-key time
    distribution stays in the event details.
    """

    path: str
    label: str
    event_type: str | None = None
    timezone: str = "UTC"
    scope: str = "row"


F = TimelineField
_BROWSER_FIELDS: tuple[TimelineField, ...] = (
    F("visited_at", "visited"),
    F("last_visited_at", "last-visited"),
    F("history[].visited_at", "visited"),
    F("history[].last_visited_at", "last-visited"),
    F("downloads[].started_at", "download-started"),
    F("downloads[].ended_at", "download-ended"),
    F("started_at", "download-started"),
    F("ended_at", "download-ended"),
)

# artifact_type -> fields that are evidence timestamps. Types not listed emit
# no events (their unmapped timestamp-like fields are counted in the summary).
TIMELINE_FIELD_MAP: dict[str, tuple[TimelineField, ...]] = {
    # --- execution -------------------------------------------------------
    "prefetch-file": (
        F("last_run_times[*]", "run"),
        *(F(f"run_time_{index}", f"run-{index}") for index in range(1, 9)),
        F("volume_created_at", "volume-created"),
    ),
    "prefetch-invalid-content": (),
    # link_date/compile_time (PE TimeDateStamp) are build stamps (often
    # reproducible-build hashes), not events: see TIMELINE_BUILD_STAMP_FIELDS.
    "amcache-schema-row": (
        F("key_last_written_at", "last-written"),
        F("decoded_values.InstallDate", "installed", timezone="local-unknown"),
    ),
    "amcache-entry": (F("key_last_written_at", "last-written"),),
    # Amcache extended inventory (R2-A/R3): the subkey LastWrite is rewritten
    # in bulk by the inventory task, so it is one event per (hive, section)
    # (``scope="inventory"``); link/install/driver dates
    # (``secondary_timestamps``) stay row fields.
    **{name: (F("key_last_written_at", "last-written", scope="inventory"),) for name in (
        "amcache-driver-binary",
        "amcache-driver-package",
        "amcache-device-pnp",
        "amcache-device-container",
        "amcache-application-shortcut",
        "amcache-device-census",
        "amcache-inventory-row",
    )},
    "shimcache-schema-entry": (F("timestamp", "file-modified"), F("key_last_written_at", "last-written", scope="key")),
    "shimcache-entry": (F("key_last_written_at", "last-written", scope="key"),),
    "bam-schema-entry": (F("timestamp", "run"), F("key_last_written_at", "last-written", scope="key")),
    "userassist-schema-entry": (F("timestamp", "run"), F("key_last_written_at", "last-written", scope="key")),
    "srum-row-candidate": (F("normalized_time", "event"),),
    "srum-network-usage": (F("timestamp", "srum-record"),),
    "srum-app-usage": (F("timestamp", "srum-record"),),
    "bam-entry": (F("timestamp", "run"),),
    # --- filesystem ------------------------------------------------------
    "mft-record": (
        F("attributes[].standard_information.timestamps.created_at", "si-created"),
        F("attributes[].standard_information.timestamps.modified_at", "si-modified"),
        F("attributes[].standard_information.timestamps.mft_modified_at", "si-mft-modified"),
        F("attributes[].standard_information.timestamps.accessed_at", "si-accessed"),
        F("attributes[].file_name.timestamps.created_at", "fn-created"),
        F("attributes[].file_name.timestamps.modified_at", "fn-modified"),
    ),
    "usn-record": (F("timestamp", "usn-change"),),
    # --- registry --------------------------------------------------------
    "registry-deleted-cell-candidate": (F("last_written_at", "last-written-recovered"),),
    "registry-key-recovery-candidate": (F("last_written_at", "last-written-recovered"),),
    "registry-user-activity": (F("last_written_at", "last-written"),),
    "shellbag-native-candidate": (F("key_last_written_at", "last-written"),),
    "shellbag-entry": (
        F("key_last_written_at", "last-written"),
        F("item_created_at", "item-created"),
        F("item_modified_at", "item-modified"),
        F("item_accessed_at", "item-accessed"),
    ),
    "registry-hive": (F("native_header.last_written_at", "hive-last-written"),),
    "windows-sam-group-candidate": (F("last_written_at", "last-written"),),
    "windows-sam-account-candidate": (
        F("last_written_at", "last-written"),
        F("last_logon_at", "last-logon"),
        F("password_last_set_at", "password-set"),
        F("last_failed_logon_at", "last-failed-logon"),
        F("created_at", "account-created"),
    ),
    "windows-sam-account": (),
    "windows-sam-group": (F("last_written_at", "last-written"),),
    "registry-persistence-entry": (F("key_last_written_at", "last-written"),),
    "windows-installed-program": (F("install_date", "installed", timezone="local-unknown"), F("key_last_written_at", "last-written")),
    "windows-profile-list-entry": (F("key_last_written_at", "last-written"),),
    "windows-os-version": (F("install_time", "os-installed"),),
    "windows-account-lifecycle": (
        F("last_logon_at", "last-logon"),
        F("password_last_set_at", "password-set"),
        F("created_at", "account-created"),
    ),
    "windows-usb-device": (
        F("first_install_at", "first-install"),
        F("last_arrival_at", "last-arrival"),
        F("last_removal_at", "last-removal"),
        F("key_last_written_at", "last-written"),
    ),
    "windows-mounted-device": (F("key_last_written_at", "last-written"),),
    "windows-service-config": (F("key_last_written_at", "last-written"),),
    # R3 O1 registry depth. NetworkList dates are SYSTEMTIME in local wall-clock time; key-level
    # LastWrite times (MRU lists, FeatureUsage, PCA Store, KnownDLLs) are one event per key.
    "registry-network-profile": (
        F("first_connected_at", "first-connected", timezone="local-unknown"),
        F("last_connected_at", "last-connected", timezone="local-unknown"),
    ),
    "registry-wlan-profile": (
        F("first_connected_at", "first-connected", timezone="local-unknown"),
        F("last_connected_at", "last-connected", timezone="local-unknown"),
        F("key_last_written_at", "last-written"),
    ),
    "registry-network-share": (F("key_last_written_at", "last-written", scope="key"),),
    "registry-office-mru": (F("last_opened_at", "last-opened"),),
    "registry-known-dll": (F("key_last_written_at", "last-written", scope="key"),),
    "registry-default-browser": (F("key_last_written_at", "last-written"),),
    "registry-install-state": (F("install_date", "installed", timezone="local-unknown"), F("key_last_written_at", "last-written")),
    "execution-pca": (F("last_run_at", "run"), F("event_at", "pca-event"), F("key_last_written_at", "last-written", scope="key")),
    "execution-feature-usage": (F("key_last_written_at", "last-written", scope="key"),),
    "bitlocker-recovery-key-file": (F("key_created_at", "created"),),
    # --- R5 L2: OS / system rows (registry_depth.py, system_extras.py) ---------------------
    "startup-item": (
        F("disabled_at", "disabled"),
        F("key_last_written_at", "last-written", scope="key"),
        F("target_created_at", "target-created"),
        F("target_modified_at", "target-modified"),
    ),
    "registry-logon-banner": (F("key_last_written_at", "last-written"),),
    "ssh-known-host": (F("key_last_written_at", "last-written", scope="key"),),
    "ssh-client-session": (F("key_last_written_at", "last-written"),),
    "office-identity": (F("key_last_written_at", "last-written"),),
    "office-backstage-item": (F("modified_at", "modified"),),
    "desktop-wallpaper": (F("key_last_written_at", "last-written", scope="key"),),
    "vm-config": (F("last_state_change_at", "last-updated"),),
    "av-detection-log": (F("detected_at", "event", timezone="local-unknown"),),
    # --- file usage ------------------------------------------------------
    "shell-shortcut": (
        F("target_created_at", "target-created"),
        F("target_modified_at", "target-modified"),
        F("target_accessed_at", "target-accessed"),
    ),
    "recent-shortcut-invalid-content": (),
    "shell-shortcut-invalid-content": (),
    "recent-shortcut": (
        F("target_created_at", "target-created"),
        F("target_modified_at", "target-modified"),
        F("target_accessed_at", "target-accessed"),
    ),
    "jumplist-automatic": (
        F("destinations[].target_created_at", "target-created"),
        F("destinations[].target_modified_at", "target-modified"),
        F("destinations[].target_accessed_at", "target-accessed"),
        F("destinations[].destlist_last_modified_at", "destlist-last-modified"),
        F("destlist_entries[].last_modified_at", "destlist-last-modified"),
    ),
    "jumplist-entry": (
        F("timestamp", "destlist-last-modified"),
        F("target_created_at", "target-created"),
        F("target_modified_at", "target-modified"),
        F("target_accessed_at", "target-accessed"),
        F("destlist_last_modified_at", "destlist-last-modified"),
    ),
    "jumplist-custom": (
        F("destinations[].target_created_at", "target-created"),
        F("destinations[].target_modified_at", "target-modified"),
        F("destinations[].target_accessed_at", "target-accessed"),
    ),
    "recycle-bin-entry": (F("deleted_at", "deleted"),),
    # --- event logs ------------------------------------------------------
    # eventlog-event / eventlog-detection use eventlog_detail_event (below).
    "eventlog-logon-session": (F("started_at", "logon"), F("ended_at", "logoff")),
    # --- system ----------------------------------------------------------
    "wer-report": (F("event_time", "event"),),
    # Minidump header times only; module TimeDateStamps are build hashes, not events.
    "crash-dump-indicators": (F("dump_time", "crash"), F("process_create_time", "process-created")),
    "memory-minidump": (F("dump_time", "crash"), F("process_create_time", "process-created")),
    "notification-row-candidate": (F("normalized_time", "notification"),),
    "webshell-source-candidate": (F("normalized_time", "event"),),
    "task-scheduler-task": (F("registration_date", "registered", timezone="local-unknown"),),
    "windows-search-index-entry": (
        F("created_at", "indexed-created"),
        F("modified_at", "indexed-modified"),
        F("accessed_at", "indexed-accessed"),
    ),
    "windows-filesystem-usn": (),
    "usn-journal-inventory": (
        F(
            "timeline_review_candidates[].timestamp",
            "observed",
            event_type="artifact-usn-journal-inventory-timeline-review-candidate-observed",
        ),
        F(
            "usn_replay_inventory_profile.bounded_state_replay_preview.transitions[].timestamp",
            "observed",
            event_type="artifact-usn-journal-inventory-usn-state-transition-observed",
        ),
    ),
    # --- browser / web ---------------------------------------------------
    "browser-history": _BROWSER_FIELDS,
    "browser-history-downloads": _BROWSER_FIELDS,
    "browser-history-visit": _BROWSER_FIELDS,
    "browser-visit": (F("timestamp", "visited"), *_BROWSER_FIELDS),
    # Rows without evidence time (browser rows otherwise use the row-level
    # timestamp/timestamp_kind contract).
    "browser-top-site": (),
    "browser-acquisition-anomaly": (),
    "browser-parse-error": (),
    "browser-ai-usage": (F("ai_usage[].last_visited_at", "ai-usage-visited"),),
    "browser-download": _BROWSER_FIELDS,
    "browser-cookie": (F("created_at", "cookie-created"), F("last_accessed_at", "cookie-accessed")),
    "browser-login": (F("created_at", "login-created"), F("last_used_at", "login-used")),
    "browser-bookmark": (F("created_at", "bookmark-added"),),
    "browser-extension": (F("install_time", "installed"),),
    "macos-quarantine-event": (F("started_at", "download-started"), F("ended_at", "download-ended")),
    # --- apps / media ----------------------------------------------------
    "cloud-export-archive": (
        F("cloud_archive_manifest.entry_manifest[].modified_at", "archive-entry-modified", timezone="local-unknown"),
    ),
    "mobile-message": (F("message_timestamp", "message"), F("sent_at", "message"), F("edited_at", "edited")),
    "cloud-message": (F("message_timestamp", "message"), F("sent_at", "message")),
    # Cloud sync clients (R2 M4): events/files use the row-level contract
    # (``timestamp`` + ``timestamp_kind`` cloud-upload/cloud-modified/...);
    # account and inventory rows carry no evidence time.
    "cloud-sync-event": (),
    # OneDrive SyncEngineDatabase diskCreationTime / diskLastAccessTime: the local copy's times.
    "cloud-sync-file": (
        F("viewed_at", "cloud-viewed"),
        F("shared_with_me_at", "cloud-shared-with-me"),
        F("disk_created_at", "sync-local-created"),
        F("disk_accessed_at", "sync-local-accessed"),
    ),
    "cloud-sync-account": (),
    "cloud-sync-inventory": (),
    # r2 M2: decrypted KakaoTalk PC messages (sendAt, UTC) and saved pictures whose
    # KakaoTalk_<yyyymmdd>_<hhmmssSSS> file name is a local wall-clock save time.
    "kakaotalk-message": (F("timestamp", "message"),),
    "kakaotalk-shared-picture": (F("download_time", "saved", timezone="local-unknown"),),
    # media-image/media-video evidence times come through the row-level
    # timestamp/timestamp_kind contract (EXIF DateTimeOriginal, mp4 mvhd).
    "media-image": (F("exif_gps_profile.gps_datetime_utc_candidate", "gps-fix"),),
    "media-image-unreadable": (F("exif_gps_profile.gps_datetime_utc_candidate", "gps-fix"),),
    "media-video": (),
    "sticky-note": (F("created_at", "note-created"), F("updated_at", "note-updated")),
}
# Rows that only aggregate other rows (their times duplicate the source rows)
# and per-reference rows of a parent artifact never emit events.
TIMELINE_EXCLUDED_TYPES: frozenset[str] = frozenset(
    {
        "prefetch-reference",
        "registry-hive-cell",
        # Bulk key inventory (hundreds of thousands of rows): key LastWrite
        # times surface through the semantic registry rows instead (W2).
        "registry-key-tree-node",
        "shellbag-hive-summary",
        "registry-summary",
        "eventlog-summary",
        "windows-execution-summary",
        "mobile-correlation-summary",
        "kakaotalk-windows-correlation-summary",
        "synthetic-media-scan-status",
        "synthetic-media-scan-summary",
        # Derived lead rows that re-copy the time of their source cache/history row.
        "web-upload-candidate",
    }
)
# Aggregate rows that re-copy times of per-row artifacts of the same payload:
# skipped when the payload also carries the per-row types (summary
# ``artifact_type_counts``), emitted otherwise (older payloads).
TIMELINE_AGGREGATE_TYPES: dict[str, tuple[str, ...]] = {
    "browser-history-downloads": ("browser-history", "browser-visit", "browser-download"),
    # Logon/logoff of a correlated session are the 4624/4634 eventlog-event rows.
    "eventlog-logon-session": ("eventlog-event",),
}
# PE TimeDateStamp-like fields: kept as row fields, never events.
TIMELINE_BUILD_STAMP_FIELDS: dict[str, tuple[str, ...]] = {
    "amcache-schema-row": ("link_date_raw", "link_date", "compile_time"),
    "amcache-entry": ("link_date_raw", "link_date", "compile_time"),
    "prefetch-file": ("pe_timestamp",),
}
BUILD_STAMP_NOTE = (
    "PE 링크/컴파일 시각(TimeDateStamp)은 재현 가능 빌드에서 해시값이 들어가므로 이벤트로 쓰지 않고 행 필드로만 둡니다."
)
LOCAL_TIMEZONE_LABELS = frozenset({"local-unknown", "exif-local", "local", "device-local"})
_OFFSET_LABEL_RE = re.compile(r"^[+-]\d{2}:?\d{2}$")
EVENTLOG_TYPES = frozenset({"eventlog-event", "eventlog-detection"})
# Record identity used for dedupe: first present field wins.
RECORD_IDENTITY_FIELDS: tuple[str, ...] = (
    "record_id",
    "cell_offset",
    "entry_offset",
    "value_cell_offset",
    "key_path",
    "target_path",
    "executable_path",
    "url",
    "rowid",
    "entry_name",
)
TIMESTAMP_LIKE_KEY_RE = re.compile(r"(_at|_time|^timestamp|_timestamp|_date)$")
CONTEXT_EXCLUDED_KEY_RE = re.compile(r"(_hash|_sha256|_hashes|_fingerprint)$")
MAX_CONTEXT_VALUE_LENGTH = 256
MAX_SUMMARY_LENGTH = 240
LABEL_ALIAS_PREFIXES: tuple[str, ...] = ("lnk-",)
_NON_ISO_FORMATS = ("%m/%d/%Y %H:%M:%S", "%Y:%m:%d %H:%M:%S", "%Y:%m:%d %H:%M:%SZ", "%Y-%m-%d %H:%M:%S")
FILE_EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("fs_created_at", "created"),
    ("fs_modified_at", "modified"),
    ("fs_accessed_at", "accessed"),
    ("fs_changed_at", "mft-changed"),
)
# Kept for compatibility with older imports; the generic walker is gone.
TIMESTAMP_EVENT_NAMES: dict[str, str] = {
    field.path.rsplit(".", 1)[-1].replace("[*]", "").replace("[]", ""): field.label
    for fields in TIMELINE_FIELD_MAP.values()
    for field in fields
}


# Bounded display previews (the full value stays in the source record):
# disclosed, not promoted to a step warning (R2-A eventlog contract).
PREVIEW_TRUNCATION_FLAGS = frozenset(
    {"event_message_truncated", "message_truncated", "event_data_truncated", "text_truncated", "preview_truncated", "local_file_truncated"}
)
PREVIEW_TRUNCATION_COUNTS = frozenset({"text_truncated_rows", "preview_truncated_rows"})
DOS_ZERO_SENTINEL = dt.datetime(1980, 1, 1, tzinfo=dt.timezone.utc)
REFERENCE_BASIS_NOW = "now"


class TimelineStats:
    """Counters disclosed in ``timeline.json`` summary.

    ``now`` is the reference time of the plausibility window (upper bound =
    reference + 1 day); ``reference_basis`` says where it came from
    (``now``, ``run-start``, ``acquisition``).
    """

    def __init__(self, *, now: dt.datetime | None = None, reference_basis: str = REFERENCE_BASIS_NOW) -> None:
        if now is not None and now.tzinfo is None:
            now = now.replace(tzinfo=dt.timezone.utc)
        self.now = now or dt.datetime.now(dt.timezone.utc)
        self.reference_basis = reference_basis if now is not None else REFERENCE_BASIS_NOW
        self.label_merges: Counter[str] = Counter()
        self.key_level_collapsed: Counter[str] = Counter()
        self.aggregate_types_skipped: Counter[str] = Counter()
        self.build_stamp_fields: Counter[str] = Counter()
        self.cross_record_merges = 0
        self.timezone_relabelled = 0
        # Row-level truncation seen while streaming every artifact row (the
        # run steps promote it to step warnings): kind -> Counter.
        self.row_truncation_flags: dict[str, Counter[str]] = {}
        self.row_truncation_counts: dict[str, Counter[str]] = {}
        self.row_truncation_rows: Counter[str] = Counter()
        self.row_preview_flags: dict[str, Counter[str]] = {}
        self.row_preview_counts: dict[str, Counter[str]] = {}
        self.row_preview_rows: Counter[str] = Counter()
        # Capped scans that say how many candidates they skipped
        # (synthetic-media ``unscanned_candidate_count``): kind -> coverage.
        self.scan_coverage: dict[str, dict[str, object]] = {}
        self.out_of_range: Counter[str] = Counter()
        self.out_of_range_by_type: Counter[str] = Counter()
        self.out_of_range_samples: list[dict[str, object]] = []
        self.unparseable: Counter[str] = Counter()
        self.duplicates: Counter[str] = Counter()
        self.merged_detections = 0
        self.unmapped_types: Counter[str] = Counter()
        self.excluded_types: Counter[str] = Counter()
        self.copy_time_candidates = 0
        self.legacy_file_time_events = 0
        self.evidence_timezone: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "out_of_range_excluded_count": sum(self.out_of_range.values()),
            "out_of_range_reason_counts": dict(self.out_of_range),
            "out_of_range_by_event_type": dict(self.out_of_range_by_type.most_common(50)),
            "out_of_range_samples": self.out_of_range_samples,
            "unparseable_timestamp_count": sum(self.unparseable.values()),
            "unparseable_by_field": dict(self.unparseable.most_common(50)),
            "duplicate_events_removed": sum(self.duplicates.values()),
            "duplicate_events_by_type": dict(self.duplicates.most_common(50)),
            "eventlog_detections_merged": self.merged_detections,
            "unmapped_artifact_type_counts": dict(self.unmapped_types.most_common(100)),
            "excluded_artifact_type_counts": dict(self.excluded_types.most_common(100)),
            "acquisition_copy_time_candidates_not_emitted": self.copy_time_candidates,
            "legacy_file_time_events": self.legacy_file_time_events,
            "label_variants_merged": sum(self.label_merges.values()),
            "label_variants_merged_by_type": dict(self.label_merges.most_common(50)),
            "cross_record_merges": self.cross_record_merges,
            "key_level_events_collapsed": sum(self.key_level_collapsed.values()),
            "key_level_events_collapsed_by_type": dict(self.key_level_collapsed.most_common(20)),
            "aggregate_rows_not_emitted": dict(self.aggregate_types_skipped),
            "build_stamp_fields_not_emitted": dict(self.build_stamp_fields),
            "build_stamp_note": BUILD_STAMP_NOTE,
            "offset_timezone_relabelled_utc": self.timezone_relabelled,
            "input_row_truncation": self.row_truncation_disclosure(),
            "valid_range": {
                "min": MIN_PLAUSIBLE.isoformat(),
                "max": self.max_plausible().isoformat(),
                "max_basis": f"{self.reference_basis} + 1 day",
                "reference_time": self.now.isoformat(),
                "invalid_sentinels": ["1980-01-01T00:00:00 (DOS zero)", "1601-01-01 (FILETIME zero)"],
            },
        }

    def max_plausible(self) -> dt.datetime:
        return self.now + dt.timedelta(days=1)

    def observe_row_truncation(self, kind: str, artifact_type: str, details: Mapping[str, object]) -> None:
        """Count ``*_truncated: true`` flags, ``scan_capped`` and numeric
        ``*_truncated_rows``/``*_truncated_count`` disclosures of one row.

        Bounded display previews (EVTX message/EventData previews, the
        ``text_truncated_rows`` tally) are disclosed separately from cuts of
        evidence payloads (command lines, script blocks, reference lists,
        ``payload_truncated_rows``): only the latter become step warnings.
        """
        flagged = False
        previewed = False
        unscanned = details.get("unscanned_candidate_count")
        if details.get("scan_capped") is True and isinstance(unscanned, int) and unscanned > 0:
            scanned = int(details.get("scan_file_count") or 0)
            skipped = int(details.get("skipped_oversize_count") or 0)
            self.scan_coverage[kind] = {
                "unscanned": unscanned,
                "scanned": scanned,
                "candidates": scanned + skipped + unscanned,
                "reason": str(details.get("scan_cap_reason") or "max-files"),
                "max_files": details.get("max_files"),
                "cpu_budget_seconds": details.get("scan_cpu_budget_seconds"),
            }
        for key, value in details.items():
            name = str(key)
            if value is True and (name.endswith("_truncated") or name in ("truncated", "scan_capped", "capped")):
                if name.endswith("may_be_truncated"):
                    continue
                if name in PREVIEW_TRUNCATION_FLAGS:
                    self.row_preview_flags.setdefault(kind, Counter())[f"{artifact_type}.{name}"] += 1
                    previewed = True
                    continue
                self.row_truncation_flags.setdefault(kind, Counter())[f"{artifact_type}.{name}"] += 1
                flagged = True
            elif (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value > 0
                and (name.endswith(("_truncated_rows", "_truncated_count")) or name.startswith("truncated_"))
            ):
                target = self.row_preview_counts if name in PREVIEW_TRUNCATION_COUNTS else self.row_truncation_counts
                target.setdefault(kind, Counter())[name] += value
        if flagged:
            self.row_truncation_rows[kind] += 1
        elif previewed:
            self.row_preview_rows[kind] += 1

    def row_truncation_disclosure(self) -> dict[str, object]:
        kinds = sorted(
            set(self.row_truncation_flags)
            | set(self.row_truncation_counts)
            | set(self.row_preview_flags)
            | set(self.row_preview_counts)
            | set(self.scan_coverage)
        )
        return {
            kind: {
                **({"scan_coverage": dict(self.scan_coverage[kind])} if kind in self.scan_coverage else {}),
                "rows_with_truncation": self.row_truncation_rows.get(kind, 0),
                "flag_counts": dict(self.row_truncation_flags.get(kind, Counter()).most_common(20)),
                "count_fields": dict(self.row_truncation_counts.get(kind, Counter()).most_common(20)),
                "preview_only_rows": self.row_preview_rows.get(kind, 0),
                "preview_flag_counts": dict(self.row_preview_flags.get(kind, Counter()).most_common(20)),
                "preview_count_fields": dict(self.row_preview_counts.get(kind, Counter()).most_common(20)),
            }
            for kind in kinds
        }


def run_timeline(
    *,
    root: Path | None = None,
    input_kind: str | None = None,
    files_inputs: Sequence[Path] | None = None,
    docs_inputs: Sequence[Path] | None = None,
    artifacts_inputs: Sequence[Path] | None = None,
    rule_set: RuleSet | None = None,
    input_payloads: Mapping[str, Mapping[str, object]] | None = None,
    reference_time: dt.datetime | None = None,
    reference_basis: str = "run-start",
) -> dict[str, object]:
    """Build the timeline payload.

    ``reference_time`` (run start or acquisition time, when known) bounds the
    plausible range at reference + 1 day instead of the wall clock.
    """
    input_root = resolve_input_root(root or Path.cwd(), kind=input_kind)
    normalized_files = normalize_input_paths(files_inputs)
    normalized_docs = normalize_input_paths(docs_inputs)
    normalized_artifacts = normalize_input_paths(artifacts_inputs)

    if root is None and not normalized_files and not normalized_docs and not normalized_artifacts:
        raise TimelineError("timeline requires a ROOT or at least one --files, --docs, or --artifacts input")

    stats = TimelineStats(now=reference_time, reference_basis=reference_basis)
    builder = TimelineBuilder(stats)
    file_times: dict[str, str] = {}
    file_time_origin = ""
    if normalized_files:
        for input_path in normalized_files:
            payload = load_input_payload(input_path, expected_command="files", input_payloads=input_payloads)
            file_time_origin = file_time_origin or str(_summary(payload).get("time_origin") or "")
            builder.extend(extract_file_events(payload, input_path, stats=stats, file_times=file_times))
    else:
        payload = run_files_scan(input_root, rule_set=rule_set)
        file_time_origin = str(_summary(payload).get("time_origin") or "")
        builder.extend(extract_file_events(payload, Path("generated:files"), stats=stats, file_times=file_times))

    if normalized_docs:
        for input_path in normalized_docs:
            payload = load_input_payload(input_path, expected_command="docs", input_payloads=input_payloads)
            builder.extend(extract_docs_events(payload, input_path, file_times=file_times))
    else:
        builder.extend(
            extract_document_candidate_events(scan_document_candidates(input_root), Path("generated:docs"), file_times=file_times)
        )

    if normalized_artifacts:
        for input_path in normalized_artifacts:
            payload = load_input_payload(input_path, expected_command="artifacts", input_payloads=input_payloads)
            builder.extend(extract_artifact_events(payload, input_path, stats=stats))
    else:
        for kind in SUPPORTED_ARTIFACT_KINDS:
            payload = run_artifact_collection(input_root, kind=kind, rule_set=rule_set)
            builder.extend(extract_artifact_events(payload, Path(f"generated:artifacts:{kind}"), stats=stats))

    events = builder.events()
    events.sort(key=event_sort_key)
    event_type_counts = Counter(str(event["event_type"]) for event in events)
    source_counts = Counter(str(event["source"]) for event in events)
    kind_counts = Counter(str(event.get("timestamp_kind") or "") for event in events)
    timestamps = [str(event["timestamp"]) for event in events]

    payload = {
        "command": "timeline",
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "inputs": {
            "files": [str(path) for path in normalized_files],
            "docs": [str(path) for path in normalized_docs],
            "artifacts": [str(path) for path in normalized_artifacts],
        },
        "summary": {
            "input_file_count": len(normalized_files) + len(normalized_docs) + len(normalized_artifacts),
            "event_count": len(events),
            "source_counts": dict(source_counts),
            "event_type_counts": dict(event_type_counts),
            "timestamp_kind_counts": dict(kind_counts),
            "earliest_event_at": timestamps[0] if timestamps else None,
            "latest_event_at": timestamps[-1] if timestamps else None,
            "timezone": build_timezone_disclosure(stats.evidence_timezone),
            "file_time_origin": file_time_origin or "unknown",
            "time_policy": {
                "event_sources": "아티팩트 내부 시각(TIMELINE_FIELD_MAP)과 파일시스템 fs_* 시각만 사용",
                "acquisition_copy_times": "취득 사본의 호스트 시각(source_file_*·사본 stat)은 이벤트로 쓰지 않음",
                "dedupe_key": "(source record, timestamp): 같은 레코드·같은 시각의 라벨 변형은 labels[]로 한 이벤트",
                "key_level_times": "ShimCache/UserAssist/BAM 키 LastWrite는 키당 한 이벤트",
                "inventory_key_times": (
                    "Amcache 인벤토리(드라이버·장치·바로 가기·DeviceCensus) 하위 키 LastWrite는 인벤토리 재작성 시각이므로 "
                    "하이브·섹션당 한 이벤트(가장 많은 키가 가진 시각)로 묶고 키별 시각 분포는 details에 둠"
                ),
                "aggregate_rows": "행별 아티팩트 시각을 복사한 집계 행(browser-history-downloads, logon-session 등)은 이벤트로 쓰지 않음",
                "build_stamps": BUILD_STAMP_NOTE,
                "local_unknown": "timezone=local-unknown 시각은 오프셋 없이(+00:00 미부착) 원문 벽시계 시각으로 저장",
            },
            **stats.as_dict(),
        },
        "events": events,
    }
    if rule_set is not None:
        annotate_timeline_payload(payload, rule_set)
    return payload


def _summary(payload: Mapping[str, object]) -> Mapping[str, object]:
    summary = payload.get("summary")
    return summary if isinstance(summary, Mapping) else {}


class TimelineBuilder:
    """Collects events: one event per ``(source record, timestamp)``.

    A second event of the same record and instant (a label variant such as
    ``run``/``run-1``, ``created``/``cookie-created``, accessed == modified,
    or the same URL's ``last-visited``/``visited``) is merged into the first:
    its label joins ``labels`` and, when it came from another artifact row,
    the row is listed in ``details.also_in``. An ``eventlog-detection`` for
    the same record/time as its ``eventlog-event`` is merged into that event
    (``details.detections``) instead of becoming a second event.
    """

    MAX_ALSO_IN = 5

    def __init__(self, stats: TimelineStats) -> None:
        self.stats = stats
        self._events: list[dict[str, object]] = []
        self._index: dict[tuple[str, str], int] = {}

    def extend(self, events: Iterable[dict[str, object]]) -> None:
        for event in events:
            self.add(event)

    def add(self, event: dict[str, object]) -> None:
        record_key = event.pop("record_key", None)
        scope = event.pop("_scope", "row")
        if not record_key:
            self._events.append(event)
            return
        key = (str(record_key), _instant_key(event.get("timestamp")))
        existing_index = self._index.get(key)
        if existing_index is None:
            self._index[key] = len(self._events)
            self._events.append(event)
            return
        existing = self._events[existing_index]
        if _merge_eventlog_detection(existing, event):
            self.stats.merged_detections += 1
            return
        event_type = str(event.get("event_type"))
        if scope == "key":
            self.stats.key_level_collapsed[event_type] += 1
        incoming_label = str(event.get("timestamp_kind") or "")
        labels = _event_labels(existing)
        new_labels = [label for label in _event_labels(event) if label not in labels]
        if new_labels:
            existing["labels"] = [*labels, *new_labels]
            self.stats.label_merges[event_type] += 1
        elif scope != "key":
            self.stats.duplicates[event_type] += 1
        existing_details = existing.get("details") if isinstance(existing.get("details"), dict) else None
        incoming_details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
        if existing_details is not None and scope != "key":
            existing_record = existing_details.get("source_record")
            incoming_record = incoming_details.get("source_record")
            if isinstance(incoming_record, Mapping) and incoming_record != existing_record:
                also_in = existing_details.setdefault("also_in", [])
                if isinstance(also_in, list) and len(also_in) < self.MAX_ALSO_IN:
                    also_in.append(
                        {
                            "artifact_type": incoming_details.get("artifact_type"),
                            "label": incoming_label,
                            **{k: v for k, v in incoming_record.items() if k in ("output", "row_index")},
                        }
                    )
                self.stats.cross_record_merges += 1

    def events(self) -> list[dict[str, object]]:
        return self._events


def _event_labels(event: Mapping[str, object]) -> list[str]:
    labels = event.get("labels")
    if isinstance(labels, list) and labels:
        return [str(label) for label in labels]
    kind = str(event.get("timestamp_kind") or "")
    return [kind] if kind else []


def _instant_key(value: object) -> str:
    """Same instant, same key (``Z``/``+00:00``/7-digit fractions agree)."""
    parsed = parse_iso_utc(value)
    return parsed.isoformat() if parsed is not None else str(value)


def _merge_eventlog_detection(existing: dict[str, object], incoming: dict[str, object]) -> bool:
    existing_details = existing.get("details") if isinstance(existing.get("details"), dict) else {}
    incoming_details = incoming.get("details") if isinstance(incoming.get("details"), dict) else {}
    pair = {existing_details.get("artifact_type"), incoming_details.get("artifact_type")}
    if pair != EVENTLOG_TYPES:
        return False
    if incoming_details.get("artifact_type") == "eventlog-event":
        # The detection arrived first: keep it as the merged row but adopt the
        # event's category/type so the timeline still shows the event.
        detection = dict(existing_details)
        existing["event_type"] = incoming["event_type"]
        existing["summary"] = incoming["summary"]
        existing["details"] = {**incoming_details, "detections": [_detection_brief(detection)]}
        return True
    detections = existing_details.setdefault("detections", [])
    if isinstance(detections, list):
        detections.append(_detection_brief(incoming_details))
    existing_details["has_detection"] = True
    return True


def _detection_brief(details: Mapping[str, object]) -> dict[str, object]:
    rule = details.get("rule")
    brief: dict[str, object] = {}
    if isinstance(rule, Mapping):
        brief["rule_id"] = rule.get("id")
        brief["rule_title"] = rule.get("title") or rule.get("name")
    for key in ("risk_score", "risk_flags", "source_record"):
        if details.get(key) not in (None, "", []):
            brief[key] = details.get(key)
    return brief


def normalize_input_paths(paths: Sequence[Path] | None) -> list[Path]:
    normalized: list[Path] = []
    seen: set[str] = set()
    for raw_path in paths or ():
        resolved = Path(raw_path).expanduser().resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(resolved)
    return normalized


def load_input_payload(
    path: Path,
    *,
    expected_command: str,
    input_payloads: Mapping[str, Mapping[str, object]] | None = None,
) -> Mapping[str, object]:
    if input_payloads:
        override = input_payloads.get(str(path.expanduser().resolve()))
        if override is not None:
            return validate_input_payload(override, path, expected_command=expected_command)
    if not path.is_file():
        raise TimelineError(f"timeline input does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TimelineError(f"timeline input is not valid JSON: {path}") from exc
    return validate_input_payload(payload, path, expected_command=expected_command)


def validate_input_payload(
    payload: object,
    path: Path,
    *,
    expected_command: str,
) -> Mapping[str, object]:
    if not isinstance(payload, Mapping):
        raise TimelineError(f"timeline input must be a JSON object: {path}")
    if payload.get("command") != expected_command:
        actual = payload.get("command")
        raise TimelineError(f"timeline input {path} must have command={expected_command!r} (got {actual!r})")
    return payload


# --- timestamp normalization ----------------------------------------------


def parse_event_timestamp(value: object) -> dt.datetime | None:
    """ISO (``Z``/offset/naive = UTC) or the few non-ISO artifact formats."""
    parsed = parse_iso_utc(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, str):
        return None
    text = value.strip()
    for pattern in _NON_ISO_FORMATS:
        try:
            moment = dt.datetime.strptime(text, pattern)
        except ValueError:
            continue
        return moment.replace(tzinfo=dt.timezone.utc)
    return None


def normalize_event_timestamp(
    value: object,
    *,
    stats: TimelineStats | None,
    event_type: str,
    field_path: str,
    timezone: str = "UTC",
) -> str | None:
    """Normalized text for ``value``; ``None`` when missing, unparseable or out of range."""
    normalized = normalize_event_time(value, stats=stats, event_type=event_type, field_path=field_path, timezone=timezone)
    return normalized[0] if normalized is not None else None


def normalize_event_time(
    value: object,
    *,
    stats: TimelineStats | None,
    event_type: str,
    field_path: str,
    timezone: str = "UTC",
) -> tuple[str, str, str] | None:
    """``(text, timezone, source_timezone)`` for an evidence time, or ``None``.

    * UTC/offset values are stored as UTC ISO (``+00:00``). A value that
      carries its own offset is UTC once converted: it is labelled ``UTC``
      with the original label in ``source_timezone`` (EXIF ``+09:00``).
    * A naive value labelled with an offset (``+09:00``) is converted with it.
    * ``local-unknown`` (and ``exif-local``) naive values keep the wall-clock
      text without an offset: appending ``+00:00`` would claim UTC.

    Range: before 1980-01-01, the DOS-zero sentinel 1980-01-01T00:00:00 and
    after reference + 1 day are excluded and counted.
    """
    if value in (None, "", 0):
        return None
    parsed = parse_event_timestamp(value)
    if parsed is None:
        if stats is not None:
            stats.unparseable[field_path] += 1
        return None
    text = str(value).strip() if isinstance(value, str) else ""
    has_offset = bool(text) and _has_explicit_offset(text)
    tz_label = str(timezone or "UTC")
    source_timezone = ""
    local = tz_label in LOCAL_TIMEZONE_LABELS and not has_offset and bool(text)
    if not local and _OFFSET_LABEL_RE.match(tz_label):
        if not has_offset and text:
            offset = _parse_offset_label(tz_label)
            parsed = parsed.replace(tzinfo=dt.timezone(offset)).astimezone(dt.timezone.utc)
        source_timezone = tz_label
        tz_label = "UTC"
        if stats is not None:
            stats.timezone_relabelled += 1
    elif tz_label in LOCAL_TIMEZONE_LABELS and has_offset:
        source_timezone = tz_label
        tz_label = "UTC"
    if stats is not None:
        reason = ""
        if parsed < MIN_PLAUSIBLE:
            reason = "before-1980"
        elif parsed == DOS_ZERO_SENTINEL:
            reason = "dos-zero-sentinel"
        elif parsed > stats.max_plausible():
            reason = f"after-{stats.reference_basis}-plus-1d"
        if reason:
            stats.out_of_range[reason] += 1
            stats.out_of_range_by_type[event_type] += 1
            if len(stats.out_of_range_samples) < 20:
                stats.out_of_range_samples.append({"event_type": event_type, "field": field_path, "value": str(value)})
            return None
    if local:
        return parsed.replace(tzinfo=None).isoformat(), tz_label, source_timezone
    if text and _is_utc_iso_text(text) and not source_timezone:
        return (text.replace("Z", "+00:00") if text.endswith("Z") else text), tz_label, source_timezone
    return parsed.isoformat(), tz_label, source_timezone


_EXPLICIT_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def _has_explicit_offset(text: str) -> bool:
    return len(text) >= 19 and text[10:11] in ("T", " ") and bool(_EXPLICIT_OFFSET_RE.search(text))


def _parse_offset_label(label: str) -> dt.timedelta:
    sign = -1 if label.startswith("-") else 1
    digits = label[1:].replace(":", "")
    return sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))


def _is_utc_iso_text(text: str) -> bool:
    return len(text) >= 19 and text[4] == "-" and text[10] == "T" and (text.endswith("+00:00") or text.endswith("Z"))


# --- files / docs ------------------------------------------------------------


def extract_file_events(
    payload: Mapping[str, object],
    input_path: Path,
    *,
    stats: TimelineStats | None = None,
    file_times: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    """Events for filesystem (``fs_*``) times only.

    Acquisition-copy host times (``source_file_*``, or ``modified_at`` with
    ``modified_at_origin == "acquisition-copy"``) are counted, never
    emitted. A legacy payload without provenance fields still yields its
    ``modified_at`` event flagged ``time_origin: unknown-legacy``.
    """
    events: list[dict[str, object]] = []
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        path = str(candidate.get("path", ""))
        name = str(candidate.get("name") or Path(path).name)
        fields: list[tuple[str, str, object]] = [
            (field, label, candidate.get(field)) for field, label in FILE_EVENT_FIELDS if candidate.get(field)
        ]
        origin = str(candidate.get("time_origin") or "")
        legacy = "modified_at_origin" not in candidate and "time_origin" not in candidate
        if not fields:
            if legacy and candidate.get("modified_at"):
                fields = [("modified_at", "modified", candidate.get("modified_at"))]
                if stats is not None:
                    stats.legacy_file_time_events += 1
            elif stats is not None and (candidate.get("source_file_mtime") or origin == "acquisition-copy"):
                stats.copy_time_candidates += 1
        for field, label, raw in fields:
            event_type = f"file-{label}"
            timestamp = normalize_event_timestamp(raw, stats=stats, event_type=event_type, field_path=f"files.{field}")
            if timestamp is None:
                continue
            if file_times is not None and field in {"fs_modified_at", "modified_at"}:
                file_times[path] = timestamp
            events.append(
                {
                    "timestamp": timestamp,
                    "timestamp_kind": label,
                    "timezone": "UTC",
                    "source": "files",
                    "event_type": event_type,
                    "path": path,
                    "input_file": str(input_path),
                    "summary": f"파일 {label}: {name}",
                    "details": {
                        "name": candidate.get("name"),
                        "extension": candidate.get("extension"),
                        "size": candidate.get("size"),
                        "categories": list(candidate.get("categories", [])),
                        "field": field,
                        "time_origin": "unknown-legacy" if legacy else (candidate.get("modified_at_origin") or origin),
                        "is_deleted": candidate.get("is_deleted"),
                    },
                    "record_key": f"file:{path}",
                }
            )
    return events


def extract_document_candidate_events(
    candidates: Sequence[object],
    input_path: Path,
    *,
    file_times: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    """Document candidates have no evidence time of their own; only a known
    filesystem time of the same path (from files.json) is used."""
    events: list[dict[str, object]] = []
    for candidate in candidates:
        path = str(getattr(candidate, "path", "") or "")
        timestamp = (file_times or {}).get(path)
        if not path or not timestamp:
            continue
        events.append(
            {
                "timestamp": timestamp,
                "timestamp_kind": "modified",
                "timezone": "UTC",
                "source": "docs",
                "event_type": "document-modified",
                "path": path,
                "input_file": str(input_path),
                "summary": f"문서 수정: {Path(path).name}",
                "details": {"kind": str(getattr(candidate, "kind", "")), "size": getattr(candidate, "size", None)},
                "record_key": f"doc:{path}",
            }
        )
    return events


def extract_docs_events(
    payload: Mapping[str, object],
    input_path: Path,
    *,
    file_times: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    """Keyword hits placed at the document's filesystem modified time (when known)."""
    events: list[dict[str, object]] = []
    candidates_by_path = {
        str(candidate.get("path")): candidate
        for candidate in payload.get("candidates", [])
        if isinstance(candidate, dict) and candidate.get("path")
    }
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        path = str(result.get("path", ""))
        timestamp = (file_times or {}).get(path)
        if timestamp is None:
            continue
        candidate = candidates_by_path.get(path, {})
        matched_keywords = [str(keyword) for keyword in result.get("matched_keywords", [])]
        kind = str(result.get("kind", candidate.get("kind", "")))
        events.append(
            {
                "timestamp": timestamp,
                "timestamp_kind": "modified",
                "timezone": "UTC",
                "source": "docs",
                "event_type": "document-keyword-hit",
                "path": path,
                "input_file": str(input_path),
                "summary": build_document_summary(path, matched_keywords),
                "details": {
                    "kind": kind,
                    "matched_keywords": matched_keywords,
                    "preview": result.get("preview"),
                    "size": result.get("size", candidate.get("size")),
                },
            }
        )
    return events


def build_document_summary(path: str, matched_keywords: Sequence[str]) -> str:
    label = Path(path).name or path
    if matched_keywords:
        return f"Document keyword hit: {label} ({', '.join(matched_keywords)})"
    return f"Document keyword hit: {label}"


# --- artifacts ---------------------------------------------------------------


def extract_artifact_events(
    payload: Mapping[str, object],
    input_path: Path,
    *,
    stats: TimelineStats | None = None,
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    inventory = InventoryKeyTimes()
    kind = str(payload.get("kind", ""))
    present_types = _payload_artifact_types(payload)
    # JSONL-backed run payloads keep only a preview inline; stream every row
    # (profile-expanded) from ``records_path`` instead. ``row_index`` matches
    # the case DB's ``/artifacts/<row_index>`` locator.
    for row_index, artifact in enumerate(iter_payload_records(payload, payload_path=input_path)):
        artifact_type = str(artifact.get("artifact_type", "artifact"))
        artifact_path = str(artifact.get("path", ""))
        provider = str(artifact.get("provider", ""))
        details = artifact.get("details")
        if not isinstance(details, dict):
            continue
        if stats is not None:
            if stats.evidence_timezone is None:
                stats.evidence_timezone = detect_evidence_timezone(artifact_type, details)
            stats.observe_row_truncation(kind, artifact_type, details)
        superseded_by = TIMELINE_AGGREGATE_TYPES.get(artifact_type)
        if superseded_by and present_types & set(superseded_by):
            if stats is not None:
                stats.aggregate_types_skipped[artifact_type] += 1
            continue
        if stats is not None:
            for field_name in TIMELINE_BUILD_STAMP_FIELDS.get(artifact_type, ()):
                if details.get(field_name) not in (None, "", 0):
                    stats.build_stamp_fields[f"{artifact_type}.{field_name}"] += 1
        source_record = {"output": f"artifacts_{kind}" if kind else "", "row_index": row_index}
        for detail_event in iter_artifact_detail_events(artifact_type, details, stats=stats):
            event_type = str(detail_event["event_type"])
            normalized = normalize_event_time(
                detail_event["timestamp"],
                stats=stats,
                event_type=event_type,
                field_path=f"{artifact_type}.{detail_event['field_path']}",
                timezone=str(detail_event.get("timezone") or "UTC"),
            )
            if normalized is None:
                continue
            timestamp, timezone, source_timezone = normalized
            if detail_event.get("scope") == "inventory":
                inventory.add(
                    artifact_type=artifact_type,
                    details=details,
                    detail_event=detail_event,
                    timestamp=timestamp,
                    timezone=timezone,
                    kind=kind,
                    provider=provider,
                    source_record=source_record,
                )
                continue
            context = compact_event_context(detail_event["context"], event_path=artifact_path)
            identity = detail_event.get("identity") or _record_identity(details) or f"row={row_index}"
            element_identity = str(detail_event.get("element_identity") or "")
            event_details: dict[str, object] = {
                "kind": kind,
                "provider": provider,
                "artifact_type": artifact_type,
                "field_path": detail_event["field_path"],
                "source_record": source_record,
                **context,
            }
            if element_identity:
                event_details["element"] = _short(element_identity, MAX_CONTEXT_VALUE_LENGTH)
            if source_timezone:
                event_details["source_timezone"] = source_timezone
            event: dict[str, object] = {
                "timestamp": timestamp,
                "timestamp_kind": detail_event["timestamp_kind"],
                "timezone": timezone,
                "source": "artifacts",
                "event_type": event_type,
                "path": artifact_path,
                "summary": _short(build_artifact_summary(artifact_type, artifact_path, context), MAX_SUMMARY_LENGTH),
                "details": event_details,
                "record_key": f"{artifact_path}|{identity}|{element_identity}",
                "_scope": detail_event.get("scope") or "row",
            }
            extra_labels = [label for label in detail_event.get("extra_labels") or () if label != event["timestamp_kind"]]
            if extra_labels:
                event["labels"] = [event["timestamp_kind"], *dict.fromkeys(extra_labels)]
                if stats is not None:
                    stats.label_merges[event_type] += len(event["labels"]) - 1
            events.append(event)
    events.extend(inventory.events(stats))
    return events


class _InventoryGroup:
    __slots__ = ("event_type", "field_path", "first_value", "kind", "provider", "sample_key", "source_record", "times", "timestamp_kind", "timezone")

    def __init__(
        self,
        *,
        event_type: str,
        timestamp_kind: str,
        field_path: str,
        timezone: str,
        kind: str,
        provider: str,
        source_record: dict[str, object],
    ) -> None:
        self.event_type = event_type
        self.timestamp_kind = timestamp_kind
        self.field_path = field_path
        self.timezone = timezone
        self.kind = kind
        self.provider = provider
        self.source_record = source_record
        self.times: Counter[str] = Counter()
        self.first_value: dict[str, str] = {}
        self.sample_key: dict[str, str] = {}


class InventoryKeyTimes:
    """One event per (hive, section, artifact type) for ``scope="inventory"``
    key times: the instant most keys share (the inventory rewrite; ties go to
    the latest), with the per-key time distribution in ``details``."""

    MAX_LISTED_TIMES = 10

    def __init__(self) -> None:
        self._groups: dict[tuple[str, str, str], _InventoryGroup] = {}

    def add(
        self,
        *,
        artifact_type: str,
        details: Mapping[str, object],
        detail_event: Mapping[str, object],
        timestamp: str,
        timezone: str,
        kind: str,
        provider: str,
        source_record: Mapping[str, object],
    ) -> None:
        source_path = str(details.get("source_path") or "")
        section = str(details.get("section") or artifact_type)
        key = (source_path, section, artifact_type)
        group = self._groups.get(key)
        if group is None:
            group = _InventoryGroup(
                event_type=str(detail_event["event_type"]),
                timestamp_kind=str(detail_event["timestamp_kind"]),
                field_path=str(detail_event["field_path"]),
                timezone=timezone,
                kind=kind,
                provider=provider,
                source_record=dict(source_record),
            )
            self._groups[key] = group
        second = _instant_key(timestamp)[:19]
        group.times[second] += 1
        group.first_value.setdefault(second, timestamp)
        group.sample_key.setdefault(second, str(details.get("key_name") or details.get("key_path") or ""))

    def events(self, stats: TimelineStats | None) -> list[dict[str, object]]:
        output: list[dict[str, object]] = []
        for (source_path, section, artifact_type), group in self._groups.items():
            times = group.times
            first_value = group.first_value
            sample_key = group.sample_key
            dominant = max(times.items(), key=lambda item: (item[1], item[0]))[0]
            key_count = sum(times.values())
            event_type = group.event_type
            if stats is not None and key_count > 1:
                stats.key_level_collapsed[event_type] += key_count - 1
            ordered = sorted(times)
            listed = sorted(times.most_common(self.MAX_LISTED_TIMES), key=lambda item: item[0])
            output.append(
                {
                    "timestamp": first_value[dominant],
                    "timestamp_kind": group.timestamp_kind,
                    "timezone": group.timezone,
                    "source": "artifacts",
                    "event_type": event_type,
                    "path": source_path,
                    "summary": _short(
                        f"{artifact_type}: {section} 인벤토리 키 {key_count}개 최종 수정(대표 시각, 서로 다른 시각 {len(times)}개)",
                        MAX_SUMMARY_LENGTH,
                    ),
                    "details": {
                        "kind": group.kind,
                        "provider": group.provider,
                        "artifact_type": artifact_type,
                        "field_path": group.field_path,
                        "source_record": group.source_record,
                        "scope": "inventory",
                        "section": section,
                        "source_path": source_path,
                        "key_count": key_count,
                        "keys_at_timestamp": times[dominant],
                        "distinct_key_times": len(times),
                        "key_time_min": first_value[ordered[0]],
                        "key_time_max": first_value[ordered[-1]],
                        "key_times": [
                            {"timestamp": first_value[second], "key_count": count, "sample_key": _short(sample_key[second], 160)}
                            for second, count in listed
                        ],
                        "key_times_truncated": len(times) > self.MAX_LISTED_TIMES,
                        "note": "인벤토리 하위 키 LastWrite(재작성 시각) — 설치·연결·실행 시각 아님",
                    },
                }
            )
        return output


def _payload_artifact_types(payload: Mapping[str, object]) -> set[str]:
    summary = payload.get("summary")
    counts = summary.get("artifact_type_counts") if isinstance(summary, Mapping) else None
    if isinstance(counts, Mapping):
        return {str(name) for name, count in counts.items() if count}
    rows = payload.get("artifacts")
    if isinstance(rows, list) and not (payload.get("records_path") or payload.get("records_file")):
        return {str(row.get("artifact_type")) for row in rows if isinstance(row, Mapping)}
    return set()


def _record_identity(details: Mapping[str, object]) -> str:
    for key in RECORD_IDENTITY_FIELDS:
        value = details.get(key)
        if value not in (None, "", []):
            return f"{key}={value}"
    return ""


def canonical_label(label: str, artifact_type: str = "") -> str:
    """One spelling per label family: ``last-arrival-at`` -> ``last-arrival``,
    ``cookie-created`` (browser-cookie) -> ``created``, ``lnk-target-accessed``
    -> ``target-accessed``. Numbered labels (``run-1``) are kept."""
    text = normalize_kind_label(label)
    if text.endswith("-at") and len(text) > 3:
        text = text[:-3]
    for prefix in LABEL_ALIAS_PREFIXES:
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix) :]
            break
    nouns = {part for part in artifact_type.split("-") if len(part) > 2}
    head, _, rest = text.partition("-")
    if rest and head in nouns and not rest.isdigit():
        text = rest
    return text or "observed"


def _instant(value: object) -> str:
    parsed = parse_event_timestamp(value)
    return parsed.isoformat() if parsed is not None else ""


def _same_instant(events: Sequence[dict[str, object]], value: object) -> dict[str, object] | None:
    instant = _instant(value)
    if not instant:
        return None
    return next((event for event in events if _instant(event["timestamp"]) == instant), None)


def iter_artifact_detail_events(
    artifact_type: str,
    details: Mapping[str, object],
    *,
    stats: TimelineStats | None = None,
) -> Iterable[dict[str, object]]:
    if artifact_type in TIMELINE_EXCLUDED_TYPES:
        if stats is not None:
            stats.excluded_types[artifact_type] += 1
        return
    if artifact_type in EVENTLOG_TYPES:
        event = eventlog_detail_event(artifact_type, details)
        if event is not None:
            yield event
        return
    fields = TIMELINE_FIELD_MAP.get(artifact_type)
    explicit = explicit_row_timestamp(details)
    if fields is None and explicit is None and not details.get("timeline_events"):
        if stats is not None and any(TIMESTAMP_LIKE_KEY_RE.search(str(key)) for key in details):
            stats.unmapped_types[artifact_type] += 1
        return
    base_context = collect_scalar_context(details, skip_keys=set())
    mapped: list[dict[str, object]] = []
    for field in fields or ():
        if explicit is not None and field.path == "timestamp":
            continue
        for value, element, element_identity, label in _resolve_field(details, field):
            canonical = canonical_label(label, artifact_type)
            if field.scope == "inventory":
                mapped.append(
                    {
                        "timestamp": value,
                        "timestamp_kind": canonical,
                        "timezone": field.timezone,
                        "event_type": field.event_type or f"artifact-{artifact_type}-{canonical}",
                        "field_path": f"details.{field.path}",
                        "element_identity": "",
                        "scope": "inventory",
                        "context": {},
                    }
                )
                continue
            if field.scope == "key":
                # One registry key LastWrite shared by every value of the key.
                key_name = str(details.get("source_key") or details.get("key_path") or details.get("source_key_path") or "key")
                mapped.append(
                    {
                        "timestamp": value,
                        "timestamp_kind": canonical,
                        "timezone": field.timezone,
                        "event_type": field.event_type or f"artifact-{artifact_type}-{canonical}",
                        "field_path": f"details.{field.path}",
                        "identity": f"key={key_name}",
                        "element_identity": "",
                        "scope": "key",
                        "context": collect_selected_context(details, ("source_key", "key_path", "source_path", "user", "sid")),
                    }
                )
                continue
            context = base_context if element is None else collect_scalar_context(element, skip_keys=set())
            mapped.append(
                {
                    "timestamp": value,
                    "timestamp_kind": canonical,
                    "timezone": field.timezone,
                    "event_type": field.event_type or f"artifact-{artifact_type}-{canonical}",
                    "field_path": f"details.{field.path}",
                    "element_identity": element_identity,
                    "context": context,
                }
            )
    row_events: list[dict[str, object]] = [
        entry for entry in mapped if entry.get("scope") not in ("key", "inventory") and not entry.get("element_identity")
    ]
    if explicit is not None and any(
        entry.get("scope") == "inventory" and _instant(entry["timestamp"]) == _instant(explicit[0]) for entry in mapped
    ):
        # Amcache inventory rows restate the key LastWrite as the row
        # ``timestamp``: it is the collapsed inventory event, not a row event.
        explicit = None
    if explicit is not None:
        # Row-level contract (W5): ``timestamp`` + ``timestamp_kind`` (+ label /
        # timezone) declares an evidence time. When a mapped row-level field
        # holds the same instant, the explicit label joins that event instead
        # of re-emitting it (tracked by field and value). ``source_file_mtime``
        # is never read.
        value, kind, timezone = explicit
        kind = canonical_label(kind, artifact_type)
        twin = _same_instant(row_events, value)
        if twin is not None:
            twin.setdefault("extra_labels", []).append(kind)
        else:
            explicit_event = {
                "timestamp": value,
                "timestamp_kind": kind,
                "timezone": timezone,
                "event_type": f"artifact-{artifact_type}-{kind}",
                "field_path": "details.timestamp",
                "element_identity": "",
                "context": base_context,
            }
            mapped.insert(0, explicit_event)
            row_events.insert(0, explicit_event)
    # A key LastWrite equal to an entry time of the same row (BAM: the last
    # execution wrote the key) is that entry's event, labelled twice.
    for item in [entry for entry in mapped if entry.get("scope") == "key"]:
        twin = _same_instant(row_events, item["timestamp"])
        if twin is not None:
            twin.setdefault("extra_labels", []).append(str(item["timestamp_kind"]))
            mapped.remove(item)
    for position, item in enumerate(details.get("timeline_events") or ()):
        # Row-level list contract (W2): [{timestamp, timestamp_kind|kind|label, ...}].
        if not isinstance(item, Mapping):
            continue
        kind = item.get("timestamp_kind") or item.get("kind") or item.get("label") or item.get("timestamp_label")
        if item.get("timestamp") in (None, "", 0) or not isinstance(kind, str) or not kind:
            continue
        label = canonical_label(kind, artifact_type)
        yield {
            "timestamp": item.get("timestamp"),
            "timestamp_kind": label,
            "timezone": str(item.get("timestamp_timezone") or item.get("timezone") or "UTC"),
            "event_type": f"artifact-{artifact_type}-{label}",
            "field_path": f"details.timeline_events[{position}].timestamp",
            # Same record as the row: an item repeating a mapped field merges.
            "element_identity": "",
            "context": {**base_context, **collect_scalar_context(item, skip_keys={"timestamp"})},
        }
    yield from mapped


def explicit_row_timestamp(details: Mapping[str, object]) -> tuple[object, str, str] | None:
    """``(timestamp, kind, timezone)`` when a row declares its own evidence time."""
    value = details.get("timestamp")
    kind = details.get("timestamp_kind") or details.get("timestamp_label")
    if value in (None, "", 0) or not isinstance(kind, str) or not kind.strip():
        return None
    timezone = details.get("timestamp_timezone")
    return value, normalize_kind_label(kind), str(timezone) if isinstance(timezone, str) and timezone else "UTC"


def normalize_kind_label(kind: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", kind.strip().lower()).strip("-") or "observed"


def _resolve_field(
    details: Mapping[str, object],
    field: TimelineField,
) -> Iterable[tuple[object, Mapping[str, object] | None, str, str]]:
    """Yield ``(value, list element or None, element identity, label)`` for a field path."""
    parts = field.path.split(".")

    def walk(node: object, index: int, element: Mapping[str, object] | None, identity: str) -> Iterable[tuple]:
        if index == len(parts):
            if node not in (None, "", 0):
                yield node, element, identity, field.label
            return
        part = parts[index]
        if part.endswith("[*]"):
            values = node.get(part[:-3]) if isinstance(node, Mapping) else None
            if isinstance(values, list):
                for position, value in enumerate(values, start=1):
                    if value not in (None, "", 0):
                        # identity omits the position: the label carries it, so
                        # last_run_times[0] and run_time_1 dedupe to one event.
                        yield value, element, identity, f"{field.label}-{position}"
            return
        if part.endswith("[]"):
            items = node.get(part[:-2]) if isinstance(node, Mapping) else None
            if isinstance(items, list):
                for position, item in enumerate(items):
                    if isinstance(item, Mapping):
                        item_identity = _record_identity(item) or f"[{position}]"
                        yield from walk(item, index + 1, item, f"{identity}/{part[:-2]}:{item_identity}")
            return
        child = node.get(part) if isinstance(node, Mapping) else None
        yield from walk(child, index + 1, element, identity)

    yield from walk(details, 0, None, "")


EVENTLOG_CONTEXT_KEYS: tuple[str, ...] = (
    "reportability",
    "record_id",
    "event_id",
    "event_category",
    "event_family",
    "channel",
    "provider_name",
    "computer",
    "user_name",
    "target_user_name",
    "subject_user_name",
    "logon_type",
    "source_ip",
    "destination_ip",
    "process_name",
    "command_line",
    "script_block_text",
    "service_name",
    "risk_score",
    "risk_flags",
    "rule",
)


def eventlog_detail_event(artifact_type: str, details: Mapping[str, object]) -> dict[str, object] | None:
    timestamp = str(details.get("event_created_at") or details.get("timestamp") or "")
    if not timestamp:
        return None
    category = str(details.get("event_category") or "event")
    family = str(details.get("event_family") or "")
    context = collect_selected_context(details, EVENTLOG_CONTEXT_KEYS)
    if not context.get("risk_score"):
        context.pop("risk_score", None)
    return {
        "timestamp": timestamp,
        "timestamp_kind": "event",
        "timezone": "UTC",
        "event_type": f"eventlog-{category}" if artifact_type == "eventlog-event" else "eventlog-detection",
        "field_path": "details.event_created_at" if details.get("event_created_at") else "details.timestamp",
        "identity": f"record_id={details.get('record_id')}" if details.get("record_id") not in (None, "") else "",
        "context": {**context, **({"timeline_family": family or category} if (family or category) != context.get("event_family") else {})},
    }


# Context copied into an event is a pointer, not a copy of the row: the row
# itself stays in the artifacts output (``details.source_record``).
CONTEXT_DROP_KEYS: frozenset[str] = frozenset(
    {
        "parser",
        "parser_version",
        "coverage_status",
        "source_format",
        "commercial_grade_ready",
        "validation_guidance",
        "timestamp",
        "timestamp_kind",
        "timestamp_label",
        "timestamp_timezone",
        "timestamp_source",
        "timestamp_semantics",
        "timestamp_note",
        "event_tags",
        "channel_family",
        "raw_preview",
        "source_file_mtime",
        "source_file_ctime",
        "source_file_atime",
        "row_kind",
        "provider",
        "kind",
        "artifact_type",
        "field_path",
        "source_record",
    }
)
CONTEXT_DROP_KEY_RE = re.compile(r"(_raw|_filetime|droid|_hex|_bytes|_b64|_base64|_mac_address)$|droid_")


def compact_event_context(context: Mapping[str, object], *, event_path: str) -> dict[str, object]:
    """Locator-sized context: no copied tool fields, no other times of the
    row (they are their own events), no ``source_path`` equal to the event
    path, strings shortened."""
    compact: dict[str, object] = {}
    for key, value in context.items():
        name = str(key)
        if name in CONTEXT_DROP_KEYS or CONTEXT_DROP_KEY_RE.search(name):
            continue
        if name in ("source_path", "path") and str(value) == event_path:
            continue
        if TIMESTAMP_LIKE_KEY_RE.search(name):
            continue
        if isinstance(value, str):
            value = _short(value, MAX_CONTEXT_VALUE_LENGTH)
        compact[name] = value
    return compact


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def collect_scalar_context(value: Mapping[str, object], *, skip_keys: set[str]) -> dict[str, object]:
    context: dict[str, object] = {}
    for key, item in value.items():
        if key in skip_keys or isinstance(item, (dict, list)):
            continue
        if CONTEXT_EXCLUDED_KEY_RE.search(str(key)):
            continue
        if isinstance(item, str) and len(item) > MAX_CONTEXT_VALUE_LENGTH:
            item = item[:MAX_CONTEXT_VALUE_LENGTH] + "…"
        context[key] = item
    return context


def collect_selected_context(value: Mapping[str, object], keys: Sequence[str]) -> dict[str, object]:
    context: dict[str, object] = {}
    for key in keys:
        item = value.get(key)
        if item in (None, "", []):
            continue
        if isinstance(item, str) and len(item) > MAX_CONTEXT_VALUE_LENGTH:
            item = item[:MAX_CONTEXT_VALUE_LENGTH] + "…"
        context[key] = item
    return context


# --- timezone disclosure -----------------------------------------------------

TIMEZONE_KEYS: tuple[str, ...] = (
    "evidence_timezone",
    "time_zone_key_name",
    "timezone_key_name",
    "time_zone_name",
    "timezone_name",
    "standard_name",
    "timezone",
    "time_zone",
)
TIMEZONE_BIAS_KEYS: tuple[str, ...] = ("bias_minutes", "active_time_bias_minutes", "utc_offset_minutes", "bias")


def detect_evidence_timezone(artifact_type: str, details: Mapping[str, object]) -> dict[str, object] | None:
    """Evidence time zone from a registry/system summary row (W2 TimeZoneInformation)."""
    if not (artifact_type.startswith(("registry", "windows-system", "windows-timezone", "windows-os")) or "timezone" in artifact_type):
        return None
    structured = details.get("timezone")
    if isinstance(structured, Mapping) and structured:
        # registry-summary.details.timezone (W2): {utc_offset, bias, key_name, label}
        name = structured.get("key_name") or structured.get("time_zone_key_name") or structured.get("label") or structured.get("standard_name")
        bias = structured.get("bias") if isinstance(structured.get("bias"), int) else structured.get("bias_minutes")
        return {
            "name": name,
            "label": structured.get("label"),
            "utc_offset": structured.get("utc_offset"),
            "bias_minutes": bias,
            "artifact_type": artifact_type,
            "source_path": details.get("source_path"),
        }
    candidates: list[Mapping[str, object]] = [details]
    for key in ("time_zone_information", "timezone_information", "timezone_info"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            candidates.insert(0, nested)
    for mapping in candidates:
        name = next((mapping.get(key) for key in TIMEZONE_KEYS if isinstance(mapping.get(key), str) and mapping.get(key)), None)
        if name:
            bias = next((mapping.get(key) for key in TIMEZONE_BIAS_KEYS if isinstance(mapping.get(key), int)), None)
            return {"name": name, "bias_minutes": bias, "artifact_type": artifact_type, "source_path": details.get("source_path")}
    return None


def build_timezone_disclosure(evidence_timezone: Mapping[str, object] | None) -> dict[str, object]:
    return {
        "storage": "UTC",
        "display": "UTC (ISO 8601 +00:00)",
        "evidence_timezone": dict(evidence_timezone) if evidence_timezone else None,
        "evidence_timezone_status": "registry-reported" if evidence_timezone else "not-reported",
        "note": (
            "모든 이벤트 시각은 UTC로 저장합니다. timezone=local-unknown 이벤트(EXIF·ZIP DOS 시각 등)는 "
            "원본이 지역 시각이라 UTC 변환이 검증되지 않았습니다."
        ),
    }


# --- summaries / report ------------------------------------------------------


def field_label(name: str, value: object) -> str:
    return f"{name}={value}" if value not in (None, "") else ""


def build_artifact_summary(artifact_type: str, artifact_path: str, context: Mapping[str, object]) -> str:
    if artifact_type in EVENTLOG_TYPES:
        label = "EventLog detection" if artifact_type == "eventlog-detection" else "EventLog event"
        bits = [
            field_label("id", context.get("event_id")),
            str(context.get("event_category") or ""),
            field_label("channel", context.get("channel")),
            field_label("user", context.get("user_name") or context.get("target_user_name") or context.get("subject_user_name")),
            field_label("src", context.get("source_ip")),
            field_label("cmd", context.get("command_line") or context.get("script_block_text")),
        ]
        return f"{label}: {' '.join(bit for bit in bits if bit)}".strip()
    if "ai_service" in context:
        bits = [
            str(context.get("ai_service") or "AI service"),
            str(context.get("query_hint") or context.get("prompt_hint") or context.get("title") or context.get("url") or ""),
        ]
        return f"AI usage: {' '.join(bit for bit in bits if bit)}".strip()
    if "url" in context:
        return f"Artifact event: {artifact_type} {context['url']}"
    if "source_url" in context:
        return f"Artifact event: {artifact_type} {context['source_url']}"
    if context.get("target_path"):
        return f"Artifact event: {artifact_type} {context['target_path']}"
    if context.get("executable_path"):
        return f"Artifact event: {artifact_type} {context['executable_path']}"
    if context.get("key_path"):
        return f"Artifact event: {artifact_type} {context['key_path']}"
    if "timeline_type" in context and str(context.get("timeline_type") or "").startswith("usn-"):
        label = str(context.get("event_label") or context.get("timeline_type") or "USN timeline candidate")
        path = str(context.get("path_candidate") or context.get("file_name") or "")
        return f"{label} {path}".strip()
    if "entry_name" in context:
        return f"Artifact event: {artifact_type} {context['entry_name']}"
    label = Path(artifact_path).name or artifact_path or artifact_type
    return f"Artifact event: {artifact_type} {label}"


def event_sort_key(event: Mapping[str, object]) -> tuple[float, str, str, str]:
    timestamp_text = str(event.get("timestamp", ""))
    return (
        timestamp_to_epoch(timestamp_text),
        timestamp_text,
        str(event.get("source", "")),
        str(event.get("path", "")),
    )


def timestamp_to_epoch(value: str) -> float:
    if not value:
        return float("-inf")
    parsed = parse_iso_utc(value)
    if parsed is None:
        return float("-inf")
    return (parsed - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)).total_seconds()


def coerce_utc_timestamp(value: object, *, fallback: object = None) -> str | None:
    if isinstance(value, (float, int)) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(float(value), dt.timezone.utc).isoformat()
    parsed = parse_iso_utc(fallback)
    return parsed.isoformat() if parsed is not None else None


def build_timeline_report(payload: Mapping[str, object]) -> str:
    inputs = payload.get("inputs", {})
    summary = payload.get("summary", {})
    events = payload.get("events", [])
    summary = summary if isinstance(summary, Mapping) else {}
    timezone = summary.get("timezone") if isinstance(summary.get("timezone"), Mapping) else {}
    evidence_tz = timezone.get("evidence_timezone") if isinstance(timezone, Mapping) else None

    lines = [
        "# rapidtriage timeline report",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Events: {summary.get('event_count', 0)}",
        f"- Earliest event: `{summary.get('earliest_event_at')}`",
        f"- Latest event: `{summary.get('latest_event_at')}`",
        "",
        "## 시각 기준 / Time basis",
        "",
        "- 저장 시간대: UTC (모든 이벤트 시각은 UTC ISO 8601)",
        (
            f"- 증거 시스템 시간대: `{evidence_tz.get('name')}` (bias {evidence_tz.get('bias_minutes')} min, 레지스트리 보고)"
            if isinstance(evidence_tz, Mapping)
            else "- 증거 시스템 시간대: 보고되지 않음 (레지스트리 TimeZoneInformation 없음)"
        ),
        f"- 파일 시각 출처: `{summary.get('file_time_origin', 'unknown')}`",
        "- 취득 사본 시각(호스트 mtime/ctime/atime)은 증거 시각이 아니므로 이벤트로 넣지 않았습니다"
        f" (사본 시각만 있는 파일 후보 {summary.get('acquisition_copy_time_candidates_not_emitted', 0)}건).",
        f"- 범위 밖 시각 제외: {summary.get('out_of_range_excluded_count', 0)}건 (1980-01-01 이전, DOS 0 시각, "
        f"{_valid_range_max_text(summary)} 이후)",
        f"- 해석 불가 시각: {summary.get('unparseable_timestamp_count', 0)}건",
        f"- 중복 제거: {summary.get('duplicate_events_removed', 0)}건, 라벨 변형 병합: {summary.get('label_variants_merged', 0)}건, "
        f"키 단위 병합: {summary.get('key_level_events_collapsed', 0)}건, 탐지-이벤트 병합: {summary.get('eventlog_detections_merged', 0)}건",
        f"- PE 링크/컴파일 시각(빌드 스탬프)은 이벤트 아님: {sum((summary.get('build_stamp_fields_not_emitted') or {}).values())}개 필드",
        "",
        "## Inputs",
        "",
    ]
    unmapped = summary.get("unmapped_artifact_type_counts")
    if isinstance(unmapped, Mapping) and unmapped:
        insert_at = lines.index("## Inputs")
        lines[insert_at:insert_at] = [
            "### 타임라인 매핑이 없는 아티팩트 유형 (시각 필드 있음, 이벤트 미생성)",
            "",
            *[f"- `{name}`: {count}" for name, count in sorted(unmapped.items())],
            "",
        ]

    if isinstance(inputs, dict):
        for key in ("files", "docs", "artifacts"):
            rows = inputs.get(key, [])
            lines.append(f"### {key}")
            if isinstance(rows, list) and rows:
                for row in rows:
                    lines.append(f"- `{row}`")
            else:
                lines.append("- none")
            lines.append("")

    lines.extend(["## Event type counts", ""])
    event_type_counts = summary.get("event_type_counts", {})
    if isinstance(event_type_counts, dict) and event_type_counts:
        for name, count in sorted(event_type_counts.items()):
            lines.append(f"- `{name}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Timeline", ""])
    if isinstance(events, list) and events:
        for event in events:
            if not isinstance(event, dict):
                continue
            caveat = timeline_report_caveat(event)
            suffix = f" — {caveat}" if caveat else ""
            kind = event.get("timestamp_kind")
            labels = event.get("labels")
            if isinstance(labels, list) and len(labels) > 1:
                kind = "/".join(str(label) for label in labels)
            kind_text = f" [{kind}]" if kind else ""
            lines.append(
                f"- `{event.get('timestamp')}`{kind_text} `{event.get('source')}` `{event.get('event_type')}` "
                f"`{event.get('path')}` — {event.get('summary')}{suffix}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def _valid_range_max_text(summary: Mapping[str, object]) -> str:
    valid = summary.get("valid_range") if isinstance(summary.get("valid_range"), Mapping) else {}
    basis = str(valid.get("max_basis") or "now + 1 day")
    return f"{valid.get('max') or '?'} ({basis})"


def write_timeline_result(payload: Mapping[str, object], output: Path) -> None:
    """Write ``timeline.json``: head keys indented, one compact event per line.

    Same JSON document as ``json.dump`` (readers and the streaming importer
    are unchanged) without the indentation overhead of 300k+ events.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    head = {key: value for key, value in payload.items() if key != "events"}
    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    head_text = json.dumps(head, ensure_ascii=False, indent=2, default=str)
    with output.open("w", encoding="utf-8", newline="\n", buffering=4 * 1024 * 1024) as handle:
        handle.write(head_text[:-1].rstrip())
        handle.write(',\n  "events": [')
        for index, event in enumerate(events):
            handle.write("\n    " if index == 0 else ",\n    ")
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str))
        handle.write("\n  ]\n}\n" if events else "]\n}\n")


def timeline_report_caveat(event: Mapping[str, object]) -> str:
    details = event.get("details")
    if not isinstance(details, Mapping):
        return ""
    bits: list[str] = []
    if event.get("timezone") and event.get("timezone") != "UTC":
        bits.append(f"timezone={event.get('timezone')}")
    if details.get("validation_required") is True:
        bits.append("validation required")
    reportability = details.get("reportability")
    if isinstance(reportability, str) and reportability:
        bits.append(f"reportability={reportability}")
    blockers = details.get("blockers")
    if isinstance(blockers, list):
        visible = [str(item) for item in blockers[:3] if item]
        if visible:
            bits.append(f"blockers={', '.join(visible)}")
    if not bits:
        return ""
    return "Caveat: " + "; ".join(bits)
