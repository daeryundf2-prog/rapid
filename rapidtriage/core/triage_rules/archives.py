"""Archive / encrypted-container indicators (catalogue: apps §7)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Mapping

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    as_list,
    base_name,
    evidence,
    extension,
    parse_time,
    register,
    select,
)

ARCHIVES = select(types={"archive-file-inventory", "archive-entry", "archive-inventory"})
SIGNATURE_ROWS = select(types={"file-signature-mismatch"})
ARCHIVE_SIGNATURES = frozenset({"zip", "zip-ooxml", "7z", "7zip", "rar", "rar5", "gzip", "gz", "cab", "xz", "bzip2", "bz2", "tar", "alz", "egg", "lzh"})
ZIP_FAMILY_EXTENSIONS = frozenset(
    {
        "zip", "docx", "docm", "dotx", "xlsx", "xlsm", "pptx", "pptm", "hwpx", "odt", "ods", "odp", "epub", "jar", "apk", "aab", "xpi",
        "crx", "nupkg", "whl", "vsix", "appx", "msix", "ipa", "kmz", "3mf", "xps", "oxps", "cbz", "war", "ear", "aar", "sketch",
        "7z", "rar", "gz", "tgz", "cab", "xz", "bz2", "tar", "alz", "egg", "lzh", "msu", "xap", "pbix", "vsdx", "one", "onepkg",
    }
)


def profile(row: RowView) -> Mapping[str, object]:
    value = row.get("archive_inventory_profile")
    return value if isinstance(value, Mapping) else {}


def archive_encrypted(row: RowView) -> bool:
    return bool(row.number("encrypted_entry_count")) or as_bool(row.get("encrypted")) is True


@register("archives.enc_archive_with_exfil")
class EncryptedArchiveExfil(Rule):
    """Encrypted archive later referenced by a removable/network shortcut, or written within ``window_hours`` before a USB connection."""

    selector = select(types={"archive-file-inventory", "recent-shortcut", "shell-shortcut"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.archives: list[tuple[RowRef, str, dt.datetime | None]] = []
        self.offline_targets: set[str] = set()

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "archive-file-inventory":
            if archive_encrypted(row):
                self.archives.append((row.ref, base_name(row.path()), parse_time(row.get("source_file_mtime"))))
            return None
        from .lnk import drive_type, lnk_target

        target = lnk_target(row)
        if drive_type(row) in {"removable", "network"} or target.startswith("\\\\") or (len(target) > 1 and target[1] == ":" and target[0].lower() != "c"):
            self.offline_targets.add(base_name(target))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(hours=float(self.param("window_hours", 24)))
        arrivals = sorted(ctx.shared.get("usb_arrivals", []))
        for ref, name, modified in self.archives:
            if name in self.offline_targets:
                yield ref, RuleResult(evidence(archive=name, reason="이동식/네트워크 바로 가기의 대상 이름과 같음"))
                continue
            if modified is not None:
                arrival = next((at for at in arrivals if modified <= at <= modified + window), None)
                if arrival is not None:
                    yield ref, RuleResult(evidence(archive=name, modified=modified, usb_arrival=arrival, reason="작성 직후 USB 연결"))


@register("archives.header_encrypted_list_hidden")
class HeaderEncrypted(Rule):
    """Archive whose file list itself is encrypted (ZIP central-directory encryption, 7z -mhe)."""

    selector = ARCHIVES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        hidden = as_bool(row.get("header_encrypted")) is True or as_bool(profile(row).get("header_encrypted")) is True
        return RuleResult(evidence(archive=base_name(row.path()), format=row.text("archive_format"))) if hidden else None


@register("archives.high_entropy_no_sig")
class HighEntropyNoSignature(Rule):
    """File without a known signature, entropy ≥ ``min_entropy``, size a multiple of 64 and ≥ ``min_bytes`` (VeraCrypt-style container candidate)."""

    selector = select(collections={"artifacts", "files"}, types={"file", "archive-file-inventory", "file-signature-mismatch"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        entropy = row.number("entropy", "shannon_entropy", "content_entropy")
        size = row.number("size", "source_size", "size_bytes")
        if entropy is None or size is None:
            return None
        if entropy < float(self.param("min_entropy", 7.9)) or size < float(self.param("min_bytes", 1024 * 1024)) or int(size) % 64:
            return None
        # A sniffed heuristic kind (``high-entropy-binary`` of the signature scan) is no signature.
        if row.text("signature", "detected_signature_kind", "file_signature") and row.text("detected_content_basis") != "heuristic":
            return None
        return RuleResult(evidence(file=base_name(row.path() or row.text("path")), entropy=entropy, size=int(size)))


@register("archives.ext_mismatch_container")
class ExtensionMismatchContainer(Rule):
    """Archive magic under a non-archive extension (``.dat``, ``.jpg`` …)."""

    selector = SIGNATURE_ROWS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        kind = row.text("detected_signature_kind").lower()
        if kind not in ARCHIVE_SIGNATURES:
            return None
        ext = row.text("actual_extension").lower().lstrip(".") or extension(row.path())
        if ext in ZIP_FAMILY_EXTENSIONS:
            return None
        # Windows 10+ Prefetch (.pf) is MAM/Xpress-compressed: generic sniffers call it an archive.
        if ext in {str(item).lower().lstrip(".") for item in self.param("ignored_extensions", [])}:
            return None
        return RuleResult(evidence(file=base_name(row.path()), extension=ext or "(없음)", signature=kind))


@register("archives.nested_deep")
class NestedDeep(Rule):
    """Archive nesting depth ≥ ``min_depth``."""

    selector = ARCHIVES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        depth = row.number("nested_depth", "max_nested_depth") or profile(row).get("max_nested_depth")
        depth = float(depth) if isinstance(depth, (int, float)) else None
        if depth is None or depth < int(self.param("min_depth", 3)):
            return None
        return RuleResult(evidence(archive=base_name(row.path()), depth=int(depth)))


@register("archives.zip_bomb_ratio")
class ZipBombRatio(Rule):
    """Compression ratio ≥ ``min_ratio`` with ≥ ``min_uncompressed_bytes`` unpacked."""

    selector = ARCHIVES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        ratio = row.number("compression_ratio")
        total = profile(row).get("total_uncompressed_size")
        if ratio is None or not isinstance(total, (int, float)):
            return None
        if ratio < float(self.param("min_ratio", 100)) or total < float(self.param("min_uncompressed_bytes", 100 * 1024 * 1024)):
            return None
        return RuleResult(evidence(archive=base_name(row.path()), ratio=ratio, uncompressed_bytes=int(total)))


@register("archives.sfx_exe")
class SfxExecutable(Rule):
    """Self-extracting archive: an executable carrying archive data, or an SFX flag."""

    selector = select(types={"archive-file-inventory", "file-signature-mismatch"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if as_bool(row.get("sfx")) is True or as_bool(profile(row).get("sfx")) is True:
            return RuleResult(evidence(file=base_name(row.path())))
        if row.type == "file-signature-mismatch":
            ext = row.text("actual_extension").lower().lstrip(".") or extension(row.path())
            if ext == "exe" and row.text("detected_signature_kind").lower() in ARCHIVE_SIGNATURES:
                return RuleResult(evidence(file=base_name(row.path()), signature=row.text("detected_signature_kind")))
        return None


@register("archives.entry_time_later_than_container")
class EntryLaterThanContainer(Rule):
    """An archive entry modified more than ``slack_hours`` after the archive file itself (DOS times are local: slack)."""

    selector = ARCHIVES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        container = parse_time(row.get("source_file_mtime"))
        if container is None:
            return None
        slack = dt.timedelta(hours=float(self.param("slack_hours", 24)))
        entries = [item for item in as_list(profile(row).get("sample_entries")) if isinstance(item, Mapping)]
        for entry in entries:
            moment = parse_time(entry.get("modified_at") or entry.get("last_modified") or entry.get("date_time"))
            if moment is not None and moment > container + slack:
                return RuleResult(evidence(archive=base_name(row.path()), entry=entry.get("name"), entry_modified=moment, archive_modified=container))
        return None
