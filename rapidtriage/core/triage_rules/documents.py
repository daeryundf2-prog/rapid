"""Document metadata indicators: Office / HWP / PDF (catalogue: apps §6)."""

from __future__ import annotations

from collections.abc import Mapping

from .base import (
    FlagContext,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    as_list,
    as_number,
    base_name,
    evidence,
    parse_time,
    register,
    select,
)

DOCUMENTS = select(types={"document-metadata-risk", "document-metadata", "pdf-metadata", "hwp-metadata"})


def _name(value: str) -> str:
    return " ".join(value.casefold().split())


def _script_path(value: object) -> str:
    return str(value).replace("\\", "/").strip("/").casefold()


def normalized_metadata(row: RowView, key: str) -> str:
    """A ``metadata_profile.normalized_metadata`` value the parser does not lift to the top level (PDF Producer)."""
    profile = row.get("metadata_profile")
    metadata = profile.get("normalized_metadata") if isinstance(profile, Mapping) else None
    value = metadata.get(key) if isinstance(metadata, Mapping) else None
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def document_label(row: RowView) -> str:
    return row.text("file_name", "entry_name") or base_name(row.path())


@register("documents.lastsaved_ne_author")
class LastSavedNotAuthor(Rule):
    """Last saved by someone other than the author."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        author, last = row.text("author"), row.text("last_modified_by")
        if not author or not last or _name(author) == _name(last):
            return None
        return RuleResult(evidence(document=document_label(row), author=author, last_modified_by=last))


@register("documents.edit_time_zero_many_rev")
class EditTimeZero(Rule):
    """Total editing time ≤ ``max_edit_minutes`` with a revision number ≥ ``min_revision``."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        seconds = row.number("total_edit_time_seconds")
        revision = row.number("revision")
        if seconds is None or revision is None:
            return None
        if seconds > float(self.param("max_edit_minutes", 1)) * 60 or revision < float(self.param("min_revision", 10)):
            return None
        return RuleResult(evidence(document=document_label(row), total_edit_seconds=int(seconds), revision=int(revision)))


@register("documents.created_after_modified")
class CreatedAfterModified(Rule):
    """Internal created time later than internal modified time by more than ``tolerance_hours``.

    Writers that store one time zone-naive and the other in UTC shift a same-day pair by the
    UTC offset (up to ±14 h), so only a gap beyond that is reported.
    """

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        created, modified = row.time("created_at"), row.time("modified_at")
        if created is None or modified is None:
            return None
        if (created - modified).total_seconds() <= float(self.param("tolerance_hours", 14)) * 3600:
            return None
        return RuleResult(evidence(document=document_label(row), created_at=created, modified_at=modified))


@register("documents.modified_vs_fs")
class ModifiedVsFs(Rule):
    """Internal modified time more than ``max_gap_hours`` away from the file-system modification time."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        internal = row.time("modified_at")
        fs_time = row.time("source_file_mtime", "fs_modified_at") or parse_time(ctx.shared.get("file_mtimes", {}).get(row.path().casefold()))
        if internal is None or fs_time is None:
            return None
        gap = abs((fs_time - internal).total_seconds()) / 3600
        if gap <= float(self.param("max_gap_hours", 24)):
            return None
        return RuleResult(evidence(document=document_label(row), internal_modified=internal, fs_modified=fs_time, gap_hours=round(gap, 1)))


@register("documents.meta_tool_name_user")
class MetaToolName(Rule):
    """Author / last saved by is a library or conversion tool name (programmatically generated)."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        tools = [str(item).casefold() for item in self.param("tool_names", [])]
        for key in ("last_modified_by", "author"):
            value = row.text(key)
            if value and any(tool in value.casefold() for tool in tools):
                return RuleResult(evidence(document=document_label(row), field=key, value=value))
        return None


@register("documents.macro_or_ole")
class MacroOrOle(Rule):
    """VBA project, embedded OLE objects or DDE fields present."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        macro = row.get("macro_profile")
        macro = macro if isinstance(macro, Mapping) else {}
        ignored = {_script_path(item) for item in self.param("ignored_script_paths", [])}
        listed = [str(item) for item in as_list(macro.get("macro_paths"))]
        paths = [item for item in listed if _script_path(item) not in ignored]
        count = as_number(macro.get("macro_path_count"))
        # Only the default parts every Hancom-written HWPX carries (Scripts/headerScripts.js, …): no macro.
        default_only = bool(listed) and not paths and (count is None or count <= len(listed))
        macro_present = as_bool(macro.get("macro_present")) is True and not default_only
        flags = {str(item).lower() for item in as_list(row.get("risk_flags"))}
        ole = row.number("ole_object_count", "embedded_object_count") or 0
        dde = as_bool(row.get("dde_present")) is True or any("dde" in flag for flag in flags)
        macro_flag = any("macro" in flag for flag in flags) and not default_only
        if not macro_present and not ole and not dde and not macro_flag:
            return None
        return RuleResult(evidence(document=document_label(row), macro=macro_present or macro_flag, ole_objects=int(ole), dde=dde, macro_paths=paths))


@register("documents.external_template_url")
class ExternalTemplate(Rule):
    """Template or external relationship pointing to http(s)/UNC (remote template injection)."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        candidates = [row.text("template"), *[str(item.get("target") if isinstance(item, Mapping) else item) for item in as_list(row.get("external_reference_candidates"))]]
        for value in candidates:
            lowered = value.strip().lower()
            if lowered.startswith(("http://", "https://", "\\\\", "file://")):
                return RuleResult(evidence(document=document_label(row), reference=value))
        return None


@register("documents.printed_present")
class PrintedPresent(Rule):
    """Last-printed time recorded."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        printed = row.time("last_printed_at")
        return RuleResult(evidence(document=document_label(row), last_printed_at=printed)) if printed else None


@register("documents.pdf_creator_producer_odd")
class PdfCreatorProducer(Rule):
    """PDF Creator is an office application but Producer is an editor / online converter."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        creator = row.text("creator", "pdf_creator", "xmp_creator_tool", "application")
        producer = row.text("producer", "pdf_producer") or normalized_metadata(row, "producer")
        if not creator or not producer:
            return None
        office = [str(item).casefold() for item in self.param("office_creators", [])]
        editors = [str(item).casefold() for item in self.param("editor_producers", [])]
        if not any(item in creator.casefold() for item in office) or not any(item in producer.casefold() for item in editors):
            return None
        return RuleResult(evidence(document=document_label(row), creator=creator, producer=producer))


@register("documents.pdf_incremental_update")
class PdfIncrementalUpdate(Rule):
    """PDF with more than one ``%%EOF`` (incremental updates after creation)."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        count = row.number("pdf_eof_count", "eof_marker_count", "incremental_update_count")
        if count is None:
            return None
        updates = int(count) - (0 if row.get("incremental_update_count") is not None else 1)
        if updates < 1:
            return None
        return RuleResult(evidence(document=document_label(row), incremental_updates=updates))


@register("documents.tracked_authors_many")
class TrackedAuthorsMany(Rule):
    """≥ ``min_authors`` distinct tracked-change/comment authors, or ones other than the document author."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        names = {str(item).strip() for item in as_list(row.get("tracked_change_authors", "revision_authors", "comment_authors")) if str(item).strip()}
        if not names:
            return None
        author = _name(row.text("author"))
        others = sorted(name for name in names if _name(name) != author)
        if len(names) < int(self.param("min_authors", 3)) and not (author and others):
            return None
        return RuleResult(evidence(document=document_label(row), authors=sorted(names), other_than_author=others))


@register("documents.meta_scrubbed")
class MetaScrubbed(Rule):
    """Author, last saved by and company all empty although the properties were parsed."""

    selector = DOCUMENTS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not (row.get("created_at") or row.get("modified_at") or row.get("application")):
            return None  # properties not parsed at all
        if row.text("author", "last_modified_by", "company") or row.get("author_candidates"):
            return None
        return RuleResult(evidence(document=document_label(row), application=row.text("application")))
