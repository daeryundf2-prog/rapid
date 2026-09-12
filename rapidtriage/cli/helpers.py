"""Shared helpers for rapidtriage CLI subcommand handlers."""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
from collections.abc import Mapping
from pathlib import Path

from ..core.cross_tool import iter_rows as iter_cross_tool_rows


def compact_commercial_readiness_payload(payload: dict[str, object], *, limit: int) -> dict[str, object]:
    """Keep commercial-readiness stdout usable while full --output-dir reports remain complete."""
    row_limit = max(0, int(limit))
    compact = json.loads(json.dumps(payload, ensure_ascii=False, default=str))
    truncated_paths: list[dict[str, object]] = []
    validation_summary = compact.get("validation_evidence_summary")
    pinned_item_numbers = set()
    if isinstance(validation_summary, dict):
        pinned_item_numbers = {
            int(number)
            for number in validation_summary.get("mapped_item_numbers", [])
            if isinstance(number, int) or (isinstance(number, str) and number.isdigit())
        }

    def bounded_with_pinned_items(values: list[object]) -> list[object]:
        if not pinned_item_numbers:
            return values[:row_limit]
        selected = values[:row_limit]
        selected_numbers = {item.get("number") for item in selected if isinstance(item, dict)}
        for item in values[row_limit:]:
            if not isinstance(item, dict):
                continue
            number = item.get("number")
            if number in pinned_item_numbers and number not in selected_numbers:
                selected.append(item)
                selected_numbers.add(number)
        return selected

    def truncate_list(path: tuple[str, ...]) -> None:
        target: dict[str, object] = compact
        for key in path[:-1]:
            child = target.get(key)
            if not isinstance(child, dict):
                return
            target = child
        key = path[-1]
        values = target.get(key)
        if not isinstance(values, list):
            return
        original_count = len(values)
        if original_count > row_limit:
            if path in (("all_items",), ("critical_non_commercial_items",), ("non_commercial_items",)):
                target[key] = bounded_with_pinned_items(values)
            else:
                target[key] = values[:row_limit]
            truncated_paths.append(
                {
                    "path": ".".join(path),
                    "original_count": original_count,
                    "returned_count": len(target[key]),
                }
            )

    for path in (
        ("all_items",),
        ("critical_non_commercial_items",),
        ("non_commercial_items",),
        ("priority_work_plan",),
        ("commercial_blocker_matrix", "rows"),
        ("commercial_blocker_matrix", "top_internal_items"),
        ("commercial_blocker_matrix", "top_external_evidence_items"),
    ):
        truncate_list(path)

    compact["stdout_limit_profile"] = {
        "profile_version": "commercial-readiness-stdout-limit-v1",
        "limit": row_limit,
        "truncated": bool(truncated_paths),
        "truncated_paths": truncated_paths,
        "full_report_hint": "Use --output-dir to write complete JSON/Markdown reports; stdout is compacted for terminal usability.",
    }
    return compact


def add_rules_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", help="Path to a rapidtriage JSON/YAML or YARA-lite string rule file for matched_rules and IOC lookup")


def resolve_reviewer_identity(explicit: str | None) -> str | None:
    """Resolve reviewer attribution for CLI review marks.

    Precedence: explicit ``--reviewer`` value, then ``RAPIDTRIAGE_REVIEWER``,
    then the local system user. Returns None only when no identity can be
    determined (e.g. getpass fails in a stripped environment).
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env_value = os.environ.get("RAPIDTRIAGE_REVIEWER", "").strip()
    if env_value:
        return env_value
    try:
        user = getpass.getuser().strip()
    except (KeyError, OSError):
        user = ""
    return user or None


def add_web_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="Host interface for the local web server")
    parser.add_argument("--port", type=int, default=8765, help="Port for the local web server")
    parser.add_argument("--auth-token", help="Require X-RapidTriage-Token for API calls")
    parser.add_argument("--allow-remote-without-auth", action="store_true", help="Allow non-localhost binding without auth token")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload for UI/API development")
    parser.add_argument("--crash-log-dir", help="Local-only directory for web/API crash reports")


def parse_named_cli_values(
    values: list[str],
    *,
    option_name: str,
    parser: argparse.ArgumentParser,
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            parser.error(f"{option_name} must use NAME=VALUE")
        name, raw = value.split("=", 1)
        if not name.strip() or not raw.strip():
            parser.error(f"{option_name} must use NAME=VALUE")
        parsed[name.strip()] = raw.strip()
    return parsed


def load_image_workflow_rows(path: Path, *, max_rows: int = 50000) -> list[dict[str, object]]:
    """Load image workflow comparison rows while preserving nested Rapid JSON.

    Generic cross-tool rows are intentionally flattened for broad artifact diffs.
    Image workflow evidence often keeps partition/source metadata under nested
    `details` blocks, so preserve those rows too before applying field-specific
    normalization in the image trusted-diff layer.
    """
    rows = list(iter_cross_tool_rows(path, max_rows=max_rows))
    if path.suffix.lower() != ".json" or len(rows) >= max_rows:
        return rows[:max_rows]

    raw = json.loads(path.read_text(encoding="utf-8"))
    preserved: list[Mapping[str, object]] = []
    if isinstance(raw, Mapping):
        preserved.append(raw)
        for key in ("artifacts", "events", "results", "records", "rows", "candidates", "entries"):
            value = raw.get(key)
            if isinstance(value, list):
                preserved.extend(item for item in value if isinstance(item, Mapping))
    elif isinstance(raw, list):
        preserved.extend(item for item in raw if isinstance(item, Mapping))

    for item in preserved:
        if len(rows) >= max_rows:
            break
        rows.append(dict(item))
    return rows[:max_rows]


def load_source_read_review_package(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read source-read JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"source-read JSON is invalid: {path}") from exc
    package = payload.get("source_citation_package") if isinstance(payload, dict) else None
    if not isinstance(package, dict):
        raise ValueError("source-read JSON is missing source_citation_package")
    return dict(package)


def build_source_read_review_note(package: Mapping[str, object]) -> str:
    review_note = str(package.get("review_note_template") or "").strip()
    citation_text = str(package.get("citation_text") or "").strip()
    package_hash = str(package.get("package_hash") or "").strip()
    if not review_note:
        raise ValueError("source-read JSON does not contain a review_note_template")
    footer = []
    if citation_text:
        footer.append(f"Source citation: {citation_text}")
    if package_hash:
        footer.append(f"Source citation package hash: {package_hash}")
    if footer:
        return f"{review_note}\n" + "\n".join(footer)
    return review_note


def write_kakaotalk_message_residue_csv(payload: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = payload.get("chat_message_residues") or []
    fieldnames = [
        "source_path",
        "source_offset",
        "chat_id",
        "log_id",
        "author_id",
        "send_at",
        "send_at_utc",
        "type",
        "deleted",
        "message_text",
        "message_text_length",
        "message_text_sha256",
        "attachment_length",
        "attachment_sha256",
    ]
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                writer.writerow(row)

__all__ = [
    "add_rules_argument",
    "add_web_arguments",
    "build_source_read_review_note",
    "compact_commercial_readiness_payload",
    "load_image_workflow_rows",
    "load_source_read_review_package",
    "parse_named_cli_values",
    "resolve_reviewer_identity",
    "write_kakaotalk_message_residue_csv",
]
