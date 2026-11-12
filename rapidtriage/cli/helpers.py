"""Shared helpers for rapidtriage CLI subcommand handlers."""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from ..core.output_guard import (
    OUTPUT_INSIDE_EVIDENCE,
    OutputInsideEvidenceError,
    check_output_outside_evidence,
    output_evidence_conflict,
)


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


#: ``rapidtriage run`` without ``--output-dir`` (R7: no default output folder inside the evidence).
CLI_RUN_OUTPUT_DIR_REQUIRED = (
    "--output-dir 를 지정하세요. 증거 밖의 출력 폴더가 필요합니다 (증거 안에는 쓰지 않습니다) / "
    "--output-dir is required: choose an output folder outside the evidence (no output is written inside the evidence)."
)


def refuse_output_inside_evidence(
    parser: argparse.ArgumentParser,
    output: Path | str | None,
    evidence: list[Path | str | None],
    *,
    allow_evidence_inside: bool = False,
) -> None:
    """``parser.error`` (exit 2, Korean + English) when ``output`` overlaps an evidence path (R7)."""
    if output is None:
        return
    try:
        check_output_outside_evidence(output, evidence, allow_evidence_inside=allow_evidence_inside)
    except OutputInsideEvidenceError as exc:
        parser.error(exc.cli_message)


class DefaultOutput(str):
    """An ``--output`` default file name the user did not type (T-033).

    Parsers declare ``default=DefaultOutput("rapidtriage-x.json")`` so the value
    still behaves as the old cwd-relative file name, while :func:`main` can tell
    "no ``--output`` given" apart from an explicit path that happens to match.
    """

    __slots__ = ()


#: Commands whose input positional(s) name the evidence a default output must stay out of.
_EVIDENCE_INPUT_DESTS = ("root", "current_root", "snapshot_roots", "paths")
#: Commands whose input is a RapidTriage run folder: writing next to it is legitimate.
_RUN_INPUT_DESTS = ("run_output",)
#: Commands whose default output is derived in the handler (``--output`` default ``None``).
_DERIVED_DEFAULT_OUTPUTS = {
    "artifacts": lambda args: f"rapidtriage-artifacts-{getattr(args, 'kind', '')}.json",
}

CLI_DEFAULT_OUTPUT_HINT = (
    "--output 으로 증거 밖의 파일 경로를 지정하거나 증거 밖 폴더에서 실행하세요 / "
    "pass --output with a path outside the evidence, or run from a folder outside it."
)
CLI_DEFAULT_OUTPUT_EVIDENCE_FILES_WARNING = (
    "경고: 현재 폴더에 증거로 보이는 파일이 있습니다. 기본 출력 파일이 이 폴더에 만들어집니다: {output} "
    "(--output 으로 증거 밖 경로를 지정하세요) / warning: the current folder holds evidence-like files; "
    "the default output is written here: {output} (use --output to write outside the evidence)."
)


def _input_paths(args: argparse.Namespace, dests: tuple[str, ...]) -> list[Path]:
    paths: list[Path] = []
    for dest in dests:
        value = getattr(args, dest, None)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip():
                paths.append(Path(str(item)).expanduser())
    return paths


def _run_evidence_roots(run_folders: list[Path]) -> list[Path]:
    """Evidence roots recorded in the run summaries of the run folders a command reads."""
    roots: list[Path] = []
    for folder in run_folders:
        summary_path = folder / "rapidtriage-run-summary.json"
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        root = summary.get("root") if isinstance(summary, dict) else None
        if isinstance(root, str) and root.strip() and Path(root).expanduser().is_absolute():
            roots.append(Path(root).expanduser())
    return roots


def _with_image_folders(evidence: list[Path]) -> list[Path]:
    """``evidence`` plus the folder of each evidence image file (E01, dd, VHD ... -- ``core/browse.py``).

    A default output is a file in the current folder: run beside ``case.E01`` it would
    land in the evidence folder, so that folder counts as evidence for the default.
    """
    from ..core.browse import EVIDENCE_FILE_SUFFIXES

    folders: list[Path] = []
    for item in evidence:
        if item.suffix.lower() in EVIDENCE_FILE_SUFFIXES and item.is_file():
            folders.append(item.resolve().parent)
    return evidence + folders


def default_output_name(args: argparse.Namespace) -> str | None:
    """The cwd-relative default file name this command would write, ``None`` when ``--output`` was given."""
    output = getattr(args, "output", None)
    if isinstance(output, DefaultOutput):
        return str(output)
    if output is None:
        derive = _DERIVED_DEFAULT_OUTPUTS.get(str(getattr(args, "command", "")))
        if derive is not None:
            return derive(args)
    return None


def resolve_output_path(
    args: argparse.Namespace,
    evidence_root: list[Path | str] | Path | str | None,
) -> Path | None:
    """Absolute default single-file output of ``args`` (``None`` when ``--output`` was given).

    Raises :class:`OutputInsideEvidenceError` (``OUTPUT_INSIDE_EVIDENCE``) when the
    default -- a file in the current folder -- lands inside ``evidence_root`` (the
    current folder is the evidence folder or below it). An explicit ``--output``
    is the operator's choice and is not re-judged here.
    """
    name = default_output_name(args)
    if name is None:
        return None
    output = (Path.cwd() / name).resolve()
    roots = evidence_root if isinstance(evidence_root, list) else [evidence_root]
    check_output_outside_evidence(output, roots, allow_evidence_inside=True)
    return output


def _cwd_evidence_files(limit: int = 1) -> list[Path]:
    # Imported here: core.browse loads the evidence adapters (kept off the --help path, T-161).
    from ..core.browse import EVIDENCE_FILE_SUFFIXES

    found: list[Path] = []
    try:
        for entry in Path.cwd().iterdir():
            if entry.suffix.lower() in EVIDENCE_FILE_SUFFIXES and entry.is_file():
                found.append(entry)
                if len(found) >= limit:
                    break
    except OSError:
        return []
    return found


def guard_default_output(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """R7 / IS-068 for single-file ``--output`` defaults (T-033), run once before dispatch.

    * The command names evidence (``root`` / ``paths`` ..., or the ``root`` recorded in
      the summary of the run folder it reads) and the current folder is that evidence
      or inside it: exit 2 with ``OUTPUT_INSIDE_EVIDENCE``.
    * Otherwise (no evidence known, e.g. an index or feed): when the current
      folder holds evidence-like files (``core/browse.py`` suffixes) and is not the
      run folder the command reads, print a warning only.
    """
    name = default_output_name(args)
    if name is None:
        return
    run_inputs = _input_paths(args, _RUN_INPUT_DESTS)
    evidence = _input_paths(args, _EVIDENCE_INPUT_DESTS) + _run_evidence_roots(run_inputs)
    if evidence:
        try:
            resolve_output_path(args, _with_image_folders(evidence))
        except OutputInsideEvidenceError as exc:
            parser.error(f"[{OUTPUT_INSIDE_EVIDENCE}] {exc.cli_message}. {CLI_DEFAULT_OUTPUT_HINT}")
        return
    output = (Path.cwd() / name).resolve()
    if any(output_evidence_conflict(output, run) == OUTPUT_INSIDE_EVIDENCE for run in run_inputs):
        return
    if _cwd_evidence_files():
        print(CLI_DEFAULT_OUTPUT_EVIDENCE_FILES_WARNING.format(output=output), file=sys.stderr)


def add_eventlog_output_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--eventlog-structure-rows",
        action="store_true",
        help="Also emit EVTX eventlog-chunk and eventlog-record-candidate structure rows (off by default; counts stay on eventlog-file rows)",
    )
    command.add_argument(
        "--eventlog-record-detail",
        choices=("triage", "full"),
        default=None,
        help="Per-event output shape: triage (default compact projection) or full (every per-event validation/report block)",
    )


def eventlog_collector_options(args: argparse.Namespace) -> dict[str, object]:
    """Eventlog collector options requested on the command line (empty = pipeline defaults)."""
    options: dict[str, object] = {}
    if getattr(args, "eventlog_structure_rows", False):
        options["structure_rows"] = True
    record_detail = getattr(args, "eventlog_record_detail", None)
    if record_detail:
        options["record_detail"] = str(record_detail)
    return options


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
    parser.add_argument(
        "--auth-token",
        "--token",
        dest="auth_token",
        help=(
            "Require X-RapidTriage-Token for API calls (default: RAPIDTRIAGE_AUTH_TOKEN, or its older alias "
            "RAPIDTRIAGE_TOKEN; a loopback server without one generates a token)"
        ),
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Hardened remote mode: allow non-loopback binding only with a token; keeps auth and Host/Origin gates on",
    )
    parser.add_argument(
        "--browse-root",
        dest="browse_roots",
        action="append",
        default=None,
        metavar="DIR",
        help=(
            "Remote/non-loopback server only (repeatable): the evidence picker (/api/browse) lists only inside "
            "these folders (default: the server's run folders + home). A loopback server lists the whole disk"
        ),
    )
    parser.add_argument("--allow-remote-without-auth", action="store_true", help="Allow non-localhost binding without auth token")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload for UI/API development")
    parser.add_argument("--crash-log-dir", help="Local-only directory for web/API crash reports")
    parser.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "Serve every run read-only: state-changing API requests get 409 RUN_READ_ONLY "
            "(readonly_reason SERVER_READ_ONLY) and nothing is written into a result folder; no browser is opened"
        ),
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help=(
            "Do not open a browser (also RAPIDTRIAGE_NO_BROWSER=1). A browser opens only for a loopback "
            "server on an interactive terminal outside CI"
        ),
    )
    parser.add_argument("--ssl-certfile", metavar="PEM", help="TLS certificate file: serve HTTPS (needs --ssl-keyfile)")
    parser.add_argument("--ssl-keyfile", metavar="PEM", help="TLS private key file for --ssl-certfile")
    parser.add_argument(
        "--allow-plain-http",
        action="store_true",
        help="Let --remote serve plain HTTP without --ssl-certfile/--ssl-keyfile (e.g. behind a TLS reverse proxy)",
    )


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
    # Imported here: core.cross_tool loads the artifact engine, and helpers is
    # imported by the argparse parsers that ``--help`` builds (T-161b).
    from ..core.cross_tool import iter_rows as iter_cross_tool_rows

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
    "DefaultOutput",
    "add_rules_argument",
    "add_web_arguments",
    "build_source_read_review_note",
    "compact_commercial_readiness_payload",
    "default_output_name",
    "guard_default_output",
    "load_image_workflow_rows",
    "load_source_read_review_package",
    "parse_named_cli_values",
    "resolve_output_path",
    "resolve_reviewer_identity",
    "write_kakaotalk_message_residue_csv",
]
