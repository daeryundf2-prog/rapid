from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Sequence

from ..core.docs import write_result
from ..core.submission import compute_hashes
from .email import EMAIL_FORMAT_PROFILES, EMAIL_REQUIRED_TOOLS_BY_FORMAT, EMAIL_TRUSTED_DIFF_TOOLS


EMAIL_EXTERNAL_PARSE_VERSION = "email-external-parser-wrapper-v1"


class EmailExternalParserError(ValueError):
    """Raised when external email parser input is invalid."""


def run_email_external_parse(
    *,
    source_path: Path,
    output_dir: Path,
    preferred_tool: str | None = None,
    timeout_seconds: int = 300,
    overwrite: bool = False,
    tool_resolver: Callable[[str], str | None] = shutil.which,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    source_path = source_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise EmailExternalParserError(f"email parser output directory is not empty: {output_dir}")
    if not source_path.is_file():
        raise EmailExternalParserError(f"email source not found: {source_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = source_path.suffix.lower().lstrip(".")
    if suffix not in {"pst", "ost", "msg"}:
        raise EmailExternalParserError("external parser wrapper currently targets PST/OST/MSG files")

    source_header = read_email_source_header(source_path)
    source_header_profile = email_source_header_profile(suffix, source_header)
    selected = select_email_external_tool(suffix, preferred_tool=preferred_tool, tool_resolver=tool_resolver)
    json_path = output_dir / "email-external-parser.json"
    markdown_path = output_dir / "email-external-parser.md"
    export_dir = output_dir / "export"
    if overwrite and export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.mkdir(exist_ok=True)
    source_hashes = compute_hashes(source_path)
    command: list[str] = []
    completed: subprocess.CompletedProcess[str] | None = None
    status = "blocked"
    error = ""
    if not source_header_profile["compatible"] and not preferred_tool:
        status = "blocked"
        error = str(source_header_profile["reason"])
    elif selected["available"]:
        command = build_email_external_command(str(selected["tool"]), source_path, export_dir, suffix)
        try:
            completed = command_runner(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
            status = "complete" if completed.returncode == 0 else "failed"
        except Exception as exc:  # pragma: no cover - external runtime dependent
            status = "failed"
            error = str(exc)
    exports = inventory_email_external_exports(export_dir)
    payload: dict[str, object] = {
        "command": "email-external-parse",
        "profile_version": EMAIL_EXTERNAL_PARSE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "source": {
            "path": str(source_path),
            "format": suffix,
            "hashes": source_hashes,
            "format_profile": EMAIL_FORMAT_PROFILES.get(suffix, {}),
            "header_profile": source_header_profile,
        },
        "selected_tool": selected,
        "required_tools": EMAIL_REQUIRED_TOOLS_BY_FORMAT.get(suffix, []),
        "trusted_tool_families": sorted(EMAIL_TRUSTED_DIFF_TOOLS),
        "execution": {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "returncode": completed.returncode if completed is not None else None,
            "stdout_tail": tail_text(completed.stdout if completed is not None else ""),
            "stderr_tail": tail_text(completed.stderr if completed is not None else error),
        },
        "exports": exports,
        "summary": {
            "export_file_count": len(exports),
            "native_decode_attempted": bool(selected["available"]),
            "native_decode_completed": status == "complete",
            "ready_for_trusted_diff": status == "complete" and bool(exports),
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "trusted-libpff-readpst-outlook-diff-required",
            "broad-mailbox-known-answer-corpus-required",
            "deleted-item-recovery-validation-required",
        ],
        "outputs": {"json": str(json_path), "markdown": str(markdown_path), "export_dir": str(export_dir)},
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_email_external_parse_markdown(payload), encoding="utf-8")
    return payload


def select_email_external_tool(
    suffix: str,
    *,
    preferred_tool: str | None,
    tool_resolver: Callable[[str], str | None],
) -> dict[str, object]:
    candidates = [preferred_tool] if preferred_tool else []
    if suffix in {"pst", "ost"}:
        candidates.extend(["pffexport", "readpst"])
    elif suffix == "msg":
        candidates.extend(["msg-extractor", "extract_msg", "pffexport"])
    seen: list[str] = []
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.append(candidate)
        resolved = tool_resolver(candidate)
        if resolved:
            return {"tool": candidate, "path": resolved, "available": True, "candidates": seen}
    return {"tool": preferred_tool or "", "path": "", "available": False, "candidates": seen}


def read_email_source_header(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(8)
    except OSError:
        return b""


def email_source_header_profile(suffix: str, header: bytes) -> dict[str, object]:
    if suffix in {"pst", "ost"}:
        compatible = header.startswith(b"!BDN")
        expected = "PST/OST !BDN header"
    elif suffix == "msg":
        compatible = header.startswith(bytes.fromhex("d0cf11e0a1b11ae1"))
        expected = "OLE Compound File header"
    else:
        compatible = False
        expected = "supported email container header"
    return {
        "compatible": compatible,
        "expected": expected,
        "observed_hex": header.hex(),
        "reason": "" if compatible else f"source header does not match {expected}",
    }


def build_email_external_command(tool: str, source_path: Path, export_dir: Path, suffix: str) -> list[str]:
    if tool == "pffexport":
        return [tool, "-f", "all", "-t", str(export_dir / source_path.stem), str(source_path)]
    if tool == "readpst":
        return [tool, "-r", "-o", str(export_dir), str(source_path)]
    if tool in {"msg-extractor", "extract_msg"}:
        return [tool, "--out", str(export_dir), str(source_path)]
    return [tool, str(source_path), str(export_dir)]


def inventory_email_external_exports(export_dir: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted(export_dir.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        stat = path.stat()
        rows.append({"path": str(path), "name": path.name, "size_bytes": stat.st_size, "sha256": compute_hashes(path)["sha256"]})
    return rows


def tail_text(value: str, limit: int = 4000) -> str:
    return str(value or "")[-limit:]


def render_email_external_parse_markdown(payload: dict[str, object]) -> str:
    return "\n".join(
        [
            "# Email External Parser Wrapper",
            "",
            f"- Status: `{payload['status']}`",
            f"- Source: `{payload['source']['path']}`",
            f"- Format: `{payload['source']['format']}`",
            f"- Tool: `{payload['selected_tool'].get('tool', '')}` available={payload['selected_tool'].get('available')}",
            f"- Export files: `{payload['summary']['export_file_count']}`",
            "",
            "This wrapper records external parser evidence; report-grade claims still require trusted diff validation.",
            "",
        ]
    )
