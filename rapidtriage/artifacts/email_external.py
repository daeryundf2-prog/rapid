from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from ..core.docs import write_result
from ..core.submission import compute_hashes
from .email import EMAIL_FORMAT_PROFILES, EMAIL_REQUIRED_TOOLS_BY_FORMAT, EMAIL_TRUSTED_DIFF_TOOLS


EMAIL_EXTERNAL_PARSE_VERSION = "email-external-parser-wrapper-v2"
EMAIL_EXTERNAL_EVIDENCE_MANIFEST_VERSION = "email-external-parser-evidence-manifest-v1"


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
    tool_matrix = email_external_tool_availability_matrix(suffix, preferred_tool=preferred_tool, tool_resolver=tool_resolver)
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
        command = build_email_external_command(str(selected["path"] or selected["tool"]), source_path, export_dir, suffix)
        try:
            completed = command_runner(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
            status = "complete" if completed.returncode == 0 else "failed"
        except Exception as exc:  # pragma: no cover - external runtime dependent
            status = "failed"
            error = str(exc)
    exports = inventory_email_external_exports(export_dir)
    execution = {
        "command": command,
        "command_argv_sha256": stable_json_sha256(command),
        "timeout_seconds": timeout_seconds,
        "returncode": completed.returncode if completed is not None else None,
        "stdout_tail": tail_text(completed.stdout if completed is not None else ""),
        "stdout_sha256": sha256_text(completed.stdout if completed is not None else ""),
        "stderr_tail": tail_text(completed.stderr if completed is not None else error),
        "stderr_sha256": sha256_text(completed.stderr if completed is not None else error),
    }
    validation_checks = email_external_validation_checks(
        source_header_profile=source_header_profile,
        selected=selected,
        status=status,
        exports=exports,
        preferred_tool=preferred_tool,
    )
    evidence_manifest = email_external_evidence_manifest(
        source_path=source_path,
        suffix=suffix,
        source_hashes=source_hashes,
        selected=selected,
        tool_matrix=tool_matrix,
        execution=execution,
        exports=exports,
        status=status,
        validation_checks=validation_checks,
    )
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
        "tool_availability_matrix": tool_matrix,
        "required_tools": EMAIL_REQUIRED_TOOLS_BY_FORMAT.get(suffix, []),
        "trusted_tool_families": sorted(EMAIL_TRUSTED_DIFF_TOOLS),
        "execution": execution,
        "exports": exports,
        "evidence_manifest": evidence_manifest,
        "validation_checks": validation_checks,
        "forensic_review": {
            "review_profile": "email_external_parser_review_profile",
            "analyst_action": "Attach this JSON, Markdown report, exported-file hashes, and a trusted parser diff before relying on PST/OST/MSG contents.",
            "source_citation": f"{source_path.name}:{source_hashes['sha256']}",
            "export_inventory_hash": evidence_manifest["export_inventory_sha256"],
            "external_validation_required": True,
        },
        "commercial_uplift_evidence": {
            "target_items": [36, 55, 81, 85, 90, 95],
            "passed_checks": [row["id"] for row in validation_checks if row["status"] == "passed"],
            "failed_or_blocked_checks": [row["id"] for row in validation_checks if row["status"] != "passed"],
            "evidence_manifest_hash": evidence_manifest["manifest_sha256"],
            "report_grade_claim": "blocked_until_trusted_diff_attached",
        },
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
    seen: list[str] = []
    for candidate in email_external_tool_candidates(suffix, preferred_tool):
        if not candidate or candidate in seen:
            continue
        seen.append(candidate)
        resolved = resolve_email_external_tool(candidate, tool_resolver)
        if resolved:
            return {"tool": candidate, "path": resolved, "available": True, "candidates": seen}
    return {"tool": preferred_tool or "", "path": "", "available": False, "candidates": seen}


def email_external_tool_candidates(suffix: str, preferred_tool: str | None) -> list[str]:
    candidates = [preferred_tool] if preferred_tool else []
    if suffix in {"pst", "ost"}:
        candidates.extend(["pffexport", "readpst"])
    elif suffix == "msg":
        candidates.extend(["msg-extractor", "extract_msg", "pffexport"])
    return [str(candidate) for candidate in candidates if candidate]


def resolve_email_external_tool(candidate: str, tool_resolver: Callable[[str], str | None]) -> str | None:
    expanded = os.path.expanduser(candidate)
    if os.path.sep in expanded:
        path = Path(expanded)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
    return tool_resolver(candidate)


def email_external_tool_availability_matrix(
    suffix: str,
    *,
    preferred_tool: str | None,
    tool_resolver: Callable[[str], str | None],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for candidate in email_external_tool_candidates(suffix, preferred_tool):
        if candidate in seen:
            continue
        seen.add(candidate)
        resolved = resolve_email_external_tool(candidate, tool_resolver)
        rows.append(
            {
                "tool": candidate,
                "path": resolved or "",
                "available": bool(resolved),
                "preferred": candidate == preferred_tool,
                "family": email_external_tool_family(candidate),
            }
        )
    return rows


def email_external_tool_family(tool: str) -> str:
    name = Path(tool).name.lower()
    if name in {"pffexport", "pffinfo"}:
        return "libpff"
    if name == "readpst":
        return "libpst"
    if name in {"msg-extractor", "extract_msg"}:
        return "python-extract-msg"
    return "custom"


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
    tool_name = Path(tool).name
    if tool_name == "pffexport":
        return [tool, "-f", "all", "-t", str(export_dir / source_path.stem), str(source_path)]
    if tool_name == "readpst":
        return [tool, "-r", "-o", str(export_dir), str(source_path)]
    if tool_name in {"msg-extractor", "extract_msg"}:
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()


def stable_json_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def email_external_validation_checks(
    *,
    source_header_profile: dict[str, object],
    selected: dict[str, object],
    status: str,
    exports: list[dict[str, object]],
    preferred_tool: str | None,
) -> list[dict[str, object]]:
    return [
        {
            "id": "email_external_source_header",
            "status": "passed" if source_header_profile.get("compatible") or preferred_tool else "blocked",
            "evidence": source_header_profile.get("expected", ""),
        },
        {
            "id": "email_external_tool_available",
            "status": "passed" if selected.get("available") else "blocked",
            "evidence": selected.get("path", ""),
        },
        {
            "id": "email_external_command_completed",
            "status": "passed" if status == "complete" else status,
            "evidence": f"status={status}",
        },
        {
            "id": "email_external_export_inventory",
            "status": "passed" if exports else "blocked",
            "evidence": f"export_file_count={len(exports)}",
        },
        {
            "id": "email_external_trusted_diff_ready",
            "status": "passed" if status == "complete" and exports else "blocked",
            "evidence": "requires independent parser/client export comparison",
        },
    ]


def email_external_evidence_manifest(
    *,
    source_path: Path,
    suffix: str,
    source_hashes: dict[str, str],
    selected: dict[str, object],
    tool_matrix: list[dict[str, object]],
    execution: dict[str, object],
    exports: list[dict[str, object]],
    status: str,
    validation_checks: list[dict[str, object]],
) -> dict[str, object]:
    export_inventory_sha256 = stable_json_sha256(exports)
    manifest: dict[str, object] = {
        "manifest_version": EMAIL_EXTERNAL_EVIDENCE_MANIFEST_VERSION,
        "source_name": source_path.name,
        "source_format": suffix,
        "source_sha256": source_hashes["sha256"],
        "selected_tool": selected.get("tool", ""),
        "selected_tool_path_sha256": sha256_text(str(selected.get("path", ""))),
        "tool_availability_sha256": stable_json_sha256(tool_matrix),
        "command_argv_sha256": execution["command_argv_sha256"],
        "stdout_sha256": execution["stdout_sha256"],
        "stderr_sha256": execution["stderr_sha256"],
        "export_inventory_sha256": export_inventory_sha256,
        "export_file_count": len(exports),
        "status": status,
        "validation_check_ids": [row["id"] for row in validation_checks],
        "report_grade_claim": "blocked_until_trusted_diff_attached",
    }
    manifest["manifest_sha256"] = stable_json_sha256(manifest)
    return manifest


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
            f"- Evidence manifest: `{payload['evidence_manifest']['manifest_sha256']}`",
            f"- Export inventory hash: `{payload['evidence_manifest']['export_inventory_sha256']}`",
            "",
            "This wrapper records external parser evidence; report-grade claims still require trusted diff validation.",
            "",
        ]
    )
