"""Catalog path presence and credential-file presence (R7 stage 3.5 lane A).

``ai-tool-presence`` (``install_kind=path``): one row per tool × profile whose catalog paths exist —
matched path count, catalog path kinds, newest / oldest mtime, a version when a manifest beside
the tool folder states one, retention note, ``coverage_status`` from the catalog confidence.

``ai-credential-presence``: one row per credential file (catalog ``credentials`` paths and names
matching :func:`is_credential_name` below a matched tool folder) — path, size, mtime and how it was
recognized. Contents are never opened and no hash is computed (plan §3.2 secret policy).

Privacy at the provider's row sink (:class:`~rapidtriage.artifacts.ai_agents.AiAgentsProvider`):

* :func:`mask_row_identity` — every lane A row (presence, install, credential, model file,
  unknown-tool candidate, execution) has email-like tokens in its path fields rewritten by
  :func:`~.base.mask_identity_in_path` (``u-<sha256 8 hex>@domain``); no raw copy is kept.
* :func:`dedupe_credential_rows` — lane A and lane B both report some credential files. One
  ``ai-credential-presence`` row is kept per (profile user, masked path, key name); the reporting
  adapters go to ``adapters[]`` and the adapter-specific ``credential_kind`` wins over lane A's
  generic ``catalog-credential`` / ``name-pattern``.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from ...core.ai_catalog.catalog import (
    AiCatalog,
    AiTool,
    DirCache,
    ExpandedPath,
    expand_paths,
    tool_root,
)
from .base import (
    AiRow,
    EvidenceProfile,
    is_credential_name,
    mask_identity_in_path,
    profile_account_key,
)

__all__ = [
    "MAX_CREDENTIAL_ROWS_PER_PROFILE",
    "MAX_MATCHED_PATH_SAMPLE",
    "credential_rows",
    "dedupe_credential_rows",
    "mask_row_identity",
    "path_presence_rows",
    "read_manifest_version",
]

PARSER = "ai-tool-presence"
MAX_MATCHED_PATH_SAMPLE = 20
MAX_CREDENTIAL_ROWS_PER_PROFILE = 500
CREDENTIAL_SCAN_DEPTH = 3
CREDENTIAL_SCAN_ENTRY_LIMIT = 5000
MAX_MANIFEST_BYTES = 256 * 1024
# Big content folders a credential-name scan never descends into.
_SKIP_SCAN_DIRS = frozenset(
    {
        "projects", "node_modules", "cache", "cache_data", "code cache", "gpucache", "dawncache", "models", "blobs",
        "extensions", "file-history", "indexeddb", "local storage", "session storage", "service worker",
        "conversations", "brain", "scratch", "sessions", "shell-snapshots", "logs", "tmp", "workspacestorage",
        "crashpad", "blob_storage", "webstorage", "hub", "snapshots", "rollout", ".git",
    }
)


def _stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def read_manifest_version(path: Path) -> str:
    """``version`` of a ``package.json`` / ``manifest.json`` at or directly inside ``path``.

    Only these small manifest files are read (≤ 256 KiB); never a credential file."""
    candidates = [path] if path.is_file() else [path / "package.json", path / "manifest.json", path / "version.json"]
    for candidate in candidates:
        if candidate.name.lower() not in ("package.json", "manifest.json", "version.json") or is_credential_name(candidate.name):
            continue
        stat = _stat(candidate)
        if stat is None or stat.st_size > MAX_MANIFEST_BYTES or not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, str) and 0 < len(version) <= 64:
            return version
    return ""


def _iso(stamp: float | None) -> str:
    if stamp is None:
        return ""
    try:
        return dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _relative(path: Path, profile: EvidenceProfile) -> str:
    try:
        return mask_identity_in_path("~/" + path.relative_to(profile.home).as_posix())
    except ValueError:
        return mask_identity_in_path(path)


def path_presence_rows(
    tool: AiTool,
    profile: EvidenceProfile,
    matches: Sequence[ExpandedPath],
) -> list[AiRow]:
    """The ``install_kind=path`` presence row for one tool and profile (empty if nothing matched)."""
    evidence = [match for match in matches if not match.template.shared and not match.template.credential]
    if not evidence:
        return []
    stamps: list[float] = []
    for match in evidence:
        stat = _stat(match.path)
        if stat is not None:
            stamps.append(stat.st_mtime)
    shallowest = min(evidence, key=lambda match: (len(match.path.parts), str(match.path).lower())).path
    primary = tool_root(shallowest, profile) or shallowest
    version = ""
    for match in evidence:
        root = tool_root(match.path, profile)
        version = read_manifest_version(root) if root is not None else ""
        if version:
            break
    newest = _iso(max(stamps)) if stamps else ""
    kinds = sorted({match.template.kind or "path" for match in evidence})
    sample = sorted({_relative(match.path, profile) for match in evidence})
    return [
        AiRow(
            artifact_type="ai-tool-presence",
            tool=tool.id,
            tool_label=tool.label,
            account_key=profile_account_key(profile),
            profile_label=profile.label,
            user=profile.user,
            path=mask_identity_in_path(primary),
            timestamp=newest,
            timestamp_kind="modified" if newest else "",
            modified_at=newest,
            coverage_status=tool.coverage_status(match.template for match in evidence),
            parser=PARSER,
            payload={
                "install_kind": "path",
                "source": "catalog-path",
                "category": tool.category,
                "vendor": tool.vendor,
                "version": version,
                "mtime": newest,
                "earliest_mtime": _iso(min(stamps)) if stamps else "",
                "matched_path_count": len(evidence),
                "matched_paths": sample[:MAX_MATCHED_PATH_SAMPLE],
                "matched_paths_truncated": len(sample) > MAX_MATCHED_PATH_SAMPLE,
                "matched_path_kinds": kinds,
                "retention": tool.retention,
                "retention_auto_delete": tool.retention_auto_delete,
                "catalog_confidence": tool.confidence,
                "os": profile.os,
                "env_override_vars": list(tool.env_vars[:8]),
            },
        )
    ]


def _credential_row(tool: AiTool, profile: EvidenceProfile, path: Path, *, recognized_by: str, catalog_kind: str) -> AiRow | None:
    stat = _stat(path)
    if stat is None:
        return None
    modified = _iso(stat.st_mtime)
    return AiRow(
        artifact_type="ai-credential-presence",
        tool=tool.id,
        tool_label=tool.label,
        account_key=profile_account_key(profile),
        profile_label=profile.label,
        user=profile.user,
        path=mask_identity_in_path(path),
        timestamp=modified,
        timestamp_kind="modified" if modified else "",
        modified_at=modified,
        coverage_status=tool.coverage_status(),
        parser=PARSER,
        payload={
            "credential_kind": recognized_by,
            "catalog_kind": catalog_kind,
            "is_directory": path.is_dir(),
            "size": None if path.is_dir() else int(stat.st_size),
            "mtime": modified,
            # Fixed policy flags: the value and any digest of it are never collected.
            "value_collected": False,
            "hash_collected": False,
            "os": profile.os,
        },
    )


def _scan_credential_names(root: Path, cache: DirCache) -> Iterator[Path]:
    """Credential-named files below a tool folder (bounded depth / entries, big folders skipped)."""
    frontier = [root]
    seen = 0
    for _depth in range(CREDENTIAL_SCAN_DEPTH + 1):
        following: list[Path] = []
        for folder in frontier:
            for name, path, is_dir in cache.entries(folder):
                seen += 1
                if seen > CREDENTIAL_SCAN_ENTRY_LIMIT:
                    return
                if is_credential_name(path.name):
                    yield path
                    continue
                if is_dir and name not in _SKIP_SCAN_DIRS:
                    following.append(path)
        frontier = following
        if not frontier:
            return


def credential_rows(
    tool: AiTool,
    profile: EvidenceProfile,
    matches: Sequence[ExpandedPath],
    cache: DirCache,
    *,
    seen: set[str],
) -> list[AiRow]:
    """``ai-credential-presence`` rows for one tool and profile (``seen`` de-duplicates paths
    across tools that share a folder)."""
    rows: list[AiRow] = []

    def add(path: Path, recognized_by: str, catalog_kind: str) -> None:
        key = str(path).lower()
        if key in seen or len(seen) >= MAX_CREDENTIAL_ROWS_PER_PROFILE:
            return
        row = _credential_row(tool, profile, path, recognized_by=recognized_by, catalog_kind=catalog_kind)
        if row is not None:
            seen.add(key)
            rows.append(row)

    roots: list[Path] = []
    for match in matches:
        if match.template.credential and not match.template.shared:
            if match.path.is_dir():
                for _name, path, is_dir in cache.entries(match.path):
                    if not is_dir:
                        add(path, "catalog-credential", match.template.kind)
            else:
                add(match.path, "catalog-credential", match.template.kind)
        if match.template.shared:
            continue
        root = tool_root(match.path, profile)
        if root is not None and root not in roots:
            roots.append(root)
    for root in roots:
        for path in _scan_credential_names(root, cache):
            add(path, "name-pattern", "")
    return rows


def presence_rows_for_profile(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    """Path presence then credential presence for every product tool of the catalog."""
    credential_seen: set[str] = set()
    for tool in catalog.product_tools:
        matches = expand_paths(tool, profile.os, [profile], catalog=catalog, cache=cache)
        if not matches:
            continue
        yield from path_presence_rows(tool, profile, matches)
        if any(not match.template.shared for match in matches):
            yield from credential_rows(tool, profile, matches, cache, seen=credential_seen)


def _mask_value(value: object) -> object:
    if isinstance(value, str):
        return mask_identity_in_path(value)
    if isinstance(value, (list, tuple)):
        return [_mask_value(item) for item in value]
    return value


def mask_row_identity(row: AiRow) -> AiRow:
    """``row`` with email-like tokens masked in ``path`` and every text (or list-of-text) payload
    value — lane A payloads hold paths, names and catalog labels only, never message bodies."""
    row.path = mask_identity_in_path(row.path)
    row.payload = {key: _mask_value(value) for key, value in row.payload.items()}
    return row


_LANE_A_ADAPTER = PARSER  # lane A rows carry no ``adapter``; they are listed under the parser id


def _row_adapter(row: AiRow) -> str:
    return str(row.payload.get("adapter") or row.parser or _LANE_A_ADAPTER)


def _credential_key(row: AiRow) -> tuple[str, str, str]:
    path = mask_identity_in_path(row.path).replace("\\", "/").rstrip("/").lower()
    return (row.user.lower(), path, str(row.payload.get("key_name") or ""))


def _unique(values: Iterable[object]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value or "")
        if text and text not in out:
            out.append(text)
    return out


def _merge_credential_group(group: Sequence[AiRow]) -> AiRow:
    # The adapter-specific row (lane B, ``adapter`` set) is the base: its credential_kind wins.
    base = next((row for row in group if row.payload.get("adapter")), group[0])
    payload = dict(base.payload)
    for row in group:
        for key, value in row.payload.items():
            payload.setdefault(key, value)
    payload["adapters"] = _unique(_row_adapter(row) for row in group)
    payload["credential_kinds"] = _unique(row.payload.get("credential_kind") for row in group)
    payload["merged_row_count"] = len(group)
    tools = _unique(row.tool for row in group)
    if len(tools) > 1:
        payload["tools"] = tools
    timed = base if base.timestamp else next((row for row in group if row.timestamp), base)
    return dataclasses.replace(
        base,
        path=mask_identity_in_path(base.path),
        payload=payload,
        timestamp=timed.timestamp,
        timestamp_kind=timed.timestamp_kind,
        modified_at=base.modified_at or next((row.modified_at for row in group if row.modified_at), ""),
    )


def dedupe_credential_rows(rows: Iterable[AiRow]) -> Iterator[AiRow]:
    """Pass every row through; ``ai-credential-presence`` rows are held and emitted after the
    stream, one per (profile user, masked path, key name), in first-seen order."""
    groups: dict[tuple[str, str, str], list[AiRow]] = {}
    for row in rows:
        if row.artifact_type != "ai-credential-presence":
            yield row
            continue
        groups.setdefault(_credential_key(row), []).append(row)
    for group in groups.values():
        yield _merge_credential_group(group)
