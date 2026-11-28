"""Local-path rules and the operator's server root lists.

Shared by the API path gates (``api/app/analyses.py``) and ``rapidtriage web``
(which must check the root lists before the app module is imported: importing
it creates the app and reads the auth token from the environment). Everything
here is lexical except ``overlapping_roots``, which also compares resolved forms.
"""

from __future__ import annotations

import logging
import ntpath
import os

LOGGER = logging.getLogger(__name__)

# Roots an operator allows for analysis/run *inputs* (os.pathsep list). They are
# evidence: never an output target.
ANALYSIS_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
# Roots an operator allows for analysis/run *outputs* (same parsing rules).
ANALYSIS_OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
_BACKSLASH = "\\"


def local_path_problem(text: str) -> str | None:
    """Why ``text`` is not an absolute local path (UNC/device/relative/``~``), else ``None``.

    Lexical only: the filesystem is never touched.
    """
    if text.startswith("~"):
        return "홈 디렉터리(~) 표기는 쓸 수 없습니다"
    if os.name == "nt":
        normalized = text.replace("/", _BACKSLASH)
        if normalized.startswith(_BACKSLASH * 2):
            return r"UNC·장치 경로(\\server, \\?\, \\.\)는 쓸 수 없습니다"
        drive, rest = ntpath.splitdrive(normalized)
        if not drive:
            return "드라이브 문자를 포함한 절대 경로여야 합니다"
        if not rest.startswith(_BACKSLASH):
            return "드라이브 상대 경로(C:foo)는 쓸 수 없습니다"
        return None
    if text.startswith("//"):
        return "네트워크 경로는 쓸 수 없습니다"
    if not text.startswith("/"):
        return "절대 경로여야 합니다"
    return None


def configured_root_entries(env: str) -> list[str]:
    """Entries of ``env`` (an os.pathsep list): quotes stripped; relative/UNC/``~`` entries ignored with a warning."""
    entries: list[str] = []
    for item in os.environ.get(env, "").split(os.pathsep):
        item = item.strip().strip("\"'").strip()
        if not item:
            continue
        problem = local_path_problem(item)
        if problem is not None:
            LOGGER.warning("ignoring %s entry %r: %s", env, item, problem)
            continue
        entries.append(item)
    return entries


def _root_keys(entry: str) -> set[str]:
    keys = {os.path.normcase(os.path.abspath(entry))}
    try:
        keys.add(os.path.normcase(os.path.realpath(entry)))
    except (OSError, ValueError):
        pass
    return keys


def _contains(parent: str, child: str) -> bool:
    """Whether ``child`` is ``parent`` or lies under it (both case-normalized absolute keys).

    Compared by drive (or UNC share) and path components: ``commonpath`` raises
    for a bare share root (``\\\\srv\\share`` has no root separator) next to a
    folder inside it, which would hide the overlap.
    """
    parent_drive, parent_rest = os.path.splitdrive(parent)
    child_drive, child_rest = os.path.splitdrive(child)
    if parent_drive != child_drive:
        return False
    parent_parts = [part for part in parent_rest.split(os.path.sep) if part]
    child_parts = [part for part in child_rest.split(os.path.sep) if part]
    return child_parts[: len(parent_parts)] == parent_parts


def overlapping_roots(inputs: list[str], outputs: list[str]) -> list[tuple[str, str]]:
    """``(input root, output root)`` pairs where one folder is, or contains, the other.

    Compared case-normalized in lexical and resolved form, so an output root that
    is a parent of (or a link into) an evidence root counts: run output would land
    inside the evidence.
    """
    pairs: list[tuple[str, str]] = []
    for evidence in inputs:
        evidence_keys = _root_keys(evidence)
        for output in outputs:
            output_keys = _root_keys(output)
            if any(_contains(a, b) or _contains(b, a) for a in evidence_keys for b in output_keys):
                pairs.append((evidence, output))
    return pairs
