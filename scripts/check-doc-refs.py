#!/usr/bin/env python3
"""Scan documentation for stale references to repository paths.

Checks ``README.md`` and ``docs/**/*.md`` for inline-code tokens and markdown
link targets that look like repo-relative paths (``rapidtriage/core/run.py``,
``scripts/build-release.py``, ``api/app.py``-style package-relative tokens)
and reports any that no longer resolve to a real file or directory.

Historical record documents (``docs/plans/``, ``docs/validation/``, dated
``release-notes-*``/batch validation records) are reported as informational
only: they are records of what was true when written and are intentionally
not rewritten.

Exit status:
    1  stale references found in non-historical docs
    0  clean (or --warn-only)
"""
from __future__ import annotations

# Force UTF-8 stdio so JSON output with non-ASCII evidence text (e.g.
# Korean filenames) survives Windows consoles whose default codec is cp1252.
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Top-level directories that hold committed source/docs/test content. A
# backtick token or link target starting with one of these is treated as a
# repo-path reference and must resolve. Output/generated roots (logs/,
# release-ci/, qc-runs/, rapidtriage-sample/, OUTPUT_DIR/, ...) are not in
# this set, so example output paths are never flagged.
REPO_ROOT_PREFIXES = (
    "rapidtriage",
    "dashcam_tools",
    "tests",
    "scripts",
    "docs",
    "engines",
    "tools",
    ".github",
)

# Second-level prefixes: tokens like ``api/app.py`` or ``windows/foo.ps1``
# that omit the package root. Each is resolved under these parent dirs.
NESTED_PREFIX_PARENTS = (
    "rapidtriage",
    "scripts",
)


def _nested_first_segments() -> frozenset[str]:
    """Real second-level directory names under the nested parents."""
    segments: set[str] = set()
    for parent in NESTED_PREFIX_PARENTS:
        parent_dir = REPO_ROOT / parent
        if parent_dir.is_dir():
            segments.update(
                child.name for child in parent_dir.iterdir() if child.is_dir()
            )
    segments.discard("__pycache__")
    return frozenset(segments)


NESTED_FIRST_SEGMENTS = _nested_first_segments()

# Gitignored build-output subtrees inside source roots (e.g. cargo target/).
# References to paths under these are build artifacts, not committed files.
IGNORED_SUBTREES = (
    "engines/rust/target",
)

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
FENCED_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
DATE_RE = re.compile(r"20\d\d[-_]\d\d[-_]\d\d")
BATCH_RECORD_RE = re.compile(r"rapidtriage-core-forensics-\d+-\d+-validation\.md$")

# Token characters stripped from both ends before resolving.
TOKEN_STRIP = "\"'()[]{}<>,;:!"

# Extensions that make a bare second-level token (``api/app.py``) plausible
# as a repo path. Directory-style tokens (trailing slash) are also checked.
SOURCE_EXTENSIONS = (
    ".py",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".sh",
    ".ps1",
    ".bat",
    ".rs",
    ".ts",
    ".js",
    ".txt",
    ".cfg",
    ".ini",
)


@dataclass
class Finding:
    doc: str
    line: int
    ref: str
    historical: bool


def is_historical_doc(doc: Path) -> bool:
    """Docs that are point-in-time records rather than living references."""
    rel = doc.relative_to(REPO_ROOT).as_posix()
    if rel.startswith("docs/plans/") or rel.startswith("docs/validation/"):
        return True
    name = doc.name
    if name.startswith("release-notes-") or BATCH_RECORD_RE.search(name):
        return True
    return bool(DATE_RE.search(name))


def candidate_tokens(text: str) -> list[str]:
    """Extract whitespace-separated candidate path tokens from code text."""
    tokens: list[str] = []
    for raw in text.split():
        token = raw.strip(TOKEN_STRIP)
        if token:
            tokens.append(token)
    return tokens


def looks_like_path(token: str) -> bool:
    """Cheap filter before resolving: must be a relative multi-segment path."""
    dot_relative = token.startswith("./")
    if dot_relative:
        token = token[2:]
    if "/" not in token:
        return False
    if token.startswith(("/", "-", "~", "..")):
        return False
    if any(mark in token for mark in ("*", "$", "{", "}", "<", ">", "...", "%")):
        return False
    first = token.split("/", 1)[0]
    if dot_relative:
        # ``./validation/pkg.json``-style tokens are example output/operator
        # paths; only check them when they name a committed source root.
        return first in REPO_ROOT_PREFIXES
    if first in REPO_ROOT_PREFIXES:
        return True
    # ``api/app.py``-style: only when the first segment is a real subdir of a
    # package root (api/, core/, windows/, ...) — otherwise tokens like
    # ``db/video_index.json`` describing evidence layout are not repo refs.
    if first not in NESTED_FIRST_SEGMENTS:
        return False
    if token.endswith("/"):
        return True
    return token.rsplit("/", 1)[1].endswith(SOURCE_EXTENSIONS)


def resolve_ref(token: str) -> str | None:
    """Return the repo-relative path a token resolves to, or None if stale.

    Returns the resolved relative path on success, or None when no candidate
    location exists.
    """
    cleaned = token.removeprefix("./")
    cleaned = cleaned.split("#", 1)[0]
    # ``tests/test_x.py::test_name`` and ``file.py:123`` reference styles.
    cleaned = cleaned.split("::", 1)[0]
    cleaned = re.sub(r":\d+$", "", cleaned)
    is_dir_ref = cleaned.endswith("/")
    cleaned = cleaned.rstrip("/")
    if not cleaned:
        return ""

    candidates = [REPO_ROOT / cleaned]
    first = cleaned.split("/", 1)[0]
    if any(
        cleaned == subtree or cleaned.startswith(subtree + "/")
        for subtree in IGNORED_SUBTREES
    ):
        return cleaned
    if first not in REPO_ROOT_PREFIXES:
        for parent in NESTED_PREFIX_PARENTS:
            candidates.append(REPO_ROOT / parent / cleaned)

    for candidate in candidates:
        if is_dir_ref:
            if candidate.is_dir():
                return candidate.relative_to(REPO_ROOT).as_posix() + "/"
        elif candidate.exists():
            return candidate.relative_to(REPO_ROOT).as_posix()
    return None


def iter_refs(doc: Path) -> list[tuple[int, str]]:
    """Yield (line_number, raw_ref_token) pairs from a markdown document."""
    text = doc.read_text(encoding="utf-8")
    refs: list[tuple[int, str]] = []

    # Markdown link targets: [text](docs/foo.md), skip external/anchor links.
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = match.group(1).strip("<>")
        if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
            continue
        line = text.count("\n", 0, match.start()) + 1
        refs.append((line, target))

    # Inline code spans.
    for match in CODE_SPAN_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        refs.extend((line, token) for token in candidate_tokens(match.group(1)))

    # Fenced code blocks (command examples carry bare path tokens).
    for match in FENCED_BLOCK_RE.finditer(text):
        base_line = text.count("\n", 0, match.start()) + 1
        block = match.group(1)
        for offset, block_line in enumerate(block.split("\n")):
            refs.extend(
                (base_line + offset, token) for token in candidate_tokens(block_line)
            )

    return refs


def scan(docs: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        historical = is_historical_doc(doc)
        seen: set[tuple[int, str]] = set()
        for line, token in iter_refs(doc):
            if not looks_like_path(token):
                continue
            key = (line, token)
            if key in seen:
                continue
            seen.add(key)
            resolved = resolve_ref(token)
            if resolved is None:
                findings.append(
                    Finding(
                        doc=doc.relative_to(REPO_ROOT).as_posix(),
                        line=line,
                        ref=token,
                        historical=historical,
                    )
                )
    return findings


def collect_docs() -> list[Path]:
    docs = [REPO_ROOT / "README.md"]
    docs.extend(sorted((REPO_ROOT / "docs").rglob("*.md")))
    return [doc for doc in docs if doc.is_file()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check markdown docs for stale references to repo paths",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="always exit 0 (report only, for informational CI steps)",
    )
    args = parser.parse_args(argv)

    findings = scan(collect_docs())
    active = [finding for finding in findings if not finding.historical]
    historical = [finding for finding in findings if finding.historical]

    if args.json:
        print(
            json.dumps(
                {
                    "stale_active": [finding.__dict__ for finding in active],
                    "stale_historical": [finding.__dict__ for finding in historical],
                    "stale_active_count": len(active),
                    "stale_historical_count": len(historical),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for finding in active:
            print(f"STALE {finding.doc}:{finding.line}: `{finding.ref}` does not exist")
        for finding in historical:
            print(
                f"STALE (historical, left as record) "
                f"{finding.doc}:{finding.line}: `{finding.ref}`"
            )
        print(
            f"doc-ref check: {len(active)} stale reference(s) in maintained docs, "
            f"{len(historical)} in historical record docs"
        )

    if active and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
