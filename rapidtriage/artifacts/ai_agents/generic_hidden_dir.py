"""Unknown AI tool candidates: home dot-folders with a session-like layout (R7 stage 3.5, lane A).

The PC survey found AI tools that no catalog listed (ZCode, claude-swap, codegraph) by looking at
home ``.<name>`` folders. This detector does the same for every profile: a dot-folder that no
catalog template claims and that is not a well-known developer / system folder, whose top three
levels contain session-like folders (``sessions``, ``conversations``, ``history``, ``memory``,
``transcripts``…) and / or ``*.jsonl`` / ``*.sqlite`` / ``*.vscdb`` / ``*.db`` files, becomes an
``unknown-ai-tool-candidate`` row with a structure summary: counts by extension, the session-like
folder names, size and mtime range. File contents are never read; file names are not listed
(only folder names, with e-mail-like text masked).
"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from collections.abc import Iterator

from ...core.ai_catalog.catalog import AiCatalog, DirCache, catalog_home_roots
from .base import AiRow, EvidenceProfile, profile_account_key

__all__ = ["KNOWN_NON_AI_DOT_DIRS", "SESSION_DIR_NAMES", "hidden_dir_candidate_rows"]

PARSER = "ai-unknown-tool-candidate"
SCAN_DEPTH = 3
SCAN_ENTRY_LIMIT = 4000
MAX_FOLDER_NAMES = 20
SESSION_DIR_NAMES = frozenset(
    {
        "sessions", "session", "conversations", "conversation", "history", "memory", "memories", "transcripts",
        "transcript", "chats", "chat", "threads", "rollout", "rollouts", "agents", "agent", "prompts", "brain",
    }
)
_DATA_SUFFIXES = (".jsonl", ".sqlite", ".sqlite3", ".vscdb", ".db")
# Developer / system dot-folders that are not AI tools (never reported as candidates).
KNOWN_NON_AI_DOT_DIRS = frozenset(
    {
        ".git", ".ssh", ".gnupg", ".vscode", ".vscode-insiders", ".vscode-oss", ".vscode-server", ".config", ".local",
        ".cache", ".npm", ".nvm", ".node-gyp", ".yarn", ".pnpm-store", ".bun", ".deno", ".cargo", ".rustup", ".go",
        ".docker", ".kube", ".minikube", ".gradle", ".m2", ".ivy2", ".sbt", ".android", ".conda", ".ipython",
        ".jupyter", ".matplotlib", ".keras", ".vim", ".emacs.d", ".oh-my-zsh", ".pyenv", ".rbenv", ".dotnet",
        ".nuget", ".templateengine", ".azure", ".aws", ".gcloud", ".mozilla", ".thunderbird", ".java", ".eclipse",
        ".idlerc", ".python_history", ".ms-ad", ".wdc", ".librarymanager", ".designer", ".pki", ".dbus", ".gnome",
        ".kde", ".thumbnails", ".trash", ".dropbox", ".dropbox-dist", ".icloud", ".streamlit", ".vagrant.d",
        ".terraform.d", ".rest-client", ".redhat", ".sonarlint", ".gem", ".bundle", ".composer", ".expo",
        ".swiftpm", ".ollama", ".lmstudio", ".huggingface", ".pip", ".virtualenvs", ".poetry", ".pylint.d",
        ".mypy_cache", ".ruff_cache", ".pytest_cache", ".tox", ".nx", ".angular-config", ".electron",
        ".electron-gyp", ".playwright", ".cypress", ".wine", ".steam", ".zoom", ".teams", ".jdks", ".gradle-wrapper",
        ".dart", ".dartserver", ".pub-cache", ".flutter", ".flutter-devtools", ".tmux", ".zsh_sessions",
        ".bash_sessions", ".anydesk", ".putty", ".fontconfig", ".texlive", ".wget-hsts",
    }
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _iso(stamp: float | None) -> str:
    if stamp is None:
        return ""
    try:
        return dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _mask(name: str) -> str:
    return _EMAIL_RE.sub("<email>", name)


def _summary(root, cache: DirCache) -> dict[str, object]:
    extensions: Counter[str] = Counter()
    session_dirs: set[str] = set()
    folder_names: list[str] = []
    files = dirs = 0
    total = 0
    stamps: list[float] = []
    seen = 0
    frontier = [root]
    truncated = False
    for depth in range(SCAN_DEPTH):
        following = []
        for folder in frontier:
            for name, path, is_dir in cache.entries(folder):
                seen += 1
                if seen > SCAN_ENTRY_LIMIT:
                    truncated = True
                    break
                try:
                    stat = path.stat()
                except OSError:
                    continue
                stamps.append(stat.st_mtime)
                if is_dir:
                    dirs += 1
                    if name in SESSION_DIR_NAMES:
                        session_dirs.add(name)
                    if depth == 0 and len(folder_names) < MAX_FOLDER_NAMES:
                        folder_names.append(_mask(path.name))
                    following.append(path)
                else:
                    files += 1
                    total += int(stat.st_size)
                    suffix = path.suffix.lower()
                    extensions[suffix if suffix else "(none)"] += 1
                    if name in ("history.jsonl", "history"):
                        session_dirs.add(name)
            if truncated:
                break
        frontier = following
        if truncated or not frontier:
            break
    return {
        "file_count": files,
        "folder_count": dirs,
        "total_bytes": total,
        "extension_counts": dict(sorted(extensions.items(), key=lambda item: (-item[1], item[0]))[:15]),
        "jsonl_count": extensions.get(".jsonl", 0),
        "sqlite_count": extensions.get(".sqlite", 0) + extensions.get(".sqlite3", 0) + extensions.get(".db", 0),
        "vscdb_count": extensions.get(".vscdb", 0),
        "session_like_names": sorted(session_dirs),
        "top_folder_names": sorted(folder_names),
        "newest_mtime": _iso(max(stamps)) if stamps else "",
        "oldest_mtime": _iso(min(stamps)) if stamps else "",
        "scan_depth": SCAN_DEPTH,
        "scan_truncated": truncated,
    }


def _is_candidate(summary: dict[str, object]) -> bool:
    session_like = bool(summary["session_like_names"])
    data_files = int(summary["jsonl_count"]) + int(summary["sqlite_count"]) + int(summary["vscdb_count"])  # type: ignore[arg-type]
    return (session_like and data_files > 0) or int(summary["vscdb_count"]) > 0 or int(summary["jsonl_count"]) >= 3  # type: ignore[arg-type]


def hidden_dir_candidate_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    # ``..gemini`` (a double-dot copy seen on the survey PC) counts as the known ``.gemini``.
    known = {item.lstrip(".") for item in catalog_home_roots(catalog) | KNOWN_NON_AI_DOT_DIRS}
    for name, path, is_dir in cache.entries(profile.home):
        if not is_dir or not name.startswith(".") or name.lstrip(".") in known:
            continue
        summary = _summary(path, cache)
        if not _is_candidate(summary):
            continue
        newest = str(summary["newest_mtime"])
        yield AiRow(
            artifact_type="unknown-ai-tool-candidate",
            tool="unknown",
            tool_label=_mask(path.name),
            account_key=profile_account_key(profile),
            profile_label=profile.label,
            user=profile.user,
            path=str(path),
            timestamp=newest,
            timestamp_kind="modified" if newest else "",
            modified_at=newest,
            coverage_status="unverified",
            parser=PARSER,
            payload={
                "folder_name": _mask(path.name),
                "detection": "home-dot-folder-session-layout",
                "reason_code": "not-in-catalog-session-like-layout",
                "os": profile.os,
                **summary,
            },
        )
