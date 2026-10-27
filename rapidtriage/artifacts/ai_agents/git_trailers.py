"""AI commit trailers in git repositories of the evidence (R7 stage 3.5 §3.4, lane C).

Reads a repository's ``.git`` folder with the standard library only -- never the ``git`` binary,
never a write:

* start points: ``HEAD``, loose refs (``refs/heads``, ``refs/remotes``, ``refs/tags``), ``packed-refs``
  and the reflogs (``logs/HEAD``, ``logs/refs/**``: the *new* object id of every line);
* commit objects: loose objects (``objects/xx/<38 hex>``, zlib) and packed objects found through the
  pack index (``objects/pack/*.idx`` v2), deltas (``OFS_DELTA`` / ``REF_DELTA``) resolved within the
  same pack up to depth 50. A delta whose base is elsewhere (thin pack, other pack) is counted in
  ``delta_commits_unread`` and its parents are not followed;
* walk: from the start points over ``parent`` lines, at most :data:`MAX_COMMITS_PER_REPO` commits
  per repository (``commits_capped``).

A commit is AI-attributed when its message has a trailer that names an AI tool --
``Co-Authored-By:`` with an AI co-author (name or address, :data:`AI_COAUTHOR_PATTERNS`; human
co-authors never count), ``Agent-Logs-Url:`` or a ``Generated with …`` line. Each such commit
becomes one ``ai-code-attribution`` row (``source = git-trailer``); each repository one
``ai-tool-presence`` row (``presence_kind = git-repo-scan``) with the scan counts, so the report can
state "N of M read commits carry an AI trailer". Commit subjects are masked
(:func:`redact.redact_str`) and e-mail addresses in trailers are reduced to ``u-<hash>@domain``.

Repositories come from the run's files inventory (any listed path inside a ``.git`` folder); only
paths that exist on disk are read (directory and mounted-image inputs).
"""

from __future__ import annotations

import datetime as dt
import mmap
import re
import zlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ...core.ai_catalog.catalog import AiCatalog, load_catalog
from .base import AiRow
from .redact import mask_emails_in, redact_str

__all__ = [
    "AI_COAUTHOR_PATTERNS",
    "MAX_COMMITS_PER_REPO",
    "GitRepoScan",
    "ai_trailers",
    "git_dirs_from_paths",
    "git_trailer_rows",
    "scan_repository",
]

PARSER = "ai-git-trailers"
MAX_COMMITS_PER_REPO = 5000
MAX_REPOS = 200
MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_REFLOG_BYTES = 32 * 1024 * 1024
MAX_IDX_BYTES = 512 * 1024 * 1024
SUBJECT_CHARS = 200
TRAILER_CHARS = 300
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_REFLOG_LINE = re.compile(r"^([0-9a-f]{40}) ([0-9a-f]{40}) ")
_PERSON = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^>]*)>\s+(?P<ts>-?\d+)\s+(?P<tz>[+-]\d{4})")
_TRAILER_CO = re.compile(r"^\s*co-authored-by\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_TRAILER_LOGS = re.compile(r"^\s*agent-logs-url\s*:\s*(?P<value>\S+)\s*$", re.IGNORECASE)
_GENERATED = re.compile(r"\bgenerated\s+(?:with|by)\b\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_URL_HOST = re.compile(r"https?://([^/\s)>\]]+)", re.IGNORECASE)

# (pattern over "name <email>" / generated-with text / URL, catalog tool id). First match wins;
# patterns name products, never a generic word a person's name could hold.
AI_COAUTHOR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"claude\s*code|claude\.com/claude-code|code\.claude\.com", re.IGNORECASE), "claude-code"),
    (re.compile(r"\bclaude\b|@anthropic\.com\b|anthropic", re.IGNORECASE), "claude-code"),
    (re.compile(r"cursor\s*agent|cursoragent@|@cursor\.(?:com|sh)\b|\bcursor\.com\b", re.IGNORECASE), "cursor"),
    (re.compile(r"copilot|copilot-swe-agent|githubcopilot\.com", re.IGNORECASE), "github-copilot-coding-cloud-agent"),
    (re.compile(r"\bcodex\b|@openai\.com\b|chatgpt", re.IGNORECASE), "codex"),
    (re.compile(r"devin-ai-integration|\bdevin\b|devin\.ai", re.IGNORECASE), "devin"),
    (re.compile(r"\bjules\b|jules\.google", re.IGNORECASE), "jules"),
    (re.compile(r"gemini", re.IGNORECASE), "gemini-cli"),
    (re.compile(r"\baider\b", re.IGNORECASE), "aider"),
    (re.compile(r"windsurf|codeium", re.IGNORECASE), "windsurf"),
    (re.compile(r"\bamp\s*(?:code)?\b.*@ampcode\.com|ampcode\.com", re.IGNORECASE), "amp"),
    (re.compile(r"\bkiro\b", re.IGNORECASE), "kiro"),
    (re.compile(r"\bcline\b", re.IGNORECASE), "cline"),
    (re.compile(r"opencode", re.IGNORECASE), "opencode"),
    (re.compile(r"factory-droid|@factory\.ai\b", re.IGNORECASE), "droid"),
)


def _tool_for(text: str) -> str:
    for pattern, tool in AI_COAUTHOR_PATTERNS:
        if pattern.search(text):
            return tool
    return ""


def ai_trailers(message: str) -> list[dict[str, str]]:
    """AI trailers of a commit message: ``[{kind, tool, value}]`` (``kind`` = co-authored-by /
    agent-logs-url / generated-with). A co-author that names no AI tool is not returned."""
    found: list[dict[str, str]] = []
    for line in message.splitlines():
        co = _TRAILER_CO.match(line)
        if co:
            value = co.group("value")
            tool = _tool_for(value)
            if tool:
                found.append({"kind": "co-authored-by", "tool": tool, "value": value})
            continue
        logs = _TRAILER_LOGS.match(line)
        if logs:
            value = logs.group("value")
            host = _URL_HOST.search(value)
            found.append({"kind": "agent-logs-url", "tool": _tool_for(value), "value": host.group(1).lower() if host else ""})
            continue
        generated = _GENERATED.search(line)
        if generated:
            value = generated.group("value")
            tool = _tool_for(value)
            if tool:
                found.append({"kind": "generated-with", "tool": tool, "value": value})
    return found


# --- object store ---------------------------------------------------------------------------------


MAX_DELTA_DEPTH = 50


def _varint(data: bytes, position: int) -> tuple[int, int]:
    value = shift = 0
    while position < len(data):
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, position


def apply_delta(base: bytes, delta: bytes) -> bytes | None:
    """A git pack delta (copy / insert instructions) applied to ``base``; ``None`` when malformed."""
    source_size, position = _varint(delta, 0)
    target_size, position = _varint(delta, position)
    if source_size != len(base) or target_size > MAX_OBJECT_BYTES:
        return None
    out = bytearray()
    while position < len(delta):
        op = delta[position]
        position += 1
        if op & 0x80:
            copy_offset = copy_size = 0
            for bit in range(4):
                if op & (1 << bit):
                    copy_offset |= delta[position] << (8 * bit)
                    position += 1
            for bit in range(3):
                if op & (0x10 << bit):
                    copy_size |= delta[position] << (8 * bit)
                    position += 1
            copy_size = copy_size or 0x10000
            if copy_offset + copy_size > len(base):
                return None
            out += base[copy_offset : copy_offset + copy_size]
        elif op:
            out += delta[position : position + op]
            position += op
        else:
            return None
    return bytes(out) if len(out) == target_size else None


class _PackIndex:
    """One ``.idx`` v2 + its ``.pack`` (memory-mapped, read only)."""

    def __init__(self, idx_path: Path, pack_path: Path) -> None:
        self.idx_handle = idx_path.open("rb")
        self.idx = mmap.mmap(self.idx_handle.fileno(), 0, access=mmap.ACCESS_READ)
        if self.idx[:4] != b"\377tOc" or int.from_bytes(self.idx[4:8], "big") != 2:
            self.close()
            raise ValueError("unsupported pack index")
        self.count = int.from_bytes(self.idx[8 + 255 * 4 : 8 + 256 * 4], "big")
        self.names_at = 8 + 256 * 4
        self.offsets_at = self.names_at + self.count * 20 + self.count * 4
        self.large_at = self.offsets_at + self.count * 4
        self.pack_handle = pack_path.open("rb")
        self.pack = mmap.mmap(self.pack_handle.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self) -> None:
        for name in ("idx", "idx_handle", "pack", "pack_handle"):
            item = getattr(self, name, None)
            if item is not None:
                try:
                    item.close()
                except (OSError, ValueError, BufferError):
                    pass

    def offset(self, sha: bytes) -> int | None:
        first = sha[0]
        low = int.from_bytes(self.idx[8 + (first - 1) * 4 : 8 + first * 4], "big") if first else 0
        high = int.from_bytes(self.idx[8 + first * 4 : 8 + (first + 1) * 4], "big")
        while low < high:
            middle = (low + high) // 2
            start = self.names_at + middle * 20
            name = self.idx[start : start + 20]
            if name == sha:
                raw = int.from_bytes(self.idx[self.offsets_at + middle * 4 : self.offsets_at + middle * 4 + 4], "big")
                if raw & 0x80000000:
                    position = self.large_at + (raw & 0x7FFFFFFF) * 8
                    return int.from_bytes(self.idx[position : position + 8], "big")
                return raw
            if name < sha:
                low = middle + 1
            else:
                high = middle
        return None

    def _inflate(self, position: int, size: int) -> bytes:
        inflater = zlib.decompressobj()
        out = bytearray()
        while not inflater.eof and len(out) <= size:
            chunk = self.pack[position : position + 65536]
            if not chunk:
                break
            position += len(chunk)
            out += inflater.decompress(chunk, size + 1 - len(out))
            if inflater.unconsumed_tail:
                break
        return bytes(out[:size])

    def read(self, offset: int, depth: int = 0) -> tuple[int, bytes | None]:
        """``(object type, inflated bytes)``. Deltas (``OFS_DELTA`` / ``REF_DELTA`` against an object of
        the same pack) are resolved up to :data:`MAX_DELTA_DEPTH`; bytes are ``None`` (type 6/7) when
        the base cannot be resolved here, and for an oversize object."""
        position = offset
        byte = self.pack[position]
        kind = (byte >> 4) & 7
        size = byte & 15
        shift = 4
        position += 1
        while byte & 0x80:
            byte = self.pack[position]
            size |= (byte & 0x7F) << shift
            shift += 7
            position += 1
        if size > MAX_OBJECT_BYTES:
            return kind, None
        if kind not in (6, 7):
            return kind, self._inflate(position, size)
        if depth >= MAX_DELTA_DEPTH:
            return kind, None
        if kind == 6:  # OFS_DELTA: negative offset varint
            byte = self.pack[position]
            distance = byte & 0x7F
            position += 1
            while byte & 0x80:
                byte = self.pack[position]
                distance = ((distance + 1) << 7) | (byte & 0x7F)
                position += 1
            base_offset: int | None = offset - distance
        else:  # REF_DELTA: base object id (same pack only)
            base_offset = self.offset(bytes(self.pack[position : position + 20]))
            position += 20
        if base_offset is None or base_offset < 0:
            return kind, None
        base_kind, base = self.read(base_offset, depth + 1)
        if base is None:
            return kind, None
        result = apply_delta(base, self._inflate(position, size))
        return (base_kind, result) if result is not None else (kind, None)


@dataclass
class GitRepoScan:
    """Counts of one repository scan (the ``git-repo-scan`` row)."""

    git_dir: Path
    commits_read: int = 0
    ai_commits: int = 0
    commits_capped: bool = False
    delta_commits_unread: int = 0
    missing_objects: int = 0
    start_points: int = 0
    pack_indexes: int = 0
    errors: list[str] = field(default_factory=list)
    tools: dict[str, int] = field(default_factory=dict)
    first_commit_at: str = ""
    last_commit_at: str = ""


class _ObjectStore:
    def __init__(self, git_dir: Path, scan: GitRepoScan) -> None:
        self.objects = git_dir / "objects"
        self.scan = scan
        self.packs: list[_PackIndex] = []
        pack_dir = self.objects / "pack"
        try:
            idx_paths = sorted(pack_dir.glob("*.idx"))
        except OSError:
            idx_paths = []
        for idx_path in idx_paths:
            pack_path = idx_path.with_suffix(".pack")
            try:
                if idx_path.stat().st_size > MAX_IDX_BYTES or not pack_path.is_file():
                    continue
                self.packs.append(_PackIndex(idx_path, pack_path))
            except (OSError, ValueError) as exc:
                scan.errors.append(f"{idx_path.name}: {type(exc).__name__}")
        scan.pack_indexes = len(self.packs)

    def close(self) -> None:
        for pack in self.packs:
            pack.close()

    def commit(self, sha: str) -> bytes | None:
        """The commit body (after the ``commit <len>\\0`` header for loose objects); ``None`` when
        the object is missing, not a commit, or a packed delta."""
        loose = self.objects / sha[:2] / sha[2:]
        try:
            if loose.is_file() and loose.stat().st_size <= MAX_OBJECT_BYTES:
                raw = zlib.decompress(loose.read_bytes())
                header, _, body = raw.partition(b"\0")
                return body if header.startswith(b"commit ") else None
        except (OSError, zlib.error) as exc:
            self.scan.errors.append(f"{sha[:12]}: {type(exc).__name__}")
            return None
        binary = bytes.fromhex(sha)
        for pack in self.packs:
            try:
                offset = pack.offset(binary)
                if offset is None:
                    continue
                kind, data = pack.read(offset)
            except (IndexError, ValueError, zlib.error) as exc:
                self.scan.errors.append(f"{sha[:12]}: {type(exc).__name__}")
                return None
            if data is None:
                if kind in (6, 7):
                    self.scan.delta_commits_unread += 1
                return None
            return data if kind == 1 else None
        self.scan.missing_objects += 1
        return None


# --- refs -----------------------------------------------------------------------------------------


def _read_text(path: Path, limit: int = 1024 * 1024) -> str:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _start_points(git_dir: Path) -> list[str]:
    points: list[str] = []

    def add(value: str) -> None:
        value = value.strip().lower()
        if _HEX40.match(value) and value not in points and value != "0" * 40:
            points.append(value)

    head = _read_text(git_dir / "HEAD").strip()
    if head.startswith("ref:"):
        target = head[4:].strip()
        add(_read_text(git_dir / target))
    else:
        add(head)
    for sub in ("refs/heads", "refs/remotes", "refs/tags"):
        base = git_dir / sub
        try:
            refs = [path for path in base.rglob("*") if path.is_file()]
        except OSError:
            refs = []
        for ref in sorted(refs)[:2000]:
            add(_read_text(ref, 4096))
    for line in _read_text(git_dir / "packed-refs", 32 * 1024 * 1024).splitlines():
        if line and not line.startswith(("#", "^")):
            add(line.split(" ", 1)[0])
    logs = [git_dir / "logs" / "HEAD"]
    try:
        logs.extend(sorted(path for path in (git_dir / "logs" / "refs").rglob("*") if path.is_file())[:2000])
    except OSError:
        pass
    for log in logs:
        for line in _read_text(log, MAX_REFLOG_BYTES).splitlines():
            match = _REFLOG_LINE.match(line)
            if match:
                add(match.group(2))
    return points


# --- commits --------------------------------------------------------------------------------------


def _iso(seconds: str) -> str:
    try:
        return dt.datetime.fromtimestamp(int(seconds), tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _parse_commit(body: bytes) -> tuple[list[str], str, str]:
    """``(parents, committed_at ISO UTC, message)``."""
    text = body.decode("utf-8", errors="replace")
    head, _, message = text.partition("\n\n")
    parents: list[str] = []
    committed = ""
    for line in head.splitlines():
        if line.startswith("parent "):
            parents.append(line[7:].strip().lower())
        elif line.startswith("committer "):
            match = _PERSON.match(line[10:])
            if match:
                committed = _iso(match.group("ts"))
    return parents, committed, message


def scan_repository(git_dir: Path, *, max_commits: int = MAX_COMMITS_PER_REPO) -> tuple[GitRepoScan, list[dict[str, object]]]:
    """Walk one repository: the scan counts and one record per AI-trailer commit."""
    scan = GitRepoScan(git_dir=git_dir)
    store = _ObjectStore(git_dir, scan)
    commits: list[dict[str, object]] = []
    try:
        queue = _start_points(git_dir)
        scan.start_points = len(queue)
        seen: set[str] = set(queue)
        position = 0
        while position < len(queue):
            if scan.commits_read >= max_commits:
                scan.commits_capped = True
                break
            sha = queue[position]
            position += 1
            body = store.commit(sha)
            if body is None:
                continue
            scan.commits_read += 1
            parents, committed, message = _parse_commit(body)
            for parent in parents:
                if parent not in seen and _HEX40.match(parent):
                    seen.add(parent)
                    queue.append(parent)
            if committed:
                if not scan.first_commit_at or committed < scan.first_commit_at:
                    scan.first_commit_at = committed
                if not scan.last_commit_at or committed > scan.last_commit_at:
                    scan.last_commit_at = committed
            trailers = ai_trailers(message)
            if not trailers:
                continue
            scan.ai_commits += 1
            for tool in {item["tool"] for item in trailers if item["tool"]} or {""}:
                scan.tools[tool] = scan.tools.get(tool, 0) + 1
            subject = message.strip().splitlines()[0] if message.strip() else ""
            commits.append({"commit": sha, "committed_at": committed, "subject": subject, "trailers": trailers, "parents": len(parents)})
    finally:
        store.close()
    return scan, commits


def git_dirs_from_paths(paths: Iterable[object], *, limit: int = MAX_REPOS) -> list[Path]:
    """``.git`` folders named by listed paths (``…/.git/HEAD``, ``…\\.git\\objects\\…``) that exist."""
    found: dict[str, Path] = {}
    for raw in paths:
        if not isinstance(raw, str) or ".git" not in raw.lower():
            continue
        text = raw.replace("\\", "/")
        lowered = text.lower()
        index = lowered.find("/.git/")
        if index < 0:
            continue
        git_dir = Path(text[: index + 5])
        key = str(git_dir).casefold()
        if key in found:
            continue
        try:
            if not (git_dir / "HEAD").is_file() or not (git_dir / "objects").is_dir():
                continue
        except OSError:
            continue
        found[key] = git_dir
        if len(found) >= limit:
            break
    return [found[key] for key in sorted(found)]


def _files_paths(files_payload: Mapping[str, object] | None) -> Iterator[object]:
    if not isinstance(files_payload, Mapping):
        return
    for collection in ("inventory", "candidates"):
        rows = files_payload.get(collection)
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, Mapping):
                    yield row.get("path")


def git_trailer_rows(
    files_payload: Mapping[str, object] | None,
    *,
    catalog: AiCatalog | None = None,
    max_commits: int = MAX_COMMITS_PER_REPO,
) -> list[AiRow]:
    """``ai-code-attribution`` (``source = git-trailer``) rows + one ``git-repo-scan`` row per repo."""
    catalog = catalog or load_catalog()
    rows: list[AiRow] = []
    for git_dir in git_dirs_from_paths(_files_paths(files_payload)):
        repo = str(git_dir.parent)
        try:
            scan, commits = scan_repository(git_dir, max_commits=max_commits)
        except (OSError, ValueError, MemoryError) as exc:  # one repository never stops the others
            scan, commits = GitRepoScan(git_dir=git_dir, errors=[f"{type(exc).__name__}: {exc}"[:200]]), []
        for commit in commits:
            trailers = list(commit["trailers"])  # type: ignore[call-overload]
            tool_id = next((item["tool"] for item in trailers if item["tool"]), "")
            tool = catalog.tool(tool_id) if tool_id else None
            committed = str(commit["committed_at"] or "")
            rows.append(
                AiRow(
                    artifact_type="ai-code-attribution",
                    tool=tool.id if tool else "",
                    tool_label=tool.label if tool else "미상 AI 도구",
                    path=str(git_dir / "objects"),
                    timestamp=committed,
                    timestamp_kind="committed" if committed else "",
                    coverage_status="local-verified" if tool else "inferred",
                    parser=PARSER,
                    payload={
                        "source": "git-trailer",
                        "repository": repo,
                        "commit": commit["commit"],
                        "commit_message": redact_str(mask_emails_in(str(commit["subject"])))[:SUBJECT_CHARS],
                        "trailer_kinds": sorted({item["kind"] for item in trailers}),
                        "trailers": [
                            {
                                "kind": item["kind"],
                                "tool": item["tool"],
                                "value": redact_str(mask_emails_in(item["value"]))[:TRAILER_CHARS],
                            }
                            for item in trailers[:10]
                        ],
                        "tools": sorted({item["tool"] for item in trailers if item["tool"]}),
                        "ts": committed,
                        "file": "",
                        "ai_lines": None,
                        "human_lines": None,
                        "ai_percent": None,
                    },
                )
            )
        rows.append(
            AiRow(
                artifact_type="ai-tool-presence",
                tool="",
                tool_label="git 저장소",
                path=str(git_dir),
                timestamp=scan.last_commit_at,
                timestamp_kind="committed" if scan.last_commit_at else "",
                coverage_status="local-verified",
                parser=PARSER,
                payload={
                    "presence_kind": "git-repo-scan",
                    "install_kind": "",
                    "source": "git-trailer",
                    "repository": repo,
                    "commits_read": scan.commits_read,
                    "ai_commits": scan.ai_commits,
                    "ai_commit_tools": dict(sorted(scan.tools.items())),
                    "commits_capped": scan.commits_capped,
                    "commit_cap": max_commits,
                    "delta_commits_unread": scan.delta_commits_unread,
                    "missing_objects": scan.missing_objects,
                    "start_points": scan.start_points,
                    "pack_indexes": scan.pack_indexes,
                    "first_commit_at": scan.first_commit_at,
                    "last_commit_at": scan.last_commit_at,
                    "read_errors": scan.errors[:20],
                    "git_binary_used": False,
                },
            )
        )
    return rows
