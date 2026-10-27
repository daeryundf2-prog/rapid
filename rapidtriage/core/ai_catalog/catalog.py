"""AI tool catalog loader (R7 stage 3.5 §3.1) — the single source for AI tool knowledge.

``data/*.json`` are copies of ``docs/ai-tool-catalog/*.json`` (``scripts/check-ai-catalog.py``
keeps them identical). The research JSON is heterogeneous (seven files, four path layouts,
free-text confidence notes), so this module normalizes it into :class:`AiTool` records:

* ``paths``: :class:`PathTemplate` (OS, catalog kind, template, normalized confidence,
  credential flag). Templates keep the catalog variables (``%USERPROFILE%``, ``~``, ``%APPDATA%``,
  ``%LOCALAPPDATA%``, ``%TEMP%``, ``$XDG_*``, absolute ``/…`` and ``C:\\…``); ``<…>`` placeholders
  become ``*`` globs and ``{a,b}`` is brace-expanded.
* ``domains`` (hostnames only; generic hosting / analytics hosts are dropped), ``binaries`` and
  ``process_names`` (execution match), ``install`` (npm / pip / winget / msix / vscode-extension
  ids found in the install notes), ``retention`` text and ``confidence``.

:func:`expand_paths` resolves a tool's templates against :class:`EvidenceProfile` homes from
:func:`enumerate_profiles` (every ``Users/<u>``, ``/home/<u>``, ``/Users/<u>`` of an image, or the
evidence root itself when it is a home folder).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .profiles import EvidenceProfile, is_credential_name

__all__ = [
    "CATALOG_DATA_DIR",
    "CATALOG_FILES",
    "CONFIDENCE_LEVELS",
    "TOOL_CATALOG_FILES",
    "AiCatalog",
    "AiTool",
    "ExpandedPath",
    "PathTemplate",
    "ai_service_tokens",
    "catalog_domain_pairs",
    "domains",
    "enumerate_profiles",
    "expand_paths",
    "expand_template",
    "key_prefixes",
    "load_catalog",
    "normalize_confidence",
    "path_templates_from_text",
]

CATALOG_DATA_DIR = Path(__file__).resolve().parent / "data"
TOOL_CATALOG_FILES: tuple[str, ...] = ("chatbots", "cli_agents", "ide_agents", "harnesses", "cloud_agents", "local_llm")
CATALOG_FILES: tuple[str, ...] = (*TOOL_CATALOG_FILES, "infrastructure")
FILE_CATEGORY = {
    "chatbots": "chatbot",
    "cli_agents": "cli_agent",
    "ide_agents": "ide_agent",
    "harnesses": "harness",
    "cloud_agents": "cloud_agent",
    "local_llm": "local_llm",
}
# Normalized confidence, most confident first (``coverage_status`` uses ``official`` for
# ``official-doc``; ``verified-on-test-pc`` is ``local-verified``).
CONFIDENCE_LEVELS: tuple[str, ...] = ("local-verified", "official", "third-party", "inferred", "unverified")
_CONF_TOKENS: tuple[tuple[str, str], ...] = (
    ("verified-on-test-pc", "local-verified"),
    ("local-verified", "local-verified"),
    ("official-doc", "official"),
    ("third-party", "third-party"),
    ("inferred", "inferred"),
    ("unverified", "unverified"),
    ("unknown", "unverified"),
)

# Stable ids that lane B adapters and the rules use; everything else is a slug of the name.
ID_OVERRIDES: dict[str, str] = {
    "OpenAI Codex CLI": "codex",
    "Codex (CLI + IDE extension)": "codex",
    "Claude Code (CLI + IDE extension)": "claude-code",
    "Pi (pi-coding-agent) / Senpi": "pi-coding-agent",
    "Kiro CLI (ex Amazon Q Developer CLI)": "kiro-cli",
    "Cursor CLI / cursor-agent": "cursor-cli",
    "ZCode (Z.ai coding agent; ~/.zcode)": "zcode",
    "claude-swap (Claude account switcher; ~/.claude-swap-backup)": "claude-swap",
    "Bolt (bolt.new / bolt.diy)": "bolt",
    "Bolt.new": "bolt",
    "A. (에이닷)": "adot",
    "Z.ai / GLM": "z-ai",
    "Hermes Agent": "hermes-agent",
    "Hermes Agent (Nous Research)": "hermes-agent",
}
# Catalog entries that describe a surface or a format rather than one product: kept in the catalog
# (instruction files, MCP configs, model formats) but never reported as an installed tool.
META_TOOL_IDS: frozenset[str] = frozenset(
    {
        "other-listed-cli-agents",
        "model-file-formats",
        "mcp-client-configs",
        "instruction-files-other-agents",
        "claude-code-extension-surfaces",
    }
)

_OS_KEYS = {"windows": "windows", "win": "windows", "macos": "macos", "mac": "macos", "linux": "linux"}
_ANCHOR_RE = re.compile(
    r"((?<![\w.])%[A-Za-z_()0-9]+%|\$\{?(?:HOME|XDG_[A-Z_]+|TMPDIR)\}?|(?<![\w.])~(?=[\\/])|(?<![\w.])[A-Za-z]:\\|(?<![^\s\"'(`])/(?=[A-Za-z.]))"
)
# Text that ends a path inside a free-text catalog note.
_PATH_STOP_RE = re.compile(r"\(|;|,\s|,(?=[^\w.<*])|\s-\s|\s\+\s|\s->|\s→|\sor\s|\sand\s|\s\[|\s{2,}|\"|'|`|\)|:\s")
_SPACED_SEGMENTS = ("Application Support", "LM Studio", "Program Files", "Cherry Studio", "Open WebUI", "Msty Studio")
_PLACEHOLDER_RE = re.compile(r"<[^<>]*>")
_BRACE_RE = re.compile(r"\{([^{}]*,[^{}]*)\}")
_GLOB_CHARS = set("*?[")
_FILE_SUFFIXES = {
    "json", "jsonl", "jsonc", "db", "sqlite", "sqlite3", "vscdb", "md", "log", "txt", "exe", "js", "ts", "toml",
    "yaml", "yml", "ini", "pem", "key", "enc", "sh", "ps1", "bin", "gguf", "py", "html", "xml", "plist", "zip",
}
_HOST_RE = re.compile(r"(?<![\w@/.-])(?:\*\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?![\w-])")
_HOST_TLDS = {
    "ai", "app", "bot", "cn", "co", "com", "cloud", "dev", "google", "im", "io", "kr", "me", "net", "new", "org", "sh",
    "so", "tt", "chat",
}
# Hosts that are generic hosting, analytics, identity or vendor-wide portals: matching them would
# flag non-AI browsing as AI use (plan §3.1 single domain source, false-positive guard).
GENERIC_HOSTS: frozenset[str] = frozenset(
    {
        "github.com", "githubusercontent.com", "google.com", "cloud.google.com", "myactivity.google.com",
        "googleapis.com", "oauth2.googleapis.com", "microsoft.com", "x.com", "intercom.io", "fengkongcloud.com",
        "portal101.cn", "volces.com", "brave.com", "vercel.com", "stackblitz.com", "zapier.com", "make.com",
        "integromat.com", "n8n.io", "n8n.cloud", "powerplatform.com", "replit.app", "lovable.app",
        "us.i.posthog.com", "posthog.com", "amazonaws.com", "azure.com", "cloudflare.com", "api.cloudflare.com",
        "npmjs.com", "pypi.org", "aliyun.com", "baidu.com", "naver.com", "kakao.com", "models.dev", "app.factory.ai",
    }
)
# Short hosts that consumers also match as plain substrings (``"pi.ai" in "api.airtable.com"``):
# left out of the shared domain list (see docs/rapidtriage-known-limitations.md, R7 AI lane A).
SUBSTRING_UNSAFE_HOSTS: frozenset[str] = frozenset({"pi.ai"})
_GENERIC_BINARIES = frozenset(
    {
        "agent", "mini", "code", "node", "python", "java", "chat", "app", "cn", "q", "pi", "pdx", "amp", "roo", "kilo",
        "vibe", "cli", "chrome", "msedge", "firefox", "safari", "brave", "opera", "explorer", "iexplore", "electron",
        "rg", "docker", "update", "setup", "helper", "git",
    }
)
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][\w.\-]*/)?[a-z0-9][\w.\-]*$")
_WINGET_RE = re.compile(r"\bwinget\s+(?:install\s+)?(?:--id\s+)?([A-Za-z0-9][\w\-]*\.[A-Za-z0-9][\w.\-]*)")
_MSIX_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9.\-]*_(?=[a-z]*[0-9])[a-z0-9]{13})\b")
_NPM_PHRASE_RE = re.compile(r"\bnpm(?:/bun)?(?:\s+(?:i|install|add))?(?:\s+-g)?(?:\s+package)?\s+(@[\w.\-]+/[\w.\-]+|[a-z][\w.\-]+)")
_PIP_PHRASE_RE = re.compile(r"\b(?:pip|pipx|uv tool)\s+install\s+(?:-U\s+)?([A-Za-z0-9][\w.\-]*)")
_EXT_ID_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9\-]*\.[a-z][a-z0-9\-]{2,})\b")
_GLOBAL_STORAGE_RE = re.compile(r"globalStorage[\\/]+([A-Za-z0-9\-]+\.[A-Za-z0-9\-]+)(?=[\\/\s\"]|$)")
_EXE_RE = re.compile(r"(?:^|(?<=[\s,;(]))((?:[A-Z][\w.\-]* [A-Z][\w.\-]*|[A-Za-z0-9][\w.\-]*)\.(?:exe|EXE))\b|'([^']+\.(?:exe|EXE))'")
_INSTRUCTION_RE = re.compile(
    r"(?<![\w.])((?:CLAUDE|AGENTS|GEMINI|MEMORY|QWEN|CRUSH|AGENT|CONVENTIONS)(?:\.local)?\.md|\.cursorrules|\.clinerules|\.windsurfrules|\.cursor/rules)"
)
_CREDENTIAL_TEXT_RE = re.compile(
    r"credential|oauth|\btokens?\b|secret|sensitive|never export|keychain|password|auth\.json|api key", re.IGNORECASE
)
_RETENTION_LIMIT_RE = re.compile(
    r"\b\d+\s*-?\s*days?\b|cleanupPeriodDays|auto[- ]?(?:delete|purge|expir)|purged|rotat|older than|retention period", re.IGNORECASE
)
# Containers below a home that are not a tool's own folder.
_GENERIC_CONTAINERS = frozenset(
    {
        "library", "application support", "caches", "logs", "preferences", "containers", "group containers",
        ".config", ".local", "share", "state", "lib", "bin", "appdata", "roaming", "local", "locallow", "programs",
        "packages", "temp", "tmp", ".cache", "documents", "users", "home", "usr", "opt", "etc", "var", "private",
        "program files", "programdata",
    }
)
DOMAIN_LABEL_OVERRIDES: dict[str, str] = {
    "cursor.com": "Cursor",
    "cursor.sh": "Cursor",
    "api2.cursor.sh": "Cursor",
    "api.anthropic.com": "Claude",
    "openrouter.ai": "OpenRouter",
}
_LEGACY_BROWSER_DOMAINS: tuple[tuple[str, str], ...] = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("openai.com", "OpenAI"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("aistudio.google.com", "Google AI Studio"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("bing.com", "Microsoft Copilot/Bing Chat"),
    ("poe.com", "Poe"),
    ("huggingface.co", "Hugging Face"),
    ("grok.com", "Grok"),
    ("x.ai", "Grok"),
    ("you.com", "You.com"),
    ("phind.com", "Phind"),
    ("chat.mistral.ai", "Mistral Le Chat"),
    ("deepseek.com", "DeepSeek"),
    ("meta.ai", "Meta AI"),
    ("character.ai", "Character.AI"),
    ("notion.so", "Notion AI"),
)
_LEGACY_MEMORY_DOMAINS: tuple[tuple[str, str], ...] = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("poe.com", "Poe"),
)
_LEGACY_SERVICE_TOKENS: tuple[str, ...] = ("chatgpt", "claude", "gemini", "perplexity", "copilot")
_TOKEN_DENY = frozenset({"microsoft", "mistral", "character", "notion", "manus", "brave", "liner", "ernie", "clova", "google"})


def normalize_confidence(text: object) -> str:
    """Catalog ``conf`` / ``confidence`` text → one of :data:`CONFIDENCE_LEVELS` (``""`` if none).

    The catalog writes free text (``"official-doc (file name); unverified (keychain on mac)"``);
    the first known token by position wins."""
    lowered = str(text or "").lower()
    best: tuple[int, str] | None = None
    for token, level in _CONF_TOKENS:
        index = lowered.find(token)
        if index >= 0 and (best is None or index < best[0]):
            best = (index, level)
    return best[1] if best else ""


def _best_confidence(levels: Iterable[str]) -> str:
    ranked = [level for level in levels if level in CONFIDENCE_LEVELS]
    return min(ranked, key=CONFIDENCE_LEVELS.index) if ranked else "unverified"


@dataclass(frozen=True)
class PathTemplate:
    os: str  # windows | macos | linux | any
    kind: str
    template: str  # "/"-separated, anchor variable first, ``*`` for placeholders
    raw: str
    confidence: str
    credential: bool = False
    # True when the path sits in another tool's folder without naming this tool (e.g. a harness
    # listing ``~/.claude/skills``): kept for reference, never evidence that *this* tool exists.
    shared: bool = False

    @property
    def anchor(self) -> str:
        return self.template.split("/", 1)[0]

    @property
    def relative_parts(self) -> tuple[str, ...]:
        rest = self.template.split("/", 1)[1] if "/" in self.template else ""
        return tuple(part for part in rest.split("/") if part)


@dataclass(frozen=True)
class AiTool:
    id: str
    name: str
    vendor: str
    category: str
    categories: tuple[str, ...]
    aliases: tuple[str, ...]
    binaries: tuple[str, ...]
    process_names: tuple[str, ...]
    install: Mapping[str, tuple[str, ...]]
    domains: tuple[str, ...]
    env_vars: tuple[str, ...]
    paths: tuple[PathTemplate, ...]
    instruction_files: tuple[str, ...]
    retention: str
    confidence: str
    local_verification: bool
    source_files: tuple[str, ...]
    meta: bool = False

    @property
    def credential_paths(self) -> tuple[PathTemplate, ...]:
        return tuple(item for item in self.paths if item.credential)

    @property
    def retention_auto_delete(self) -> bool:
        return bool(_RETENTION_LIMIT_RE.search(self.retention))

    @property
    def label(self) -> str:
        return _display_name(self.name)

    def paths_for(self, os_name: str) -> tuple[PathTemplate, ...]:
        if os_name not in ("windows", "macos", "linux"):
            return self.paths
        return tuple(item for item in self.paths if item.os in (os_name, "any"))

    def paths_by_os(self) -> dict[str, dict[str, list[str]]]:
        """``paths[OS][kind] -> [template…]`` view (plan §3.1)."""
        result: dict[str, dict[str, list[str]]] = {}
        for item in self.paths:
            result.setdefault(item.os, {}).setdefault(item.kind or "path", []).append(item.template)
        return result

    def coverage_status(self, matched: Iterable[PathTemplate] = ()) -> str:
        if self.local_verification:
            return "local-verified"
        levels = [item.confidence for item in matched]
        return _best_confidence(levels or [self.confidence])


@dataclass(frozen=True)
class AiCatalog:
    tools: tuple[AiTool, ...]
    key_prefixes: tuple[str, ...]
    infrastructure_domains: tuple[tuple[str, str], ...]
    raw: Mapping[str, object] = field(default_factory=dict, repr=False, compare=False)

    def tool(self, tool_id: str) -> AiTool | None:
        for tool in self.tools:
            if tool.id == tool_id:
                return tool
        return None

    @property
    def product_tools(self) -> tuple[AiTool, ...]:
        return tuple(tool for tool in self.tools if not tool.meta)


# --------------------------------------------------------------------------- text helpers


def _display_name(name: str) -> str:
    text = re.sub(r"\s*\([^)]*\)\s*", " ", str(name or "")).strip()
    text = text.split(" / ")[0].strip()
    return re.sub(r"\s+", " ", text) or str(name or "")


def _slug(name: str) -> str:
    if name in ID_OVERRIDES:
        return ID_OVERRIDES[name]
    text = re.sub(r"\([^)]*\)", " ", name)
    text = text.split(" / ")[0]
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "unnamed"


def _texts(value: object) -> Iterator[str]:
    """Every string inside a catalog value (dict values and keys, lists, scalars)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _texts(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _texts(item)


def _value(value: object) -> object:
    """``{"value": X}`` / ``{"v": X}`` → ``X``."""
    if isinstance(value, Mapping):
        for key in ("value", "v"):
            if key in value:
                return value[key]
    return value


def _conf_of(value: object, default: str = "") -> str:
    if isinstance(value, Mapping):
        for key in ("conf", "confidence"):
            if key in value and isinstance(value[key], str):
                return normalize_confidence(value[key]) or default
    return default


def _expand_braces(text: str) -> list[str]:
    match = _BRACE_RE.search(text)
    if not match:
        return [text]
    head, tail = text[: match.start()], text[match.end() :]
    results: list[str] = []
    for option in match.group(1).split(","):
        results.extend(_expand_braces(head + option.strip() + tail))
    return results[:32]


def _cut_path(text: str) -> str:
    """The path at the start of ``text`` (free text after it dropped; ``{a,b}`` kept whole)."""
    candidate = text
    position = 0
    while True:
        stop = _PATH_STOP_RE.search(text, position)
        if stop is None:
            break
        opened = text.rfind("{", 0, stop.start())
        closing = text.find("}", stop.start())
        if opened > text.rfind("}", 0, stop.start()) and closing > 0:
            position = closing + 1
            continue
        candidate = text[: stop.start()]
        break
    words = candidate.split(" ")
    kept = [words[0]]
    for word in words[1:]:
        joined = f"{kept[-1].replace(chr(92), '/').rsplit('/', 1)[-1]} {word}"
        if any(seg.lower().startswith(joined.lower()) or joined.lower().startswith(seg.lower()) for seg in _SPACED_SEGMENTS) or ("/" in word or "\\" in word) and not word.startswith(("/", "\\")) and word[:1].isupper():
            kept.append(word)
        else:
            break
    return " ".join(kept).rstrip(".:")


def _normalize_template(path_text: str) -> str:
    text = path_text.replace("\\", "/").strip()
    text = re.sub(r"/{2,}", "/", text)
    text = re.sub(r"^\$\{(\w+)\}", r"$\1", text)
    if re.match(r"^[A-Za-z]:/", text):
        text = "/" + text[3:]
    if text.startswith("%"):
        end = text.find("%", 1)
        text = text[: end + 1].upper() + text[end + 1 :]
    text = _PLACEHOLDER_RE.sub("*", text)
    text = re.sub(r"^/(?:Users|home)/\*/", "~/", text, flags=re.IGNORECASE)
    parts = text.split("/")
    for index, part in enumerate(parts):
        if re.fullmatch(r"(?:YYYY|YY|MM|DD|HH)", part):
            parts[index] = "*"
        elif part in ("...", "…"):
            parts[index] = "**"
    return "/".join(parts).rstrip("/")


def path_templates_from_text(text: str) -> list[str]:
    """Anchored path templates found in one free-text catalog string."""
    found: list[str] = []
    for match in _ANCHOR_RE.finditer(text):
        start = match.start()
        if start > 0 and text[start - 1] in "<":
            continue
        raw = _cut_path(text[start:])
        if len(raw) < 3:
            continue
        for expanded in _expand_braces(raw):
            template = _normalize_template(expanded)
            if template in ("~", "/") or template.count("/") < 1 or re.search(r"[%$]", template.split("/", 1)[1]):
                continue
            if template not in found:
                found.append(template)
    return found


def _label_kind(text: str) -> tuple[str, str]:
    """``"models: ~/.ollama/models"`` → ``("models", "~/.ollama/models")`` (local_llm style)."""
    match = re.match(r"^\s*([A-Za-z][\w \-/()]{0,40}?):\s+(?=\S)", text)
    if match and not re.match(r"^[A-Za-z]$", match.group(1)):
        return match.group(1).strip().lower(), text[match.end() :]
    return "", text


def _is_credential_template(kind: str, template: str, note: str) -> bool:
    kind_says = re.search(r"credential|auth|token|secret|oauth|keys?\b", kind, re.IGNORECASE) and "keybinding" not in kind
    if kind_says and not re.search(r"config|setting|data", kind, re.IGNORECASE):
        return True
    last = template.rsplit("/", 1)[-1]
    if last and "*" not in last.strip("*.") and is_credential_name(last):
        return True
    return bool(last and is_credential_name(last.replace("*", "")) and _CREDENTIAL_TEXT_RE.search(note))


def _path_entries(entry: Mapping[str, object]) -> Iterator[tuple[str, str, str, str]]:
    """(os, kind, text, confidence) for every path-bearing string of one tool entry."""
    paths = entry.get("paths")
    if isinstance(paths, list):
        for item in paths:
            if not isinstance(item, Mapping):
                continue
            kind = str(item.get("kind") or "")
            conf = normalize_confidence(item.get("conf"))
            previous = ""
            for os_key in ("win", "mac", "linux"):
                text = str(item.get(os_key) or "")
                if text.lower().startswith("same") and not path_templates_from_text(text) and previous:
                    text = previous
                previous = text or previous
                yield _OS_KEYS[os_key], kind, text, conf
    elif isinstance(paths, Mapping):
        for key, value in paths.items():
            key_text = str(key)
            if key_text in ("android", "ios", "project"):
                continue
            os_name = _OS_KEYS.get(key_text, "any")
            conf = _conf_of(value)
            if os_name == "any" and path_templates_from_text(key_text):
                yield "any", "", f"{key_text} {' '.join(_texts(value))}", conf
                continue
            inner = _value(value)
            items = inner if isinstance(inner, list) else [inner]
            for item in items:
                for text in _texts(item):
                    kind, rest = _label_kind(text)
                    yield os_name, kind, rest, conf
    for key in ("local_verification", "local_verification_extra", "local_verification_desktop"):
        block = entry.get(key)
        if isinstance(block, Mapping):
            for text in _texts(block):
                yield "any", "local-verification", text, "local-verified"


def _templates_for_entry(entry: Mapping[str, object], default_conf: str) -> list[PathTemplate]:
    templates: list[PathTemplate] = []
    seen: set[tuple[str, str]] = set()
    for os_name, kind, text, conf in _path_entries(entry):
        for template in path_templates_from_text(text):
            key = (os_name, template)
            if key in seen:
                continue
            seen.add(key)
            templates.append(
                PathTemplate(
                    os=os_name,
                    kind=kind,
                    template=template,
                    raw=text[:300],
                    confidence=conf or default_conf or "unverified",
                    credential=_is_credential_template(kind, template, text),
                )
            )
    return templates


def _hosts(values: Iterable[str]) -> list[str]:
    hosts: list[str] = []
    for text in values:
        lowered = text.lower()
        for match in _HOST_RE.finditer(lowered):
            host = match.group(1).strip(".")
            if "{" in lowered[max(0, match.start() - 1) : match.end() + 1]:
                continue
            if host.rsplit(".", 1)[-1] not in _HOST_TLDS or host in GENERIC_HOSTS:
                continue
            host = host.removeprefix("www.")
            if host not in hosts:
                hosts.append(host)
    return hosts


def _domain_texts(entry: Mapping[str, object]) -> list[str]:
    texts: list[str] = []
    for key in ("domains", "api_domains"):
        value = entry.get(key)
        if isinstance(value, list):
            for item in value:
                texts.extend(_texts(_value(item)))
        elif value is not None:
            texts.extend(_texts(_value(value)))
    return texts


def _names(value: object) -> list[str]:
    names: list[str] = []
    inner = _value(value)
    for text in _texts(inner):
        for match in _EXE_RE.finditer(text):
            names.append((match.group(1) or match.group(2) or "").strip())
    result: list[str] = []
    for name in names:
        if name.lower() not in {item.lower() for item in result} and name.lower() != "unknown":
            result.append(name)
    return result


def _install(entry: Mapping[str, object], whole_text: str) -> dict[str, tuple[str, ...]]:
    npm: list[str] = []
    pip: list[str] = []
    install = entry.get("install")
    if isinstance(install, Mapping):
        for raw in str(install.get("npm") or "").replace(",", " / ").split(" / "):
            token = raw.strip().split(" ")[0]
            if token and _NPM_NAME_RE.match(token):
                npm.append(token)
        for raw in str(install.get("pip") or "").replace(",", " / ").split(" / "):
            token = re.sub(r"\(.*", "", raw).strip()
            token = token.split(" ")[-1] if token.startswith("uv tool install") else token.split(" ")[0]
            if token and re.fullmatch(r"[A-Za-z0-9][\w.\-]*", token):
                pip.append(token)
    install_texts = " ".join(_texts(entry.get("install_artifacts"))) + " " + " ".join(_texts(install))
    for match in _NPM_PHRASE_RE.finditer(install_texts):
        token = match.group(1).rstrip(".")
        if token not in {"global", "package", "install", "i", "add", "and", "or"} and _NPM_NAME_RE.match(token):
            npm.append(token)
    for match in _PIP_PHRASE_RE.finditer(install_texts):
        pip.append(match.group(1).rstrip("."))
    winget = [match.group(1).rstrip(".,") for match in _WINGET_RE.finditer(whole_text)]
    msix = [match.group(1) for match in _MSIX_RE.finditer(whole_text)]
    extensions = [match.group(1).lower() for match in _GLOBAL_STORAGE_RE.finditer(whole_text)]
    for text in _texts(entry):
        if "extension" not in text.lower():
            continue
        for match in _EXT_ID_RE.finditer(text):
            candidate = match.group(1)
            head, tail = candidate.split(".", 1)
            if tail in _FILE_SUFFIXES or tail in _HOST_TLDS or head.lower() in {"com", "docs", "e", "i", "www"}:
                continue
            extensions.append(candidate.lower())
    extensions = [item for item in extensions if not item.endswith((".vscdb", ".json"))]

    def unique(values: list[str]) -> tuple[str, ...]:
        out: list[str] = []
        for value in values:
            if value and value not in out:
                out.append(value)
        return tuple(out)

    return {
        "npm": unique(npm),
        "pip": unique(pip),
        "winget": unique(winget),
        "msix": unique(msix),
        "vscode-extension": unique(extensions),
    }


def _retention_text(entry: Mapping[str, object]) -> str:
    for key in ("retention", "retention_export_audit", "retention_deletion"):
        value = entry.get(key)
        if value in (None, "", []):
            continue
        texts = [text for text in _texts(_value(value)) if text not in ("claim", "confidence", "source")]
        joined = " ".join(text for text in texts if not text.startswith("http"))
        if joined.strip():
            return re.sub(r"\s+", " ", joined).strip()[:400]
    return ""


def _env_vars(entry: Mapping[str, object]) -> tuple[str, ...]:
    names: list[str] = []
    value = entry.get("env_vars")
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping) and item.get("name"):
                names.append(str(item["name"]))
    for text in _texts(value) if isinstance(value, str) else ():
        names.extend(re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", text))
    return tuple(dict.fromkeys(names))


def _entry_confidence(entry: Mapping[str, object]) -> str:
    levels = [normalize_confidence(text) for key in ("conf", "confidence") for text in _texts(entry.get(key))]
    if not any(levels):
        levels = [normalize_confidence(text) for text in _texts(entry.get("paths"))]
    return _best_confidence([level for level in levels if level])


def _tool_from_entry(file_stem: str, entry: Mapping[str, object]) -> AiTool:
    name = str(entry.get("name") or entry.get("id") or "")
    tool_id = str(entry.get("id") or "") or _slug(name)
    if name in ID_OVERRIDES:
        tool_id = ID_OVERRIDES[name]
    whole_text = json.dumps(entry, ensure_ascii=False)
    confidence = _entry_confidence(entry)
    category = FILE_CATEGORY[file_stem]
    aliases = tuple(str(item) for item in entry.get("aliases") or () if isinstance(item, str))
    return AiTool(
        id=tool_id,
        name=name,
        vendor=str(entry.get("vendor") or ""),
        category=category,
        categories=(category,),
        aliases=aliases,
        binaries=tuple(str(item) for item in entry.get("binaries") or () if isinstance(item, str)),
        process_names=tuple(_names(entry.get("process_names")) + _names(entry.get("ports_processes"))),
        install=_install(entry, whole_text),
        domains=tuple(_hosts(_domain_texts(entry))),
        env_vars=_env_vars(entry),
        paths=tuple(_templates_for_entry(entry, confidence)),
        instruction_files=tuple(dict.fromkeys(_INSTRUCTION_RE.findall(whole_text))),
        retention=_retention_text(entry),
        confidence=confidence,
        local_verification=any(key.startswith("local_verification") for key in entry)
        or normalize_confidence(entry.get("confidence")) == "local-verified",
        source_files=(file_stem,),
        meta=tool_id in META_TOOL_IDS,
    )


def _merge(first: AiTool, second: AiTool) -> AiTool:
    def union(left: Sequence[object], right: Sequence[object]) -> tuple:
        return tuple(dict.fromkeys([*left, *right]))

    install = {key: union(first.install.get(key, ()), second.install.get(key, ())) for key in {*first.install, *second.install}}
    return AiTool(
        id=first.id,
        name=first.name,
        vendor=first.vendor or second.vendor,
        category=first.category,
        categories=union(first.categories, second.categories),
        aliases=union(first.aliases, second.aliases),
        binaries=union(first.binaries, second.binaries),
        process_names=union(first.process_names, second.process_names),
        install=install,
        domains=union(first.domains, second.domains),
        env_vars=union(first.env_vars, second.env_vars),
        paths=union(first.paths, second.paths),
        instruction_files=union(first.instruction_files, second.instruction_files),
        retention=first.retention or second.retention,
        confidence=_best_confidence([first.confidence, second.confidence]),
        local_verification=first.local_verification or second.local_verification,
        source_files=union(first.source_files, second.source_files),
        meta=first.meta and second.meta,
    )


def _key_prefixes(infrastructure: Mapping[str, object]) -> tuple[str, ...]:
    section = infrastructure.get("2_api_keys_and_credential_storage")
    prefixes: list[str] = []
    formats = section.get("key_formats") if isinstance(section, Mapping) else None
    for item in formats or ():
        if not isinstance(item, Mapping):
            continue
        pattern = str(item.get("pattern") or "")
        body = re.sub(r"^(?:\\b)?\(?", "", pattern)
        literal = re.match(r"[A-Za-z0-9_\-]+", body)
        if not literal:
            continue
        head = literal.group(0)
        rest = body[len(head) :]
        alternatives = re.match(r"\(\?:([\w|]+)\)(-|_)", rest)
        if alternatives:
            candidates = [f"{head}{option}{alternatives.group(2)}" for option in alternatives.group(1).split("|")]
        else:
            candidates = [head]
        followed_by_pattern = rest[:1] in ("[", "\\", "(", "{")
        for candidate in candidates:
            shaped = candidate[-1] in "-_" or (followed_by_pattern and len(candidate) >= 4)
            if shaped and len(candidate) >= 3 and candidate != "sk-" and candidate not in prefixes:
                prefixes.append(candidate)
    return tuple(prefixes)


def _infrastructure_domains(infrastructure: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    section = infrastructure.get("1_relays_gateways_providers")
    pairs: list[tuple[str, str]] = []
    entries = section.get("entries") if isinstance(section, Mapping) else None
    for item in entries or ():
        if not isinstance(item, Mapping):
            continue
        label = _display_name(str(item.get("name") or ""))
        for host in _hosts(_texts(item.get("domains"))):
            if all(host != existing for existing, _ in pairs):
                pairs.append((host, label))
    return tuple(pairs)


_GENERIC_TOKENS = frozenset(
    {
        "code", "cli", "ai", "agent", "agents", "chat", "the", "app", "desktop", "assistant", "developer", "extension",
        "ide", "mode", "modes", "memory", "bank", "rules", "method", "kit", "plugin", "web", "cloud", "studio", "open",
        "local", "server", "engineer", "configs", "config", "files", "other", "per", "client", "framework", "based",
        "legacy", "formerly", "new", "plus", "pro", "max", "dev", "labs", "mcp",
    }
)
_HOME_ANCHORS = frozenset({"~", "%USERPROFILE%", "$HOME", "%HOMEPATH%"})


def _tool_tokens(tool: AiTool) -> tuple[frozenset[str], frozenset[str]]:
    """(distinctive tokens, generic id words) a path must contain to be evidence of ``tool``."""
    tokens: set[str] = set()
    generic: set[str] = set()
    for word in re.split(r"[^a-z0-9]+", tool.id.lower()):
        if len(word) >= 3 and word not in _GENERIC_TOKENS:
            tokens.add(word)
        elif word:
            generic.add(word)
    for alias in tool.aliases:
        for word in re.split(r"[^a-z0-9]+", alias.lower()):
            if len(word) >= 4 and word not in _GENERIC_TOKENS:
                tokens.add(word)
    for name in (*tool.binaries, *tool.install.get("npm", ()), *tool.install.get("pip", ())):
        stem = name.lower().rsplit("/", 1)[-1].removesuffix(".exe")
        if len(stem) >= 4 and stem not in _GENERIC_BINARIES:
            tokens.add(stem)
    for name in (*tool.install.get("vscode-extension", ()), *tool.install.get("msix", ())):
        tokens.add(name.lower())
    # A vendor name (Google, Microsoft, GitHub…) is shared by all of that vendor's products and
    # folders (``%LOCALAPPDATA%/Google``), so it never identifies one tool.
    vendor_words = {word for word in re.split(r"[^a-z0-9]+", tool.vendor.lower()) if word}
    return frozenset(tokens - vendor_words), frozenset(generic - vendor_words)


def _root_key(template: PathTemplate) -> tuple[str, str] | None:
    anchor = "~" if template.anchor in _HOME_ANCHORS else template.anchor
    parts = template.relative_parts
    for index, part in enumerate(parts):
        if part.lower() not in _GENERIC_CONTAINERS:
            return anchor, "/".join(parts[: index + 1]).lower()
    return None


_BROWSER_STORAGE_RE = re.compile(
    r"/user data(?:/[^/]*)?|/google-chrome(?:/[^/]*)?|/chromium(?:/[^/]*)?|/bravesoftware/[^/]*|/firefox/profiles(?:/[^/]*)?|/safari",
    re.IGNORECASE,
)


def _names_tool(below_root: str, tokens: frozenset[str], generic: frozenset[str]) -> bool:
    lowered = below_root.lower()
    if any(token in lowered for token in tokens):
        return True
    words = set(re.split(r"[^a-z0-9]+", lowered))
    return bool(generic & words - {"code", "ai"})


def _mark_shared(tools: list[AiTool]) -> list[AiTool]:
    """Flag templates that are not evidence of their own tool (see :attr:`PathTemplate.shared`).

    Each tool folder (``~/.claude``, ``%APPDATA%/Cursor``…) has an owner: a claimant whose
    distinctive token appears in the folder name (non-chatbot first, then most templates). Any
    other tool's template below that folder counts only if it names that tool."""
    tokens = {tool.id: _tool_tokens(tool) for tool in tools}
    claimants: dict[tuple[str, str], dict[str, int]] = {}
    for tool in tools:
        if tool.meta:
            continue
        for template in tool.paths:
            key = _root_key(template)
            if key is not None:
                claimants.setdefault(key, {}).setdefault(tool.id, 0)
                claimants[key][tool.id] += 1
    by_id = {tool.id: tool for tool in tools}
    owners: dict[tuple[str, str], str] = {}
    for key, counts in claimants.items():
        root_name = key[1].rsplit("/", 1)[-1]
        named = [tool_id for tool_id in counts if any(token in root_name for token in tokens[tool_id][0])]
        if not named:
            continue
        named.sort(key=lambda tool_id: (by_id[tool_id].category == "chatbot", -counts[tool_id], tool_id))
        owners[key] = named[0]
    result: list[AiTool] = []
    for tool in tools:
        own_tokens, generic = tokens[tool.id]
        templates: list[PathTemplate] = []
        for template in tool.paths:
            key = _root_key(template)
            shared = False
            browser = _BROWSER_STORAGE_RE.search(template.template)
            if browser is not None and not tool.meta:
                # Browser profile storage is browser evidence (the browser kind reads it); only a
                # tool-specific origin folder below it (``https_gemini.google.com_0…``) counts.
                shared = not _names_tool(template.template[browser.end() :], own_tokens, generic)
            elif key is not None and not tool.meta:
                owner = owners.get(key)
                below = template.template.lower().split(key[1], 1)[-1] if key[1] in template.template.lower() else ""
                if owner is None:
                    shared = len(claimants.get(key, {})) > 1 and not _names_tool(below, own_tokens, generic)
                elif owner != tool.id:
                    shared = not _names_tool(below, own_tokens, generic)
            templates.append(PathTemplate(**{**template.__dict__, "shared": shared}) if shared else template)
        result.append(AiTool(**{**tool.__dict__, "paths": tuple(templates)}))
    return result


def _read_json(name: str, data_dir: Path) -> object:
    return json.loads((data_dir / f"{name}.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def _load(data_dir_text: str) -> AiCatalog:
    data_dir = Path(data_dir_text)
    raw: dict[str, object] = {name: _read_json(name, data_dir) for name in CATALOG_FILES}
    tools: dict[str, AiTool] = {}
    for stem in TOOL_CATALOG_FILES:
        entries = raw[stem]
        for entry in entries if isinstance(entries, list) else ():
            if not isinstance(entry, Mapping) or not entry.get("name"):
                continue
            tool = _tool_from_entry(stem, entry)
            tools[tool.id] = _merge(tools[tool.id], tool) if tool.id in tools else tool
    infrastructure = raw["infrastructure"] if isinstance(raw["infrastructure"], Mapping) else {}
    return AiCatalog(
        tools=tuple(_mark_shared(list(tools.values()))),
        key_prefixes=_key_prefixes(infrastructure),
        infrastructure_domains=_infrastructure_domains(infrastructure),
        raw=raw,
    )


def load_catalog(data_dir: Path | None = None) -> AiCatalog:
    """The normalized catalog (cached per data directory)."""
    return _load(str((data_dir or CATALOG_DATA_DIR).resolve()))


# --------------------------------------------------------------------------- domains / terms


def catalog_domain_pairs(catalog: AiCatalog | None = None) -> tuple[tuple[str, str], ...]:
    """``(host, label)`` from every catalog tool and AI gateway, catalog order, no duplicates."""
    catalog = catalog or load_catalog()
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(host: str, label: str) -> None:
        if host not in seen and host not in SUBSTRING_UNSAFE_HOSTS:
            seen.add(host)
            pairs.append((host, DOMAIN_LABEL_OVERRIDES.get(host, label)))

    # Products first, then gateways, then agents whose ``api_domains`` also list the providers
    # they call (so ``openrouter.ai`` is "OpenRouter", not the first agent that mentions it).
    for category in ("chatbot",):
        for tool in catalog.tools:
            if tool.category == category:
                for host in tool.domains:
                    add(host, tool.label)
    for host, label in catalog.infrastructure_domains:
        add(host, label)
    for category in ("cloud_agent", "ide_agent", "cli_agent", "harness", "local_llm"):
        for tool in catalog.tools:
            if tool.category == category:
                for host in tool.domains:
                    add(host, tool.label)
    return tuple(pairs)


def _covered(host: str, domains_: Iterable[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains_)


def domains(*, legacy: str = "browser", catalog: AiCatalog | None = None) -> tuple[tuple[str, str], ...]:
    """AI service ``(domain, label)`` pairs — the one domain list for browser, memory and mobile.

    The legacy list of the consumer (``browser`` 21 / ``memory`` 8, same order and labels, so
    first-match detection is unchanged) comes first; catalog hosts not already covered by a
    listed domain follow (``host == d`` or ``host`` ends with ``.d``)."""
    base = {"browser": _LEGACY_BROWSER_DOMAINS, "memory": _LEGACY_MEMORY_DOMAINS}.get(legacy, ())
    pairs = list(base)
    listed = [domain for domain, _ in pairs]
    for host, label in catalog_domain_pairs(catalog):
        if not _covered(host, listed):
            pairs.append((host, label))
            listed.append(host)
    return tuple(pairs)


def ai_service_tokens(catalog: AiCatalog | None = None) -> tuple[str, ...]:
    """Lower-case product tokens for free-text matching (mobile app / message / URL hints).

    The five legacy tokens first, then distinctive chatbot names (one word, ≥ 6 letters, not a
    common word or a vendor name)."""
    catalog = catalog or load_catalog()
    tokens = list(_LEGACY_SERVICE_TOKENS)
    for tool in catalog.tools:
        if tool.category != "chatbot":
            continue
        word = re.split(r"[\s./]", tool.label.lower())[0]
        if len(word) >= 6 and word.isalpha() and word not in _TOKEN_DENY and word not in tokens:
            tokens.append(word)
    return tuple(tokens)


# Product names that are ordinary words or too short for a document keyword search.
_KEYWORD_NAME_DENY = frozenset(
    {
        "pi", "amp", "jan", "zeta", "dust", "void", "goose", "crush", "continue", "felo", "wrtn", "liner", "trae",
        "make ai agents", "zapier agents", "n8n ai agents", "replit", "bolt", "v0", "a.", "kiro", "droid", "factory",
        "conductor", "crystal", "superpowers", "gstack", "ecc", "happy coder", "plandex", "mentat", "letta code",
        "junie", "manus", "jules", "msty", "chatbox", "enchanted", "flowise", "dify", "poe", "you.com", "meta ai",
    }
)


def keyword_terms(catalog: AiCatalog | None = None) -> tuple[str, ...]:
    """The ``ai-tools`` keyword pack: product names, one main domain per product and API key
    *prefixes* (the prefix strings only; no key value is ever part of the pack)."""
    catalog = catalog or load_catalog()
    terms: list[str] = []

    def add(term: str) -> None:
        text = term.strip().lower()
        if len(text) >= 4 and text not in _KEYWORD_NAME_DENY and text not in terms:
            terms.append(text)

    for tool in catalog.product_tools:
        if tool.category == "harness" and not tool.local_verification:
            continue  # harness names are mostly generic words; their files are found by path
        add(tool.label)
    for tool in catalog.product_tools:
        if tool.domains and tool.category in ("chatbot", "cloud_agent", "ide_agent"):
            if tool.domains[0] not in SUBSTRING_UNSAFE_HOSTS:
                add(tool.domains[0])
    for host, _label in catalog.infrastructure_domains[:12]:
        add(host)
    for prefix in catalog.key_prefixes:
        if prefix not in terms:
            terms.append(prefix)
    return tuple(terms)


def key_prefixes(catalog: AiCatalog | None = None) -> tuple[str, ...]:
    """API key prefix strings (prefixes only, never values) from the catalog key formats."""
    return (catalog or load_catalog()).key_prefixes


def execution_names(catalog: AiCatalog | None = None) -> dict[str, tuple[str, ...]]:
    """Lower-case executable stem (``claude`` for ``claude.exe``) → catalog tool ids.

    Generic or very short names (``agent``, ``q``, ``pi``…) are excluded: they would match
    unrelated programs."""
    catalog = catalog or load_catalog()
    index: dict[str, list[str]] = {}
    for tool in catalog.product_tools:
        for name in (*tool.binaries, *tool.process_names):
            stem = name.strip().lower()
            stem = stem.removesuffix(".exe")
            stem = stem.removesuffix(".cmd")
            if len(stem) < 4 or stem in _GENERIC_BINARIES or "/" in stem or "\\" in stem:
                continue
            index.setdefault(stem, [])
            if tool.id not in index[stem]:
                index[stem].append(tool.id)
    return {key: tuple(value) for key, value in index.items()}


# --------------------------------------------------------------------------- profiles / expansion

_SKIP_PROFILE_NAMES = frozenset({"public", "default", "default user", "all users", "defaultapppool", "desktop.ini", "shared", "guest"})
_HOME_MARKERS = ("AppData", "NTUSER.DAT", "Library/Application Support", ".config", ".local", ".bash_history", ".zshrc", ".profile")


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _profile_os(home: Path, hint: str = "") -> str:
    if _is_dir(home / "AppData") or _exists(home / "NTUSER.DAT"):
        return "windows"
    if _is_dir(home / "Library"):
        return "macos"
    if _is_dir(home / ".config") or _is_dir(home / ".local") or home.parent.name == "home" or home.name == "root":
        return "linux"
    return hint if hint in ("windows", "macos", "linux") else "unknown"


def catalog_home_roots(catalog: AiCatalog) -> frozenset[str]:
    names: set[str] = set()
    for tool in catalog.tools:
        for template in tool.paths:
            if template.anchor in ("~", "%USERPROFILE%", "$HOME") and template.relative_parts:
                first = template.relative_parts[0]
                if first.startswith(".") and not set(first) & _GLOB_CHARS:
                    names.add(first.lower())
    return frozenset(names)


def _looks_like_home(path: Path, catalog: AiCatalog) -> bool:
    if any(_exists(path / marker) for marker in _HOME_MARKERS):
        return True
    roots = catalog_home_roots(catalog)
    try:
        return any(child.name.lower() in roots for child in path.iterdir())
    except OSError:
        return False


def enumerate_profiles(root: Path, *, os_hint: str = "", catalog: AiCatalog | None = None) -> list[EvidenceProfile]:
    """Every user profile under an evidence root (plan §3.2 OS rule).

    ``Users/<u>`` (Windows, macOS), ``Documents and Settings/<u>``, ``home/<u>`` and ``root``
    (Linux) at the root or one level down (a mounted partition folder), or the root itself when it
    is a home folder (e.g. a ``%USERPROFILE%`` copy)."""
    catalog = catalog or load_catalog()
    root = Path(root)
    profiles: list[EvidenceProfile] = []
    seen: set[str] = set()

    def add(home: Path, system_root: Path | None) -> None:
        key = str(home).lower()
        if key in seen:
            return
        seen.add(key)
        profiles.append(EvidenceProfile(home=home, user=home.name, os=_profile_os(home, os_hint), system_root=system_root))

    def scan(base: Path) -> bool:
        found = False
        for container in ("Users", "Documents and Settings", "home"):
            folder = _child_ci(base, container)
            if folder is None:
                continue
            try:
                children = sorted(folder.iterdir(), key=lambda item: item.name.lower())
            except OSError:
                continue
            for child in children:
                if child.name.lower() in _SKIP_PROFILE_NAMES or child.name.startswith(".") or not _is_dir(child):
                    continue
                add(child, base)
                found = True
        root_home = _child_ci(base, "root")
        if root_home is not None and _is_dir(root_home) and _child_ci(base, "etc") is not None:
            add(root_home, base)
            found = True
        return found

    if root.name.lower() in ("users", "home") and _is_dir(root):
        try:
            for child in sorted(root.iterdir(), key=lambda item: item.name.lower()):
                if child.name.lower() not in _SKIP_PROFILE_NAMES and not child.name.startswith(".") and _is_dir(child):
                    add(child, root.parent)
        except OSError:
            pass
        return profiles
    if scan(root):
        return profiles
    try:
        children = sorted((child for child in root.iterdir() if _is_dir(child)), key=lambda item: item.name.lower())
    except OSError:
        children = []
    for child in children[:16]:
        scan(child)
    if not profiles and _looks_like_home(root, catalog):
        add(root, None)
    return profiles


def _child_ci(base: Path, name: str) -> Path | None:
    exact = base / name
    if _exists(exact):
        return exact
    lowered = name.lower()
    try:
        for child in base.iterdir():
            if child.name.lower() == lowered:
                return child
    except OSError:
        return None
    return None


_ANCHOR_BASES: dict[str, tuple[str, ...]] = {
    "~": (),
    "$HOME": (),
    "%USERPROFILE%": (),
    "%HOMEPATH%": (),
    "%APPDATA%": ("AppData", "Roaming"),
    "%LOCALAPPDATA%": ("AppData", "Local"),
    "%TEMP%": ("AppData", "Local", "Temp"),
    "%TMP%": ("AppData", "Local", "Temp"),
    "$XDG_CONFIG_HOME": (".config",),
    "$XDG_DATA_HOME": (".local", "share"),
    "$XDG_CACHE_HOME": (".cache",),
    "$XDG_STATE_HOME": (".local", "state"),
}
_SYSTEM_ANCHORS: dict[str, tuple[str, ...]] = {
    "%PROGRAMDATA%": ("ProgramData",),
    "%PROGRAMFILES%": ("Program Files",),
    "%PROGRAMFILES(X86)%": ("Program Files (x86)",),
    "%WINDIR%": ("Windows",),
    "%SYSTEMROOT%": ("Windows",),
}
KNOWN_ANCHORS: frozenset[str] = frozenset({*_ANCHOR_BASES, *_SYSTEM_ANCHORS, "", "$TMPDIR"})


@dataclass(frozen=True)
class ExpandedPath:
    path: Path
    template: PathTemplate
    profile: EvidenceProfile | None


class DirCache:
    """Case-insensitive directory listing cache for one collection."""

    def __init__(self) -> None:
        self._entries: dict[str, list[tuple[str, Path, bool]]] = {}

    def entries(self, directory: Path) -> list[tuple[str, Path, bool]]:
        key = str(directory)
        cached = self._entries.get(key)
        if cached is not None:
            return cached
        listing: list[tuple[str, Path, bool]] = []
        try:
            with os.scandir(directory) as iterator:
                for item in iterator:
                    try:
                        is_dir = item.is_dir()
                    except OSError:
                        is_dir = False
                    listing.append((item.name.lower(), Path(item.path), is_dir))
        except OSError:
            listing = []
        listing.sort(key=lambda entry: entry[0])
        self._entries[key] = listing
        return listing


def _template_base(template: PathTemplate, profile: EvidenceProfile) -> Path | None:
    anchor = template.anchor
    if anchor == "":  # absolute "/usr/…" or "C:\…"
        return profile.system_root
    if anchor in _ANCHOR_BASES:
        return profile.home.joinpath(*_ANCHOR_BASES[anchor])
    if anchor in _SYSTEM_ANCHORS and profile.system_root is not None:
        return profile.system_root.joinpath(*_SYSTEM_ANCHORS[anchor])
    return None


def template_is_resolvable(template: PathTemplate) -> bool:
    """A template whose first segment below the anchor is literal (``~/.claude/…``, not
    ``~/*/…``) and not just a generic container; everything else is too broad to resolve."""
    parts = template.relative_parts
    if not parts or set(parts[0]) & _GLOB_CHARS:
        return False
    if template.anchor not in KNOWN_ANCHORS or template.anchor == "$TMPDIR":
        return False
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered[:-1]):
        # ``…/globalStorage/*/…`` matches every editor extension, not one tool.
        if part == "globalstorage" and set(lowered[index + 1]) & _GLOB_CHARS:
            return False
    meaningful = [part for part in parts if part.lower() not in _GENERIC_CONTAINERS and not set(part) & _GLOB_CHARS]
    return bool(meaningful)


def expand_template(
    template: PathTemplate,
    profile: EvidenceProfile,
    *,
    max_matches: int = 200,
    cache: DirCache | None = None,
) -> list[Path]:
    """Existing paths matching ``template`` under ``profile`` (case-insensitive, bounded)."""
    if not template_is_resolvable(template):
        return []
    base = _template_base(template, profile)
    if base is None or not _is_dir(base):
        return []
    cache = cache or DirCache()
    current: list[Path] = [base]
    parts = template.relative_parts
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        following: list[Path] = []
        lowered = part.lower()
        for directory in current:
            if part == "**":
                following.extend(_walk_dirs(directory, cache, depth=6, limit=max_matches * 4))
                continue
            for name, path, is_dir in cache.entries(directory):
                if (fnmatch.fnmatchcase(name, lowered) if set(part) & _GLOB_CHARS else name == lowered) and (last or is_dir):
                    following.append(path)
                    if len(following) >= max_matches * 4:
                        break
        current = following
        if not current:
            return []
    return current[:max_matches]


def _walk_dirs(directory: Path, cache: DirCache, *, depth: int, limit: int) -> list[Path]:
    result = [directory]
    frontier = [directory]
    for _ in range(depth):
        nxt: list[Path] = []
        for folder in frontier:
            nxt.extend(path for _name, path, is_dir in cache.entries(folder) if is_dir)
        result.extend(nxt)
        frontier = nxt
        if len(result) >= limit or not frontier:
            break
    return result[:limit]


def expand_paths(
    tool: AiTool | str,
    os_name: str,
    roots: Sequence[EvidenceProfile | Path],
    *,
    kinds: Iterable[str] | None = None,
    max_matches_per_template: int = 200,
    catalog: AiCatalog | None = None,
    cache: DirCache | None = None,
) -> list[ExpandedPath]:
    """Existing evidence paths for a tool's catalog templates (plan §3.1 ``expand_paths``).

    ``roots`` are profiles (or bare home folders, taken as ``os_name`` homes). ``kinds`` keeps
    only templates whose catalog kind is listed. Results are de-duplicated by path."""
    catalog = catalog or load_catalog()
    resolved = catalog.tool(tool) if isinstance(tool, str) else tool
    if resolved is None:
        return []
    wanted = {kind.lower() for kind in kinds} if kinds is not None else None
    cache = cache or DirCache()
    results: list[ExpandedPath] = []
    seen: set[str] = set()
    for root in roots:
        profile = root if isinstance(root, EvidenceProfile) else EvidenceProfile(home=Path(root), user=Path(root).name, os=os_name or "unknown")
        os_for_profile = profile.os if profile.os != "unknown" else os_name
        for template in resolved.paths_for(os_for_profile):
            if wanted is not None and template.kind.lower() not in wanted:
                continue
            for path in expand_template(template, profile, max_matches=max_matches_per_template, cache=cache):
                key = str(path).lower()
                if key in seen or key == str(profile.home).lower():
                    continue
                seen.add(key)
                results.append(ExpandedPath(path=path, template=template, profile=profile))
    return results


def tool_root(path: Path, profile: EvidenceProfile) -> Path | None:
    """The tool's own top folder for a matched path: the first non-generic folder below the
    home (``~/.claude``, ``AppData/Roaming/Cursor``, ``Library/Application Support/Claude``)."""
    try:
        relative = path.relative_to(profile.home)
    except ValueError:
        return None
    current = profile.home
    for part in relative.parts:
        current = current / part
        if part.lower() not in _GENERIC_CONTAINERS:
            return current if _is_dir(current) else None
    return None
