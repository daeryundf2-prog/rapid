"""Local LLM extension: model files (R7 stage 3.5, lane A).

Presence of the 27 catalog local-LLM tools (Ollama, LM Studio, GPT4All, Jan, Open WebUI,
AnythingLLM, KoboldCpp, llama.cpp, llamafile, LocalAI, vLLM, Msty, Chatbox, Cherry Studio,
ComfyUI, A1111, the Hugging Face cache …) comes from the catalog path scan (``presence.py``).
This module adds ``ai-model-file`` rows: model weights in the tools' model folders (catalog
templates of kind ``models`` / ``model``, the HF hub cache, Ollama blobs) and loose model files in
``Downloads`` / ``Desktop`` / ``Documents``. Only names, sizes and mtimes are recorded.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

from ...core.ai_catalog.catalog import AiCatalog, AiTool, DirCache, expand_paths
from .base import AiRow, EvidenceProfile, profile_account_key

__all__ = ["MODEL_SUFFIX_FORMATS", "model_file_rows"]

PARSER = "ai-model-file"
MODEL_SUFFIX_FORMATS: dict[str, str] = {
    ".gguf": "GGUF",
    ".ggml": "GGML",
    ".safetensors": "safetensors",
    ".llamafile": "llamafile",
    ".onnx": "ONNX",
    ".ckpt": "checkpoint",
    ".pt": "PyTorch",
    ".pth": "PyTorch",
    ".mlmodel": "Core ML",
    ".tflite": "TFLite",
}
# Weights inside a known model folder: these generic suffixes count only there.
_IN_MODEL_DIR_SUFFIXES = {".bin": "binary weights"}
MIN_MODEL_BYTES = 1024 * 1024
MAX_MODEL_ROWS_PER_PROFILE = 2000
MODEL_SCAN_DEPTH = 7
MODEL_SCAN_ENTRY_LIMIT = 20000
_LOOSE_DIRS = ("Downloads", "Desktop", "Documents")
_EXTRA_MODEL_DIRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hugging-face-cache", (".cache", "huggingface", "hub")),
    ("ollama", (".ollama", "models")),
    ("lm-studio", (".lmstudio", "models")),
    ("lm-studio", (".cache", "lm-studio", "models")),
    ("gpt4all", ("AppData", "Local", "nomic.ai", "GPT4All")),
    ("gpt4all", ("Library", "Application Support", "nomic.ai", "GPT4All")),
    ("whisper-based-transcribers", (".cache", "whisper")),
)


def _iso(stamp: float) -> str:
    try:
        return dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _model_dirs(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> list[tuple[AiTool | None, Path]]:
    dirs: list[tuple[AiTool | None, Path]] = []
    for tool in catalog.tools:
        if tool.category != "local_llm" or tool.meta:
            continue
        for match in expand_paths(tool, profile.os, [profile], catalog=catalog, cache=cache):
            kind = match.template.kind.lower()
            if "model" in kind and not match.template.shared:
                folder = match.path if match.path.is_dir() else match.path.parent
                dirs.append((tool, folder))
    for tool_id, parts in _EXTRA_MODEL_DIRS:
        folder = profile.home.joinpath(*parts)
        if folder.is_dir():
            dirs.append((catalog.tool(tool_id), folder))
    unique: list[tuple[AiTool | None, Path]] = []
    seen: set[str] = set()
    for tool, folder in dirs:
        key = str(folder).lower()
        if key not in seen and not any(key.startswith(other + "\\") or key.startswith(other + "/") for other in seen):
            seen.add(key)
            unique.append((tool, folder))
    return unique


def _walk_files(root: Path, cache: DirCache, depth: int, limit: int) -> Iterator[Path]:
    frontier = [root]
    seen = 0
    for _level in range(depth):
        following: list[Path] = []
        for folder in frontier:
            for _name, path, is_dir in cache.entries(folder):
                seen += 1
                if seen > limit:
                    return
                if is_dir:
                    following.append(path)
                else:
                    yield path
        frontier = following
        if not frontier:
            return


def _model_format(path: Path, in_model_dir: bool) -> str:
    suffix = path.suffix.lower()
    if suffix in MODEL_SUFFIX_FORMATS:
        return MODEL_SUFFIX_FORMATS[suffix]
    if in_model_dir and suffix in _IN_MODEL_DIR_SUFFIXES:
        return _IN_MODEL_DIR_SUFFIXES[suffix]
    if in_model_dir and path.name.startswith("sha256-") and "blobs" in {part.lower() for part in path.parts[-3:]}:
        return "Ollama blob"
    return ""


def _row(tool: AiTool | None, profile: EvidenceProfile, path: Path, fmt: str, size: int, modified: str, location: str) -> AiRow:
    return AiRow(
        artifact_type="ai-model-file",
        tool=tool.id if tool is not None else "unknown",
        tool_label=tool.label if tool is not None else "",
        account_key=profile_account_key(profile),
        profile_label=profile.label,
        user=profile.user,
        path=str(path),
        timestamp=modified,
        timestamp_kind="modified" if modified else "",
        modified_at=modified,
        coverage_status=tool.coverage_status() if tool is not None else "unverified",
        parser=PARSER,
        payload={
            "format": fmt,
            "size": size,
            "file_name": path.name,
            "mtime": modified,
            "location": location,
            "os": profile.os,
        },
    )


def model_file_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    emitted = 0
    seen: set[str] = set()
    sources: list[tuple[AiTool | None, Path, bool, str]] = [(tool, folder, True, "model-folder") for tool, folder in _model_dirs(catalog, profile, cache)]
    for name in _LOOSE_DIRS:
        folder = profile.home / name
        if folder.is_dir():
            sources.append((None, folder, False, "user-folder"))
    for tool, folder, in_model_dir, location in sources:
        depth = MODEL_SCAN_DEPTH if in_model_dir else 2
        for path in _walk_files(folder, cache, depth, MODEL_SCAN_ENTRY_LIMIT):
            fmt = _model_format(path, in_model_dir)
            if not fmt:
                continue
            key = str(path).lower()
            if key in seen:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size < MIN_MODEL_BYTES and fmt in ("binary weights", "Ollama blob"):
                continue
            seen.add(key)
            yield _row(tool, profile, path, fmt, int(stat.st_size), _iso(stat.st_mtime), location)
            emitted += 1
            if emitted >= MAX_MODEL_ROWS_PER_PROFILE:
                return
