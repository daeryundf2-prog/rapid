from __future__ import annotations

from pathlib import Path, PureWindowsPath
from typing import Iterable


def candidate_source_paths(raw_path: str, allowed_roots: Iterable[Path]) -> list[Path]:
    """Return safe source-path candidates for absolute, relative, and Windows-style paths."""
    text = str(raw_path or "").strip()
    if not text:
        return []

    roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    candidates: list[Path] = []
    requested = Path(text).expanduser()

    def add(path: Path) -> None:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            return
        if resolved not in candidates:
            candidates.append(resolved)

    if requested.is_absolute():
        add(requested)
    else:
        normalized = text.replace("\\", "/")
        windows_tail = windows_path_tail(text)
        for root in roots:
            if windows_tail:
                add(root.joinpath(*windows_tail))
            add(root / normalized)
        add(Path(normalized))

    return candidates


def resolve_source_path_in_roots(raw_path: str, allowed_roots: Iterable[Path]) -> Path:
    roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    for candidate in candidate_source_paths(raw_path, roots):
        if any(is_relative_to(candidate, root) for root in roots):
            return candidate
    text = str(raw_path or "").strip()
    return Path(text).expanduser().resolve()


def source_path_resolution_diagnostics(raw_path: str, allowed_roots: Iterable[Path]) -> dict[str, object]:
    roots = [Path(root).expanduser().resolve() for root in allowed_roots]
    candidate_rows: list[dict[str, object]] = []
    for candidate in candidate_source_paths(raw_path, roots):
        matched_roots = [str(root) for root in roots if is_relative_to(candidate, root)]
        try:
            exists = candidate.exists()
            is_file = candidate.is_file()
        except OSError:
            exists = False
            is_file = False
        candidate_rows.append(
            {
                "path": str(candidate),
                "inside_allowed_roots": bool(matched_roots),
                "matched_roots": matched_roots,
                "exists": exists,
                "is_file": is_file,
            }
        )
    return {
        "profile_version": "source-path-resolution-diagnostics-v1",
        "raw_path": str(raw_path or ""),
        "allowed_roots": [str(root) for root in roots],
        "candidate_count": len(candidate_rows),
        "existing_file_count": sum(1 for item in candidate_rows if item["is_file"]),
        "inside_allowed_root_count": sum(1 for item in candidate_rows if item["inside_allowed_roots"]),
        "status": "matched" if any(item["is_file"] and item["inside_allowed_roots"] for item in candidate_rows) else "unresolved",
        "candidates": candidate_rows[:10],
        "candidate_limit": 10,
    }


def windows_path_tail(raw_path: str) -> list[str]:
    pure = PureWindowsPath(str(raw_path or ""))
    if not pure.drive:
        return []
    tail: list[str] = []
    for part in pure.parts[1:]:
        if part in {"\\", "/"}:
            continue
        tail.append(part)
    return tail


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
