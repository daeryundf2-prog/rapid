from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


PLUGIN_KINDS = ("parser", "evidence-adapter", "viewer", "report-exporter")


class PluginError(ValueError):
    """Raised when a plugin manifest is invalid."""


def builtin_plugins() -> list[dict[str, object]]:
    return [
        {
            "id": "rapidtriage.files",
            "name": "RapidTriage file metadata parser",
            "version": "1",
            "kind": "parser",
            "enabled": True,
            "entrypoint": "rapidtriage.core.files",
        },
        {
            "id": "rapidtriage.docs",
            "name": "RapidTriage document text indexer",
            "version": "1",
            "kind": "parser",
            "enabled": True,
            "entrypoint": "rapidtriage.core.docs",
        },
        {
            "id": "rapidtriage.folder-adapter",
            "name": "Folder evidence adapter",
            "version": "1",
            "kind": "evidence-adapter",
            "enabled": True,
            "entrypoint": "rapidtriage.core.evidence:FolderAdapter",
        },
        {
            "id": "rapidtriage.markdown-report",
            "name": "Markdown report exporter",
            "version": "1",
            "kind": "report-exporter",
            "enabled": True,
            "entrypoint": "rapidtriage.core.case_report",
        },
    ]


def load_plugin_registry(paths: list[Path] | None = None) -> dict[str, object]:
    plugins = builtin_plugins()
    errors = []
    for root in paths or []:
        root = root.expanduser().resolve()
        if not root.exists():
            errors.append({"path": str(root), "error": "plugin directory not found"})
            continue
        for manifest_path in sorted(root.rglob("plugin.json")):
            try:
                plugins.append(validate_plugin_manifest(read_plugin_manifest(manifest_path), manifest_path=manifest_path))
            except PluginError as exc:
                errors.append({"path": str(manifest_path), "error": str(exc)})
    return {
        "command": "plugins",
        "summary": {
            "plugin_count": len(plugins),
            "error_count": len(errors),
            "enabled_count": sum(1 for plugin in plugins if plugin.get("enabled", True)),
        },
        "plugins": plugins,
        "errors": errors,
    }


def read_plugin_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PluginError(f"could not read plugin manifest: {path}") from exc
    if not isinstance(payload, dict):
        raise PluginError("plugin manifest must be a JSON object")
    return payload


def validate_plugin_manifest(payload: Mapping[str, object], *, manifest_path: Path | None = None) -> dict[str, object]:
    plugin_id = str(payload.get("id") or "").strip()
    name = str(payload.get("name") or "").strip()
    version = str(payload.get("version") or "").strip()
    kind = str(payload.get("kind") or "").strip()
    entrypoint = str(payload.get("entrypoint") or "").strip()
    if not plugin_id:
        raise PluginError("plugin id is required")
    if not name:
        raise PluginError("plugin name is required")
    if not version:
        raise PluginError("plugin version is required")
    if kind not in PLUGIN_KINDS:
        raise PluginError(f"plugin kind must be one of: {', '.join(PLUGIN_KINDS)}")
    if not entrypoint:
        raise PluginError("plugin entrypoint is required")
    return {
        "id": plugin_id,
        "name": name,
        "version": version,
        "kind": kind,
        "enabled": bool(payload.get("enabled", True)),
        "entrypoint": entrypoint,
        "description": str(payload.get("description") or ""),
        "manifest_path": str(manifest_path) if manifest_path else "",
    }
