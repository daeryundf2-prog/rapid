#!/usr/bin/env python3
"""Check the AI tool catalog (R7 stage 3.5 §3.1).

1. ``rapidtriage/core/ai_catalog/data/*.json`` are identical to ``docs/ai-tool-catalog/*.json``
   (same JSON; text equal after CRLF → LF, the package copy is LF).
2. Schema: the six tool files are lists of objects with a ``name``; path-bearing files carry
   ``paths``; ``cloud_agents`` carries ``domains``; ``infrastructure`` has its sections.
3. Every ``conf`` / ``confidence`` text names a known level
   (``official-doc|third-party|inferred|unverified|local-verified`` — ``verified-on-test-pc`` and
   ``unknown`` are accepted spellings of the last two).
4. Path templates: every anchored path uses a known variable (``%USERPROFILE%``, ``~``,
   ``%APPDATA%``, ``%LOCALAPPDATA%``, ``%TEMP%``, ``$XDG_*`` …), ``<…>`` placeholders are closed.
   Unknown variables are listed as warnings (tool-specific homes such as ``%HERMES_HOME%``).
5. The loader runs, tool ids are unique, and the legacy browser / memory AI domains are kept.

Usage: python scripts/check-ai-catalog.py [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.ai_catalog import catalog as ai_catalog

DOCS_DIR = REPO_ROOT / "docs" / "ai-tool-catalog"
DATA_DIR = ai_catalog.CATALOG_DATA_DIR
PATH_FILES = ("chatbots", "cli_agents", "ide_agents", "harnesses", "local_llm")
INFRASTRUCTURE_SECTIONS = ("meta", "1_relays_gateways_providers", "2_api_keys_and_credential_storage")
_VARIABLE_RE = re.compile(r"%[A-Za-z_()0-9]+%|\$\{?[A-Z_][A-Z0-9_]*\}?")


def _conf_texts(value: object, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if child_key in ("conf", "confidence"):
                if isinstance(child, str):
                    yield str(child_key), child
                elif isinstance(child, Mapping):
                    for sub_key, sub in child.items():
                        if isinstance(sub, str):
                            yield f"{child_key}.{sub_key}", sub
                continue
            yield from _conf_texts(child, str(child_key))
    elif isinstance(value, list):
        for item in value:
            yield from _conf_texts(item, key)


def check() -> dict[str, object]:
    errors: list[str] = []
    warnings: list[str] = []
    raw: dict[str, object] = {}
    for name in ai_catalog.CATALOG_FILES:
        docs = DOCS_DIR / f"{name}.json"
        data = DATA_DIR / f"{name}.json"
        if not docs.is_file() or not data.is_file():
            errors.append(f"{name}.json: missing ({'docs' if not docs.is_file() else 'package data'})")
            continue
        docs_text = docs.read_bytes().replace(b"\r\n", b"\n")
        data_bytes = data.read_bytes()
        if b"\r\n" in data_bytes:
            errors.append(f"{name}.json: package copy must use LF line endings")
        if docs_text != data_bytes.replace(b"\r\n", b"\n"):
            errors.append(f"{name}.json: package copy differs from docs/ai-tool-catalog/{name}.json")
        try:
            raw[name] = json.loads(data_bytes.decode("utf-8"))
        except ValueError as exc:
            errors.append(f"{name}.json: invalid JSON ({exc})")
    for name in ai_catalog.TOOL_CATALOG_FILES:
        entries = raw.get(name)
        if not isinstance(entries, list):
            errors.append(f"{name}.json: top level must be a list")
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping) or not isinstance(entry.get("name"), str) or not entry.get("name"):
                errors.append(f"{name}.json[{index}]: entry needs a non-empty name")
                continue
            if name in PATH_FILES and "paths" not in entry:
                errors.append(f"{name}.json[{index}] {entry['name']}: missing paths")
            if name == "cloud_agents" and "domains" not in entry:
                errors.append(f"{name}.json[{index}] {entry['name']}: missing domains")
    infrastructure = raw.get("infrastructure")
    if isinstance(infrastructure, Mapping):
        for section in INFRASTRUCTURE_SECTIONS:
            if section not in infrastructure:
                errors.append(f"infrastructure.json: missing section {section}")
    elif "infrastructure" in raw:
        errors.append("infrastructure.json: top level must be an object")
    conf_count = 0
    for name, payload in raw.items():
        for key, text in _conf_texts(payload):
            conf_count += 1
            if not ai_catalog.normalize_confidence(text):
                errors.append(f"{name}.json: {key} has no known confidence level: {text[:80]!r}")
    template_count = 0
    unknown_variables: dict[str, int] = {}
    try:
        catalog = ai_catalog.load_catalog(DATA_DIR)
    except Exception as exc:  # the loader itself must never fail on the shipped catalog
        errors.append(f"loader failed: {type(exc).__name__}: {exc}")
        catalog = None
    if catalog is not None:
        ids = [tool.id for tool in catalog.tools]
        if len(ids) != len(set(ids)):
            errors.append("tool ids are not unique")
        for tool in catalog.tools:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", tool.id):
                errors.append(f"tool id {tool.id!r} is not a slug")
            for template in tool.paths:
                template_count += 1
                if "<" in template.template or ">" in template.template:
                    errors.append(f"{tool.id}: unclosed <placeholder> in {template.template!r}")
                if template.anchor and template.anchor not in ai_catalog.KNOWN_ANCHORS:
                    unknown_variables[template.anchor] = unknown_variables.get(template.anchor, 0) + 1
        for name in PATH_FILES:
            for text in _all_strings(raw.get(name)):
                for variable in _VARIABLE_RE.findall(text):
                    normalized = re.sub(r"^\$\{?(\w+)\}?$", r"$\1", variable)
                    normalized = normalized.upper() if normalized.startswith("%") else normalized
                    if normalized not in ai_catalog.KNOWN_ANCHORS:
                        unknown_variables.setdefault(normalized, 0)
        browser = ai_catalog.domains(legacy="browser", catalog=catalog)
        if tuple(browser[: len(ai_catalog._LEGACY_BROWSER_DOMAINS)]) != ai_catalog._LEGACY_BROWSER_DOMAINS:
            errors.append("browser AI domains no longer start with the 21 legacy domains")
        memory = ai_catalog.domains(legacy="memory", catalog=catalog)
        if tuple(memory[: len(ai_catalog._LEGACY_MEMORY_DOMAINS)]) != ai_catalog._LEGACY_MEMORY_DOMAINS:
            errors.append("memory AI domains no longer start with the 8 legacy domains")
    for variable in sorted(unknown_variables):
        warnings.append(f"path variable {variable} is not expanded (tool-specific home or env override)")
    return {
        "ok": not errors,
        "files": list(ai_catalog.CATALOG_FILES),
        "tool_count": len(catalog.tools) if catalog is not None else 0,
        "path_template_count": template_count,
        "confidence_value_count": conf_count,
        "errors": errors,
        "warnings": warnings,
    }


def _all_strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _all_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _all_strings(child)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    result = check()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"AI catalog: {result['tool_count']} tools, {result['path_template_count']} path templates")
        for warning in result["warnings"]:
            print(f"warning: {warning}")
        for error in result["errors"]:
            print(f"error: {error}")
        print("ok" if result["ok"] else "FAILED")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
