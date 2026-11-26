from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from ...core.docs import redact_document_text
from ...core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from .constants import (
    JSON_PREVIEW_ITEM_LIMIT,
    STRUCTURED_PREVIEW_MAX_BYTES,
    XML_PREVIEW_NODE_LIMIT,
)
from .viewer_core import (
    structured_viewer_metadata,
)


def write_json_file(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_json_preview(source_path: Path, suffix: str) -> dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"JSON preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("json", "bounded-json-parse", "capped"),
            "json": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "preview_type": "text",
            "message": f"JSON parse failed, showing text fallback: {exc}",
            "text": "",
            "truncated": False,
            "redacted": False,
            "viewer_metadata": structured_viewer_metadata("json", "parse-fallback-text", "parse-failed"),
        }
    return build_json_preview_from_text(
        text,
        suffix,
        path=source_path,
        strategy="bounded-json-parse",
        message="JSON structured preview is available.",
    )


def build_json_preview_from_text(
    text: str,
    suffix: str,
    *,
    path: Path,
    strategy: str = "bounded-zip-entry-json-parse",
    message: str = "JSON structured preview is available from a ZIP entry.",
) -> dict[str, object]:
    """JSON/JSONL text of the file at ``path`` as a structured preview, its secrets masked
    (:func:`~rapidtriage.core.docs.redact_document_text`): in the text before parsing, and again in
    every parsed string, where ``\\u`` escapes and ``\\n`` in a PEM block are decoded."""
    masked = redact_document_text(path, text)
    redacted = masked != text
    try:
        if suffix == ".json":
            parsed = json.loads(masked)
            data = redact_json_value(path, parsed)
            redacted = redacted or data != parsed
            preview = summarize_json_value(data)
            formatted = json.dumps(data, ensure_ascii=False, indent=2)
            item_count = json_item_count(data)
        else:
            rows = []
            errors = []
            for line_number, line in enumerate(masked.splitlines(), start=1):
                if not line.strip():
                    continue
                if len(rows) >= JSON_PREVIEW_ITEM_LIMIT:
                    break
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append({"line": line_number, "error": str(exc)})
                    continue
                value = redact_json_value(path, parsed)
                redacted = redacted or value != parsed
                rows.append({"line": line_number, "value": summarize_json_value(value)})
            preview = {"type": "jsonl", "rows": rows, "errors": errors[:5]}
            formatted = "\n".join(masked.splitlines()[:JSON_PREVIEW_ITEM_LIMIT])
            item_count = len(rows)
    except json.JSONDecodeError as exc:
        return {
            "preview_type": "text",
            "message": f"JSON parse failed, showing text fallback: {exc}",
            "text": masked[:20000],
            "truncated": len(masked) > 20000,
            "redacted": redacted,
            "viewer_metadata": structured_viewer_metadata("json", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "json",
        "message": message,
        "text": formatted[:20000],
        "truncated": len(formatted) > 20000,
        "redacted": redacted,
        "viewer_metadata": structured_viewer_metadata("json", strategy, "available"),
        "json": {
            "summary": preview,
            "item_count": item_count,
            "item_limit": JSON_PREVIEW_ITEM_LIMIT,
            "truncated": item_count >= JSON_PREVIEW_ITEM_LIMIT,
        },
    }


def redact_json_value(path: Path, value: object) -> object:
    """Parsed JSON with every string, keys included, masked by redact_document_text."""
    if isinstance(value, str):
        return redact_document_text(path, value)
    if isinstance(value, list):
        return [redact_json_value(path, item) for item in value]
    if isinstance(value, dict):
        return {redact_document_text(path, key): redact_json_value(path, item) for key, item in value.items()}
    return value


def summarize_json_value(value: object, *, depth: int = 0) -> object:
    if depth >= 3:
        if isinstance(value, dict):
            return {"type": "object", "keys": len(value)}
        if isinstance(value, list):
            return {"type": "array", "items": len(value)}
        return value
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": list(value.keys())[:JSON_PREVIEW_ITEM_LIMIT],
            "sample": {str(key): summarize_json_value(item, depth=depth + 1) for key, item in list(value.items())[:10]},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "items": len(value),
            "sample": [summarize_json_value(item, depth=depth + 1) for item in value[:10]],
        }
    return value


def json_item_count(value: object) -> int:
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 1


def build_xml_preview(source_path: Path) -> dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"XML preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "capped"),
            "xml": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "preview_type": "text",
            "message": f"XML parse failed, showing text fallback: {exc}",
            "text": "",
            "truncated": False,
            "redacted": False,
            "viewer_metadata": structured_viewer_metadata("xml", "parse-fallback-text", "parse-failed"),
        }
    # Secrets are masked in the text before parsing, then in each parsed text and attribute value,
    # where character references are decoded.
    masked = redact_document_text(source_path, text)
    try:
        root = safe_xml_fromstring(masked.encode("utf-8", errors="replace"))
    except (ET.ParseError, UnsafeXmlError) as exc:
        return {
            "preview_type": "text",
            "message": f"XML parse failed, showing text fallback: {exc}",
            "text": masked[:20000],
            "truncated": len(masked) > 20000,
            "redacted": masked != text,
            "viewer_metadata": structured_viewer_metadata("xml", "parse-fallback-text", "parse-failed"),
        }
    tree_redacted = redact_xml_tree(source_path, root)
    nodes = summarize_xml_nodes(root)
    return {
        "preview_type": "xml",
        "message": "XML structured preview is available.",
        "text": masked[:20000],
        "truncated": len(masked) > 20000,
        "redacted": masked != text or tree_redacted,
        "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "available"),
        "xml": {
            "root_tag": local_xml_name(root.tag),
            "root_attributes": dict(root.attrib),
            "nodes": nodes,
            "node_limit": XML_PREVIEW_NODE_LIMIT,
            "truncated": len(nodes) >= XML_PREVIEW_NODE_LIMIT,
        },
    }


def redact_xml_tree(path: Path, root: ET.Element) -> bool:
    """Mask every text, tail and attribute value under ``root`` in place; True when one changed."""
    changed = False
    for element in root.iter():
        for field in ("text", "tail"):
            value = getattr(element, field)
            if value:
                masked = redact_document_text(path, value)
                if masked != value:
                    setattr(element, field, masked)
                    changed = True
        for name, value in element.attrib.items():
            masked = redact_document_text(path, value)
            if masked != value:
                element.set(name, masked)
                changed = True
    return changed


def summarize_xml_nodes(root: ET.Element) -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    stack: list[tuple[ET.Element, str, int]] = [(root, "/" + local_xml_name(root.tag), 0)]
    while stack and len(nodes) < XML_PREVIEW_NODE_LIMIT:
        node, path, depth = stack.pop()
        text = " ".join((node.text or "").split())
        nodes.append(
            {
                "path": path,
                "tag": local_xml_name(node.tag),
                "depth": depth,
                "attributes": dict(list(node.attrib.items())[:10]),
                "text": text[:240],
                "child_count": len(list(node)),
            }
        )
        children = list(node)
        for index, child in reversed(list(enumerate(children[:20], start=1))):
            stack.append((child, f"{path}/{local_xml_name(child.tag)}[{index}]", depth + 1))
    return nodes


def local_xml_name(value: str) -> str:
    return value.rsplit("}", 1)[-1] if "}" in value else value
