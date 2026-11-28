"""Bounded reads of chat values in a private copy of editor global storage and of omp prompt history."""
from __future__ import annotations

import json
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from ..core.sqlite_snapshot import open_sqlite_snapshot, sqlite_snapshot_reference
from .ai_agent_records import clean, content, items, mapping, tool

DB_BYTES = 256 << 20
VALUE_BYTES = 2 << 20
KEYS = ("bubbleId:%", "composerData:%", "composer.composerData", "workbench.panel.aichat.view.aichat.chatdata",
        "workbench.panel.chat.view.copilot.chatdata", "chat.ChatSessionStore.index", "aiService.prompts")


def editor_message(src, message):
    role = message.get("role", message.get("type"))
    if type(role) is int:
        role = {1: "user", 2: "assistant"}.get(role)
    if role == "ai":
        role = "assistant"
    if role not in ("user", "assistant", "tool"):
        yield src.note("unrecognized-editor-message")
        return
    stamp = message.get("createdAt", message.get("timestamp"))
    model = mapping(message.get("modelInfo")).get("modelName", message.get("model", ""))
    text = content(message.get("text", message.get("content")))
    if text:
        yield src.row("message", role=role, timestamp=stamp, unit="ms", model=model, text=text)
    call = mapping(message.get("toolFormerData"))
    if call:
        yield from tool(src, call.get("name"), call.get("params", call.get("rawArgs")),
                        timestamp=stamp, unit="ms", model=model, call_id=call.get("toolCallId"))
        if call.get("result") is not None:
            yield src.row("tool-result", role="tool", timestamp=stamp, unit="ms", model=model,
                          tool_name=call.get("name"), call_id=call.get("toolCallId"), text=content(call["result"]))


def editor_value(src, key, value):
    doc = mapping(value)
    parts = key.split(":")
    src.session = doc.get("composerId", parts[1] if len(parts) > 1 else doc.get("sessionId", ""))
    if key.startswith("bubbleId:"):
        yield from editor_message(src, doc)
        return
    if key == "aiService.prompts":
        for index, item in enumerate(items(value)):
            text = mapping(item).get("text", item)
            if isinstance(text, str):
                yield replace(src, location={**src.location, "message_index": index}).row("message", role="user", text=text)
        return
    if isinstance(doc.get("requests"), list):
        for index, entry in enumerate(doc["requests"]):
            entry = mapping(entry)
            part = replace(src, location={**src.location, "request_index": index})
            message = entry.get("message")
            prompt = mapping(message).get("text", message)
            if isinstance(prompt, str):
                yield part.row("message", role="user", timestamp=entry.get("timestamp"), unit="ms", text=prompt)
            response = [mapping(v).get("value", v) for v in items(entry.get("response"))]
            text = content(response)
            if text:
                yield part.row("message", role="assistant", text=text)
        return
    messages = doc.get("conversation", doc.get("messages"))
    if isinstance(messages, list):
        for index, item in enumerate(messages):
            yield from editor_message(replace(src, location={**src.location, "message_index": index}), mapping(item))
    elif isinstance(doc.get("tabs"), list):
        for index, tab in enumerate(doc["tabs"]):
            tab = mapping(tab)
            tab_src = replace(src, session=tab.get("tabId", ""), location={**src.location, "tab_index": index})
            for seq, bubble in enumerate(items(tab.get("bubbles"))):
                yield from editor_message(replace(tab_src, location={**tab_src.location, "message_index": seq}), mapping(bubble))
    else:
        yield src.note("editor-index-or-unsupported-layout")


def database_bytes(path: Path) -> int:
    size = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            size += path.with_name(path.name + suffix).lstat().st_size
        except FileNotFoundError:
            continue
    return size


def editor(src, path: Path):
    if database_bytes(path) > DB_BYTES:
        yield src.note("database-size-limit")
        return
    provenance = {}
    with open_sqlite_snapshot(path, provenance=provenance) as db:
        db.execute("PRAGMA trusted_schema=OFF").close()
        snapshot = sqlite_snapshot_reference(provenance)
        with closing(db.execute("PRAGMA main.table_list")) as listing:
            # Table names are fixed. Never run a view or virtual table supplied by evidence.
            tables = {name for _, name, kind, *_ in listing if kind == "table"}
        found = False
        for table in ("ItemTable", "cursorDiskKV"):
            if table not in tables:
                continue
            found = True
            conditions = " OR ".join("key LIKE ?" for _ in KEYS)
            # Closing the cursor finalizes its statement even when the consumer stops at a cap,
            # so the connection really releases the private copy (Windows cannot delete open files).
            with closing(db.execute(
                    f"SELECT rowid, substr(key,1,512), CASE WHEN length(CAST(value AS BLOB)) <= ? THEN value END "
                    f'FROM "{table}" WHERE {conditions} ORDER BY rowid', (VALUE_BYTES, *KEYS))) as rows:
                yield from _editor_rows(src, table, snapshot, rows)
        if not found:
            yield src.note("editor-tables-missing")


def _editor_rows(src, table, snapshot, rows):
    for rowid, key, raw in rows:
        source = replace(src, location={"source_table": table, "source_rowid": rowid,
                                        "source_key": clean(key), "snapshot_id": snapshot["snapshot_id"]})
        if raw is None:
            yield source.note("empty-or-oversize-editor-value")
            continue
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
            yield source.note("invalid-editor-json")
            continue
        yield from editor_value(source, key, doc)


def prompt_history(src, path: Path):
    """omp ``history.db`` table ``history(prompt, created_at, cwd, session_id, use_count)``. A resubmitted prompt
    keeps one row: ``created_at`` (epoch seconds) is its latest submission and ``use_count`` the submissions."""
    if database_bytes(path) > DB_BYTES:
        yield src.note("database-size-limit")
        return
    provenance = {}
    with open_sqlite_snapshot(path, provenance=provenance) as db:
        db.execute("PRAGMA trusted_schema=OFF").close()
        snapshot = sqlite_snapshot_reference(provenance)
        with closing(db.execute("PRAGMA main.table_list")) as listing:
            if not any(name == "history" and kind == "table" for _, name, kind, *_ in listing):
                yield src.note("history-table-missing")
                return
        with closing(db.execute(
                "SELECT rowid, CASE WHEN length(CAST(prompt AS BLOB)) <= ? THEN prompt END, created_at, cwd, session_id, "
                "use_count FROM history ORDER BY rowid", (VALUE_BYTES,))) as rows:
            for rowid, prompt, created, cwd, session, uses in rows:
                source = replace(src, session=session, cwd=cwd, location={
                    "source_table": "history", "source_rowid": rowid, "snapshot_id": snapshot["snapshot_id"]})
                if not isinstance(prompt, str):
                    yield source.note("empty-or-oversize-history-value")
                    continue
                yield source.row("message", role="user", timestamp=created, unit="s", text=prompt,
                                 use_count=str(uses) if type(uses) is int else "")
