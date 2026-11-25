"""Read message and tool records from Claude Code, Codex CLI and Gemini CLI."""
from __future__ import annotations

from dataclasses import replace

from .ai_agent_records import content, items, mapping, tool


def claude(src, record):
    message = mapping(record.get("message"))
    role = message.get("role", record.get("type"))
    if role not in ("assistant", "user"):
        if not record.get("type") or "message" in record:
            yield src.note("unrecognized-claude-record")
        return
    source = replace(src, session=record.get("sessionId", ""), cwd=record.get("cwd", ""),
                     app_version=record.get("version", ""))
    stamp = record.get("timestamp")
    model = message.get("model", "")
    blocks = message.get("content")
    if not isinstance(blocks, (str, list)):
        yield source.note("invalid-message-content", damaged_count=1)
        return
    text = content(blocks)
    if text or isinstance(blocks, str):
        yield source.row("message", role=role, timestamp=stamp, model=model, text=text)
    for index, block in enumerate(items(blocks)):
        block = mapping(block)
        part = replace(source, location={**source.location, "content_index": index})
        if block.get("type") == "tool_use":
            yield from tool(part, block.get("name"), block.get("input"), call_id=block.get("id"),
                            timestamp=stamp, model=model)
        elif block.get("type") == "tool_result":
            yield part.row("tool-result", role="tool", timestamp=stamp, model=model,
                           call_id=block.get("tool_use_id"), text=content(block.get("content")))


def claude_history(src, record):
    """``~/.claude/history.jsonl``: one typed prompt per line with epoch-millisecond time and project folder."""
    if not isinstance(record.get("display"), str):
        yield src.note("unrecognized-history-record", damaged_count=1)
        return
    yield replace(src, session=record.get("sessionId", ""), cwd=record.get("project", "")).row(
        "message", role="user", timestamp=record.get("timestamp"), unit="ms", text=record["display"])


def codex(src, record, history):
    if history:
        if not isinstance(record.get("text"), str):
            yield src.note("unrecognized-history-record", damaged_count=1)
            return
        yield replace(src, session=record.get("session_id", "")).row(
            "message", role="user", timestamp=record.get("ts"), unit="s", text=record["text"])
        return
    payload = mapping(record.get("payload"))
    kind = record.get("type")
    if kind == "session_meta":
        src.session = payload.get("id", payload.get("session_id", ""))
        src.cwd = payload.get("cwd", "")
        src.app_version = payload.get("cli_version", "")
        src.model = payload.get("model", "")
    elif kind == "turn_context":
        src.cwd = payload.get("cwd", src.cwd)
        src.model = payload.get("model", src.model)
    elif kind == "response_item":
        action = payload.get("type")
        stamp = record.get("timestamp")
        if action == "message":
            yield src.row("message", role=payload.get("role"), timestamp=stamp, text=content(payload.get("content")))
        elif action in ("function_call", "custom_tool_call"):
            yield from tool(src, payload.get("name"), payload.get("arguments"), call_id=payload.get("call_id"),
                            timestamp=stamp, patch=payload.get("input") if payload.get("name") == "apply_patch" else None)
        elif action in ("function_call_output", "custom_tool_call_output"):
            yield src.row("tool-result", role="tool", timestamp=stamp, call_id=payload.get("call_id"),
                          text=content(payload.get("output")))
    elif kind not in ("event_msg", "compacted", "token_count"):
        yield src.note("unrecognized-rollout-record")


def gemini_message(src, message):
    role = message.get("type")
    if role not in ("user", "gemini", "assistant"):
        return
    stamp = message.get("timestamp")
    model = message.get("model", "")
    text = content(message.get("content", message.get("message")))
    if text:
        yield src.row("message", timestamp=stamp, role="user" if role == "user" else "assistant", model=model, text=text)
    for index, call in enumerate(items(message.get("toolCalls"))):
        call = mapping(call)
        part = replace(src, location={**src.location, "tool_index": index})
        yield from tool(part, call.get("name"), call.get("args"), call_id=call.get("id"),
                        timestamp=call.get("timestamp", stamp), model=model)
        if call.get("result") is not None:
            result = call["result"]
            text = content(result)
            if not text:
                outputs = []
                for item in items(result):
                    response = mapping(mapping(item).get("functionResponse"))
                    output = mapping(response.get("response")).get("output")
                    if isinstance(output, str):
                        outputs.append(output)
                text = "\n".join(outputs)
            yield part.row("tool-result", role="tool", call_id=call.get("id"), tool_name=call.get("name"),
                           text=text, model=model, timestamp=call.get("timestamp", stamp))


def gemini(src, record):
    if isinstance(record, dict):
        src.session = record.get("sessionId", src.session)
        if any(k in record for k in ("$patch", "$rewindTo", "$set")):
            yield src.note("session-update-not-replayed")
            return
        if "messages" not in record:
            yield from gemini_message(src, record)
            return
        messages = record["messages"]
    else:
        messages = record
    for index, entry in enumerate(items(messages)):
        message = mapping(entry)
        source = replace(src, session=message.get("sessionId", src.session),
                         location={**src.location, "message_index": index})
        yield from gemini_message(source, message)
