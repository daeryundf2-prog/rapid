"""Read message and tool records from Claude Code, Codex CLI, Gemini CLI and pi-family (omp, pi, senpi, OmO)."""
from __future__ import annotations

from dataclasses import replace

from .ai_agent_records import clean, content, items, mapping, tool

# pi-family entry types that carry no user, assistant or tool text (oh-my-pi docs/session.md "Entry Taxonomy",
# pi docs/session-format.md "Entry Types"). Summaries and extension context are model-generated or injected.
PI_QUIET_ENTRIES = frozenset({
    "thinking_level_change", "service_tier_change", "model_usage", "usage", "compaction", "branch_summary",
    "reset_boundary", "custom", "custom_message", "label", "title_change", "ttsr_injection", "credential_pin",
    "session_init", "mode_change", "context_edit", "session_info"})
# Prompt, extension and summary messages that the loader reconstructs; no user or assistant turn of their own.
PI_QUIET_ROLES = frozenset({"system", "custom", "hookMessage", "branchSummary", "compactionSummary"})


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


def pi_header(src, record):
    """The ``session`` header names the session, its working folder, layout version and parent session
    (a fork's or a subagent's parent transcript, recorded as an id or a path)."""
    src.session = record["id"]
    src.cwd = record.get("cwd", "")
    version = record.get("version")
    if isinstance(version, (str, int)) and not isinstance(version, bool):
        src.version = str(version)
    parent = record.get("parentSession")
    src.parent_session = parent if isinstance(parent, str) else ""


def pi_entry(src, record, models):
    """``models`` maps each entry id to the model in effect there. A ``model_change`` applies to its descendants
    in the tree, so a switch made on an abandoned branch does not carry over to the active one. Entries without a
    tree id (pi's version 1 layout) fall back to file order."""
    kind = record.get("type")
    ident, parent = record.get("id"), record.get("parentId")
    tree_model = isinstance(ident, str)
    inherited = (models.get(parent, "") if isinstance(parent, str) else "") if tree_model else src.model
    if kind == "model_change":
        # omp records ``provider/model``; pi records ``provider`` and ``modelId``.
        model = record.get("model")
        if not isinstance(model, str):
            model = "/".join(v for v in (record.get("provider"), record.get("modelId")) if isinstance(v, str) and v)
        if tree_model:
            models[ident] = model or inherited
        else:
            src.model = model or src.model
        return
    if tree_model:
        models[ident] = inherited
    if kind != "message":
        if kind not in PI_QUIET_ENTRIES:
            yield src.note("unrecognized-session-record")
        return
    message = mapping(record.get("message"))
    role = message.get("role")
    tree = {key: clean(value) for key, value in (("entry_id", ident), ("parent_entry_id", parent)) if isinstance(value, str)}
    part = replace(src, location={**src.location, **tree}, model=inherited)
    # Entry time is ISO 8601; the nested message keeps epoch milliseconds and stands in when the entry has none.
    stamp, unit = record.get("timestamp"), ""
    if stamp is None and type(message.get("timestamp")) in (int, float):
        stamp, unit = message["timestamp"], "ms"
    model = message.get("model", "") if role == "assistant" else ""
    if role in ("user", "developer", "assistant"):
        blocks = message.get("content")
        if not isinstance(blocks, (str, list)):
            yield part.note("invalid-message-content", damaged_count=1)
            return
        text = content(blocks)
        # omp records who initiated a user or developer turn: ``user`` for typed input, ``agent`` for text an
        # extension generated or relayed from another agent (subagent task prompts, parent steering). ``role`` stays
        # the message role; ``attribution`` is exported as recorded so agent-written turns are not read as typed.
        attribution = message.get("attribution")
        extra = {"attribution": attribution} if isinstance(attribution, str) else {}
        if text or isinstance(blocks, str):
            yield part.row("message", role=role, timestamp=stamp, unit=unit, model=model, text=text, **extra)
        for index, block in enumerate(items(blocks) if role == "assistant" else ()):
            block = mapping(block)
            if block.get("type") == "toolCall":
                yield from tool(replace(part, location={**part.location, "content_index": index}), block.get("name"),
                                block.get("arguments"), call_id=block.get("id"), timestamp=stamp, unit=unit, model=model)
    elif role == "toolResult":
        yield part.row("tool-result", role="tool", timestamp=stamp, unit=unit, call_id=message.get("toolCallId"),
                       tool_name=message.get("toolName"), text=content(message.get("content")))
    elif role in ("bashExecution", "pythonExecution"):
        # A command the user ran directly (``!`` or ``$``), not a model tool call.
        name, command = ("bash", message.get("command")) if role == "bashExecution" else ("python", message.get("code"))
        yield part.row("tool-call", role="user", timestamp=stamp, unit=unit, tool_name=name, command_line=command,
                       record_format=role)
        yield part.row("tool-result", role="tool", timestamp=stamp, unit=unit, tool_name=name,
                       text=message.get("output"), record_format=role)
    elif role == "fileMention":
        # Inlined file contents are the file, not something the user typed; only the paths are kept.
        paths = [mapping(item).get("path") for item in items(message.get("files"))]
        yield part.row("message", role="user", timestamp=stamp, unit=unit, file_paths=paths, record_format=role)
    elif role not in PI_QUIET_ROLES:
        yield part.note("unrecognized-session-message")


def pi_log(src, record):
    """omp ``logs/omp.<date>.<pid>.log``: one JSON record per line with local time and offset, level, process id
    and message. Other context fields can hold request data and are not exported."""
    if not isinstance(record.get("message"), str):
        yield src.note("unrecognized-log-record", damaged_count=1)
        return
    pid = record.get("pid")
    yield replace(src, session=record.get("sessionId", "")).row(
        "log", timestamp=record.get("timestamp"), text=record["message"], level=record.get("level"),
        pid=str(pid) if type(pid) is int else "")
