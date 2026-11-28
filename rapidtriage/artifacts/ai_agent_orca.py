"""Orca Bots records (github.com/stablyai/orca): bots that take requests from Slack, GitHub, Linear and Discord and run
coding agents in worktrees. Formats follow Orca's public source at commit ``c46704e1``: ``src/shared/bot-types.ts``
and ``src/main/bots/bot-home.ts`` (the bot record and its home in ``~/.orca/bots``), ``bot-work-rows.ts`` and
``bot-work-store.ts`` (``bot-work.sqlite``), ``bot-items-schema.ts`` and ``src/shared/bots/bot-items.ts``
(``bot-items.sqlite``), ``bot-memory-history.ts`` (``bot-memory-history/``), ``bot-look-around-store.ts``
(``bot-look-around.json``), ``src/main/runtime/orchestration/db`` with ``bot-requests/`` (``orchestration.db``),
``src/main/persistence/profile-state`` (``profiles/<id>/profile-state.db`` and the legacy ``orca-data.json``),
``src/shared/orca-profiles/orca-profiles.ts`` (``orca-profile-index.json``) and
``src/main/orca-profiles/cloud-session/profile-cloud-session-store.ts`` (``account-session.json.enc``).

Credentials are never exported: the Orca Cloud session file gives only its seal format and save time, and token or
key files only their names. No argv or command line is exported either: a worker's launch options (argv,
environment, env files), effects and terminal handle can hold unlabelled secrets that redaction cannot see. Every
exported text passes ``clean()``."""
from __future__ import annotations

import json
import re
import urllib.parse
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from ..core.sqlite_snapshot import open_sqlite_snapshot, sqlite_snapshot_reference
from .ai_agent_editor import DB_BYTES, VALUE_BYTES
from .ai_agent_records import TEXT_LIMIT, clean, items, mapping, utc

KIND = "orca-bots"
DOCUMENT_BYTES = 8 << 20
MEMORY_BYTES = 64 << 10
LIST_LIMIT = 64
# Electron's userData: ``<appData>/orca`` (macOS ``Library/Application Support``, Windows ``AppData/Roaming``,
# Linux ``.config``), ``orca-dev`` for development builds. ``app.setName`` may recase it to ``Orca``.
APP_DIRS = {"orca", "orca-dev"}
APP_PARENTS = {("library", "application support"), ("appdata", "roaming")}
# ``bot-home.ts``: the folder is the bot's slug, never a path.
BOT_FOLDER = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SQLITE_TIME = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d{1,9})?)$")
USER_DATA_FILES = {"bot-work.sqlite": "bot-work", "bot-items.sqlite": "bot-items", "orchestration.db": "orchestration",
                   "bot-look-around.json": "look-around", "orca-data.json": "profile-json",
                   "orca-profile-index.json": "profile-index", "connector-host-key.json": "secret"}
# Credential files Orca keeps in ``~/.orca`` whatever the userData folder (``linear-credential-paths.ts``,
# ``bitbucket/credential-store.ts``): named only.
HOME_SECRETS = {"linear-token.enc", "bitbucket-credential.enc"}
MEMORY_FILES = {"soul.md": "soul", "memory.md": "memory"}


def identify_orca(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Files in Orca's userData folder and in ``.orca`` (the bot homes, Orca's own credential files, and the userData
    of a shared-home server). A ``--user-data-dir``, ``ORCA_DEV_USER_DATA_PATH`` or other moved folder is not
    searched."""
    for index in range(len(parts) - 1):
        part = parts[index]
        tail = parts[index + 1:]
        if part == ".orca":
            mode = home_mode(tail) or user_data_mode(tail)
        elif part in APP_DIRS and (parts[max(0, index - 2):index] in APP_PARENTS or parts[index - 1:index] == (".config",)):
            mode = user_data_mode(tail) or bot_home_mode(tail)
        else:
            mode = None
        if mode:
            return KIND, mode
    return None


def bot_home_mode(tail: tuple[str, ...]) -> str | None:
    """``<bots root>/<folder>/``: ``bot.json``, ``SOUL.md``, ``MEMORY.md`` and ``memory/<topic>.md``."""
    if len(tail) < 3 or tail[0] != "bots" or not BOT_FOLDER.match(tail[1]):
        return None
    if tail[2:] == ("bot.json",):
        return "bot-home"
    if len(tail) == 3 and tail[2] in MEMORY_FILES:
        return "memory-file"
    return "memory-file" if len(tail) == 4 and tail[2] == "memory" and tail[3].endswith(".md") else None


def home_mode(tail: tuple[str, ...]) -> str | None:
    if len(tail) == 1 and tail[0] in HOME_SECRETS:
        return "secret"
    if len(tail) == 2 and tail[0] == "linear-tokens" and tail[1].endswith(".enc"):
        return "secret"
    return bot_home_mode(tail)


def user_data_mode(tail: tuple[str, ...]) -> str | None:
    name = tail[-1]
    if len(tail) == 1:
        return USER_DATA_FILES.get(name)
    if len(tail) == 2 and tail[0] == "bot-memory-history" and name.endswith(".json"):
        return "memory-history"
    if len(tail) == 3 and tail[0] == "profiles":
        return {"profile-state.db": "profile-db", "orca-data.json": "profile-json",
                "account-session.json.enc": "cloud-session"}.get(name)
    return None


def ms(value):
    return utc(value, "ms") if type(value) in (int, float) else None


def number(value) -> str:
    return str(value) if type(value) in (int, float) and not isinstance(value, bool) else ""


def flag(value) -> str:
    return str(value).lower() if isinstance(value, bool) else ""


def text_of(value) -> str:
    return value if isinstance(value, str) else ""


def listed(row, key, values):
    """A list field: string entries only, each redacted, at most ``LIST_LIMIT``."""
    values = items(values)
    row.details[key] = [clean(v) for v in values[:LIST_LIMIT] if isinstance(v, str)]
    if len(values) > LIST_LIMIT:
        row.details["flags"].append("list-length-limit")
    return row


def stamped(row, **times):
    """Extra event times as ISO UTC; an absent time leaves no field."""
    for key, value in times.items():
        if value:
            row.details[key] = value
    return row


def sqlite_time(value):
    """SQLite ``datetime('now')`` text (UTC, ``YYYY-MM-DD HH:MM:SS``) as RFC 3339 text."""
    match = SQLITE_TIME.match(value) if isinstance(value, str) else None
    return f"{match[1]}T{match[2]}Z" if match else None


def sqlite_row(src, category, raw_time, **fields):
    """A row timed by SQLite ``datetime`` text, keeping the recorded text as ``timestamp_raw``."""
    out = src.row(category, timestamp=sqlite_time(raw_time) or raw_time, **fields)
    if isinstance(raw_time, str):
        out.details["timestamp_raw"] = clean(raw_time)
    return out


def json_cell(value):
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except (ValueError, RecursionError):
        return None


def orca(src, path: Path, mode: str):
    src.location = {"source_offset": 0}
    if mode == "secret":
        # Presence only: never opened.
        yield src.row("secret-file", file_name=path.name)
        return
    if mode in SQLITE_STORES:
        yield from store(src, path, mode)
        return
    limit = MEMORY_BYTES if mode == "memory-file" else DOCUMENT_BYTES
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if mode == "memory-file":
        yield memory_file(src, path, raw[:limit], len(raw) > limit)
        return
    if len(raw) > limit:
        yield src.note("document-size-limit")
        return
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        if mode == "cloud-session":
            # A sealed file that does not parse is still evidence of a stored session.
            yield cloud_session(src, {}, path)
        else:
            yield src.note("invalid-document")
        return
    if mode == "cloud-session":
        yield cloud_session(src, doc, path)
    else:
        yield from DOCUMENT_ROWS[mode](src, doc, path)


def bot_row(src, bot, layout):
    """The bot record (``BotSchema``): name, agent and model, permission mode, the channels it takes requests from
    and its chat. Members are counted by service; their names and IDs are not exported."""
    slack_apps = [mapping(app) for app in items(bot.get("slackApps")) or [bot.get("slack")] if isinstance(app, dict)]
    linear = [mapping(ws) for ws in items(bot.get("linearWorkspaces")) or [bot.get("linear")] if isinstance(ws, dict)]
    members = [mapping(m) for m in items(bot.get("members"))]
    sources = sorted({text_of(m.get("source")) or "slack" for m in members})
    channels = [name for name, present in (("slack", slack_apps), ("linear", linear),
                                           ("github", isinstance(bot.get("github"), dict))) if present]
    launch = mapping(bot.get("launch"))
    look = mapping(bot.get("lookAround"))
    out = replace(src, session=text_of(bot.get("chatSessionId"))).row(
        "bot", timestamp=bot.get("createdAt"), unit="ms", text=bot.get("name"), model=launch.get("model"),
        bot_id=bot.get("id"), bot_folder=bot.get("folder"), bot_agent=bot.get("agent"),
        permission_mode=bot.get("permissionMode"), paused=flag(bot.get("paused")), member_count=number(len(members)),
        template_id=bot.get("templateId"), google_access=flag(bot.get("google")),
        look_around=flag(look.get("on")) if look else "", record_layout=layout)
    listed(out, "trigger_channels", channels)
    listed(out, "member_sources", sources)
    listed(out, "slack_teams", [app.get("teamId") for app in slack_apps])
    listed(out, "linear_workspaces", [ws.get("workspaceName") or ws.get("workspaceId") for ws in linear])
    return stamped(out, updated_utc=ms(bot.get("updatedAt")))


def profile_bots(src, doc, path):
    """``orca-data.json`` (the legacy root file and a profile's JSON copy): ``bots`` and ``botsNewerAgents``."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    yield from bots_of(src, doc, "orca-data")


def bots_of(src, doc, layout):
    for key in ("bots", "botsNewerAgents"):
        for index, bot in enumerate(items(doc.get(key))):
            if isinstance(bot, dict):
                yield bot_row(replace(src, location={**src.location, "entry_key": key, "entry_index": index}), bot,
                              layout)


def bot_home(src, doc, path):
    """``bot.json``, which Orca regenerates from the bot record: ID, name, agent and members (counted only)."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    members = [mapping(m) for m in items(doc.get("members"))]
    out = src.row("bot", text=doc.get("name"), bot_id=doc.get("id"), bot_folder=path.parent.name,
                  bot_agent=doc.get("agent"), member_count=number(len(members)), record_layout="bot-home")
    yield listed(out, "member_sources", sorted({text_of(m.get("source")) or "slack" for m in members}))


def memory_file(src, path, raw, truncated):
    """``SOUL.md``, ``MEMORY.md`` and ``memory/<topic>.md``: the bot's own instructions and remembered facts. The text
    passes the usual redaction and length limit; at most the first 64 KiB is read."""
    folder = path.parent.parent if path.parent.name.casefold() == "memory" else path.parent
    role = MEMORY_FILES.get(path.name.casefold(), "memory-topic")
    out = src.row("bot-memory-file", text=raw.decode("utf-8", "replace"), bot_folder=folder.name, memory_file=path.name,
                  memory_role=role, file_bytes=number(path.stat().st_size))
    if truncated and "text-length-limit" not in out.details["flags"]:
        out.details["flags"].append("text-length-limit")
    return out


def memory_history(src, doc, path):
    """``bot-memory-history/<bot ID>.json``: one row per change to ``MEMORY.md``, newest first, kept 90 days. ``by``
    names who wrote it: a chat (with the outside speaker in that window, empty for the owner), the owner, the bot's
    own forget command, Orca restoring a dropped line, an undo or the nightly tidy-up."""
    if not isinstance(doc, list):
        yield src.note("invalid-config-shape")
        return
    bot_id = urllib.parse.unquote(path.name[:-len(".json")])
    for index, entry in enumerate(doc):
        entry = mapping(entry)
        by = mapping(entry.get("by"))
        change = mapping(entry.get("change"))
        out = replace(src, location={"source_offset": 0, "entry_index": index},
                      session=text_of(by.get("sessionId"))).row(
            "bot-memory-change", timestamp=entry.get("at"), unit="ms", bot_id=bot_id, change_id=entry.get("id"),
            author_kind=by.get("kind"), speaker=by.get("source"), undo_of=by.get("of"),
            undoable=flag(entry.get("undoable")))
        listed(out, "added_lines", [mapping(line).get("line") for line in items(change.get("added"))])
        yield listed(out, "removed_lines", [mapping(line).get("line") for line in items(change.get("removed"))])


def look_around(src, doc, path):
    """``bot-look-around.json``: each bot's background look-around and tidy-up runs (their agent session, start, end
    and error) and the suggestions they left. Dismissals are not exported."""
    if not isinstance(mapping(doc).get("bots"), dict):
        yield src.note("invalid-config-shape")
        return
    for bot_id, look in doc["bots"].items():
        look = mapping(look)
        runs = [("look-around", run) for run in items(look.get("runs"))]
        runs += [("tidy-up", run) for run in items(mapping(look.get("tidyUp")).get("runs"))]
        for index, (kind, run) in enumerate(runs):
            run = mapping(run)
            out = replace(src, location={"source_offset": 0, "entry_key": bot_id, "entry_index": index},
                          session=text_of(run.get("sessionId"))).row(
                "bot-run", timestamp=run.get("startedAt"), unit="ms", text=run.get("error"), bot_id=bot_id,
                run_kind=kind, asleep=flag(run.get("asleep")), usage_limited=flag("usageLimited" in run))
            yield stamped(out, ended_utc=ms(run.get("endedAt")))
        for index, suggestion in enumerate(items(look.get("suggestions"))):
            suggestion = mapping(suggestion)
            out = replace(src, location={"source_offset": 0, "entry_key": bot_id, "suggestion_index": index},
                          session=text_of(suggestion.get("runSessionId"))).row(
                "bot-suggestion", timestamp=suggestion.get("createdAt"), unit="ms", text=suggestion.get("title"),
                bot_id=bot_id, suggestion_id=suggestion.get("id"), why=suggestion.get("why"),
                ask=suggestion.get("ask"), link=suggestion.get("link"), channel_kind=suggestion.get("source"),
                state=suggestion.get("status"))
            yield stamped(out, resolved_utc=ms(suggestion.get("resolvedAt")))


def profile_index(src, doc, path):
    """``orca-profile-index.json``: local and Orca Cloud-linked profiles. A linked profile names the cloud account
    (user ID, e-mail, display name, organization) and when it was linked; the tokens are elsewhere."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    if type(doc.get("schemaVersion")) is int:
        src.version = str(doc["schemaVersion"])
    active = doc.get("activeProfileId")
    for index, profile in enumerate(items(doc.get("profiles"))):
        profile = mapping(profile)
        cloud = mapping(profile.get("cloud"))
        out = replace(src, location={"source_offset": 0, "entry_index": index}).row(
            "cloud-profile", timestamp=profile.get("createdAt"), unit="ms", text=profile.get("name"),
            profile_id=profile.get("id"), profile_kind=profile.get("kind"),
            active=flag(profile.get("id") == active) if isinstance(active, str) else "",
            cloud_user_id=cloud.get("userId"), cloud_profile_id=cloud.get("cloudProfileId"),
            cloud_email=cloud.get("email"), cloud_display_name=cloud.get("displayName"),
            cloud_org_id=cloud.get("activeOrgId"), cloud_org_name=cloud.get("activeOrgName"))
        yield stamped(out, linked_utc=ms(cloud.get("linkedAt")), last_opened_utc=ms(profile.get("lastOpenedAt")))


def cloud_session(src, doc, path):
    """``profiles/<id>/account-session.json.enc``: the Orca Cloud session, sealed with Electron safeStorage (or
    orcad's host key, or in plain text in development builds). Only the seal format and save time are exported;
    the ciphertext and any plain session are not."""
    doc = mapping(doc)
    out = src.row("secret-file", file_name=path.name, profile_id=path.parent.name,
                  session_format=doc.get("format"))
    return stamped(out, saved_utc=ms(doc.get("savedAt")))


def column_sql(name, kind, present):
    if name not in present:
        return "NULL"
    if kind == "text":
        return f'substr("{name}", 1, {TEXT_LIMIT + 1})'
    if kind == "json":
        return f"""CASE WHEN length(CAST("{name}" AS BLOB)) > {VALUE_BYTES} THEN NULL ELSE "{name}" END"""
    return f'"{name}"'


def store_bytes(path: Path) -> int:
    size = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            size += path.with_name(path.name + suffix).lstat().st_size
        except FileNotFoundError:
            continue
    return size


def store(src, path: Path, mode: str):
    """Read-only from a verified private snapshot (committed WAL content included). Table and column names are fixed;
    the evidence's views, triggers and virtual tables are never run."""
    if store_bytes(path) > DB_BYTES:
        yield src.note("database-size-limit")
        return
    tables_spec = SQLITE_STORES[mode]
    provenance = {}
    with open_sqlite_snapshot(path, provenance=provenance) as db:
        db.execute("PRAGMA trusted_schema=OFF").close()
        snapshot = sqlite_snapshot_reference(provenance)
        with closing(db.execute("PRAGMA main.table_list")) as listing:
            tables = {name for _, name, kind, *_ in listing if kind == "table"}
        if not tables & set(tables_spec):
            yield src.note("orca-tables-missing")
            return
        with closing(db.execute("PRAGMA main.user_version")) as version:
            # bot-items.sqlite and orchestration.db count their migrations here; bot-work.sqlite adds columns instead.
            src.version = str(version.fetchone()[0] or "")
        context = {}
        for table, columns in tables_spec.items():
            if table not in tables:
                continue
            with closing(db.execute(f'PRAGMA main.table_info("{table}")')) as info:
                present = {row[1] for row in info}
            sql = ", ".join(column_sql(name, kind, present) for name, kind in columns)
            # Closing the cursor finalizes its statement even when the consumer stops at a cap.
            where = STORE_FILTERS.get(table, "")
            with closing(db.execute(f'SELECT rowid, {sql} FROM "{table}" {where} ORDER BY rowid')) as rows:
                for rowid, *values in rows:
                    record = dict(zip((name for name, _ in columns), values))
                    source = replace(src, location={"source_table": table, "source_rowid": rowid,
                                                    "snapshot_id": snapshot["snapshot_id"]})
                    yield from STORE_ROWS[table](source, record, context)


def bot_work(src, row, context):
    """``bot_work``: links a conversation on a channel (a Slack thread, a GitHub or Linear issue, a Discord thread)
    to the orchestration task and dispatch that work it. It holds no request text."""
    out = src.row("bot-work", timestamp=row["created_at"], unit="ms", bot_id=row["bot_id"],
                  channel_kind=row["source"], external_id=row["external_id"], generation=number(row["generation"]),
                  task_id=row["task_id"], dispatch_id=row["dispatch_id"], host=row["host"],
                  asked_in_app=flag(bool(row["asked_in_app"])) if row["asked_in_app"] is not None else "",
                  current=flag(bool(row["current"])) if row["current"] is not None else "",
                  close_reason=row["close_reason"])
    yield stamped(out, closed_utc=ms(row["closed_at"]))


def item_link(src, row, context):
    """``item_links``: collected per item before the items are read (``dispatch``, ``pr``, ``url`` and ``file``)."""
    if isinstance(row["item_uid"], str) and row["kind"] in ("dispatch", "pr", "url", "file"):
        links = context.setdefault(row["item_uid"], {})
        links.setdefault(row["kind"], []).append(row["ref"])
    return ()


def bot_item(src, row, context):
    """``items``: the bot's to-do list (``Items`` tab): title, description, what done means, status, where it came
    from, close note and its links: pull requests, URLs, files and the dispatches that worked it."""
    source = mapping(json_cell(row["source"]))
    made_by = mapping(json_cell(row["made_by"]))
    links = context.get(row["uid"], {})
    out = replace(src, session=text_of(row["chat_id"])).row(
        "bot-item", timestamp=row["created_at"], unit="ms", text=row["title"], item_id=row["uid"],
        item_number=number(row["number"]), bot_id=row["owner_bot_id"], description=row["description"],
        done_means=row["done_means"], state=row["status"], close_note=row["close_note"],
        item_source=source.get("kind"), item_source_title=source.get("title"), made_by_bot=made_by.get("botId"))
    for kind, key in (("pr", "pr_links"), ("url", "url_links"), ("file", "file_links"), ("dispatch", "dispatch_ids")):
        listed(out, key, links.get(kind, []))
    yield stamped(out, updated_utc=ms(row["updated_at"]), closed_utc=ms(row["closed_at"]),
                  last_activity_utc=ms(row["last_activity_at"]), snoozed_until_utc=ms(row["snoozed_until"]))


def item_event(src, row, context):
    """``item_events``: made, edited, status, commented, linked, snoozed and unsnoozed, with the actor (a bot's chat,
    the owner or Orca). A comment's text, a status move and its note are exported; other event data by key name."""
    actor = mapping(json_cell(row["actor"]))
    data = mapping(json_cell(row["data"]))
    out = replace(src, session=text_of(actor.get("chatId"))).row(
        "bot-item-event", timestamp=row["created_at"], unit="ms", text=data.get("text") or data.get("note"),
        item_id=row["item_uid"], event_kind=row["kind"], actor_kind=actor.get("kind"), actor_bot=actor.get("botId"),
        actor_reason=actor.get("why"), status_from=data.get("from"), status_to=data.get("to"))
    yield listed(out, "event_keys", list(data))


def bot_request_outcome(src, row, context):
    """``bot_request_outcomes``: collected per message before the requests are read."""
    if isinstance(row["message_id"], str):
        context[row["message_id"]] = row
    return ()


def bot_request(src, row, context):
    """``bot_requests``: a request one bot (or a person through a connector) put to another bot, with purpose
    (status, handoff, question), depth and the original request text, and its outcome when one was recorded."""
    record = mapping(json_cell(row["record"]))
    outcome = mapping(context.get(row["message_id"]))
    out = sqlite_row(src, "bot-request", row["created_at"], text=record.get("request"), message_id=row["message_id"],
                     root_key=row["root_key"], from_bot_id=row["from_bot_id"], from_bot_name=record.get("fromBotName"),
                     to_bot_id=row["to_bot_id"], to_bot_name=record.get("toBotName"), purpose=row["purpose"],
                     depth=number(row["depth"]), outcome=outcome.get("outcome"))
    return [stamped(out, outcome_utc=utc(sqlite_time(outcome.get("recorded_at")), ""))]


def worker_dispatch(src, row, context):
    """``worker_dispatches``: an agent started for a task, with its state, stage, worktree and last error. Orca's
    worktree ID is ``<repo ID>::<worktree path>``."""
    worktree = text_of(row["worktree_id"])
    out = sqlite_row(src, "bot-dispatch", row["created_at"], text=row["last_error"], dispatch_id=row["dispatch_id"],
                     state=row["state"], stage=row["stage"], worktree_id=worktree,
                     worktree_path=worktree.partition("::")[2])
    return [stamped(out, updated_utc=utc(sqlite_time(row["updated_at"]), ""))]


def profile_document(src, row, context):
    """``profile_state_documents``: one JSON document per top-level state key. Only the bot records are read."""
    if row["payload"] is None:
        yield src.note("invalid-or-oversize-orca-value", column="payload")
        return
    doc = json_cell(row["payload"])
    if not isinstance(doc, list):
        yield src.note("invalid-or-oversize-orca-value", column="payload")
        return
    yield from bots_of(src, {row["domain"]: doc}, "profile-state")


SQLITE_STORES = {
    "bot-work": {"bot_work": [(name, "text") for name in ("bot_id", "source", "external_id", "task_id", "dispatch_id",
                                                           "host", "close_reason")]
                 + [(name, "int") for name in ("generation", "asked_in_app", "current", "created_at", "closed_at")]},
    "bot-items": {
        "item_links": [("item_uid", "text"), ("kind", "text"), ("ref", "text")],
        "items": [(name, "text") for name in ("uid", "owner_bot_id", "chat_id", "title", "description", "done_means",
                                              "status", "close_note")]
        + [("source", "json"), ("made_by", "json")]
        + [(name, "int") for name in ("number", "created_at", "updated_at", "closed_at", "last_activity_at",
                                      "snoozed_until")],
        "item_events": [("item_uid", "text"), ("kind", "text"), ("actor", "json"), ("data", "json"),
                        ("created_at", "int")]},
    "orchestration": {
        "bot_request_outcomes": [("message_id", "text"), ("outcome", "text"), ("recorded_at", "text")],
        "bot_requests": [(name, "text") for name in ("message_id", "root_key", "from_bot_id", "to_bot_id", "purpose",
                                                     "created_at")] + [("depth", "int"), ("record", "json")],
        "worker_dispatches": [(name, "text") for name in ("dispatch_id", "state", "stage", "worktree_id", "last_error",
                                                          "created_at", "updated_at")]},
    "profile-db": {"profile_state_documents": [("domain", "text"), ("payload", "json")]},
}
# Profile state holds every top-level key (settings, sessions, SSH relays, ...) as its own document: only the bot
# records are selected.
STORE_FILTERS = {"profile_state_documents": "WHERE domain IN ('bots', 'botsNewerAgents')"}
STORE_ROWS = {"bot_work": bot_work, "item_links": item_link, "items": bot_item, "item_events": item_event,
              "bot_request_outcomes": bot_request_outcome, "bot_requests": bot_request,
              "worker_dispatches": worker_dispatch, "profile_state_documents": profile_document}
DOCUMENT_ROWS = {"bot-home": bot_home, "profile-json": profile_bots, "memory-history": memory_history,
                 "look-around": look_around, "profile-index": profile_index}
