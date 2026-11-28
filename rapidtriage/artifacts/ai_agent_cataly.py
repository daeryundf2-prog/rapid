"""Cataly hub records: the store ``cataly.db``, the event and hub logs, session stderr, the configuration, the OMP
overlay, service definitions and install records (github.com/vntrevx/Cataly). Formats follow Cataly's public
source: ``src/store/migrations/*.sql``, ``src/lanes/record.rs``, ``src/hub/streams.rs``, ``src/log.rs``,
``src/jobs/route.rs``, ``src/omp/launch.rs``, ``src/sys/{paths,service,install}.rs`` and ``docs/config.md``."""
from __future__ import annotations

import json
import plistlib
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from xml.parsers.expat import ExpatError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from ..core.sqlite_snapshot import open_sqlite_snapshot, sqlite_snapshot_reference
from .ai_agent_editor import DB_BYTES, VALUE_BYTES
from .ai_agent_records import TEXT_LIMIT, clean, items, mapping, utc

DOCUMENT_BYTES = 8 << 20
LIST_LIMIT = 64
# Sections of ``config.toml`` (docs/config.md); a ``cataly/config.toml`` with none of them is not Cataly's.
CONFIG_SECTIONS = frozenset({"hub", "omp", "sessions", "lead", "fallback", "discord", "telegram", "slack", "voice",
                             "lanes", "jobs", "destinations", "coord", "workers", "update", "ops"})
RELAYS = ("discord", "telegram", "slack")
# Columns read from each store table: ``int`` as stored, ``text`` cut just past the row text limit (so the row is
# flagged), ``json`` whole up to the per-value cap and empty beyond it. A column an older schema lacks reads NULL.
# Message bodies (``events.body``), the owner's request text (``requests.title``, the first line of the owner's
# message), lane briefs (inside ``lanes.record``), relay intake and delivery text are not read.
TABLES = (
    ("lanes", (("key", "text"), ("state", "text"), ("outcome", "text"), ("thread", "text"), ("opened_ms", "int"),
               ("closed_ms", "int"), ("revision", "int"), ("record", "json"))),
    ("lane_history", (("key", "text"), ("seq", "int"), ("at_ms", "int"), ("state", "text"), ("note", "text"))),
    ("requests", (("id", "int"), ("source", "text"), ("thread", "text"), ("created_ms", "int"), ("updated_ms", "int"),
                  ("closed_ms", "int"))),
    ("questions", (("id", "text"), ("text", "text"), ("source", "text"), ("thread", "text"), ("options", "json"),
                   ("recommended", "int"), ("request", "int"), ("state", "text"), ("outcome", "text"),
                   ("created_ms", "int"), ("settled_ms", "int"))),
    ("stream_jobs", (("name", "text"), ("spec", "json"), ("created_ms", "int"))),
    ("sessions", (("handle", "text"), ("role", "text"), ("runtime", "text"), ("cwd", "text"), ("name", "text"),
                  ("model", "text"), ("state", "text"), ("session_id", "text"), ("session_file", "text"),
                  ("pid", "int"), ("started_ms", "int"), ("stop_how", "text"), ("stop_ms", "int"))),
    ("events", (("id", "int"), ("at_ms", "int"), ("job", "text"), ("subject", "text"), ("kind", "text"),
                ("severity", "text"), ("text", "text"), ("lane", "text"), ("thread", "text"), ("urgent", "int"),
                ("dry", "int"))),
)


def identify_cataly(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """``<state>/cataly`` and ``<config>/cataly`` under any XDG base (several hubs can share one account, such as
    ``.local/state/<name>/cataly``), the install folder ``<data>/cataly`` and the user service definitions."""
    name = parts[-1]
    if parts[-2:-1] == ("launchagents",) and name.startswith("dev.cataly.") and name.endswith(".plist"):
        return "cataly-hub", "service"
    if parts[-3:-1] == ("systemd", "user") and name.startswith("cataly") and name.endswith(".service"):
        return "cataly-hub", "service"
    for index, part in enumerate(parts[:-1]):
        if part != "cataly":
            continue
        tail = parts[index + 1:]
        mode = None
        if tail == ("cataly.db",) or (len(tail) == 2 and tail[0] == "backup" and name.startswith("cataly-v")
                                       and name.endswith(".db")):
            mode = "store"
        elif tail in (("logs", "events.jsonl"), ("logs", "events.jsonl.1")):
            mode = "events"
        elif tail in (("logs", "hub.log"), ("logs", "hub.log.1")):
            mode = "hub-log"
        elif name.endswith(".err") and (len(tail) == 2 or tail[1:2] == ("sessions",) and len(tail) == 3) \
                and tail[0] == "logs":
            mode = "stderr"
        elif tail in (("omp-overlay.yml",), ("omp-overlay-lane.yml",)):
            mode = "overlay"
        elif tail == ("config.toml",):
            mode = "hub-config"
        elif len(tail) == 2 and tail[0] == "secrets":
            mode = "secret"
        elif len(tail) == 2 and tail[0] == "records" and name.endswith(".json"):
            mode = "install-record"
        elif len(tail) == 3 and tail[0] == "versions" and name in ("cataly", "cataly.ts"):
            mode = "install-file"
        if mode:
            return "cataly-hub", mode
    return None


def ms(value):
    return utc(value, "ms") if type(value) is int else None


def number(value) -> str:
    if type(value) is float and value.is_integer():
        # Cataly writes counts as JSON floats (``spend`` is ``(f64, f64)``): ``12000.0`` reads as ``12000``.
        value = int(value)
    return str(value) if type(value) in (int, float) and not isinstance(value, bool) else ""


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


def executable(argv) -> str:
    """The program only, as ``agent-mcp`` does: arguments can hold unlabelled credentials (bot tokens in URLs,
    positional keys)."""
    values = items(argv)
    return values[0] if values and isinstance(values[0], str) else ""


def cataly(src, path: Path, mode: str, line_records):
    if mode == "store":
        yield from store(src, path)
    elif mode in ("events", "hub-log", "stderr"):
        yield from log_lines(src, path, mode, line_records)
    elif mode in ("secret", "install-file"):
        # Presence only: token files and program files are never opened.
        if mode == "secret":
            yield src.row("secret-file", file_name=path.name)
        else:
            yield src.row("install", file_name=path.name, install_version=path.parent.name)
    else:
        src.location = {"source_offset": 0}
        with path.open("rb") as stream:
            raw = stream.read(DOCUMENT_BYTES + 1)
        if len(raw) > DOCUMENT_BYTES:
            yield src.note("document-size-limit")
            return
        try:
            if mode == "service" and path.suffix.lower() == ".plist":
                doc = plistlib.loads(raw)
            elif mode == "service":
                doc = raw.decode("utf-8")
            elif mode == "hub-config":
                doc = tomllib.loads(raw.decode("utf-8-sig"))
            else:
                doc = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, LookupError, RecursionError, ExpatError):
            # plistlib raises LookupError for an unknown XML encoding and IndexError for an unbalanced key.
            yield src.note("invalid-document")
            return
        yield from {"service": service, "hub-config": hub_config, "overlay": overlay,
                    "install-record": install_record}[mode](src, doc)


def hub_config(src, doc):
    """Model names, owner IDs, token and key file paths and job definitions. The relay owner IDs are personal
    identifiers, exported on purpose: they name the account that controls the hub. Token values live in separate
    files that are never read; ``[sessions] credentials`` and ``service.env`` hold environment variable names,
    exported as names. A job's ``argv`` gives its program only."""
    if not isinstance(doc, dict) or not CONFIG_SECTIONS & set(doc):
        yield src.note("unrecognized-hub-config")
        return
    relays = {name: mapping(doc.get(name)) for name in RELAYS}
    chains = mapping(mapping(doc.get("fallback")).get("chains"))
    row = src.row(
        "settings", model=mapping(doc.get("lead")).get("model", ""), lanes_model=mapping(doc.get("lanes")).get("model"),
        fallback_chains="; ".join(f"{k}={', '.join(v for v in items(c) if isinstance(v, str))}" for k, c in chains.items()),
        log_level=mapping(doc.get("hub")).get("log_level"), omp_path=mapping(doc.get("omp")).get("path"),
        **{f"{name}_owner": number(relay.get("owner")) or relay.get("owner") for name, relay in relays.items()},
    )
    listed(row, "env_names", mapping(doc.get("sessions")).get("credentials"))
    voice = mapping(doc.get("voice"))
    yield listed(row, "token_files", [relay.get("token_file") for relay in relays.values()] + [voice.get("key_file")])
    for name, job in mapping(doc.get("jobs")).items():
        if not isinstance(job, dict):
            yield src.note("invalid-job-config", job_name=name)
            continue
        row = src.row("hub-job", job_name=name, job_kind=job.get("kind"), every=job.get("every"),
                      command_line=executable(job.get("argv")), cwd_configured=job.get("cwd"))
        yield listed(row, "destinations", job.get("destinations"))


def overlay(src, doc):
    """``omp-overlay.yml`` / ``omp-overlay-lane.yml``: JSON settings the hub passes to OMP with ``--config``."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    retry = mapping(doc.get("retry"))
    chains = mapping(retry.get("fallbackChains"))
    goal = mapping(doc.get("goal")).get("enabled")
    yield src.row(
        "settings", fallback_on=retry.get("fallbackOn"), goal_enabled=str(goal).lower() if isinstance(goal, bool) else "",
        fallback_chains="; ".join(f"{k}={', '.join(v for v in items(c) if isinstance(v, str))}" for k, c in chains.items()),
        eval_approval=mapping(mapping(doc.get("tools")).get("approval")).get("eval"))


def install_record(src, doc):
    """``<data>/cataly/records/<version>.json``: one installed version with its file hashes."""
    doc = mapping(doc)
    if not isinstance(doc.get("version"), str):
        yield src.note("unrecognized-install-record")
        return
    src.app_version = doc["version"]
    yield src.row("install", timestamp=doc.get("installed_ms"), unit="ms", install_version=doc["version"],
                  commit=doc.get("commit"), target=doc.get("target"), binary_sha256=doc.get("binary_sha256"),
                  extension_sha256=doc.get("extension_sha256"), install_source=doc.get("source"),
                  install_role=doc.get("role"))


def service(src, doc):
    """A launchd agent (``ProgramArguments``) or a systemd user unit (``ExecStart``): the program only, as for hub
    jobs. Cataly's launchd agent runs ``/bin/sh -c <script> <env file> <program>`` (``src/sys/service.rs``), so the
    program is its fifth argument and the environment file, the agent's only link to its hub's config folder, is
    exported as ``environment_file``. Environment values are not exported; the environment file holding provider
    keys is named, not read."""
    if isinstance(doc, dict):
        argv = items(doc.get("ProgramArguments"))
        shell = argv[0].rsplit("/", 1)[-1] if argv and isinstance(argv[0], str) else ""
        wrapped = len(argv) >= 5 and shell in ("sh", "bash", "zsh", "dash") and argv[1] == "-c"
        yield listed(src.row("service", service_label=doc.get("Label"),
                             command_line=argv[4] if wrapped else executable(argv),
                             environment_file=argv[3] if wrapped else "",
                             run_at_load=str(doc.get("RunAtLoad", "")).lower()),
                     "env_names", list(mapping(doc.get("EnvironmentVariables"))))
        return
    if not isinstance(doc, str) or "[Service]" not in doc:
        yield src.note("unrecognized-service-definition")
        return
    fields = {}
    env = []
    for line in doc.splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep:
            continue
        if key == "Environment":
            env.append(value.strip('"').partition("=")[0])
        elif key in ("Description", "ExecStart", "EnvironmentFile"):
            fields.setdefault(key, value)
    yield listed(src.row("service", service_label=fields.get("Description"),
                         command_line=executable(fields.get("ExecStart", "").split()),
                         environment_file=fields.get("EnvironmentFile", "").lstrip("-")), "env_names", env)


def log_lines(src, path, mode, line_records):
    """``events.jsonl`` mirrors store events (``src/jobs/route.rs``); ``hub.log`` holds ``{"t", "level", "msg",
    ...}`` with masked key-values, of which only time, level and message are exported (``src/log.rs``);
    ``*.err`` is an OMP session's or probe's stderr, one row per line without a time."""
    for location, doc, reason in line_records(path, text=mode == "stderr"):
        src.location = location
        if reason:
            yield src.note(reason, **({"damaged_count": 1} if reason != "stream-byte-limit" else {}))
        elif mode == "stderr":
            if doc.strip():
                yield src.row("log", text=doc, level="stderr")
        elif not isinstance(doc, dict):
            yield src.note("invalid-record-shape", damaged_count=1)
        elif mode == "events":
            yield from event(src, doc)
        elif not isinstance(doc.get("msg"), str):
            yield src.note("unrecognized-log-record", damaged_count=1)
        else:
            yield src.row("log", timestamp=doc.get("t"), text=doc["msg"], level=doc.get("level"))


def event(src, doc):
    if type(doc.get("at_ms")) is not int or not isinstance(doc.get("kind"), str):
        yield src.note("unrecognized-event-record", damaged_count=1)
        return
    yield src.row("hub-event", timestamp=doc["at_ms"], unit="ms", text=doc.get("text"), event_id=number(doc.get("id")),
                  job=doc.get("job"), subject=doc.get("subject"), event_kind=doc["kind"], severity=doc.get("severity"),
                  lane_key=doc.get("lane"), thread=doc.get("thread"), urgent=str(doc.get("urgent", "")).lower(),
                  dry=str(doc.get("dry", "")).lower())


def column_sql(name, kind, present):
    if name not in present:
        return "NULL"
    if kind == "text":
        return f'substr("{name}", 1, {TEXT_LIMIT + 1})'
    if kind == "json":
        return f"""CASE WHEN length(CAST("{name}" AS BLOB)) > {VALUE_BYTES} THEN '' ELSE "{name}" END"""
    return f'"{name}"'


def store_bytes(path: Path) -> int:
    size = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            size += path.with_name(path.name + suffix).lstat().st_size
        except FileNotFoundError:
            continue
    return size


def store(src, path: Path):
    """Read-only from a verified private snapshot (committed WAL content included). Table and column names are fixed;
    the evidence's views, triggers and virtual tables are never run."""
    if store_bytes(path) > DB_BYTES:
        yield src.note("database-size-limit")
        return
    provenance = {}
    with open_sqlite_snapshot(path, provenance=provenance) as db:
        db.execute("PRAGMA trusted_schema=OFF").close()
        snapshot = sqlite_snapshot_reference(provenance)
        with closing(db.execute("PRAGMA main.table_list")) as listing:
            tables = {name for _, name, kind, *_ in listing if kind == "table"}
        if not tables & {name for name, _ in TABLES}:
            yield src.note("hub-tables-missing")
            return
        with closing(db.execute("PRAGMA main.user_version")) as version:
            # Each migration ``NNNN_*.sql`` sets the store's schema version (``src/store/schema.rs``).
            src.version = str(version.fetchone()[0] or "")
        for table, columns in TABLES:
            if table not in tables:
                continue
            with closing(db.execute(f'PRAGMA main.table_info("{table}")')) as info:
                present = {row[1] for row in info}
            sql = ", ".join(column_sql(name, kind, present) for name, kind in columns)
            # Closing the cursor finalizes its statement even when the consumer stops at a cap.
            with closing(db.execute(f'SELECT rowid, {sql} FROM "{table}" ORDER BY rowid')) as rows:
                for rowid, *values in rows:
                    record = dict(zip((name for name, _ in columns), values))
                    source = replace(src, location={"source_table": table, "source_rowid": rowid,
                                                    "snapshot_id": snapshot["snapshot_id"]})
                    yield from STORE_ROWS[table](source, record)


def json_value(src, raw, column):
    if raw is None:
        return None, None
    try:
        return json.loads(raw), None
    except (ValueError, TypeError, RecursionError):
        return None, src.note("invalid-or-oversize-hub-value", column=column)


def lane(src, row):
    """``lanes``: the columns listings filter on, plus selected fields of the ``record`` JSON (``src/lanes/record.rs``).
    The brief, checks, shell rules and grants are not exported. ``spend`` is the run's final reading of tokens and
    cost in USD, which Cataly itself labels an estimate."""
    record, note = json_value(src, row["record"], "record")
    if note:
        yield note
    record = mapping(record)
    spend = items(record.get("spend"))
    src = replace(src, session=record.get("session_id") or "", cwd=record.get("cwd") or "")
    out = src.row("lane", timestamp=row["opened_ms"], unit="ms", text=record.get("title"), model=record.get("model"),
                  lane_key=row["key"], state=row["state"], outcome=row["outcome"], thread=row["thread"],
                  origin=record.get("origin"), revision=number(row["revision"]), session_file=record.get("session_file"),
                  run_id=record.get("run_id"), worker=record.get("worker"),
                  spend_tokens=number(spend[0]) if len(spend) == 2 else "",
                  spend_usd_estimate=number(spend[1]) if len(spend) == 2 else "")
    yield stamped(listed(out, "worktrees", record.get("worktrees")), closed_utc=ms(row["closed_ms"]))


def lane_history(src, row):
    yield src.row("lane-history", timestamp=row["at_ms"], unit="ms", text=row["note"], lane_key=row["key"],
                  seq=number(row["seq"]), state=row["state"])


def request(src, row):
    """``requests``: one owner request, opened on admission; ``source`` is the originating message reference. The
    title is the first line of the owner's message (``src/store/lead.rs``) and the next step and result are free text,
    so none is read: only the ID, message references, times and whether the request is still open."""
    out = src.row("request", timestamp=row["created_ms"], unit="ms", request_id=number(row["id"]),
                  source_message=row["source"], thread=row["thread"],
                  state="closed" if row["closed_ms"] is not None else "open")
    yield stamped(out, updated_utc=ms(row["updated_ms"]), closed_utc=ms(row["closed_ms"]))


def question(src, row):
    """``questions``: a question the lead put to the owner; ``outcome`` is the answer or choice when settled."""
    options, note = json_value(src, row["options"], "options")
    if note:
        yield note
    out = src.row("question", timestamp=row["created_ms"], unit="ms", text=row["text"], question_id=row["id"],
                  source_message=row["source"], thread=row["thread"], recommended=number(row["recommended"]),
                  request_id=number(row["request"]), state=row["state"], answer=row["outcome"])
    yield stamped(listed(out, "options", options), settled_utc=ms(row["settled_ms"]))


def stream_job(src, row):
    """``stream_jobs``: the lead's long-running watch commands (``src/hub/streams.rs`` ``Spec``)."""
    spec, note = json_value(src, row["spec"], "spec")
    if note:
        yield note
    spec = mapping(spec)
    yield src.row("stream-job", timestamp=row["created_ms"], unit="ms", job_name=row["name"],
                  command_line=executable(spec.get("argv")), filter=spec.get("filter"),
                  restarts=number(spec.get("restarts")))


def hosted_session(src, row):
    """``sessions``: one OMP session the hub started; ``session_file`` is the OMP transcript it wrote."""
    src = replace(src, session=row["session_id"] or "", cwd=row["cwd"] or "")
    out = src.row("hosted-session", timestamp=row["started_ms"], unit="ms", model=row["model"], handle=row["handle"],
                  session_role=row["role"], runtime=row["runtime"], session_name=row["name"], state=row["state"],
                  session_file=row["session_file"], pid=number(row["pid"]), stop_how=row["stop_how"])
    yield stamped(out, stopped_utc=ms(row["stop_ms"]))


def store_event(src, row):
    yield from event(src, {**row, "urgent": bool(row["urgent"]) if row["urgent"] is not None else "",
                           "dry": bool(row["dry"]) if row["dry"] is not None else ""})


STORE_ROWS = {"lanes": lane, "lane_history": lane_history, "requests": request, "questions": question,
              "stream_jobs": stream_job, "sessions": hosted_session, "events": store_event}
