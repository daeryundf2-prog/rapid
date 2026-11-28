"""dori records (github.com/sisyphuslabs/dori-superagent): the harness store in ``$DORI_HOME`` (default ``~/.dori``)
and the dori-mode skill state in ``stateDir`` (default ``~/.dori/state``). Formats follow dori's public source at
commit ``8beff59``: ``src/store.ts``, ``src/store-types.ts``, ``src/store-journal.ts``, ``src/inbox-files.ts``,
``src/gate.ts``, ``src/telemetry.ts`` and, under ``skills/dori-mode/scripts/src``, ``registry.ts``, ``reports.ts``,
``checkpoints.ts``, ``supervision.ts``, ``worklog.ts``, ``lessons.ts``, ``config.ts``, ``cli-messenger.ts`` and
``messenger/thread-ledger.ts``. dori keeps no log of messenger traffic: inbound messages are printed for the lead
and sends print an ID, so the Slack thread ledger and the Telegram offset are what remains on disk.

Message text (queued messages, reports, worklog entries, lane notes) is exported on purpose, as the conversation text
of the session collectors is: it is the evidence and it is personal data. Every text field passes ``clean()`` and the
row text limit. Owner IDs and references to the owner's private chat (``PRIVATE_ROOM``) are not exported: such a lane
``thread``, request ``source``, evidence entry or Slack DM channel is left empty. Argument vectors are not exported:
``agentCommand`` and launchd ``ProgramArguments`` give the program only."""
from __future__ import annotations

import datetime as dt
import json
import plistlib
import re
from dataclasses import replace
from pathlib import Path
from xml.parsers.expat import ExpatError

from .ai_agent_records import PRIVATE_ROOM, clean, items, mapping, reference, utc

KIND = "dori-state"
DOCUMENT_BYTES = 8 << 20
BRIEF_BYTES = 64 << 10
OFFSET_BYTES = 64
LIST_LIMIT = 64
# A user LaunchAgent whose label has a ``dori`` component (``com.<user>.dori-backup.plist``). dori installs none;
# these come from the operator's own tooling, as do the plists parked in ``~/.dori/disabled-launchd``.
LAUNCHD_NAME = re.compile(r"(?:^|\.)dori[-.]")
HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t#]*$", re.MULTILINE)
# ``gate.ts``: ``<pr with "/"->"__" and "#"->"_">@<sha>-<uuid>.noverdict.txt``, the reviewer's output tail.
NO_VERDICT = re.compile(r"^(?P<pr>.+)@(?P<sha>[0-9a-f]{7,64})-[0-9a-f-]{36}\.noverdict\.txt$")
# ``migrate-capture.ts``: ``<name>.handoff.md`` and ``<name>.migrate-<epoch ms>.md``.
MIGRATE_BRIEF = re.compile(r"^(?P<key>.+)\.migrate-(?P<at>\d{1,15})\.md$")
# Skill-state files directly in ``stateDir`` and in ``stateDir/lanes/<key>/``.
STATE_FILES = {"worklog.jsonl": "worklog", "lessons.jsonl": "lessons", "slack-threads.json": "slack-threads",
               "telegram-offset": "telegram-offset"}
LANE_FILES = {"reports.jsonl": "reports", "checkpoints.jsonl": "checkpoints", "cost.jsonl": "usage"}
JSON_LINES = {"reports", "checkpoints", "usage", "worklog", "lessons", "inbox"}


def identify_dori(parts: tuple[str, ...]) -> tuple[str, str] | None:
    """Files below a ``.dori`` folder at any depth (the harness root and its ``state`` folder) and user LaunchAgents
    named for dori. A ``$DORI_HOME`` or ``stateDir`` moved elsewhere is not searched."""
    name = parts[-1]
    if parts[-2:-1] == ("launchagents",) and name.endswith(".plist") and LAUNCHD_NAME.search(name):
        return KIND, "service"
    for index, part in enumerate(parts[:-1]):
        if part != ".dori":
            continue
        mode = dori_mode(parts[index + 1:])
        if mode:
            return KIND, mode
    return None


def dori_mode(tail: tuple[str, ...]) -> str | None:
    name = tail[-1]
    if tail[0] == "state" and len(tail) > 1:
        # The skill's ``stateDir``: the same lane folder layout as the harness, told apart by content.
        tail = tail[1:]
        if len(tail) == 1 and name in STATE_FILES:
            return STATE_FILES[name]
        if len(tail) == 3 and tail[0] == "lanes" and name in LANE_FILES:
            return LANE_FILES[name]
        return "lane" if len(tail) == 2 and tail[0] == "lanes" and name.endswith(".json") else None
    if len(tail) == 2 and tail[0] == "lanes" and name.endswith(".json"):
        return "lane"
    if len(tail) == 2 and tail[0] == "briefs" and name.endswith(".md"):
        return "brief"
    if len(tail) == 2 and tail[0] == "receipts" and (name.endswith(".json") or NO_VERDICT.match(name)):
        return "receipt"
    if len(tail) == 2 and tail[0] == "inbox" and name.endswith(".jsonl"):
        return "inbox"
    if len(tail) == 2 and tail[0] == "backlog" and name.endswith(".json"):
        return "backlog"
    if tail == ("loop", "last-run.json") or (len(tail) == 3 and tail[:2] == ("loop", "runs") and name.endswith(".json")):
        return "loop-run"
    if tail in (("loop", "stop"), ("duty", "stop")):
        return "pause"
    if len(tail) == 2 and tail[0] == "migrate" and name.endswith(".json"):
        return "migration"
    if len(tail) == 1 and name in ("roles.json", "telemetry.json"):
        return name.partition(".")[0]
    if len(tail) == 1 and (name == "secrets.env" or name.startswith("secrets.env.bak")):
        # ``secrets.env`` and the operator's ``secrets.env.bak-*`` copies: presence only.
        return "secrets"
    if len(tail) == 1 and (name == "config.json" or name.startswith("config.json.bak")):
        return "dori-config"
    if len(tail) == 2 and tail[0] == "disabled-launchd" and name.endswith(".plist"):
        return "service"
    return None


def ms(value):
    return utc(value, "ms") if type(value) is int else None


def iso(value):
    return utc(value, "") if isinstance(value, str) else None


def number(value) -> str:
    return str(value) if type(value) in (int, float) else ""


def flag(value) -> str:
    return str(value).lower() if isinstance(value, bool) else ""


def listed(row, key, values):
    """A list field: string entries only, each redacted, at most ``LIST_LIMIT``."""
    values = items(values)
    row.details[key] = [clean(v) for v in values[:LIST_LIMIT] if isinstance(v, str)]
    if len(values) > LIST_LIMIT:
        row.details["flags"].append("list-length-limit")
    return row


def public(values) -> list:
    """List entries other than references to a private chat."""
    return [value for value in items(values) if reference(value)]


def stamped(row, **times):
    """Extra event times as ISO UTC; an absent time leaves no field."""
    for key, value in times.items():
        if value:
            row.details[key] = value
    return row


def ref_text(ref, pane=None) -> str:
    """``refs.ts``: a herdr ref is the bare pane ID (``w1:p3``), any other runtime is prefixed (``hc:t7``). A record
    written before runtimes existed names only its herdr pane."""
    ref = mapping(ref)
    if isinstance(ref.get("id"), str):
        return ref["id"] if ref.get("runtime") in (None, "herdr") else f"{ref['runtime']}:{ref['id']}"
    return pane if isinstance(pane, str) else ""


def slack_time(value):
    """A Slack message ``ts`` (``"1712345678.000100"``: epoch seconds and microseconds) as ISO UTC, exactly."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,11}\.\d{6}", value):
        return None
    seconds, micros = value.split(".")
    instant = dt.datetime.fromtimestamp(int(seconds), dt.timezone.utc).replace(microsecond=int(micros))
    return instant.isoformat()


def executable(argv) -> str:
    """The program only, as ``agent-mcp`` does: arguments can hold unlabelled credentials (bot tokens in URLs,
    positional keys, owner IDs)."""
    values = items(argv)
    return values[0] if values and isinstance(values[0], str) else ""


def dori(src, path: Path, mode: str, line_records):
    if mode in JSON_LINES:
        reader = LINE_ROWS[mode]
        for location, doc, reason in line_records(path):
            src.location = location
            if reason:
                yield src.note(reason, **({"damaged_count": 1} if reason != "stream-byte-limit" else {}))
            elif not isinstance(doc, dict):
                yield src.note("invalid-record-shape", damaged_count=1)
            else:
                yield from reader(src, doc, path)
        return
    src.location = {"source_offset": 0}
    if mode == "secrets":
        # Presence only: never opened.
        yield src.row("secret-file", file_name=path.name)
        return
    if mode == "receipt" and path.suffix.lower() == ".txt":
        # The reviewer's output tail when it printed no verdict: named, not read.
        match = NO_VERDICT.match(path.name)
        yield src.row("review-receipt", file_name=path.name, pr_file_key=match["pr"] if match else "",
                      sha=match["sha"] if match else "", verdict="")
        return
    limit = BRIEF_BYTES if mode == "brief" else OFFSET_BYTES if mode == "telegram-offset" else DOCUMENT_BYTES
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if mode == "brief":
        yield brief(src, path, raw[:limit])
        return
    if len(raw) > limit:
        yield src.note("document-size-limit")
        return
    try:
        if mode == "service":
            doc = plistlib.loads(raw)
        elif mode == "telegram-offset":
            doc = raw.decode("ascii").strip()
        else:
            doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, LookupError, RecursionError, ExpatError):
        # plistlib raises LookupError for an unknown XML encoding and IndexError for an unbalanced key.
        yield src.note("invalid-document")
        return
    yield from DOCUMENT_ROWS[mode](src, doc, path)


def lane(src, doc, path):
    """``lanes/<key>.json`` from either writer: the skill registry records ``openedAt`` as ISO text and a ``title``;
    the harness records ``createdAt`` in epoch ms with its own event ``log``."""
    if not isinstance(doc, dict) or not isinstance(doc.get("key"), str):
        yield src.note("unrecognized-lane-record")
    elif isinstance(doc.get("openedAt"), str):
        yield from skill_lane(src, doc)
    elif type(doc.get("createdAt")) is int:
        yield from harness_lane(src, doc)
    else:
        yield src.note("unrecognized-lane-record")


def skill_lane(src, doc):
    """``registry.ts`` ``Lane``. The brief text, the done signal and the posted report lines are not exported; the
    brief file is named by ``brief_path``. ``session`` is the omo session the lane's transcript belongs to."""
    src = replace(src, session=doc.get("session") or "", cwd=doc.get("cwd") or "")
    key = doc["key"]
    claim = mapping(doc.get("claim"))
    objection = mapping(doc.get("objection"))
    out = src.row("lane", timestamp=doc["openedAt"], text=doc.get("title"), model=doc.get("model"), lane_key=key,
                  state="closed" if doc.get("closedAt") else doc.get("status") or "working",
                  thread=reference(doc.get("thread")), session_ref=ref_text(doc.get("sessionRef"), doc.get("pane")),
                  session_via=doc.get("sessionVia"), brief_path=doc.get("brief"), paused_from=doc.get("pausedFrom"),
                  claim_evidence=reference(claim.get("evidence")), receipt_note=mapping(doc.get("receipt")).get("note"),
                  record_layout="dori-mode")
    listed(out, "worktrees", doc.get("worktrees"))
    listed(out, "objection_reasons", objection.get("reasons"))
    yield stamped(out, closed_utc=iso(doc.get("closedAt")), claimed_utc=iso(claim.get("at")),
                  objected_utc=iso(objection.get("at")))
    for index, entry in enumerate(items(doc.get("history"))):
        entry = mapping(entry)
        yield replace(src, location={"source_offset": 0, "history_index": index}).row(
            "lane-history", timestamp=entry.get("at"), text=entry.get("note"), lane_key=key, state=entry.get("status"))


def harness_lane(src, doc):
    """``store-types.ts`` ``Lane``. There is no title, model or thread; ``final`` is the lane's closing answer and
    ``log`` its start, report, ready, nudge, done and lost events. Closing appends a ``done`` event."""
    src = replace(src, cwd=doc.get("cwd") or "")
    key = doc["key"]
    log = [mapping(entry) for entry in items(doc.get("log"))]
    final = mapping(doc.get("final"))
    done = [entry.get("at") for entry in log if entry.get("kind") == "done"]
    out = src.row("lane", timestamp=doc["createdAt"], unit="ms", lane_key=key, state=doc.get("status"),
                  session_ref=ref_text(doc.get("sessionRef"), doc.get("paneId")), session_file=doc.get("sessionPath"),
                  brief_path=doc.get("brief"), result=final.get("text"), nudges=number(doc.get("nudges")),
                  record_layout="dori-harness")
    listed(out, "evidence", public(final.get("evidence")))
    yield stamped(out, closed_utc=ms(done[-1] if done else final.get("at")),
                  last_activity_utc=ms(doc.get("lastActivityAt")))
    for index, entry in enumerate(log):
        yield replace(src, location={"source_offset": 0, "history_index": index}).row(
            "lane-history", timestamp=entry.get("at"), unit="ms", text=entry.get("text"), lane_key=key,
            state=entry.get("kind"))


def lane_key(doc, path):
    return doc.get("key") if isinstance(doc.get("key"), str) else path.parent.name


def report(src, doc, path):
    """``reports.ts``: a lane's own report (``milestone``, ``blocker``, ``question``, ``halted``, ``done``) or an
    activity mark (``running``, ``stalled``)."""
    kind = doc.get("kind") if doc.get("type") == "report" else doc.get("state") if doc.get("type") == "activity" else None
    if not isinstance(kind, str):
        yield src.note("unrecognized-report-record", damaged_count=1)
        return
    yield src.row("lane-report", timestamp=doc.get("at"), text=doc.get("text"), lane_key=lane_key(doc, path),
                  record_type=doc["type"], report_kind=kind)


def checkpoint(src, doc, path):
    """``checkpoints.ts``: one finished step with its result, evidence and the remote effects it caused."""
    if not isinstance(doc.get("step"), str):
        yield src.note("unrecognized-checkpoint-record", damaged_count=1)
        return
    out = src.row("lane-checkpoint", timestamp=doc.get("at"), text=doc.get("result"), lane_key=lane_key(doc, path),
                  step=doc["step"])
    listed(out, "evidence", public(doc.get("evidence")))
    yield listed(out, "remote_effects", public(doc.get("remoteEffects")))


def usage(src, doc, path):
    """``supervision.ts`` ``UsageSnapshot``: tokens and cost the configured usage command reported for the lane."""
    yield src.row("lane-usage", timestamp=doc.get("at"), lane_key=lane_key(doc, path), tokens=number(doc.get("tokens")),
                  cost_usd=number(doc.get("costUsd")), final=flag(doc.get("final")))


def worklog(src, doc, path):
    """``worklog.ts`` events: ``add`` (title and the owner request it came from), ``next``, ``note`` and ``close``."""
    op = doc.get("op")
    if op not in ("add", "next", "note", "close"):
        yield src.note("unrecognized-worklog-record", damaged_count=1)
        return
    yield src.row("worklog", timestamp=doc.get("at"), text=doc.get({"add": "title", "close": "result"}.get(op, "text")),
                  item_id=doc.get("id"), worklog_op=op, source_message=reference(doc.get("source")))


def lesson(src, doc, path):
    """``lessons.ts``: append-only, the newest record of an ID wins (only ``outcome`` changes between records)."""
    if not isinstance(doc.get("rule"), str):
        yield src.note("unrecognized-lesson-record", damaged_count=1)
        return
    src = replace(src, cwd=doc.get("cwd") or "")
    out = src.row("lesson", timestamp=doc.get("at"), text=doc["rule"], lesson_id=doc.get("id"), lane_key=doc.get("lane"),
                  scope=doc.get("scope"), outcome=doc.get("outcome"))
    yield listed(out, "evidence", public([doc.get("evidence")]))


def queued(src, doc, path):
    """``inbox/<session>.jsonl``: messages dori queued for a lead, duty or lane session and typed into its pane.
    The file name is the session (``w1_p3`` is herdr pane ``w1:p3``, ``hc--t7`` is ``hc:t7``); ``from`` names the
    sender (``cli``, ``duty`` or a lane key). An ``ambiguous`` attempt is a held message."""
    stem = path.name[:-len(".jsonl")]
    attempt = mapping(doc.get("attempt"))
    out = src.row("queued-message", timestamp=doc.get("at"), unit="ms", text=doc.get("text"), sender=doc.get("from"),
                  target_ref=f"hc:{stem[4:]}" if stem.startswith("hc--") else stem.replace("_", ":"),
                  delivery_state=attempt.get("state"), delivery_detail=attempt.get("detail"),
                  delivery_agent=attempt.get("agent"))
    yield stamped(out, delivery_utc=ms(attempt.get("at")))


def receipt(src, doc, path):
    """``receipts/<pr>@<sha>.json``: the pre-merge review verdict and the reviewer's output tail."""
    doc = mapping(doc)
    if doc.get("verdict") not in ("CLEAR", "BLOCK"):
        yield src.note("unrecognized-review-receipt")
        return
    yield src.row("review-receipt", timestamp=doc.get("at"), unit="ms", text=doc.get("summary"), model=doc.get("model"),
                  pr=doc.get("pr"), sha=doc.get("sha"), verdict=doc["verdict"])


def backlog(src, doc, path):
    """``backlog/<id>.json``: a queued task the hourly loop starts as a lane. The brief copy beside it is not read."""
    doc = mapping(doc)
    if not isinstance(doc.get("id"), str) or not isinstance(doc.get("title"), str):
        yield src.note("unrecognized-backlog-item")
        return
    ends = [mapping(e).get("at") for e in items(doc.get("log")) if mapping(e).get("kind") in ("done", "drop")]
    src = replace(src, cwd=doc.get("cwd") or "")
    out = src.row("backlog-item", timestamp=doc.get("createdAt"), unit="ms", text=doc["title"], item_id=doc["id"],
                  state=doc.get("status"), priority=number(doc.get("priority")), source_message=reference(doc.get("source")),
                  decision=doc.get("decision"), attempts=number(doc.get("attempts")), brief_path=doc.get("brief"))
    closed = doc.get("status") in ("done", "dropped") and ends
    yield stamped(out, updated_utc=ms(doc.get("updatedAt")), asked_utc=ms(doc.get("askedAt")),
                  closed_utc=ms(ends[-1]) if closed else None)


def loop_run(src, doc, path):
    """``loop/runs/<time>.json`` and ``loop/last-run.json``: one hourly-loop pass (``LoopRun``)."""
    doc = mapping(doc)
    if type(doc.get("at")) is not int:
        yield src.note("unrecognized-loop-run")
        return
    status = mapping(doc.get("status"))
    out = src.row("loop-run", timestamp=doc["at"], unit="ms", text=doc.get("skipped"),
                  lanes=number(status.get("lanes")), max_lanes=number(status.get("maxLanes")))
    for key in ("findings", "started", "held", "asked", "synced"):
        listed(out, key, doc.get(key))
    yield out


def pause(src, doc, path):
    """``loop/stop`` and ``duty/stop``: the kill switch of the hourly or the duty loop."""
    doc = mapping(doc)
    yield src.row("pause", timestamp=doc.get("at"), unit="ms", text=doc.get("reason"), loop_name=path.parent.name)


def migration(src, doc, path):
    """``migrate/<name>.json`` (``store-journal.ts``): an unfinished move of a session to another runtime."""
    doc = mapping(doc)
    yield src.row("migration", timestamp=doc.get("at"), unit="ms", migration_name=doc.get("name"),
                  migration_kind=doc.get("kind"), phase=doc.get("phase"), from_ref=ref_text(doc.get("from")),
                  to_runtime=doc.get("to"), new_ref=ref_text(doc.get("newRef")), brief_path=doc.get("briefPath"))


def brief(src, path, raw):
    """``briefs/<key>.md``, ``<key>.handoff.md`` and ``<key>.migrate-<ms>.md``: only the first heading is exported as
    the title; the brief text, the handoff screen dump and the queued messages in it are not."""
    name = path.name
    migrate = MIGRATE_BRIEF.match(name)
    if migrate:
        key, kind, at = migrate["key"], "migrate", int(migrate["at"])
    elif name.endswith(".handoff.md"):
        key, kind, at = name[:-len(".handoff.md")], "handoff", None
    else:
        key, kind, at = name[:-len(".md")], "brief", None
    heading = HEADING.search(raw.decode("utf-8", "replace"))
    return src.row("brief", timestamp=at, unit="ms", text=heading[1] if heading else "", lane_key=key, brief_kind=kind)


def roles(src, doc, path):
    """``roles.json``: the lead, duty and loop sessions as ref text."""
    refs = {k: v for k, v in mapping(doc).items() if isinstance(k, str) and isinstance(v, str)}
    yield src.row("settings", role_refs="; ".join(f"{k}={v}" for k, v in refs.items()))


def telemetry(src, doc, path):
    """``telemetry.json``: the install ID dori reports usage under. The ingest ``key`` is a credential: only whether
    one is stored is exported."""
    doc = mapping(doc)
    out = src.row("settings", telemetry_install_id=doc.get("installId"), last_active_day=doc.get("lastActiveDay"),
                  telemetry_key_stored=flag(isinstance(doc.get("key"), str) and bool(doc["key"])),
                  notice_shown=flag(doc.get("noticeShown")), installed_sent=flag(doc.get("installedSent")))
    yield stamped(out, duty_counts_since_utc=ms(mapping(doc.get("duty")).get("since")))


def dori_config(src, doc, path):
    """``config.json``, shared by the harness and the skill. ``agentCommand`` gives its program only; hook argv
    templates are named, not exported; commit identities are listed by repository only (the names and e-mail
    addresses are not exported)."""
    if not isinstance(doc, dict):
        yield src.note("invalid-config-shape")
        return
    out = src.row("settings", model=doc.get("defaultModel"), runtime=doc.get("runtime"), state_dir=doc.get("stateDir"),
                  sessions_dir=doc.get("sessionsDir"), default_cwd=doc.get("defaultCwd"),
                  lane_workspace=doc.get("laneWorkspace"), command_line=executable(doc.get("agentCommand")))
    listed(out, "config_keys", list(doc))
    listed(out, "hook_names", list(mapping(doc.get("hooks"))))
    yield listed(out, "repo_identities", list(mapping(doc.get("repoIdentities"))))


def slack_threads(src, doc, path):
    """``slack-threads.json`` (``ThreadLedger``): Slack threads the lead watches, with the root message's and the
    newest seen reply's ``ts``. A direct-message channel (``D``) is the owner's chat and is left empty."""
    if not isinstance(doc, list):
        yield src.note("invalid-config-shape")
        return
    for index, thread in enumerate(doc):
        thread = mapping(thread)
        root, channel = thread.get("rootTs"), thread.get("channel")
        if isinstance(channel, str) and PRIVATE_ROOM.fullmatch(f"slack:{channel}"):
            channel = ""
        out = replace(src, location={"source_offset": 0, "entry_index": index}).row(
            "messenger-thread", channel_kind="slack", channel=channel, thread_ts=root, seen_ts=thread.get("seenTs"))
        out.details["timestamp_raw"] = clean(root) if isinstance(root, str) else None
        out.details["timestamp_utc"] = slack_time(root)
        if isinstance(root, str) and out.details["timestamp_utc"] is None:
            out.details["flags"].append("timestamp-not-normalized")
        yield stamped(out, seen_utc=slack_time(thread.get("seenTs")))


def telegram_offset(src, doc, path):
    """``telegram-offset``: the next Telegram ``update_id`` the inbound poller will ask for."""
    if not doc.isdigit():
        yield src.note("invalid-document")
        return
    yield src.row("messenger-offset", channel_kind="telegram", next_update_id=doc)


def service(src, doc, path):
    """A launchd agent: label, the program (first ``ProgramArguments`` entry, or ``Program``) and environment variable
    names, never their values. dori installs no launchd agent and the operator's own wrappers follow no known
    layout, so no argument (script, environment file or token) is exported."""
    if not isinstance(doc, dict):
        yield src.note("unrecognized-service-definition")
        return
    program = executable(doc.get("ProgramArguments")) or doc.get("Program")
    out = src.row("service", service_label=doc.get("Label"), command_line=program, run_at_load=flag(doc.get("RunAtLoad")),
                  disabled=flag(path.parent.name == "disabled-launchd"))
    yield listed(out, "env_names", list(mapping(doc.get("EnvironmentVariables"))))


LINE_ROWS = {"reports": report, "checkpoints": checkpoint, "usage": usage, "worklog": worklog, "lessons": lesson,
             "inbox": queued}
DOCUMENT_ROWS = {"lane": lane, "receipt": receipt, "backlog": backlog, "loop-run": loop_run, "pause": pause,
                 "migration": migration, "roles": roles, "telemetry": telemetry, "dori-config": dori_config,
                 "slack-threads": slack_threads, "telegram-offset": telegram_offset, "service": service}
