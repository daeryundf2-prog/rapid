"""Append-only local telemetry log: ``<app_data>/telemetry/events-YYYYMMDD.jsonl``.

Nothing here opens a network connection; the log only leaves the machine when
the user runs ``rapidtriage telemetry export`` and hands the bundle over.

Recording happens only in a process started through the product entry points
(``rapidtriage`` / ``rapidtriage-web`` call :func:`activate_for_process`), so
library use and test suites never write events. ``RAPIDTRIAGE_TELEMETRY=off``
or ``rapidtriage telemetry disable`` turns recording off entirely.

Ids are never written raw: case, run, tag and analysis ids become
``HMAC-SHA256(salt, kind:id)`` prefixes with a 32-byte salt that stays in
``salt.bin`` (excluded from exports), so ids cannot be joined across installs.
"""

from __future__ import annotations

import contextvars
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import threading
from collections.abc import Iterator, Mapping
from pathlib import Path

from ... import __version__
from ..doctor import default_app_data_dir
from .schema import EVENTS, FORBIDDEN_NAME_WORDS, SCHEMA_VERSION, clean_props

LOGGER = logging.getLogger(__name__)

DISABLE_ENV = "RAPIDTRIAGE_TELEMETRY"
DIR_ENV = "RAPIDTRIAGE_TELEMETRY_DIR"
ACTIVE_ENV = "RAPIDTRIAGE_TELEMETRY_ACTIVE"
SETTINGS_FILE = "settings.json"
SALT_FILE = "salt.bin"
EVENT_FILE_GLOB = "events-*.jsonl"
_OFF_VALUES = frozenset({"0", "off", "false", "no", "disabled"})
_SESSION_ID = re.compile(r"[A-Za-z0-9\-]{8,64}")
_HID = re.compile(r"[0-9a-f]{16}")
_PATH_LIKE = re.compile(r"[\\/]|^[A-Za-z]:|^~")

#: ``X-RapidTriage-Session`` of the API request being served (set by the app middleware).
SESSION_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("telemetry_session_id", default=None)

_LOCK = threading.Lock()
_RUN_CASES: dict[str, str] = {}
_SALT_CACHE: dict[Path, bytes] = {}


def telemetry_dir() -> Path:
    override = os.environ.get(DIR_ENV, "").strip()
    return Path(override).expanduser() if override else default_app_data_dir() / "telemetry"


def activate_for_process() -> None:
    """Mark this process (and the server it starts) as the app: events are recorded unless disabled."""
    os.environ[ACTIVE_ENV] = "1"


def read_settings(directory: Path | None = None) -> dict[str, object]:
    path = (directory or telemetry_dir()) / SETTINGS_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("telemetry settings unreadable (%s); recording stays off", type(exc).__name__)
        return {"enabled": False}
    return payload if isinstance(payload, dict) else {}


def write_settings(*, enabled: bool, directory: Path | None = None) -> Path:
    target = directory or telemetry_dir()
    target.mkdir(parents=True, exist_ok=True)
    path = target / SETTINGS_FILE
    path.write_text(json.dumps({"enabled": enabled}) + "\n", encoding="utf-8")
    return path


def disabled_reason(directory: Path | None = None) -> str | None:
    """Why nothing is recorded now (``None`` when recording is on)."""
    if os.environ.get(DISABLE_ENV, "").strip().lower() in _OFF_VALUES:
        return f"{DISABLE_ENV}=off"
    if read_settings(directory).get("enabled") is False:
        return "settings.json enabled=false"
    if os.environ.get(ACTIVE_ENV) != "1":
        return "not started through the rapidtriage app entry points"
    return None


def is_recording() -> bool:
    return disabled_reason() is None


def _salt(directory: Path) -> bytes:
    cached = _SALT_CACHE.get(directory)
    if cached is not None:
        return cached
    path = directory / SALT_FILE
    try:
        salt = path.read_bytes()
    except FileNotFoundError:
        directory.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(32)
        with path.open("xb") as handle:
            handle.write(salt)
    _SALT_CACHE[directory] = salt
    return salt


def hid(kind: str, raw: str, directory: Path | None = None) -> str:
    """Salted, install-local id of ``raw`` (``case``/``run``/``tag``/``analysis``/``install``)."""
    salt = _salt(directory or telemetry_dir())
    return hmac.new(salt, f"{kind}:{raw}".encode(), hashlib.sha256).hexdigest()[:16]


def link_run_case(run_id: str, case_id: str) -> None:
    """Remember the case a run belongs to so the run's later events carry its ``case_hid``."""
    with _LOCK:
        _RUN_CASES[run_id] = case_id


def _os_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux" if sys.platform.startswith("linux") else "other"


def privacy_violations(record: Mapping[str, object]) -> list[str]:
    """Reasons ``record`` must not be written: a forbidden property name or a path-like string."""
    problems: list[str] = []
    props = record.get("props")
    for key, value in (props.items() if isinstance(props, Mapping) else ()):
        if FORBIDDEN_NAME_WORDS & set(str(key).lower().split("_")):
            problems.append(f"forbidden property name {key}")
        if isinstance(value, str) and _PATH_LIKE.search(value):
            problems.append(f"path-like value in {key}")
    for key in ("install_hid", "case_hid", "run_hid"):
        value = record.get(key)
        if value is not None and not (isinstance(value, str) and _HID.fullmatch(value)):
            problems.append(f"{key} is not a salted hash")
    return problems


def build_record(
    event: str,
    props: Mapping[str, object],
    *,
    ids: Mapping[str, str | None],
    directory: Path,
) -> dict[str, object]:
    """Envelope + whitelisted props; ``ids`` holds raw ``run``/``case``/``tag``/``analysis`` ids to hash."""
    cleaned = clean_props(event, props)
    run_id, case_id = ids.get("run"), ids.get("case")
    if run_id and not case_id:
        with _LOCK:
            case_id = _RUN_CASES.get(run_id)
    for kind in ("tag", "analysis"):
        raw = ids.get(kind)
        if raw and f"{kind}_hid" in EVENTS[event]:
            cleaned[f"{kind}_hid"] = hid(kind, raw, directory)
    session = SESSION_ID.get()
    return {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "schema_version": SCHEMA_VERSION,
        "event": event,
        "install_hid": hid("install", "", directory),
        "session_id": session if session and _SESSION_ID.fullmatch(session) else None,
        "case_hid": hid("case", case_id, directory) if case_id else None,
        "run_hid": hid("run", run_id, directory) if run_id else None,
        "app_version": __version__,
        "os": _os_name(),
        "props": cleaned,
    }


def record(
    event: str,
    props: Mapping[str, object],
    *,
    run_id: str | None = None,
    case_id: str | None = None,
    tag: str | None = None,
    analysis_id: str | None = None,
) -> bool:
    """Append one event when recording is on; ``True`` when a line was written.

    Telemetry never fails the caller: a write error or a record that fails the
    privacy check is logged as a local warning and the event is dropped.
    """
    directory = telemetry_dir()
    if disabled_reason(directory) is not None:
        return False
    try:
        line = build_record(
            event, props, ids={"run": run_id, "case": case_id, "tag": tag, "analysis": analysis_id}, directory=directory
        )
        problems = privacy_violations(line)
        if problems:
            LOGGER.warning("telemetry event %s dropped by the privacy check: %s", event, "; ".join(problems))
            return False
        path = directory / f"events-{dt.datetime.now(dt.timezone.utc):%Y%m%d}.jsonl"
        text = json.dumps(line, ensure_ascii=True, separators=(",", ":")) + "\n"
        with _LOCK, path.open("a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        LOGGER.warning("telemetry event %s not written (%s)", event, type(exc).__name__)
        return False
    return True


def iter_events(directory: Path | None = None) -> Iterator[dict[str, object]]:
    """Every parsed record of the local log, oldest file first (unparseable lines are skipped with a warning)."""
    for path in sorted((directory or telemetry_dir()).glob(EVENT_FILE_GLOB)):
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    LOGGER.warning("telemetry log %s line %d is not JSON; skipped", path.name, number)
                    continue
                if isinstance(item, dict):
                    yield item
