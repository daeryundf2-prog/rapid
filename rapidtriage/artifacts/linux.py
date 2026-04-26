from __future__ import annotations

import datetime as dt
import hashlib
import re
import shlex
from pathlib import Path
from typing import Iterable

from ..core.models import ArtifactRecord

PARSER_VERSION = "linux-system-v1"
SKIP_USERS = {"daemon", "nobody", "sync", "shutdown", "halt", "mail", "news", "uucp", "operator", "games"}
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_LOG_LINES = 5000
AUTH_LOG_RELATIVE_PATHS = (
    ("var", "log", "auth.log"),
    ("var", "log", "auth.log.1"),
    ("var", "log", "secure"),
    ("var", "log", "secure.1"),
)
SHELL_HISTORY_NAMES = (".bash_history", ".zsh_history", ".sh_history", ".ash_history")
SYSTEMD_DIRS = (
    ("etc", "systemd", "system"),
    ("usr", "lib", "systemd", "system"),
    ("lib", "systemd", "system"),
)
CRON_PATHS = (
    ("etc", "crontab"),
    ("etc", "cron.d"),
    ("var", "spool", "cron"),
    ("var", "spool", "cron", "crontabs"),
)
AUTH_PATTERNS = (
    ("ssh-accepted", re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")),
    ("ssh-failed", re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")),
    ("sudo-command", re.compile(r"sudo: +(?P<user>\S+) .*COMMAND=(?P<command>.+)$")),
    ("user-added", re.compile(r"(?:useradd|adduser).*(?:new user|name=)(?P<user>[A-Za-z0-9_.-]+)?")),
    ("cron-command", re.compile(r"CRON\[(?P<pid>\d+)\].*CMD \((?P<command>.+)\)")),
)
SUSPICIOUS_COMMAND_TOKENS = (
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "bash -i",
    "/dev/tcp/",
    "chmod 777",
    "base64 -d",
    "python -c",
    "perl -e",
    "socat",
)


class LinuxSystemArtifactsProvider:
    name = "linux-system-artifacts"
    collector_kind = "linux-system"
    description = "Linux user, shell history, SSH, auth log, cron, and systemd triage artifacts"
    target_platform = "linux"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        if not looks_like_linux_evidence(root):
            return
        yield from collect_linux_users(root)
        for user_root in iter_linux_user_homes(root):
            yield from collect_shell_history(user_root)
            yield from collect_ssh_artifacts(user_root)
        yield from collect_auth_logs(root)
        yield from collect_cron(root)
        yield from collect_systemd_units(root)


def looks_like_linux_evidence(root: Path) -> bool:
    return any(
        candidate.exists()
        for candidate in (
            root / "etc" / "passwd",
            root / "etc" / "shadow",
            root / "var" / "log",
            root / "home",
            root / "root",
        )
    )


def collect_linux_users(root: Path) -> Iterable[ArtifactRecord]:
    passwd_path = root / "etc" / "passwd"
    if not passwd_path.is_file():
        for user_root in iter_linux_user_homes(root):
            yield linux_user_record(user_root.name, str(user_root), "", "", source_path=user_root)
        return
    source_hashes = file_hashes(passwd_path)
    for index, line in enumerate(read_text_lines(passwd_path)):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, gecos, home, shell = parts[:7]
        if user.lower() in SKIP_USERS:
            continue
        yield linux_user_record(
            user,
            home,
            uid,
            shell,
            source_path=passwd_path,
            source_hashes=source_hashes,
            source_index=index,
            gid=gid,
            gecos=gecos,
        )


def linux_user_record(
    user: str,
    home: str,
    uid: str,
    shell: str,
    *,
    source_path: Path,
    source_hashes: dict[str, str] | None = None,
    source_index: int | None = None,
    gid: str = "",
    gecos: str = "",
) -> ArtifactRecord:
    details: dict[str, object] = {
        "parser": "linux-user-inventory",
        "parser_version": PARSER_VERSION,
        "coverage_status": "parsed" if source_path.name == "passwd" else "inventory",
        "reportability": "triage",
        "source_path": str(source_path.resolve()),
        "user": user,
        "uid": uid,
        "gid": gid,
        "gecos": gecos,
        "home": home,
        "shell": shell,
        "risk_flags": linux_user_risk_flags(uid=uid, shell=shell),
    }
    if source_hashes:
        details["source_hashes"] = source_hashes
    if source_index is not None:
        details["source_index"] = source_index
    return ArtifactRecord(
        provider=LinuxSystemArtifactsProvider.name,
        artifact_type="linux-user-profile",
        path=str(source_path.resolve()),
        supported=True,
        details=details,
    )


def linux_user_risk_flags(*, uid: str, shell: str) -> list[str]:
    flags: list[str] = []
    if uid == "0":
        flags.append("uid-zero-account")
    if shell and not shell.endswith(("nologin", "false")):
        flags.append("interactive-shell")
    return flags


def iter_linux_user_homes(root: Path) -> Iterable[Path]:
    home_root = root / "home"
    if home_root.is_dir():
        for candidate in sorted(home_root.iterdir(), key=lambda item: item.name.lower()):
            if candidate.is_dir() and candidate.name.lower() not in SKIP_USERS:
                yield candidate
    root_home = root / "root"
    if root_home.is_dir():
        yield root_home


def collect_shell_history(user_root: Path) -> Iterable[ArtifactRecord]:
    for name in SHELL_HISTORY_NAMES:
        path = user_root / name
        if not path.is_file():
            continue
        source_hashes = file_hashes(path)
        for index, raw_line in enumerate(read_text_lines(path)):
            command, timestamp = parse_shell_history_line(raw_line)
            if not command:
                continue
            flags = command_risk_flags(command)
            yield ArtifactRecord(
                provider=LinuxSystemArtifactsProvider.name,
                artifact_type="linux-shell-history",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "linux-shell-history",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "user": user_root.name,
                    "shell_history": name,
                    "command": command,
                    "timestamp": timestamp,
                    "risk_flags": flags,
                    "risk_score": command_risk_score(flags),
                },
            )


def parse_shell_history_line(line: str) -> tuple[str, str]:
    if line.startswith(": ") and ";" in line:
        prefix, command = line.split(";", 1)
        parts = prefix.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return command.strip(), isoformat_from_unix(parts[1])
        return command.strip(), ""
    return line.strip(), ""


def collect_ssh_artifacts(user_root: Path) -> Iterable[ArtifactRecord]:
    ssh_dir = user_root / ".ssh"
    if not ssh_dir.is_dir():
        return
    authorized = ssh_dir / "authorized_keys"
    if authorized.is_file():
        source_hashes = file_hashes(authorized)
        for index, line in enumerate(read_text_lines(authorized)):
            if not line or line.startswith("#"):
                continue
            parsed = parse_authorized_key(line)
            yield ArtifactRecord(
                provider=LinuxSystemArtifactsProvider.name,
                artifact_type="linux-ssh-authorized-key",
                path=str(authorized.resolve()),
                supported=True,
                details={
                    "parser": "linux-ssh-authorized-keys",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(authorized.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "user": user_root.name,
                    **parsed,
                    "risk_flags": ssh_key_risk_flags(parsed),
                },
            )
    known_hosts = ssh_dir / "known_hosts"
    if known_hosts.is_file():
        source_hashes = file_hashes(known_hosts)
        for index, line in enumerate(read_text_lines(known_hosts)):
            if not line or line.startswith("#"):
                continue
            yield ArtifactRecord(
                provider=LinuxSystemArtifactsProvider.name,
                artifact_type="linux-ssh-known-host",
                path=str(known_hosts.resolve()),
                supported=True,
                details={
                    "parser": "linux-ssh-known-hosts",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(known_hosts.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "user": user_root.name,
                    "host_pattern": line.split()[0] if line.split() else "",
                    "raw_preview": line[:240],
                },
            )


def parse_authorized_key(line: str) -> dict[str, object]:
    parts = shlex.split(line, comments=False, posix=True)
    key_index = next((index for index, part in enumerate(parts) if part.startswith(("ssh-", "ecdsa-", "sk-"))), -1)
    if key_index < 0:
        return {"key_type": "", "key_comment": "", "options": "", "raw_preview": line[:240]}
    options = " ".join(parts[:key_index])
    key_type = parts[key_index]
    key_body = parts[key_index + 1] if len(parts) > key_index + 1 else ""
    key_comment = " ".join(parts[key_index + 2 :])
    return {
        "key_type": key_type,
        "key_comment": key_comment,
        "options": options,
        "key_sha256": hashlib.sha256(key_body.encode("utf-8")).hexdigest() if key_body else "",
        "raw_preview": f"{options} {key_type} <key-redacted> {key_comment}".strip(),
    }


def ssh_key_risk_flags(parsed: dict[str, object]) -> list[str]:
    flags: list[str] = []
    options = str(parsed.get("options") or "").lower()
    if not options:
        flags.append("unrestricted-authorized-key")
    if "command=" in options:
        flags.append("forced-command-key")
    return flags


def collect_auth_logs(root: Path) -> Iterable[ArtifactRecord]:
    for relative_parts in AUTH_LOG_RELATIVE_PATHS:
        path = root.joinpath(*relative_parts)
        if not path.is_file():
            continue
        source_hashes = file_hashes(path)
        for index, line in enumerate(read_text_lines(path, max_lines=MAX_LOG_LINES)):
            parsed = parse_auth_log_line(line)
            if not parsed:
                continue
            flags = auth_log_risk_flags(parsed)
            yield ArtifactRecord(
                provider=LinuxSystemArtifactsProvider.name,
                artifact_type="linux-auth-log-event",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "linux-auth-log",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": index,
                    **parsed,
                    "risk_flags": flags,
                    "risk_score": auth_log_risk_score(flags),
                },
            )


def parse_auth_log_line(line: str) -> dict[str, object]:
    for event_type, pattern in AUTH_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        data = {key: value for key, value in match.groupdict().items() if value}
        return {
            "event_type": event_type,
            "timestamp_hint": line[:15].strip(),
            "process_hint": process_hint(line),
            "message": line,
            **data,
        }
    return {}


def process_hint(line: str) -> str:
    match = re.search(r"\s([A-Za-z0-9_.\-/]+)(?:\[\d+\])?:\s", line)
    return match.group(1) if match else ""


def auth_log_risk_flags(parsed: dict[str, object]) -> list[str]:
    flags: list[str] = []
    event_type = str(parsed.get("event_type") or "")
    if event_type == "ssh-failed":
        flags.append("failed-login")
    if event_type == "ssh-accepted":
        flags.append("remote-login")
    if event_type == "sudo-command":
        flags.append("sudo-command")
        flags.extend(command_risk_flags(str(parsed.get("command") or "")))
    if event_type == "user-added":
        flags.append("account-created")
    if event_type == "cron-command":
        flags.append("cron-execution")
        flags.extend(command_risk_flags(str(parsed.get("command") or "")))
    return sorted(set(flags))


def auth_log_risk_score(flags: list[str]) -> int:
    weights = {
        "failed-login": 15,
        "remote-login": 20,
        "sudo-command": 20,
        "account-created": 25,
        "cron-execution": 10,
        "suspicious-command-token": 25,
    }
    return min(sum(weights.get(flag, 5) for flag in flags), 100)


def collect_cron(root: Path) -> Iterable[ArtifactRecord]:
    for relative_parts in CRON_PATHS:
        path = root.joinpath(*relative_parts)
        if path.is_file():
            yield from collect_cron_file(path, owner=path.name, has_user_field=cron_file_has_user_field(path))
        elif path.is_dir():
            for cron_file in sorted((item for item in path.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
                yield from collect_cron_file(
                    cron_file,
                    owner=cron_file.name,
                    has_user_field=cron_file_has_user_field(cron_file),
                )


def collect_cron_file(path: Path, *, owner: str, has_user_field: bool) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    for index, line in enumerate(read_text_lines(path)):
        parsed = parse_cron_line(line, has_user_field=has_user_field)
        if not parsed:
            continue
        command = str(parsed.get("command") or "")
        flags = ["scheduled-command", *command_risk_flags(command)]
        yield ArtifactRecord(
            provider=LinuxSystemArtifactsProvider.name,
            artifact_type="linux-cron-entry",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "linux-cron",
                "parser_version": PARSER_VERSION,
                "coverage_status": "parsed",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "owner": owner,
                **parsed,
                "risk_flags": sorted(set(flags)),
                "risk_score": command_risk_score(flags),
            },
        )


def cron_file_has_user_field(path: Path) -> bool:
    parts = path.parts
    return path.name == "crontab" or ("etc" in parts and "cron.d" in parts)


def parse_cron_line(line: str, *, has_user_field: bool) -> dict[str, object]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" in stripped.split(maxsplit=1)[0]:
        return {}
    parts = stripped.split()
    if len(parts) < 6:
        return {}
    schedule = " ".join(parts[:5])
    command_parts = parts[5:]
    user = ""
    if has_user_field and len(parts) >= 7:
        user = command_parts[0]
        command_parts = command_parts[1:]
    return {"schedule": schedule, "user": user, "command": " ".join(command_parts)}


def collect_systemd_units(root: Path) -> Iterable[ArtifactRecord]:
    for relative_parts in SYSTEMD_DIRS:
        directory = root.joinpath(*relative_parts)
        if not directory.is_dir():
            continue
        for unit_path in sorted(directory.glob("*.service"), key=lambda item: str(item).lower()):
            details = parse_systemd_unit(unit_path)
            if not details:
                continue
            command = " ".join(details.get("exec_start", []))
            flags = systemd_risk_flags(details, unit_path)
            yield ArtifactRecord(
                provider=LinuxSystemArtifactsProvider.name,
                artifact_type="linux-systemd-service",
                path=str(unit_path.resolve()),
                supported=True,
                details={
                    "parser": "linux-systemd-service",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(unit_path.resolve()),
                    "source_hashes": file_hashes(unit_path),
                    "unit_name": unit_path.name,
                    **details,
                    "risk_flags": flags,
                    "risk_score": command_risk_score([*flags, *command_risk_flags(command)]),
                },
            )


def parse_systemd_unit(path: Path) -> dict[str, object]:
    details: dict[str, object] = {"exec_start": [], "exec_start_pre": [], "user": "", "description": "", "wanted_by": []}
    current_section = ""
    for line in read_text_lines(path):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped.strip("[]")
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if current_section == "Unit" and key == "Description":
            details["description"] = value
        elif current_section == "Service" and key == "ExecStart":
            details.setdefault("exec_start", []).append(value)
        elif current_section == "Service" and key == "ExecStartPre":
            details.setdefault("exec_start_pre", []).append(value)
        elif current_section == "Service" and key == "User":
            details["user"] = value
        elif current_section == "Install" and key == "WantedBy":
            details.setdefault("wanted_by", []).append(value)
    return details if details.get("exec_start") or details.get("exec_start_pre") else {}


def systemd_risk_flags(details: dict[str, object], unit_path: Path) -> list[str]:
    flags: list[str] = []
    command = " ".join([*list(details.get("exec_start", [])), *list(details.get("exec_start_pre", []))])
    if str(details.get("user") or "") in {"", "root"}:
        flags.append("runs-as-root")
    if any(path in command for path in ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/")):
        flags.append("user-writable-exec-path")
    if unit_path.parts[-3:-1] == ("etc", "systemd"):
        flags.append("local-systemd-unit")
    flags.extend(command_risk_flags(command))
    return sorted(set(flags))


def command_risk_flags(command: str) -> list[str]:
    lowered = command.lower()
    if any(token in lowered for token in SUSPICIOUS_COMMAND_TOKENS):
        return ["suspicious-command-token"]
    return []


def command_risk_score(flags: list[str]) -> int:
    weights = {
        "scheduled-command": 10,
        "runs-as-root": 15,
        "local-systemd-unit": 10,
        "user-writable-exec-path": 25,
        "suspicious-command-token": 30,
    }
    return min(sum(weights.get(flag, 5) for flag in flags), 100)


def read_text_lines(path: Path, *, max_lines: int = MAX_LOG_LINES) -> list[str]:
    try:
        data = path.read_bytes()[:MAX_TEXT_BYTES]
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[:max_lines]


def isoformat_from_unix(value: str) -> str:
    try:
        return dt.datetime.fromtimestamp(int(value), tz=dt.timezone.utc).isoformat()
    except (OSError, OverflowError, TypeError, ValueError):
        return ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
