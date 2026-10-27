"""claude-swap (``~/.claude-swap-backup``) account switcher adapter (R7 AI plan §3.2, S2).

``sequence.json`` lists the Claude accounts registered on the PC: one ``ai-account`` row each with
the organisation label, the email DOMAIN and a hash of the local part (never the address), the
active flag and the ``added`` time. ``claude-swap.log`` lines that mention a switch become
``ai-account-switch`` rows (time, from/to account numbers; addresses in the line are replaced by
``u-<hash>@domain``). ``configs/`` file names embed emails, so they are counted only;
``credentials/*`` are existence-only with the email in the path masked the same way.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import mask_email, mask_emails_in, redact_str, short_hash
from ._common import (
    RowContext,
    iter_profiles,
    iter_text_lines,
    log_line_time,
    make_found,
    presence_row,
    read_small_json,
    safe_stat,
    summary_row,
    to_iso,
    walk_files,
)
from ._iface import AiAgentAdapter, AiLimits, AiRow, Found, register_adapter

TOOL = "claude-swap"
LABEL = "claude-swap"
_SWITCH_RE = re.compile(r"(?i)\bswitch(?:ed|ing)?\b")
_FROM_TO_RE = re.compile(r"(?i)from\s+account\s+#?(\d+).*?to\s+account\s+#?(\d+)")
_TO_RE = re.compile(r"(?i)to\s+account\s+#?(\d+)")


class ClaudeSwapAdapter(AiAgentAdapter):
    name = "claude_swap"
    tool = TOOL

    def detect(self, roots: Sequence[object], os_hint: str = "") -> list[Found]:
        return [make_found(self, profile, profile.home / ".claude-swap-backup") for profile in iter_profiles(roots, os_hint) if (profile.home / ".claude-swap-backup").is_dir()]

    def collect(self, found: Found, limits: AiLimits) -> Iterator[AiRow]:
        base = found.path
        ctx = RowContext(self, LABEL, found, limits)
        rows: list[AiRow] = [presence_row(ctx, base, "tool-home")]
        sequence = base / "sequence.json"
        if sequence.is_file():
            rows.extend(self._accounts(ctx, sequence))
        log = base / "claude-swap.log"
        if log.is_file():
            rows.extend(self._switches(ctx, log))
        configs = base / "configs"
        if configs.is_dir():
            # file names carry account emails: counted, never listed
            rows.append(presence_row(ctx, configs, "account-config-copies", file_count=sum(1 for _ in walk_files(configs, limit=1000)), names_collected=False))
        creds = base / "credentials"
        if creds.is_dir():
            for path in walk_files(creds, limit=1000):
                size, mtime = safe_stat(path)
                rows.append(
                    ctx.row(
                        "ai-credential-presence",
                        mask_emails_in(str(path)),
                        credential_kind="encrypted-account-credential",
                        size=size,
                        file_mtime=mtime,
                        key_name="",
                        value_collected=False,
                        hash_collected=False,
                    )
                )
        cache = base / "cache"
        if cache.is_dir():
            rows.append(presence_row(ctx, cache, "cache", file_count=sum(1 for _ in walk_files(cache, limit=1000))))
        yield from rows
        yield summary_row(ctx, base)

    def _accounts(self, ctx: RowContext, path: Path) -> list[AiRow]:
        data = read_small_json(path, ctx.budget)
        if not isinstance(data, Mapping):
            return []
        accounts = data.get("accounts")
        active = str(data.get("activeAccountNumber") or "")
        rows: list[AiRow] = []
        if isinstance(accounts, Mapping):
            items = accounts.items()
        elif isinstance(accounts, list):
            items = ((str(i + 1), a) for i, a in enumerate(accounts))
        else:
            items = ()
        for number, account in items:
            if not isinstance(account, Mapping):
                continue
            domain, local_hash = mask_email(account.get("email"))
            added = to_iso(account.get("added"))
            rows.append(
                ctx.row(
                    "ai-account",
                    path,
                    timestamp=added,
                    kind="added",
                    tool_account_key=f"swap-{number}",
                    account_number=str(number),
                    org_label=redact_str(account.get("organizationName") or ""),
                    org_key=short_hash(str(account.get("organizationUuid") or "")) if account.get("organizationUuid") else "",
                    email_domain=domain,
                    email_local_hash=local_hash,
                    active=str(number) == active,
                    first_seen=added,
                    last_seen=to_iso(data.get("lastUpdated")) if str(number) == active else "",
                    linked_tool="claude-code",
                    source="sequence.json",
                )
            )
        return rows

    def _switches(self, ctx: RowContext, path: Path) -> list[AiRow]:
        rows: list[AiRow] = []
        for number, line in enumerate(iter_text_lines(path, ctx.budget), start=1):
            if not _SWITCH_RE.search(line):
                continue
            stamp = log_line_time(line)
            pair = _FROM_TO_RE.search(line)
            to_only = _TO_RE.search(line)
            rows.append(
                ctx.row(
                    "ai-account-switch",
                    path,
                    timestamp=stamp,
                    kind="switched",
                    ts=stamp,
                    from_account=f"swap-{pair.group(1)}" if pair else "",
                    to_account=f"swap-{pair.group(2)}" if pair else (f"swap-{to_only.group(1)}" if to_only else ""),
                    log_line=redact_str(mask_emails_in(line))[:512],
                    line_number=number,
                    source="claude-swap.log",
                )
            )
        return rows


register_adapter(ClaudeSwapAdapter)
