"""AI 사용 기록 indicators (R7 stage 3.5 §3.4, lane C; catalogue ``catalog/ai.yaml``).

The rows come from the ``ai-agent`` kind (``rapidtriage/artifacts/ai_agents``). Paths and commands
in them are already masked by the collector; the rules never unmask anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_bool,
    as_list,
    evidence,
    org_domain,
    register,
    select,
    split_windows_path,
)
from .registry import removable_letters

AI_KIND = "ai-agent"
CLOUD_SYNC_ACCOUNT_TYPE = "cloud-sync-account"


def _ai(*types: str):
    return select(kinds={AI_KIND}, types=set(types))


@register("ai.credential_file_present")
class CredentialFilePresent(Rule):
    """A credential-presence row (token / OAuth / cookie / key file; the value is never collected)."""

    selector = _ai("ai-credential-presence")

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                path=row.path(),
                credential_kind=row.text("credential_kind", "catalog_kind"),
                key_name=row.text("key_name"),
                value_collected=False,
            )
        )


@register("ai.destructive_tool_call")
class DestructiveToolCall(Rule):
    """``destructive`` from the tool's own record (``destructive_source = tool-record``) or a delete /
    format command pattern (``params.command_patterns``) in the call's command."""

    selector = _ai("ai-agent-tool-call")

    def prepare(self, ctx: FlagContext) -> None:
        self.patterns = [re.compile(str(pattern), re.IGNORECASE) for pattern in self.param("command_patterns", [])]

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        command = row.text("command")
        recorded = as_bool(row.get("destructive")) is True and row.text("destructive_source") == "tool-record"
        matched = next((pattern.pattern for pattern in self.patterns if command and pattern.search(command)), "")
        if not recorded and not matched:
            return None
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                tool_name=row.text("tool_name"),
                command=command,
                target_path=row.text("target_path"),
                basis="tool-record" if recorded else "command-pattern",
                session_id=row.text("session_id"),
            )
        )


def _norm(path: str) -> str:
    """Comparable path: ``\\`` separators, case-folded, ``\\`` at both ends (prefix matching)."""
    text = path.strip().strip('"').replace("/", "\\").casefold()
    return text if text.endswith("\\") else text + "\\"


@register("ai.evidence_path_in_tool_call")
class EvidencePathInToolCall(Rule):
    """A tool-call target / file-touch path under a case evidence root (``params.evidence_roots``,
    set per run), a removable drive (letters the run proved removable, macOS / Linux removable mount
    prefixes) or a cloud-sync folder (sync roots of the run's ``cloud-sync-account`` rows, default
    folder names). Decided in ``finalize`` because the sync-account rows may come after the AI rows."""

    selector = select(kinds={AI_KIND, "cloud-sync"}, types={"ai-agent-tool-call", "ai-agent-file-touch", CLOUD_SYNC_ACCOUNT_TYPE})

    def prepare(self, ctx: FlagContext) -> None:
        self.candidates: list[tuple[RowRef, str, list[str], dict[str, str]]] = []
        self.sync_roots: set[str] = set()
        self.evidence_roots = [_norm(str(root)) for root in as_list(self.param("evidence_roots", [])) if str(root).strip()]
        self.cloud_markers = [str(marker).casefold() for marker in self.param("cloud_folder_markers", [])]
        self.mount_prefixes = [str(prefix).casefold() for prefix in self.param("removable_mount_prefixes", [])]

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == CLOUD_SYNC_ACCOUNT_TYPE:
            for root in [*as_list(row.get("sync_roots")), row.text("sync_root")]:
                if isinstance(root, str) and root.strip():
                    self.sync_roots.add(_norm(root))
            return None
        paths: list[str] = []
        for key in ("target_path", "touched_path"):
            value = row.text(key)
            if value and value not in paths:
                paths.append(value)
        if not paths:
            return None
        info = {
            "tool": row.text("tool_label", "tool"),
            "tool_name": row.text("tool_name"),
            "op": row.text("op", "tool_kind"),
            "session_id": row.text("session_id"),
        }
        self.candidates.append((row.ref, row.type, paths, info))
        return None

    def _reason(self, path: str, letters: set[str]) -> str:
        probe = _norm(path)
        for root in self.evidence_roots:
            if probe.startswith(root):
                return "사건 증거 폴더"
        drive, _rest = split_windows_path(path)
        if len(drive) == 1 and drive != "c" and drive in letters:
            return f"이동식 드라이브({drive.upper()}:)"
        posix = path.strip().replace("\\", "/").casefold()
        if any(posix.startswith(prefix) for prefix in self.mount_prefixes):
            return "이동식 볼륨 마운트"
        for root in self.sync_roots:
            if probe.startswith(root):
                return "클라우드 동기화 폴더"
        if any(marker in probe or marker in posix for marker in self.cloud_markers):
            return "클라우드 동기화 폴더(기본 이름)"
        return ""

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult, str]]:
        letters = removable_letters(ctx)
        for ref, row_type, paths, info in self.candidates:
            for path in paths:
                reason = self._reason(path, letters)
                if reason:
                    yield ref, RuleResult(evidence(path=path, location=reason, **info)), row_type
                    break


@register("ai.account_switch")
class AccountSwitch(Rule):
    """An account switch record (``ai-account-switch``)."""

    selector = _ai("ai-account-switch")

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                from_account=row.text("from_account"),
                to_account=row.text("tool_account_key", "account_number", "to_account"),
                switched_at=row.text("ts", "timestamp"),
            )
        )


@register("ai.personal_account_on_corporate")
class PersonalAccountOnCorporate(Rule):
    """An AI account whose e-mail domain is not the organisation domain (``params.org_email_domain``,
    the run option). Without that option the rule never fires."""

    selector = _ai("ai-account")

    def prepare(self, ctx: FlagContext) -> None:
        domain = str(self.param("org_email_domain", "") or "").strip().lower().lstrip("@")
        self.org = org_domain(domain) if domain else ""

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not self.org:
            return None
        domain = row.text("email_domain").lower().lstrip("@")
        if not domain or org_domain(domain) == self.org:
            return None
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                account=row.text("tool_account_key", "account_number"),
                email_domain=domain,
                org_label=row.text("org_label"),
                org_email_domain=self.org,
            )
        )


@register("ai.retention_cleanup_observed")
class RetentionCleanupObserved(Rule):
    """A retention cleanup marker (``ai-retention-cleanup``)."""

    selector = _ai("ai-retention-cleanup")

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                path=row.path(),
                cleaned_at=row.text("cleaned_at"),
                retention_days=row.get("retention_days"),
            )
        )


@register("ai.unknown_tool_candidate")
class UnknownToolCandidate(Rule):
    """A home dot-folder outside the catalogue with a session-like layout."""

    selector = _ai("unknown-ai-tool-candidate")

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        return RuleResult(evidence(path=row.path(), name=row.text("folder_name", "name", "tool_label")))


@register("ai.mcp_server_remote")
class McpServerRemote(Rule):
    """An MCP server with a remote URL (``remote = true``)."""

    selector = _ai("ai-mcp-server")

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if as_bool(row.get("remote")) is not True:
            return None
        return RuleResult(
            evidence(
                tool=row.text("tool_label", "tool"),
                server=row.text("server"),
                transport=row.text("transport"),
                endpoint=row.text("endpoint"),
                status=row.text("status"),
            )
        )


def ai_rule_params(collector_options: object) -> dict[str, dict[str, object]] | None:
    """Rule parameter overrides from the ``ai-agent`` run options: ``org_email_domain`` (activates
    ``ai.personal_account_on_corporate``) and ``evidence_roots`` (case evidence folders for
    ``ai.evidence_path_in_tool_call``). ``None`` when neither is set."""
    options = collector_options.get(AI_KIND) if isinstance(collector_options, Mapping) else None
    if not isinstance(options, Mapping):
        return None
    params: dict[str, dict[str, object]] = {}
    domain = str(options.get("org_email_domain") or "").strip()
    if domain:
        params["ai.personal_account_on_corporate"] = {"org_email_domain": domain}
    roots = [str(item) for item in as_list(options.get("evidence_roots")) if str(item).strip()]
    if roots:
        params["ai.evidence_path_in_tool_call"] = {"evidence_roots": roots}
    return params or None
