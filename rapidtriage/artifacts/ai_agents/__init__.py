"""AI usage records — collector kind ``ai-agent`` (R7 stage 3.5).

Lane A (this package's top level): catalog path presence, credential-file presence (values
never collected), install traces (npm / pip / winget / MSIX / editor extensions), execution
match against a run's Prefetch / Amcache / ShimCache / SRUM rows, unknown AI tool candidates
(home dot-folders with a session layout) and local LLM model files.

Lane B: session adapters register through :func:`base.register_adapter` from
``rapidtriage.artifacts.ai_agents.adapters`` (imported here when present) and run after the
presence scan, one parse-error row per failing adapter location.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Iterator
from pathlib import Path

from ...core.ai_catalog.catalog import DirCache, enumerate_profiles, load_catalog
from ...core.models import ArtifactRecord
from .base import (
    AI_PROVIDER_NAME,
    AiLimits,
    AiRow,
    EvidenceProfile,
    registered_adapters,
)
from .execution_match import execution_presence_from_artifacts_dir
from .generic_hidden_dir import hidden_dir_candidate_rows
from .install import install_rows_for_profile
from .local_llm_ext import model_file_rows
from .presence import (
    dedupe_credential_rows,
    mask_row_identity,
    presence_rows_for_profile,
)

__all__ = ["AiAgentsProvider", "load_adapters"]

_ADAPTERS_LOADED = False


def load_adapters() -> None:
    """Import lane B's adapter package once (absent package = no session adapters yet)."""
    global _ADAPTERS_LOADED
    if _ADAPTERS_LOADED:
        return
    _ADAPTERS_LOADED = True
    try:
        importlib.import_module(f"{__name__}.adapters")
    except ModuleNotFoundError as exc:
        if exc.name != f"{__name__}.adapters":
            raise


def _parse_error(adapter: str, tool: str, path: str, exc: BaseException, profile: EvidenceProfile | None) -> AiRow:
    return AiRow(
        artifact_type="ai-agent-parse-error",
        tool=tool,
        account_key=profile.user if profile is not None else "",
        profile_label=profile.label if profile is not None else "",
        user=profile.user if profile is not None else "",
        path=path,
        coverage_status="parser-error",
        parser=f"ai-adapter-{adapter}",
        payload={
            "adapter": adapter,
            "parser_error": True,
            "reason": "adapter-failed",
            "reason_code": "adapter-failed",
            "reason_ko": "AI 기록 어댑터가 이 위치를 읽지 못했습니다(실행은 계속됨)",
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:300],
        },
    )


class AiAgentsProvider:
    collector_kind = "ai-agent"
    name = AI_PROVIDER_NAME
    description = (
        "AI usage records: catalog tool presence (paths, npm/pip/winget/MSIX/editor-extension installs, "
        "execution traces), credential-file presence without values, unknown AI tool candidates, local LLM "
        "model files and agent session adapters"
    )
    target_platform = "any"

    def __init__(
        self,
        *,
        ai_bodies: bool = True,
        ai_hash_dbs: bool = False,
        execution_artifacts_dir: Path | None = None,
        os_hint: str = "",
    ) -> None:
        self.ai_bodies = bool(ai_bodies)
        self.ai_hash_dbs = bool(ai_hash_dbs)
        self.execution_artifacts_dir = Path(execution_artifacts_dir) if execution_artifacts_dir else None
        self.os_hint = str(os_hint or "")
        self.collection_notes: list[str] = []
        self._profiles: list[EvidenceProfile] = []

    @property
    def options_key(self) -> str:
        defaults = self.ai_bodies and not self.ai_hash_dbs and self.execution_artifacts_dir is None and not self.os_hint
        if defaults:
            return ""
        return f"bodies={int(self.ai_bodies)};hash={int(self.ai_hash_dbs)};exec={self.execution_artifacts_dir or ''};os={self.os_hint}"

    def with_options(self, **options: object) -> AiAgentsProvider:
        execution_dir = options.get("execution_artifacts_dir")
        return AiAgentsProvider(
            ai_bodies=self.ai_bodies if options.get("ai_bodies") is None else bool(options["ai_bodies"]),
            ai_hash_dbs=self.ai_hash_dbs if options.get("ai_hash_dbs") is None else bool(options["ai_hash_dbs"]),
            execution_artifacts_dir=Path(str(execution_dir)) if execution_dir else self.execution_artifacts_dir,
            os_hint=str(options.get("os_hint") or self.os_hint),
        )

    def supported(self) -> bool:
        return True

    def limits(self) -> AiLimits:
        return AiLimits(include_bodies=self.ai_bodies, hash_large_dbs=self.ai_hash_dbs)

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for row in self.collect_rows(Path(root)):
            yield row.to_record()

    def collect_rows(self, root: Path) -> Iterator[AiRow]:
        """Every row; credential files reported by both lanes come out once (after the stream)."""
        yield from dedupe_credential_rows(self._all_rows(root))

    def _all_rows(self, root: Path) -> Iterator[AiRow]:
        for row in self._lane_a_rows(root):
            yield mask_row_identity(row)
        yield from self._adapter_rows(self._profiles)

    def _lane_a_rows(self, root: Path) -> Iterator[AiRow]:
        catalog = load_catalog()
        profiles = enumerate_profiles(root, os_hint=self.os_hint, catalog=catalog)
        self._profiles = profiles
        self.collection_notes = []
        if not profiles:
            self.collection_notes.append("사용자 프로필 폴더(Users\\<사용자>, /home/<사용자>, /Users/<사용자>)를 찾지 못해 AI 도구 흔적을 검사하지 않았습니다")
        cache = DirCache()
        for profile in profiles:
            yield from presence_rows_for_profile(catalog, profile, cache)
            yield from install_rows_for_profile(catalog, profile, cache)
            yield from hidden_dir_candidate_rows(catalog, profile, cache)
            yield from model_file_rows(catalog, profile, cache)
        if self.execution_artifacts_dir is not None:
            yield from execution_presence_from_artifacts_dir(self.execution_artifacts_dir, catalog=catalog)

    def _adapter_rows(self, profiles: list[EvidenceProfile]) -> Iterator[AiRow]:
        load_adapters()
        limits = self.limits()
        for adapter in registered_adapters():
            try:
                found_list = adapter.detect(profiles, self.os_hint)
            except Exception as exc:  # one adapter never stops the provider
                yield _parse_error(adapter.name, adapter.tool, "", exc, None)
                continue
            for found in found_list:
                try:
                    yield from adapter.collect(found, limits)
                except Exception as exc:
                    yield _parse_error(adapter.name, adapter.tool, str(found.path), exc, found.profile)
