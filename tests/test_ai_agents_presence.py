"""R7 stage 3.5 lane A: ai-agent presence on synthetic home trees (Windows / macOS / Linux, multi-profile)."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from rapidtriage.artifacts import artifact_collectors
from rapidtriage.artifacts.ai_agents import AiAgentsProvider
from rapidtriage.artifacts.ai_agents.base import (
    AI_ARTIFACT_TYPES,
    AiAgentAdapter,
    AiLimits,
    AiRow,
    EvidenceProfile,
    Found,
    clear_adapters,
    mask_identity_in_path,
    register_adapter,
    registered_adapters,
    unregister_adapter,
)
from rapidtriage.artifacts.ai_agents.execution_match import (
    execution_presence_from_artifacts_dir,
    execution_presence_rows,
)
from rapidtriage.core.ai_catalog import enumerate_profiles
from rapidtriage.core.ai_catalog.labels import (
    ARTIFACT_TYPE_LABELS_KO,
    INSTALL_KIND_LABELS_KO,
    label_ko,
)
from rapidtriage.core.run.constants import GENERAL_FORENSIC_ARTIFACT_KINDS

# Values written into credential files; no output row may ever contain them.
SECRET_VALUES = (
    "sk-ant-oat01-SYNTHETICSECRET0001",
    "ya29.SYNTHETIC-OAUTH-0002",
    "SYNTHETIC-COOKIE-0003",
    "hf_SYNTHETICHFTOKEN0004",
    "SYNTHETIC-SWAP-0005",
)


def write(path: Path, text: str = "x", *, size: int | None = None, mtime: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if size is not None:
        with path.open("wb") as handle:
            handle.truncate(size)
    else:
        path.write_text(text, encoding="utf-8")
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def build_windows_image(root: Path) -> None:
    """Two Windows users (alice: Claude Code + Codex + Cursor + installs; carol: Ollama + HF)."""
    alice = root / "Users" / "alice"
    write(alice / ".claude" / "projects" / "C--work-case" / "11111111-aaaa.jsonl", '{"type":"user"}\n')
    write(alice / ".claude" / "projects" / "C--work-case" / "11111111-aaaa" / "subagents" / "agent-1.jsonl", "{}\n")
    write(alice / ".claude" / "history.jsonl", "{}\n")
    write(alice / ".claude" / "settings.json", "{}")
    write(alice / ".claude" / ".credentials.json", json.dumps({"token": SECRET_VALUES[0]}))
    write(alice / ".claude" / ".last-cleanup", "")
    write(alice / ".codex" / "sqlite" / "state_5.sqlite", "sqlite")
    write(alice / ".codex" / "auth.json", json.dumps({"OPENAI_API_KEY": SECRET_VALUES[1]}))
    write(alice / ".codex" / "config.toml", "model = 'x'")
    write(alice / ".cursor" / "ai-tracking" / "ai-code-tracking.db", "db")
    write(alice / "AppData" / "Roaming" / "Cursor" / "User" / "globalStorage" / "state.vscdb", "db")
    write(alice / "AppData" / "Local" / "Claude-Data" / "claude_pzs8sxrjxfjjc" / "Network" / "Cookies", SECRET_VALUES[2])
    write(alice / "AppData" / "Local" / "Packages" / "Claude_pzs8sxrjxfjjc" / "Settings" / "settings.dat", "s")
    write(alice / "AppData" / "Roaming" / "npm" / "node_modules" / "@anthropic-ai" / "claude-code" / "package.json", json.dumps({"version": "2.1.300"}))
    write(alice / "AppData" / "Roaming" / "Python" / "Python312" / "site-packages" / "aider_chat-0.82.1.dist-info" / "RECORD", "")
    write(alice / ".vscode" / "extensions" / "saoudrizwan.claude-dev-3.17.0" / "package.json", json.dumps({"version": "3.17.0"}))
    write(alice / ".vscode" / "extensions" / "github.copilot-chat-0.30.1" / "package.json", "{}")
    write(alice / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages" / "Anthropic.ClaudeCode_Microsoft.Winget.Source_8wekyb3d8bbwe" / "claude.exe", "")
    # not in the catalog: session-like dot folders (ZCode-like layout under a new name) and a non-AI one
    write(alice / ".zzagent" / "cli" / "sessions" / "s1.jsonl", "{}\n")
    write(alice / ".zzagent" / "cli" / "db" / "db.sqlite", "db")
    write(alice / ".zzagent" / "configs" / "acct-1-alice@example.com.json", "{}")
    write(alice / ".gradle" / "caches" / "x.db", "db")
    write(alice / ".notes" / "readme.txt", "plain")
    write(alice / "Downloads" / "llama-3-8b.Q4_K_M.gguf", "gguf")
    write(alice / "NTUSER.DAT", "")
    carol = root / "Users" / "carol"
    write(carol / ".ollama" / "models" / "manifests" / "registry.ollama.ai" / "library" / "llama3" / "latest", "{}")
    write(carol / ".ollama" / "models" / "blobs" / "sha256-1234", size=2 * 1024 * 1024)
    write(carol / ".ollama" / "history", "hi")
    write(carol / ".cache" / "huggingface" / "hub" / "models--org--m" / "snapshots" / "abc" / "model.safetensors", "w")
    write(carol / ".cache" / "huggingface" / "token", SECRET_VALUES[3])
    write(carol / "AppData" / "Local" / "Temp" / "x.tmp", "")
    write(root / "Users" / "Public" / ".claude" / "settings.json", "{}")
    write(root / "Windows" / "Prefetch" / "CLAUDE.EXE-1A2B3C4D.pf", "pf")


def build_macos_home(root: Path) -> None:
    dana = root / "Users" / "dana"
    write(dana / "Library" / "Application Support" / "Claude-3p" / "config.json", "{}")
    write(dana / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb", "db")
    write(dana / ".claude" / "projects" / "-Users-dana-src" / "22222222.jsonl", "{}\n")
    write(dana / ".gemini" / "settings.json", "{}")
    write(dana / ".gemini" / "oauth_creds.json", SECRET_VALUES[1])
    write(dana / ".claude-swap-backup" / "sequence.json", "{}")
    write(dana / ".claude-swap-backup" / "credentials" / ".creds-1-dana@example.com.enc", SECRET_VALUES[4])
    write(root / "usr" / "local" / "lib" / "node_modules" / "@openai" / "codex" / "package.json", json.dumps({"version": "0.40.0"}))


def build_linux_home(root: Path) -> None:
    bob = root / "home" / "bob"
    write(bob / ".config" / "Cursor" / "User" / "globalStorage" / "state.vscdb", "db")
    write(bob / ".local" / "share" / "opencode" / "opencode.db", "db")
    write(bob / ".local" / "share" / "opencode" / "auth.json", SECRET_VALUES[1])
    write(bob / ".kiro" / "sessions" / "ws1" / "sess_1" / "session.json", "{}")
    write(bob / ".local" / "lib" / "python3.12" / "site-packages" / "llm-0.19.dist-info" / "RECORD", "")
    write(root / "etc" / "hostname", "box")


def collect(root: Path, **options: object) -> list[dict[str, object]]:
    provider = AiAgentsProvider().with_options(**options) if options else AiAgentsProvider()
    return [record.to_dict() for record in provider.collect(root)]


def rows_of(rows: list[dict[str, object]], artifact_type: str) -> Iterator[dict[str, object]]:
    for row in rows:
        if row["artifact_type"] == artifact_type:
            yield row


def catalog_presence(rows: list[dict[str, object]]) -> Iterator[dict[str, object]]:
    """Lane A catalog/install/execution ``ai-tool-presence`` rows. Lane B session adapters also
    emit ``ai-tool-presence`` rows (tool home, settings, run summary); those always carry a
    ``presence_kind`` and no ``install_kind``."""
    for row in rows_of(rows, "ai-tool-presence"):
        if "presence_kind" not in row["details"]:
            yield row


def presence(rows: list[dict[str, object]], *, kind: str = "path") -> set[tuple[str, str]]:
    return {
        (str(row["details"]["tool"]), str(row["details"]["account_key"]))
        for row in catalog_presence(rows)
        if row["details"]["install_kind"] == kind
    }


class ProviderRegistrationTests(unittest.TestCase):
    def test_kind_registered(self) -> None:
        self.assertIn("ai-agent", artifact_collectors())
        self.assertIn("ai-agent", GENERAL_FORENSIC_ARTIFACT_KINDS)

    def test_label_hints_cover_every_type(self) -> None:
        self.assertEqual(set(ARTIFACT_TYPE_LABELS_KO), set(AI_ARTIFACT_TYPES))
        self.assertEqual(label_ko("install_kind", "npm-global"), INSTALL_KIND_LABELS_KO["npm-global"])
        self.assertEqual(label_ko("install_kind", "nope"), "nope")


class WindowsImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        build_windows_image(cls.root)
        cls.rows = collect(cls.root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_profiles_enumerated_per_user(self) -> None:
        profiles = enumerate_profiles(self.root)
        self.assertEqual([(profile.user, profile.os) for profile in profiles], [("alice", "windows"), ("carol", "windows")])

    def test_path_presence_per_tool_and_account(self) -> None:
        found = presence(self.rows)
        for expected in (
            ("claude-code", "alice"),
            ("codex", "alice"),
            ("cursor", "alice"),
            ("claude", "alice"),
            ("ollama", "carol"),
            ("hugging-face-cache", "carol"),
        ):
            self.assertIn(expected, found)
        # Public profile skipped; harness paths inside ~/.claude are not evidence of the harness.
        self.assertFalse(any(account == "Public" for _tool, account in found))
        self.assertNotIn(("ecc", "alice"), found)
        self.assertNotIn(("ccusage", "alice"), found)
        claude = next(row for row in catalog_presence(self.rows) if row["details"]["tool"] == "claude-code" and row["details"]["install_kind"] == "path")
        self.assertEqual(claude["details"]["coverage_status"], "local-verified")
        self.assertTrue(claude["details"]["retention_auto_delete"])
        self.assertIn("session_log", claude["details"]["matched_path_kinds"])
        self.assertTrue(claude["details"]["mtime"])

    def test_install_presence(self) -> None:
        npm = [row for row in catalog_presence(self.rows) if row["details"]["install_kind"] == "npm-global"]
        self.assertEqual([(row["details"]["tool"], row["details"]["version"]) for row in npm], [("claude-code", "2.1.300")])
        self.assertIn(("aider", "alice"), presence(self.rows, kind="pip"))
        extensions = {(row["details"]["tool"], row["details"]["package"], row["details"]["version"]) for row in catalog_presence(self.rows) if row["details"]["install_kind"] == "vscode-extension"}
        self.assertIn(("cline", "saoudrizwan.claude-dev", "3.17.0"), extensions)
        self.assertIn(("github-copilot-chat", "github.copilot-chat", "0.30.1"), extensions)
        # ``github.copilot`` must not match the ``github.copilot-chat-…`` folder.
        self.assertNotIn("github.copilot", {package for _tool, package, _version in extensions})
        self.assertIn(("claude-code", "alice"), presence(self.rows, kind="winget"))
        self.assertIn(("claude", "alice"), presence(self.rows, kind="msix"))

    def test_credential_presence_metadata_only(self) -> None:
        creds = list(rows_of(self.rows, "ai-credential-presence"))
        names = {Path(str(row["path"])).name for row in creds}
        self.assertTrue({".credentials.json", "auth.json", "Cookies", "token"} <= names, names)
        for row in creds:
            details = row["details"]
            self.assertFalse(details["value_collected"])
            self.assertFalse(details["hash_collected"])
            self.assertIsInstance(details["size"], int)
            self.assertNotIn("sha256", json.dumps(details))
        # One row per file: a file lane B also reports is merged (``adapters``), the adapter-specific
        # kind wins and lane A's catalog classification stays in ``credential_kinds``.
        paths = [str(row["path"]).lower() for row in creds]
        self.assertEqual(len(paths), len(set(paths)))
        by_name = {Path(str(row["path"])).name: row["details"] for row in creds}
        self.assertIn("catalog-credential", by_name[".credentials.json"]["credential_kinds"])
        self.assertIn("ai-tool-presence", by_name[".credentials.json"]["adapters"])
        self.assertIn("name-pattern", by_name["Cookies"]["credential_kinds"])
        if by_name[".credentials.json"].get("adapter"):
            self.assertEqual(by_name[".credentials.json"]["credential_kind"], "oauth-credentials")

    def test_no_credential_value_in_any_row(self) -> None:
        dumped = json.dumps(self.rows, ensure_ascii=False)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, dumped)

    def test_unknown_tool_candidate(self) -> None:
        candidates = list(rows_of(self.rows, "unknown-ai-tool-candidate"))
        self.assertEqual([row["details"]["folder_name"] for row in candidates], [".zzagent"])
        details = candidates[0]["details"]
        self.assertIn("sessions", details["session_like_names"])
        self.assertEqual(details["jsonl_count"], 1)
        self.assertEqual(details["sqlite_count"], 1)
        self.assertNotIn("alice@example.com", json.dumps(candidates))
        self.assertNotIn("s1.jsonl", json.dumps(details))

    def test_model_files(self) -> None:
        models = {(row["details"]["tool"], row["details"]["format"], row["details"]["location"]) for row in rows_of(self.rows, "ai-model-file")}
        self.assertIn(("ollama", "Ollama blob", "model-folder"), models)
        self.assertIn(("hugging-face-cache", "safetensors", "model-folder"), models)
        self.assertIn(("unknown", "GGUF", "user-folder"), models)

    def test_counts(self) -> None:
        counts = Counter(row["artifact_type"] for row in self.rows)
        self.assertGreater(counts["ai-tool-presence"], 10)
        self.assertEqual(counts["unknown-ai-tool-candidate"], 1)
        self.assertEqual(counts["ai-model-file"], 3)
        for row in self.rows:
            self.assertIn(row["artifact_type"], AI_ARTIFACT_TYPES)
            self.assertEqual(row["provider"], "ai-agents")

    def test_execution_match_from_rows(self) -> None:
        rows = [
            {"artifact_type": "windows-prefetch", "path": r"C:\Windows\Prefetch\CLAUDE.EXE-1A2B3C4D.pf", "details": {"timestamp": "2026-10-20T01:02:03+00:00", "executable_hint": "CLAUDE.EXE"}},
            {"artifact_type": "windows-prefetch", "path": r"C:\Windows\Prefetch\CLAUDE.EXE-1A2B3C4D.pf", "details": {"timestamp": "2026-10-21T01:02:03+00:00"}},
            {"artifact_type": "amcache-entry", "path": "Amcache.hve", "details": {"executable_path": r"c:\users\alice\appdata\local\programs\ollama\ollama.exe"}},
            {"artifact_type": "srum-row-candidate", "path": "SRUDB.dat", "details": {"app_id": r"\device\harddiskvolume3\tools\agent.exe"}},
            {"artifact_type": "windows-prefetch", "path": r"C:\Windows\Prefetch\NOTEPAD.EXE-11111111.pf", "details": {}},
            {"artifact_type": "browser-history", "path": "History", "details": {"executable_path": "claude.exe"}},
        ]
        result = execution_presence_rows(rows)
        keys = {(row.tool, row.payload["execution_source"], row.payload["executable_name"]) for row in result}
        self.assertIn(("claude-code", "prefetch", "claude"), keys)
        self.assertIn(("ollama", "amcache", "ollama"), keys)
        self.assertFalse(any(name == "agent" for _tool, _source, name in keys))
        prefetch = next(row for row in result if row.tool == "claude-code")
        self.assertEqual(prefetch.payload["execution_row_count"], 2)
        self.assertEqual(prefetch.payload["last_seen"], "2026-10-21T01:02:03+00:00")
        self.assertEqual(prefetch.payload["install_kind"], "execution")
        self.assertIn("claude", prefetch.payload["ambiguous_tools"])

    def test_execution_match_from_run_artifacts_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp)
            payload = {
                "command": "artifacts",
                "kind": "windows-prefetch",
                "artifacts": [{"provider": "windows-prefetch", "artifact_type": "windows-prefetch", "path": r"C:\Windows\Prefetch\CODEX.EXE-ABCDEF12.pf", "supported": True, "details": {}}],
            }
            (artifacts / "rapidtriage-artifacts-windows-prefetch.json").write_text(json.dumps(payload), encoding="utf-8")
            rows = execution_presence_from_artifacts_dir(artifacts)
            self.assertEqual([(row.tool, row.payload["execution_source"]) for row in rows], [("codex", "prefetch")])
            provider_rows = collect(self.root, execution_artifacts_dir=str(artifacts))
            self.assertIn(("codex", ""), presence(provider_rows, kind="execution"))


class MacLinuxTests(unittest.TestCase):
    def test_macos_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_macos_home(root)
            profiles = enumerate_profiles(root)
            self.assertEqual([(profile.user, profile.os) for profile in profiles], [("dana", "macos")])
            rows = collect(root)
            found = presence(rows)
            for tool in ("claude", "cursor", "claude-code", "gemini-cli", "claude-swap"):
                self.assertIn((tool, "dana"), found)
            self.assertNotIn(("antigravity", "dana"), found)  # ~/.gemini alone is Gemini CLI's folder
            self.assertIn(("codex", "dana"), presence(rows, kind="npm-global"))
            creds = {Path(str(row["path"])).name for row in rows_of(rows, "ai-credential-presence")}
            self.assertIn("oauth_creds.json", creds)
            self.assertIn(mask_identity_in_path(".creds-1-dana@example.com.enc"), creds)
            dumped = json.dumps(rows)
            self.assertNotIn("dana@example.com", dumped)
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, dumped)

    def test_linux_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_linux_home(root)
            profiles = enumerate_profiles(root)
            self.assertEqual([(profile.user, profile.os) for profile in profiles], [("bob", "linux")])
            rows = collect(root)
            found = presence(rows)
            for tool in ("cursor", "opencode", "kiro"):
                self.assertIn((tool, "bob"), found)
            self.assertIn(("llm-cli", "bob"), presence(rows, kind="pip"))
            self.assertIn("auth.json", {Path(str(row["path"])).name for row in rows_of(rows, "ai-credential-presence")})

    def test_bare_home_root_and_empty_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "someone"
            write(home / ".codex" / "config.toml", "x")
            write(home / ".codex" / "sessions" / "2026" / "10" / "01" / "rollout-1.jsonl", "{}\n")
            profiles = enumerate_profiles(home)
            self.assertEqual([profile.user for profile in profiles], ["someone"])
            self.assertIn(("codex", "someone"), presence(collect(home)))
            empty = Path(tmp) / "empty"
            empty.mkdir()
            provider = AiAgentsProvider()
            self.assertEqual(list(provider.collect(empty)), [])
            self.assertTrue(provider.collection_notes)

    def test_multi_os_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_windows_image(root / "C")
            build_linux_home(root / "linuxpart")
            users = sorted((profile.user, profile.os) for profile in enumerate_profiles(root))
            self.assertEqual(users, [("alice", "windows"), ("bob", "linux"), ("carol", "windows")])


class _FakeAdapter(AiAgentAdapter):
    name = "fake_test"
    tool = "claude-code"

    def detect(self, roots, os_hint=""):
        return [Found(adapter=self.name, tool=self.tool, path=profile.home, profile=profile) for profile in roots]

    def collect(self, found, limits):
        if found.profile is not None and found.profile.user == "carol":
            raise RuntimeError("boom")
        yield AiRow(artifact_type="ai-agent-session", tool=self.tool, account_key=found.profile.user, path=str(found.path), payload={"session_id": "s", "limit": limits.max_messages_per_session})


class AdapterRegistryTests(unittest.TestCase):
    def tearDown(self) -> None:
        unregister_adapter("fake_test")

    def test_registered_adapter_runs_and_failure_is_isolated(self) -> None:
        register_adapter(_FakeAdapter)
        self.assertIn("fake_test", [adapter.name for adapter in registered_adapters()])
        with self.assertRaises(ValueError):
            register_adapter(_FakeAdapter)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_windows_image(root)
            rows = collect(root)
        # Only the fake adapter's rows: the registered lane B adapters also run (claude_code finds alice's session file).
        sessions = [row for row in rows_of(rows, "ai-agent-session") if row["details"]["parser"] == "ai-agents"]
        self.assertEqual([row["details"]["account_key"] for row in sessions], ["alice"])
        self.assertEqual(sessions[0]["details"]["limit"], AiLimits().max_messages_per_session)
        errors = [row for row in rows_of(rows, "ai-agent-parse-error") if row["details"]["adapter"] == "fake_test"]
        self.assertEqual(list(rows_of(rows, "ai-agent-parse-error")), errors, "no lane B adapter fails on this tree")
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0]["details"]["parser_error"])
        self.assertEqual(errors[0]["details"]["reason_code"], "adapter-failed")

    def test_limits_follow_run_options(self) -> None:
        provider = AiAgentsProvider().with_options(ai_bodies=False, ai_hash_dbs=True)
        self.assertFalse(provider.limits().include_bodies)
        self.assertTrue(provider.limits().hash_large_dbs)
        self.assertTrue(provider.options_key)
        self.assertEqual(AiAgentsProvider().options_key, "")
        self.assertEqual(AiLimits().max_message_bytes, 16 * 1024)
        self.assertEqual(AiLimits().max_sqlite_bytes, 1024**3)

    def test_clear_adapters_is_available(self) -> None:
        snapshot = registered_adapters()
        clear_adapters()
        self.assertEqual(registered_adapters(), [])
        for adapter in snapshot:
            register_adapter(adapter)

    def test_evidence_profile_label(self) -> None:
        self.assertEqual(EvidenceProfile(home=Path("x"), user="alice", os="windows").label, "alice (Windows)")


class PerformanceTests(unittest.TestCase):
    def test_wide_home_stays_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alice = root / "Users" / "alice"
            for index in range(300):
                write(alice / ".claude" / "projects" / f"p{index}" / f"{index}.jsonl", "{}\n")
            started = time.perf_counter()
            rows = collect(root)
            elapsed = time.perf_counter() - started
            self.assertIn(("claude-code", "alice"), presence(rows))
            self.assertLess(elapsed, 30.0)


if __name__ == "__main__":
    unittest.main()
