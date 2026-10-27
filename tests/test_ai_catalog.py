"""R7 stage 3.5 lane A: AI tool catalog loader, path expansion, single domain source, keyword pack."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.memory import AI_SERVICE_DOMAINS as MEMORY_AI_SERVICE_DOMAINS
from rapidtriage.artifacts.mobile.constants import MOBILE_AI_SERVICE_TOKENS
from rapidtriage.artifacts.windows.browser import (
    AI_SERVICE_DOMAINS as BROWSER_AI_SERVICE_DOMAINS,
)
from rapidtriage.artifacts.windows.browser import detect_ai_service
from rapidtriage.core.ai_catalog import (
    EvidenceProfile,
    ai_service_tokens,
    domains,
    execution_names,
    expand_paths,
    is_credential_name,
    key_prefixes,
    load_catalog,
    normalize_confidence,
)
from rapidtriage.core.ai_catalog.catalog import (
    PathTemplate,
    expand_template,
    path_templates_from_text,
)
from rapidtriage.core.keyword_packs import BUILTIN_KEYWORD_PACKS, resolve_keyword_packs

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check-ai-catalog.py"

# The browser list before R7 (artifacts/windows/browser.py AI_SERVICE_DOMAINS, 21 domains).
LEGACY_BROWSER_DOMAINS = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("openai.com", "OpenAI"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("aistudio.google.com", "Google AI Studio"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("bing.com", "Microsoft Copilot/Bing Chat"),
    ("poe.com", "Poe"),
    ("huggingface.co", "Hugging Face"),
    ("grok.com", "Grok"),
    ("x.ai", "Grok"),
    ("you.com", "You.com"),
    ("phind.com", "Phind"),
    ("chat.mistral.ai", "Mistral Le Chat"),
    ("deepseek.com", "DeepSeek"),
    ("meta.ai", "Meta AI"),
    ("character.ai", "Character.AI"),
    ("notion.so", "Notion AI"),
)
LEGACY_MEMORY_DOMAINS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "claude.ai": "Claude",
    "gemini.google.com": "Gemini",
    "bard.google.com": "Gemini",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Microsoft Copilot",
    "poe.com": "Poe",
}
# Hosts the plan (§3.1) lists as missing before R7 → (sample URL host, expected label).
PLAN_MISSING_HOSTS = {
    "kimi.com": "Kimi",
    "chat.qwen.ai": "Qwen",
    "www.doubao.com": "Doubao",
    "chat.z.ai": "Z.ai",
    "manus.im": "Manus",
    "www.genspark.ai": "Genspark",
    "felo.ai": "Felo",
    "notebooklm.google.com": "NotebookLM",
    "duck.ai": "Duck.ai",
    "openrouter.ai": "OpenRouter",
    "api.anthropic.com": "Claude",
    "api.openai.com": "OpenAI",
    "www.cursor.com": "Cursor",
    "app.devin.ai": "Devin",
    "jules.google.com": "Jules",
    "lovable.dev": "Lovable",
    "bolt.new": "Bolt",
    "v0.dev": "v0",
    "replit.com": "Replit Agent",
    "clova-x.naver.com": "CLOVA X",
    "wrtn.ai": "Wrtn",
    "kanana.kakao.com": "Kanana",
    "zeta-ai.io": "Zeta",
    "getliner.com": "Liner",
}


def _match(host: str, pairs) -> str:
    for domain, label in pairs:
        if host == domain or host.endswith("." + domain):
            return label
    return ""


class CatalogCheckScriptTests(unittest.TestCase):
    def test_script_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(CHECK_SCRIPT), "--json"], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["errors"], [])
        self.assertGreater(result["tool_count"], 150)
        self.assertGreater(result["path_template_count"], 400)

    def test_script_detects_a_drifted_copy(self) -> None:
        spec = importlib.util.spec_from_file_location("check_ai_catalog", CHECK_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            docs = Path(tmp)
            for source in module.DOCS_DIR.glob("*.json"):
                (docs / source.name).write_bytes(source.read_bytes())
            drifted = json.loads((docs / "local_llm.json").read_text(encoding="utf-8"))
            drifted[0]["name"] = "Ollama (edited)"
            (docs / "local_llm.json").write_text(json.dumps(drifted), encoding="utf-8")
            module.DOCS_DIR = docs
            result = module.check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("local_llm.json" in error for error in result["errors"]))


class CatalogModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_catalog()

    def test_tool_ids_and_adapter_ids(self) -> None:
        ids = [tool.id for tool in self.catalog.tools]
        self.assertEqual(len(ids), len(set(ids)))
        # Ids lane B adapters bind to.
        for tool_id in ("claude-code", "codex", "cursor", "antigravity", "kiro", "omo", "zcode", "claude", "claude-swap", "gemini-cli"):
            self.assertIsNotNone(self.catalog.tool(tool_id), tool_id)
        claude_code = self.catalog.tool("claude-code")
        self.assertIn("cli_agent", claude_code.categories)
        self.assertIn("ide_agent", claude_code.categories)  # merged with "Claude Code (CLI + IDE extension)"
        self.assertTrue(claude_code.local_verification)
        self.assertIn("@anthropic-ai/claude-code", claude_code.install["npm"])
        self.assertIn("CLAUDE.md", claude_code.instruction_files)
        self.assertTrue(claude_code.retention_auto_delete)
        self.assertIn(".credentials.json", [item.template.rsplit("/", 1)[-1] for item in claude_code.credential_paths])
        self.assertIn("session_log", claude_code.paths_by_os()["windows"])
        self.assertTrue(self.catalog.tool("model-file-formats").meta)

    def test_normalize_confidence(self) -> None:
        self.assertEqual(normalize_confidence("official-doc (file name); unverified (keychain on mac)"), "official")
        self.assertEqual(normalize_confidence("verified-on-test-pc (structure only)"), "local-verified")
        self.assertEqual(normalize_confidence("third-party/inferred"), "third-party")
        self.assertEqual(normalize_confidence("unknown"), "unverified")
        self.assertEqual(normalize_confidence("no idea"), "")

    def test_path_template_extraction(self) -> None:
        self.assertEqual(
            path_templates_from_text("%USERPROFILE%\\.claude\\projects\\<encoded-cwd>\\<session>.jsonl"),
            ["%USERPROFILE%/.claude/projects/*/*.jsonl"],
        )
        self.assertEqual(
            path_templates_from_text("~/.zcode/v2/{config.json,bot-state.v3.json}"),
            ["~/.zcode/v2/config.json", "~/.zcode/v2/bot-state.v3.json"],
        )
        self.assertEqual(path_templates_from_text("models: ~/Library/Application Support/LM Studio/models (x)"), ["~/Library/Application Support/LM Studio/models"])
        self.assertEqual(path_templates_from_text("~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl"), ["~/.codex/sessions/*/*/*/rollout-*.jsonl"])
        self.assertEqual(path_templates_from_text("C:\\Users\\<u>\\AppData\\Local\\nomic.ai\\GPT4All"), ["~/AppData/Local/nomic.ai/GPT4All"])
        self.assertEqual(path_templates_from_text("unknown in docs (macOS Keychain per prior knowledge)"), [])
        # A "/x" inside a sentence after a placeholder is not an absolute path.
        self.assertEqual(path_templates_from_text("<proj>/tool-results/"), [])

    def test_expand_paths_variables_and_globs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "Users" / "alice"
            for relative in (
                ".claude/projects/C--a/1.jsonl",
                "AppData/Roaming/Cursor/User/globalStorage/state.vscdb",
                "AppData/Local/Claude-Data/claude_pzs8sxrjxfjjc/x.json",
                "AppData/Local/Temp/claude/proj/sess/scratchpad/f.txt",
            ):
                target = home / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("x", encoding="utf-8")
            profile = EvidenceProfile(home=home, user="alice", os="windows", system_root=Path(tmp))
            claude_code = {str(match.path.relative_to(home)).replace("\\", "/") for match in expand_paths("claude-code", "windows", [profile])}
            self.assertIn(".claude/projects/C--a/1.jsonl", claude_code)  # ~ / %USERPROFILE% + <…> glob
            self.assertIn("AppData/Local/Temp/claude/proj/sess/scratchpad", claude_code)  # %TEMP%
            cursor = {match.path.name for match in expand_paths("cursor", "windows", [profile])}
            self.assertIn("state.vscdb", cursor)  # %APPDATA%
            claude = {match.path.name for match in expand_paths("claude", "windows", [profile])}
            self.assertIn("claude_pzs8sxrjxfjjc", claude)  # %LOCALAPPDATA%
            # Case-insensitive resolution (evidence copied from NTFS onto a case-sensitive disk).
            template = PathTemplate(os="windows", kind="", template="%APPDATA%/cursor/user/GLOBALSTORAGE/STATE.VSCDB", raw="", confidence="official")
            self.assertEqual(len(expand_template(template, profile)), 1)
            # Too-broad templates never resolve.
            broad = PathTemplate(os="any", kind="", template="~/*/x", raw="", confidence="official")
            self.assertEqual(expand_template(broad, profile), [])

    def test_shared_folders_are_not_harness_evidence(self) -> None:
        ecc = self.catalog.tool("ecc")
        shared = {item.template for item in ecc.paths if item.shared}
        self.assertIn("%USERPROFILE%/.claude/skills", shared)
        self.assertFalse(any(item.shared for item in ecc.paths if "/ecc" in item.template.lower()))
        claude_code = self.catalog.tool("claude-code")
        self.assertFalse(any(item.shared for item in claude_code.paths))

    def test_execution_names_skip_generic(self) -> None:
        names = execution_names()
        self.assertIn("claude-code", names["claude"])
        self.assertEqual(names["codex"], ("codex",))
        for generic in ("agent", "q", "pi", "chrome", "msedge", "chat"):
            self.assertNotIn(generic, names)

    def test_credential_names(self) -> None:
        for name in (".credentials.json", "auth.json", "oauth_creds.json", "jetski-standalone-oauth-token", "Cookies", "buddy-tokens.json", ".sandbox-secrets", "id_ed25519"):
            self.assertTrue(is_credential_name(name), name)
        for name in ("tokenizer.json", "tokenizer_config.json", "token_count.json", "settings.json", "history.jsonl"):
            self.assertFalse(is_credential_name(name), name)


class DomainSourceTests(unittest.TestCase):
    def test_browser_keeps_the_21_legacy_domains_first(self) -> None:
        self.assertEqual(BROWSER_AI_SERVICE_DOMAINS[: len(LEGACY_BROWSER_DOMAINS)], LEGACY_BROWSER_DOMAINS)
        self.assertEqual(domains(), BROWSER_AI_SERVICE_DOMAINS)
        self.assertGreater(len(BROWSER_AI_SERVICE_DOMAINS), 80)
        hosts = [domain for domain, _label in BROWSER_AI_SERVICE_DOMAINS]
        self.assertEqual(len(hosts), len(set(hosts)))

    def test_memory_keeps_the_8_legacy_domains_first(self) -> None:
        self.assertEqual(list(MEMORY_AI_SERVICE_DOMAINS.items())[: len(LEGACY_MEMORY_DOMAINS)], list(LEGACY_MEMORY_DOMAINS.items()))
        self.assertIn("openrouter.ai", MEMORY_AI_SERVICE_DOMAINS)

    def test_plan_missing_domains_are_added(self) -> None:
        for host, label in PLAN_MISSING_HOSTS.items():
            self.assertEqual(_match(host, BROWSER_AI_SERVICE_DOMAINS), label, host)
        self.assertEqual(detect_ai_service("https://openrouter.ai/chat"), "OpenRouter")
        self.assertEqual(detect_ai_service("https://chat.z.ai/c/1"), "Z.ai")

    def test_generic_hosts_never_listed(self) -> None:
        for host in ("github.com", "brave.com", "vercel.com", "x.com", "google.com", "zapier.com", "pi.ai", "posthog.com"):
            self.assertEqual(_match(host, BROWSER_AI_SERVICE_DOMAINS[len(LEGACY_BROWSER_DOMAINS) :]), "", host)
        # Legacy special cases unchanged: plain Bing search and plain Notion are not AI use.
        self.assertEqual(detect_ai_service("https://www.bing.com/search?q=weather"), "")
        self.assertEqual(detect_ai_service("https://www.notion.so/page"), "")

    def test_mobile_tokens(self) -> None:
        self.assertEqual(MOBILE_AI_SERVICE_TOKENS[:5], ("chatgpt", "claude", "gemini", "perplexity", "copilot"))
        self.assertEqual(MOBILE_AI_SERVICE_TOKENS, ai_service_tokens())
        self.assertIn("deepseek", MOBILE_AI_SERVICE_TOKENS)
        for word in ("mistral", "notion", "manus", "brave"):
            self.assertNotIn(word, MOBILE_AI_SERVICE_TOKENS)

    def test_keyword_pack(self) -> None:
        pack = BUILTIN_KEYWORD_PACKS["ai-tools"]
        for term in ("claude code", "cursor", "ollama", "openrouter.ai", "sk-ant-api03-", "sk-proj-", "AIza", "hf_"):
            self.assertIn(term, pack)
        for word in ("continue", "goose", "pi", "jan"):
            self.assertNotIn(word, pack)
        self.assertEqual(set(key_prefixes()) - set(pack), set())
        self.assertEqual(len(resolve_keyword_packs([], pack_names=["ai-tools"])), len(pack))
        self.assertIn("browser-ai", BUILTIN_KEYWORD_PACKS)


if __name__ == "__main__":
    unittest.main()
