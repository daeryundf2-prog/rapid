from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.generic import infer_local_llm_product
from rapidtriage.artifacts.memory import classify_memory_url
from rapidtriage.cli import main
from tests.windows_artifact_fixtures import ChromiumVisit, _write_chromium_history

# One visit per service added with docs/ai-usage-coverage-matrix.md, as a user
# would reach it: the chat page, sometimes on a subdomain.
NEW_SERVICE_VISITS = (
    ("https://chat.deepseek.com/a/chat/s/0001", "DeepSeek"),
    ("https://grok.com/chat/0002", "Grok"),
    ("https://chat.mistral.ai/chat/0003", "Mistral Le Chat"),
    ("https://www.meta.ai/prompt/0004", "Meta AI"),
    ("https://character.ai/chat/0005", "Character.AI"),
    ("https://wrtn.ai/chat/0006", "뤼튼"),
    ("https://clova-x.naver.com/chat/0007", "CLOVA X"),
    ("https://www.kimi.com/chat/0008", "Kimi"),
    ("https://chat.qwen.ai/c/0009", "Qwen"),
    ("https://www.doubao.com/chat/0010", "Doubao"),
    ("https://chatglm.cn/main/0011", "ChatGLM"),
    ("https://copilot.cloud.microsoft/chat", "Microsoft 365 Copilot"),
    ("https://notebooklm.google/notebook/0012", "NotebookLM"),
)
# Hosts that only contain a service name: none of them is the service.
LOOKALIKE_VISITS = (
    "https://notwrtn.ai/chat",
    "https://kimi.com.evil.example/chat",
    "https://clova-x.naver.com.example/chat",
)


class BrowserAiServiceRowsTests(unittest.TestCase):
    def test_each_added_service_yields_its_own_ai_usage_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            start = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
            urls = [url for url, _service in NEW_SERVICE_VISITS] + list(LOOKALIKE_VISITS)
            history = root / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
            _write_chromium_history(
                history,
                visits=[
                    ChromiumVisit(url=url, title="", visited_at=start + timedelta(minutes=index))
                    for index, url in enumerate(urls)
                ],
                downloads=[],
            )
            output = root / "browser.json"

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(output)]), 0)

            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            ai_usage = next(item for item in artifacts if item["artifact_type"] == "browser-ai-usage")
            service_by_url = {row["url"]: row["ai_service"] for row in ai_usage["details"]["ai_usage"]}
            self.assertEqual(service_by_url, dict(NEW_SERVICE_VISITS))
            self.assertEqual(ai_usage["details"]["ai_usage_count"], len(NEW_SERVICE_VISITS))


class MemoryAiServiceUrlTests(unittest.TestCase):
    def test_memory_strings_classify_added_services(self) -> None:
        for url, service in NEW_SERVICE_VISITS:
            with self.subTest(url=url):
                result = classify_memory_url(url)
                self.assertEqual(result["service"], service)
                self.assertIn("ai-service", result["categories"])

    def test_memory_strings_do_not_classify_lookalike_hosts(self) -> None:
        for url in LOOKALIKE_VISITS:
            with self.subTest(url=url):
                self.assertNotIn("ai-service", classify_memory_url(url)["categories"])


class LocalLlmDesktopAppPathTests(unittest.TestCase):
    def test_documented_data_folders_name_their_product(self) -> None:
        cases = {
            r"C:\Users\alice\AppData\Roaming\Jan\data\threads\t1\messages.jsonl": "Jan",
            "/Users/alice/Library/Application Support/Jan/data/threads/t1/thread.json": "Jan",
            r"C:\Users\alice\AppData\Roaming\anythingllm-desktop\storage\anythingllm.db": "AnythingLLM",
            r"C:\Users\alice\AppData\Roaming\Msty\config.json": "Msty",
            r"C:\Users\alice\AppData\Roaming\ai.backend.go\logs\app.log": "AI:GO",
            r"C:\Users\alice\AppData\Local\LocalAI\data\chats.json": "LocalAI",
            "/opt/venv/lib/python3.12/site-packages/open_webui/data/webui.db": "Open WebUI",
            "/home/alice/text-generation-webui/user_data/logs/instruct/0001.json": "text-generation-webui",
            r"C:\Users\alice\AppData\Local\Ollama\db.sqlite": "Ollama",
        }
        for raw, product in cases.items():
            with self.subTest(path=raw):
                self.assertEqual(infer_local_llm_product(Path(raw)), product)

    def test_a_folder_that_merely_contains_jan_is_not_jan(self) -> None:
        self.assertEqual(infer_local_llm_product(Path("/home/alice/january/data/notes.json")), "")

    def test_jan_thread_messages_become_prompt_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            thread = root / "Users" / "alice" / "AppData" / "Roaming" / "Jan" / "data" / "threads" / "t1"
            thread.mkdir(parents=True)
            (thread / "messages.jsonl").write_text(
                json.dumps({"role": "user", "content": "User: summarize the incident timeline"}) + "\n",
                encoding="utf-8",
            )
            output = root / "generic.json"

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["artifacts", str(root), "--kind", "generic-documents", "--output", str(output)]), 0
                )

            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            inventory = [item for item in artifacts if item["artifact_type"] == "local-llm-artifact"]
            prompts = [item for item in artifacts if item["artifact_type"] == "local-llm-prompt-candidate"]
            self.assertEqual([item["details"]["product_hint"] for item in inventory], ["Jan"])
            self.assertTrue(prompts)
            self.assertTrue(all(item["details"]["product_hint"] == "Jan" for item in prompts))


if __name__ == "__main__":
    unittest.main()
