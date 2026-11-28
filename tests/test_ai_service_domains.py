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
from rapidtriage.artifacts.windows.browser import (
    detect_ai_service,
    extract_ai_conversation_candidates,
    infer_ai_service_from_path,
    likely_ai_storage_text,
)
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
    ("https://notebooklm.google.com/notebook/0012", "NotebookLM"),
)
# Hosts that only contain a service name: none of them is the service.
LOOKALIKE_VISITS = (
    "https://notwrtn.ai/chat",
    "https://kimi.com.evil.example/chat",
    "https://clova-x.naver.com.example/chat",
)
# Office on the web shares m365.cloud.microsoft with Copilot Chat: only /chat is chat.
M365_VISITS = (
    ("https://m365.cloud.microsoft/chat", "Microsoft 365 Copilot"),
    ("https://m365.cloud.microsoft/chat/?auth=2", "Microsoft 365 Copilot"),
    ("https://m365.cloud.microsoft/launch/word", ""),
    ("https://m365.cloud.microsoft/chats", ""),
)


class BrowserAiServiceRowsTests(unittest.TestCase):
    def test_each_added_service_yields_its_own_ai_usage_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            start = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
            urls = (
                [url for url, _service in NEW_SERVICE_VISITS]
                + list(LOOKALIKE_VISITS)
                + [url for url, _service in M365_VISITS]
            )
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
            expected = dict(NEW_SERVICE_VISITS) | {url: service for url, service in M365_VISITS if service}
            self.assertEqual(service_by_url, expected)
            self.assertEqual(ai_usage["details"]["ai_usage_count"], len(expected))

    def test_m365_host_counts_only_on_the_chat_path(self) -> None:
        for url, service in M365_VISITS:
            with self.subTest(url=url):
                self.assertEqual(detect_ai_service(url), service)


class BrowserAiStorageHostBoundaryTests(unittest.TestCase):
    """Storage paths and blobs hold hosts inside longer strings; a host must not match inside another host."""

    def test_storage_path_labels_need_a_host_boundary(self) -> None:
        cases = {
            "IndexedDB/https_api.githubcopilot.com_0.indexeddb.leveldb/000003.log": "",
            "IndexedDB/https_roadot.ai_0.indexeddb.leveldb/000003.log": "",
            "IndexedDB/https_kimi.community_0.indexeddb.leveldb/000003.log": "",
            "IndexedDB/https_box.ai_0.indexeddb.leveldb/000003.log": "",
            "IndexedDB/https_copilot.com_0.indexeddb.leveldb/000003.log": "Microsoft Copilot",
            "IndexedDB/https_www.kimi.com_0.indexeddb.leveldb/000003.log": "Kimi",
            "IndexedDB/https_chat.openai.com_0.indexeddb.leveldb/000003.log": "ChatGPT",
            "IndexedDB/https_x.ai_0.indexeddb.leveldb/000003.log": "Grok",
        }
        for raw, service in cases.items():
            with self.subTest(path=raw):
                self.assertEqual(infer_ai_service_from_path(Path("Default") / raw), service)

    def test_storage_text_gate_needs_a_host_boundary(self) -> None:
        self.assertFalse(likely_ai_storage_text("visit githubcopilot.com now"))
        self.assertFalse(likely_ai_storage_text("_https://www.felo.airline.example\x00"))
        self.assertTrue(likely_ai_storage_text("_https://www.felo.ai\x00"))
        self.assertTrue(likely_ai_storage_text("_https://www.kimi.com\x00"))

    def test_github_copilot_storage_is_not_labelled_microsoft_copilot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            profile = Path(tmp_dir) / "Default"
            messages = (
                b'{"role":"user","content":"Explain this stack trace from the parser"}\n'
                b'{"role":"assistant","content":"The parser reads past the end of the record header."}\n'
            )
            github = profile / "IndexedDB" / "https_api.githubcopilot.com_0.indexeddb.leveldb" / "000003.log"
            kimi = profile / "IndexedDB" / "https_www.kimi.com_0.indexeddb.leveldb" / "000003.log"
            felo_lookalike = profile / "Local Storage" / "leveldb" / "000005.ldb"
            for path in (github, kimi, felo_lookalike):
                path.parent.mkdir(parents=True, exist_ok=True)
            github.write_bytes(messages)
            kimi.write_bytes(messages)
            felo_lookalike.write_bytes(
                b"_https://www.felo.airline.example\x00"
                b'{"prompt":"Which seat has the most legroom","answer":"Exit rows usually have the most legroom."}\n'
            )

            rows = extract_ai_conversation_candidates(profile)

            service_by_source: dict[str, set[str]] = {}
            for row in rows:
                service_by_source.setdefault(str(row["source_path"]), set()).add(str(row["ai_service"]))
            self.assertEqual(
                service_by_source,
                {str(github.resolve()): {"AI service"}, str(kimi.resolve()): {"Kimi"}},
            )


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
            "/home/alice/.local/share/Jan/data/threads/t1/messages.jsonl": "Jan",
            "/home/alice/.jan/projects/demo/threads/t1/messages.jsonl": "Jan",
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
        for raw in (
            "/home/alice/january/data/notes.json",
            "/home/jan/data/notes.json",
            r"C:\Users\Jan\data\notes.json",
            "/srv/reports/2024/Jan/data/sales.json",
            r"C:\Users\alice\Documents\Finance\Jan\data\ledger.db",
        ):
            with self.subTest(path=raw):
                self.assertEqual(infer_local_llm_product(Path(raw)), "")

    def test_user_folder_named_jan_yields_no_local_llm_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            notes = root / "Users" / "Jan" / "data" / "notes.txt"
            notes.parent.mkdir(parents=True)
            notes.write_text("chat with the landlord about the response deadline\n", encoding="utf-8")

            artifacts = run_generic_documents(root)

            self.assertEqual([item for item in artifacts if item["artifact_type"].startswith("local-llm-")], [])

    def test_jan_thread_messages_become_prompt_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            thread = root / "Users" / "alice" / "AppData" / "Roaming" / "Jan" / "data" / "threads" / "jan_1732700000"
            thread.mkdir(parents=True)
            # Jan ThreadMessage lines (janhq/jan core/src/types/message/messageEntity.ts).
            lines = [
                jan_thread_message("msg_1", "user", "summarize the incident timeline for the board"),
                jan_thread_message("msg_2", "assistant", "The intrusion began on 3 November with a phishing email."),
            ]
            (thread / "messages.jsonl").write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")

            artifacts = run_generic_documents(root)

            inventory = [item for item in artifacts if item["artifact_type"] == "local-llm-artifact"]
            prompts = [item for item in artifacts if item["artifact_type"] == "local-llm-prompt-candidate"]
            self.assertEqual([item["details"]["product_hint"] for item in inventory], ["Jan"])
            self.assertEqual(
                [(item["details"]["direction"], item["details"]["source_offset"]) for item in prompts],
                [
                    ("user-prompt-candidate", 0),
                    ("assistant-response-candidate", len(json.dumps(lines[0]).encode("utf-8")) + 1),
                ],
            )
            self.assertTrue(all(item["details"]["product_hint"] == "Jan" for item in prompts))
            self.assertIn("incident timeline", prompts[0]["details"]["content_preview"])


def jan_thread_message(message_id: str, role: str, text: str) -> dict[str, object]:
    return {
        "id": message_id,
        "object": "thread.message",
        "thread_id": "jan_1732700000",
        "assistant_id": "jan",
        "role": role,
        "content": [{"type": "text", "text": {"value": text, "annotations": []}}],
        "status": "ready",
        "created_at": 1732700000,
        "completed_at": 1732700001,
    }


def run_generic_documents(root: Path) -> list[dict[str, object]]:
    output = root / "generic.json"
    with contextlib.redirect_stdout(io.StringIO()):
        if main(["artifacts", str(root), "--kind", "generic-documents", "--output", str(output)]) != 0:
            raise AssertionError("generic-documents run failed")
    return json.loads(output.read_text(encoding="utf-8"))["artifacts"]


if __name__ == "__main__":
    unittest.main()
