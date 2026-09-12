from __future__ import annotations

import unittest

from rapidtriage.artifacts.memory import classify_memory_url


class MemoryUrlClassificationTests(unittest.TestCase):
    def test_classify_memory_url_survives_bracketed_regex_fragment(self) -> None:
        # Carved from a real hiberfil/pagefile scan: the string "[a-z1-9-]"
        # looks like a bracketed host to urlparse and raises ValueError in
        # _check_bracketed_host before this guard existed, killing the whole
        # run against the parser crash isolation contract.
        result = classify_memory_url("[a-z1-9-]", context_preview="regex charset fragment")

        self.assertEqual(result["host"], "")
        self.assertEqual(result["scheme"], "")
        self.assertIn("web-url", result["categories"])
        self.assertNotIn("ai-service", result["categories"])

    def test_classify_memory_url_survives_ipv6_like_garbage(self) -> None:
        result = classify_memory_url("http://[not-an-address]/path", context_preview="")

        self.assertIsInstance(result, dict)
        self.assertEqual(result["host"], "")

    def test_classify_memory_url_still_classifies_real_urls(self) -> None:
        result = classify_memory_url("https://chat.openai.com/chat?q=forensics", context_preview="")

        self.assertEqual(result["host"], "chat.openai.com")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["service"], "ChatGPT")
        self.assertIn("ai-service", result["categories"])
        self.assertIn("search-query", result["categories"])


if __name__ == "__main__":
    unittest.main()
