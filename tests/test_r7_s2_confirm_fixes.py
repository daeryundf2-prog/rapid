"""R7 stage 2 confirmation pass: regressions found after the review fixes.

Each test class names the confirmation finding it guards.
"""

from __future__ import annotations

import time
import unittest


class CredentialMaskSpeedTest(unittest.TestCase):
    """S2: credential masking was quadratic on long alphanumeric runs (v1 search 10x slower)."""

    def test_long_alphanumeric_leaf_masks_fast(self) -> None:
        from rapidtriage.core.search_hits import redact_text

        for text in ("a" * 65536 + "=1", "=" + "Ab0_.-" * 11000, "x=" + "a" * 65536, "token" * 13000 + "=v"):
            started = time.perf_counter()
            redact_text(text)
            elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 0.05, (text[:20], elapsed))

    def test_record_with_many_long_leaves_snippet_is_fast(self) -> None:
        from rapidtriage.core.search_hits import search_snippet

        record = {"details": {f"k{index}": "b" * 16000 + "=" for index in range(40)} | {"hit": "근로 token=abc"}}
        started = time.perf_counter()
        snippet, _ = search_snippet(record, ["근로"])
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertEqual(snippet, "hit: 근로 token=[가림]")

    def test_masking_semantics_kept(self) -> None:
        from rapidtriage.core.search_hits import redact_text

        cases = {
            "…token=abc def": "…token=[가림] def",
            'Version=4.0, PublicKeyToken=b77a5c561934e089"': 'Version=4.0, PublicKeyToken=[가림]"',
            "a&rpctoken=123&b=1": "a&rpctoken=[가림]&b=1",
            "Endpoint=sb://x/;SharedAccessKeyName=k;SharedAccessToken=sasKey99": "Endpoint=sb://x/;SharedAccessKeyName=k;SharedAccessToken=[가림]",
            "db_password=hunter2 next": "db_password=[가림] next",
            "x-api-key=K1 my.secret='s p' API_KEY=\"q\"": "x-api-key=K1 my.secret=[가림] API_KEY=[가림]",
            "user pwd=p1 passwd=p2)": "user pwd=[가림] passwd=[가림])",
            "https://user:pw@host/x": "https://[가림]@host/x",
            ("v" * 200) + "token=abc": ("v" * 200) + "token=[가림]",
            "tokenizer=abc keyword=1": "tokenizer=abc keyword=1",
            "plain text": "plain text",
        }
        for text, expected in cases.items():
            self.assertEqual(redact_text(text), expected, text)

    def test_keyword_only_inside_a_masked_value_does_not_select_the_leaf(self) -> None:
        from rapidtriage.core.search_hits import search_snippet

        record = {"details": {"a": "token=secretword", "b": "the secretword note"}}
        snippet, _ = search_snippet(record, ["secretword"])
        self.assertEqual(snippet, "b: the secretword note")
        snippet, _ = search_snippet({"details": {"a": "token=secretword"}}, ["secretword"])
        self.assertEqual(snippet, "a: token=[가림]")


if __name__ == "__main__":
    unittest.main()
