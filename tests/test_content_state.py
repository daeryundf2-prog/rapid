"""T-185: ``content_state`` pure function on synthetic head bytes (8 cases + edge checks)."""

from __future__ import annotations

import hashlib
import unittest

from rapidtriage.core.content_state import (
    CONTENT_STATES,
    DEFAULT_HEAD_BYTES,
    content_state,
    describe_content_state,
    shannon_entropy,
)


def pseudo_random(size: int, seed: bytes = b"t-185") -> bytes:
    """Deterministic high-entropy bytes (SHA-256 counter stream)."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(8, "little")).digest()
        counter += 1
    return bytes(out[:size])


class ContentStateCases(unittest.TestCase):
    def test_1_empty(self) -> None:
        self.assertEqual(content_state(b"", 0), "empty")
        self.assertEqual(content_state(b"\xff\xd8\xff", 0), "empty")  # length wins over stale head bytes

    def test_2_zero_filled(self) -> None:
        self.assertEqual(content_state(b"\x00" * DEFAULT_HEAD_BYTES, 1_048_576), "zero-filled")
        self.assertEqual(content_state(b"\x00", 1), "zero-filled")

    def test_3_high_entropy(self) -> None:
        detail = describe_content_state(pseudo_random(DEFAULT_HEAD_BYTES), 10_000_000)
        self.assertEqual(detail["state"], "high-entropy")
        self.assertGreaterEqual(detail["entropy"], 7.5)

    def test_4_signature_at_start(self) -> None:
        jpeg = b"\xff\xd8\xff\xe0" + pseudo_random(4092)
        detail = describe_content_state(jpeg, 250_000)
        self.assertEqual((detail["state"], detail["signature"]), ("signature-valid", "jpeg"))
        self.assertEqual(content_state(b"SQLite format 3\x00" + b"\x00" * 84, 4096), "signature-valid")

    def test_5_signature_at_offset(self) -> None:
        mp4 = b"\x00\x00\x00\x20ftypisom" + b"\x00" * 20
        self.assertEqual(describe_content_state(mp4, 5_000_000)["signature"], "iso-bmff")

    def test_6_text_is_unclassified(self) -> None:
        text = ("사건 메모 line of plain text\n" * 100).encode("utf-8")
        self.assertEqual(content_state(text, len(text)), "unclassified")

    def test_7_short_random_head_is_not_high_entropy(self) -> None:
        self.assertEqual(content_state(pseudo_random(200), 200), "unclassified")
        self.assertEqual(content_state(b"MZ" + pseudo_random(100), 102), "unclassified")  # 2-byte magics not listed

    def test_8_head_cut_to_length(self) -> None:
        # Bytes past the declared length (slack) do not count: 2 KiB zeros then random slack.
        head = b"\x00" * 2048 + pseudo_random(2048)
        self.assertEqual(content_state(head, 2048), "zero-filled")
        self.assertEqual(content_state(head, 4096), "unclassified")


class ContentStateContract(unittest.TestCase):
    def test_errors_and_vocabulary(self) -> None:
        with self.assertRaises(ValueError):
            content_state(b"", 10)
        with self.assertRaises(ValueError):
            content_state(b"\x00", -1)
        self.assertEqual(
            set(CONTENT_STATES), {"empty", "signature-valid", "zero-filled", "high-entropy", "unclassified"}
        )
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)


if __name__ == "__main__":
    unittest.main()
