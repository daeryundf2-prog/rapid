import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.docs import write_result


class CompactJsonWriteTests(unittest.TestCase):
    def test_compact_write_is_single_line_and_round_trips(self) -> None:
        payload = {
            "rows": [
                {"id": index, "name": f"row-{index}", "tags": ["a", "b"], "ok": True, "value": None}
                for index in range(500)
            ],
            "summary": {"count": 500},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            write_result(payload, path, indent=None)
            text = path.read_text(encoding="utf-8")

        self.assertEqual(text.count("\n"), 1)
        self.assertEqual(json.loads(text), payload)

    def test_indented_write_keeps_human_format(self) -> None:
        payload = {"summary": {"count": 1}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            write_result(payload, path)
            text = path.read_text(encoding="utf-8")

        self.assertIn('\n  "summary"', text)
        self.assertEqual(json.loads(text), payload)


if __name__ == "__main__":
    unittest.main()
