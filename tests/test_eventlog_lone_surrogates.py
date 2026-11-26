"""Lone UTF-16 surrogates in eventlog input.

A surrogate code point is not a character: UTF-8 cannot encode it, so one in a
row made the whole streamed eventlog collection fail (``failed-isolated``, no
rows). Nothing is dropped now:

- an EVTX character reference to a surrogate (``&#xD800;``) is kept as its
  reference text (``&#xd800;``), the way invalid character references already
  are, and the row carries ``evtx_lone_surrogate_references`` and the caution
  label ``lone-surrogate-character-reference``;
- a JSON export escape (``"\\ud800"``) is kept as its escape text (``\\ud800``)
  and the row carries ``export_lone_surrogate_escapes`` and the caution label
  ``lone-surrogate-json-escape``.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from evtx_engine_corpus import build_edge_corpus

from rapidtriage.artifacts.windows import evtx_engine
from rapidtriage.artifacts.windows.eventlog import parse_binxml_misc_token
from rapidtriage.core.artifacts import run_artifact_collection

NATIVE, _ = evtx_engine.load_native_evtx_decoder()
LABEL = "lone-surrogate-character-reference"


def has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in text)


def strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in (*strings(key), *strings(item))]
    if isinstance(value, list):
        return [text for item in value for text in strings(item)]
    return []


class LoneSurrogateReferenceTests(unittest.TestCase):
    def collect(self, detail: str, engine: str) -> tuple[dict[str, object], list[dict[str, object]]]:
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "tree" / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            (logs / "python-fallback-chunks.evtx").write_bytes(build_edge_corpus()["python-fallback-chunks.evtx"])
            records = Path(tmp) / "records.jsonl"
            payload = run_artifact_collection(
                Path(tmp) / "tree",
                kind="eventlog",
                records_path=records,
                collector_options={"record_detail": detail, "evtx_engine": engine},
            )
            text = records.read_bytes().decode("utf-8")
        return payload, [json.loads(line) for line in text.splitlines()]

    def test_streamed_collection_keeps_every_row(self) -> None:
        engines = ["python"] + (["rust"] if NATIVE is not None else [])
        for engine in engines:
            for detail in ("full", "triage"):
                with self.subTest(engine=engine, detail=detail):
                    payload, rows = self.collect(detail, engine)
                    summary = payload["summary"]
                    self.assertEqual(summary["collection_status"], "completed", payload["parser_errors"])
                    self.assertEqual(payload["parser_errors"], [])
                    self.assertEqual(payload["record_count"], len(rows))
                    self.assertGreater(len(rows), 10)
                    self.assertFalse(any(has_surrogate(json.dumps(row, ensure_ascii=False)) for row in rows))
                    flagged = [row for row in rows if row["details"].get("evtx_lone_surrogate_references")]
                    self.assertEqual(len(flagged), 1)
                    details = flagged[0]["details"]
                    self.assertEqual(details["evtx_lone_surrogate_references"], 1)
                    self.assertIn(LABEL, details["caution_labels"])
                    data = details["Ref"] if detail == "full" else details["event_data"]["Ref"]
                    self.assertEqual(data, "&#xd800;x")

    def test_structural_token_parser_keeps_reference_text(self) -> None:
        parsed = parse_binxml_misc_token(b"\x08\x00\xd8", 0, current_path="Event/EventData/Data")
        self.assertEqual(parsed["value_fields"][0]["text"], "&#xd800;")
        self.assertEqual(parsed["rendered"], "&amp;#xd800;")
        self.assertIn(f"{LABEL}:0", parsed["warnings"])
        ordinary = parse_binxml_misc_token(b"\x08\x41\x00", 0, current_path="Event/EventData/Data")
        self.assertEqual(ordinary["value_fields"][0]["text"], "A")
        self.assertEqual(ordinary["warnings"], [])

    def test_json_export_keeps_escape_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "tree" / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            (logs / "Security.json").write_text(
                '[{"EventID": 4688, "Channel": "Security", "TimeCreated": "2025-01-01T00:00:00Z",'
                ' "CommandLine": "cmd \\ud800 x", "NewProcessName": "a\\udfff.exe", "\\udc00k": "\\ud83d\\ude00"}]',
                encoding="utf-8",
            )
            records = Path(tmp) / "records.jsonl"
            payload = run_artifact_collection(Path(tmp) / "tree", kind="eventlog", records_path=records)
            rows = [json.loads(line) for line in records.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(payload["summary"]["collection_status"], "completed", payload["parser_errors"])
        events = [row for row in rows if row["artifact_type"] == "eventlog-event"]
        self.assertEqual(len(events), 1)
        details = events[0]["details"]
        self.assertEqual(details["export_lone_surrogate_escapes"], 3)
        self.assertIn("lone-surrogate-json-escape", details["caution_labels"])
        texts = set(strings(details))
        self.assertIn("cmd \\ud800 x", texts)
        self.assertIn("a\\udfff.exe", texts)
        # A valid pair is one character (the JSON decoder joins it), not escaped.
        self.assertIn("😀", texts)


if __name__ == "__main__":
    unittest.main()
