from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.extract import ExtractError, run_extract
from rapidtriage.core.indicators import (
    build_indicator_summary,
    collect_indicators_from_stream,
)
from rapidtriage.core.json_stream import (
    JsonStreamError,
    LazyArray,
    LazyObject,
    Scalar,
    iter_array_items,
    open_json,
    read_member,
)
from rapidtriage.core.run.incremental_indexing import (
    load_reusable_json,
    reusable_json_max_bytes,
)
from rapidtriage.core.timeline import TimelineError, run_timeline


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


class JsonStreamReaderTests(unittest.TestCase):
    def test_read_member_skips_other_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(
                Path(tmp_dir) / "big.json",
                {
                    "command": "docs",
                    "bulk": [{"blob": "x" * 64} for _ in range(8)],
                    "summary": {"candidate_count": 8, "match_count": 2},
                    "tail": True,
                },
            )
            self.assertEqual(
                read_member(path, "summary"),
                {"candidate_count": 8, "match_count": 2},
            )
            self.assertEqual(read_member(path, "command"), "docs")
            self.assertTrue(read_member(path, "tail"))

    def test_read_member_missing_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(Path(tmp_dir) / "a.json", {"a": 1})
            with self.assertRaises(JsonStreamError):
                read_member(path, "missing")

    def test_iter_array_items_materializes_each_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(
                Path(tmp_dir) / "arr.json",
                {"meta": 1, "items": [{"n": 1}, {"n": 2}, {"n": 3}], "tail": "x"},
            )
            self.assertEqual(list(iter_array_items(path, "items")), [{"n": 1}, {"n": 2}, {"n": 3}])

    def test_members_yield_lazy_nodes_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(
                Path(tmp_dir) / "obj.json",
                {"a": 1, "b": {"nested": [1, 2]}, "c": [3], "d": "txt"},
            )
            seen: list[tuple[str, object]] = []
            with open_json(path) as root:
                self.assertIsInstance(root, LazyObject)
                for key, node in root.members():
                    seen.append((key, type(node).__name__))
                    if isinstance(node, (LazyObject, LazyArray)):
                        node.materialize()
            self.assertEqual(
                seen,
                [("a", "Scalar"), ("b", "LazyObject"), ("c", "LazyArray"), ("d", "Scalar")],
            )

    def test_abandoned_lazy_child_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(
                Path(tmp_dir) / "skip.json",
                {"huge": [{"deep": {"x": list(range(20))}} for _ in range(4)], "after": 42},
            )
            with open_json(path) as root:
                keys = []
                for key, node in root.members():
                    keys.append(key)
                    if key == "after":
                        self.assertIsInstance(node, Scalar)
                        self.assertEqual(node.value, 42)
            self.assertEqual(keys, ["huge", "after"])

    def test_materialize_nested_containers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = {"outer": {"inner": [1, {"leaf": None}, "s"]}, "z": 0}
            path = write_json(Path(tmp_dir) / "m.json", payload)
            with open_json(path) as root:
                for key, node in root.members():
                    if key == "outer":
                        self.assertEqual(node.materialize(), payload["outer"])
            self.assertEqual(read_member(path, "outer"), payload["outer"])

    def test_truncated_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "trunc.json"
            path.write_text('{"a": [1, 2, {"b": ', encoding="utf-8")
            with self.assertRaises(JsonStreamError):
                read_member(path, "a")

    def test_chunk_boundary_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "chunk.json"
            long_text = 'ab\\"cd' * 400
            write_json(path, {"text": long_text, "arr": list(range(5000)), "end": "ok"})
            with open_json(path, chunk_size=1024) as root:
                values = {key: node.materialize() for key, node in root.members()}
            self.assertEqual(values["text"], long_text)
            self.assertEqual(values["end"], "ok")
            self.assertEqual(values["arr"], list(range(5000)))
            self.assertEqual(list(iter_array_items(path, "arr")), list(range(5000)))

    def test_root_must_be_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(Path(tmp_dir) / "list.json", [1, 2, 3])
            with self.assertRaises(JsonStreamError):
                with open_json(path):
                    pass

    def test_skip_container_escape_at_chunk_boundary(self) -> None:
        # A "\\" as the last byte of a chunk must not let the escaped char in
        # the next chunk be interpreted (e.g. '"' toggling in_string), which
        # desyncs the skip and corrupts all following members.
        payload = {
            "big": ["pre\\" + "x" * 33 + '"post', {"k": ["v\\", 1]}],
            "wanted": [1, {"deep": "v"}, 3],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(Path(tmp_dir) / "esc.json", payload)
            for chunk_size in range(4, 96):
                with self.subTest(chunk_size=chunk_size):
                    self.assertEqual(
                        read_member(path, "wanted", chunk_size=chunk_size),
                        payload["wanted"],
                    )
                    self.assertEqual(
                        list(
                            iter_array_items(path, "wanted", chunk_size=chunk_size)
                        ),
                        payload["wanted"],
                    )

    def test_number_at_chunk_boundary(self) -> None:
        # raw_decode stops a number at a '.'/'e'/'+'/'-' that lacks its
        # continuation; when that stop lands on the buffer edge the reader
        # must refill instead of accepting the truncated value.
        payload = {
            "nums": [-1.973, 1.5e30, 222, -0.001, 3.14e-7, 1.25e+8],
            "obj": {"a": -2.5, "b": 6.02e23},
            "wanted": "ok",
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(Path(tmp_dir) / "nums.json", payload)
            for chunk_size in range(4, 80):
                with self.subTest(chunk_size=chunk_size):
                    self.assertEqual(
                        list(iter_array_items(path, "nums", chunk_size=chunk_size)),
                        payload["nums"],
                    )
                    self.assertEqual(
                        read_member(path, "obj", chunk_size=chunk_size),
                        payload["obj"],
                    )
                    self.assertEqual(
                        read_member(path, "wanted", chunk_size=chunk_size),
                        "ok",
                    )


class ExtractPayloadTests(unittest.TestCase):
    def test_run_extract_accepts_in_memory_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            root.mkdir()
            source = root / "hit.txt"
            source.write_text("payload", encoding="utf-8")
            missing_input = Path(tmp_dir) / "does-not-exist.json"
            payload = {
                "command": "files",
                "root": str(root),
                "candidates": [{"path": str(source), "categories": ["documents"]}],
            }
            output_dir = Path(tmp_dir) / "extract-out"
            result = run_extract(
                missing_input,
                output_dir,
                categories=["documents"],
                payload=payload,
            )
            self.assertEqual(result["summary"]["extracted_count"], 1)
            self.assertEqual(result["source_command"], "files")
            self.assertTrue((output_dir / "hit.txt").is_file())

    def test_run_extract_payload_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ExtractError):
                run_extract(
                    Path(tmp_dir) / "in.json",
                    Path(tmp_dir) / "out",
                    payload={"command": "bogus"},
                )


class TimelinePayloadTests(unittest.TestCase):
    def test_run_timeline_uses_payload_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_root = Path(tmp_dir) / "empty-root"
            empty_root.mkdir()
            files_path = write_json(
                Path(tmp_dir) / "files.json",
                {
                    "command": "files",
                    "candidates": [
                        {
                            "path": str(Path(tmp_dir) / "a.exe"),
                            "name": "a.exe",
                            "modified_at": "2024-01-02T03:04:05+00:00",
                            "categories": ["executables"],
                            "reasons": {},
                        }
                    ],
                },
            )
            payload = run_timeline(
                root=empty_root,
                files_inputs=[files_path],
                input_payloads={str(files_path.resolve()): {"command": "files", "candidates": [
                    {
                        "path": str(Path(tmp_dir) / "b.exe"),
                        "name": "b.exe",
                        "modified_at": "2025-05-06T07:08:09+00:00",
                        "categories": ["executables"],
                        "reasons": {},
                    }
                ]}},
            )
            paths = [event["path"] for event in payload["events"]]
            self.assertIn(str(Path(tmp_dir) / "b.exe"), paths)
            self.assertNotIn(str(Path(tmp_dir) / "a.exe"), paths)

    def test_run_timeline_rejects_wrong_command_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_root = Path(tmp_dir) / "empty-root"
            empty_root.mkdir()
            files_path = write_json(Path(tmp_dir) / "files.json", {"command": "files", "candidates": []})
            with self.assertRaises(TimelineError):
                run_timeline(
                    root=empty_root,
                    files_inputs=[files_path],
                    input_payloads={str(files_path.resolve()): {"command": "docs", "results": []}},
                )


class IndicatorStreamTests(unittest.TestCase):
    def _sample_docs_payload(self) -> dict[str, object]:
        return {
            "command": "docs",
            "results": [
                {
                    "path": "/ev/note.txt",
                    "kind": "txt",
                    "matched_keywords": ["login"],
                    "preview": "visit https://malicious.example/login now",
                }
            ],
            "ioc_hits": [
                {"rule_id": "root-rule", "type": "domain", "value": "root.example", "count": 2}
            ],
        }

    def test_streamed_output_matches_in_memory_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = self._sample_docs_payload()
            docs_path = write_json(Path(tmp_dir) / "docs.json", payload)
            run_output = {"outputs": {"docs": str(docs_path)}}
            in_memory = build_indicator_summary(run_output)
            streamed = build_indicator_summary(run_output, streamed_outputs={"docs"})
            self.assertEqual(
                [(i["type"], i["value"], i["count"]) for i in in_memory["indicators"]],
                [(i["type"], i["value"], i["count"]) for i in streamed["indicators"]],
            )
            self.assertEqual(
                [(h["rule_id"], h["value"]) for h in in_memory["ioc_scanner_hits"]],
                [(h["rule_id"], h["value"]) for h in streamed["ioc_scanner_hits"]],
            )

    def test_output_payloads_skip_file_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            docs_path = write_json(
                Path(tmp_dir) / "docs.json",
                {"command": "docs", "results": [{"path": "/x", "preview": "https://on-disk.example"}]},
            )
            run_output = {"outputs": {"docs": str(docs_path)}}
            payload = build_indicator_summary(
                run_output,
                output_payloads={"docs": self._sample_docs_payload()},
            )
            values = {i["value"] for i in payload["indicators"]}
            self.assertIn("https://malicious.example/login", values)
            self.assertNotIn("https://on-disk.example", values)

    def test_collect_indicators_from_stream_nested_hits_win(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = {
                "command": "artifacts",
                "artifacts": [
                    {
                        "artifact_type": "evt",
                        "path": "/x",
                        "ioc_hits": [{"rule_id": "r1", "type": "hash", "value": "a" * 64, "count": 1}],
                    }
                ],
                "ioc_hits": [{"rule_id": "root", "type": "domain", "value": "root.example"}],
            }
            path = write_json(Path(tmp_dir) / "art.json", payload)
            acc: dict = {}
            scan_acc: dict = {}
            collect_indicators_from_stream(
                path, acc, scan_acc, source={"output": "x"}, max_sources_per_indicator=5
            )
            rules = {key[0] for key in scan_acc}
            self.assertIn("r1", rules)
            self.assertNotIn("root", rules)


class ReusableJsonGuardTests(unittest.TestCase):
    def test_oversized_cached_output_is_not_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = write_json(
                Path(tmp_dir) / "big.json",
                {"command": "files", "summary": {}, "pad": "x" * 2048},
            )
            loaded = load_reusable_json(path, expected_command="files", required_keys=("summary",))
            self.assertIsNotNone(loaded)
            skipped = load_reusable_json(
                path,
                expected_command="files",
                required_keys=("summary",),
                max_load_bytes=64,
            )
            self.assertIsNone(skipped)

    def test_reusable_json_max_bytes_env_override(self) -> None:
        default = reusable_json_max_bytes()
        self.assertGreater(default, 0)


if __name__ == "__main__":
    unittest.main()
