"""Hash search (plan §3.2 search/hashes, /api/hash-sets): 10k mixed hashes, NSRL sets, -hashset."""

from __future__ import annotations

import hashlib
import json
import os
import random
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.search_index.build import build_search_index, index_meta
from rapidtriage.core.search_index.engine import (
    Budget,
    QueryRequest,
    SearchOptions,
    run_hashes,
    run_query,
)
from rapidtriage.core.search_index.hashsets import (
    DATA_DIR_ENV,
    HashSetError,
    create_hash_set,
    delete_hash_set,
    hash_set_path,
    list_hash_sets,
    read_hash_set,
    read_hash_values,
)
from rapidtriage.core.search_index.schema import INDEX_FILE_NAME
from rapidtriage.core.search_index.textutil import normalize_hash
from tests.search_index_fixture import build_fixture_run

FILE_COUNT = 5000


def _hashes(seed: str) -> dict[str, str]:
    data = seed.encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class HashSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        cls.data_dir = base / "data"
        cls.env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(cls.data_dir)})
        cls.env.start()
        cls.fixture = build_fixture_run(base)
        run_dir = cls.fixture["run_dir"]
        files_path = Path(cls.fixture["summary"]["outputs"]["files"])
        files = json.loads(files_path.read_text(encoding="utf-8"))
        cls.file_hashes = [_hashes(f"file-{index}") for index in range(FILE_COUNT)]
        for index, hashes in enumerate(cls.file_hashes):
            files["candidates"].append(
                {"path": str(cls.fixture["evidence"] / "bulk" / f"f{index}.bin"), "name": f"f{index}.bin", "size": index, "categories": ["other"], "hashes": hashes}
            )
        files_path.write_text(json.dumps(files, ensure_ascii=False), encoding="utf-8")
        build_search_index(run_dir, cls.fixture["summary"], run_id="hashes")
        cls.index = run_dir / INDEX_FILE_NAME
        cls.meta = index_meta(cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.env.stop()
        cls.temp.cleanup()

    def query_total(self, q: str, **kwargs: object) -> int:
        result = run_query(self.index, self.meta, QueryRequest(q=q, **kwargs), budget=Budget(15), hashset_resolver=hash_set_path)
        return int(result["page"]["total"])

    def test_ten_thousand_mixed_hashes(self) -> None:
        rng = random.Random(7)
        wanted: list[str] = []
        for index, hashes in enumerate(self.file_hashes):
            wanted.append(hashes[("md5", "sha1", "sha256")[index % 3]])
        wanted.extend(_hashes(f"absent-{index}")[("md5", "sha1", "sha256")[index % 3]] for index in range(FILE_COUNT))
        rng.shuffle(wanted)
        pairs = [normalize_hash(value) for value in wanted]
        started = time.monotonic()
        result = run_hashes(self.index, self.meta, [pair for pair in pairs if pair is not None], budget=Budget(15))
        elapsed = time.monotonic() - started
        self.assertEqual(result["matched_count"], FILE_COUNT)
        self.assertEqual(result["unmatched_count"], FILE_COUNT)
        self.assertLess(elapsed, 10.0)  # plan target 3 s on the real run; loose bound for CI
        sample = result["matched"][0]
        self.assertEqual(sample["docs"][0]["collection"], "files")
        self.assertIn(sample["algorithm"], {"md5", "sha1", "sha256"})

    def test_artifact_analysis_and_indicator_hashes_match(self) -> None:
        exe = self.fixture["exe_hashes"]
        pairs = [normalize_hash(exe["sha256"]), normalize_hash(self.fixture["carve_hash"]), normalize_hash("0000" + exe["sha1"])]
        result = run_hashes(self.index, self.meta, [pair for pair in pairs if pair is not None], budget=Budget(15))
        collections = {row["hash"]: sorted(doc["collection"] for doc in row["docs"]) for row in result["matched"]}
        self.assertEqual(collections[exe["sha256"]], ["files", "indicators"])
        self.assertEqual(collections[self.fixture["carve_hash"]], ["analysis"])
        self.assertEqual(collections[exe["sha1"]], ["files"])  # Amcache-style 0000+SHA1 normalizes

    def test_nsrl_hash_set_and_exclusion(self) -> None:
        exe = self.fixture["exe_hashes"]
        lines = ['"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"']
        lines.append(f'"{exe["sha1"].upper()}","{exe["md5"].upper()}","0000ABCD","AnyDesk.exe",68,1,"WIN",""')
        for index in range(1, 100):
            hashes = self.file_hashes[index]
            lines.append(f'"{hashes["sha1"].upper()}","{hashes["md5"].upper()}","00000000","f{index}.bin",{index},1,"WIN",""')
        lines.append('"","","00000000","empty.bin",0,1,"WIN",""')
        summary = create_hash_set(name="NSRL 일부", label="known-good", data="\n".join(lines).encode("utf-8"), filename="NSRLFile.txt")
        self.assertEqual(summary["format"], "nsrl-rds-csv")
        self.assertEqual(summary["count_by_algorithm"], {"md5": 100, "sha1": 100})
        self.assertEqual(summary["rejected_count"], 1)
        self.assertEqual(summary["rejected_lines"][0]["line"], 102)
        self.assertEqual(read_hash_set(summary["id"])["name"], "NSRL 일부")
        self.assertIn(summary["id"], [item["id"] for item in list_hash_sets()])
        self.assertEqual(len(read_hash_values(summary["id"])), 200)

        self.assertEqual(self.query_total(f"hashset:{summary['id']}"), 100)
        everything = self.query_total("in:files")
        self.assertEqual(self.query_total(f"in:files -hashset:{summary['id']}"), everything - 100)
        hidden = self.query_total("in:files", options=SearchOptions(hide_hashsets=[summary["id"]]))
        self.assertEqual(hidden, everything - 100)
        by_set = run_hashes(self.index, self.meta, read_hash_values(summary["id"]), budget=Budget(15))
        self.assertEqual(by_set["matched_count"], 200)  # 100 files x (sha1 + md5)

        delete_hash_set(summary["id"])
        self.assertIsNone(hash_set_path(summary["id"]))
        with self.assertRaises(HashSetError) as caught:
            read_hash_set(summary["id"])
        self.assertEqual(caught.exception.status, 404)

    def test_text_hash_set_rejects_lines(self) -> None:
        text = "# 수사기관 제공 목록\n" + self.file_hashes[0]["sha256"] + "\n" + "not a hash\n\n" + self.file_hashes[1]["md5"].upper() + "  file1\n"
        summary = create_hash_set(name="custom", label="known-bad", data=text.encode("utf-8"))
        self.assertEqual(summary["format"], "text")
        self.assertEqual(summary["count_by_algorithm"], {"md5": 1, "sha256": 1})
        self.assertEqual(summary["rejected_lines"], [{"line": 3, "reason": "해시(MD5·SHA-1·SHA-256 16진수)가 없습니다", "text": "not a hash"}])
        self.assertEqual(self.query_total(f"hashset:{summary['id']}"), 2)

    def test_hash_set_validation(self) -> None:
        with self.assertRaises(HashSetError):
            create_hash_set(name="x", label="weird", data=b"a" * 32)
        with self.assertRaises(HashSetError):
            create_hash_set(name="", label="custom", data=b"a" * 32)
        with self.assertRaises(HashSetError):
            create_hash_set(name="x", label="custom", data=b"nothing here")
        with self.assertRaises(HashSetError) as caught:
            create_hash_set(name="x", label="custom", data=b"0" * (50 * 1024 * 1024 + 1))
        self.assertEqual(caught.exception.status, 413)
        self.assertIsNone(hash_set_path("../../etc/passwd"))


if __name__ == "__main__":
    unittest.main()
