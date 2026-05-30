from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.extract import ExtractError, run_extract


class RapidTriageExtractContractTests(unittest.TestCase):
    def test_extract_preserves_relative_paths_for_duplicate_basenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "alpha").mkdir()
            (root / "beta").mkdir()
            alpha = root / "alpha" / "evidence.txt"
            beta = root / "beta" / "evidence.txt"
            alpha.write_text("alpha", encoding="utf-8")
            beta.write_text("beta", encoding="utf-8")

            files_json = root / "files.json"
            out_dir = root / "extract-out"

            self.assertEqual(main(["files", str(root), "--output", str(files_json)]), 0)
            self.assertEqual(main(["extract", str(files_json), str(out_dir), "--ext", "txt"]), 0)

            manifest = json.loads((out_dir / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
            relative_paths = {entry["relative_path"] for entry in manifest["entries"]}
            self.assertEqual(relative_paths, {"alpha/evidence.txt", "beta/evidence.txt"})
            self.assertEqual((out_dir / "alpha" / "evidence.txt").read_text(encoding="utf-8"), "alpha")
            self.assertEqual((out_dir / "beta" / "evidence.txt").read_text(encoding="utf-8"), "beta")

    def test_extract_rejects_absolute_source_outside_declared_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            evidence_root = workspace / "evidence"
            evidence_root.mkdir()
            outside = workspace / "outside-secret.txt"
            outside.write_text("do not copy", encoding="utf-8")
            files_json = workspace / "files.json"
            files_json.write_text(
                json.dumps(
                    {
                        "command": "files",
                        "root": str(evidence_root),
                        "candidates": [
                            {
                                "path": str(outside),
                                "name": outside.name,
                                "extension": ".txt",
                                "categories": ["documents"],
                                "reasons": [],
                                "size": outside.stat().st_size,
                                "modified_at": "",
                                "modified_epoch": 0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ExtractError):
                run_extract(files_json, workspace / "extract-out", extensions=["txt"])
            self.assertFalse((workspace / "extract-out" / "_external").exists())


if __name__ == "__main__":
    unittest.main()
