from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


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


if __name__ == "__main__":
    unittest.main()
