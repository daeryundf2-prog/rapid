"""Compare allocated NTFS file metadata and selected collector rows on the public images."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rapidtriage.core.artifact_profiles import iter_payload_records

FAMILIES = ("files", "size", "macb", "registry", "eventlog", "history_db", "moz_places", "moz_historyvisits")
HIVES = {"sam", "security", "software", "system", "default", "ntuser.dat", "usrclass.dat"}
METADATA = {"$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot",
            "$BadClus", "$Secure", "$UpCase", "$Extend", "$OrphanFiles"}


def ordinary_path(path):
    return path.split("/")[0] not in METADATA and ":" not in path.rsplit("/", 1)[-1]


def nfc(path):
    return unicodedata.normalize("NFC", str(path))


def file_keys(groups, path, size, times):
    groups["files"][(path,)] += 1
    groups["size"][(path, size)] += 1
    groups["macb"][(path, *times)] += 1


def reference_rows(args):
    groups = {family: Counter() for family in FAMILIES}
    with args.body.open(encoding="utf-8") as body:
        for line in body:
            # Split off the leading hash, then work from the right so a pipe in a name survives.
            _, tail = line.rstrip("\n").split("|", 1)
            name, address, mode, _, _, size, atime, mtime, ctime, birth = tail.rsplit("|", 9)
            path = nfc(name.removeprefix("/"))
            if not (mode.startswith("r/r") and re.fullmatch(r"\d+-128-\d+", address) and ordinary_path(path)):
                continue
            file_keys(groups, path, int(size), map(int, (mtime, atime, ctime, birth)))
            leaf = path.rsplit("/", 1)[-1].lower()
            if leaf in HIVES:
                groups["registry"][(path,)] += 1
            if leaf.endswith((".evt", ".evtx")):
                groups["eventlog"][(path,)] += 1
            if leaf != "places.sqlite":
                continue
            groups["history_db"][(path,)] += 1
            with tempfile.TemporaryDirectory(dir=args.output.parent) as temp:
                db = Path(temp) / "places.sqlite"
                with db.open("wb") as out:
                    subprocess.run(["icat", "-o", str(args.sector), args.image, address], stdout=out, check=True)
                if db.stat().st_size != int(size):
                    raise ValueError(f"incomplete icat export of {address}")
                for table in ("moz_places", "moz_historyvisits"):
                    ids = subprocess.check_output(["sqlite3", "-readonly", db, f"SELECT id FROM {table}"], text=True)
                    groups[table].update((path, int(i)) for i in ids.splitlines())
    return groups


def epoch(text):
    if not text:
        return None
    instant = dt.datetime.fromisoformat(text)
    return int(instant.timestamp()) if instant.utcoffset() is not None else None


def rapid_rows(run):
    groups = {family: Counter() for family in FAMILIES}
    files = json.loads((run / "rapidtriage-files.json").read_text())
    root = Path(files["root"])
    for row in files["candidates"] + files["inventory"]:
        path = nfc(row["relative_path"])
        if row.get("is_deleted") is True or not ordinary_path(path):
            continue
        times = [epoch(row.get("fs_" + field + "_at")) for field in ("modified", "accessed", "changed", "created")]
        file_keys(groups, path, row["size"], times)
    db_paths = set()
    for kind in ("windows-registry", "eventlog", "browser"):
        head = run / "artifacts" / f"rapidtriage-artifacts-{kind}.json"
        payload = json.loads(head.read_text())
        count = 0
        for row in iter_payload_records(payload, payload_path=head):
            count += 1
            typ = row["artifact_type"]
            if typ not in {"registry-hive", "eventlog-file", "browser-history", "browser-visit"}:
                continue
            path = nfc(Path(row["path"]).relative_to(root).as_posix())
            leaf = path.rsplit("/", 1)[-1].lower()
            if typ == "registry-hive" and leaf in HIVES:
                groups["registry"][(path,)] += 1
            elif typ == "eventlog-file" and leaf.endswith((".evt", ".evtx")):
                groups["eventlog"][(path,)] += 1
            elif leaf == "places.sqlite":
                db_paths.add((path,))
                table = row["details"].get("source_table")
                if table in ("moz_places", "moz_historyvisits"):
                    groups[table][(path, int(row["details"]["source_row_id"]))] += 1
        if count != payload["record_count"]:
            raise ValueError(f"incomplete {kind} row stream")
    groups["history_db"].update(db_paths)
    return groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--sector", type=int, required=True)
    parser.add_argument("--body", type=Path, required=True, help="allocated fls -r -u -m / body file")
    parser.add_argument("--output", type=Path, required=True, help="private row-level JSONL file in the run workspace")
    args = parser.parse_args()
    reference = reference_rows(args)
    rapid = rapid_rows(args.run)
    with args.output.open("w", encoding="utf-8") as output:
        for family in FAMILIES:
            left, right = rapid[family], reference[family]
            results = {"matches": left & right, "rapid_only": left - right, "tool_only": right - left}
            print(family, *(counts.total() for counts in results.values()))
            for status, rows in results.items():
                for key, count in rows.items():
                    output.write(json.dumps([family, status, key, count]) + "\n")


if __name__ == "__main__":
    main()
