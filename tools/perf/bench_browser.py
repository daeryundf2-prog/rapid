"""Generate synthetic browser stores, time the providers, or fingerprint every output row.

Run with the tested checkout on PYTHONPATH. Use the same untouched corpus and
absolute path for both revisions because citations include source file metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import statistics
import tempfile
import time
from collections import Counter
from contextlib import closing
from pathlib import Path

from rapidtriage.artifacts.macos import (
    QUARANTINE_DB,
    SAFARI_HISTORY,
    collect_macos_browsers,
)
from rapidtriage.artifacts.windows.browser import (
    CHROMIUM_BROWSER_ROOTS,
    FIREFOX_PROFILE_ROOT,
    WindowsBrowserArtifactsProvider,
)


def make_store(path: Path, size: int, script: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TEMP TABLE seq(i INTEGER PRIMARY KEY)")
        db.executemany("INSERT INTO seq VALUES (?)", ((i,) for i in range(1, size + 1)))
        db.executescript(script)


def generate(root: Path, visits: int, cookies: int) -> None:
    root.mkdir(parents=True, exist_ok=False)
    user = root / "Users" / "sample"
    chromium = user.joinpath(*dict(CHROMIUM_BROWSER_ROOTS)["chromium"], "Default")
    firefox = user.joinpath(*FIREFOX_PROFILE_ROOT, "sample.default")
    # Ten visits per URL, including referrers later in query order and timestamp ties.
    pages = max(1, visits // 10)
    url = "'https://example.invalid/경로/' || i"
    title = "CASE WHEN i % 7 != 0 THEN '합성 제목 ' || i END"
    make_store(
        chromium / "History",
        visits,
        f"""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER,
                          typed_count INTEGER, visit_count INTEGER);
        INSERT INTO urls SELECT i, {url}, {title}, 13350000000000000+i, 1, 10 FROM seq WHERE i <= {pages};
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER,
                            visit_duration INTEGER, from_visit INTEGER);
        INSERT INTO visits SELECT i, 1+i%{pages}, 13350000000000000+i/2, i%10, i*11, i+1 FROM seq;
        CREATE INDEX visits_url ON visits(url);
    """,
    )
    make_store(
        chromium / "Cookies",
        cookies,
        """
        CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, creation_utc INTEGER,
                             last_access_utc INTEGER, expires_utc INTEGER, last_update_utc INTEGER);
        INSERT INTO cookies SELECT 'example.invalid', 'item'||i, '/', NULL, 13350000000000000+i,
            13350100000000000+i, 13350200000000000+i, 13350000000000000+i FROM seq;
    """,
    )
    make_store(
        chromium / "Login Data",
        128,
        """
        CREATE TABLE logins(id INTEGER PRIMARY KEY, origin_url TEXT, date_created INTEGER, password_value BLOB);
        INSERT INTO logins SELECT i, 'https://example.invalid/', 13350000000000000+i, NULL FROM seq;
    """,
    )
    make_store(
        chromium / "Web Data",
        256,
        """
        CREATE TABLE autofill(name TEXT, value TEXT, count INTEGER, date_created INTEGER, date_last_used INTEGER);
        INSERT INTO autofill SELECT 'field', '합성'||i, i, 1700000000+i, 1700000000+i FROM seq;
    """,
    )
    make_store(
        firefox / "places.sqlite",
        visits,
        f"""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        INSERT INTO moz_places SELECT i, {url}, {title}, 10 FROM seq WHERE i <= {pages};
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER,
                                      visit_type INTEGER, from_visit INTEGER);
        INSERT INTO moz_historyvisits SELECT i, 1+i%{pages}, 1700000000000000+i/2, i%8, i+1 FROM seq;
        CREATE INDEX visits_place ON moz_historyvisits(place_id);
    """,
    )
    make_store(
        firefox / "cookies.sqlite",
        cookies,
        """
        CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, creationTime INTEGER);
        INSERT INTO moz_cookies SELECT 'example.invalid', CASE WHEN i%25=0 THEN '_ga' ELSE 'item'||i END,
            '', 1700000000000000+i FROM seq;
    """,
    )
    make_store(
        user.joinpath(*SAFARI_HISTORY),
        visits,
        f"""
        CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
        INSERT INTO history_items SELECT i, {url}, {title} FROM seq WHERE i <= {pages};
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL);
        INSERT INTO history_visits SELECT i, 1+i%{pages}, 750000000.0+i/2 FROM seq;
        CREATE INDEX visits_item ON history_visits(history_item);
    """,
    )


def fixtures(root: Path) -> None:
    from tests.test_d14_artefacts import build_wal_only_history
    from tests.test_rapidtriage_macos_artifacts import create_quarantine_db

    generate(root, 40, 25)
    with tempfile.TemporaryDirectory(dir=root.parent) as work:
        wal = build_wal_only_history(Path(work), ("wal-profile",))
        shutil.copytree(wal, root, dirs_exist_ok=True)
    user = root / "Users" / "sample"
    quarantine = user.joinpath(*QUARANTINE_DB)
    quarantine.parent.mkdir(parents=True, exist_ok=True)
    create_quarantine_db(quarantine)
    profiles = user.joinpath(*dict(CHROMIUM_BROWSER_ROOTS)["chromium"])
    with closing(sqlite3.connect(profiles / "Default" / "History")) as db:
        db.execute(
            "UPDATE urls SET title=?, last_visit_time=? WHERE id=1",
            ("긴 제목" * 32768, 2**63 - 1),
        )
        db.execute("UPDATE visits SET url=NULL, from_visit=999 WHERE id=1")
        db.commit()
    damaged = profiles / "Damaged"
    damaged.mkdir()
    (damaged / "History").write_bytes(b"SQLite format 3\x00" + b"broken" * 128)


def collect(root: Path):
    yield from WindowsBrowserArtifactsProvider().collect(root)
    for user in sorted((root / "Users").iterdir()):
        yield from collect_macos_browsers(user)


def inventory(root: Path) -> dict:
    result = {}
    for path in root.rglob("*"):
        if path.is_file():
            stat = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[path.relative_to(root)] = (
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
                digest.digest(),
            )
    return result


def fingerprints(root: Path, output: Path) -> None:
    # One digest per complete JSON row in emission order. Include even empty
    # values, nested manifests, evidence hashes, locators and parser errors.
    if output.resolve().is_relative_to(root):
        raise ValueError("fingerprints must be written outside the evidence tree")
    before = inventory(root)
    counts = Counter()
    with output.open("x", encoding="ascii") as handle:
        for record in collect(root):
            counts[record.artifact_type] += 1
            data = json.dumps(
                record.to_dict(), ensure_ascii=True, separators=(",", ":")
            ).encode("ascii")
            handle.write(hashlib.sha256(data).hexdigest() + "\n")
    if inventory(root) != before:
        raise ValueError("evidence files, metadata or contents changed")
    if not counts:
        raise ValueError("provider returned no rows")
    print(
        json.dumps(
            {"rows": counts.total(), "counts": counts, "evidence_files": len(before)}
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("generate")
    create.add_argument("root", type=Path)
    create.add_argument("--visits", type=int, default=100_000)
    create.add_argument("--cookies", type=int, default=50_000)
    sub.add_parser("fixtures").add_argument("root", type=Path)
    run = sub.add_parser("time")
    run.add_argument("root", type=Path)
    run.add_argument("--runs", type=int, default=3)
    diff = sub.add_parser("fingerprint")
    diff.add_argument("root", type=Path)
    diff.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "generate":
        if min(args.visits, args.cookies) < 1:
            parser.error("row counts must be positive")
        generate(root, args.visits, args.cookies)
    elif args.command == "fixtures":
        fixtures(root)
    elif args.command == "fingerprint":
        fingerprints(root, args.output)
    else:
        if args.runs < 1:
            parser.error("runs must be positive")
        samples = []
        for _ in range(args.runs):
            start = time.perf_counter()
            counts = Counter(record.artifact_type for record in collect(root))
            samples.append(time.perf_counter() - start)
            print(json.dumps({"seconds": samples[-1], "counts": counts}), flush=True)
        print(json.dumps({"median_seconds": statistics.median(samples)}))


if __name__ == "__main__":
    main()
