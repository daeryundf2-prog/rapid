# Public Windows disk image validation

On 2026-11-22 Rapid ingested two hash-verified E01 images on macOS. The NTFS test volume exercises sector-zero recovery and timestamps. The partitioned Windows XP system adds user profiles, registry hives, browser databases and event logs. The total download was 3,075,833,939 bytes. Both runs used the public CLI, recovered allocated and deleted entries, and ran every collector in scope. The expanded system disk is 10 GiB.

## Sources and integrity

| Image segment | Bytes | Published MD5 | Published SHA-1 |
| --- | ---: | --- | --- |
| [NTFS test volume, generation 2](https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ntfs1/ntfs1-gen2.E01) | 36,083,007 | `5e28d70f86f8e105fec78a89b0cbea63` | `8f99ee7f0a31e4c1dbd120db67973a19a578d212` |
| [M57 system, segment 1](https://downloads.digitalcorpora.org/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E01) | 1,572,860,321 | `647f22836426e071d8e1ccac6da54baf` | `c0e06707c0326d33f1de6c985745bc9d03925e24` |
| [M57 system, segment 2](https://downloads.digitalcorpora.org/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E02) | 1,466,890,611 | `e8845c20bdd2c24e734b7c0bcd1a8eab` | `85bdcef6390d18fca1292a2fefc15f924b54c5fc` |

All three sizes, MD5s and SHA-1s matched the publisher's manifest. Independently of the segment checks, `ewfverify` matched the stored media MD5 for each image. The NTFS digest was `27a9053e35aac74608493e755353cb95`. The system-disk digest was `78a52b5bac78f4e711607707ac0e3f93`. [Published hashdeep manifest](https://downloads.digitalcorpora.org/corpora/hashes/digitalcorpora.org-hashdeep-2020-08-01.csv)

Digital Corpora permits use of its public disk images for forensic research and education without prior authorization. Its NPS terms place NPS-created content in the public domain. Third-party material may retain copyright. This report publishes aggregate observations only. Attribution for the corpus methodology is Garfinkel, Farrell, Roussev and Dinolt, *Bringing Science to Digital Forensics with Standardized Forensic Corpora*, DFRWS 2009. [Use terms](https://digitalcorpora.org/) · [NPS rights and attribution](https://digitalcorpora.org/corpora/disk-images/) · [NTFS image narrative](https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ntfs1/narrative.txt) · [M57 scenario](https://digitalcorpora.org/corpora/scenarios/m57-jean/)

## Reproduction

Run from the repository root with a project Python 3.12 environment. These commands use macOS `md5`, `shasum`, libewf 20140816, Sleuth Kit 4.14.0 and SQLite 3.54.0. Use fresh output directories. Keep private filenames, row streams, and recovered material under the ignored directory.

```bash
set -eu
D=.rapid-images
git check-ignore "$D/probe"
mkdir -p "$D/tmp"
export TMPDIR="$PWD/$D/tmp" TZ=UTC
base=https://downloads.digitalcorpora.org/corpora
curl -fLsS "$base/hashes/digitalcorpora.org-hashdeep-2020-08-01.csv" -o "$D/published.csv"
for key in nps-2009-ntfs1/ntfs1-gen2.E01 nps-2008-m57-jean/nps-2008-jean.E01 nps-2008-m57-jean/nps-2008-jean.E02; do
  file="$D/${key##*/}"
  curl -fLsS "$base/drives/$key" -o "$file"
  expected=$(awk -F, -v suffix="/corpora/drives/$key" 'index($4,suffix) && substr($4,length($4)-length(suffix)+1)==suffix {print $1,$2,$3}' "$D/published.csv")
  actual="$(stat -f %z "$file") $(md5 -q "$file") $(shasum -a 1 "$file" | cut -d' ' -f1)"
  test "$expected" = "$actual"
done
ntfs="$D/ntfs1-gen2.E01"
system="$D/nps-2008-jean.E01"
ewfverify -q "$ntfs"
ewfverify -q "$system"
fsstat -o 0 "$ntfs" > "$D/ntfs-fsstat.txt"
mmls "$system" > "$D/xp-partitions.txt"

python -m rapidtriage run "$ntfs" --mode seizure --read-only --e01-partition-start-sector 0 \
  --skip-task kakaotalk-windows --skip-task kakaotalk-macos --output-dir "$D/volume-checked"
python -m rapidtriage run "$system" --mode fraud --read-only --e01-partition-start-sector 63 --no-case-db \
  --skip-task kakaotalk-windows --skip-task kakaotalk-macos --output-dir "$D/system-checked"

compare_image() {
  tag=$1 image=$2 sector=$3 run=$4
  fls -r -u -m / -z UTC -o "$sector" "$image" > "$D/$tag-allocated.body"
  fls -r -m / -z UTC -o "$sector" "$image" > "$D/$tag-all.body"
  mactime -z UTC -d -b "$D/$tag-allocated.body" > "$D/$tag-mactime.csv"
  python scripts/public-image-diff.py --run "$D/$run" --image "$image" --sector "$sector" \
    --body "$D/$tag-allocated.body" --output "$D/$tag-checked-rows.jsonl"
}
compare_image ntfs "$ntfs" 0 volume-checked
compare_image xp "$system" 63 system-checked
```

The raw-volume regression was also exercised with `ewfexport -u -q -t "$D/ntfs" "$ntfs"`, followed by the volume command above using `"$D/ntfs.raw"` and a fresh output directory. Automatic and explicit sector-zero raw selection both completed. The system run omitted the optional case database. Its collectors, document scan, file inventory and timeline ran on the complete recovered tree.

## Row comparisons

The file comparison uses each occurrence of an exact, Unicode-NFC, case-sensitive relative path in an allocated ordinary NTFS file's unnamed data stream. Directories, filesystem metafiles, named streams and the separate NTFS filename-attribute timestamps are outside this denominator. The reference contains 79 allocated body records on the volume and 65,554 on the system disk before filtering. Rapid's side includes candidates and inventory. It excludes confirmed deleted rows and retains rows with unknown allocation so extra rows remain visible. Each difference file stores the family, match status, row key and multiplicity.

MACB compares the tuple of modification, access, metadata change and creation times in UTC epoch seconds. Missing offsets remain unknown. Presence checks use exact file paths. The hive scope covers SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT, NTUSER.DAT and UsrClass.dat. The event-log scope covers EVT and EVTX. Browser presence requires that the collector actually produced a record for that database. For Firefox, the script independently exports each allocated `places.sqlite` by its image attribute address with `icat -o 63` and runs `sqlite3 -readonly` with `SELECT id FROM moz_places` and `SELECT id FROM moz_historyvisits`. It compares database path, table and primary key, preserving duplicates and excluding aggregate browser rows. Neither database had a corresponding allocated WAL. Row identity does not establish URL, title or event-field fidelity.

| Row identity | NTFS matches | Rapid only | Tool only | System matches | Rapid only | Tool only |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| File path | 19 | 0 | 0 | 30,939 | 604 | 6 |
| File path and byte length | 19 | 0 | 0 | 30,933 | 610 | 12 |
| File path and four MACB times | 19 | 0 | 0 | 30,933 | 610 | 12 |
| Selected registry hive path | 0 | 0 | 0 | 22 | 0 | 0 |
| Event log file path | 0 | 0 | 0 | 3 | 0 | 0 |
| Firefox history database path | 0 | 0 | 0 | 2 | 0 | 0 |
| Firefox places row ID | 0 | 0 | 0 | 543 | 0 | 0 |
| Firefox visit row ID | 0 | 0 | 0 | 520 | 0 | 0 |

Of 30,945 allocated system paths, 30,939 match exactly. The six reference-only names have case-only counterparts in the export. Of 604 Rapid-only spellings, 603 also occur under a deleted name in the all-entries listing after case folding. A name match alone does not identify the bytes. Six additional shared paths have conflicting byte lengths and therefore lack attributed MACB times in the final run. File-size and MACB differences use separate multiset counts, so a conflicting shared path contributes one row to each exclusive column. The NTFS test volume has no operating-system hives, event logs or Firefox databases.

## Collectors

The registry in this checkout contains 30 providers. The two product-specific providers excluded in the brief were disabled before both image runs. The table covers the remaining 28. Times are per-provider elapsed milliseconds from the scheduler, which runs providers concurrently. Rows include summaries, candidates and inventory. A zero reports the output of this run. The parser-error count comes from the collector summary.

| Collector | NTFS rows | NTFS ms | System rows | System ms | Emitted artifacts |
| --- | ---: | ---: | ---: | ---: | --- |
| android-apk | 0 | 86 | 0 | 341 | None |
| browser | 0 | 100 | 1,111 | 22,541 | browser-analytics-cookie, browser-history, browser-storage-inventory, browser-visit, location-url-candidate |
| cloud-export | 0 | 40 | 0 | 159 | None |
| cloud-sync | 0 | 81 | 0 | 88 | None |
| email | 0 | 38 | 6 | 11,886 | email-container-inventory, email-mailbox |
| email-clients | 0 | 108 | 0 | 1,132 | None |
| eventlog | 0 | 37 | 4 | 12,708 | eventlog-file, eventlog-summary |
| generic-documents | 6 | 187 | 37 | 5,497 | archive-file-inventory, document-metadata-risk |
| linux-system | 0 | 41 | 0 | 123 | None |
| macos-system | 0 | 17 | 0 | 165 | None |
| media-image | 3 | 222 | 5,695 | 40,855 | media-audio, media-image, media-image-unreadable, media-video |
| media-player | 0 | 68 | 0 | 96 | None |
| memory-volatility | 0 | 96 | 1 | 3,135 | disk-memory-file-indicators |
| mobile-export | 0 | 22 | 0 | 2,824 | None |
| p2p | 0 | 44 | 0 | 291 | None |
| recent-files | 0 | 22 | 144 | 26,026 | shell-shortcut |
| synthetic-media | 1 | 142 | 1 | 93 | synthetic-media-scan-status |
| windows-execution | 0 | 33 | 491 | 30,330 | bam-string-candidate, shimcache-string-candidate, userassist-schema-entry, windows-execution-summary |
| windows-filesystem | 4 | 147 | 425 | 61,038 | ads-stream-candidate, file-signature-mismatch, zone-identifier |
| windows-messenger | 0 | 47 | 0 | 158 | None |
| windows-os-account | 0 | 16 | 34 | 12,306 | windows-sam-account, windows-sam-group |
| windows-phone-link | 0 | 52 | 0 | 142 | None |
| windows-prefetch | 0 | 36 | 8,285 | 33,980 | prefetch-file, prefetch-reference |
| windows-registry | 0 | 20 | 108,595 | 25,798 | Hive inventory and strings, key tree, activity, configuration, persistence and recovery candidates (23 hive rows, including one outside the comparison names) |
| windows-remote-access | 0 | 89 | 0 | 467 | None |
| windows-search-index | 0 | 13 | 0 | 199 | None |
| windows-shellbags | 0 | 25 | 29 | 12,181 | shellbag-entry, shellbag-hive-summary |
| windows-system | 0 | 95 | 32 | 5,365 | bits-qmgr-transfer-candidate, credential-store-presence, webshell-source-candidate |

Both runs reported zero collector crashes and zero parser errors. The volume emitted 14 rows and the system emitted 124,890. The synthetic-media collector returned a single skipped-status row per image because its optional classifier was unavailable. The volume also had one unreadable media row. The system run disclosed bounded signature findings, memory-indicator pivots, registry strings and Prefetch references. Its secondary silent-failure check reached its 20,000-file inventory cap. These disclosures limit depth claims even when a collector completed.

To inspect the exact artifact types and counts behind each total, run:

```bash
python - <<'PY'
import json
from pathlib import Path
for run in ("volume-checked", "system-checked"):
    root = Path(".rapid-images") / run
    plan = json.loads((root / "rapidtriage-run-plan.json").read_text())
    for group in plan["groups"]:
        for task in group["tasks"]:
            if task["type"] != "provider" or task["status"] == "skipped":
                continue
            path = root / "artifacts" / f"rapidtriage-artifacts-{task['id']}.json"
            summary = json.loads(path.read_text())["summary"]
            print(run, task["id"], task["status"], task["duration_ms"],
                  summary["artifact_count"], summary["parser_error_count"], summary["artifact_type_counts"])
PY
```

## Defects reproduced

- On this Mac the installed `ewfmount` reports `No sub system to mount EWF format.`. Rapid now records that failed attempt and uses direct Sleuth Kit access after a successful partition or filesystem probe. Both E01s completed through this route.
- The raw NTFS volume has no partition table. An explicit zero offset previously stopped with `mmls failed for raw/split image:`. Rapid now accepts that offset after positive filesystem identification and can reuse a verified zero-offset checkpoint.
- The macOS `fls -l -z UTC` output contained KST wall times nine hours ahead of the reference epochs. Before the timestamp correction, all 19 volume records lacked a usable UTC tuple. Fresh macOS long listings use a UTC child environment. Readers withhold ambiguous local timestamps in older listings. Earlier materialized reports need regeneration.
- The system disk uses the legacy profile layout. Rapid originally emitted zero rows from two Firefox databases containing 75 and 468 places, and 39 and 481 visits. Both databases are now discovered. The three legacy EVT files originally yielded zero file records. Signature-checked inventory now surfaces each file and identifies the unsupported event decoding.
- The file inventory dropped 104 zero-length names outside the active scan categories despite having their metadata in the extraction listing. File inventory now retains excluded sidecar rows with their listing times and inode.
- At six reused paths, allocated and deleted versions had different lengths. Direct `icat` SHA-256 comparisons showed all six exported byte streams matched the deleted version and none matched the allocated version. The matcher now withholds the allocated inode when the exported length contradicts that listing at a reused path. An older completed extraction checkpoint can contain the previous inode map. Use fresh stages to reproduce these results.

The following reproduces the six content checks from the repository root. The first address in each pair is the allocated data stream. The second is the deleted stream. The expected result is six lines of `allocated=False deleted=True`.

```bash
python - <<'PY_HASH'
import hashlib
import subprocess
from pathlib import Path

d = Path(".rapid-images")
root = d / "system-checked/_e01/fs"
paths = {}
for line in (d / "xp-allocated.body").read_text().splitlines():
    fields = line.split("|", 1)[1].rsplit("|", 9)
    paths[fields[1]] = fields[0].removeprefix("/")
for allocated, deleted in [
    ("17871-128-3", "17621-128-3"), ("23572-128-3", "9866-128-1"),
    ("18423-128-3", "2036-128-3"), ("18422-128-3", "2032-128-3"),
    ("20046-128-3", "1486-128-3"), ("18717-128-3", "2098-128-3"),
]:
    observed = hashlib.sha256((root / paths[allocated]).read_bytes()).digest()
    def matches(address):
        data = subprocess.check_output(["icat", "-o", "63", d / "nps-2008-jean.E01", address])
        return hashlib.sha256(data).digest() == observed
    print(f"allocated={matches(allocated)} deleted={matches(deleted)}")
PY_HASH
```

## Release evidence

These are engineering measurements from one macOS host, two public images and one TSK build. The E01 extractor also uses TSK. The separate body-file traversal checks Rapid's handling of that listing but shares the underlying NTFS implementation. SQLite supplies an independent SQL comparison. The run adds no clean Windows 11 or Ex01 execution, independent parser implementation or reviewer signoff, contemporary EVTX validation, scale evidence or release-operations evidence. `commercial_claim_allowed=false`.

## Round two — Windows 10

The source is the simulated hard-drive case in NISTIR 8412. NIST supplied it for forensic examiners to analyze with tools of their choice. The archive contains an acquisition receipt and fourteen E01 segments. The NIST data terms request attribution and cover rights NIST holds. Third-party software in the image retains its own rights. Only aggregate measurements are published here. [Study and archive reference, hard-drive case and reference 12](https://doi.org/10.6028/NIST.IR.8412) · [NIST data-use terms](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications)

The transport checks below use the study download signatures as reproduced in the 2020 study announcement. The independent media check uses the MD5 and SHA-1 in the acquisition receipt included with the archive. [Published archive signatures](https://dforensic.blogspot.com/2020/06/nist-scientific-foundation-study-for.html)

Round two reused the 14 verified segments already in private storage. The earlier acquisition checked the 20,252,022,199-byte archive (MD5 `c1128ffc1c0582234d3a6fbb3a762d11`, SHA-1 `795c2fd3632e5dc76cb4acfc9e42a948f73599a0`, SHA-256 `8501aa9ba74fd4410489c8b2e1b120aa27c1bb8bac4c740f73ba708fff836445`). The segments total 20,473,205,185 bytes. The retained `ewfverify` log reports success and agrees with the acquisition receipt on media MD5 `b5ae724f3c01a1daf94be64aa2cde231` and SHA-1 `5275781b4e7349b289d08a3152d3b885579be762`.

The acquisition contains 265,148,416 sectors of 512 bytes. Sleuth Kit recognized NTFS at sector zero. Reading the allocated SOFTWARE hive with python-registry identified Windows 10 Enterprise Evaluation, release 1903, build 18362.356.

Use fresh output directories under ignored storage for the commands below. The input is the existing segment set. The commands read the NTFS listing and export selected allocated streams. The Python environment for this run included python-registry 1.3.1, python-evtx 0.8.1 and dissect.eventlog 3.11.

```bash
set -eu
D="$PWD/.rapid-images"
git check-ignore .rapid-images/probe
mkdir -p "$D/tmp"
export TMPDIR="$D/tmp" TZ=UTC
. .venv/bin/activate
image="$D/Logical/Strongwill.E01"
ewfverify -q -d sha1 "$image" > "$D/win10-ewfverify.txt"
fsstat -o 0 "$image" > "$D/win10-fsstat.txt"
fls -r -u -m / -z UTC -o 0 "$image" > "$D/win10-allocated.body"
# Independent export of live hives and the allocated Logs directory.
python scripts/public-windows-reference-export.py --body "$D/win10-allocated.body" \
  --image "$image" --sector 0 --output "$D/ref" --max-bytes 250000000
# A separate target tree for Rapid, with browser databases and their journals.
python scripts/public-windows-reference-export.py --body "$D/win10-allocated.body" \
  --image "$image" --sector 0 --output "$D/win10-target-source" --max-bytes 200000000 \
  --include-browser --event-log Security.evtx --event-log System.evtx \
  --event-log 'Windows PowerShell.evtx' --event-log 'Microsoft-Windows-PowerShell%4Operational.evtx' \
  --event-log 'Microsoft-Windows-Partition%4Diagnostic.evtx' --event-log 'Microsoft-Windows-Kernel-PnP%4Configuration.evtx' \
  --event-log 'Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx' --event-log 'Microsoft-Windows-USB-*.evtx'
run="$D/win10-target-run"
python -m rapidtriage run "$D/win10-target-source" --mode fraud --read-only \
  --no-case-db --skip-task kakaotalk-windows --skip-task kakaotalk-macos --output-dir "$run"
python scripts/registry-value-diff.py --run "$run" --hive-root "$D/ref" > "$D/a2-registry.json"
python scripts/public-evtx-diff.py --run "$run" \
  --reference-logs "$D/ref/Windows/System32/winevt/Logs" > "$D/a2-evtx.json"
```

The allocated `fls` traversal yielded 775,122 body rows. The exporter selected unnamed data streams, used `icat` at their attribute addresses and checked each exported length. The independent export contained SAM, SYSTEM, SOFTWARE, two profile hives and 163 EVTX files. The 19-file Rapid input contained the same five hives, six selected event logs, four Chromium databases and four rollback journals, totaling 136,964,096 bytes. All 11 overlapping hives and logs matched by SHA-256. Both exports use the same NTFS implementation. DriverFrameworks Operational and USB-prefixed channels were absent from the allocated Logs directory.

### Windows 10 collector results

The folder run completed through the CLI report stage. Rapid inventoried 19 files, emitted 14,140 timeline events and produced 363,701 collector rows. Each row below represents a completed provider. Zero rows apply only to the selected input. Counts include inventory, detections and summaries. The folder export preserves the selected paths and file bytes. Its host filesystem timestamps cannot validate NTFS MACB times. Two registry string-scan rows reported truncation, and 77 event rows had truncated message previews, including 49 with truncated event-data previews.

| Collector | Rows | Elapsed ms | Parser errors |
| --- | ---: | ---: | ---: |
| windows-os-account | 26 | 181 | 0 |
| windows-registry | 348,723 | 43,372 | 0 |
| windows-shellbags | 3 | 367 | 0 |
| windows-execution | 505 | 1,193 | 0 |
| windows-prefetch | 0 | 63 | 0 |
| recent-files | 0 | 433 | 0 |
| eventlog | 14,441 | 29,745 | 0 |
| windows-filesystem | 0 | 1,051 | 0 |
| windows-search-index | 0 | 188 | 0 |
| browser | 2 | 13,366 | 0 |
| p2p | 0 | 254 | 0 |
| email | 0 | 298 | 0 |
| windows-messenger | 0 | 347 | 0 |
| mobile-export | 0 | 161 | 0 |
| email-clients | 0 | 233 | 0 |
| cloud-export | 0 | 187 | 0 |
| cloud-sync | 0 | 208 | 0 |
| media-image | 0 | 138 | 0 |
| generic-documents | 0 | 102 | 0 |
| synthetic-media | 1 | 184 | 0 |
| media-player | 0 | 274 | 0 |
| windows-remote-access | 0 | 228 | 0 |
| windows-system | 0 | 607 | 0 |
| memory-volatility | 0 | 253 | 0 |
| android-apk | 0 | 274 | 0 |
| windows-phone-link | 0 | 300 | 0 |
| linux-system | 0 | 378 | 0 |
| macos-system | 0 | 301 | 0 |

All four rollback journals were empty. Read-only immutable SQLite counts on the selected browser databases returned one cookie and zero rows in the URLs, visits, downloads, logins and autofill tables. Rapid emitted one cookie and one storage inventory row. This checks browser counts only.

The following prints the collector table inputs and SQLite counts without emitting recovered values.

```bash
python - "$run" "$D/win10-target-source" <<'PY_CHECK'
import json, sqlite3, sys
from pathlib import Path

run, source = map(Path, sys.argv[1:])
plan = json.loads((run / "rapidtriage-run-plan.json").read_bytes())
for group in plan["groups"]:
    for task in group["tasks"]:
        if task["type"] == "provider" and task["status"] != "skipped":
            report = run / "artifacts" / f"rapidtriage-artifacts-{task['id']}.json"
            totals = json.loads(report.read_bytes())["summary"]
            print(task["id"], task["status"], totals["artifact_count"],
                  task["duration_ms"], totals["parser_error_count"])
tables = {"History": ("urls", "visits", "downloads"), "Login Data": ("logins",),
          "Web Data": ("autofill",), "Cookies": ("cookies",)}
for path in source.rglob("*"):
    if path.name in tables and path.is_file():
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            for table in tables[path.name]:
                print(table, db.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
        finally:
            db.close()
PY_CHECK
```

### Windows 10 registry values

The round-two comparison joined five live hives by relative path and SHA-256. Within each family it compared projected values as multisets, using case-insensitive key paths and value names. A projection such as a Run command retains text. The collector row does not preserve the original registry type tag for that field. SYSTEM projections use the control set selected by the hive. A differing pair shares its identity and disagrees on the projected values.

| Artifact family and projection | Hives compared | Matched | Differing | Rapid only | Reader only |
| --- | ---: | ---: | ---: | ---: | ---: |
| SAM account RID and name | 1 | 5 | 0 | 0 | 0 |
| Installed program display name, version and publisher | 3 | 197 | 0 | 0 | 0 |
| USBSTOR class, serial, friendly name and driver | 1 | 0 | 0 | 0 | 0 |
| RecentDocs value text and MRU position | 2 | 30 | 0 | 0 | 0 |
| Run-family value name and command | 3 | 5 | 0 | 0 | 0 |
| Timezone key, standard name, bias and active bias | 1 | 1 | 0 | 0 | 0 |
| Computer name | 1 | 1 | 0 | 0 | 0 |

The round-two script reported 239 matching projected tuples. The reviewed comparator checks hive allocation and value identities more strictly. Counts under those checks require a new run on the exported hives. USBSTOR had no positive examples. One uninstall subkey index referenced a free cell. The reference script reconciled the remaining allocated children against the parent's declared count and checked the child links before using python-registry to read their values. All five hives were readable. The remaining registry rows, including deleted-cell candidates, are outside the comparison.

### Windows 10 EVTX records

The reference reader decoded 11,758 active events across six files. Every one paired uniquely by file and physical record offset. Record ID, event ID, provider, channel and computer matched on all pairs. The round-two timestamp criterion compared UTC at millisecond precision. The table records the original named-field projections. For example, a PowerShell pair could count as a match even when its unnamed arguments differed. The reviewed comparator also checks the retained payload fields for the five named families and agreement on family assignment. Updated counts require the original log exports and collector rows.

| Event family | Paired | All compared fields match | Differing or missing | Rapid only | Reader only |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logon | 782 | 1 | 781 | 64 | 0 |
| Logoff | 58 | 0 | 58 | 0 | 0 |
| Service installation | 32 | 32 | 0 | 1 | 0 |
| PowerShell | 92 | 91 | 1 | 0 | 0 |
| USB | 31 | 31 | 0 | 0 | 0 |
| Other (system fields only) | 10,763 | 10,756 | 7 | 171 | 0 |
| **Total** | **11,758** | **10,911** | **847** | **236** | **0** |

Of the paired records, 839 logon IDs had different text representations of the same integer. One PowerShell script differed by XML newline normalization. The timestamp check counted 6,464 nonzero differences below one millisecond, including nine pairs that crossed a millisecond boundary by one microsecond. On those nine, the raw FILETIME bytes agreed with Rapid's integer conversion. Two of the nine also had logon-ID text differences. The table retains mismatches under the original projections and timestamp criterion. All 236 additional Rapid events were labelled inactive-chunk. Their contents need a separate independent recovery check. The six selected files produced zero reference parser errors.

### Round-one XP record decoding

Use the existing round-one image in its read-only checkout. This run needs only the three allocated EVT streams. The comparison preserves multiplicity and checks record number, qualified event ID, type, category, both timestamps, source, computer and ordered insertion strings.

```bash
xp="../rapid/.rapid-images/nps-2008-jean.E01"
mkdir "$D/xp-logs"
fls -r -p -u -o 63 "$xp" > "$D/xp-fls.txt"
python - "$D" "$xp" <<'PY'
import re, subprocess, sys
from pathlib import Path
d = Path(sys.argv[1])
for line in (d / "xp-fls.txt").read_text().splitlines():
    m = re.fullmatch(r"r/r (\d+-128-\d+):\s*(.+\.evt)", line, re.I)
    if m:
        with (d / "xp-logs" / Path(m[2]).name).open("xb") as out:
            subprocess.run(["icat", "-o", "63", sys.argv[2], m[1]], stdout=out, check=True)
PY
python - "$D/xp-logs" <<'PY'
from collections import Counter, defaultdict
from pathlib import Path
import sys
from dissect.eventlog.evt import Evt
from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider
root = Path(sys.argv[1])
rapid = defaultdict(Counter)
inventory = {}
for row in WindowsEventLogProvider().collect(root):
    if row.artifact_type == "eventlog-file":
        path = Path(row.path)
        assert path not in inventory and row.details["native_parse_status"] == "complete-active-record-walk"
        inventory[path] = row.details["native_record_count"]
    elif row.artifact_type == "eventlog-event":
        d = row.details
        key = (int(d["record_id"]), int(d["event_id"]) | (d["event_id_qualifiers"] << 16),
               d["evt_event_type"], d["evt_event_category"], d["timestamp"], d["evt_time_written"],
               d["provider_name"], d["computer"], tuple(d["data"].values()))
        rapid[Path(row.path)][key] += 1
logs = sorted(root.glob("*"))
assert len(logs) == 3 and set(inventory) == {path.resolve() for path in logs}
for path in logs:
    with path.open("rb") as stream:
        ref = Counter((r.RecordNumber, r.EventID, r.EventType, r.EventCategory,
                       r.TimeGenerated.isoformat(), r.TimeWritten.isoformat(),
                       r.SourceName, r.Computername, tuple(r.Strings)) for r in Evt(stream))
    got = rapid[path.resolve()]
    assert inventory[path.resolve()] == got.total()
    print(path.stem, got.total(), ref.total(), (got & ref).total(),
          (got - ref).total(), (ref - got).total())
PY
```

| XP log | Rapid events | Independent events | Matching tuples | Rapid only | Reference only |
| --- | ---: | ---: | ---: | ---: | ---: |
| Application | 105 | 105 | 105 | 0 | 0 |
| Security | 0 | 0 | 0 | 0 | 0 |
| System | 470 | 470 | 470 | 0 | 0 |

All three active walks completed. The empty Security log used different oldest-record counters in its file header and EOF record. An explicit regression covers that empty layout. Synthetic tests also cover ring wrap, damaged records, dirty-header ambiguity and a legacy event ID that collides with a modern logon ID. The comparison covers active EVT records and their insertion strings. Message-DLL rendering, SID decoding, opaque event data and slack recovery remain outside this measurement. [Event log file format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format) · [Independent EVT reader](https://github.com/fox-it/dissect.eventlog)

### Release evidence after round two

The Windows 10 results cover allocated streams selected on macOS, six event channels and seven registry projections. Positive USBSTOR values, the remaining channels, deleted or slack content, full-volume behavior, a native Windows run, Ex01, scale and independent review remain open. The XP result covers the three active log walks. Release status remains `commercial_claim_allowed=false`.
