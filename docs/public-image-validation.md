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
