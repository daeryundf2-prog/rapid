# RapidTriage Known Limitations

RapidTriage is a local triage and review tool, not a full commercial forensic suite.

## Evidence Handling

- Mounted folders and exported evidence folders are the most reliable input.
- E01/Ex01 direct handling requires external `libewf` and Sleuth Kit tools.
- Raw/split images can be extracted with Sleuth Kit (`mmls`, `tsk_recover`) when those tools are installed.
- ISO/DMG/WIM/SWM images can be extracted when supported archive tooling is available (`7zz`/`7z`, or `bsdtar` for ISO).
- VHD/VHDX/VMDK/VDI/QCOW/QCOW2 virtual disks can be converted with `qemu-img` and then recovered with Sleuth Kit when those tools are installed.
- AD1, L01/Lx01, AFF/AFF4, XVA, and mobile packages are still adapter-detected only and require vendor/tool export first. Memory dumps also receive bounded indicator scanning, not full process reconstruction.
- `rapidtriage evidence PATH --json` now reports `support_level`, `scan_strategy`, `next_actions`, `warnings`, and missing tools so analysts can decide whether to scan directly, install tooling, mount read-only, or vendor-export first.
- XFS/ext partition selection is supported for direct image recovery, but actual XFS file recovery depends on the installed Sleuth Kit build. XVA virtual-server dump workflows are not implemented yet.
- Deep deleted-file carving is not implemented.

## Parser Coverage

- Browser, recent-file, EventLog export, Registry export, ShellBags export, Prefetch inventory, Task Scheduler XML, Defender MPLog, Firewall W3C log, WER report, and Zone.Identifier sidecar artifacts are implemented first.
- macOS user profile, browser history, quarantine event, TCC privacy permission, and LaunchAgent plist triage is implemented as a baseline; full unified logs, Spotlight, FSEvents, and APFS snapshot parsing remain planned.
- Linux user, shell history, SSH, auth log, cron, and systemd triage is implemented as a baseline; full filesystem-level XFS parsing, journal replay, package manager databases, auditd, and container/runtime artifacts remain planned.
- Full EVTX BinXML field decoding, full Prefetch file-reference decoding, full Jump List OLE stream traversal, full SRUDB/Windows.edb table decoding, full mobile extraction imports, and live cloud acquisition are roadmap items. Native EVTX record-header scanning emits partial rows when recoverable, and EVTX-oriented XML/JSON/JSONL/CSV exports from tools such as EvtxECmd, Hayabusa, Chainsaw, or Velociraptor can be imported and normalized; Prefetch SCCA header/version/executable hints, common-version run counts, last-run timestamps, and referenced-path pivots are parsed when available. Direct SRUDB and Windows.edb files are currently inventoried with ESE header metadata, hashes, and bounded string/path/URL pivots; Jump Lists promote embedded Shell Link destinations when recoverable.
- Full native MFT attribute decoding, full USN validation, direct VSC extraction, AI prompt extraction, and deeper LotL command correlation are roadmap items. MFT/USN CSV/JSON/JSONL exports can be imported and normalized; native `$MFT` and `$J` files currently provide bounded inventory, path pivots, and recoverable USN rows. Mounted/exported VSC folders can be compared with `rapidtriage vsc-compare`.
- APK inventory/risk triage works on exported `.apk` files; Volatility/Volatility3 JSON/JSONL memory output import and bounded direct memory dump indicator scans are supported.
- Google Takeout-style location/activity JSON and Apple/general account JSON imports are supported; direct provider API collection is not implemented.
- Full direct memory process reconstruction, password cracking, live USB collection, and remote-agent collection are deferred until the security and validation model matures.
- Image perceptual hashes and similarity buckets are triage hints only; they do not replace full media forensics, visual similarity review, or classifier validation.
- Parser output should be verified against source evidence before report inclusion.

## Search And OCR

- Case DB search currently uses SQLite FTS5 for documents and artifact metadata, plus metadata scans for file/timeline/review filters.
- OCR depends on local Tesseract availability and quality varies by image.
- Large-case performance must be tracked with `rapidtriage benchmark`.

## Reporting

- Markdown, browser-friendly HTML, portable DOCX, dependency-free PDF, and report export hash manifests are available from the web API and reviewer bundle.
- Digital signing, notarization, and court-specific certification packets still require external release infrastructure and independent validation.
- Reports should include analyst review notes and hash manifests for defensibility.
- The validation package is a release-readiness checklist; it does not replace independent legal validation, signed installer infrastructure, or a maintained support program.

## Security

- The web UI is designed for localhost use.
- Remote binding requires explicit auth-token configuration.
- Do not expose RapidTriage directly to the internet.
