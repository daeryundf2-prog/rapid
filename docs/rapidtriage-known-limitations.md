# RapidTriage Known Limitations

RapidTriage is a local triage and review tool, not a full commercial forensic suite.

## Evidence Handling

- Mounted folders and exported evidence folders are the most reliable input.
- E01/Ex01 direct handling requires external `libewf` and Sleuth Kit tools.
- Raw, ISO, VHD/VHDX, and VMDK formats are currently detected by adapters, but full native extraction is still planned.
- Deep deleted-file carving is not implemented.

## Parser Coverage

- Browser and recent-file artifacts are implemented first.
- Windows Event Logs, Registry hives, Prefetch, Jump Lists, ShellBags, SRUM, mobile, and cloud imports are roadmap items.
- Parser output should be verified against source evidence before report inclusion.

## Search And OCR

- Case DB search currently uses SQLite FTS5 and metadata scans.
- OCR depends on local Tesseract availability and quality varies by image.
- Large-case performance must be tracked with `rapidtriage benchmark`.

## Reporting

- Markdown report generation is available.
- PDF/DOCX polished exports are not yet first-class release artifacts.
- Reports should include analyst review notes and hash manifests for defensibility.

## Security

- The web UI is designed for localhost use.
- Remote binding requires explicit auth-token configuration.
- Do not expose RapidTriage directly to the internet.
