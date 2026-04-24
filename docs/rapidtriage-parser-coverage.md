# RapidTriage Parser Coverage Matrix

| Area | Status | Notes |
| --- | --- | --- |
| File metadata | Implemented | Names, paths, extensions, sizes, modified time, categories. |
| Document text | Implemented | Text/log/config/data, PDF, Office OpenXML, OpenDocument where dependencies support extraction. |
| Browser history/downloads | Partial | Dedicated browser artifact collector exists for supported local fixtures/profiles. |
| Recent files | Partial | Dedicated recent-files collector exists. |
| Timeline merge | Implemented baseline | Files, docs, artifacts, and normalized timeline export. |
| Case DB FTS | Implemented baseline | Documents, file metadata, artifacts, timeline, review status filters. |
| OCR | Partial | Depends on local Tesseract and image quality. |
| Windows Event Logs | Planned | EVTX parser contract should emit normalized Event records. |
| Registry hives | Planned | USB history/ShellBags/UserAssist style parser coverage pending. |
| Prefetch | Planned | Execution artifacts pending. |
| Jump Lists/LNK | Planned | Link and destination parsing pending. |
| Mobile/cloud acquisition | Deferred | Long-term domain, not current desktop triage scope. |

Every new parser should publish:

- Stable parser ID and version.
- Input evidence type.
- Normalized output model.
- Fixture path and expected output.
- Known limitations.
