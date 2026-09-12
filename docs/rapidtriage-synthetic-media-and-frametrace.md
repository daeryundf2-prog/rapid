# Synthetic-media screening provider and FrameTrace package ingest

Two optional integrations live outside the mandatory toolchain so a run never
depends on them:

- `synthetic-media` artifact collector backed by the optional
  [deepfake-lens](https://github.com/) screening toolkit.
- `frametrace-import` adapter that ingests a FrameTrace `package-case`
  directory into a case database.

## synthetic-media artifact collector

`rapidtriage.artifacts.synthetic_media.SyntheticMediaProvider`
(`collector_kind = "synthetic-media"`) is registered like every other provider
and runs in the `seizure`, `fraud`, `hacking`, and `recovery` run profiles.

Behavior:

- If `import deepfake_lens` succeeds, the provider scans image (`.jpg`,
  `.jpeg`, `.png`, `.webp`) and text (`.txt`, `.md`) files under the input
  root with `deepfake_lens.analyze_file`, bounded to
  `SYNTHETIC_MEDIA_MAX_FILES` (512) files, `SYNTHETIC_MEDIA_MAX_FILE_BYTES`
  per file, and 64 KiB text / 4 MiB metadata reads.
- If `deepfake_lens` is not importable, `supported()` returns `False` and
  `collect()` emits a single `synthetic-media-scan-status` record with
  `coverage_status: provider-unavailable` and
  `scan_status: skipped-optional-dependency`. The run continues normally.
- Per-file failures produce `synthetic-media-scan-error` records instead of
  crashing the collection; a provider-level crash still lands in the
  `failed-isolated` crash-isolation contract.
- A `synthetic-media-scan-summary` record closes each collection with scan
  counts, caps, and the score-semantics disclaimer.

### Score semantics — prioritization, not truth

Every record carries `score_semantics: prioritization-score-not-truth-label`,
`reportability: triage`, and `validation_required: true`. The deepfake-lens
`score`/`band` order files for examiner review; they are heuristic screening
output and are not authenticity verdicts. `limitations`, `signals`,
`source_guess`, and `model_analysis_available` from the deepfake-lens JSON
contract (`schema_version` 1) are preserved in the record details.

## frametrace-import adapter

`rapidtriage.core.frametrace_import` ingests a FrameTrace `package_*`
directory produced by `frametrace package-case`.

Steps:

1. Parse `manifest.sha256` (`<sha256>  <relative/path>` lines) and
   `package-manifest.json` (`package_type: frametrace-case-package`,
   `files[]` with `relative_path`/`size_bytes`/`sha256`).
2. Recompute SHA-256 for every listed file. Mismatches, missing files,
   manifest/disagreement rows, and path-escape attempts (`..`, absolute
   paths) are flagged per entry.
3. Read `db/video_index.json` (`videos[]` array; falls back to
   `db/videos.jsonl` rows) and import each video as a `file_record` plus a
   `frametrace-video-record` artifact under a `frametrace-package`
   `evidence_source`, via `CaseDatabase.import_run_output`.
4. Non-`ok` manifest entries are imported as `frametrace-package-integrity`
   findings (`supported=False`) and a `frametrace.package-imported` audit
   event records the verification summary (`result: ok` or `partial`).
   Mismatches are never silently accepted.

### Invocation

The module is callable directly — no `cli/` wiring is required:

```bash
# verify only
.venv/bin/python -m rapidtriage.core.frametrace_import /path/to/package_1700000000 --verify-only

# import into a case database
.venv/bin/python -m rapidtriage.core.frametrace_import /path/to/package_1700000000 \
    --db ./rapidtriage-case.db --case-id CASE-001 --case-name "Case 001"
```

From Python:

```python
from pathlib import Path
from rapidtriage.core.frametrace_import import import_frametrace_package

result = import_frametrace_package(
    Path("/path/to/package_1700000000"),
    case_id="CASE-001",
    db_path=Path("./rapidtriage-case.db"),
)
```
