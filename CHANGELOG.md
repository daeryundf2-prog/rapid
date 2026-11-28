# Changelog

## Unreleased

### Added

- Console verdict keys (design-viewer-keys F15–F26): R/I/X/B, the batch bar, the row menu and
  the viewer header act on one scope (`reviewScope`: two or more selected rows, else the
  viewer's row) that the status bar names before and announces after; after a verdict the
  list moves on (판정 후 이동: 다음 행 · 다음 미판정 행 · 그대로, in `?` and the palette), and
  `Z` puts the last batch back (status / report flag / tags as they were). J/K work while the
  viewer has focus, Esc in the viewer returns to the same grid row. The status bar shows where
  you are, the verdict scope and the keys usable now (from the command registry); grid
  timings moved behind 진단; at 390 the run status and error count never clip and the timezone
  sits in a menu. Viewer: four verdict buttons with key caps under a full-width title (the
  duplicate status chip is gone), timeline events with a source record open on the record
  (메타) first, modes the row cannot show fold into 쓸 수 없는 보기 n, the hex view fits 16 bytes
  in the default width (character column behind 문자 열 when narrow), a 2px hex cursor and a
  polite cursor read-out with signature/record edges; pivots ±5분 · 같은 대상 · 같은 원본 파일
  have keys Alt+T · Alt+A · Alt+S (`frontend/src/commands/verdict.ts`).

- `omp-pi` collector for oh-my-pi (omp), pi, senpi and OmO: session JSONL
  under `<home>/agent/sessions` (subagent transcripts included, linked by
  `parent_session`), sessions in other folders recognized by their `session`
  header (string `id`, `cwd` and `timestamp`, strict UTF-8), omp
  `history.db` prompt history, `logs/omp.*.log` (`agent-log` rows in the
  timeline), model names from `config.yml`, `settings.json` and
  `models.yml`/`models.json`, and pi-family `mcp.json` in `agent-mcp`.
  omp's `attribution` (`user` or `agent`) is exported on user and developer
  rows, so an agent-written prompt is not read as typed by a person; rows on
  abandoned branches carry the flag `off-active-branch`, and `model_change`
  applies along the entry tree. See `docs/ai-agent-artifacts.md`
  (`tests/test_ai_agents.py`).
- Action API v1 (`docs/ai-action-api.md`): `GET /api/actions` (catalog),
  `POST /api/runs/{run}/actions/select` (analyse a selection: count, time span,
  sources, event types, top paths, samples; read-only) and
  `POST /api/runs/{run}/actions/mark` (check or tag every row of a selection;
  `dry_run` defaults to true and takes only a JSON boolean; a preview refuses
  what an apply would refuse -- mixed `tag_ids`, unknown rows or tag ids, an
  empty tag list -- and never builds the case DB). A selection is explicit row locators, a timeline
  window/text filter, or the timeline rows related to an anchor (same time
  window, same path, same file name). Marks go through the run's case DB
  review batch; `actor.kind = "agent"` records the reviewer as
  `agent:<name>`, an unnamed person as `RAPIDTRIAGE_REVIEWER` or `local-user`
  (never the row's previous reviewer), and a `human` name cannot start with
  `agent:` (422). Row ordinals in locators are ASCII digits (at most 12).
  Above 10,000 rows nothing is applied (Korean 422)
  (`tests/test_console_actions_api.py`).
- `GET /api/runs/{run}/timeline-histogram` takes `from`/`to` and buckets only
  that window, with finer buckets.
- Console: a time overview strip above the timeline grid (click or drag a bar
  to zoom, `[` / `]` previous / next range, `-` widen, a typed time opens the
  30 minutes around it); the command palette opens the timeline at a typed
  date or date-time and lists runnable commands before disabled ones;
  "선택 항목 분석…" and "관련 항목 표시…" open one dialog over the action API that
  also shows the request an agent would send.
- AI usage coverage matrix (`docs/ai-usage-coverage-matrix.md`, Korean, with
  the GitHub appendix `docs/ai-usage-coverage-github.md`): AI usage
  setups by category (web chat, desktop apps, browser AI, IDEs, CLI agents,
  harnesses, orchestrators, messenger agents, cloud agents, local LLMs, API and
  automation, image and voice generation, mobile), the traces each leaves, the
  primary source for each path, what Rapid collects today and the ordered list
  of next collectors. The appendix lists the repositories the matrix links to
  and the non-excluded ones with 5,000+ stars (1,561 of 10,406 surveyed, no
  descriptions); `scripts/ai-usage-github-appendix.py` holds the searches and
  classification rules and regenerates the full list outside Git.
- Browser history and memory URL classification recognise more web AI
  services: Microsoft 365 Copilot (`copilot.cloud.microsoft`), `copilot.com`,
  NotebookLM (`notebooklm.google.com`), 뤼튼, CLOVA X, 에이닷, Kimi, Qwen,
  Doubao, ChatGLM, Genspark, Manus and Felo. Both collectors now read one host
  table (`rapidtriage/core/ai_service_domains.py`), so memory strings also
  classify Google AI Studio, Grok, Mistral Le Chat, DeepSeek, Meta AI,
  Character.AI, You.com and Phind, which only browser history knew before.
  Browser history also counts `m365.cloud.microsoft/chat` (only the `/chat`
  path: the host also serves Office on the web) as Microsoft 365 Copilot.
- Local LLM inventory names Jan (its data folder on Windows, macOS and Linux
  and `~/.jan`, not any `jan/data` folder), AnythingLLM, Msty, AI:GO, LocalAI,
  Open WebUI, text-generation-webui and KoboldCpp data folders, matches Windows
  paths with either separator, and reads `.jsonl` chat logs one message per
  line: a Jan `messages.jsonl` line becomes a user or assistant prompt
  candidate at the line's byte offset (`tests/test_ai_service_domains.py`).
- `cataly-hub` collector for the Cataly agent hub (github.com/vntrevx/Cataly):
  the store `cataly.db` (and `backup/cataly-v*.db`) read from a private
  snapshot with its WAL -- lanes with state, outcome, thread, open and close
  times, worktrees, model, OMP session and Cataly's spend estimate, lane
  history, requests (IDs, message references, times and open/closed state;
  the owner's message text is not read), questions and answers, stream jobs
  (program only), hosted OMP sessions and events -- plus `logs/events.jsonl`,
  `logs/hub.log`, session stderr `logs/**/*.err`, `config.toml` (models,
  token and voice key file paths, job programs; relay owner IDs are omitted),
  the OMP overlay, launchd/systemd service definitions (program and env file
  path, no arguments), install records and the presence of token files (never
  read). Lanes and requests open and close in the timeline, events and hub log
  lines too. Any XDG base is recognized, so several hubs on one account are
  found. A document that does not parse leaves a note instead of stopping the
  collector. References to a private chat (a Telegram chat whose ID is the
  user's, a Slack direct message) are left empty in `thread`,
  `source_message`, `origin` and job `destinations`. See
  `docs/ai-agent-artifacts.md` (`tests/test_ai_agent_cataly.py`).
- AI-agent row redaction also masks Telegram bot tokens (including inside a
  Bot API `/bot<token>/` URL) and Discord bot tokens.

### Changed

- Console layout: toolbar buttons no longer wrap their label ("조건" split
  into two lines at 390 px), a narrow timeline keeps 요약 next to 시각, the
  stage rail is 48 px on phones, 실행 is icon-only there so the global search
  shows its placeholder, 보고 › 내보내기 buttons share one width, and a dialog
  hides the floating 뷰어 열기 handle. Selected rows, the current stage, case,
  analysis card and review-marked thumbnails or messages are a tonal wash (with
  a check for the current case) instead of a coloured side stripe. The 조건
  row wraps onto a second line in a narrow pane (viewer open at 1440 px, a
  zoomed time range, phones) instead of clipping 조건 지우기, the count and 열
  설정; the 조건 button ellipsises its applied summary
  (`frontend/src/features/filters/filterRowLayout.test.ts`).
- Remote use, path confinement (remote review R1, R2, R10): `rapidtriage web
  --remote` -- and any other non-loopback bind, `--host 0.0.0.0
  --auth-token` and `--allow-remote-without-auth` included -- refuses to
  start without `RAPIDTRIAGE_ANALYSIS_ROOTS` and
  `RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS`, or when an output root is, contains or
  lies inside an evidence root (compared case-insensitively by drive or UNC
  share and folder names on Windows, so a drive or share root overlaps every
  folder on it). With them set, `POST /api/runs`
  (`root`, `rules`, `known_good_hash_feeds`, `output_dir` -- also the default
  output folder next to the evidence), retry, `/api/evidence/identify`,
  `/api/collect/plan`, `/api/commercial-readiness` and the ti-enrichment
  `ti_feed` paths outside the roots are 422; output folders (runs,
  `/api/runs/import`, `/api/sample-case/run`) must be under an output root
  and outside every evidence root (422); runs registered earlier or imported
  reach only their roots inside the lists (`source-file` 403; 404 when a
  drive-letter path also maps into a root as a recorded evidence path and is
  not found there, as on Windows hosts), and writes
  into a run output folder outside the output roots or inside an evidence
  root (extract, notes, reports, bookmarks, analyses, search) are 403;
  `GET /api/browse` without `scope` lists only the roots (no home folder, no
  drive list). These routes now also refuse `~`, relative and UNC paths
  (422) as the case routes already did. The console picker shows such a
  listing as a root list
  (`tests/test_rapidtriage_remote_path_confinement.py`,
  `frontend/src/features/case/BrowsePanel.test.tsx`).
- Sample case overwrite (`POST /api/sample-case/run`, `rapidtriage sample
  --overwrite`) deletes only an earlier sample folder (marker
  `.rapidtriage-sample-case` or `rapidtriage-sample-expected.json`); any
  other non-empty folder is refused instead of deleted recursively. With the
  output roots set the API default is `<first output root>/rapidtriage-sample`.
- Run evidence walks skip a symlink or junction that resolves outside the
  run root, so the analysis server's own files are no longer indexed (docs
  index, case DB) through a link inside collected evidence.

### Fixed

- `wait: true` on `POST /api/runs` and `POST /api/cases/{id}/runs` ran the
  whole run inside a request thread, so 40 concurrent requests exhausted the
  server's thread pool and `/api/health`, `/` and the run list stopped
  answering (remote-use review R3). The run now goes through the run worker
  pool (`RAPIDTRIAGE_RUN_WORKERS`, default 2) and the request awaits it
  without a thread for at most `RAPIDTRIAGE_RUN_WAIT_SECONDS` (default 60);
  past that it answers with the run still `queued`/`running` and
  `wait_timed_out: true` (`tests/test_rapidtriage_run_wait.py`).
- Review marks and tags under concurrent users (remote-use review R4): two
  people tagging one row at once lost tags, and concurrent marks on a new row
  created several `review_mark` rows (each with its own citation id). Marks
  and tag batches (and tag deletion) now read and write under `BEGIN
  IMMEDIATE`, `add_tags` merges inside that transaction, case DB connections
  wait up to 30 s for the write lock, and `idx_review_mark_case_target` is
  UNIQUE. Opening an older case DB for writing merges its duplicate marks
  first: the first mark keeps its citation id and takes the newest mark's
  fields and tags (only live tags, so a tag removed or deleted after the race
  does not come back), and a `review.duplicates-merged` audit event lists the
  removed citation ids and the dropped tags (`tests/test_review_mark_atomic.py`).
- Who did what on a shared server (remote-use review R5, R12): the web API
  recorded the name each browser sent (`web-ui` by default) and ignored
  `RAPIDTRIAGE_REVIEWER`. `RAPIDTRIAGE_TOKENS_FILE` now gives each person
  (or `agent:<name>`) a token, and the token decides the author of review
  marks, tags, notes, baselines and case audit entries; client `reviewer` /
  `actor` / `author` names are display values then. Without the file
  `RAPIDTRIAGE_REVIEWER` is the server's author for web writes. Runs record
  `owner` (create, import, retry), cancel and plan control log their actor
  (the control file keeps `actor: web` and adds `by`; the run plan and report
  name that person), run notes record `updated_by`, and removing a run
  leaves a `removed_runs` record in `runs.json`. The action API's `actor`
  follows the token (an `agent:` token is always that agent; a person's agent is
  `agent:<name>@<person>`). The tokens file cannot be combined with a single
  token or disabled auth, is never printed, and tokens are compared as
  SHA-256 digests in constant time. A UTF-8 BOM is skipped, a name cannot
  contain `@` (nor can an action API agent name), and `rapidtriage web` warns
  when other accounts can read the file or a token is shorter than 24
  characters (`tests/test_user_tokens_actor.py`).
- Browser storage (Local Storage, IndexedDB) matches AI service hosts only at
  a host boundary, so GitHub Copilot storage (`api.githubcopilot.com`) is no
  longer labelled Microsoft Copilot and `box.ai` / `bayou.com` no longer read
  as Grok / You.com. The AI-uplift `supported_ai_services` list no longer
  repeats a service per host; its manifest hash changes with it
  (`tests/test_ai_service_domains.py`).
- "더 보기" in the console's text view decoded the original as UTF-8 only, so
  a CP949, UTF-16 or UTF-32 file turned into replacement characters once
  expanded. It now decodes in the order of the server preview
  (`core/doc_text.decode_text_bytes`): BOM (UTF-8, UTF-32, UTF-16), BOM-less
  UTF-16, UTF-8, then CP949. A character cut by the 2 MB cap is dropped instead
  of switching the encoding (`tests/test_source_text_redaction.py::DecodeTextPrefixTests`).
- The console's text views past the preview, "더 보기" and the first 2 MB of a
  text file over the extraction limit, read the raw bytes of `source-file`, so
  a BitLocker recovery password, a saved WinSCP/FileZilla password or a private
  key that the text preview masks showed in clear. They now read the new
  `GET /api/runs/{run}/source-text?path=…&max_bytes=…` (at most 2 MB), which
  decodes and redacts on the server exactly as the preview does
  (`core/docs.redact_document_text`). A secret the cap cuts in two is not shown
  in part: the text ends before it. The response's `redacted` flag puts a note
  over the text saying that secrets are masked. Only 원본 열기 (`source-file`)
  still hands out raw bytes (`tests/test_source_text_redaction.py`,
  `frontend/src/features/viewer/views/fallbacks.test.tsx`).
- `source-preview` masked secrets only in files of the listed text and
  document kinds. A JSON or XML file, a text file of another extension
  (`.ps1`, `.reg`, …), an e-mail body or subject and a ZIP entry's text came
  back with BitLocker recovery passwords, private keys and saved passwords in
  clear. Every textual preview now goes through `core/docs.redact_document_text`.
  JSON and XML are masked in the text, then in each parsed string, so `\u`
  escapes and character references are masked too. E-mail bodies are masked
  before they are cut to the preview length. The payload carries `redacted`,
  and the source, document and e-mail views show the same note as the other
  text views. Secret-store files (`logins.json`, …) come back withheld instead
  of parsed (`tests/test_source_text_redaction.py::PreviewRedactionTests`).
- An SVG shown in the console's image view or thumbnail grid was a `blob:` URL
  in the console's own origin, so "open image in new tab" ran the evidence's
  script with access to the console. It is now a `data:` URL, whose origin is
  opaque. 원본 열기 hands the browser the original as
  `application/octet-stream` (`frontend/src/features/viewer/views/fallbacks.test.tsx`,
  `frontend/src/features/viewer/Viewer.test.tsx`).
- The timeline merged an offset-free local wall clock with a UTC instant
  whose digits matched. A registry row with the local-unknown installation
  time `2024-11-03T01:30:00` and the key LastWrite `2024-11-03T01:30:00Z`
  became one `local-unknown` event labelled `installed, last-written`, and
  the known UTC instant disappeared. Same-instant merges now compare the time
  basis as well as the digits: a UTC instant and an offset-free
  `local-unknown`/`exif-local`/`local`/`device-local` wall clock stay two
  events with their own labels and zones, in either order. Times with explicit
  offsets for one UTC instant still merge. A row's own `timestamp` or
  `timeline_events` item that declares no zone and repeats the text of a mapped
  field verbatim takes that field's zone instead of the UTC default, so it
  still joins that event (`tests/test_d27_timeline.py::TimeBasisMergeTests`).
- Timeline key-row citations did not name their input file. Two registry
  exports passed to one `timeline` run whose rows share a key LastWrite each
  contributed row 0, and both `details.key_rows` entries read
  `(artifacts_windows-registry, 0)`, so neither value could be traced back to
  its file. Every artifact event's `details.source_record`, each
  `details.key_rows` entry and each `details.also_in` entry now also carry
  `input_file`, the timeline input the row was read from
  (`tests/test_d27_timeline.py::KeyRowCitationTests`).
- The timeline Markdown report stated "모든 이벤트 시각은 UTC ISO 8601" and
  `summary.timezone.note` began "모든 이벤트 시각은 UTC로 저장합니다" even when
  events were offset-free local wall clocks (`timezone=local-unknown`), so the
  header and the rows disagreed about which times carry an offset. The storage
  line is now counted from the report's own rows: UTC instants with `+00:00`,
  offset-free local wall clocks kept as their original text (not UTC), or both.
  `summary.timezone` adds `utc_event_count`, `local_wall_clock_event_count`
  and `local_wall_clock_by_timezone`; its `storage` is `UTC`,
  `UTC+local-wall-clock` or `local-wall-clock`, and its `display`/`note` say
  the same. The run report's disclosure section says offset-known times are
  UTC and adds the wall-clock count when there is one. Rows without an offset
  keep their caveat; one without a local label now gets one too
  (`tests/test_d27_timeline.py::ReportTimeBasisTests`).
- A Taskband Favorites or FavoritesResolve value holding exactly 4,096 pins
  (the frame cap) followed by its proper end was labelled
  `partial`/`frame-cap`, the same as a value with 4,097 pins, because the cap
  was checked before the end marker. **Output change:** such values are now
  `decoded` with `end_status` `terminator` or `end-of-value`; `frame-cap` is
  reported only when another frame follows
  (`tests/test_taskband_featureusage.py::TaskbarProviderTests::test_clean_end_at_exactly_the_frame_cap_is_complete`).
- Journald marked an entry with sequence number 0, or with a monotonic time of
  2^55 or more, as fully `parsed` with no limitation, although systemd's
  entry check rejects both. **Output change:** such entries are `partial` and
  carry `invalid-sequence-number` (citing header offset +16) or
  `monotonic-out-of-range` (+32). The raw values and a valid UTC time are kept
  (`tests/test_journald.py::JournalTests::test_sequence_and_monotonic_validity_are_checked_separately`).
- A lastlog row could name a single account for a UID that two accounts share
  when the passwd file exceeded the 4 MiB lookup cap and the second alias lay
  past it; the summary still read `parsed` with `capped=false`. A truncated
  passwd file now names nobody, and lastlog rows and their summary carry
  `account_lookup` (`complete`, `truncated` or `unavailable`), separate from
  the record scan's `capped`. **Output change:** `user` is empty on every
  lastlog row when passwd exceeds 4 MiB; new `account_lookup` field
  (`tests/test_linux_login_accounting.py::LinuxLoginAccountingTests::test_truncated_passwd_never_settles_a_shared_uid`).
- KnowledgeC exported the string value of every known `/app/` stream as the
  subject app's `bundle_id` before consulting stored identifiers, so a
  `/app/webUsage` page URL became the bundle ID even when the linked metadata
  stored `ZBUNDLEID=org.example.browser`. Stored identifiers (object, then
  structured metadata) now come first, and the value names the app only on
  `/app/inFocus`, `/app/usage`, `/app/activity` and `/app/mediaUsage`.
  **Output change:** `/app/webUsage` and `/app/intents` rows without a stored
  identifier have an empty `bundle_id`; a bundle-ID value that disagrees with
  a stored identifier adds the warning `subject-bundle-conflict`
  (`tests/test_knowledgec.py::KnowledgeCTest::test_value_names_the_subject_only_for_streams_whose_payload_is_the_app`).
- A Codex rollout that repeated the same prompt in two turns, with a replay
  (`response_item`) recorded only in the second turn, lost the first turn's
  prompt and exported two rows for the second turn (wrong time, working
  directory and source line). Replays were matched by role and text across the
  whole file. They are now matched only within the same turn, identified by the
  `turn_context` record's `turn_id` when recorded. **Output change:** such
  prompts keep their own turn's row; when one turn holds more progress copies
  than replays, the unpaired copy carries the new flag
  `replay-pairing-ambiguous`
  (`tests/test_ai_agents.py::AgentTests::test_replay_matching_stays_within_the_source_turn`).
- Coding-agent transcript timestamps with an out-of-range UTC offset minute
  (`2024-01-01T12:00:00+01:60`, `-00:60`) were rolled over by the
  date parser into a different, apparently exact UTC instant
  (`2024-01-01T10:00:00+00:00`). RFC 3339 §5.6 limits the offset to hours
  00-23 and minutes 00-59. **Output change:** such rows keep `timestamp_raw`,
  leave `timestamp_utc` empty and carry `timestamp-not-normalized`
  (`tests/test_ai_agents.py::AdversarialAgentTests::test_out_of_range_offsets_are_not_normalized`).
- Native E01 extraction (Python and Rust engines) lost one of two entries in
  an NTFS directory whose names differ only in case (`Foo.txt` and `foo.txt`:
  POSIX namespace, case-sensitive directories). The walk listed the names and
  looked each one up again by name; NTFS looks names up case-insensitively,
  so both names reached the same record. The other record was never
  extracted, one twin's name could hold the other twin's content, and the
  loss was counted in `alias_skips` as if it were an 8.3 alias. Both engines
  now follow each directory entry by its own MFT reference (dissect
  `IndexEntry.dereference`; Rust `Ntfs::directory_entries`), so every record
  is extracted once under its own name; a twin the output drive folds onto
  another name gets the `<stem>~mft<record>[-n]<extension>` name and is
  listed in `output_name_collisions`. A DOS 8.3 alias of a record already
  listed under its long name is still skipped and counted in `alias_skips`,
  and a record named only in the DOS namespace is still recovered. The
  priority pass expands `Users/*` the same way. **Output change:** images
  with case twins recover more files and report fewer `alias_skips`. The Rust
  extension ABI is now 5 (an older build, which loses twins, is refused). On
  a drive that folds case (Windows, default macOS), a parallel Rust copy that
  meets a twin reruns sequentially
  (`tests/test_e01_extract_rust_parity.py::CaseTwinTests`).
- Native E01 extraction (Python and Rust engines) wrote two distinct NTFS
  records to one output file and counted both: names equal after
  `_safe_component` cut them at 180 characters (or replaced characters), or
  names the output drive folds together (`é.txt` composed and decomposed on
  APFS, case twins on Windows/macOS), left only the later body while
  `files`/`bytes` counted two. A source entry named `_deleted_mft` also made
  the deleted-record sweep fail the whole extraction. Each (output folder,
  MFT record) pair now gets its own name: the first record in walk order
  keeps it, later ones become `<stem>~mft<record>[-n]<extension>` (the
  extension kept), checked against the names given in this run and against
  what the output drive resolves before writing; nothing is overwritten or
  merged. **Output change:** `extract_e01_native` returns
  `output_name_collisions` (status, kind, output path, source name and path,
  MFT segment and sequence; first 1,000), the recovered manifest carries it as
  `native_output_name_collisions`, stats add `name_collision_renames` and
  `name_collisions_unresolved`, and the run warns when either is non-zero. The
  Rust extension ABI is now 4 (older builds are refused). The parallel Rust
  copy falls back to the sequential walk when two planned names meet on the
  drive
  (`tests/test_e01_extract_rust_parity.py::OutputNameCollisionTests`).
- With the Rust EVTX engine, the eventlog-file row counted chunks handed to
  the Python decoder (`native_evtx_engine_python_fallback_chunk_count`) but
  not why or where. One valid non-ASCII ANSI string gave a count of 1 and no
  way to find the record. The row now adds
  `native_evtx_engine_python_fallback_reason_counts` (per bounded reason
  code: `non-ascii-ansi-string`, `surrogate-character-reference`,
  `element-nesting-too-deep`, `unrecognized-native-reason`) and cites the
  first switch with `native_evtx_engine_python_fallback_first_reason`,
  `…_first_chunk_index`, `…_first_chunk_offset`, `…_first_record_offset`
  (absolute) and `…_first_record_id` (`null` when nothing switched). These
  are separate from `native_fallback_record_count`, which counts records
  read by the legacy token scan. **Output change:** new eventlog-file fields
  on Rust-engine runs only; event rows are unchanged
  (`tests/test_evtx_engine_diff.py::ProviderEngineSwitchTests::test_python_fallback_cites_reason_and_first_record`).
- The Rust EVTX engine spelled some finite doubles differently from Python's
  `repr`. When a value lies exactly halfway between its two shortest
  round-trip spellings, CPython keeps the even last digit and Rust rounded up:
  `2**50 + 0.25` became `1125899906842624.3` instead of `1125899906842624.2`.
  This changed the string-valued `data` field, the rendered event XML and JSON
  row bytes (`python_float_repr`, shared by `real_text` and
  `push_json_float`). The Rust formatter now breaks those ties to even. A
  13-million-double fuzz against CPython 3.12 (random bits, subnormals, short
  mantissas, parsed decimals, f32 widenings and 2 million exact midpoints)
  shows no differences. **Output change** for the Rust engine
  only: affected Real32/Real64 values and JSON floats now have Python's text
  (`tests/test_evtx_engine_diff.py::ProviderEngineSwitchTests::test_real64_ties_spell_like_python_repr`,
  `evtx_binxml::tests::float_repr_breaks_shortest_ties_to_even_like_python`).
- Console list APIs on large cases (`view=list`, row index of large `files` /
  `timeline` outputs, `/tree` and filter caches): the row index now exists only
  when `json.load` reads the same rows (every element and member is parsed and
  the bytes between them checked once per file revision), so a corrupt or split
  line fails like the full parse instead of serving rows at shifted positions.
  Indexes, kind-filter matches and head-scan values are keyed by the file
  revision `(device, inode, size, mtime)`, re-check it on every read (a file
  replaced or appended to meanwhile falls back to the full parse) and are
  bounded in memory; the file is no longer memory-mapped. `sort=timestamp` on
  the timeline is the console's own evidence-time order (wall clocks of
  undetermined zone apart, 100 ns ticks, events without a time first in `desc`;
  `tests/fixtures/timeline-sort-parity.json` pins it for both sides).
  `view=list` names every value it leaves out (`raw.nested`,
  `pagination.<manifest>`), keeps lists of flat records (Prefetch volumes,
  attachments) that grid columns read, and the viewer says when a row's full
  record is not loaded yet and does not copy it as the record
  (`tests/test_console_api_review.py`).
- On Windows an analysis could vanish from the analysis list for one read. The
  state reader treated the sharing error raised while another thread
  `os.replace`d `analysis.json` (a heartbeat or progress write) as "no state".
  `GET …/search/index` then reported the previous build as `ready` instead of
  `build-failed-swap`. State reads now retry that error the way state writes
  already do (`tests/test_rapidtriage_analyses.py::StateReadRetryTests`).
- One EVTX record holding a character reference to a lone UTF-16 surrogate
  (`&#xD800;`, found in damaged logs) or one JSON export row with a `"\ud800"`
  escape made the whole streamed eventlog collection fail (`failed-isolated`,
  no rows), because UTF-8 output cannot hold a surrogate. The reference is now
  kept as its text `&#xd800;` (as invalid character references already were),
  and the JSON escape as its text `\ud800`. The row discloses this with
  `evtx_lone_surrogate_references` / `export_lone_surrogate_escapes` and the
  caution labels `lone-surrogate-character-reference` /
  `lone-surrogate-json-escape`. No text is dropped
  (`tests/test_eventlog_lone_surrogates.py`).
- EVTX structural scanners read the chunk free-space offset from byte 44, which
  holds the last-event-record offset, instead of byte 48 (chunk header layout:
  libyal libevtx "Windows XML Event Log (EVTX) format", section "Chunk header").
  As a result the last live record of every chunk was labelled slack. Affected:
  the Python scanner in `rapidtriage.core.native_accel`,
  `rapidcore::evtx::scan_evtx` / `rapidcore_native.scan_evtx`, and
  `rapid-worker evtx-scan` / `parse --kind evtx-records`. All of them now read
  the last record offset from byte 44 and free space from byte 48, and fall
  back to byte 44 when byte 48 is zero, as the BinXML decoder already did.
  **Output change:** these scans now report more `allocated` /
  `allocated-or-live-record` records and fewer slack or recovery candidates.
  On the 500,000-record profiling log the count goes from 497,500 allocated +
  2,525 slack to 500,000 + 25. The BinXML event collector
  (`collect_native_evtx_events`) read byte 48 already and its rows are
  unchanged.
- Native E01 extraction names files and directories with a Win32 device name
  (`CON`, `nul.txt`, `COM1.log`, ...) with a leading `_` on Windows, where the
  plain name opened the device instead of a file in the extraction folder.
  **Output change (Windows only):** such entries are now recovered as
  `_CON`, `_nul.txt`, ... Other platforms keep the names.
- The recovered-root manifest of E01/disk-image extractions lists files depth
  first with names sorted instead of in the output drive's listing order, so
  its first 5,000 entries (and the inventory fingerprint) no longer depend on
  the order files were created in on drives that list in creation order
  (exFAT, tmpfs). **Output change:** manifest entry order.

### Added

- The console viewer shows a file in a view of its own type instead of a hex
  dump. A PDF renders as pages in the browser's PDF viewer, from the bytes of
  `GET /api/runs/{run}/source-file`, whether or not text could be extracted; a
  toggle switches to the extracted text, which comes first when the search
  keywords hit it. A file named `.pdf` without the `%PDF-` header is reported as
  such and not framed; only its first 1 KB is read to tell. The frame always
  gets the bytes as `application/pdf`, so an HTML polyglot starting with
  `%PDF-` never runs as a page. The PDF is fetched once per file and kept across
  the toggle until the viewer closes. An image the browser cannot decode (TIFF,
  ...) falls back to the server's JPEG preview, and media it cannot play says
  so. A plain-text file over the server's extraction limit opens as text from
  its first 2 MB. A type with no viewer keeps the hex grid under a notice with
  its format, MIME type and size. Each of these states offers 원본 열기. No API
  change.

- The `macos-unified-log` collector extracts log, activity, signpost and trace
  events from stored tracev3 chunksets in offline evidence. Calibrated events
  appear on the timeline with source offsets. Compressed blocks, damaged
  records and missing format strings carry explicit coverage information.
  [Formats, limits and synthetic example](docs/rapidtriage-macos-unified-log.md)

- The `macos-knowledgec` collector reads system and per-user KnowledgeC
  activity streams, including committed WAL rows. It retains raw time values
  alongside UTC timestamps and flags unknown streams.
- The `linux-journald` collector reads persistent systemd journals in regular
  and compact layouts. Entries carry source offsets and raw clock values.
  Field DATA hashes are recomputed (Jenkins or keyed SipHash-2-4) and
  mismatches are flagged. Undecodable fields and damaged structures carry
  diagnostics. Both collectors are selectable in run plans and contribute
  events to the timeline.
- Explorer taskbar records from NTUSER hives and `.reg` exports, on both
  registry engines: `execution-feature-usage` rows now carry the user, the
  value name and the raw key LastWrite FILETIME, and report a count only for an
  integer value within the DWORD range; `registry-taskband-pin` rows resolve
  Favorites item ID lists and FavoritesResolve Shell Links;
  `registry-taskband-summary` discloses each value's walk (undecoded frames,
  why it stopped, caps).
  **Output change:** a registry row whose own timestamp restates its key-scoped
  LastWrite now joins the single per-key timeline event instead of adding one
  event per value (affects `registry-known-dll`, `registry-network-share`,
  registry `execution-pca`, `execution-feature-usage`, `registry-taskband-pin`,
  `ssh-known-host`, `desktop-wallpaper` and enabled `startup-item` rows;
  artifact rows are unchanged). Every key-scoped timeline event now lists the
  rows it stands for in `details.key_rows` (artifact type, output, row index,
  value; up to 1,000, then `key_rows_truncated`) with the full
  `details.key_row_count`.
- Linux login accounting in `linux-system`: utmp, wtmp, btmp (live and
  uncompressed rotations) and sparse lastlog in the 384/292-byte glibc x86
  layouts, with per-file `linux-login-accounting-summary` rows for damage,
  truncation, caps, unknown layouts and compressed rotations. See
  `docs/rapidtriage-parser-coverage.md`.
- Opt-in Rust EVTX chunk decoder (`rapidcore_native.EvtxChunkDecoder`),
  selected with `RAPIDTRIAGE_EVTX_ENGINE=rust` or
  `--eventlog-evtx-engine rust`. The default stays Python. Rows are identical to
  the Python decoder's (`tests/test_evtx_engine_diff.py`). See
  `docs/architecture/rust-bootstrap.md`.
- Opt-in Rust engine for the native E01 -> NTFS file extraction
  (`RAPIDTRIAGE_E01_EXTRACT_ENGINE=rust`, built with
  `python scripts/build-e01-extract-native.py`): its own EWF v1 reader and
  parallel copies (`RAPIDTRIAGE_E01_EXTRACT_THREADS`), with the tree and stats
  of the Python engine (`tests/test_e01_extract_rust_parity.py`). It hands the
  image to the Python engine, and records why, when it fails, when the output
  drive nears its free-space reserve, when corrupt metadata asks for a read
  over 256 MiB, and on Windows without long-path support when an output path
  reaches 248 characters. Parallel copies whose targets meet on the output
  drive (names equal after sanitizing, case or Unicode normalization) are redone
  sequentially. Segment sets the Rust EWF reader does not take (Ex01, damaged
  chunk tables) and chunks that fail their checksum are read through pyewf.
- Indicator extraction can use a Rust worker for URLs, IPv4 addresses and hashes. Set `RAPIDTRIAGE_RUST_INDICATORS=1` to enable it. The worker reads JSONL artifact record streams itself, applying the Python field policy, and returns only scalar fields with candidates. Rows and Unicode text outside its exact subset go to Python. Other outputs send ASCII scalar fields in batches. The indicator output and run disclosures record worker use and fallback; after a worker failure Python resumes from the last applied checkpoint. [Build and validation instructions](docs/architecture/rust-indicators.md)
- Opt-in Rust $MFT / $UsnJrnl:$J parser (`engines/rust/crates/rapid-ntfs`,
  module `rapid_ntfs_native`), selected with `RAPIDTRIAGE_NTFS_ENGINE=rust` for
  the NTFS-meta analysis. The default stays Python. Rows are identical to the
  Python parser's (`tests/test_rapid_ntfs_parity.py`); a missing or stale
  build, a Rust error, or a consumer that reads Python-only fields (hashes,
  attribute-list resolution, USN cursor window) falls back to Python and
  records why in `native_mft_engine*` / `native_usn_engine*` run metadata.
  Build with `python scripts/build-rapid-ntfs.py`. See
  `docs/architecture/rapid-ntfs.md`.
- With the Rust EVTX engine selected, event and detection rows are walked for
  BitLocker recovery passwords in Rust
  (`rapidcore_native.redact_recovery_passwords_in`). Any string that could hold
  one still goes through the Python `redact_recovery_passwords`, so the output
  is identical (`tests/test_evtx_engine_rows_diff.py`). About 10× faster per
  full-detail row: 580–670 µs down to 50–65 µs.
- With the Rust EVTX engine selected, the eventlog stage folds and strips
  per-type/per-file constant blocks (`artifact_type_profiles`) in Rust
  (`rapidcore_native.profile_observe_details`, `profile_common`,
  `profile_strip_level`), and readers of that eventlog output expand rows with
  `profile_merge`. Equality stays type-strict (`True` ≠ `1` ≠ `1.0`, `-0.0` ≠
  `0.0`), key order and object identity are kept, and anything other than plain
  JSON values goes to the Python code, so profiles and JSONL bytes are identical
  (`tests/test_evtx_engine_rows_diff.py`). On 50,000 events, compaction CPU
  went from 6.4 s to 1.6 s.
- With the Rust EVTX engine selected, the eventlog stage writes its JSONL rows
  with `rapidcore_native.dump_json_row`: the text of
  `json.dumps(ensure_ascii=False, separators=(",", ":"), default=json_default)`,
  including Python float `repr`, `NaN`/`Infinity`, big ints and `default=`
  conversions. Subclasses of str/int/float/list/tuple/dict, non-str keys, lone
  surrogates, deep nesting and errors go to `json.dumps`
  (`tests/test_evtx_engine_rows_diff.py`). About 2.8× faster per row.
- With the Rust EVTX engine selected, triage-detail event rows are projected in
  Rust (`rapidcore_native.EventlogTriageProjector`, the port of
  `triage_eventlog_details`): same keys, order, values and types; values it
  cannot reproduce exactly (subclasses, custom objects, lone surrogates in
  bounded text) go to the Python function
  (`tests/test_evtx_engine_rows_diff.py`). About 2× faster per row (18–23 µs
  down to 9–10 µs).
- Five evidence collectors for AI coding agents: `claude-code`, `codex-cli`,
  `gemini-cli`, `editor-chat` (Cursor and VS Code-family chat storage) and
  `agent-mcp` (MCP server configuration). Dated messages, tool calls and tool
  results appear in the timeline. Secrets are redacted before output, SQLite
  is read from a verified private snapshot, and rows without a recorded
  version carry `version-unknown`. See `docs/ai-agent-artifacts.md`.
