# Interaction measurements (T-203 · IS-134 · QA-195)

`interaction.spec.ts` measures every item of the IS-134 interaction budget table 5 times (after two
unmeasured warm-up rounds, so the cache is warm) and writes the p75 of each item to a JSON file.
8 items × 5 = 40 measurements; a cell that cannot be measured fails the run (`unmeasured` must be 0).

| id | trigger → end | budget (p75) |
|---|---|---|
| `jk_down` | `J` keydown → next row painted as focused | 50 ms |
| `jk_up` | `K` keydown → previous row painted as focused | 50 ms |
| `viewer_skeleton` | row mousedown → first viewer repaint for that row | 100 ms |
| `viewer_body` | row mousedown → viewer body ready (`aria-busy` off, no "불러오는 중") | 500 ms |
| `review_mark` | `R` keydown → row painted with the 관련 있음 mark (undone with Ctrl+Z after each) | 100 ms |
| `category_first_row` | tree item mousedown → first row of the new list | 1.0 s |
| `search_first_result` | Enter in 전체 검색 → first `search:` result row | 1.5 s |
| `scroll_dropped_frames` | grid scroll container moved every frame for 120 frames → dropped frames | ≤ 5 % |

How it measures: a capture listener takes the input event's `timeStamp` before the app sees it; a
`MutationObserver` (plus a per-frame check) notices the expected DOM change; then
`requestAnimationFrame` + a macrotask marks the frame that carries it (the "next paint"
approximation the Event Timing API uses). `samples`/`p75` are those paint times;
`commit_samples` are the DOM-change times without the paint. Dropped frames are counted from
`requestAnimationFrame` intervals (each interval rounded to the idle frame interval measured just
before) while the scroll position moves 240 px per frame. p75 = nearest rank (4th of 5 sorted).

Budget overruns do not fail the spec: QA-195 registers them as GAPs. Unmeasured cells do.

Order: J/K → viewer → scroll → category → search → review mark. The mark goes last because the
first mark of a run builds the case DB, which switches 전체 검색 from the scan to FTS. On the
synthetic fixture the case DB resolves none of the grid's rows, so the server rejects each mark
and the app rolls it back (`review_mark_saves.rejected`); the measured time is the optimistic
on-screen mark either way. On a real run the saves succeed and each one is taken back with Ctrl+Z.

## Not in the default e2e run

`e2e/playwright.config.ts` ignores `e2e/perf/**` unless a CLI argument names a `perf` path or
`RAPIDTRIAGE_PERF=1` is set, so `npm run e2e` (nightly) and the gate's smoke spec never run it.

## Synthetic run (engineering check, this repo)

Starts its own isolated server (start-server.mjs, port from `.rt-dev.env`), writes the SYNTHETIC
r8-rich fixture (`scripts/make-r8-fixture.py` via `e2e/r8_fixture.py`, fake values only) and imports it.
Not release evidence.

```bash
cd frontend
RAPIDTRIAGE_E2E_PORT=<port from .rt-dev.env> \
  python ../scripts/dev/run.py --timeout 700 -- npm run e2e -- e2e/perf/interaction.spec.ts
# or: npm run e2e:perf
```

The JSON goes to `frontend/test-results/perf/interaction-<time>.json` (git-ignored) unless
`RAPIDTRIAGE_PERF_OUTPUT` names a file. The built console (`rapidtriage/web/static/v2`) is measured,
so build it first (`npm run build`) when the sources changed.

## Real data: C2 baseline (QA, outside Git)

1. Start a RapidTriage server for the C2 case on a free port (never 8710, the operator's server),
   with a token, e.g. `RAPIDTRIAGE_AUTH_TOKEN=<token> python scripts/dev/run.py --timeout 3600 --port 8761 --
   rapidtriage-web --host 127.0.0.1 --port 8761` (or the QA runbook's own command).
2. Import the C2 result folder as a perf-only run (`POST /api/runs/import {"output_dir": "<C2 result>"}`
   or the console's 열기) and note its `run_id`. The review-mark item marks 7 rows 관련 있음 and takes
   each back with Ctrl+Z; the marks are undone but stay in that run's review history, so never use
   the case's working run.
3. Pick the knobs for that case (tree node ids are the `data-node-id` of the tree items; use leaf nodes that open a list, their parents are expanded by the spec):

| env | meaning | default (synthetic) |
|---|---|---|
| `RAPIDTRIAGE_PERF_BASE_URL` | server to measure; no server is started | (own server) |
| `RAPIDTRIAGE_PERF_TOKEN` | API token of that server | `e2e-token` |
| `RAPIDTRIAGE_PERF_RUN_ID` | run to measure; no fixture is imported | (fixture import) |
| `RAPIDTRIAGE_PERF_GRID_KIND` | artifact kind of the J/K, viewer, mark and scroll grid (many rows) | `windows-filesystem` |
| `RAPIDTRIAGE_PERF_CATEGORIES` | tree node ids: the first is measured, the others are opened in between (not measured) | `domain:web:web-all,domain:eventlog:evt-all` |
| `RAPIDTRIAGE_PERF_QUERIES` | ≥ 7 distinct queries that each return rows (a repeated query is served from cache; a query with no rows fails the run) | `Chrome,합성,docx,Outlook,History,example,synth` |
| `RAPIDTRIAGE_PERF_LABEL` | label in the JSON | `real` / `synthetic-r8-rich` |
| `RAPIDTRIAGE_PERF_OUTPUT` | JSON path | `frontend/test-results/perf/…` |
| `RAPIDTRIAGE_PERF_COMPARE` | earlier JSON: adds per-item p75 deviation (limit 20 %) | — |
| `RAPIDTRIAGE_PERF_COMMIT` | commit recorded in the JSON | `git rev-parse HEAD` |

4. Run it twice at the same commit, the second time comparing with the first (PowerShell on C2):

```powershell
cd frontend
$env:RAPIDTRIAGE_PERF_BASE_URL = "http://127.0.0.1:8761"
$env:RAPIDTRIAGE_PERF_TOKEN = "<token>"
$env:RAPIDTRIAGE_PERF_RUN_ID = "<run_id>"
$env:RAPIDTRIAGE_PERF_GRID_KIND = "windows-filesystem"
$env:RAPIDTRIAGE_PERF_CATEGORIES = "domain:web:web-all,domain:eventlog:evt-all"
$env:RAPIDTRIAGE_PERF_QUERIES = "<q1>,<q2>,<q3>,<q4>,<q5>,<q6>,<q7>"
$env:RAPIDTRIAGE_PERF_LABEL = "c2-baseline"
$c = git rev-parse --short HEAD
$env:RAPIDTRIAGE_PERF_OUTPUT = "D:\rapid-qa\derived\r8\perf\interaction-c2-$c-1.json"
python ..\scripts\dev\run.py --timeout 900 -- npm run e2e -- e2e/perf/interaction.spec.ts
$env:RAPIDTRIAGE_PERF_COMPARE = $env:RAPIDTRIAGE_PERF_OUTPUT
$env:RAPIDTRIAGE_PERF_OUTPUT = "D:\rapid-qa\derived\r8\perf\interaction-c2-$c-2.json"
python ..\scripts\dev\run.py --timeout 900 -- npm run e2e -- e2e/perf/interaction.spec.ts
```

The first file is the C2 baseline (p75 per item); the second one's `compare.items[].within` shows the
same-commit repeatability (≤ 20 % per item). Search queries and case values stay in
`D:\rapid-qa\derived\r8\perf\` with the JSON, never in Git.

## Reading the JSON

`schema` `rapidtriage-interaction-perf/1`; `items[]` has `id`, `budget`, `unit`, `samples` (5),
`commit_samples`, `p75`, `within_budget`; `unmeasured` (must be 0); `compare` when
`RAPIDTRIAGE_PERF_COMPARE` was set. Sub-frame items (J/K, mark) move in whole frames (≈16.7 ms), so
their deviation is read against one frame as well as the 20 % ratio.
