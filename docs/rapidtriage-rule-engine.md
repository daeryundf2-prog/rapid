# rapidtriage rule engine and IOC lookup plan

This document captures the planned contract for the `rapidtriage` rule-engine and IOC lookup addition requested for the current workstream. The implementation is intended to be **additive**: existing command outputs keep their current shape, while rule/IOC metadata is added through new fields.

The canonical sample rule file lives at `docs/samples/rapidtriage-rules.sample.yaml`.

## Goals

- Load analyst-authored rule files from YAML or JSON.
- Support rule conditions for `ext`, `path`, `date`, `artifact`, `keyword`, `hash`, `domain`, and `url`.
- Record `matched_rules` and `ioc_hits` in `files`, `docs`, `artifacts`, `timeline`, and `run-summary` outputs.
- Keep the contract additive so existing consumers do not break.

## Recommended rule file shape

YAML and JSON should use the same object layout.

Top-level keys:

- `version`
- `defaults`
- `rules`
- `iocs`

### `defaults`

Recommended defaults:

- `match`: default boolean strategy (`any` or `all`)
- `timezone`: timezone used when date windows are authored without offsets
- `hash_algorithms`: allowed hash types such as `sha256` and `md5`

### `rules[]`

Each rule should include:

- `id`: stable identifier written to output payloads
- `name`: analyst-facing label
- `description`: short explanation of why the rule exists
- `severity`: optional priority label such as `low`, `medium`, `high`
- `tags`: optional classification labels
- `match`: optional override for `any` vs `all`
- `conditions`: one or more condition blocks

Supported `conditions` keys:

- `ext`: extension allow/block matches
- `path`: substring, glob, or regex-style path matches
- `date`: modified/created/accessed windows
- `artifact`: provider, artifact kind, or artifact type filters
- `keyword`: keyword hits from document text or previews
- `hash`: exact hash matches against extracted file hashes
- `domain`: observed domain matches from documents or artifact details
- `url`: observed URL matches from documents or artifact details

## Output additions

The rule engine should add fields without removing existing keys.

### `files`

Per candidate row, add:

- `matched_rules`: array of rule-match objects
- `ioc_hits`: array of IOC-hit objects

Recommended `matched_rules[]` shape:

- `rule_id`
- `rule_name`
- `severity`
- `matched_on`: condition types that matched

Recommended `ioc_hits[]` shape:

- `type`: `hash`, `domain`, `url`, or `keyword`
- `value`: normalized IOC value
- `source`: IOC list/source label
- `context`: short explanation or evidence location

### `docs`

For each result row, add:

- `matched_rules`
- `ioc_hits`

Keyword matches should be reusable as both document search output and rule-evaluation evidence.

### `artifacts`

For each artifact row, add:

- `matched_rules`
- `ioc_hits`

Artifact-based rules should support matching on collector `kind`, provider name, artifact type, and artifact detail values.

### `timeline`

For each event row, add:

- `matched_rules`
- `ioc_hits`

Timeline events derived from `files`, `docs`, or `artifacts` should carry forward the matches that produced the event so analysts can pivot from chronology back to the originating evidence.

### `run-summary`

Recommended additive summary fields:

- `summary.rule_match_counts`
- `summary.ioc_hit_counts`
- `highlights.rule_hits`
- `highlights.ioc_hits`

Run-level reports should aggregate by rule id and IOC type while preserving the per-output evidence in the component JSON files.

## Integration review notes

Current modules that will need coordinated updates:

- `rapidtriage/core/docs.py` — add rule/IOC evaluation to document candidates and results
- `rapidtriage/core/files.py` — evaluate file metadata, hashes, and path/date conditions
- `rapidtriage/core/artifacts.py` — evaluate provider/artifact/detail matches
- `rapidtriage/core/timeline.py` — propagate `matched_rules` and `ioc_hits` into generated events
- `rapidtriage/core/run.py` — aggregate rule and IOC counts into run summaries and report highlights
- `rapidtriage/core/models.py` — extend dataclasses or output shims for additive fields
- `rapidtriage/schemas/*.schema.json` — update JSON Schema contracts for every touched command

## Quality guardrails

- Prefer one shared evaluator instead of duplicating rule logic in each command.
- Normalize IOC values before comparison (`lower()` for domains/URLs, canonical hex for hashes).
- Emit empty arrays instead of omitting `matched_rules` / `ioc_hits` when no match exists.
- Treat schema, sample JSON, README, and tests as one contract update.
- Keep field names stable and additive to protect downstream automation.

## Sample coverage checklist

The sample rule file should exercise all requested condition families:

- `ext`
- `path`
- `date`
- `artifact`
- `keyword`
- `hash`
- `domain`
- `url`

## Sample rule file

See `docs/samples/rapidtriage-rules.sample.yaml` for the concrete YAML example. JSON support should mirror the same object structure.
