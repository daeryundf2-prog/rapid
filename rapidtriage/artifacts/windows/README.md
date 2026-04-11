# Windows artifact collector notes

This package keeps Windows-specific collection logic outside the OS-agnostic `rapidtriage.core` modules.

## Initial collection scope

The first real collector pass should focus on:

- browser history
- browser downloads
- recent files / recent items

Keep each artifact family behind a dedicated Windows module so the core CLI can continue treating providers as pluggable JSON producers.

## Implementation guidelines

- Keep parsing and filesystem access in `rapidtriage.artifacts.windows.*`.
- Keep `rapidtriage.core` limited to orchestration, shared models, and JSON serialization.
- Prefer normalized dictionaries that are immediately JSON serializable.
- Use stable machine-readable `provider` and `artifact_type` values.
- Normalize timestamps as ISO-8601 strings when present; use `null` when unavailable.
- Return deterministic ordering so repeated runs on the same fixture produce stable JSON.
- For browser SQLite databases, copy to a temporary path before reading when the live file may be locked on Windows.

## Recommended result fields

At minimum, keep each collected row consistent with the existing artifact manifest model:

- `provider`
- `artifact_type`
- `path`
- `supported`
- `details`

Recommended `details` keys for the first collector wave:

- `browser`
- `profile`
- `user`
- `source_path`
- `target_path`
- `url`
- `title`
- `last_visited_at`
- `started_at`
- `ended_at`
- `last_opened_at`
- `evidence_type`

Not every row needs every field, but missing values should remain explicit and predictable.

## Fixture guidance

- Prefer small synthetic fixtures over live user data.
- Keep one fixture set per artifact family.
- Include cases for empty data, multiple profiles, and non-ASCII paths where practical.
- Assert the JSON shape and a few representative field values instead of overfitting to implementation details.

## Review checklist

Before merging Windows collectors, confirm that:

- provider boundaries remain OS-specific
- output is JSON serializable without custom encoders
- locked or missing source files fail gracefully
- timestamps are normalized consistently
- tests use deterministic fixture data
