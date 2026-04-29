# RapidTriage LTS And Hotfix Policy

## Branching

- Maintain one active development branch and one release/LTS branch when distributing to analysts.
- Backport only security fixes, parser correctness fixes, crash fixes, and evidence-handling safety fixes to LTS.

## Hotfix Gates

- Add or update a fixture for parser correctness fixes.
- Run unit tests, smoke tests, validation package, and dependency monitoring.
- Update release notes, known limitations, parser coverage, and checksums.
- Do not claim report-grade parser behavior without known-answer evidence.

## Emergency Fixes

- Emergency builds may be issued before broad validation only when the release notes clearly mark the fix scope and validation gap.
- Attach the previous release hash and rollback guidance.
