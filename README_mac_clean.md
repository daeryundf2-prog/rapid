# Mac Storage Cleaner (safe audit-first)

This folder includes `mac-clean.sh`, a safe, audit-first cleanup script for macOS.

- Defaults to audit (no deletions). Add `--run` to actually clean.
- Offers a "safe" preset (`--all`) and an "aggressive" add-on (`--aggressive`).
- Targets caches, old logs, Trash, Xcode build artifacts, simulators, Homebrew leftovers, and more.
- Prompts before each destructive step unless `-y/--yes` is passed.

## Quick start

1) Audit what can be freed (safe preset):

```bash
./mac-clean.sh --audit --all
```

2) Perform cleanup (safe preset):

```bash
./mac-clean.sh --run --all -y
```

3) Add aggressive items (use with care):

```bash
./mac-clean.sh --audit --all --aggressive
# then, if the totals and prompts look good
./mac-clean.sh --run --all --aggressive -y
```

## Useful options

- `--keep-days=N` — age threshold for log files, Xcode archives, iOS backups (default 30).
- `--big[=SIZE]` — list large files under your home (default `1G`), no deletion.
- Package caches: `--npm`, `--yarn`, `--pnpm`
- Individual toggles: `--caches`, `--logs`, `--trash`, `--xcode`, `--sims`, `--brew`, `--docker`, `--ios-backups`, `--imessage`, `--quicklook`, `--snapshots`.

## Notes and safety

- "System Data" in macOS storage often includes local Time Machine snapshots, caches, logs, and temporary data. This script focuses on safe, user-space cleanup first.
- Docker pruning and iMessage deletions are risky and disabled unless explicitly requested.
- Snapshot thinning uses `tmutil` and may require admin; it requests ~10 GB of reclamation.
- After big cleanups, rebooting or logging out/in can help the Storage graph update.

## Uninstall

Just delete the files:

```bash
rm -f mac-clean.sh README_mac_clean.md
```

