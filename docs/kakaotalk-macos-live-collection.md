# KakaoTalk macOS live memory collection — field procedure

This page describes the authorized, consent-based procedure for collecting the
running KakaoTalk process memory of a logged-in macOS user, and how RapidTriage
analyzes the resulting dump. It covers the collector command
`kakaotalk-collect-macos`, its preflight checks, the manifest it writes, and the
macOS Mach-O core support added to the memory-carve analysis.

> **Authorized use only.** Collect only a live session you are legally
> authorized to examine, with the account holder physically present and
> consenting. The collector never bypasses macOS security controls; if the
> system refuses access, the refusal is recorded and collection stops.

## When to use it

Use this on site, during an authorized examination, when the subject is logged in
to KakaoTalk on their Mac and consents to a live acquisition. Post-patch
KakaoTalk keeps chat-database keys and decrypted message residues in process
memory, so a live core can hold evidence that is not recoverable from disk alone.

For disk-based artifacts (container inventory, database openability), use
`kakaotalk-macos-report` instead. For carving an already-collected dump, use
`kakaotalk-memory-carve` (see "Analysis" below).

## Method on current macOS

The collector uses the debugger's documented core-dump facility:

```
lldb -b -o "process attach --pid <pid>" \
        -o "process save-core --style=modified-memory <out>.core" \
        -o "detach" -o "quit"
```

`process save-core` writes a 64-bit Mach-O core file (`MH_CORE`) whose
`LC_SEGMENT_64` load commands describe each mapped region. Under the hood this
relies on the kernel granting the target task port (`task_for_pid` /
`mach_vm_read` of readable regions); lldb is simply the supported front end.

### Requirements and limits

macOS — not RapidTriage — decides whether the task port is granted. The preflight
reports each of these so the operator knows what to expect:

- **Admin / sudo.** Reading another user's process requires root. Run the command
  under `sudo` with the account holder present. The preflight reports the
  effective UID and whether it is 0.
- **System Integrity Protection (SIP).** `csrutil status` is reported. SIP
  governs debugging of system and protected processes.
- **Developer Mode / debugging authorization.** `DevToolsSecurity -status` is
  reported. Debugging may require developer-mode authorization.
- **Hardened runtime / `get-task-allow`.** KakaoTalk ships with the hardened
  runtime and no `get-task-allow` entitlement, so macOS may refuse the task port
  even to root. This is expected and is reported as a refusal — it is never
  bypassed. If the system refuses, note it in the field record and fall back to
  authorized disk acquisition.
- **lldb availability.** Requires the Xcode command line tools. The preflight
  reports the lldb version or that it is missing.

### What works without admin

Without root you can still run the preflight to document system posture, and you
can run every downstream analysis step (`kakaotalk-memory-carve`,
`kakaotalk-sqlcipher-probe`) against an already-collected core. Only the live
`save-core` step needs root; the preflight clearly marks it as blocked when the
effective UID is not 0.

## Running the collector

Document posture first, without attempting any dump:

```
rapidtriage kakaotalk-collect-macos --output-root ./cases --preflight-only
```

Perform an authorized, consenting collection:

```
sudo rapidtriage kakaotalk-collect-macos --output-root ./cases \
        --operator "Investigator Name" \
        --consent-statement "Account holder consented on site on 2026-11-25" \
        --authority-reference "Case 2026-1234"
```

Key options: `--operator` (recorded), `--consent-statement` (recorded; required
unless `--preflight-only`), `--authority-reference`, `--lldb-bin`,
`--save-core-style` (`modified-memory`, `full`, `stack`), `--timeout-seconds`,
`--preflight-only`, and `--json`.

### Manifest and provenance

Each case directory holds a `collection_manifest.json` with:

- SHA-256 hash, size, and UTC mtime of every collected file (the cores).
- `generated_at` timestamp and the macOS, architecture, and lldb tool versions.
- The `user_consent` block: operator, consent statement, authority reference, and
  the consent-recorded timestamp.
- The full `preflight` result (checks, blockers, advisories).
- Per-process `core_dumps` entries with status (`saved`, `refused`,
  `tool-error`) and the exact lldb command used.

An audit record is written alongside the manifest, with sensitive material
redacted.

## Analysis: reading the macOS dump format

The memory-carve and residue analyses understand the Mach-O core format the
collector produces, in addition to Windows minidumps and raw region dumps:

- `detect_memory_dump_format` classifies a dump as `minidump`, `macho-core`, or
  `raw`.
- `build_memory_address_ranges` parses `LC_SEGMENT_64` load commands into
  `(virtual_address, size, file_offset)` ranges, so virtual-address mapping works
  on macOS cores.
- `kakaotalk-memory-carve` tags each carved SQLite fragment with its
  `memory_dump_format` and a `region_provenance` block naming the containing
  segment (index, name, virtual address, file offset, protection) and the mapped
  virtual address of the hit.

Carve an authorized core and its region provenance:

```
rapidtriage kakaotalk-memory-carve ./cases/kakaotalk_macos_collection_*/collection \
        --output kakao-macos-carve.json
```

The collected `.core` files are picked up automatically by the memory-dump
discovery used by the carve and SQLCipher-probe workflows.

## Legal and consent notes

- Only collect within a lawful authorization (consent, warrant, or equivalent).
  Record the authority in `--authority-reference`.
- Obtain and record the account holder's informed consent before a live
  acquisition; `--consent-statement` is stored verbatim in the manifest.
- Live memory acquisition is inherently non-reproducible: the process state
  changes continuously. The manifest timestamps and hashes establish what was
  captured and when.
- Never disable SIP, strip entitlements, or otherwise weaken system security to
  force a collection. If macOS refuses, document the refusal and stop.
- Collected cores may contain third-party personal data beyond the subject.
  Handle, store, and dispose of them under the applicable legal and evidentiary
  rules.
