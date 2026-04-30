# KakaoTalk PC Post-Patch Memory Reversing Notes

This note records the current RapidTriage strategy for authorized PC KakaoTalk
analysis when legacy `chatLogs_*.edb` page decryption no longer opens the
database.

## Evidence Model

RapidTriage keeps the old and new approaches separate:

1. `legacy-page-aes-cbc`: pre-patch `chatLogs_*.edb` page decryption using
   recovered KakaoTalk pragma/user-id material.
2. `postpatch-memory-sqlite-carve`: process-memory triage for post-patch cases
   where legacy EDB decryption fails.
3. `sqlcipher-key-hunt`: experimental follow-up path that records SQLCipher
   keying/migration indicators and redacted key-literal residues from memory.
4. `postpatch-appstate-key-store`: inspection of `appstate.dat` and
   `appstate.dat.backup` to map per-EDB wrapped DEKs without exporting raw key
   bytes.

The memory fallback is not treated as a final decrypted database. It is triage
evidence and must keep source offsets, hashes, parser version, and validation
warnings.

## What The Memory Dump Proves

In the current post-patch sample, selected message text appears in
`KakaoTalk.DMP` as JSON-like chat log residues. The same message terms were not
found in the encrypted `chatLogs_*.edb` files, whose headers look random rather
than SQLite plaintext.

The process dump also contains implementation clues:

- KakaoTalk chat DB symbols such as `TalkChatDB`, `TalkChatDB::_InternalOpen`,
  and `RecoverChatDbFile`.
- SQLCipher symbols and SQL such as `sqlite3_key`, `sqlite3_key_v2`,
  `sqlite3_rekey_v2`, `PRAGMA kdf_iter`, `cipher_page_size`,
  `cipher_hmac_algorithm`, `ATTACH DATABASE ... KEY`, and `sqlcipher_export`.
- Migration/error strings such as `DbLibraryMigration`, `Failed to set new key`,
  `Failed to set legacy key`, and `Failed to open legacy database`.
- Key-store strings such as `talk_db_key_store`, `wrapped_dek_map`,
  `ikm-wrap`, `km-wrap`, `entropy-bound-kek`, and
  `Succeeded to loading the database key store`.
- SQLCipher raw-key style literals in the form `x'<64-or-96-hex>'`; RapidTriage
  records only offsets, lengths, hashes, salt length, and nearby context terms.
  Raw key bytes are intentionally not written to JSON output.

In the current post-patch sample, `appstate.dat` is a definite-length CBOR map
with `info_prefix`, `salt`, and `wrapped_dek_map`. The map contains 34 wrapped
DEK entries in the live `v2:` key store and 34 more in the backup `v1:` key
store. Nine live entries correspond to `chat_data/chatLogs_*.edb`; each wrapped
value is 40 bytes, which is consistent with an AES key-wrap style envelope for a
32-byte database encryption key. This maps the new EDB method more concretely:
the remaining blocker is recovering or deriving the KEK/IKM used to unwrap those
per-database DEKs.

## Current Limitation

The observed SQLCipher key-like residues have not yet opened post-patch
`chatLogs_*.edb` in RapidTriage. They may belong to auxiliary databases, export
migration, cache databases, or transient attach/export operations rather than
the final chat log database key.

The next reverse-engineering target is to bind a key residue to a specific
database path or `TalkChatDB::_InternalOpen` call site. Useful evidence is a
memory window where `chatLogs_<id>.edb`, key material, SQLCipher settings, and
the open/export function occur close together.

RapidTriage also provides `rapidtriage kakaotalk-sqlcipher-probe` for this
research path. It extracts SQLCipher key-literal residues from process memory,
builds raw-key and key-plus-salt variants, and attempts to open
`chatLogs_*.edb` only through temporary file copies. Current negative results
are still useful: if key literals open cache or token databases but not
`chatLogs_*.edb`, they should not be presented as chat DB keys.

RapidTriage also provides `rapidtriage kakaotalk-key-store-inspect`. It parses
`appstate.dat`/backup, records `info_prefix`, salt length/hash, wrapped-DEK
length/hash, chatLog-to-key-store matches, matched EDB hashes, and memory
residency indicators. It does not export raw wrapped DEKs, unwrapped DEKs, or
candidate KEKs.

## RapidTriage Output Fields

`rapidtriage kakaotalk-memory-carve` now reports:

- `entries`: SQLite fragments carved from process memory, with table names,
  schema hashes, row counts where readable, and optional bounded previews.
- `chat_message_residues`: JSON-like message objects with source offset, chat
  id, log id, timestamp, content hash, and optional message preview.
- `reverse_indicators`: offsets for KakaoTalk/SQLCipher strings that explain
  why the memory dump is relevant for reversing.
- `sqlcipher_key_residues`: redacted key-literal candidates with byte length,
  salt length, hashes, and nearby context terms.
- `kakaotalk-sqlcipher-probe`: redacted direct-open attempts against temporary
  `chatLogs_*.edb` copies, including attempt count, SQLCipher compatibility
  mode, matched schema count, and no raw key material.
- `kakaotalk-key-store-inspect`: CBOR key-store inventory for appstate files,
  including wrapped-DEK counts, chatLog matches, EDB source hashes, memory
  residency checks, and explicit unwrap/known-answer validation blockers.

## Operator Guidance

Run legacy decrypt first. If no `chatLogs_*.edb` opens, run the memory fallback
against an authorized process dump and preserve the original dump hash. Treat
message residues as volatile process-memory evidence until corroborated by EDB,
registry, timeline, or mobile/export data.

For post-patch EDB work, run `kakaotalk-key-store-inspect` before brute-force or
manual reverse-engineering. If the tool reports `key-store-mapped`, the EDB
files are linked to wrapped DEKs and the next task is KEK/IKM recovery, not
legacy PRAGMA derivation.
