# AI coding-agent artifacts

Point the collector at a mounted or exported evidence directory containing the profile trees. Select a kind with the normal artifacts command.

```sh
python -m rapidtriage artifacts ./sample-evidence --kind codex-cli --output ./artifacts-codex-cli.json
```

The execution section of the evidence tree includes these kinds. Seizure, fraud, hacking and recovery runs schedule them.

| Kind | Evidence-relative paths | Records |
| --- | --- | --- |
| `claude-code` | `.claude/projects/**/*.jsonl`, `.claude/history.jsonl`, `.claude.json`, `.claude/settings{,.local}.json` | User and assistant text, tool use and results, working directory, model, typed prompt history with its project folder, and selected settings |
| `codex-cli` | `.codex/sessions/**/*.jsonl`, `.codex/history.jsonl`, `.codex/config.toml` | Replay messages, function and custom tool calls and results, turn model and working directory, prompt history and settings |
| `gemini-cli` | `.gemini/tmp/*/chats/*.json` or `*.jsonl`, `.gemini/tmp/*/logs.json`, `.gemini/settings.json` | Session messages, tool calls and embedded results, prompt logs and settings |
| `editor-chat` | `<editor>/User/globalStorage/state.vscdb`, `<editor>/User/workspaceStorage/*/state.vscdb`, `<editor>/User/workspaceStorage/*/chatSessions/*.json`, `<editor>/User/globalStorage/emptyWindowChatSessions/*.json` | Selected chat and composer JSON in SQLite `ItemTable` and `cursorDiskKV`, and VS Code chat session files |
| `agent-mcp` | The CLI settings above, project `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and editor `User/mcp.json` | One row per configured server with name, configured command and environment variable names |

The editor may appear under Windows `AppData/Roaming`, macOS `Library/Application Support` or Linux `.config` in the evidence. The recognized product directories are Cursor, Code, Code - Insiders and VSCodium. Product directories can belong to any profile. Discovery matches path components below the evidence root only; the examiner's own home directory and environment are never consulted, and symbolic links that leave the evidence root are skipped. The collector reads a verified private SQLite snapshot, includes committed WAL content and queries only ordinary tables. A WAL, shared-memory or journal sidecar that is not a regular file, or a hot rollback journal, makes the database unreadable with a diagnostic instead of being followed or replayed. SQLite locators identify a table, rowid and key. Recognized keys include `bubbleId:*`, `composerData:*`, `composer.composerData`, `aiService.prompts` and selected workbench chat keys. Index-only or unfamiliar chat values can produce a diagnostic.

## Reading a row

`source_path` is relative to the evidence root. JSONL citations use a one-based physical line and zero-based byte offset. A whole JSON or TOML document starts at offset zero. Array indexes, project and server names distinguish entries within documents. SQLite rowids are logical locators.

Text messages, tool calls and tool results have distinct artifact types. An assistant message with text and two tool calls produces three rows. Structured tool arguments and patch headers supply referenced file paths. A call records a request to operate on a file. Any recorded result is a separate observation. Tool names can be associated with results by call ID within a session and file.

`timestamp_raw` preserves the source representation. `timestamp_utc` is ISO 8601 UTC with a `+00:00` offset. Text is normalized only when it is an RFC 3339 date-time with an explicit `Z` or `±HH:MM` offset (hours 00-23, minutes 00-59; an out-of-range offset such as `+01:60` is not rolled over); week dates, the basic format, a space separator and wall times without an offset are not guessed. Fraction digits are kept as recorded, padded to microseconds, so nanosecond digits are not rounded. Claude prompt history and editor values use integer epoch milliseconds and Codex history integer epoch seconds, converted exactly. Tool blocks can share the timestamp of their enclosing message. Embedded Gemini results share the recorded call time, which does not establish a separate completion time. The timeline uses only normalized evidence timestamps. A missing time stays empty. An ambiguous or invalid time carries `timestamp-not-normalized`. Missing session IDs, roles, models and paths stay empty.

`schema-version-not-validated` marks every row in this release. The input layouts have synthetic fixture coverage. A product version and a declared schema version are separate fields, copied only from the record that declares them (`version`, `cli_version`, `schemaVersion`, or a VS Code chat session file's `version`). When neither is recorded the row carries `version-unknown`; no version is inferred from field shapes. Gemini JSONL update and rewind records receive a diagnostic because reconstructing the final edited conversation requires replay. Codex user and assistant progress messages are compared with replay messages by role, exact text and occurrence count within the same file. If a progress message is present, a second bounded pass counts up to 20,000 replay messages. Independent prompt history may document the same interaction.

## Bounds and privacy

| Scope | Limit and behavior |
| --- | --- |
| JSONL | 64 MiB prefix per source, 1 MiB per physical line including its delimiter. Oversized lines are drained in bounded chunks. Malformed UTF-8, malformed JSON and oversized lines produce cited diagnostic rows with a damage count. |
| Whole JSON or TOML | 8 MiB per document. Larger documents produce a diagnostic. |
| SQLite | 256 MiB for the database and sidecars combined, 2 MiB per selected value. Oversized inputs produce diagnostics. |
| Output | 20,000 rows per source and kind, then a limit diagnostic. Text fields hold up to 8,192 characters and lists up to 64 entries. Tool-name correlation retains up to 1,024 call IDs per source. |

MCP rows select server names, executable commands and environment variable names. Environment values, server arguments, headers and connection URLs are omitted. Every exported text field, including commands, file paths and tool results, passes redaction before it reaches a row: Rapid's URL credential redaction, the whole value of `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` headers in any scheme, credential assignments and option values (API keys, access and secret keys, tokens, passwords), bearer and basic credentials, private key blocks, JSON Web Tokens, AWS access key IDs and common token prefixes (`sk-`, GitHub, GitLab, Slack, Google, Hugging Face, npm). Arbitrary free text and command lines can still contain sensitive material without a recognizable label.

## Public format references

- Claude Code documents the session transcript path, tool inputs, user settings and project MCP configuration. [Hooks reference](https://code.claude.com/docs/en/hooks) · [Settings](https://code.claude.com/docs/en/settings) · [MCP](https://code.claude.com/docs/en/mcp)
- Codex documents the configuration keys and rollout item families. [Prompt history format](https://github.com/openai/codex/blob/main/codex-rs/message-history/src/lib.rs) · [Configuration reference](https://developers.openai.com/codex/config-reference/) · [Rollout record types](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/persistence_metrics.rs)
- Gemini CLI documents session storage, conversation record fields, updates and MCP settings. [Session management](https://geminicli.com/docs/cli/session-management/) · [Recording types](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingTypes.ts) · [MCP settings](https://geminicli.com/docs/tools/mcp-server/)
- Cursor's forum documents firsthand observations of SQLite key families and per-bubble model names. These are observed layouts without a published versioned contract. VS Code documents its MCP configuration. [SQLite key families](https://forum.cursor.com/t/state-vscdb-grows-to-30gb-due-to-bubbleid-agentkv-entries/167641) · [Bubble model information](https://forum.cursor.com/t/show-which-model-handled-each-step-when-using-auto-mode/164163/9) · [VS Code MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
