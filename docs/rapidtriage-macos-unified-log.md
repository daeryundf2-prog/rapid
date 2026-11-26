# macOS Unified Log events

Select **macOS 통합 로그** in a run plan or use the `macos-unified-log` artifact kind. Supply an offline `.logarchive` directory, an evidence root containing archives, or an extracted volume with `private/var/db/diagnostics` and its sibling `private/var/db/uuidtext`. Select their common parent to make both raw trees accessible. The collector resolves sidecars within each store and skips symbolic links.

```sh
python -m rapidtriage artifacts ./evidence --kind macos-unified-log --output ./unified.json
python -m rapidtriage timeline ./evidence --artifacts ./unified.json --output ./timeline.json
```

## Reading an event

Each `macos-unified-log-event` cites the trace file, physical byte offset and length. The catalog joins the Firehose process key to a PID, image UUID and subsystem/category table. A process image path comes from UUIDText. `format_source_path`, `format_uuid` and `format_offset` locate a referenced format in UUIDText or the shared cache. The format offset is a virtual string-table address.

The boot UUID identifies the clock domain. `continuous_time` holds integer ticks and `continuous_time_raw` preserves the decimal digits for clients with limited integer precision. For a matching timesync boot, the latest calibration record at or before the event supplies the origin. The boot record's wall time dates tick zero and applies only to events before the first calibration record. Rapid applies the timebase numerator and denominator with integer arithmetic and writes UTC with nanosecond precision. `timesync_source_path` and `timesync_source_offset` identify the calibration. Events without calibration retain their ticks. The timeline uses calibrated timestamps and its usual date range.

`message_status` describes the rendered message. For example, the synthetic log template `%{public}s / %{private}s` produces `ok / <private>`. Private descriptors and private or sensitive annotations produce `<private>`. The private data area at the end of a Firehose chunk is never read. A public size that reaches into it marks the chunk damaged. Missing formats or unsupported encodings leave the message empty and keep the structured event.

## Coverage

| Input | Supported content |
| --- | --- |
| tracev3 | Header boot UUID, catalog UUID/process/subsystem mappings, and stored `bv4-` chunksets with a `bv4$` footer. |
| Firehose | Log, activity, signpost and trace headers. Public string and integer arguments for supported format modes. Activity and signpost identifiers where present. |
| UUIDText and DSC | UUIDText 2.1 and shared-cache strings 1.0/2.0. Main image, inline UUID and ordinary shared-cache format offsets. UUIDText members use a two-hex-digit directory and a 30-digit filename. DSC members use a 32-digit filename in `dsc/`. |
| Timesync | Boot records and subsequent clock calibrations, including successive adjustments and multiple boot UUIDs. |
| Compression | This checkout bundles no LZ4 decoder. A framed `bv41` block produces a `compressed-unsupported` diagnostic, its byte offset and a format reference. |

A `macos-unified-log-diagnostic` cites a skipped or damaged structure. Sum `damaged_chunk_count` on diagnostic rows for the number of damaged chunks observed. Multiple malformed entries in the same Firehose chunk count once. A malformed frame with no reliable end terminates that stream. A stream may end inside the 8-byte alignment of its last chunk; any alignment bytes present must be zero. Later files can still contribute events. Missing sidecars, compressed blocks, oversize data, absolute/dynamic or extended format addressing, context arguments, custom printf conversions and non-Firehose record types can leave coverage incomplete.

## Limits and synthetic check

One collection examines up to 65,536 directory entries, opens up to 1,024 files, reads up to 64 MiB per file and 128 MiB total, and emits up to 5,000 events and diagnostics plus a limit notice. A trace has a maximum of 8,192 outer and nested chunks. An archive indexes up to 65,536 string descriptors and 65,536 clock records. String lookup reads up to 4,096 bytes per string and rendering is capped at 4,096 characters. Run the collector on an individual archive to give it a fresh budget.

Generate the four-event fixture in a new directory. It includes an uncompressed tracev3, UUIDText, DSC and timesync. The expected event order is log, activity, signpost, trace.

```sh
python -m tests.unified_log_fixture ./sample.logarchive
python -m rapidtriage artifacts ./sample.logarchive --kind macos-unified-log --output ./sample.json
```

## Format attribution

The independent decoder and synthetic writer use the binary layouts described by the Apache-2.0 `macos-UnifiedLogs` project. The project documents the archive pipeline and the roles of the trace, catalogs and sidecars. [Architecture](https://github.com/mandiant/macos-UnifiedLogs/blob/main/ARCHITECTURE.md) · [License](https://github.com/mandiant/macos-UnifiedLogs/blob/main/LICENSE)

The layout references cover block framing, process lookup, record classes, format-address ranges and calibration records. [Chunksets](https://github.com/mandiant/macos-UnifiedLogs/blob/v0.6.0/src/chunkset.rs) · [Catalog](https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/catalog.rs) · [Firehose](https://github.com/mandiant/macos-UnifiedLogs/tree/main/src/chunks/firehose) · [UUIDText](https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/uuidtext.rs) · [DSC](https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/dsc.rs) · [Timesync](https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/timesync.rs)
