# Rust indicator extraction

The `indicators` command and the indicators stage of `run` use Python by default. Build the workspace worker and set the switch to the literal value `1` in the environment of the process running the analysis.

```sh
cargo build --manifest-path engines/rust/Cargo.toml --release --locked -p rapid-indicators
export RAPIDTRIAGE_RUST_INDICATORS=1
```

In PowerShell, use `$env:RAPIDTRIAGE_RUST_INDICATORS = "1"`. The resolver checks the workspace release directory first, then searches PATH for `rapid-indicators` (or `rapid-indicators.exe`). A fresh indicators stage reads the switch. A resumed run that reuses an indicators checkpoint retains that checkpoint's results.

## Matching contract

| Stage or family | Behavior |
| --- | --- |
| Traversal | Read existing files for sorted output names `docs`, `files`, and `artifacts_*`. Walk mapping members and lists in input order. Scan non-null mapping scalars converted with Python `str`, with lengths 1 through 4,096 characters. Skip provenance subtrees and leaves according to the policy in `indicators.py`. Ignore primitive list items. |
| Storage | Inline objects follow depth-first member order. JSONL artifact outputs scan the header, then stored rows in file order, retaining original row indices and skipping excluded registry inventory row types. Streamed JSON consumes child containers before emitting buffered sibling scalars. Each mode retains its original citation order. |
| URL and domain | Find case-insensitive HTTP(S) schemes even inside words. Consume at least one character up to whitespace or any bracket, parenthesis, brace, quote or angle bracket. Python strips surrounding whitespace and trailing `.,);]`, validates the URL and applies the existing host/template exclusions. Emit the accepted URL followed by its accepted lowercased hostname. Keep the first URL spelling and deduplicate on `str.lower()`. |
| IPv4 | Match four groups of one to three decimal digits separated by literal dots, with a word boundary at each end. Python validates the address and applies field, version, path, leading-zero, broadcast and contextual rejection rules in their original order. Retain the accepted spelling and the existing private-address classification. |
| Hashes | Match a word-bounded run of 32, 40 or 64 ASCII hex characters. Python applies placeholder, label, hash-field, standalone and binary-blob checks. It emits a lowercase MD5, SHA-1 or SHA-256 value according to length. |
| Order and overlaps | Scan URL, IPv4 and hash families independently, in that order for each scalar. Within a family resume at the end of each match. An IP or hash inside a URL can also match. |
| Citations and reduction | Group by type and comparison value. Count every accepted occurrence. Keep unique, nonempty source mappings up to the source cap in encounter order. Citations contain output name, output path and escaped JSON pointer, plus present context fields from the immediate parent. These are `path`, `source_path`, `artifact_type`, `kind`, `event_type`, `source`, `parser`. Sort final indicators by severity rank, descending count, type and displayed value, then apply the indicator cap. |
| Rule hits and enrichment | Python separately consumes existing `ioc_hits`, preferring nested hits over root hits, and groups normalized values by rule ID and type. Rule matching, enrichment, row hashes, rejection counts and source locators use the existing Python code. The scalar matcher has no separate email, file-path, wallet, Korean ID, telephone or account family. |

## Python allow-list and fallback

The Rust worker implements the three candidate patterns directly on ASCII bytes. ASCII word characters are letters, digits and underscore. Python whitespace includes bytes 0x09–0x0D and 0x1C–0x20. Offsets are half-open character offsets, which equal byte offsets throughout the admitted alphabet. NUL is ordinary input to the length-framed protocol.

Every scalar containing a non-ASCII character goes through the full Python matcher, including Hangul, CP949-decoded text, combining marks and unpaired surrogates. This preserves the installed Python version's Unicode `\d`, `\w`, `\b`, `\s` and case-insensitive behavior, including the long s in an HTTPS scheme. Python and Rust regex engines have different Unicode word classes and Unicode data versions. The field-key tokenizer's negative lookahead and all context/label expressions stay in Python. No Unicode tables or lookarounds are translated.

One local worker process receives up to 8,192 scalar fields in a batch, with an additional roughly 1 MiB text budget. It returns ordered spans only for matches. Python applies a batch after validating the response framing, row count, span bounds and ordering. On an unavailable worker, timeout, nonzero exit or malformed response, Python replays that entire batch in traversal order and scans the remaining fields. Earlier successful batches keep their counts.

The opt-in indicator output contains `indicator_kernel.native_rows`, `python_rows` and `fallback_reason`. These counts refer to eligible scalar fields. A null reason with Python rows records the Unicode policy. Run summaries expose the same metadata at `disclosures.indicators.kernel`.

## Reproduce the comparison

```sh
RAPIDTRIAGE_RUST_INDICATORS=1 python -m unittest tests.test_rust_indicators
python scripts/benchmark-indicators.py --records 50000 --repeats 3
```

The differential tests exercise the release binary, existing synthetic outputs, candidate spans and complete summaries for inline, JSONL and streamed records. The benchmark alternates engine order, uses one generated JSONL input and includes traversal, worker startup, transport and finalization. It checks every summary field except invocation time and engine metadata. To measure an existing synthetic run, use `--run-summary PATH` in place of `--records` and keep its referenced output files available.
