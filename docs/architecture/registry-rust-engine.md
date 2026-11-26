# Registry hive reader: opt-in Rust engine

The hive-reading layer of the Windows registry collectors — `NativeRegistryHive` in
`rapidtriage/artifacts/windows/registry.py`, plus the whole-hive free-cell allocator walk and the
UTF-16LE string pivot — has a second, opt-in engine written in Rust:
`engines/rust/crates/rapid-registry`, exposed to Python as the PyO3 extension module
`rapid_registry_native`. Python stays the default.

Everything built on the reader uses it unchanged: key-tree rows, hive completeness
(hbin reconciliation), free-cell recovery candidates, the SYSTEM/SOFTWARE/NTUSER plugins
(`Select\Current` control set, services, USB, persistence), registry-depth rows, ShellBags,
Amcache/UserAssist/BAM/ShimCache, SAM accounts, media-player MRUs and the registry tree API.

## Selecting the engine

| How | Value |
| --- | --- |
| Environment | `RAPIDTRIAGE_REGISTRY_ENGINE=rust` (or `python`, the default) |
| CLI | `rapidtriage --registry-engine rust <command> ...` (sets the variable for the process and its children) |

Build and stage the extension once per checkout (it lands in the gitignored native folder under the `rapidtriage` package):

```sh
python scripts/build-native-accel.py --crate rapid-registry
```

When `rust` is requested but the extension is missing, fails to import, or was built for another
contract (`ABI_VERSION`), or the value is unknown, the Python engine is used, a warning is logged
once, and every `registry-hive` row records the outcome:

- `native_registry_engine` — engine that actually read the hive (`rust` / `python`);
- `native_registry_engine_requested` — the requested value;
- `native_registry_engine_notice_ko` — Korean fallback notice (empty when the request was honoured).

These three provenance fields appear only when a non-default engine was requested, so default
output is unchanged. Selection logic: `rapidtriage/artifacts/windows/registry_engine.py`.

## Design choice: own port, not an existing crate

[notatin](https://github.com/strozfriedberg/notatin) (Apache-2.0, Stroz Friedberg) is the mature
Rust registry parser; its last crates.io release (1.0.1) is from 2023-08 and the repository is
lightly maintained. It was not used because the requirement is *identical rows*, and notatin is a
different parser with its own semantics: it replays transaction logs, applies its own recovery and
cell-validation rules, decodes names and strings differently, and has no notion of this project's
walk-error counters, tolerance rules or `RegistryValueMap` lookups. Every Rapid behaviour that
reaches a row would have had to be re-imposed on top of it, which is more code and more risk than
porting the reader (about 400 lines of Python) directly.

`rapid-registry` is therefore a line-for-line port of the Python reader:

- the same cell bounds rules against the readable hive-bin end, short reads past end of data,
  `ri` depth limit, `lf`/`lh`/`li`/`ri` handling, big-data (`db`) assembly, and the same walk-error
  keys appended to the hive's own `errors` Counter in the same order;
- CPython-exact text: Latin-1 / UTF-16LE (`errors="replace"`, including CPython's error ranges
  for unpaired surrogates and odd trailing bytes), `REG_SZ`/`REG_MULTI_SZ` truncation rules,
  FILETIME rendering with all seven 100 ns digits;
- case-insensitive lookups fold ASCII names in Rust and defer non-ASCII names to Python's own
  `str.casefold`, so Unicode case folding matches the running interpreter exactly;
- it reads the very buffer (`mmap` or `bytes`) the Python object holds, with the geometry Python
  computed, through the buffer protocol (no copy, no second mapping).

`RustRegistryHive` (a `NativeRegistryHive` subclass) delegates the cell reads to the extension;
keys and values are the extension's `NativeRegistryKey`/`NativeRegistryValue` objects with the
same attributes. Header parsing, mount resolution and every consumer stay in Python.

## Verification

`tests/test_registry_rust_differential.py` runs both engines and requires zero differences:

- reader traces (`tests/registry_engine_diff.py`): every key/value field and type, last-write
  ticks, raw and decoded value data, data-cell allocation state, case-variant `value`/`subkey`/
  `open_key` lookups, raw `key_at`/`value_at`/`cell_allocated` probes (misaligned, out of range,
  beyond 32 bits), free-cell candidates and allocator stats, the string pivot, and the `errors`
  Counter after each step;
- hives: the existing synthetic fixtures (SYSTEM with `Select\Current`, SOFTWARE, SAM, NTUSER,
  UsrClass/ShellBags, Amcache, USB, PuTTY, Office MRU cycles), generated multi-hbin hives
  (`tests/registry_hive_gen.py`: up to 6000-key trees, deleted key/value cells, big data,
  Korean/Latin-1/case-folding/surrogate names) and damaged variants (truncated hbins, signature
  gaps, invalid hbin sizes, declared size beyond file, subkey-count mismatch, cycles, misaligned
  and dangling references, unknown list signatures, free-cell references, missing big-data
  segments, nk/vk signature damage, unresolved root, `ri` depth overflow, random byte damage);
- collector rows: registry, ShellBags, execution, OS-account and media-player collectors over two
  evidence trees, compared as order-sensitive JSON;
- 20,000 random byte strings and 40,000 FILETIMEs against CPython's decoders.

At the time of writing that is 96 hives (26,322 walked keys, 78,040 values, 7.4 million compared
leaf fields) and 6,474 collector rows (656,004 leaf fields), with zero differences.

CI job `rust-registry` (Linux, Windows, macOS) runs crate fmt/clippy/tests, builds the extension,
runs the differential suite with `RAPIDTRIAGE_REQUIRE_RUST_REGISTRY=1`, re-runs the existing
registry suites with `RAPIDTRIAGE_REGISTRY_ENGINE=rust`, and a benchmark smoke.

## Benchmark

`python scripts/registry-engine-benchmark.py --keys 100000` generates a large hive in a temporary
directory and reports keys/s and values/s for a full walk (`iter_keys` + `values` +
`value_data`), the free-cell allocator scan, and end-to-end `collect_registry_hive`, best of
three runs per engine. Measured on an Apple-silicon Mac (Python 3.12, release build), 100,000
keys / 299,681 values, 245 MB hive:

| Phase | Python | Rust | Speed-up |
| --- | --- | --- | --- |
| Full walk (keys/s, values/s) | 13,906 / 41,674 | 133,310 / 399,504 | 9.6x |
| Free-cell allocator scan | 0.47 s | 0.027 s | 17x |
| `collect_registry_hive`, 186 free-cell candidates | 3.73 s | 0.96 s | 3.9x |
| `collect_registry_hive`, 4,619 free-cell candidates | 38.0 s | 41.0 s | 0.9x |

With thousands of free-cell candidates the end-to-end time is dominated by Python row building
that is outside the reader — `registry_allocator_neighbor_context` re-sorts every candidate for
each candidate (quadratic) — so both engines take the same time there.
