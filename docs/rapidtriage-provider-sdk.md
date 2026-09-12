# RapidTriage Provider Plugin SDK

RapidTriage artifact collection is provider-based: each provider owns a
`collector_kind` and turns a mounted evidence root into `ArtifactRecord` rows.
Built-in providers are registered in `rapidtriage/artifacts/__init__.py` by
`all_providers()`. Out-of-tree providers can be added without modifying the
package by dropping a `*_provider.py` file into a plugin directory.

## Plugin discovery

At provider enumeration time RapidTriage scans, in order:

1. Every directory listed in the `RAPIDTRIAGE_PLUGIN_DIRS` environment
   variable (separated by the platform path separator — `:` on POSIX, `;` on
   Windows).
2. `~/.rapidtriage/plugins/` (the per-user plugin directory).

Each directory is scanned non-recursively for files matching `*_provider.py`.
Files are imported with `importlib.util.spec_from_file_location`, so plugins do
not need to be installed packages and must not rely on package-relative
imports — keep each plugin self-contained in a single file.

A plugin file that fails to import, or that defines no class matching the
provider contract below, is skipped with a `RuntimeWarning`. Provider
enumeration never crashes on a bad plugin. A plugin `collector_kind` that
collides with a built-in or an earlier plugin is skipped with a warning —
plugins cannot shadow built-in collectors.

## Provider contract

A provider class defined in the plugin file is registered when it has:

- `collector_kind` — non-empty string class attribute, lowercase slug
  recommended (e.g. `"acme-email-vault"`). This is the value passed to
  `rapidtriage artifacts --kind` and `get_artifact_collector()`.
- `supported()` — callable returning `bool`; tells the runner whether the
  provider can operate in the current environment (e.g. required external
  tool present). Must not raise.
- `collect(root)` — callable taking a `pathlib.Path` evidence root and
  returning an iterable of `ArtifactRecord` items (see
  `rapidtriage/core/models.py`).

Recommended (not required for registration, but surfaced in output):

- `name` — human-readable provider name.
- `description` — one-line description shown in run metadata.
- `target_platform` — e.g. `"windows"`, `"macos"`, `"linux"`, `"any"`.

Optional hook:

- `with_options(**options)` — when present, `run_artifact_collection` calls it
  to obtain a configured provider instance before collecting.

### ArtifactRecord shape

```python
ArtifactRecord(
    provider="acme-email-vault",      # provider name string
    artifact_type="mailbox-index",    # artifact type slug
    path="/evidence/export/mail.db",  # source path string
    supported=True,                   # row-level support flag
    details={...},                    # free-form JSON-serializable dict
)
```

Keep `details` JSON-serializable; include `parser`, `parser_version`, and
`source_path`/`source_hashes` keys when available so downstream review and
diff tooling can attribute rows.

## Crash-isolation contract

`collect()` runs inside the collection harness in
`rapidtriage/core/artifacts.py`. If `collect()` raises, the run is not lost:
the payload is emitted with `collection_status = "failed-isolated"`, an empty
`artifacts` list, and a `parser_errors` entry naming the collector and error
type. Plugins should still prefer yielding partial results plus
`details`-level error markers over raising.

`supported()` is called outside the crash-isolation boundary — it must never
raise.

## Security note

Plugin files are executed as local Python code with the full privileges of the
RapidTriage process. Only place plugin files in directories you control, and
treat `RAPIDTRIAGE_PLUGIN_DIRS` entries as trusted paths. There is no sandbox;
hostile-evidence parsing hardening still applies inside `collect()`.

## Minimal example

```python
# ~/.rapidtriage/plugins/acme_vault_provider.py
from pathlib import Path
from typing import Iterable

from rapidtriage.core.models import ArtifactRecord


class AcmeVaultProvider:
    collector_kind = "acme-vault"
    name = "acme-vault"
    description = "ACME vault export triage"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*.vault")):
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="acme-vault-export",
                path=str(path.resolve()),
                supported=True,
                details={"parser": "acme-vault", "parser_version": "1"},
            )
```

Verify registration:

```bash
RAPIDTRIAGE_PLUGIN_DIRS=/path/to/plugins rapidtriage artifacts /evidence --kind acme-vault
```
