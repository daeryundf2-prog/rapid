# EVTX Message Rendering Strategy

RapidTriage separates EVTX record recovery from report-grade provider message rendering.

## Current Rust Worker Behavior

- `evtx-records` emits structural `ArtifactRecordV1` rows for chunks and record headers.
- EVTX files are processed from the file header into 64KB chunks instead of reading the whole file into memory for the normal worker path.
- BinXML payloads are tokenized into a bounded object model when recognizable.
- Common BinXML values are decoded for strings, integers, booleans, floats, GUIDs, SIDs, FILETIME/SYSTIME candidates, binary payloads, and bounded nested `BinXmlType` payloads.
- Nested `BinXmlType` payloads are parsed into an `evtx-nested-binxml-value-v1` profile with payload hash, status, token counts, field map, and bounded rendered/text previews so reviewers can inspect embedded BinXML without treating it as provider-rendered testimony.
- Recoverable `Event/System` and `EventData` fields are promoted into `extracted_fields` for search/review pivots.
- TemplateInstance records preserve template IDs, template body object-model data, value specs, substitution values, and decoded substitution text where possible.
- Message rendering emits built-in validation-required templates for selected high-value event IDs such as 4104, 4624, 4688, 7045, and 1102.
- `rapidtriage artifacts --kind eventlog --eventlog-message-catalog catalog.json` can load a curated provider/event template catalog. Matching entries render before built-in fallbacks and record catalog path/source/locale provenance.
- Windows Event Manifest catalogs (`.man`/`.xml`) now preserve template field specs plus `valueMap`/`bitMap` entries, so manifest-based rendering can convert mapped numeric fields such as logon type values into analyst-readable labels while preserving the raw value in `used_fields`.
- Native rows without an explicit catalog keep `provider_message_resource_resolved=false` until provider DLL/resource-table rendering is implemented and validated.

## Report-Grade Target

Report-grade rendering requires:

- Provider/channel metadata extracted from BinXML `System` fields.
- Provider manifest/resource lookup for the exact Windows build where possible.
- Template insertion using typed BinXML substitution values.
- Manifest `valueMap`/`bitMap` substitution provenance for mapped fields.
- Locale-aware fallback behavior and explicit unresolved-message disclosure.
- Cross-tool validation against EVTXECmd, Hayabusa, Chainsaw, or Velociraptor fixtures.

## Safety Rule

Built-in messages are useful for analyst triage, but must stay `validation_required=true` and must not be represented as court-ready provider-rendered event messages.
Curated provider catalogs may mark `provider_message_resource_resolved=true`, but reports must preserve the catalog provenance so the analyst can prove which manifest/resource extraction was used.
