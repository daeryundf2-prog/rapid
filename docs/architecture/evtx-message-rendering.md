# EVTX Message Rendering Strategy

RapidTriage separates EVTX record recovery from report-grade provider message rendering.

## Current Rust Worker Behavior

- `evtx-records` emits structural `ArtifactRecordV1` rows for chunks and record headers.
- EVTX files are processed from the file header into 64KB chunks instead of reading the whole file into memory for the normal worker path.
- BinXML payloads are tokenized into a bounded object model when recognizable.
- Common BinXML values are decoded for strings, integers, booleans, floats, GUIDs, SIDs, FILETIME/SYSTIME candidates, and binary payloads.
- Recoverable `Event/System` and `EventData` fields are promoted into `extracted_fields` for search/review pivots.
- TemplateInstance records preserve template IDs, template body object-model data, value specs, substitution values, and decoded substitution text where possible.
- Message rendering emits built-in validation-required templates for selected high-value event IDs such as 4104, 4624, 4688, 7045, and 1102.
- `provider_message_resource_resolved` remains `false` until provider DLL/resource-table rendering is implemented and validated.

## Report-Grade Target

Report-grade rendering requires:

- Provider/channel metadata extracted from BinXML `System` fields.
- Provider manifest/resource lookup for the exact Windows build where possible.
- Template insertion using typed BinXML substitution values.
- Locale-aware fallback behavior and explicit unresolved-message disclosure.
- Cross-tool validation against EVTXECmd, Hayabusa, Chainsaw, or Velociraptor fixtures.

## Safety Rule

Built-in messages are useful for analyst triage, but must stay `validation_required=true` and must not be represented as court-ready provider-rendered event messages.
