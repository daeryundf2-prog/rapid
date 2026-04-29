# RapidTriage Parallel Execution Tracker

This tracker records the current parallel work lanes for the 120-item commercial-parity backlog. The gate remains strict: an item does not advance to `Done` unless implementation, fixtures, documentation, and validation support report-grade use without overstating evidence strength.

## Active Parallel Lanes

| Lane | Items | Owner scope | Current goal | Gate |
| --- | --- | --- | --- | --- |
| A | #6 | `windows-os-account` | SAM/SECURITY/SYSTEM native and export-backed account/security parsing | Keep `commercial_grade_ready=false` until OS-version validated SAM F/V decoding, SECURITY handling, and transaction-log validation exist. |
| B | #10 | `windows-execution` SRUM/ESE sections | SRUDB native validation and table/row candidate extraction | Keep `commercial_grade_ready=false` until native ESE catalog/page/row decoding is independently validated. |
| C | #11 | Windows Search index parser | Windows.edb ESE metadata/path/content candidates | Keep `commercial_grade_ready=false` until native Windows Search tables are decoded and validated. |
| D | #12 | Windows filesystem parser | Native MFT attribute/timestamp/sequence validation | Keep `commercial_grade_ready=false` until full FILE attribute parsing and known-answer validation exist. |

## Current Number Gate

| Range | Current state | Notes |
| --- | --- | --- |
| #1-#5 | `Partial+` | Improved, fixture-backed, but still below full commercial validation. |
| #6 | `Partial+ active` | Current blocking item for strict sequential completion. Parallel lane A is reducing blockers. |
| #7-#10 | `Partial+` | Existing triage-grade functionality; lane B is improving #10 while #6 remains the strict gate. |
| #11-#12 | `Partial` | Parallel lanes C and D can prepare improvements, but final progression still depends on earlier gates. |
| #13-#120 | Mixed `Partial`, `Partial+`, `Planned`, `External` | Not complete; use the backlog as authoritative status until each item is upgraded and validated. |
