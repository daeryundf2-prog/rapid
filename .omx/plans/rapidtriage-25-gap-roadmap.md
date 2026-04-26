# RapidTriage 25-Gap Product Roadmap

## Requirements Summary

RapidTriage should move from a local forensic triage MVP into a cross-platform, analyst-usable forensic review tool. The target is not to copy Magnet AXIOM feature-for-feature immediately; the target is to make a reliable tool that can ingest common evidence sources, index large data sets, search across documents/logs/web/OCR, let an analyst review and compare evidence comfortably, and produce defensible hash/report outputs.

Current repo facts:

- Packaging is Python-based with `rapidtriage` and `rapidtriage-web` console scripts in `pyproject.toml:39`.
- The web runtime depends on FastAPI/Uvicorn extras in `pyproject.toml:31`.
- Direct E01 support currently depends on external `ewfmount`, `mmls`, and `tsk_recover` tools in `rapidtriage/core/e01.py:11`.
- E01 direct input is limited to `.e01` and `.ex01` suffixes in `rapidtriage/core/e01.py:12`.
- The API already has source preview, file search, paginated timeline/artifacts/files/docs, and unified search endpoints in `rapidtriage/api/app.py:152`.
- The web UI already separates Triage, Find, Review, and Deliver workspaces in `rapidtriage/web/static/app.js:21`.
- The web UI already has local state keys and shortcut guidance in `rapidtriage/web/static/app.js:9` and `rapidtriage/web/static/app.js:57`.

## Target Score

Baseline: about 52/100 as an MVP forensic triage tool.

Phase target:

- 65/100: Windows users can install/run it, open cases, search, review, and export reports without developer help.
- 75/100: Large cases are indexed reliably; search/view/review/report are useful enough for real internal triage.
- 85/100: Evidence handling, artifact parsers, audit trail, validation data, and packaging are strong enough for repeatable professional use.
- 90+ requires a long-term product program: mobile/cloud acquisition, enterprise collaboration, legal validation, signed releases, support, and extensive parser coverage.

## The 25 Gaps Grouped Into Workstreams

1. Windows install/run convenience.
2. E01 direct handling.
3. Image format support: AD1, DD/raw, AFF/AFF4, VHD/VHDX, VMDK, ISO.
4. Artifact parsers.
5. Mobile/cloud acquisition.
6. Deleted file/recovery analysis.
7. Large case optimization.
8. Advanced search engine.
9. OCR pipeline.
10. Viewer functions.
11. Review/collaboration workflow.
12. Audit log and chain of custody.
13. Report quality.
14. Validation datasets.
15. Performance benchmarks.
16. Error recovery/resume.
17. Case management.
18. Security/authentication/authorization.
19. Packaging/distribution.
20. User docs/onboarding.
21. AXIOM-style timeline integration.
22. Artifact normalization model.
23. Hash/evidence submission automation.
24. Plugin architecture.
25. Commercial trust/support.

## Execution Strategy

Do not start by adding dozens of parsers. That creates impressive-looking coverage but weak reliability. Build the system in this order:

1. Make it installable and runnable by a normal Windows user.
2. Create a stable case database and evidence adapter layer.
3. Replace ad-hoc search with a real index.
4. Add high-value artifact parsers against a normalized model.
5. Improve viewers, review flow, hash manifest, and reports.
6. Add validation datasets, benchmarks, docs, and release discipline.

## Phase 0: Stabilize The Existing MVP

Goal: turn the current branch into a known baseline before adding more surface area.

Scope:

- Confirm fresh clone/install/run on macOS and Windows.
- Add a small public/synthetic sample case.
- Add a `rapidtriage doctor` diagnostic command.
- Add baseline performance metrics for file walk, document scan, OCR, and search.
- Add a roadmap issue list matching the 25 gaps.

Acceptance criteria:

- On a clean Windows 11 machine, a user can clone or download the repo, install dependencies, and run the web UI in under 15 minutes using documented commands.
- `python -m unittest discover -s tests`, `python -m compileall -q rapidtriage`, and package build all pass.
- A sample case can be run end-to-end and produces inventory, search results, review state, hash manifest, and report.
- `rapidtriage doctor` clearly reports missing Python packages, Tesseract, E01 tools, and optional image tools.

Primary gaps addressed: 1, 15, 19, 20.

## Phase 1: Windows-First Usability And Packaging

Goal: make it feel like a user-facing tool, not a developer script.

Scope:

- Add Windows launcher scripts: PowerShell and `.bat`.
- Add a portable app folder layout: app, data, cases, logs, tools.
- Add dependency checks with suggested fixes.
- Add persistent case catalog so users do not manage raw output folders manually.
- Add user-facing onboarding docs and first-run page.
- Evaluate PyInstaller/Nuitka for a portable executable build.

Acceptance criteria:

- A non-developer Windows user can start RapidTriage with a double-click or one PowerShell command.
- App data is written to a predictable user directory, not random working directories.
- If optional dependencies are missing, the UI explains what works and what will be disabled.
- Release artifact includes README, quick start, sample data instructions, and troubleshooting.

Primary gaps addressed: 1, 17, 19, 20.

## Phase 2: Evidence Adapter And Image Support

Goal: stop hard-coding evidence handling around E01 and folders.

Scope:

- Introduce an `EvidenceAdapter` interface with capabilities: identify, mount/extract, list, hash, metadata, cleanup.
- Keep mounted folders as the default universal path.
- Support raw/DD and ISO first because they are simpler and widely testable.
- Add VHD/VHDX and VMDK through external tool adapters where available.
- Keep E01 through libewf/sleuthkit on Unix/WSL, but make native Windows limitations explicit.
- Record every extraction/mount action in a case audit log.
- Build source evidence hash manifest before and after extraction where feasible.

Acceptance criteria:

- Folder, `.E01`, `.Ex01`, `.dd`, `.raw`, `.iso`, `.vhd`, `.vhdx`, and `.vmdk` inputs are detected and routed through an adapter.
- Unsupported formats fail with a clear message and fallback guidance.
- Every adapter writes an evidence action record: input path, size, timestamps, tool/version, command, output path, status, and errors.
- Extraction can resume or skip completed steps without silently corrupting previous output.

Primary gaps addressed: 2, 3, 6, 12, 16, 23, 24.

## Phase 3: Case Database And Real Search Index

Goal: large cases must not depend on repeatedly scanning JSON files and source trees.

Scope:

- Add a SQLite case database for runs, evidence items, artifacts, files, reviews, hashes, and audit events.
- Add FTS5 as the first embedded index engine.
- Index documents, logs, browser artifacts, metadata, OCR text, and extracted strings into a unified searchable model.
- Add boolean search, phrase search, extension/type filters, date filters, path filters, regex mode, saved searches, and search history.
- Add background indexing jobs with progress/resume.
- Keep JSON outputs as export artifacts, not the primary runtime state.

Acceptance criteria:

- 100k-file synthetic case opens without loading all rows into the browser.
- Indexed keyword searches return first page in under 2 seconds on a typical developer laptop for the benchmark dataset.
- Search results include source type, matched field, snippet, timestamp if available, evidence ID, hash, and review status.
- Users can search entire case or current file/view.
- Interrupted indexing resumes from the last safe checkpoint.

Primary gaps addressed: 7, 8, 9, 15, 16, 17, 21, 22.

## Phase 4: Artifact Normalization And Parser Expansion

Goal: search and timeline should work across evidence types, not just loose files.

Scope:

- Define normalized models: `EvidenceItem`, `FileRecord`, `Artifact`, `Event`, `Identity`, `ReviewMark`, `ReportItem`.
- Build parser plugin contract: input types, output schema, parser version, errors, confidence.
- Add high-value Windows parsers first: browser history/downloads/cookies where legally appropriate, Windows Event Logs, Registry hives, Prefetch, LNK, Jump Lists, ShellBags, USB history, SRUM if feasible.
- Add common app/data parsers: SQLite databases, CSV/TSV logs, email containers where feasible.
- Normalize all parser output into timeline-searchable events.

Acceptance criteria:

- Every parser output has stable IDs, source offsets/path where possible, parser version, and normalized timestamp fields.
- Timeline can merge file timestamps, browser events, Windows logs, and review marks.
- Parser failures are visible per parser and do not fail the whole case unless configured.
- At least 10 high-value parsers have unit tests with small fixtures.

Primary gaps addressed: 4, 21, 22, 24.

## Phase 5: Analyst Viewer, Review, And Reporting Workflow

Goal: finding data is not enough; analysts need to understand, compare, mark, and export it.

Scope:

- Add stronger viewers: text/log, image, PDF, office preview where possible, email/thread, SQLite table, event log table, registry key/value view, and hex/metadata fallback.
- Add compare workspace: pin A/B items, diff text, compare metadata/hashes/timestamps.
- Add review marks: relevant, notable, excluded, needs follow-up, privileged/sensitive, report candidate.
- Add review history and audit trail to every user action.
- Add report templates: executive summary, technical findings, evidence appendix, hash appendix, review notes.
- Add export bundle: report, selected evidence references, hash manifest, audit log, parser versions.

Acceptance criteria:

- User can move from search result to preview, source file, hash info, review mark, note, and report inclusion without losing context.
- User can compare at least two selected items side by side.
- Report generation includes only selected or configured evidence, not all noise.
- Every report item links back to evidence ID, source path, hash, parser, and review status.

Primary gaps addressed: 10, 11, 12, 13, 23.

## Phase 6: Validation, Security, Documentation, And Release Discipline

Goal: move from useful tool to credible forensic software.

Scope:

- Build validation datasets with expected results.
- Add benchmark suite for small, medium, and large cases.
- Add security model: local-only default, optional auth if bound to non-localhost, safe path resolution, audit logs.
- Add signed release process if distributing binaries.
- Add user manual, analyst workflow guide, evidence handling guide, and limitations page.
- Add issue templates and support process.

Acceptance criteria:

- Every release publishes test results, benchmark results, known limitations, and parser coverage.
- Localhost-only mode is safe by default; remote binding requires explicit opt-in and authentication.
- Documentation explains what RapidTriage can and cannot do compared with AXIOM.
- Validation cases prove parser/search/report behavior against known expected outputs.

Primary gaps addressed: 14, 15, 18, 20, 25.

## Phase 7: Deferred Long-Term Expansion

Goal: only after the desktop forensic workflow is stable, consider expensive domains.

Scope:

- Mobile acquisition/import workflows.
- Cloud exports and third-party service imports.
- Multi-user collaboration and enterprise case server.
- Advanced deleted-file carving and deeper filesystem-level recovery.
- Commercial support, training, and certification materials.

Reason to defer:

These areas have high legal, technical, and maintenance costs. They should not block the core desktop/search/review/report product.

Primary gaps addressed later: 5, 6, 11, 25.

## First Sprint Backlog

1. Add `rapidtriage doctor`.
2. Add Windows quick-start launcher scripts.
3. Add clean Windows install documentation.
4. Add synthetic sample case and expected output.
5. Add benchmark command for file walk, document scan, OCR, and search.
6. Draft SQLite case schema and migration strategy.
7. Prototype FTS5 index for docs/logs/metadata.
8. Add `EvidenceAdapter` interface and route folder/E01 through it.
9. Add PDF/text/log viewer improvements in the web UI.
10. Add report template spec and evidence appendix format.

## Risks And Mitigations

- Risk: native Windows E01 handling becomes toolchain pain. Mitigation: make mounted-folder and WSL workflows first-class; use adapter diagnostics instead of pretending support is seamless.
- Risk: parser expansion creates unstable output. Mitigation: require normalized schema, parser version, fixtures, and failure isolation.
- Risk: large cases freeze the UI. Mitigation: database-backed pagination and background indexing before more UI complexity.
- Risk: forensic trust is questioned. Mitigation: audit log, hash manifest, validation datasets, tool-version capture, and explicit limitations.
- Risk: report output becomes noisy. Mitigation: review-first report inclusion and evidence appendix links instead of dumping everything.

## Verification Plan

- Unit tests for adapter detection, search index, review state, hash manifest, and reports.
- Fixture tests for each parser.
- End-to-end sample case test: ingest, index, search, review, report, export.
- Windows smoke test on a clean machine.
- Performance benchmark with published numbers for 10k, 100k, and 1M file synthetic cases.
- Manual UX smoke test: search result to preview to mark to report inclusion in under 30 seconds.

## Recommended Next Move

Start with Phase 0 and Phase 1 together. The project will look much more real after Windows usability, diagnostics, sample data, and a case catalog. Then immediately begin Phase 3 search/index work before spending serious time on dozens of parsers.

# Korean Detailed Execution Plan

## 제품 방향을 한 문장으로 정의

RapidTriage는 "증거 이미지를 넣으면 자동으로 파일/문서/로그/웹/OCR/아티팩트를 인덱싱하고, 수사관이 검색 결과를 빠르게 확인/비교/체크한 뒤, 해시와 근거가 남는 보고서로 정리하는 범용 포렌식 트리아지 도구"가 되어야 한다.

중요한 점은 AXIOM을 한 번에 복제하는 것이 아니다. AXIOM은 상용 포렌식 플랫폼이고, RapidTriage는 당장은 "빠르게 훑고, 찾고, 확인하고, 정리하는 도구"가 되어야 한다. 따라서 첫 목표는 "대체재"가 아니라 "보조 분석 도구"다. 이후 인덱스, 파서, 증거 무결성, 보고서, 검증 데이터셋이 쌓이면 점진적으로 전문 도구에 가까워질 수 있다.

## 사용자 관점의 최종 흐름

1. 사용자가 RapidTriage를 실행한다.
2. 새 케이스를 만든다.
3. 증거 소스를 추가한다.
4. 소스가 폴더인지, E01인지, RAW/DD인지, ISO인지, VHD/VMDK인지 자동 감지한다.
5. 가능한 경우 자동 마운트/추출한다.
6. 불가능한 경우 어떤 도구가 필요한지 보여주고, "이미 마운트된 폴더를 선택하라"는 우회 경로를 제공한다.
7. 파일 목록, 크기, 확장자, 타임스탬프, 해시를 만든다.
8. 문서, 로그, 웹 기록, 이미지 OCR, 일반 텍스트를 인덱싱한다.
9. 브라우저 기록, 이벤트 로그, 레지스트리, LNK, Prefetch 같은 아티팩트를 파싱한다.
10. 전체 타임라인을 만든다.
11. 사용자는 전체 케이스 검색을 한다.
12. 사용자는 현재 파일 안에서 검색한다.
13. 사용자는 검색 결과를 미리보기로 본다.
14. 사용자는 의심 자료를 체크한다.
15. 사용자는 A 자료와 B 자료를 비교한다.
16. 사용자는 관련 있음, 중요, 제외, 추가 확인 필요, 보고서 포함 같은 상태를 매긴다.
17. 모든 리뷰 작업은 이력으로 남는다.
18. 사용자는 선택한 항목으로 보고서를 만든다.
19. 보고서에는 원본 경로, 추출 경로, 해시, 타임스탬프, 파서 버전, 리뷰 메모가 포함된다.
20. 제출용 번들에는 보고서, 해시 매니페스트, 감사 로그, 선택 증거 목록이 포함된다.

## 제품 원칙

1. 큰 데이터가 들어와도 UI가 멈추면 실패다.
2. 검색 결과가 빨라도 원본 확인이 불편하면 실패다.
3. 보고서가 예쁘더라도 어떤 파일에서 나온 결과인지 추적이 안 되면 실패다.
4. 포맷을 많이 지원한다고 해도 에러 메시지가 불친절하면 실패다.
5. Windows 사용자가 설치하다 막히면 실패다.
6. 해시, 감사 로그, 파서 버전이 안 남으면 증거 도구로는 부족하다.
7. 모바일/클라우드는 욕심내기 전에 데스크톱 증거 분석 흐름부터 완성해야 한다.
8. AXIOM 대비 강점은 가벼움, 빠른 커스터마이징, 로컬 자동화다.
9. AXIOM 대비 약점은 파서 범위, 검증, 신뢰, 모바일/클라우드, 보고서 품질이다.
10. 따라서 초반 승부처는 "설치성 + 검색성 + 리뷰성 + 제출 가능성"이다.

## 25개 부족분 상세 계획

### 1. Windows 설치/실행 편의성

현재 상태:

- Python 프로젝트로는 실행 가능하지만 일반 사용자가 Windows에서 바로 쓰기에는 부족하다.
- `rapidtriage-web` 스크립트는 있지만, 더블클릭 실행, 설치 진단, 앱 데이터 위치, 에러 안내가 부족하다.

목표:

- Windows 11 기준으로 비개발자도 15분 안에 실행할 수 있어야 한다.
- 장기적으로는 portable zip 또는 exe 형태를 목표로 한다.

구현 작업:

- `scripts/windows/start-rapidtriage.ps1` 추가.
- `scripts/windows/start-rapidtriage.bat` 추가.
- `rapidtriage doctor` 명령 추가.
- Python 버전, 패키지, Tesseract, ffmpeg, sleuthkit/libewf, 권한, 포트 사용 여부를 진단한다.
- 사용자 데이터 기본 위치를 `%LOCALAPPDATA%/RapidTriage`로 잡는다.
- 케이스 기본 위치를 `%USERPROFILE%/Documents/RapidTriage Cases`로 잡는다.
- 웹 UI 첫 화면에 "상태 점검" 패널을 넣는다.

완료 기준:

- 깨끗한 Windows 11에서 문서대로 설치 후 웹 UI가 열린다.
- 누락된 의존성이 있으면 명확한 메시지와 설치 안내가 나온다.
- 실행 로그가 사용자 데이터 폴더에 남는다.

### 2. E01 직접 처리

현재 상태:

- `.E01`, `.Ex01`만 감지한다.
- `ewfmount`, `mmls`, `tsk_recover` 외부 도구가 필요하다.
- Windows native 환경에서는 설치 난이도가 높다.

목표:

- E01을 넣었을 때 가능한 환경에서는 자동 추출한다.
- 불가능한 환경에서는 WSL2 또는 사전 마운트 폴더 방식으로 자연스럽게 안내한다.

구현 작업:

- E01 어댑터를 `EvidenceAdapter` 구조로 분리한다.
- E01 처리 전 도구 존재 여부와 버전을 기록한다.
- E01 segment 파일 존재 여부를 검사한다.
- 멀티 파티션 선택 전략을 만든다.
- 기본은 가장 큰 NTFS/exFAT 파티션, 고급 설정에서는 파티션 선택 가능하게 한다.
- 추출 진행률과 현재 단계 표시: identify, mount, partition scan, recover, index.
- 실패 시 stage 디렉터리 정리 정책을 명확히 한다.

완료 기준:

- E01 입력이 성공하면 추출 폴더가 케이스에 등록된다.
- 실패하면 어떤 도구가 없고 어떤 우회 방법을 써야 하는지 UI와 CLI에 표시된다.
- 감사 로그에 E01 파일 경로, 크기, 해시, 사용 도구, 파티션 오프셋, 추출 결과가 남는다.

### 3. 이미지 포맷 확장

현재 상태:

- E01 중심이고 AD1, RAW/DD, AFF/AFF4, ISO, VHD/VHDX, VMDK 처리는 없다.

목표:

- 최소한 폴더, E01/Ex01, RAW/DD, ISO, VHD/VHDX, VMDK를 하나의 evidence input 흐름으로 받는다.
- AD1/AFF4는 초기에는 "감지 + 미지원 안내 + 변환/마운트 가이드"로 시작한다.

구현 작업:

- `EvidenceAdapter` base class 추가.
- `FolderAdapter` 추가.
- `EwfAdapter` 추가.
- `RawImageAdapter` 추가.
- `IsoAdapter` 추가.
- `VirtualDiskAdapter` 추가.
- `UnsupportedAdapter` 추가.
- 파일 시그니처 기반 감지와 확장자 기반 감지를 함께 사용한다.
- 각 어댑터는 capabilities를 노출한다: can_mount, can_extract, can_hash, can_resume.
- 외부 도구 의존성은 `ToolRequirement`로 모델링한다.

완료 기준:

- 지원 포맷은 자동 감지된다.
- 미지원 포맷도 "그냥 실패"하지 않고 이유와 다음 행동을 알려준다.
- 모든 포맷 처리 결과가 동일한 케이스 DB 구조에 들어간다.

### 4. 아티팩트 파서 확장

현재 상태:

- 일부 파일/문서/간단 아티팩트 중심이다.
- AXIOM 대비 Windows artifact coverage가 매우 부족하다.

목표:

- Windows 중심의 핵심 10개 파서를 우선 구축한다.

1차 파서 우선순위:

- Chrome/Edge/Firefox history.
- Chrome/Edge/Firefox downloads.
- Windows Event Log `.evtx`.
- Registry hives: SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat.
- LNK shortcut.
- Jump Lists.
- Prefetch.
- ShellBags.
- USB device history.
- SQLite generic viewer/indexer.

2차 파서:

- SRUM.
- Amcache.
- ShimCache.
- MFT summary.
- Recycle Bin.
- RecentDocs.
- RDP artifacts.
- PowerShell history.
- Windows Defender logs.
- Email containers.

구현 작업:

- parser plugin interface 정의.
- parser result schema 정의.
- parser fixtures 추가.
- parser별 failure isolation 구현.
- parser별 confidence와 parser_version 기록.
- 모든 결과를 normalized artifact/event로 변환한다.

완료 기준:

- 10개 1차 파서가 fixture test를 가진다.
- 파서 실패가 전체 케이스 실패로 이어지지 않는다.
- 검색과 타임라인에서 parser output이 함께 검색된다.

### 5. 모바일/클라우드

현재 상태:

- 없음.

목표:

- 단기 목표는 acquisition이 아니라 export/import 분석이다.
- Cellebrite/AXIOM/Google Takeout/iCloud export 같은 외부 추출물 폴더를 읽는 방향이 현실적이다.

구현 작업:

- 모바일/클라우드는 Phase 7로 미룬다.
- 단기에는 `ImportedExportAdapter`를 만든다.
- Google Takeout JSON/HTML/CSV 일부부터 검토한다.
- iOS/Android acquisition은 직접 구현하지 않는다.

완료 기준:

- 장기 계획에 포함하되 core desktop workflow를 방해하지 않는다.
- export folder 기반 분석만 실험적으로 지원한다.

### 6. 삭제 파일/복구 분석

현재 상태:

- E01 추출 시 `tsk_recover -e`를 쓰는 수준이다.
- 삭제 파일의 의미, 복구 상태, 원본 위치, slack/carving 수준 분석은 약하다.

목표:

- 최소한 삭제 파일 후보와 복구 파일을 구분해서 표시한다.
- 복구된 항목이 보고서에 들어갈 때 provenance를 명확히 남긴다.

구현 작업:

- file record에 `deleted`, `recovered`, `allocated`, `source_offset` 필드 추가.
- sleuthkit output을 더 구조적으로 파싱한다.
- Recycle Bin parser 추가.
- MFT parser 또는 external tool integration 검토.
- carving은 장기 과제로 분리한다.

완료 기준:

- 삭제/복구 파일은 일반 파일과 구분되어 UI에 표시된다.
- 보고서에는 복구 방식과 신뢰 수준이 표시된다.

### 7. 대용량 케이스 최적화

현재 상태:

- 일부 API pagination은 있지만, 근본 상태 저장이 JSON 중심이다.
- 대용량 케이스에서 전체 파일을 다시 읽거나 브라우저에 많이 싣는 구조가 위험하다.

목표:

- 100k 파일은 기본으로 견디고, 1M 파일은 benchmark target으로 둔다.

구현 작업:

- SQLite case DB 도입.
- 파일 목록, 문서 결과, 아티팩트, 타임라인, 리뷰 상태를 DB 테이블로 저장.
- API는 offset/limit 또는 cursor 기반으로 제공.
- 프론트는 virtual table 또는 incremental rendering으로 변경.
- background job queue를 둔다.
- index progress와 cancel/resume 기능 추가.

완료 기준:

- 100k 파일 synthetic case에서 UI가 멈추지 않는다.
- 검색 첫 페이지가 2초 안에 나온다.
- 파일 목록 이동, 필터, 정렬이 페이지 단위로 동작한다.

### 8. 고급 검색 엔진

현재 상태:

- unified search는 있으나 AXIOM식 강력한 전체 인덱스 검색은 아니다.

목표:

- 케이스 전체, 현재 뷰, 현재 파일 검색이 분리되어야 한다.
- 키워드, 구문, Boolean, 확장자, 경로, 날짜, artifact type, hash 기반 검색을 지원해야 한다.

구현 작업:

- SQLite FTS5 도입.
- `indexed_document` 테이블 추가.
- `search_hit` result model 추가.
- query parser 추가: words, quoted phrase, AND/OR/NOT, field filters.
- saved search 기능 추가.
- search history 추가.
- search preset을 사용자 정의 가능하게 한다.

완료 기준:

- 검색 결과가 어디에서 매칭됐는지 field 단위로 표시된다.
- snippet과 context가 제공된다.
- 검색 결과에서 바로 viewer/review/report로 이어진다.

### 9. OCR 파이프라인

현재 상태:

- OCR 관련 기반은 있으나 대규모 이미지 OCR 캐시와 품질 관리가 약하다.

목표:

- 이미지, PDF 이미지 페이지, 스크린샷류에서 텍스트를 추출하고 검색 가능하게 한다.

구현 작업:

- OCR job queue 추가.
- OCR cache table 추가.
- 언어 설정 추가: eng, kor, mixed.
- OCR confidence 저장.
- OCR timeout과 max page/image size 제한.
- OCR 결과를 FTS index에 넣는다.
- OCR 실패를 개별 항목 에러로 남긴다.

완료 기준:

- 이미지 OCR 결과가 전체 검색에 포함된다.
- OCR 결과는 원본 이미지와 함께 viewer에서 확인 가능하다.
- OCR 시간이 오래 걸려도 UI가 멈추지 않는다.

### 10. 뷰어 기능

현재 상태:

- source preview와 다운로드는 있으나 전문 viewer로는 부족하다.

목표:

- 분석자가 검색 결과를 열었을 때 바로 판단할 수 있어야 한다.

필요 viewer:

- Text/log viewer: 줄 번호, 검색 하이라이트, current-file search.
- Image viewer: 확대/축소, OCR overlay, metadata.
- PDF viewer: page navigation, text layer, search hits.
- Office preview: text extraction fallback 우선.
- Email viewer: header/body/attachment/thread.
- SQLite viewer: table list, row search, schema view.
- Event log viewer: provider, event id, timestamp, message.
- Registry viewer: hive/key/value/timestamp.
- Hex viewer: binary fallback, hash, magic bytes.

완료 기준:

- 검색 결과에서 viewer까지 1 click.
- viewer에서 review mark까지 1 click.
- viewer에서 report include까지 1 click.
- 대용량 텍스트 파일도 부분 로딩한다.

### 11. 리뷰/협업 워크플로우

현재 상태:

- review status, tags, notes, selection tray 기반은 있다.
- 다중 사용자 협업은 없다.

목표:

- 단기에는 단일 사용자 리뷰를 완성한다.
- 장기에는 다중 사용자/역할/충돌 해결을 추가한다.

구현 작업:

- review status 표준화: unreviewed, relevant, notable, excluded, follow_up, privileged, report_candidate.
- review action history 저장.
- review filter 추가.
- selected evidence tray 개선.
- batch mark 기능 추가.
- reviewer 이름/세션 이름 기록.
- collaboration은 Phase 7에서 server mode로 분리.

완료 기준:

- 어떤 사용자가 언제 왜 체크했는지 남는다.
- 체크한 항목만 보고서 후보로 모아볼 수 있다.
- 제외 항목과 중요 항목이 명확히 분리된다.

### 12. 감사 로그/Chain of Custody

현재 상태:

- 해시 매니페스트와 일부 기록은 있으나 체계적 감사 로그가 부족하다.

목표:

- 증거 처리, 인덱싱, 검색, 리뷰, 보고서 생성까지 주요 행위가 감사 로그로 남아야 한다.

구현 작업:

- `audit_event` 테이블 추가.
- event fields: id, case_id, actor, action, target_type, target_id, timestamp, tool_version, params_hash, result, error.
- evidence ingest 시작/완료 기록.
- hash 계산 기록.
- parser 실행 기록.
- review 변경 기록.
- report export 기록.
- 감사 로그 export 기능 추가.

완료 기준:

- 보고서와 함께 감사 로그를 export할 수 있다.
- 특정 증거 항목이 어떤 처리 과정을 거쳤는지 추적 가능하다.

### 13. 보고서 품질

현재 상태:

- Markdown draft 보고서 수준이다.

목표:

- 내부 검토용 보고서와 제출용 appendix를 분리한다.

보고서 종류:

- Executive summary.
- Technical findings.
- Timeline report.
- Keyword hit report.
- Evidence appendix.
- Hash manifest.
- Review notes.
- Tool/version appendix.

구현 작업:

- report template engine 추가.
- Markdown, HTML, PDF export 검토.
- DOCX export는 이후 추가.
- report item ordering 추가.
- report section include/exclude 설정.
- screenshot/thumbnail embedding 검토.

완료 기준:

- 선택한 증거만 보고서에 포함 가능하다.
- 모든 finding은 evidence ID와 hash로 추적 가능하다.
- 보고서 생성 시 사용한 RapidTriage 버전과 parser 버전이 남는다.

### 14. 검증 데이터셋

현재 상태:

- 테스트는 있지만 forensic validation dataset은 부족하다.

목표:

- 기능이 맞는지 증명할 수 있는 작은 케이스들을 만든다.

구현 작업:

- synthetic Windows-like folder case.
- browser history fixture.
- EVTX fixture.
- Registry fixture.
- LNK fixture.
- PDF/OCR fixture.
- deleted/recovered sample if legally safe.
- expected results JSON 작성.

완료 기준:

- validation command가 expected result와 actual result를 비교한다.
- release마다 validation 결과를 저장한다.

### 15. 성능 벤치마크

현재 상태:

- 성능 기준이 없다.

목표:

- 대용량 대응을 감으로 말하지 않고 숫자로 관리한다.

벤치마크:

- 10k files.
- 100k files.
- 1M file metadata-only case.
- 10GB mixed docs/logs case.
- OCR-heavy image set.

측정 항목:

- ingest time.
- indexing time.
- DB size.
- memory peak.
- search p50/p95.
- first page render time.
- report generation time.

완료 기준:

- benchmark command가 JSON/Markdown 결과를 만든다.
- 성능 회귀가 테스트에서 감지된다.

### 16. 에러 복구/재개

현재 상태:

- 장시간 작업 중 실패하면 재개 전략이 약하다.

목표:

- ingest, extract, parse, OCR, index가 각각 checkpoint를 가져야 한다.

구현 작업:

- job table 추가.
- job step table 추가.
- step status: pending, running, completed, failed, skipped, canceled.
- retry count 기록.
- idempotent output path 전략.
- partial result cleanup 정책.

완료 기준:

- OCR 중 실패해도 전체 케이스가 망가지지 않는다.
- 재실행 시 완료된 단계는 건너뛴다.
- UI에서 실패 단계와 재시도 버튼이 보인다.

### 17. 케이스 관리

현재 상태:

- run 중심이다.
- 사용자는 여러 케이스/여러 증거를 관리하기 어렵다.

목표:

- case 중심으로 바꾼다.

구현 작업:

- case catalog 추가.
- case metadata: name, description, examiner, organization, created_at, updated_at.
- multiple evidence sources per case 지원.
- run은 case 안의 processing job으로 취급.
- case archive/export/import 추가.

완료 기준:

- 사용자는 이전 케이스를 UI에서 다시 열 수 있다.
- 한 케이스에 여러 증거 소스를 추가할 수 있다.
- case export로 다른 PC에서 열 수 있다.

### 18. 보안/인증/권한

현재 상태:

- 로컬 도구라 인증이 없다.

목표:

- 기본은 localhost-only로 안전하게 둔다.
- 외부 접속을 허용할 때만 인증을 요구한다.

구현 작업:

- bind host 기본값 `127.0.0.1`.
- `0.0.0.0` 바인딩 시 경고.
- optional local password/token auth.
- path traversal 방어 강화.
- sensitive file download audit.
- CORS 기본 차단.

완료 기준:

- 외부 접속 모드는 명시적 설정 없이는 켜지지 않는다.
- 모든 source-file 접근은 허용된 evidence root 안에서만 가능하다.

### 19. 패키징/배포

현재 상태:

- Python package build는 가능하지만 end-user distribution은 약하다.

목표:

- developer install, portable install, packaged build를 분리한다.

구현 작업:

- `make` 또는 `scripts/build-release` 추가.
- wheel/sdist 빌드 유지.
- Windows portable zip 구성.
- PyInstaller/Nuitka 실험.
- release checklist 작성.
- GitHub Actions CI 추가.

완료 기준:

- GitHub release에 사용자가 받을 수 있는 artifact가 올라간다.
- release artifact로 sample case smoke test가 가능하다.

### 20. 사용자 문서/온보딩

현재 상태:

- README는 있지만 제품 사용 설명서로는 부족하다.

목표:

- 사용자가 "무엇을 넣으면 어디까지 해주는지" 바로 이해해야 한다.

필요 문서:

- Quick start.
- Windows install.
- macOS install.
- Evidence input guide.
- E01 guide.
- Mounted folder workflow.
- Search guide.
- Review guide.
- Report guide.
- Limitations vs AXIOM.
- Troubleshooting.

완료 기준:

- 신규 사용자가 문서만 보고 sample case를 끝까지 돌린다.
- E01 실패 시 해결 방법을 찾을 수 있다.

### 21. AXIOM식 타임라인 통합

현재 상태:

- timeline output은 있지만 artifact/event 통합은 약하다.

목표:

- 파일 타임스탬프, 웹 기록, 로그, 레지스트리, 리뷰 이벤트가 하나의 timeline으로 합쳐져야 한다.

구현 작업:

- normalized `event` table 추가.
- event timestamp 종류 기록: created, modified, accessed, visited, downloaded, executed, connected, reviewed.
- timezone 처리 정책 정의.
- event source와 confidence 기록.
- timeline filter: date range, event type, source, reviewed status.

완료 기준:

- 브라우저 다운로드와 실제 파일 생성 시간이 같은 화면에서 비교된다.
- 특정 날짜 범위의 모든 이벤트를 export할 수 있다.

### 22. 아티팩트 정규화 모델

현재 상태:

- 출력별 구조가 달라 장기 확장에 불리하다.

목표:

- 모든 parser 결과를 공통 모델에 넣는다.

핵심 모델:

- Case.
- EvidenceSource.
- EvidenceItem.
- FileRecord.
- Artifact.
- Event.
- IndexedDocument.
- SearchHit.
- ReviewMark.
- ReportItem.
- AuditEvent.
- HashRecord.
- ParserRun.

완료 기준:

- 새로운 parser가 추가되어도 검색/타임라인/보고서 UI를 크게 고치지 않는다.
- 모든 결과는 stable ID를 가진다.

### 23. 해시/증거 제출 자동화

현재 상태:

- hash manifest 기반은 있다.

목표:

- 제출 가능한 evidence bundle을 만든다.

구현 작업:

- MD5/SHA1/SHA256 기본 계산.
- BLAKE3는 optional fast hash로 검토.
- selected evidence export.
- source path, extracted path, size, mtime, hash, review status 포함.
- report와 manifest cross-reference.
- bundle integrity hash 추가.

완료 기준:

- 제출 폴더 하나에 보고서, hash manifest, audit log, selected evidence list가 들어간다.
- 각 보고서 finding이 manifest 항목과 연결된다.

### 24. 플러그인 구조

현재 상태:

- 기능이 core에 직접 붙는 구조다.

목표:

- parser, evidence adapter, viewer, report exporter를 플러그인화할 수 있어야 한다.

구현 작업:

- plugin manifest 정의.
- plugin registry 추가.
- parser plugin API.
- adapter plugin API.
- report exporter plugin API.
- plugin enable/disable 설정.
- plugin error isolation.

완료 기준:

- 새 parser를 core UI 수정 없이 등록할 수 있다.
- plugin 목록과 버전이 report appendix에 표시된다.

### 25. 상용 신뢰/지원

현재 상태:

- 개인/초기 프로젝트 수준이다.

목표:

- 상용 수준까지는 아니더라도 "검증 가능한 도구"로 보이게 만들어야 한다.

구현 작업:

- release notes 작성.
- known limitations 공개.
- validation 결과 공개.
- benchmark 결과 공개.
- parser coverage matrix 공개.
- issue template 추가.
- security policy 추가.
- license와 책임 범위 명확화.

완료 기준:

- 사용자가 도구의 한계와 검증 상태를 알 수 있다.
- 버전별 기능/변경/검증 결과가 추적된다.

## 권장 구현 순서 상세

### Sprint 1: 사람이 실행 가능한 상태 만들기

목표:

- Windows 사용자가 막히지 않고 실행한다.
- 현재 기능을 sample case로 재현 가능하게 만든다.

작업:

1. `rapidtriage doctor` 추가.
2. Windows PowerShell launcher 추가.
3. Windows `.bat` launcher 추가.
4. app data directory 정책 추가.
5. sample case 생성.
6. sample case expected output 추가.
7. Windows quick start 문서 작성.
8. E01 limitation 문서 작성.
9. smoke test 스크립트 추가.
10. README에 "현재 가능한 것/불가능한 것" 표 추가.

완료 기준:

- Windows fresh install 문서를 따라 웹 UI 실행 가능.
- sample case를 돌리면 검색/리뷰/보고서 결과가 나온다.
- doctor가 누락 의존성을 감지한다.

예상 점수 변화:

- 52점에서 60-65점.

### Sprint 2: 케이스/DB 기반으로 전환

목표:

- run output folder 중심에서 case database 중심으로 바꾼다.

작업:

1. SQLite schema 초안 추가.
2. case catalog 추가.
3. evidence source table 추가.
4. file record table 추가.
5. hash record table 추가.
6. audit event table 추가.
7. review mark table 추가.
8. 기존 JSON output import/migration 함수 추가.
9. API를 case 중심으로 확장.
10. UI에 case list 추가.

완료 기준:

- 케이스를 만들고 닫고 다시 열 수 있다.
- 동일 케이스에 여러 evidence source를 붙일 수 있다.
- 기존 run output도 case로 import 가능하다.

예상 점수 변화:

- 65점에서 68-70점.

### Sprint 3: 검색 인덱스 구축

목표:

- 키워드를 치면 문서, 로그, 웹 기록, OCR, metadata에서 빠르게 찾는다.

작업:

1. FTS5 indexed_document table 추가.
2. indexer job 추가.
3. text extraction 결과 indexing.
4. metadata indexing.
5. OCR result indexing.
6. artifact result indexing.
7. query parser 추가.
8. field filter 추가.
9. saved search 추가.
10. search result UI 개선.

완료 기준:

- 전체 케이스 검색과 현재 파일 검색이 구분된다.
- 검색 결과에서 바로 preview/review/report include 가능하다.
- 100k 파일 benchmark에서 검색 p95 2초 이내를 목표로 한다.

예상 점수 변화:

- 70점에서 75점.

### Sprint 4: EvidenceAdapter와 이미지 입력 확장

목표:

- 증거 입력 경로를 통일하고 포맷 확장 준비를 끝낸다.

작업:

1. `EvidenceAdapter` interface 추가.
2. `FolderAdapter` 구현.
3. 기존 E01 코드를 `EwfAdapter`로 이동.
4. `RawImageAdapter` skeleton 추가.
5. `IsoAdapter` skeleton 추가.
6. `VirtualDiskAdapter` skeleton 추가.
7. adapter diagnostics 추가.
8. adapter audit event 추가.
9. stage directory policy 추가.
10. resume/cleanup policy 추가.

완료 기준:

- 모든 input은 adapter를 통해 처리된다.
- 지원/미지원/부분지원 상태가 UI에 표시된다.
- E01 실패 메시지가 실제 사용자가 이해할 수 있다.

예상 점수 변화:

- 75점에서 77점.

### Sprint 5: 핵심 Windows 아티팩트 1차

목표:

- "파일 검색 도구"에서 "포렌식 아티팩트 도구"로 넘어간다.

작업:

1. parser plugin contract 추가.
2. Chrome history parser.
3. Edge history parser.
4. Firefox history parser.
5. downloads parser.
6. EVTX parser.
7. LNK parser.
8. Registry USB history parser.
9. Prefetch parser.
10. JumpList parser.

완료 기준:

- 10개 parser가 normalized artifact/event를 만든다.
- parser fixture tests가 있다.
- 검색과 timeline에 parser 결과가 들어온다.

예상 점수 변화:

- 77점에서 80점.

### Sprint 6: Viewer와 Review UX 강화

목표:

- 찾은 자료를 제대로 확인하고 정리할 수 있게 한다.

작업:

1. text viewer 개선.
2. PDF viewer 추가.
3. image viewer 개선.
4. SQLite viewer 추가.
5. event log viewer 추가.
6. registry viewer 추가.
7. compare pane 개선.
8. batch review mark 추가.
9. review filters 추가.
10. keyboard shortcuts 확장.

완료 기준:

- 검색 결과에서 판단까지 클릭 수가 줄어든다.
- A/B 비교가 실제로 편하다.
- 체크한 항목만 모아볼 수 있다.

예상 점수 변화:

- 80점에서 82점.

### Sprint 7: 보고서/제출 번들

목표:

- 분석 결과를 증거물로 정리할 수 있게 한다.

작업:

1. report template engine.
2. executive summary section.
3. technical findings section.
4. evidence appendix.
5. hash appendix.
6. audit appendix.
7. selected evidence export.
8. bundle manifest.
9. HTML/PDF export.
10. report preview UI.

완료 기준:

- 사용자는 체크한 항목으로 보고서를 만든다.
- 보고서 항목은 hash manifest와 연결된다.
- 제출 번들을 하나의 폴더/zip으로 만들 수 있다.

예상 점수 변화:

- 82점에서 85점.

### Sprint 8: 검증/릴리즈 체계

목표:

- "내 컴퓨터에서는 됨" 수준을 벗어난다.

작업:

1. validation dataset 추가.
2. expected output 추가.
3. benchmark suite 추가.
4. GitHub Actions CI.
5. Windows CI smoke.
6. release checklist.
7. parser coverage matrix.
8. known limitations 문서.
9. security policy.
10. signed release 검토.

완료 기준:

- 릴리즈마다 테스트/검증/벤치마크 결과가 남는다.
- 사용자가 한계를 알고 쓸 수 있다.

예상 점수 변화:

- 85점에서 87점.

## 데이터 모델 초안

### Case

- id.
- name.
- description.
- examiner.
- organization.
- created_at.
- updated_at.
- case_root.
- status.
- schema_version.

### EvidenceSource

- id.
- case_id.
- display_name.
- source_type.
- original_path.
- staged_path.
- size_bytes.
- hash_md5.
- hash_sha1.
- hash_sha256.
- detected_format.
- adapter_name.
- adapter_version.
- status.
- added_at.

### FileRecord

- id.
- case_id.
- evidence_source_id.
- path.
- normalized_path.
- extension.
- mime_type.
- size_bytes.
- created_at.
- modified_at.
- accessed_at.
- changed_at.
- hash_md5.
- hash_sha1.
- hash_sha256.
- is_deleted.
- is_recovered.
- source_offset.
- parent_id.

### Artifact

- id.
- case_id.
- evidence_source_id.
- file_record_id.
- artifact_type.
- parser_name.
- parser_version.
- title.
- summary.
- data_json.
- confidence.
- created_at.

### Event

- id.
- case_id.
- evidence_source_id.
- artifact_id.
- file_record_id.
- event_type.
- timestamp.
- timestamp_kind.
- timezone.
- actor.
- action.
- target.
- description.
- source.
- confidence.

### IndexedDocument

- id.
- case_id.
- evidence_source_id.
- file_record_id.
- artifact_id.
- source_type.
- field_name.
- title.
- body.
- language.
- ocr_confidence.
- indexed_at.

### ReviewMark

- id.
- case_id.
- target_type.
- target_id.
- status.
- tags.
- note.
- include_in_report.
- reviewer.
- created_at.
- updated_at.

### AuditEvent

- id.
- case_id.
- actor.
- action.
- target_type.
- target_id.
- timestamp.
- tool_name.
- tool_version.
- params_json.
- result.
- error.

### ReportItem

- id.
- case_id.
- target_type.
- target_id.
- section.
- title.
- narrative.
- order_index.
- created_at.

## UI 구조 상세

### Home

- 최근 케이스 목록.
- 새 케이스 만들기.
- 샘플 케이스 실행.
- 시스템 상태 점검.
- 최근 오류.

### Case Overview

- evidence source 목록.
- 처리 상태.
- 전체 파일 수.
- 인덱싱 상태.
- parser 성공/실패 요약.
- review 진행률.
- report 후보 수.

### Ingest

- 증거 추가.
- 포맷 감지 결과.
- 필요한 도구 상태.
- 마운트/추출 옵션.
- 해시 계산 옵션.
- stage directory 선택.

### Search

- 전체 검색.
- 현재 뷰 검색.
- 현재 파일 검색.
- keyword preset.
- saved search.
- filters: file type, date, source, artifact type, review status.
- results table.
- snippet panel.

### Viewer

- preview.
- metadata.
- hash.
- source path.
- extracted text.
- OCR text.
- artifact details.
- related timeline events.
- review controls.
- report include toggle.

### Compare

- A/B pinned items.
- metadata comparison.
- text diff.
- timestamp comparison.
- hash comparison.
- review notes side by side.

### Review Board

- unreviewed.
- relevant.
- notable.
- follow up.
- excluded.
- privileged.
- report candidates.
- batch operations.

### Timeline

- date range.
- event type.
- source filter.
- confidence filter.
- review status filter.
- export selected range.

### Report

- report outline.
- selected evidence.
- section editor.
- preview.
- export.
- bundle manifest.

## API 구조 상세

필요 endpoint:

- `GET /api/health`.
- `GET /api/doctor`.
- `GET /api/cases`.
- `POST /api/cases`.
- `GET /api/cases/{case_id}`.
- `POST /api/cases/{case_id}/evidence`.
- `GET /api/cases/{case_id}/evidence`.
- `POST /api/cases/{case_id}/jobs/{job_id}/retry`.
- `POST /api/cases/{case_id}/jobs/{job_id}/cancel`.
- `GET /api/cases/{case_id}/files`.
- `GET /api/cases/{case_id}/artifacts`.
- `GET /api/cases/{case_id}/timeline`.
- `GET /api/cases/{case_id}/search`.
- `GET /api/cases/{case_id}/source-preview`.
- `GET /api/cases/{case_id}/source-file`.
- `POST /api/cases/{case_id}/review`.
- `GET /api/cases/{case_id}/review`.
- `POST /api/cases/{case_id}/reports`.
- `GET /api/cases/{case_id}/reports/{report_id}`.
- `POST /api/cases/{case_id}/exports/submission-bundle`.
- `GET /api/cases/{case_id}/audit`.

## AXIOM 대비 현실적 포지션

AXIOM이 강한 영역:

- 모바일/클라우드 acquisition.
- 매우 넓은 artifact parser coverage.
- 검증된 forensic workflow.
- 상용 보고서.
- 장기간 축적된 parser quality.
- 법정/기관 신뢰.

RapidTriage가 노릴 수 있는 영역:

- 빠른 로컬 트리아지.
- 커스터마이징 가능한 검색/리뷰 도구.
- 가벼운 웹 UI.
- 특정 조직 업무에 맞춘 parser 추가.
- 투명한 hash/audit/report bundle.
- 비용 없이 내부 preliminary review.

단기 목표:

- AXIOM 대체가 아니라 AXIOM 전/후 보조 도구.
- "먼저 빠르게 보고, 중요한 것만 추려서 AXIOM/전문 분석으로 넘기는 도구".

중기 목표:

- 일반 Windows 증거/문서/로그/웹 기록 중심 케이스는 RapidTriage만으로도 1차 보고 가능.

장기 목표:

- 검증 데이터셋과 parser coverage를 쌓아 전문 도구에 근접.

## 우선순위 매트릭스

P0:

- Windows 실행.
- doctor 진단.
- sample case.
- case catalog.
- SQLite DB.
- FTS search.
- source viewer.
- review mark.
- report bundle.
- hash manifest.

P1:

- EvidenceAdapter.
- E01 UX 개선.
- RAW/ISO/VHD/VMDK detection.
- PDF viewer.
- OCR queue.
- EVTX/browser/LNK/registry parser.
- timeline integration.
- benchmark.
- validation fixtures.

P2:

- advanced parser expansion.
- report PDF/DOCX polish.
- plugin marketplace-like structure.
- multi-user collaboration.
- auth server mode.
- signed builds.

P3:

- mobile acquisition.
- cloud collection.
- deep carving.
- enterprise deployment.
- commercial support program.

## 성공 기준

MVP+ 성공 기준:

- Windows에서 사람이 실행 가능하다.
- 폴더/E01/mounted evidence를 넣을 수 있다.
- 전체 검색이 된다.
- OCR 결과도 검색된다.
- 검색 결과를 viewer로 확인한다.
- 중요 항목을 체크한다.
- 보고서와 hash manifest를 만든다.

Professional triage 성공 기준:

- 100k 파일 케이스가 안정적으로 열린다.
- browser/eventlog/registry/LNK/prefetch 결과가 timeline에 합쳐진다.
- 감사 로그가 남는다.
- 제출 번들이 생성된다.
- validation dataset을 통과한다.

AXIOM 보조 도구 성공 기준:

- AXIOM에 넣기 전 빠른 선별이 가능하다.
- AXIOM 결과와 별도로 키워드/문서/OCR/로그 기반 빠른 확인이 가능하다.
- 특정 조직 키워드/보고서 양식에 맞게 커스터마이징 가능하다.

## 당장 다음 구현 후보

가장 추천하는 다음 작업은 `rapidtriage doctor`와 Windows 실행성이다. 이유는 단순하다. 지금 검색/뷰어/보고서가 더 좋아져도 사용자가 Windows에서 실행하다 막히면 제품 점수는 크게 안 오른다.

두 번째는 SQLite/FTS다. 확장자와 parser를 아무리 많이 추가해도 인덱스 구조가 약하면 대용량에서 무너진다.

세 번째는 viewer/review/report다. 포렌식 도구는 "찾았다"에서 끝나지 않고 "확인했다, 표시했다, 제출 가능하게 정리했다"까지 가야 한다.

# External Community And Documentation Review

Review date: 2026-04-24.

Purpose:

- Reddit, Stack Overflow, vendor docs, and open-source forensic tool docs were reviewed to harden this roadmap.
- Community opinions are used as field signals, not as authoritative forensic truth.
- Official documentation and standards-oriented sources are used to confirm implementation direction.

## Sources Reviewed

Community sources:

- Reddit `r/computerforensics`: AXIOM benchmark and hardware discussion.
- Reddit `r/computerforensics`: proprietary tool comparison discussion covering AXIOM, FTK, Cellebrite, Forensic Explorer, Belkasoft, and X-Ways.
- Reddit `r/computerforensics`: AXIOM web history / missing artifact discussion.
- Reddit `r/computerforensics`: AXIOM vs X-Ways discussion.
- Reddit `r/computerforensics`: hash validation / NSRL / hashset discussions.
- Stack Overflow: `pytesseract` not finding Tesseract on Windows.
- Stack Overflow: FastAPI static files and route mounting behavior.
- Stack Overflow: reading `.E01` with Python/pytsk3/libewf-related discussion.

Documentation and reference sources:

- Magnet AXIOM official product pages and Timeline Explorer article.
- Autopsy ingest module and keyword search documentation.
- Plaso/log2timeline supported formats and parser documentation.
- SQLite FTS5 official documentation.
- NIST NSRL FAQ.
- DHS/NIST CFTT-style forensic tool testing reports.
- SWGDE/NIST-style validation and reporting guidance.

## High-Level Findings From External Review

### Finding 1: AXIOM is treated by many practitioners as powerful, but not final truth

Community signal:

- Practitioners often use AXIOM together with FTK, X-Ways, Cellebrite, Forensic Explorer, Autopsy, or other tools.
- Several discussions emphasize that one tool may parse something another misses.
- Some users describe AXIOM as excellent for artifact-first triage, log/event/timeline analysis, and email indexing, while other tools may be stronger for carving or low-level recovery.

Impact on RapidTriage:

- RapidTriage must not claim "complete forensic truth".
- The UI and report should show source path, parser, parser version, extraction method, and confidence.
- Results should encourage verification by source file and, when appropriate, external tools.
- Report wording should separate "parsed artifact indicates" from "confirmed fact".

Roadmap changes:

- Add cross-validation fields to Artifact/Event.
- Add "source verification" UX in the viewer.
- Add report language that distinguishes extracted, parsed, inferred, and manually reviewed facts.
- Add "limitations and verification notes" section to every report.

### Finding 2: Deleted recovery and carving should not be over-promised

Community signal:

- A recurring field opinion is that AXIOM is not always the best deleted-data/carving tool.
- Practitioners may use FTK, X-Ways, or specialized tools for carving/recovery.
- Carved results can be ambiguous and should be verified against source context.

Impact on RapidTriage:

- RapidTriage should treat deleted file recovery as a staged capability, not an early headline promise.
- Phase 2 can identify deleted/recovered status from external extraction output.
- Deep carving should remain Phase 7 unless there is a dedicated recovery engine and validation corpus.

Roadmap changes:

- Add explicit `recovery_method`, `allocation_status`, `source_offset`, and `confidence` fields.
- Mark carved/recovered items differently in UI.
- Add warning labels when source path or timestamp provenance is weak.
- Keep "deep carving" out of P0/P1.

### Finding 3: Hardware and disk I/O dominate large forensic processing

Community signal:

- AXIOM processing discussions repeatedly mention CPU, RAM, and disk bottlenecks.
- Processing once and reusing results is preferred over repeatedly forcing users to wait.
- Demonstrations should use small images because watching long processing is poor UX.

Impact on RapidTriage:

- Benchmarking must record hardware profile.
- Jobs must be resumable.
- Reprocessing should be avoided when previous outputs are valid.
- Sample cases must be small and predictable.

Roadmap changes:

- Add `hardware_profile` to benchmark output.
- Add content-addressed or parameter-hashed job cache.
- Add "process once, reopen many times" as a product principle.
- Add small demo dataset and medium benchmark dataset separately.

### Finding 4: Search must include both ingest-time indexing and ad hoc/manual search

Official confirmation:

- Autopsy's keyword search model includes ingest-time extraction/indexing and later manual ad hoc search.
- It extracts text from supported formats, falls back to strings for unsupported content, can use OCR, and can skip known files via NSRL-style hash filtering.

Impact on RapidTriage:

- Search must not be just a runtime scan.
- Search should be split into indexing pipeline, indexed search, current-file search, and fallback raw/string search.
- NSRL/known-good filtering can reduce index size and noise.

Roadmap changes:

- Add `IndexedDocument` as first-class case data.
- Add "string extraction fallback" for unsupported files.
- Add "known-good skip indexing" option after hash lookup support.
- Add manual ad hoc search even while indexing is still running.

### Finding 5: OCR is useful but slow and imperfect

Official/community confirmation:

- Autopsy documents OCR as useful but slower and imperfect.
- Stack Overflow shows Windows Tesseract configuration frequently fails because executable path and language data are not configured correctly.

Impact on RapidTriage:

- OCR must be opt-in or policy-driven, not forced for every image.
- OCR must have timeout, file size, page count, and language settings.
- Windows diagnostics must explicitly detect Tesseract executable and `tessdata`.

Roadmap changes:

- `rapidtriage doctor` must test `tesseract --version`.
- Doctor must check `TESSDATA_PREFIX` or locate common Windows install paths.
- OCR queue must support retry/skip.
- OCR results must store confidence and extraction settings.
- Reports must label OCR text as OCR-derived, not native text.

### Finding 6: Timeline can explode in size

Official confirmation:

- Magnet's Timeline Explorer documentation notes that timeline rows can greatly exceed artifact count because file-system and artifact timestamps multiply quickly.

Impact on RapidTriage:

- Timeline must be database-backed from the beginning.
- UI must not render all events at once.
- Timeline must support filtering, grouping, bucketing, and pivoting around a selected artifact.

Roadmap changes:

- Add `timestamp_kind` and `event_category`.
- Add timeline buckets: minute, hour, day, month.
- Add pivot mode: show events before/after selected item.
- Add "Evidence Of" style categories.
- Add timeline export by filtered range, not only whole timeline.

### Finding 7: Parser coverage should follow established artifact ecosystems

Official confirmation:

- Plaso supports a broad set of SQLite-backed app artifacts, browser artifacts, Windows timeline data, logs, LNK, Jump Lists, and many text log formats.
- Autopsy uses ingest modules that can be enabled/disabled and configured.

Impact on RapidTriage:

- Parser expansion should use a plugin contract from the start.
- The first parsers should target high-yield artifacts, especially SQLite-backed browser/app data and Windows logs.
- Parser selection should be configurable per case.

Roadmap changes:

- Add parser enable/disable UI.
- Add parser run configuration snapshot to audit log.
- Add parser failure table.
- Add parser coverage matrix.
- Use Plaso/Autopsy coverage as inspiration, not as a promise to match everything.

### Finding 8: FTS5 is appropriate for the first serious local index, but it has boundaries

Official confirmation:

- SQLite FTS5 supports full-text indexing through virtual tables and query features such as phrase, prefix, NEAR, column filters, and Boolean operators.

Impact on RapidTriage:

- FTS5 is a good embedded first step for local-first search.
- It should be paired with structured filters in normal SQLite tables.
- If future search needs fuzzy matching, distributed indexing, or huge multi-case search, a later engine may be needed.

Roadmap changes:

- Implement FTS5 for P0/P1 search.
- Keep search abstraction so Tantivy, Lucene, OpenSearch, or another engine can be added later.
- Add query parser tests for phrase, Boolean, prefix, and field filters.
- Add "search engine capability matrix" to docs.

### Finding 9: Hash handling needs both integrity and triage roles

Official confirmation:

- NIST NSRL is used to identify known files in forensic investigations.
- NSRL data has scope limits and should not be confused with illicit/malicious hash sets.
- Autopsy supports NSRL-style known-file filtering.

Community signal:

- Hash validation discussions show confusion around what exactly is being hashed: container, logical image, extracted file, or transferred copy.

Impact on RapidTriage:

- RapidTriage must distinguish source evidence hash, mounted image hash, extracted file hash, and export bundle hash.
- Known-good hash filtering is separate from evidence integrity hashing.
- Reports must be explicit about which object each hash represents.

Roadmap changes:

- Add `hash_scope`: source_container, logical_image, extracted_file, report_bundle, selected_export.
- Add NSRL/known-good import as optional.
- Add "hash explanation" section to report.
- Add validation test that line-ending or export transformation does not masquerade as original evidence hash.

### Finding 10: FastAPI web packaging needs static route and asset smoke tests

Stack Overflow signal:

- Static file routing and root mounting can conflict with API routes if mounted carelessly.
- Packaged apps often fail because static assets are missing or routed incorrectly.

Impact on RapidTriage:

- Windows packaging must test API and static UI together.
- A PyInstaller/Nuitka build must include `rapidtriage/web/static` and any templates.
- Route ordering and root mount behavior need tests.

Roadmap changes:

- Add server smoke tests for `/`, static CSS/JS, `/api/health`, and OpenAPI.
- Add packaged-build smoke test.
- Add asset manifest check during release.

### Finding 11: Evidence source linking is a must-have, not a polish feature

Community signal:

- AXIOM users discussing missing web history or carved artifacts repeatedly point back to validating source locations and using other tools when needed.

Impact on RapidTriage:

- Every hit must link back to a source file, artifact record, offset if known, and parser.
- Viewer must expose raw source and parsed interpretation together.

Roadmap changes:

- Add "Open source context" button to each search hit.
- Add artifact-to-file and event-to-file trace panel.
- Add "copy citation" feature for report drafting.
- Add source export with hash and audit note.

### Finding 12: Training and onboarding are part of correctness

Community signal:

- Some AXIOM discussions show that powerful tools are often underused or misunderstood when users lack training.
- Users may stay in the default artifact view and miss timeline, source validation, or advanced search features.

Impact on RapidTriage:

- Documentation and guided workflows are not optional.
- The UI should teach the intended path: ingest, index, search, verify, review, report.

Roadmap changes:

- Add guided sample case walkthrough.
- Add in-app "next recommended step".
- Add glossary: evidence source, artifact, event, index, OCR, hash, review mark.
- Add "what this result means / does not mean" help text.

## Concrete Plan Changes After External Review

### Change A: Add a dedicated Verification Layer

New scope:

- Each search hit and artifact must expose verification status.
- Status values: unverified, source_opened, cross_checked, externally_verified, rejected.
- Reports should show verification status for each finding.

Implementation tasks:

1. Add `verification_status` to `ReviewMark` or a new `VerificationRecord`.
2. Add `verified_by`, `verified_at`, and `verification_note`.
3. Add UI actions: mark source checked, mark cross-checked, mark rejected.
4. Add report filter: include only verified findings.

Acceptance criteria:

- A finding cannot be silently treated as confirmed without review action.
- The report can separate "candidate hits" from "verified findings".

### Change B: Add Evidence Citation IDs

New scope:

- Every evidence item, artifact, event, search hit, and report item receives a stable citation ID.

Example:

- `CASE-2026-001-EVID-0001`.
- `CASE-2026-001-FILE-024931`.
- `CASE-2026-001-ART-000812`.
- `CASE-2026-001-EVT-140222`.
- `CASE-2026-001-RPT-000021`.

Implementation tasks:

1. Add citation ID generator.
2. Store citation IDs in DB.
3. Show citation IDs in viewer and report.
4. Add copy-citation button.

Acceptance criteria:

- A report paragraph can be traced back to the exact evidence record.
- Citation IDs remain stable after reopening the case.

### Change C: Add Known-Good / Known-Bad Hash Sets

New scope:

- Known-good reduces noise.
- Known-bad/notable flags investigative interest.
- Integrity hashes remain separate.

Implementation tasks:

1. Add `hash_set` table.
2. Add `hash_set_entry` table.
3. Add import for NSRL-like CSV/SQLite formats later.
4. Add file classification: unknown, known_good, known_bad, notable.
5. Add search/index option: skip known_good.

Acceptance criteria:

- Known-good files can be filtered from search results.
- Reports do not confuse known-good filtering with evidence integrity.

### Change D: Add Ingest Pipeline Configuration

New scope:

- Like mature tools, users should choose which modules run.

Pipeline stages:

1. Identify evidence.
2. Hash source.
3. Mount/extract.
4. File inventory.
5. File hash.
6. Text extraction.
7. OCR.
8. Artifact parsers.
9. FTS indexing.
10. Timeline generation.
11. Report draft.

Implementation tasks:

1. Add pipeline config model.
2. Add presets: Fast Triage, Balanced, Deep Scan, Documents Only, Web/Browser Focus.
3. Save pipeline config in audit log.
4. Show estimated cost/time where possible.

Acceptance criteria:

- A user can run a fast scan without OCR/carving.
- A user can run a deeper scan later without recreating the case.

### Change E: Add Timeline Pivot UX

New scope:

- Timeline should not just be a huge table.
- It should help answer "what happened around this event?"

Implementation tasks:

1. Add pivot from artifact/search hit to timeline.
2. Add before/after window filters: 5 min, 1 hour, 1 day, custom.
3. Add event grouping by category.
4. Add quick export for pivot window.

Acceptance criteria:

- From a suspicious download, user can see related browser, file, execution, and review events around it.

### Change F: Add Packaging Hardening

New scope:

- Packaged app must include web assets, static files, templates, and optional external tools diagnostics.

Implementation tasks:

1. Add asset manifest.
2. Add route smoke test.
3. Add packaged executable smoke test.
4. Add first-run log bundle collection.
5. Add "copy diagnostic report" button.

Acceptance criteria:

- A release build opens the UI and API endpoints on a clean Windows machine.
- Missing OCR/E01 tools do not crash the app; they appear as disabled capabilities.

## Revised Priority After External Review

P0 must include:

- Windows run path.
- Doctor diagnostics.
- Static asset/package smoke tests.
- Case DB.
- FTS index.
- Source-linked search results.
- Review/verification status.
- Hash scope separation.
- Sample case.

P1 must include:

- EvidenceAdapter.
- Pipeline configuration.
- OCR queue with Windows diagnostics.
- Known-good hash filtering.
- Timeline pivot.
- Browser history/download parser.
- EVTX parser.
- LNK parser.
- Report citation IDs.

P2 must include:

- Deeper parser coverage.
- VHD/VMDK/ISO adapters.
- Registry/Preamble parser expansion.
- PDF/SQLite/EventLog specialized viewers.
- Report template polish.
- Validation corpus expansion.

P3 remains:

- Deep carving.
- Mobile acquisition.
- Cloud acquisition.
- Multi-user collaboration.
- Enterprise deployment.

## Revised First 15 Implementation Tickets

1. Add `rapidtriage doctor` with Windows OCR/E01/static asset checks.
2. Add Windows PowerShell and batch launchers.
3. Add server smoke tests for UI assets and API endpoints.
4. Add sample case and guided walkthrough.
5. Add SQLite case DB schema v1.
6. Add stable citation ID generation.
7. Add evidence/source/hash scope tables.
8. Add FTS5 `IndexedDocument` prototype.
9. Add source-linked search result model.
10. Add verification status to review workflow.
11. Add audit events for ingest/search/review/report.
12. Add ingest pipeline config and presets.
13. Add OCR queue with timeout and language settings.
14. Add browser history/download parser as first parser plugin.
15. Add report appendix with citation IDs, hash scopes, and verification status.

## Revised Acceptance Gates

Gate 1: Usable Windows Alpha.

- Fresh Windows machine can run the app.
- Doctor output is understandable.
- UI and API static assets load.
- Sample case completes.

Gate 2: Searchable Case Alpha.

- Case DB stores files, hashes, indexed text, review marks, and audit events.
- FTS search works across documents/logs/OCR/artifacts.
- Results link back to source and citation ID.

Gate 3: Analyst Review Beta.

- User can verify source, mark relevance, compare items, and include in report.
- Timeline pivot works around selected artifact.
- Report separates candidate hits from verified findings.

Gate 4: Defensible Export Beta.

- Submission bundle includes report, selected evidence list, hash manifest, audit log, parser versions, and known limitations.
- Validation dataset passes.
- Benchmark results are included in release notes.

## External Review Conclusion

The original plan was directionally correct but too optimistic about parser expansion and not explicit enough about verification. External review strengthens three priorities:

1. Build a reliable local-first case/index/search foundation before parser sprawl.
2. Treat source verification, citation IDs, hash scopes, and audit logs as core features.
3. Make Windows packaging and diagnostics boringly reliable before calling it usable.

The biggest practical correction is this: RapidTriage should not try to "be AXIOM" first. It should become a transparent, source-linked, fast triage and review tool that makes it easy to verify what it found. That is a realistic lane and a strong product position.

# Coding Schedule

This schedule converts the roadmap into an executable coding plan. It assumes one primary developer with occasional parallel review/testing help. If two or more developers are available, the UI, backend, parser, and documentation lanes can run in parallel.

## Schedule Assumptions

- Total initial build window: 12 weeks.
- Sprint length: 1 week.
- Main target by week 4: Usable Windows Alpha.
- Main target by week 8: Searchable Case Alpha.
- Main target by week 10: Analyst Review Beta.
- Main target by week 12: Defensible Export Beta.
- Work style: small vertical slices, tested every week.
- Default platform: macOS for development, Windows 11 for smoke testing.
- Python version: keep current `>=3.9` unless dependency pressure requires raising it.
- Browser UI: keep current FastAPI/static web approach until there is a strong reason to split frontend build tooling.

## Development Lanes

### Lane A: Platform And Packaging

Purpose:

- Make the tool start reliably on Windows/macOS.
- Keep web assets and optional tools diagnosable.

Owner focus:

- CLI, startup scripts, package build, release smoke tests, diagnostics.

### Lane B: Case Database And Evidence Model

Purpose:

- Move from run-output-centric workflow to case-centric workflow.
- Create stable IDs, hash scopes, audit logs, and citation IDs.

Owner focus:

- SQLite schema, migrations, repositories, data model tests.

### Lane C: Search And Indexing

Purpose:

- Build fast full-case search over documents, logs, OCR, metadata, and artifacts.

Owner focus:

- FTS5 index, query parser, source-linked search result model, indexing jobs.

### Lane D: Analyst UX

Purpose:

- Make search results easy to preview, verify, compare, mark, and include in reports.

Owner focus:

- Web UI, viewer improvements, review board, timeline pivot, report preview.

### Lane E: Parsers And Evidence Adapters

Purpose:

- Add evidence format handling and high-value artifact parsers without polluting core logic.

Owner focus:

- EvidenceAdapter interface, parser plugin contract, browser/EVTX/LNK parsers.

### Lane F: Reporting, Validation, And Docs

Purpose:

- Make outputs defensible and user guidance clear.

Owner focus:

- Report templates, submission bundle, validation fixtures, benchmark docs, limitations docs.

## Week 0: Pre-Implementation Setup

Duration:

- 0.5 to 1 day before Sprint 1.

Goal:

- Freeze the current baseline and prepare execution.

Tasks:

1. Confirm current branch and clean working tree.
2. Stage/commit this roadmap if the user wants it versioned.
3. Create GitHub issues or local task list from the first 15 implementation tickets.
4. Create milestone labels: `alpha-windows`, `alpha-search`, `beta-review`, `beta-export`.
5. Decide release naming: `0.2.0-alpha.1`, `0.2.0-alpha.2`, `0.3.0-beta.1`.

Deliverables:

- Roadmap committed.
- Sprint board created.
- First sprint tickets ready.

Exit criteria:

- Developer can start Sprint 1 without rereading the entire roadmap.

## Week 1: Windows Usability Baseline

Release target:

- `0.2.0-alpha.1-dev`.

Primary goal:

- A Windows user can start the app or understand exactly why it cannot start.

Backend tasks:

1. Add `rapidtriage doctor` CLI command.
2. Implement diagnostic checks for Python version, installed package, FastAPI extra, OCR dependency, Tesseract executable, `TESSDATA_PREFIX`, E01 tools, write permissions, and port availability.
3. Add machine-readable doctor JSON output.
4. Add human-readable doctor text output.
5. Add app data directory detection for Windows/macOS/Linux.

Packaging tasks:

1. Add `scripts/windows/start-rapidtriage.ps1`.
2. Add `scripts/windows/start-rapidtriage.bat`.
3. Add `scripts/macos/start-rapidtriage.sh` if useful.
4. Add static asset manifest check.
5. Add startup log file path.

UI tasks:

1. Add simple "System Status" panel in web UI using doctor output.
2. Show disabled capabilities: OCR unavailable, E01 tools unavailable, optional parsers unavailable.

Docs tasks:

1. Add Windows quick start.
2. Add macOS quick start.
3. Add E01 limitations page.

Tests:

1. Unit tests for doctor checks using mocked tool paths.
2. CLI test for `rapidtriage doctor --json`.
3. Smoke test for `/api/health`, root UI, JS, CSS.

Acceptance criteria:

- Doctor command works without crashing on a machine missing optional dependencies.
- Windows scripts document what they run and where logs are written.
- Missing Tesseract/E01 tools are warnings, not fatal errors.

Risk buffer:

- If Windows testing is unavailable this week, add CI/smoke placeholders and perform manual Windows test in Week 2.

## Week 2: Sample Case And Release Smoke

Release target:

- `0.2.0-alpha.1`.

Primary goal:

- A user can run a known sample case end-to-end.

Sample data tasks:

1. Create synthetic sample case folder with documents, logs, browser-like SQLite sample, images for OCR, and known keywords.
2. Add expected output manifest.
3. Add guided walkthrough: ingest, search, preview, review, report.

Backend tasks:

1. Add sample runner command or UI action.
2. Add smoke test command that runs the sample case.
3. Add first-run log bundle collection.

UI tasks:

1. Add "Run sample case" entry point.
2. Add guided next-step hints for first-time users.
3. Add clearer error banner for failed runs.

Docs tasks:

1. Add "What E01 does today" section.
2. Add "What is not supported yet" section.
3. Add troubleshooting guide from doctor output.

Tests:

1. End-to-end sample case smoke.
2. Report output existence check.
3. Hash manifest existence check.
4. Static asset route smoke.

Acceptance criteria:

- Fresh checkout can run sample case and produce repeatable outputs.
- User-facing docs describe exactly what the tool does today.
- Alpha release artifact can be created.

Gate:

- Gate 1 partial: Usable Windows Alpha should be close enough to test with a real user.

## Week 3: SQLite Case DB Schema V1

Release target:

- `0.2.0-alpha.2-dev`.

Primary goal:

- Establish the persistent case model before adding more feature surface.

Backend tasks:

1. Add `rapidtriage/core/case_db.py`.
2. Add schema versioning.
3. Add tables: `case`, `evidence_source`, `file_record`, `hash_record`, `audit_event`, `review_mark`, `indexed_document`, `artifact`, `event`, `report_item`, `job`, `job_step`.
4. Add migration bootstrap.
5. Add repository functions for create/open/list cases.
6. Add citation ID generator.
7. Add hash scope model.

API tasks:

1. Add `/api/cases`.
2. Add `/api/cases/{case_id}`.
3. Add `/api/cases/{case_id}/evidence`.
4. Keep existing `/api/runs` endpoints for compatibility.

UI tasks:

1. Add case list page or panel.
2. Add create/open case flow.
3. Show case metadata and evidence sources.

Tests:

1. Schema creation test.
2. Migration idempotency test.
3. Citation ID stability test.
4. Hash scope storage test.
5. Case list API test.

Acceptance criteria:

- A case can be created, closed, reopened, and listed.
- Citation IDs remain stable after reopen.
- Existing run outputs are not broken.

Risk buffer:

- If full UI case flow takes too long, ship API/CLI first and keep UI minimal.

## Week 4: Evidence Ingest Into Case DB

Release target:

- `0.2.0-alpha.2`.

Primary goal:

- Current file inventory and hash outputs should start flowing into the case DB.

Backend tasks:

1. Add import from existing run summary into case DB.
2. Add file inventory writer to `file_record`.
3. Add hash writer to `hash_record`.
4. Add audit event creation for ingest start/end.
5. Add job/job_step tracking for existing pipeline.
6. Add basic resume marker for completed inventory/hash steps.

API tasks:

1. Add `/api/cases/{case_id}/files`.
2. Add `/api/cases/{case_id}/audit`.
3. Add `/api/cases/{case_id}/jobs`.

UI tasks:

1. Show case files from DB with pagination.
2. Show audit log table.
3. Show job progress from DB where available.

Tests:

1. Import existing run to case DB.
2. File pagination API test.
3. Audit event creation test.
4. Resume marker test.

Acceptance criteria:

- Sample case creates a case DB.
- Files and hashes are queryable from DB.
- Ingest actions are visible in audit log.

Gate:

- Gate 1 complete: usable alpha with case persistence and sample workflow.

## Week 5: FTS5 Index Prototype

Release target:

- `0.3.0-alpha.1-dev`.

Primary goal:

- Replace repeated ad-hoc search with a real indexed search path.

Backend tasks:

1. Add FTS5 virtual table for indexed text.
2. Add `IndexedDocument` writer.
3. Index plain text, extracted document text, metadata, and OCR text if available.
4. Add FTS query function.
5. Add result model with citation ID, source file, matched field, snippet, and review status.

Search tasks:

1. Add phrase search.
2. Add prefix search where safe.
3. Add Boolean `AND`, `OR`, `NOT` support if query parser can be safely constrained.
4. Add field filters: path, extension, source_type, artifact_type.

API tasks:

1. Add `/api/cases/{case_id}/search`.
2. Preserve existing run search during transition.

UI tasks:

1. Add indexed search mode.
2. Show source-linked snippets.
3. Add "open source context" action.

Tests:

1. FTS table creation.
2. Index sample docs.
3. Search phrase/keyword/filter tests.
4. Snippet generation test.
5. Source link resolution test.

Acceptance criteria:

- Sample case search uses FTS.
- Search results point to source file and citation ID.
- Query failures produce useful messages.

Risk buffer:

- Keep advanced Boolean query parsing behind a conservative parser to avoid malformed FTS syntax errors.

## Week 6: Review Verification Layer

Release target:

- `0.3.0-alpha.1`.

Primary goal:

- Search hits become reviewable and verifiable, not just visible.

Backend tasks:

1. Add verification status fields or `verification_record` table.
2. Add review status normalization.
3. Add review history events.
4. Add audit events for review changes.

API tasks:

1. Add `/api/cases/{case_id}/review`.
2. Add endpoint to mark source opened.
3. Add endpoint to mark cross-checked, externally verified, rejected.

UI tasks:

1. Add verification controls in viewer/search result.
2. Add filters: unverified, source opened, cross-checked, rejected, report candidate.
3. Add copy citation button.
4. Add review board DB-backed view.

Tests:

1. Review update API test.
2. Verification transition test.
3. Audit event test.
4. Report candidate query test.

Acceptance criteria:

- User can mark a result as candidate, verified, rejected, or report-ready.
- Verification status is visible in search and review board.
- Every review action creates audit history.

Gate:

- Gate 2 partial: Searchable Case Alpha with reviewable hits.

## Week 7: Ingest Pipeline Configuration And OCR Queue

Release target:

- `0.3.0-alpha.2-dev`.

Primary goal:

- Make processing configurable and resumable.

Backend tasks:

1. Add pipeline config model.
2. Add presets: Fast Triage, Balanced, Deep Scan, Documents Only, Web/Browser Focus.
3. Add job step execution wrapper.
4. Add OCR queue table and worker function.
5. Add OCR timeout, max file size, max pages, language selection.
6. Store OCR confidence/settings in `indexed_document`.

API tasks:

1. Add pipeline preset listing.
2. Add job retry/cancel endpoint.
3. Add OCR status endpoint.

UI tasks:

1. Add scan preset selector.
2. Show OCR disabled/available based on doctor.
3. Show job step progress.

Tests:

1. Pipeline config serialization.
2. Preset behavior test.
3. OCR skipped when disabled.
4. OCR timeout handling test with mocks.
5. Job retry/cancel state test.

Acceptance criteria:

- User can run fast scan without OCR.
- User can run deeper OCR/indexing later.
- Failed OCR does not fail the whole case.

Risk buffer:

- If real OCR is flaky in CI, use mocked OCR tests and keep manual OCR smoke.

## Week 8: First Parser Plugins And Timeline Foundation

Release target:

- `0.3.0-alpha.2`.

Primary goal:

- First real artifact plugins feed search and timeline.

Backend tasks:

1. Add parser plugin contract.
2. Add parser registry.
3. Add parser run table or parser run audit events.
4. Add Chrome/Edge browser history parser.
5. Add browser downloads parser.
6. Add generic SQLite metadata/indexer.
7. Add event writer.
8. Add timeline query with date filtering.

API tasks:

1. Add `/api/cases/{case_id}/artifacts`.
2. Add `/api/cases/{case_id}/timeline`.
3. Add parser status endpoint.

UI tasks:

1. Show artifacts from DB.
2. Show timeline from DB with pagination.
3. Allow pivot from search hit/artifact to timeline window.

Tests:

1. Parser registry test.
2. Browser history fixture test.
3. Downloads fixture test.
4. Event creation test.
5. Timeline date filter test.

Acceptance criteria:

- Browser fixture artifacts appear in search and timeline.
- Parser failure does not fail case ingest.
- Timeline can pivot around selected artifact.

Gate:

- Gate 2 complete: Searchable Case Alpha.

## Week 9: EvidenceAdapter And E01 UX Rework

Release target:

- `0.4.0-beta.1-dev`.

Primary goal:

- Prepare evidence format expansion without increasing mess.

Backend tasks:

1. Add `EvidenceAdapter` interface.
2. Add `FolderAdapter`.
3. Wrap existing E01 flow in `EwfAdapter`.
4. Add `UnsupportedAdapter`.
5. Add adapter diagnostics and capability reporting.
6. Add format detection by extension and basic signature where practical.
7. Add audit records for adapter identify/mount/extract/cleanup.

Future adapter stubs:

1. `RawImageAdapter`.
2. `IsoAdapter`.
3. `VirtualDiskAdapter`.

UI tasks:

1. Show detected evidence format.
2. Show adapter capabilities.
3. Show missing tools and fallback guidance.
4. Show "use mounted folder instead" guidance.

Tests:

1. Adapter detection tests.
2. E01 missing tools test.
3. Unsupported format message test.
4. Audit event test.

Acceptance criteria:

- Folder and E01 inputs both flow through adapters.
- Unsupported image formats fail gracefully with next-step guidance.
- The system is ready to add RAW/ISO/VHD/VMDK incrementally.

Risk buffer:

- Do not attempt full native Windows E01 mounting this week. Document WSL/mounted folder fallback clearly.

## Week 10: Viewer And Compare UX

Release target:

- `0.4.0-beta.1`.

Primary goal:

- Analysts can inspect and compare evidence comfortably.

UI tasks:

1. Improve text/log viewer with line numbers and hit highlights.
2. Improve image viewer with metadata and OCR text panel.
3. Add PDF text preview fallback.
4. Add SQLite table viewer for selected SQLite files.
5. Add compare pane with A/B pinned items.
6. Add metadata/hash/timestamp comparison.
7. Add keyboard shortcuts for verify, mark relevant, exclude, report candidate.

Backend/API tasks:

1. Add source preview modes where needed.
2. Add partial text loading for large files.
3. Add SQLite table introspection endpoint with safety limits.

Tests:

1. Large text partial preview test.
2. SQLite introspection safety test.
3. Source search within file test.
4. JS syntax test.
5. Browser smoke if available.

Acceptance criteria:

- Search result to preview to review mark takes minimal clicks.
- A/B comparison works for two selected items.
- Large text files do not load entirely into the browser.

Gate:

- Gate 3 partial: Analyst Review Beta.

## Week 11: Report And Submission Bundle

Release target:

- `0.4.0-beta.2-dev`.

Primary goal:

- Turn reviewed findings into defensible outputs.

Backend tasks:

1. Add report template engine.
2. Add report sections: executive summary, technical findings, evidence appendix, hash appendix, audit appendix, limitations.
3. Add citation IDs to report.
4. Add verification status to report.
5. Add selected evidence list.
6. Add submission bundle export folder/zip.
7. Add bundle manifest and bundle hash.

API tasks:

1. Add create report endpoint.
2. Add preview report endpoint.
3. Add export submission bundle endpoint.

UI tasks:

1. Add report outline.
2. Add include/exclude controls.
3. Add report preview.
4. Add export bundle button.

Tests:

1. Report generation test.
2. Citation traceability test.
3. Hash appendix test.
4. Bundle manifest test.
5. Audit appendix test.

Acceptance criteria:

- Report separates candidate hits from verified findings.
- Every report finding links back to citation ID and hash record.
- Submission bundle includes report, manifest, hashes, selected evidence list, and audit log.

Gate:

- Gate 3 complete: Analyst Review Beta.

## Week 12: Validation, Benchmark, Release Hardening

Release target:

- `0.4.0-beta.2`.

Primary goal:

- Make the beta testable, repeatable, and honest about limitations.

Validation tasks:

1. Add validation command.
2. Add expected outputs for sample case.
3. Add parser fixture validation.
4. Add report validation.

Benchmark tasks:

1. Add benchmark command.
2. Generate 10k synthetic file benchmark.
3. Generate 100k metadata-only benchmark if practical.
4. Record hardware profile.
5. Output JSON and Markdown benchmark reports.

Release tasks:

1. Add release checklist.
2. Add parser coverage matrix.
3. Add known limitations page.
4. Add security policy draft.
5. Add Windows manual smoke checklist.
6. Run full test suite, compileall, build.

Tests:

1. Full unit suite.
2. Compileall.
3. Package build.
4. Server smoke.
5. Sample case end-to-end.
6. Validation command.
7. Benchmark command smoke.

Acceptance criteria:

- Beta release can be tested by another person from docs.
- Release notes include features, limitations, validation status, benchmark status.
- No claim is made that the tool replaces AXIOM.

Gate:

- Gate 4 complete: Defensible Export Beta.

## Post-12-Week Backlog

Priority order:

1. EVTX parser.
2. LNK parser.
3. Registry USB history parser.
4. Prefetch parser.
5. JumpList parser.
6. RAW/DD adapter.
7. ISO adapter.
8. VHD/VHDX and VMDK adapter.
9. Known-good NSRL import.
10. Known-bad/notable hash set import.
11. Better PDF viewer.
12. Event log specialized viewer.
13. Registry viewer.
14. DOCX/PDF polished report export.
15. Multi-case search.
16. Multi-user collaboration.
17. Remote server auth.
18. Cloud/export import.
19. Mobile export import.
20. Deep carving research.

## Dependency Order

Must be done before others:

1. Doctor diagnostics before Windows alpha.
2. Case DB before FTS search.
3. Citation IDs before report traceability.
4. Hash scope before submission bundle.
5. Audit events before defensible report.
6. Parser contract before parser expansion.
7. EvidenceAdapter before image format expansion.

Can run in parallel:

1. Windows docs can run with doctor implementation.
2. Sample data can run with smoke tests.
3. UI case list can run with DB repository work after API shape is stable.
4. Report templates can start once citation ID model is stable.
5. Parser fixtures can be prepared before parser contract is fully implemented.
6. Benchmark generator can start after file inventory model is stable.

Should not be started early:

1. Mobile/cloud acquisition.
2. Deep carving.
3. Enterprise collaboration.
4. Full native Windows E01 mounting.
5. Large parser expansion before DB/search/plugin contract.

## Weekly Verification Checklist

Run every week before merging or releasing:

1. `python -m unittest discover -s tests`.
2. `python -m compileall -q rapidtriage`.
3. Package build.
4. CLI help smoke.
5. `rapidtriage doctor` smoke.
6. Web server `/api/health` smoke.
7. Static JS/CSS smoke.
8. Sample case smoke once sample exists.
9. Case DB migration test once DB exists.
10. FTS search test once index exists.

## Release Naming

- Week 2: `0.2.0-alpha.1` for Windows/sample usability.
- Week 4: `0.2.0-alpha.2` for case DB alpha.
- Week 6: `0.3.0-alpha.1` for indexed search/review alpha.
- Week 8: `0.3.0-alpha.2` for parser/timeline alpha.
- Week 10: `0.4.0-beta.1` for analyst viewer/review beta.
- Week 12: `0.4.0-beta.2` for report/export/validation beta.

## Staffing Plan If Multiple Developers Are Available

Two-person split:

- Developer 1: backend DB/search/pipeline.
- Developer 2: Windows packaging/UI/docs.

Three-person split:

- Developer 1: DB/search/audit.
- Developer 2: UI/viewer/review/report.
- Developer 3: adapters/parsers/validation/benchmarks.

Four-person split:

- Developer 1: case DB, audit, hash, citation.
- Developer 2: FTS, OCR, pipeline, jobs.
- Developer 3: web UI, viewer, review, report.
- Developer 4: Windows packaging, docs, sample data, parser fixtures.

## Time Risk Assessment

High-risk items:

- Case DB migration without breaking existing run workflow.
- FTS query parser edge cases.
- OCR reliability on Windows.
- E01 behavior across operating systems.
- UI complexity in a single static JS file.
- Report bundle traceability.

Mitigations:

- Keep existing run endpoints until case endpoints are stable.
- Start query parser conservatively.
- Treat OCR as optional capability with clear diagnostics.
- Keep E01 fallback to mounted folder first-class.
- Refactor UI only when necessary; avoid huge rewrites.
- Add citation/hash/audit tests before report polish.

## Minimum Viable Cut If Schedule Slips

If only 4 weeks are available:

- Ship Windows doctor, launchers, sample case, case DB skeleton, source-linked search, and honest docs.

If only 8 weeks are available:

- Ship Windows alpha, case DB, FTS search, review verification, browser parser, timeline foundation.

If only 12 weeks are available:

- Ship full schedule through defensible export beta.

If quality drops:

- Cut parser expansion first.
- Cut advanced viewers second.
- Cut timeline polish third.
- Do not cut doctor, case DB, source links, hash scope, audit log, or report traceability.

## First Day Coding Plan

1. Create a branch for scheduling-backed implementation if not already on one.
2. Commit this roadmap.
3. Implement `rapidtriage doctor` command skeleton.
4. Add doctor checks for Python version and optional tools.
5. Add unit tests for doctor result objects.
6. Add Windows launcher scripts.
7. Add first Windows quick-start document.
8. Run tests and compileall.

## First Week Definition Of Done

By the end of Week 1:

- `rapidtriage doctor` exists.
- Doctor has JSON and text output.
- Windows scripts exist.
- Missing OCR/E01 tools are warnings.
- Static asset smoke test exists.
- Windows quick-start exists.
- Current tests still pass.

This is intentionally not glamorous. It is the foundation that makes everything after it feel like a product instead of a pile of forensic scripts.

## Competitive Intake Addendum: Maestro WISDOM

Source: user-provided product notes. These notes are absorbed as competitive/product requirements, not independently verified benchmark facts.

Key lessons:

- Fast default processing matters. Full carving and heavy indexing should be explicit follow-up jobs, not mandatory first-pass work.
- Artifact breadth matters, but only if results are stable, categorized, source-linked, and viewer-friendly.
- Windows depth is a major differentiator: OS/account metadata, EVTX, Registry, MFT, EDB, WER, Defender/Firewall, Task Scheduler, ADS, VSC, LotL activity, and browser unification.
- Analyst UX matters as much as parser count: SQL/JSON/XML/email/media/browser viewers reduce context switching.
- Trust comes from verified-source output, confidence fields, parser versioning, hash traceability, benchmark transparency, and fast bug-fix loops.

Backlog absorbed from this intake:

1. Add run processing profiles: `fast`, `standard`, `deep`.
2. Keep full carving, OCR-heavy media work, and expensive indexing out of `fast`.
3. Add Windows OS/account summary parser: hostname, timezone, last boot, admin membership, account lifecycle.
4. Add Zone.Identifier ADS parser for download provenance.
5. Add unified browser model for Chrome, Edge, Firefox history/downloads and AI prompt artifacts.
6. Add EVTX parser skeleton with semantic tags and typed parameters.
7. Add Registry hive parser/recovery roadmap with deleted key/value marking.
8. Add MFT parser and timeline merge.
9. Add VSC compare workflow for deleted-file deltas and VSC deletion command detection.
10. Add Defender, Firewall, WER, Task Scheduler, Prefetch, LNK, JumpList, ShellBags, USB history parser backlog.
11. Add optional TI enrichment plugin for URLs, IPs, domains, and hashes.
12. Add Korean OCR validation set and OCR quality metrics.
13. Add Linux XFS and virtual-server dump requirements, including XVA detection.
14. Add APK malware triage as a future mobile-dump feature before full acquisition.
15. Defer live USB collection, remote agents, memory forensics, password cracking, deepfake detection, and similar-image clustering until validation/security posture is stronger.

Design rule:

- Do not chase an unvalidated "500 artifact" number. Prefer a smaller set of parser outputs with fixtures, expected results, parser versions, confidence, source paths, hashes, timeline integration, and report traceability.
