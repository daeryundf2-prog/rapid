# RapidForensic / RapidTriage

RapidForensic은 단일 케이스 기반 디지털 포렌식 triage 도구입니다. 현재 구현체 이름은 `rapidtriage`이며, 폴더, 마운트된 이미지, E01/Ex01 계열 입력, RAW/가상 디스크/아카이브 계열 입력을 받아 파일 목록화, 아티팩트 분석, 키워드 검색, 리뷰, 보고서 후보 생성을 하나의 로컬 GUI와 CLI 흐름으로 연결하는 것을 목표로 합니다.

이 저장소에는 과거 dashcam 유틸리티도 함께 남아 있습니다. 포렌식 제품 본체는 `rapidtriage/`, `rapidtriage/web/static/`, `docs/rapidforensic-*`, `docs/rapidtriage-*`, `scripts/`를 중심으로 봐야 합니다.

## 현재 상태 한 줄 요약

분석관이 로컬에서 케이스를 열고, 증거 폴더나 이미지 기반 추출물을 넣고, 아티팩트와 파일을 검색/리뷰/보고서 후보로 정리하는 데는 사용할 수 있습니다. 다만 AXIOM, EnCase, Maestro WISDOM 같은 상용급 완성품이라고 주장할 단계는 아닙니다. 내부 known-answer 기준 검증은 확장되어 있지만, 실제 Windows 11 E01 대형 케이스, trusted-tool record diff, 독립 검증, 장기 성능 증거가 아직 더 필요합니다.

현재 문서 기준:

| 항목 | 상태 |
| --- | --- |
| 사용자 노출 forensic target | 51개 |
| collector | 23개 |
| artifact type literal | 약 191개 |
| 내부 validation package | 120/120 연결 |
| commercial-grade gate | 0/120 |
| readiness score | 90/100 내부 기준 |
| 상용급 claim | 금지, `commercial_claim_allowed=false` |

## 핵심 사용자 흐름

RapidForensic은 아래 3가지 질문에 답하도록 설계되어 있습니다.

1. E01, 이미지, 폴더, ZIP, DB, 로그 같은 입력을 넣으면 내부 데이터를 분석할 수 있는가?
2. 입력된 증거에서 필요한 파일과 아티팩트를 추출하고 원본 근거까지 확인할 수 있는가?
3. 파일명, 본문, 문서, 브라우저, AI 사용 흔적, EVTX, Registry, 메신저, 메일, OCR 후보를 한 UX에서 검색하고 리뷰할 수 있는가?

GUI 기준 작업 순서는 다음과 같습니다.

1. 케이스 생성 또는 기존 케이스 열기
2. 증거 입력 선택
3. 의존성 검사
4. 파티션/마운트/추출 경로 확인
5. 파일 시스템 및 아티팩트 분석 실행
6. 키워드 검색, 필터, timeline 확인
7. source viewer에서 원본 근거 확인
8. relevant, needs-review, excluded, include-in-report 등 리뷰 상태 부여
9. evidence tray와 보고서 후보 생성
10. QC checklist와 validation package 확인

## 설치

### 공통 요구사항

- Python 3.9 이상
- pip
- 로컬 분석용 충분한 디스크 공간
- 대용량 케이스의 경우 SSD 권장

### macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip build
python -m pip install -e '.[web,test,kakaotalk,columnar]'
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip build
python -m pip install -e ".[web,test,kakaotalk,columnar]"
```

### 선택 의존성

| 기능 | 권장 도구 |
| --- | --- |
| E01/Ex01 직접 처리 | `libewf`, `ewfmount`, Sleuth Kit `mmls`, `tsk_recover` |
| 가상 디스크 변환 | `qemu-img` |
| OCR | `tesseract`, 필요 시 PaddleOCR 계열 외부 파이프라인 |
| 영상/오디오 메타데이터 | `ffprobe` |
| Windows 실제 E01 QC | Windows VM 또는 실제 Windows 11 분석 장비 |

Windows에서는 E01을 직접 열기보다 FTK Imager, Arsenal Image Mounter, OSFMount, libewf/WSL 등으로 읽기 전용 마운트하거나 안전하게 export한 폴더를 입력하는 흐름이 더 안정적입니다.

## 실행

### GUI 실행

macOS/Linux:

```bash
sh scripts/start-rapidtriage.sh
```

Windows:

```powershell
.\scripts\windows\start-rapidtriage.ps1
```

직접 실행:

```bash
rapidtriage web --host 127.0.0.1 --port 8765
```

브라우저에서 아래 주소를 엽니다.

```text
http://127.0.0.1:8765
```

### 환경 점검

```bash
rapidtriage doctor
```

확인 항목은 Python 버전, web extra, optional forensic tool, 포트 사용 여부, static asset 존재 여부, 쓰기 가능한 output 경로입니다.

### 샘플 케이스 실행

```bash
rapidtriage sample --run --overwrite
```

샘플 결과는 `rapidtriage-sample/` 아래에 생성됩니다. GUI에서 이 run output을 열어 검색, 리뷰, 보고서 후보 흐름을 빠르게 확인할 수 있습니다.

## CLI 주요 명령

| 목적 | 명령 |
| --- | --- |
| 전체 워크플로우 실행 | `rapidtriage run <source> --output-dir <out>` |
| 입력 adapter 판정 | `rapidtriage evidence <source> --json` |
| 파일 manifest 생성 | `rapidtriage manifest <source> --output manifest.json` |
| 문서/본문 후보 검색 | `rapidtriage docs <source> -k <keyword> --output docs.json` |
| 파일 후보 분류 | `rapidtriage files <source> --output files.json` |
| 아티팩트 수집 | `rapidtriage artifacts <source> --kind browser --output browser.json` |
| 추출 후보 복사 | `rapidtriage extract <input-json> <out-dir>` |
| timeline 생성 | `rapidtriage timeline <run-output> --output timeline.json` |
| case DB 생성/가져오기 | `rapidtriage case-db <case.db> --create-case CASE-001` |
| case 검색 | `rapidtriage case-search <case.db> --case-id CASE-001 -k password` |
| 리뷰 상태 부여 | `rapidtriage case-review <case.db> --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant` |
| 보고서 후보 | `rapidtriage case-db-report <case.db> --case-id CASE-001 --output report-candidates.json` |
| 대용량 검색 검증 | `rapidtriage large-case-readiness --case-db <case.db> --benchmark ./qc/fts-100k/sqlite-fts-benchmark.json --json` |
| taxonomy 검증 | `rapidtriage taxonomy-audit --strict` |
| commercial readiness | `rapidtriage commercial-readiness --json` |
| validation package | `rapidtriage validation --output-dir ./rapidtriage-validation --overwrite` |

문서와 스키마:

- Output schema: `docs/rapidtriage-output-schema.md`
- Extended output schemas: `docs/rapidtriage-output-schemas.md`
- Windows quickstart: `docs/rapidtriage-windows-quickstart.md`
- Rule engine and IOC lookup: `docs/rapidtriage-rule-engine.md`
- Rule sample: `docs/samples/rapidtriage-rules.sample.yaml`
- JSON schemas: `rapidtriage/schemas/manifest.schema.json`, `rapidtriage/schemas/compare.schema.json`
- Sample JSON: `docs/samples/rapidtriage-manifest.sample.json`, `docs/samples/rapidtriage-docs.sample.json`, `docs/samples/rapidtriage-files.sample.json`, `docs/samples/rapidtriage-extract.sample.json`, `docs/samples/rapidtriage-artifacts.sample.json`, `docs/samples/rapidtriage-run-summary.sample.json`

계약 상태:

- Implemented: `manifest`, `docs`, `files`, `extract`, `artifacts`, `timeline`, `indicators`, `compare`, `run`, case DB, review, report-candidate, validation package, and commercial-readiness workflows are callable from CLI/API/GUI paths.
- Experimental: source viewers, large-case cursor/resume, E01/Ex01 mount/export workflows, Windows artifact parsers, browser/AI traces, messenger/email/cloud importers, and validation gates need broader corpus and platform validation before 상용급 표현이 가능합니다.
- Planned: full native parser parity, independent validation, signed installers, external signing/notarization, 10TB stress evidence, staffed support, and complete chain-of-custody release operations remain operator/release work.

`case-db` stores bookmarks from implemented `files`, `docs`, `artifacts`, `timeline`, `indicators`, and `compare` outputs. `compare` compares two individual evidence/export files. Example commands:

```bash
rapidtriage run . --mode fraud --output-dir ./rapidtriage-run-fraud
rapidtriage artifacts . --kind browser
```

## 지원 입력 범위

| 입력 종류 | 현재 처리 방식 | 주의사항 |
| --- | --- | --- |
| 일반 폴더 | 직접 scan, manifest, artifact collector 실행 | 가장 안정적 |
| 마운트 이미지 | 폴더처럼 처리 | 읽기 전용 마운트 권장 |
| E01/Ex01 | optional libewf/Sleuth Kit 경로 또는 export/mount workflow | Windows 직접 처리보다 mount/export 권장 |
| RAW/split image | adapter 판정, 외부 도구 기반 처리 계획 | split gap 검증 필요 |
| ISO/DMG/WIM/SWM | archive image adapter, 추출 workflow | 암호화/손상 이미지는 제한 |
| VHD/VHDX/VMDK/VDI/QCOW | virtual disk adapter, qemu-img 기반 workflow | snapshot/differencing chain은 QC 필요 |
| ZIP/TAR 등 archive | bounded extraction/search | 압축폭탄 방어 cap 적용 필요 |
| SQLite/DB 파일 | source viewer, table/search, WAL/SHM sidecar 표시 | 대형 DB는 cursor/resume 확인 |
| 메신저/메일 export | parser/import workflow | 서비스별 schema version 검증 필요 |

## 주요 포렌식 기능

### 파일 시스템 및 이미지

- 파일 manifest와 hash 산출
- 파일 카테고리 분류
- 확장자/시그니처 mismatch 후보
- timestamp anomaly 후보
- MFT, USN, LogFile 관련 triage 및 검증대기 workflow
- VSS/APFS snapshot, FDE unlock, unallocated carving은 기능 노출/워크플로우가 있으며 실제 상용급 검증은 추가 필요

### Windows 아티팩트

- EVTX/EventLog triage
- Event ID 기반 log clear, logon session, USB/WLAN/Print/BITS pivot
- Registry, NTUSER/UsrClass, ShellBags, RecentDocs, MUICache, Clipboard 후보
- SAM/SECURITY/SYSTEM 계정/권한 관련 parser 구조
- Amcache, ShimCache, BAM/DAM, SRUM, Windows.edb 관련 parser/검증 workflow
- Prefetch, LNK, JumpList, Task Scheduler, WMI, Defender, Firewall, WER
- USB 외장매체 연결 이력 통합 뷰 목표
- AnyDesk, TeamViewer, Chrome Remote Desktop, RustDesk 등 원격접속 흔적 triage

### 인터넷, 브라우저, AI 사용기록

- Chrome, Edge, Firefox, Safari 계열 브라우저 히스토리/다운로드/쿠키/캐시/session 후보
- WebCacheV01.dat, 로컬 sync DB, browser storage 후보
- ChatGPT, Claude, Gemini, Perplexity 등 AI 서비스 방문/대화 후보
- ChatGPT/Copilot desktop app, 로컬 LLM(Ollama, LM Studio, GPT4All) 흔적 taxonomy
- pagefile/hiberfil/memory URL carving 후보

### 문서, 메일, 검색

- PDF, Office, TXT, EML, MBOX 등 bounded text extraction
- 문서별 size cap, PDF stream cap, ZIP member cap
- SQLite source search cursor/resume
- 현재 파일 검색, 전체 검색, case DB 검색
- PST/OST, Gmail Takeout, M365 export workflow는 parser/검증 보강 필요
- Print Spooler, Sticky Notes, macro risk, metadata extraction 항목 노출

### 메신저, 모바일, 클라우드

- PC KakaoTalk Windows 구형/후패치 계열 분석 workflow와 별도 참조 스크립트
- macOS KakaoTalk 수집/DB 후보 탐지 workflow
- WhatsApp, Telegram, Signal, LINE, Discord, WeChat, Instagram export/import taxonomy
- iOS/Android backup/export 기반 parser 구조
- Google Takeout, iCloud, M365/Teams, AWS/Azure/GCP audit log taxonomy
- cloud API acquisition은 lawful OAuth/token handling 전제

### 미디어, OCR, 메모리, 침해사고

- 이미지 EXIF/GPS, gallery review, perceptual similarity 후보
- OCR queue와 OCR hit review
- 영상/음성 preview/transcript workflow
- hiberfil.sys, pagefile.sys, MEMORY.DMP, minidump import workflow
- YARA/IOC, TI enrichment, NSRL/whitelist, super timeline 목표
- 악성 증거 파일 preview sandbox와 active content 차단은 추가 검증 필요

## GUI 구조

현재 GUI는 분석관이 대량 데이터를 덜 지치고 검토하도록 아래 구조를 목표로 합니다.

- 좌측: capability/artifact tree
- 상단: evidence input, dependency check, run state, readiness gate
- 중앙: virtualized result table
- 우측: preview/detail/source viewer
- 하단 또는 side tray: selected evidence, review state, report candidate
- 공통: current-file search, global search, cursor/resume, truncated warning, citation

중요한 UX 원칙은 “예쁜 화면”보다 “10만 건 이상 결과에서도 누락/오판을 줄이는 화면”입니다.

## 산출물

대표 산출물은 다음과 같습니다.

- `manifest.json`
- `files.json`
- `docs.json`
- `artifacts.json`
- `timeline.json`
- `normalized-case.json`
- `case.db`
- `report-candidates.json`
- `validation package`
- `commercial-readiness.json`
- `submission bundle`

보고서 후보에는 가능한 경우 source path, source hash, parser version, offset/index, reviewer state, limitation, citation metadata를 포함해야 합니다.

## 검증과 QC

핵심 검증 문서:

- [한글 기능 명세서](docs/rapidforensic-feature-spec-ko.md)
- [한글 QC 체크리스트](docs/rapidforensic-qc-checklist-ko.md)
- [사용자 노출 기능 taxonomy](docs/rapidforensic-visible-forensic-feature-taxonomy.md)
- [Windows 핵심 흐름 QC](docs/rapidforensic-core-flow-windows-qc-checklist.md)
- [E01 workflow](docs/rapidtriage-e01-workflow.md)
- [known limitations](docs/rapidtriage-known-limitations.md)

기본 검증:

```bash
.venv/bin/python -m unittest tests.test_rapidtriage_web_static tests.test_rapidtriage_artifact_taxonomy
rapidtriage taxonomy-audit --strict
rapidtriage commercial-readiness --json
```

릴리스 전에는 Windows 11 E01 실케이스, macOS 폴더/마운트 케이스, 대형 SQLite/FTS case, source viewer, report bundle, dependency check, crash/cancel/retry까지 별도 QC가 필요합니다.

## 중요한 제한사항

- 현재 구현은 triage와 reviewer workflow 중심입니다.
- 모든 parser가 상용 도구 수준의 native/full parser는 아닙니다.
- EVTX, Registry, ESE, MFT, USN은 trusted-tool diff와 대형 fixture 검증이 더 필요합니다.
- Python 기반 hot path는 대형 케이스에서 병목이 될 수 있으므로 Rust/Go/C++ sidecar 전환 대상이 남아 있습니다.
- 암호화 볼륨, browser secret, cloud token, messenger key handling은 lawful authority와 audit log를 전제로 합니다.
- GUI에 보이는 기능은 “사용 가능”을 뜻하며, “법정 제출 완성”이나 “상용급 검증 완료”를 뜻하지 않습니다.

## 개발자 참고

주요 디렉터리:

| 경로 | 설명 |
| --- | --- |
| `rapidtriage/cli.py` | CLI entrypoint |
| `rapidtriage/api/app.py` | FastAPI 로컬 API |
| `rapidtriage/web/static/` | 로컬 웹 UI |
| `rapidtriage/core/` | orchestration, case DB, search, validation, reporting |
| `rapidtriage/artifacts/` | OS/app/cloud/media artifact collectors |
| `rapidtriage/artifacts/windows/` | Windows 전용 parser/collector |
| `docs/` | 사용자 문서, QC, validation, architecture |
| `scripts/` | release, smoke, KakaoTalk, sandbox, evidence helper |
| `tests/` | unit/static/QC tests |

로컬 가상환경, 캐시, OMX 런타임 파일은 저장소에 커밋하지 않습니다. 재현 가능한 설치 명령과 문서/테스트/샘플 산출물만 Git에 남깁니다.
