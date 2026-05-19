# RapidForensic / RapidTriage

RapidForensic은 로컬 우선(local-first) 디지털 포렌식 triage 작업대입니다.
현재 실행 이름은 `rapidtriage`이며, Python CLI와 로컬 웹 UI로 구성되어
있습니다.

목표는 명확합니다. E01/Ex01 워크플로우 산출물, 마운트된 이미지, 폴더,
RAW/가상 디스크 export, ZIP/archive, DB, 로그, 문서 묶음 같은 입력을 받아
분석관이 필요한 증거를 빠르게 검색하고, 원본 근거를 확인하고, 리뷰 상태를
부여하고, 보고서 후보와 제출 패키지로 정리하게 만드는 것입니다.

이 저장소에는 과거 dashcam 도구와 Mac cleanup helper 같은 레거시 파일도
남아 있습니다. 포렌식 제품 본체는 아래 경로를 중심으로 보면 됩니다.

- `rapidtriage/`
- `rapidtriage/web/static/`
- `docs/rapidforensic-*`
- `docs/rapidtriage-*`
- `scripts/`
- `tests/`

## 현재 상태

RapidForensic은 현재 로컬 triage, 샘플 케이스, 마운트/추출된 증거 폴더,
문서 검색, 브라우저/AI 사용 흔적, Windows 아티팩트 중심 수집 workflow,
리뷰 상태, 보고서 후보 생성까지는 사용할 수 있습니다.

다만 AXIOM, EnCase, Nuix, Maestro WISDOM 같은 상용 포렌식 제품을 대체한다고
주장할 단계는 아닙니다. 내부 구현과 검증 패키지는 많이 확장되었지만, 실제
Windows E01 검증, trusted-tool row diff, 독립 검증, 서명된 설치파일,
notarization, 대용량 실장비 스트레스 증거가 아직 필요합니다.

| 항목 | 현재 증거 |
| --- | --- |
| 사용자 노출 forensic target | 51개 taxonomy target covered |
| collector surface | 23개 |
| artifact type literal | 약 190개 |
| 내부 validation package | 120/120 연결 |
| 내부 readiness score | 최신 Mac-local 증거 기준 90/100 |
| commercial-grade gate | 0/120, 의도적으로 차단 |
| 상용급 claim | 금지, `commercial_claim_allowed=false` |

최근 Mac-local 검증 산출물:

- [Mac verification README](qc-runs/2026-05-19-macos-full/README.md)
- [Commercial parity backlog](docs/rapidtriage-commercial-parity-backlog.md)
- [Known limitations](docs/rapidtriage-known-limitations.md)

## 누구를 위한 도구인가

RapidForensic은 아래 질문을 빠르게 답해야 하는 분석관을 기준으로 설계합니다.

- 사용자가 무엇을 열고, 검색하고, 다운로드하고, 복사하고, 삭제하고,
  실행했는가?
- 사건 키워드와 관련된 파일, 브라우저 기록, AI 프롬프트, 메시지, 이메일,
  로그, OCR hit는 무엇인가?
- 해당 결과가 source path, hash, parser, offset, table, validation warning으로
  추적되는가?
- 어떤 항목을 `relevant`, `needs-review`, `excluded`, `include-in-report`로
  분류해야 하는가?
- 보고서에 넣기 전에 어떤 외부 검증이 더 필요한가?

이 도구는 단순 파일 탐색기가 아니라 포렌식 판단 시스템을 목표로 합니다.
전체 파일트리 탐색은 보조 기능이고, 핵심 흐름은 증거 입력, 아티팩트 분류,
검색, 원본 확인, 리뷰, citation, bundle export입니다.

## 빠른 시작

### 권장 런타임

- Python 3.12 권장
- 최소 Python 3.10+ 권장
- Python 3.9에서도 일부 core workflow는 실행될 수 있지만, 최근 보안 패치가
  적용된 의존성을 설치하지 못할 수 있습니다.
- 대용량 케이스는 SSD 권장
- 실제 E01/Ex01은 가능하면 읽기 전용 mount 또는 검증된 export 경로 권장

### macOS / Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip build
python -m pip install -e '.[web,test,kakaotalk,columnar]'
rapidtriage doctor
```

`python3.12`가 없다면 설치된 Python 3.10+ 인터프리터를 사용하세요.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip build
python -m pip install -e ".[web,test,kakaotalk,columnar]"
rapidtriage doctor
```

`py -3.12`가 없다면 Python 3.12를 설치하거나 `py -3.11`을 사용하세요.

### 웹 UI 실행

macOS / Linux:

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

브라우저에서 엽니다.

```text
http://127.0.0.1:8765
```

원격 인터페이스에 바인딩할 때는 반드시 auth token을 설정해야 합니다.

### 샘플 케이스 생성

```bash
rapidtriage sample --run --overwrite
```

샘플 케이스는 실제 증거를 건드리지 않고 UI, 검색, 리뷰 보드, timeline,
보고서 후보, validation warning을 확인하는 용도입니다.

아래 명령에서 `rapidtriage` 실행 파일을 찾지 못하면 같은 명령을
`python -m rapidtriage ...` 형태로 실행하세요.

## 분석관 workflow

권장 흐름은 다음과 같습니다.

1. 케이스를 만들거나 기존 케이스를 엽니다.
2. 증거를 추가합니다: 폴더, 마운트 이미지, E01 export, archive, DB, run output.
3. `doctor`와 dependency check를 실행합니다.
4. 이미지/export 지원 여부와 읽기 전용 상태를 확인합니다.
5. manifest, hash, 파일 카테고리, 문서 본문, 아티팩트, timeline을 생성합니다.
6. 전체 케이스 검색과 현재 파일 검색을 사용합니다.
7. EVTX, Registry, Browser/AI, Document, Media/OCR, Messenger/Email, Timeline으로
   pivot합니다.
8. 원본 preview와 citation metadata를 확인한 뒤 결과를 신뢰합니다.
9. 리뷰 상태를 부여합니다: relevant, needs-review, excluded, include-in-report.
10. 보고서 후보와 제출 bundle을 생성합니다.
11. validation/readiness check를 실행하고 limitation을 보존합니다.

## 주요 CLI 명령

| 목적 | 명령 |
| --- | --- |
| 웹 UI 실행 | `rapidtriage web --host 127.0.0.1 --port 8765` |
| 런타임 점검 | `rapidtriage doctor` |
| 샘플 케이스 생성 | `rapidtriage sample --run --overwrite` |
| 입력 adapter 확인 | `rapidtriage evidence <source> --json` |
| 한 번에 triage 실행 | `rapidtriage run <source> --output-dir <out> --read-only` |
| 파일 manifest 생성 | `rapidtriage manifest <source> --output manifest.json` |
| 문서 본문 검색 | `rapidtriage docs <source> -k <keyword> --output docs.json` |
| 파일 후보 스캔 | `rapidtriage files <source> --output files.json` |
| 아티팩트 수집 | `rapidtriage artifacts <source> --kind browser --output artifacts.json` |
| timeline 병합 | `rapidtriage timeline <run-output> --output timeline.json` |
| 완료 run 검색 | `rapidtriage search <run-output> -k <keyword>` |
| source 안전 preview | `rapidtriage source-read <run-output> --path <source-path> --hash --json` |
| source 내부 검색 | `rapidtriage source-search <run-output> --path <source-path> -k <keyword>` |
| Case DB 생성 | `rapidtriage case-db <case.db> --create-case CASE-001` |
| Case DB 검색 | `rapidtriage case-search <case.db> --case-id CASE-001 -k password` |
| 리뷰 상태 부여 | `rapidtriage case-review <case.db> --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant` |
| 보고서 후보 export | `rapidtriage case-db-report <case.db> --case-id CASE-001 --output report-candidates.json` |
| 제출 bundle 생성 | `rapidtriage bundle <case-json> --allowed-root <evidence-root> --output-dir <bundle-dir>` |
| taxonomy audit | `rapidtriage taxonomy-audit --strict` |
| validation package | `rapidtriage validation --output-dir ./rapidtriage-validation --overwrite` |
| commercial readiness | `rapidtriage commercial-readiness --json` |

전체 명령 목록은 다음으로 확인합니다.

```bash
python -m rapidtriage --help
```

## 지원 입력 범위

| 입력 | 현재 처리 방식 | 주의사항 |
| --- | --- | --- |
| 일반 폴더 | 직접 scan, manifest, docs, artifacts, timeline | 가장 안정적 |
| 마운트 이미지 | 폴더 source처럼 처리 | 읽기 전용 mount 권장 |
| E01/Ex01 | optional libewf/Sleuth Kit workflow 또는 export/mount | native 상용급 parity는 외부 검증 필요 |
| RAW/split image | adapter와 workflow metadata 지원 | split gap과 partition 검증 필요 |
| VHD/VHDX/VMDK/VDI/QCOW | virtual disk workflow, qemu-img 중심 증거 | snapshot/differencing chain은 QC 필요 |
| ISO/DMG/WIM/SWM | archive image workflow | 암호화/손상 이미지는 limitation |
| ZIP/TAR archive | bounded extraction/search workflow | 압축폭탄 방어 cap 유지 필요 |
| SQLite/DB | source preview, table/search sidecar, WAL/SHM 인식 | 대형 DB는 cursor/resume 권장 |
| 문서 | PDF, Office, text, EML, MBOX 중심 추출 | PST/OST는 외부 parser workflow와 검증 필요 |
| 메신저/메일/cloud export | 서비스별 importer taxonomy와 일부 parser | 서비스별 schema/version 검증 필요 |

## 기능 지도

### 증거와 파일 시스템

- Manifest 생성, hash, source path 보존
- 파일 type/category triage
- 확장자/시그니처 mismatch 후보
- timestamp anomaly 후보
- bounded extraction과 copy manifest
- E01/Ex01, RAW, virtual disk, archive, mounted-image workflow
- hash cache, known-good/NSRL index, duplicate detection, large-case readiness

### Windows 아티팩트

- EVTX/EventLog triage, event pivot, validation warning
- Registry/NTUSER/UsrClass, ShellBags, RecentDocs, MUICache, Clipboard workflow
- SAM/SECURITY/SYSTEM 계정/권한 parser surface
- Amcache, ShimCache/AppCompatCache, BAM/DAM, SRUM, Windows.edb, MFT, USN,
  Prefetch, LNK, JumpList, Task Scheduler, WMI, Defender, Firewall, WER
- USB, WLAN, PrintService, BITS, 원격접속 흔적, 실행 흔적 pivot

### 브라우저, 웹, AI 사용 기록

- Chrome, Edge, Firefox, Safari 계열 history/download/storage trace
- browser cache/session/extension/cookie taxonomy와 legal warning gate
- ChatGPT, Claude, Gemini, Perplexity, Copilot, local LLM 사용 흔적
- authorized export 또는 recoverable storage가 있을 때 AI 질문/답변 pairing workflow

### 문서, 검색, 리뷰

- 전체 케이스 검색과 현재 source 검색
- PDF, HWP/Office 계열 문서, EML/MBOX, OCR 후보, 보고서 후보 중심 review lane
- keyword pack, fuzzy/proximity 계열 검색 control, source preview, citation,
  review state, evidence tray
- SQLite/table, text, image, media, hex/source, timeline, browser-history viewer surface

### 메신저, 모바일, 이메일, 클라우드

- authorized PC KakaoTalk Windows workflow
- legacy userDir 기반 recovery, post-patch memory/key-store inspection surface
- macOS KakaoTalk inventory/report workflow
- WhatsApp, Telegram, Signal, LINE, Discord, WeChat, Instagram, iOS/Android,
  Google Takeout, iCloud, M365/Teams, cloud API acquisition taxonomy
- secret handling은 opt-in, redaction, audit, lawful authority 전제

### 미디어, OCR, 메모리, IR

- 이미지 EXIF/GPS, media candidate review, OCR queue, transcript sidecar
- hiberfil.sys, pagefile.sys, MEMORY.DMP, minidump, memory-carving workflow
- IOC/TI enrichment, YARA 계열 workflow, super timeline
- parser sandboxing, crash report, cancellation/retry, local-only enterprise control

## 웹 UI 구조

UI는 일반 탐색기가 아니라 포렌식 리뷰 흐름에 맞추는 중입니다.

- 왼쪽: 증거/source group과 artifact category
- 상단: case 상태, source path, 검색, filter, readiness warning
- 중앙: document, artifact, timeline, media, source preview, search hit용 adaptive review table/viewer
- 오른쪽: intelligence, pivot, citation, hash/source detail, review state, report readiness warning

설계 우선순위:

- 관련 증거는 3클릭 안에 도달해야 합니다.
- 검색과 preview는 keyboard-first에 가까워야 합니다.
- 대형 result table은 pagination, cursor, virtualization이 필요합니다.
- validation warning은 낙관적인 summary card 뒤에 숨기면 안 됩니다.
- 보고서 후보에는 source provenance와 limitation이 반드시 따라가야 합니다.

## 대표 산출물

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

보고서 후보에는 가능한 경우 source path, source hash, parser version,
offset/index/table pointer, reviewer state, limitation text, citation metadata를
포함해야 합니다.

## 검증과 QC

빠른 로컬 점검:

```bash
python -m unittest tests.test_rapidtriage_web_static tests.test_rapidtriage_artifact_taxonomy
rapidtriage taxonomy-audit --strict
rapidtriage commercial-readiness --json
```

최근 Mac-local 전체 검증에서 사용한 핵심 명령:

```bash
sh scripts/smoke-test-rapidtriage.sh --output-dir qc-runs/2026-05-19-macos-full/smoke --venv-dir .venv --port 8879
rapidtriage macos-live-smoke --output-dir qc-runs/2026-05-19-macos-full/macos-live-smoke --benchmark-file-count 500 --fts-record-count 5000 --keyword password --overwrite --json
rapidtriage taxonomy-audit --strict --json
rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --json
```

실제 release 전에는 아래 증거를 추가해야 합니다.

- 깨끗한 Windows 11 설치 후 smoke run
- 실제 또는 trusted Windows E01/Ex01 workflow
- 핵심 parser별 trusted-tool record-level diff
- 독립 검증 또는 AppSec review
- 1TB-10TB 증거 스트레스 run
- Windows signed installer
- macOS codesign/notarization
- SBOM, dependency scan, release checklist, support process evidence

## 중요한 제한사항

- 현재는 triage/review workflow이며, 상용 forensic suite와 full native parser
  parity를 달성한 상태가 아닙니다.
- EVTX, Registry, ESE, MFT, USN, SRUM, Windows.edb, disk-image 경로는 더 큰
  fixture corpus와 trusted-tool row diff가 필요합니다.
- UI에 보이는 “사용 가능”은 “상용급 검증 완료”와 다릅니다.
- Python hot path는 대용량 증거에서 병목이 될 수 있습니다. Rust/Go/C++
  sidecar와 columnar storage 전환 대상이 남아 있습니다.
- browser secret, cloud token, messenger key, encrypted backup, memory material은
  lawful authority, opt-in, redaction, immutable audit log가 필요합니다.
- 외부 서명, notarization, 독립 검증, 실장비 stress 결과는 저장소 내부에서
  가짜로 대체할 수 없습니다.

## 문서 지도

먼저 볼 문서:

- [User guide](docs/rapidtriage-user-guide.md)
- [macOS/Linux quickstart](docs/rapidtriage-macos-linux-quickstart.md)
- [Windows quickstart](docs/rapidtriage-windows-quickstart.md)
- [E01 workflow](docs/rapidtriage-e01-workflow.md)
- [Known limitations](docs/rapidtriage-known-limitations.md)
- [Visible forensic feature taxonomy](docs/rapidforensic-visible-forensic-feature-taxonomy.md)
- [Output schema](docs/rapidtriage-output-schema.md)
- [Extended output schemas](docs/rapidtriage-output-schemas.md)
- [Rule engine and IOC lookup](docs/rapidtriage-rule-engine.md)
- [Commercial parity backlog](docs/rapidtriage-commercial-parity-backlog.md)
- [Release checklist](docs/rapidtriage-release-checklist.md)

Validation batch 문서:

- [Core #1-#5](docs/rapidtriage-core-forensics-001-005-validation.md)
- [Core #6-#10](docs/rapidtriage-core-forensics-006-010-validation.md)
- [Core #11-#15](docs/rapidtriage-core-forensics-011-015-validation.md)
- [Core #16-#20](docs/rapidtriage-core-forensics-016-020-validation.md)
- [Core #21-#25](docs/rapidtriage-core-forensics-021-025-validation.md)
- [Core #26-#30](docs/rapidtriage-core-forensics-026-030-validation.md)
- [Core #31-#40](docs/rapidtriage-core-forensics-031-040-validation.md)
- [Core #41-#50](docs/rapidtriage-core-forensics-041-050-validation.md)
- [Core #51-#60](docs/rapidtriage-core-forensics-051-060-validation.md)
- [Core #61-#70](docs/rapidtriage-core-forensics-061-070-validation.md)
- [Core #71-#80](docs/rapidtriage-core-forensics-071-080-validation.md)
- [Core #81-#90](docs/rapidtriage-core-forensics-081-090-validation.md)
- [Core #91-#100](docs/rapidtriage-core-forensics-091-100-validation.md)
- [Core #101-#120](docs/rapidtriage-core-forensics-101-120-validation.md)

Known-answer evidence는 `docs/validation/` 아래에 있습니다.

## 개발자 참고

| 경로 | 설명 |
| --- | --- |
| `rapidtriage/cli.py` | CLI entry point |
| `rapidtriage/api/app.py` | FastAPI local API |
| `rapidtriage/web/static/` | Local web UI |
| `rapidtriage/core/` | orchestration, case DB, search, validation, reporting |
| `rapidtriage/artifacts/` | OS/app/cloud/media artifact collectors |
| `rapidtriage/artifacts/windows/` | Windows parser and collector surfaces |
| `rapidtriage/schemas/` | JSON schema contracts |
| `docs/` | 사용자 문서, QC 문서, validation, architecture note |
| `scripts/` | release, smoke, sandbox, KakaoTalk, evidence helper |
| `tests/` | unit, static, QC tests |

로컬 가상환경, 캐시, OMX runtime state, 원본 증거, 개인 case output은 커밋하지
마세요. 재현 가능한 source, test, docs, schema, 작은 curated verification
evidence만 Git에 남깁니다.
