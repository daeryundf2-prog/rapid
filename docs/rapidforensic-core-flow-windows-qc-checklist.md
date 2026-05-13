# RapidForensic 핵심 흐름 Windows 기능 검토 체크리스트

작성일: 2026-05-14

이 문서는 RapidForensic의 세 가지 핵심 흐름을 실제 Windows 환경에서 검증하기 위한 기능별 체크리스트다.

핵심 질문은 아래 3개다.

1. E01/이미지/폴더를 넣으면 안의 데이터를 분석하는가?
2. 분석된 데이터에서 필요한 파일을 해시와 함께 추출할 수 있는가?
3. 분석된 데이터가 키워드 검색되고, 원본 뷰어와 리뷰/보고서까지 이어지는가?

## 현재 코드 기준 요약

| 영역 | 현재 코드상 범위 | Windows 실테스트 판단 |
| --- | ---: | --- |
| 입력 root 종류 | 6종: folder, mounted-image, e01-derived, disk-image-derived, archive-image-derived, live | UI와 CLI에서 모두 선택/자동 판별 확인 필요 |
| 직접/연동 이미지 처리 확장자 | 22개 | 외부 도구 설치 상태에 따라 성공 여부 달라짐 |
| 포렌식 이미지류 탐지 확장자 | 44개 | 탐지와 직접 분석은 구분해야 함 |
| 파일 후보 분류 확장자 | 147개 | 분류 정확도와 대용량 성능 검증 필요 |
| 추출 파일 카테고리 | 10개 | manifest, SHA256, read-only 동작 검증 필요 |
| 문서 본문 검색 확장자 | 28개 | legacy Office와 대형 문서는 별도 확인 필요 |
| 명시적 검색/뷰어 확장자 | 46개 | SQLite, OCR, 이메일, 문서 뷰어별 검증 필요 |
| OCR 이미지 확장자 | 9개 | Tesseract/OpenCV 설치와 한글 정확도 확인 필요 |
| 아티팩트 collector | 22개 | 상용급 정확도는 collector별 trusted diff 필요 |
| Windows 전용 collector | 10개 | EVTX/Registry/MFT/USN/ESE는 깊이 검증 필요 |
| macOS 전용/준전용 collector | 2개 | macOS-system, kakaotalk-macos 실데이터 검증 필요 |

## 1. 증거 입력 및 분석 흐름

### 1.1 폴더/마운트 이미지 입력

현재 기능:

- 폴더는 직접 스캔한다.
- 마운트된 이미지 폴더도 folder/mounted-image로 처리한다.
- 출력은 source 외부 output directory에 생성된다.
- 파일 후보, 문서 검색, 아티팩트, 타임라인, indicator, 보고서가 한 run으로 묶인다.

부족하거나 예상되는 문제:

- 마운트 root가 실제 증거 root인지, 하위 사용자 폴더만 넣은 것인지 UI에서 더 명확히 구분해야 한다.
- Windows 경로 대소문자, 긴 경로, 한글 경로, 공백 경로, UNC 경로를 실제로 확인해야 한다.
- 분석 root 안에 output directory를 잘못 넣는 오염 케이스를 강하게 차단하는지 확인해야 한다.

Windows 테스트:

- [ ] `C:\Cases\MountedWin11` 폴더를 root로 넣고 run이 완료되는지 확인한다.
- [ ] 한글 경로 `C:\사건\증거 1`에서 run이 완료되는지 확인한다.
- [ ] output directory를 evidence root 내부로 지정했을 때 경고 또는 차단되는지 확인한다.
- [ ] 분석 완료 후 UI 3단계 카드가 `분석 완료`, `추출 완료/추출 가능`, `검색 가능`으로 표시되는지 확인한다.
- [ ] 생성된 `rapidtriage-run-summary.json`의 `outputs`가 누락 없이 열리는지 확인한다.

합격 기준:

- UI에서 evidence 선택, run 시작, 완료 상태, output 경로가 혼동 없이 보인다.
- source root 원본은 수정되지 않는다.
- 실패 시 어느 stage에서 실패했는지 message와 log가 남는다.

### 1.2 E01/Ex01 입력

현재 기능:

- `.e01`, `.ex01`를 E01 계열로 인식한다.
- `ewfmount`, `mmls`, `tsk_recover`가 있으면 read-only mount, partition 선택, filesystem recovery, downstream analysis로 이어진다.
- E01 stage checkpoint, metadata, tool command provenance, partition start sector 기록이 있다.
- GUI에는 E01 선택, evidence support check, partition start sector 입력, run 버튼이 있다.

부족하거나 예상되는 문제:

- Windows native 환경에서는 `ewfmount`가 보통 바로 동작하지 않을 수 있다. WSL2 또는 사전 export workflow가 필요할 가능성이 높다.
- encrypted E01, corrupt E01, split E01 세트, 다중 파티션, BitLocker 볼륨은 실제 corpus 검증이 부족하다.
- 파티션 자동 선택이 항상 “분석자가 원하는 Windows 파티션”을 고르는지 실증이 필요하다.
- E01 전체 해시, segment hash, recovered filesystem hash/provenance를 보고서에서 얼마나 명확히 보여주는지 확인해야 한다.

Windows 테스트:

- [ ] `py -m rapidtriage doctor --json`에서 E01 tools 상태를 저장한다.
- [ ] `py -m rapidtriage evidence C:\Cases\Win11.E01 --json`으로 `support_level`, `can_extract`, `missing_tools`를 확인한다.
- [ ] WSL2 사용 시 Windows UI에서 WSL 경로/Windows 경로 입력이 어떻게 처리되는지 확인한다.
- [ ] `py -m rapidtriage e01-smoke C:\Cases\Win11.E01 --output-dir C:\Cases\Smoke --case-id WIN11-QC-001`를 실행한다.
- [ ] partition list가 UI 또는 output metadata에 표시되는지 확인한다.
- [ ] 자동 partition이 틀리면 `--e01-partition-start-sector` 또는 UI 입력으로 수동 지정이 되는지 확인한다.
- [ ] E01 추출 후 파일 후보/문서/아티팩트/검색/보고서까지 하나의 case로 이어지는지 확인한다.

합격 기준:

- E01 선택 후 의존성 검사, 파티션 판단, 추출, 분석, 검색, 리뷰, 보고서까지 끊기지 않는다.
- 실패 시 “도구 없음”, “partition 선택 필요”, “암호화/손상 가능성”이 명확히 나온다.
- source image와 extracted tree의 provenance가 report/export에 남는다.

### 1.3 RAW/split image 입력

현재 기능:

- `.dd`, `.raw`, `.img`, `.001`, `.000`, `.0000`, `.0001`, `.00001`, `.ima`를 RAW/split 계열로 처리한다.
- `mmls`, `tsk_recover` 기반 partition/filesystem recovery를 시도한다.
- split segment discovery와 gap warning contract가 있다.

부족하거나 예상되는 문제:

- split set naming이 다양하면 누락될 수 있다.
- encrypted volume unlock workflow는 구현되어 있지 않다.
- VSC를 raw image 내부에서 native mount하는 기능은 없다.
- 실제 1TB 이상 RAW/split에서 속도/재개/메모리 검증이 필요하다.

Windows 테스트:

- [ ] `.001`, `.002` 등 split 세트가 모두 발견되는지 확인한다.
- [ ] 일부 segment를 의도적으로 제거한 사본으로 gap warning이 뜨는지 확인한다.
- [ ] 전체 image fallback과 partition recovery 선택이 output metadata에 기록되는지 확인한다.
- [ ] 100GB 이상 RAW에서 진행률, cancel, resume이 실제로 동작하는지 확인한다.

합격 기준:

- segment 누락/순서 문제가 조용히 무시되지 않는다.
- 추출된 filesystem root가 downstream 분석에 자동 연결된다.

### 1.4 ISO/DMG/WIM/SWM archive image 입력

현재 기능:

- `.iso`, `.dmg`, `.wim`, `.swm`을 archive image로 인식한다.
- `7zz`, `7z`, `bsdtar` 중 가능한 도구로 extract를 시도한다.

부족하거나 예상되는 문제:

- DMG는 macOS와 Windows에서 도구 지원 차이가 크다.
- WIM/SWM multi-index 처리와 Windows 설치 이미지 내부 artifact 분석은 제한적이다.
- 암호화/압축폭탄성 archive 방어 확인이 필요하다.

Windows 테스트:

- [ ] ISO를 넣었을 때 extract 후 파일/문서/검색으로 연결되는지 확인한다.
- [ ] DMG를 Windows에서 넣었을 때 가능한 도구 안내 또는 실패 message가 적절한지 확인한다.
- [ ] WIM/SWM multi-part 파일에서 어떤 index가 추출되는지 기록되는지 확인한다.

합격 기준:

- 지원 불가/부분 지원 상황이 분석자에게 명확히 표시된다.
- archive extract 산출물에도 source provenance가 남는다.

### 1.5 Virtual disk 입력

현재 기능:

- `.vhd`, `.vhdx`, `.vmdk`, `.vdi`, `.qcow`, `.qcow2`는 `qemu-img` 변환 후 RAW extraction path로 이어질 수 있다.
- `.xva`는 탐지하지만 direct extraction은 제한적이다.

부족하거나 예상되는 문제:

- differencing disk, snapshot chain, parent disk resolution은 완전하지 않다.
- converted raw hash와 원본 hash provenance가 실제 보고서에서 충분히 보이는지 확인해야 한다.
- Windows에서 qemu-img 설치/경로 문제 가능성이 높다.

Windows 테스트:

- [ ] VHDX를 넣고 qemu-img preflight가 통과하는지 확인한다.
- [ ] VMDK 단일 파일과 split VMDK를 각각 확인한다.
- [ ] snapshot/differencing disk는 blocker로 명확히 표시되는지 확인한다.
- [ ] 변환 raw와 downstream extracted filesystem의 해시/provenance가 남는지 확인한다.

합격 기준:

- 단일 virtual disk는 분석 흐름으로 이어진다.
- snapshot/chain이 필요한 경우 조용히 잘못 분석하지 않고 limitation이 표시된다.

## 2. 분석 collector 및 아티팩트 흐름

### 2.1 공통 collector 10종

현재 대상:

- browser
- recent-files
- email
- cloud-export
- mobile-export
- kakaotalk-macos
- kakaotalk-windows
- android-apk
- media-image
- memory-volatility

부족하거나 예상되는 문제:

- 공통 collector는 OS별 경로 차이에 강해야 한다.
- “탐지/요약” 수준과 “법정 제출 가능한 row decode” 수준을 UI에서 구분해야 한다.
- 메신저/클라우드/모바일은 export schema version 관리와 실제 fixture가 더 필요하다.

Windows 테스트:

- [ ] Chrome/Edge/Firefox history, downloads, cache/session 후보가 잡히는지 확인한다.
- [ ] ChatGPT/Claude/Gemini/Perplexity 사용 흔적이 browser artifact와 search 결과에 연결되는지 확인한다.
- [ ] PC KakaoTalk legacy/post-patch 샘플을 각각 넣고 message count, attachment, viewer가 나오는지 확인한다.
- [ ] EML/MBOX는 message/thread/attachment viewer가 동작하는지 확인한다.
- [ ] PST/OST는 “bounded extraction/triage”인지 “full mailbox parser”인지 limitation이 명확한지 확인한다.
- [ ] mobile export는 Cellebrite/XRY/AXIOM export folder를 넣고 schema별 row가 누락되지 않는지 확인한다.
- [ ] memory dump는 `.dmp`, `.mem`, `.raw`, `.vmem`에서 indicator scan과 Volatility output import가 구분되는지 확인한다.

합격 기준:

- collector 실패가 전체 run을 죽이지 않고 parser_errors로 격리된다.
- artifact row가 search/timeline/source viewer/review로 연결된다.

### 2.2 Windows 전용 collector 10종

현재 대상:

- windows-os-account
- eventlog
- windows-search-index
- windows-remote-access
- windows-execution
- windows-registry
- windows-shellbags
- windows-prefetch
- windows-filesystem
- windows-system

부족하거나 예상되는 문제:

- EVTX는 Native BinXML 전체 문법, provider resource DLL message rendering, corrupt/deleted recovery, EvtxECmd/Hayabusa record diff가 아직 최종 상용급 검증 포인트다.
- Registry는 LOG1/LOG2 transaction replay, deleted key/value allocator 검증, NTUSER/UsrClass user activity 정확도가 더 필요하다.
- Windows.edb/SRUM은 ESE catalog/table/page/tagged-column full decode와 trusted parser diff가 필요하다.
- MFT/USN은 100만~1000만 file record, 수천만 USN record에서 path reconstruction, rename/delete replay, cursor pagination 검증이 필요하다.
- Prefetch/LNK/JumpList/ShellBags/Amcache/ShimCache/BAM/DAM은 OS build별 layout 차이를 fixture로 확인해야 한다.

Windows 테스트:

- [ ] `C:\Windows\System32\winevt\Logs`의 EVTX 전체를 분석하고 EvtxECmd/Hayabusa와 event record count를 비교한다.
- [ ] Security 4624/4625/4688, PowerShell 4103/4104, Defender, Sysmon이 message rendering되는지 확인한다.
- [ ] NTUSER.DAT, UsrClass.dat, SYSTEM, SOFTWARE, SAM, SECURITY hive를 넣고 RECmd와 key/value count 및 주요 artifact를 비교한다.
- [ ] Registry LOG1/LOG2가 있는 샘플에서 replay 전후 차이가 기록되는지 확인한다.
- [ ] `$MFT`, `$UsnJrnl:$J`, `$LogFile` 후보를 가진 NTFS export에서 MFTECmd/UsnJrnl2Csv와 비교한다.
- [ ] Prefetch는 PECmd와 실행 파일명, last run, run count, referenced file metrics를 비교한다.
- [ ] Windows.edb/SRUM은 libesedb/SrumECmd/WinSearchDBAnalyzer export와 row-level diff를 수행한다.
- [ ] ShellBags는 ShellBagsExplorer/RECmd와 BagMRU path를 비교한다.

합격 기준:

- 각 Windows artifact row가 source path, parser version, offset/table/key locator, confidence/limitation을 가진다.
- trusted tool과 불일치가 있으면 report-grade가 아니라 triage pivot으로 표시된다.

### 2.3 macOS collector

현재 대상:

- macos-system
- kakaotalk-macos
- 공통 browser/email/media/cloud/mobile collector와 같이 사용 가능

부족하거나 예상되는 문제:

- macOS 카카오톡은 사용자 동의/권한, sandbox container 경로, keychain/DB access 차이가 있다.
- APFS snapshot, unified logs, FSEvents, quarantine, TCC, Spotlight는 Windows급으로 깊게 파싱되지는 않는다.
- macOS에서 수집한 데이터를 Windows GUI에서 열 때 path normalization과 한글 파일명이 깨질 수 있다.

Windows 테스트:

- [ ] macOS export folder를 Windows RapidForensic에 넣고 macOS-system artifact가 유지되는지 확인한다.
- [ ] macOS KakaoTalk export/DB 샘플의 message/attachment metadata가 UI에서 깨지지 않는지 확인한다.
- [ ] Spotlight/Unified Log 등 미지원 항목이 “누락 없이 지원”처럼 보이지 않고 limitation으로 남는지 확인한다.

합격 기준:

- macOS 데이터도 검색/뷰어/리뷰로 이어진다.
- 미지원 macOS artifact는 명확히 gap으로 표시된다.

## 3. 추출 흐름

### 3.1 파일 후보 추출

현재 기능:

- documents, archives, databases, executables, emails, disk-images, mobile-images, memory-dumps, vehicle-images, images 등 10개 카테고리 후보를 추출 대상으로 삼을 수 있다.
- 전체 파일 후보 분류 확장자는 147개다.
- 추출 entry에는 original_path, extracted_path, relative_path, size, modified_at, sha256이 포함된다.

부족하거나 예상되는 문제:

- 대량 추출 시 같은 파일명 충돌, 긴 경로, 권한 오류, ADS, sparse file, reparse point를 확인해야 한다.
- Windows 파일 속성, Alternate Data Streams, Zone.Identifier를 추출 manifest에 어느 수준까지 보존하는지 확인해야 한다.
- read-only 모드에서 “추출 안 됨”이 사용자에게 충분히 명확한지 확인해야 한다.

Windows 테스트:

- [ ] files tab에서 documents, images, databases 카테고리를 각각 추출한다.
- [ ] `--max-file-count`, `--max-extract-size`, overwrite false/true를 확인한다.
- [ ] 같은 이름의 파일이 다른 경로에 있을 때 relative path가 충돌하지 않는지 확인한다.
- [ ] 한글 파일명, 260자 이상 path, 공백 path가 manifest와 UI에서 깨지지 않는지 확인한다.
- [ ] 추출한 파일 SHA256을 `Get-FileHash -Algorithm SHA256`과 비교한다.

합격 기준:

- 추출된 모든 파일에 SHA256이 있고 원본 경로가 보존된다.
- 실패/skip reason이 manifest와 UI에서 확인된다.

### 3.2 문서 추출

현재 기능:

- 문서 추출 kind는 24개다: cfg, conf, csv, docx, eml, htm, html, ini, json, jsonl, log, md, odp, ods, odt, pdf, pptx, rtf, tsv, txt, xlsx, xml, yaml, yml.

부족하거나 예상되는 문제:

- `.doc`, `.xls`, `.ppt`, `.docm`, `.xlsm`, `.pptm`은 파일 분류는 되지만 본문 추출/문서 추출 kind에서는 제한이 있다.
- password-protected Office/PDF는 실패/limitation을 명확히 보여야 한다.
- ZIP 기반 Office의 압축폭탄 방어와 member size cap을 Windows에서 검증해야 한다.

Windows 테스트:

- [ ] DOCX/XLSX/PPTX, PDF, RTF, ODT/ODS/ODP, EML을 각각 넣고 추출과 검색 결과가 일치하는지 확인한다.
- [ ] legacy DOC/XLS/PPT는 분류는 되는지, 본문 검색 제한이 표시되는지 확인한다.
- [ ] 암호화 PDF/Office를 넣고 실패가 조용히 누락되지 않는지 확인한다.

합격 기준:

- 지원 문서는 추출/검색/뷰어가 이어진다.
- 미지원/암호화 문서는 명확한 limitation으로 남는다.

## 4. 키워드 검색 흐름

### 4.1 전체 검색

현재 기능:

- completed run에서 documents, files, web, artifacts, timeline, indicators, OCR sidecar/engine 결과를 검색한다.
- exact, regex, fuzzy, simple suffix stemming, proximity summary를 지원한다.
- keyword packs를 선택할 수 있다.
- 문서 본문 검색 확장자는 28개다.
- OCR 이미지 확장자는 9개다: bmp, gif, heic, jpeg, jpg, png, tif, tiff, webp.

부족하거나 예상되는 문제:

- Lucene/Elastic 같은 외부 검색 엔진은 현재 production backend가 아니다. 현재는 local JSON/SQLite/FTS 중심으로 봐야 한다.
- 1000만 row급 검색은 별도 benchmark가 필요하다.
- fuzzy/stemming은 triage aid이며 보고서 증거는 source viewer에서 재확인해야 한다.
- OCR은 Tesseract/OpenCV/pytesseract 설치와 언어팩에 의존한다.

Windows 테스트:

- [ ] 전체 검색창에서 `password`, `invoice`, `powershell`, 한글 키워드를 각각 검색한다.
- [ ] source filter, extension filter, path contains filter가 동시에 적용되는지 확인한다.
- [ ] regex 검색에서 잘못된 regex가 400/error로 명확히 표시되는지 확인한다.
- [ ] fuzzy distance 0/1/2 결과 차이를 저장한다.
- [ ] OCR 포함/미포함 검색 결과 차이를 저장한다.
- [ ] 검색 결과 source_counts가 UI와 JSON에서 일치하는지 확인한다.

합격 기준:

- 검색 결과가 source viewer, current-file search, review 저장으로 이어진다.
- 검색 불가/부분 검색은 경고로 표시된다.

### 4.2 현재 파일 내부 검색

현재 기능:

- source viewer에서 현재 파일 내부 검색을 할 수 있다.
- SQLite는 table/row 기반 hit를 제공하고 row scan cap/resume state contract가 있다.
- 일반 텍스트/문서 추출 경로는 size cap과 압축 member cap을 둔다.

부족하거나 예상되는 문제:

- 매우 큰 SQLite는 default row scan limit에 걸릴 수 있으므로 searched rows, truncated state, resume state를 반드시 확인해야 한다.
- PDF/Office/EML/MBOX 대형 파일에서 timeout/cancel이 실제 UI에 잘 연결되는지 확인해야 한다.
- binary search는 hex/offset citation이 정확해야 한다.

Windows 테스트:

- [ ] 10만 row 이상 SQLite에서 5,001행 이후 키워드가 검색되는지 확인한다.
- [ ] row scan limit 도달 시 `truncated` 또는 resume state가 UI에 보이는지 확인한다.
- [ ] PDF/Office 대형 파일에서 메모리 급증 없이 실패/부분검색이 표시되는지 확인한다.
- [ ] 현재 파일 검색 hit를 review note로 저장하고 report 후보로 이어지는지 확인한다.

합격 기준:

- current-file hit는 table/row/line/offset citation을 가진다.
- “없음”과 “부분검색/제한”이 구분된다.

## 5. 뷰어/리뷰/보고서 연결

### 5.1 Source viewer

현재 viewer family:

- image gallery preview
- SQLite table preview
- JSON/JSONL/NDJSON structured preview
- XML structured preview
- EML/MBOX email thread preview
- audio/video media preview
- document text preview
- text/hex fallback preview
- OCR queue/review
- OCR/translation review

부족하거나 예상되는 문제:

- PST/OST full mailbox viewer는 아직 상용 도구 수준으로 보면 부족하다.
- media는 transcript sidecar 중심이며 자체 ASR/full video forensic 분석은 별도 검증이 필요하다.
- active content 차단은 있으나 실제 악성 HTML/SVG/Office macro corpus에서 sandbox 검증이 필요하다.
- 이미지/영상 첨부가 실제 카톡처럼 보이는 UX는 별도 대량 테스트가 필요하다.

Windows 테스트:

- [ ] TXT/PDF/DOCX/XLSX/JSON/XML/SQLite/EML/MBOX/image/video/audio를 각각 viewer에서 연다.
- [ ] 이미지 gallery 200개 이상에서 UI가 멈추지 않는지 확인한다.
- [ ] SQLite table pagination, WHERE contains, current-file search가 동작하는지 확인한다.
- [ ] 이메일 attachment export cap과 warning을 확인한다.
- [ ] media sidecar SRT/VTT/TXT가 cue로 연결되는지 확인한다.
- [ ] active content 파일 HTML/SVG/JS가 실행되지 않고 preview sandbox warning을 표시하는지 확인한다.

합격 기준:

- viewer에서 원본 파일 경로, hash, search URL, download URL, limitation이 확인된다.
- viewer에서 바로 Mark/Review/Compare/Report 후보 저장이 가능하다.

### 5.2 리뷰 워크플로우

현재 기능:

- bookmark/review board가 있다.
- relevant, excluded, include-in-report, tag/note 성격의 흐름이 있다.
- current-file hit를 review note로 저장할 수 있다.
- reviewer bundle, case report, submission manifest/export가 있다.

부족하거나 예상되는 문제:

- 단일 케이스 기준은 가능하지만 다중 사용자 assignment/RBAC는 목표 범위 밖이다.
- 되돌아가기, 비교 보기, 단축키가 대량 데이터에서 피로하지 않은지 실제 분석자 테스트가 필요하다.
- 보고서 항목마다 source locator completeness가 충분한지 검토해야 한다.

Windows 테스트:

- [ ] 검색 결과 10개를 relevant/excluded/needs-review로 나눠 저장한다.
- [ ] include-in-report만 case report에 들어가는지 확인한다.
- [ ] 동일 파일 내 hit 여러 개를 저장했을 때 citation이 겹치지 않는지 확인한다.
- [ ] reviewer bundle ZIP과 submission manifest hash를 검증한다.

합격 기준:

- 분석자가 본 근거와 보고서에 들어간 근거가 연결된다.
- report/export에는 source hash, parser version, locator, limitation이 남는다.

## 6. UI/UX 핵심 연결성

현재 기능:

- 시작 화면에 `분석`, `추출`, `검색` 3단계가 보인다.
- 완료 케이스 화면에도 같은 3단계 카드가 보이고 summary/files/search 탭으로 이동한다.
- feature catalog, artifact tree, central table, source viewer, review board, report 흐름이 있다.

부족하거나 예상되는 문제:

- 기능이 많아져서 “어디서 뭘 해야 하는지”가 여전히 복잡할 수 있다.
- 대량 데이터에서 좌측 tree, 중앙 table, 우측 preview/detail, 하단 evidence tray의 시각적 우선순위를 실제 사용자로 검증해야 한다.
- Windows 화면 배율 125%/150%, 작은 노트북 해상도, 한글 폰트에서 겹침 여부를 확인해야 한다.

Windows 테스트:

- [ ] 1920x1080, 1366x768, 150% scaling에서 화면 깨짐이 없는지 확인한다.
- [ ] E01 선택 후 사용자가 다음 행동을 묻지 않고 run을 시작할 수 있는지 관찰한다.
- [ ] 완료 후 3단계 카드만 보고 “분석/추출/검색 가능 여부”를 판단할 수 있는지 사용자에게 물어본다.
- [ ] 10만 row search 결과에서 table scroll, pagination, filter가 피로하지 않은지 확인한다.
- [ ] `Ctrl+K`, `Ctrl+F`, `Alt+R`, `Alt+X`, `Alt+I`, `[`, `]` 단축키가 충돌 없이 동작하는지 확인한다.

합격 기준:

- 사용자가 첫 화면에서 E01/폴더를 선택하고, 완료 후 검색/추출/리뷰로 자연스럽게 이동한다.
- UI가 기능을 숨기지 않고, 오류/제한을 과장 없이 보여준다.

## 7. Windows 실테스트 실행 순서

### Phase 0: 환경 기록

PowerShell:

```powershell
py -m rapidtriage doctor --json > qc\00-doctor.json
py -m rapidtriage sample --output-dir qc\sample --run --overwrite --json > qc\01-sample-run.json
```

확인:

- [ ] Python version
- [ ] FastAPI/Uvicorn import
- [ ] Tesseract 설치 여부
- [ ] E01 tools: ewfmount, mmls, tsk_recover
- [ ] qemu-img
- [ ] 7z/7zz/bsdtar
- [ ] web port conflict

### Phase 1: 샘플 케이스 smoke

```powershell
py -m rapidtriage search qc\sample\run-output -k password -k invoice --no-ocr --output qc\02-search.json
py -m rapidtriage extract qc\sample\run-output\rapidtriage-files.json qc\sample-extract --category documents --max-file-count 3 --manifest qc\03-extract-manifest.json
```

확인:

- [ ] search match count > 0
- [ ] source_counts에 documents/files/web/artifacts/timeline 중 여러 source가 보인다.
- [ ] extract manifest에 SHA256이 있다.
- [ ] web UI import 후 3단계 카드가 보인다.

### Phase 2: 실제 Windows 11 E01

```powershell
py -m rapidtriage evidence C:\Cases\Win11.E01 --json > qc\10-evidence-e01.json
py -m rapidtriage e01-smoke C:\Cases\Win11.E01 --output-dir C:\Cases\Win11-smoke --case-id WIN11-QC-001 > qc\11-e01-smoke.log
```

확인:

- [ ] support_level
- [ ] missing_tools
- [ ] selected partition start sector
- [ ] source image hash/profile
- [ ] extracted filesystem path
- [ ] downstream run summary
- [ ] report file

### Phase 3: 아티팩트 정확도 비교

권장 trusted tools:

- EVTX: EvtxECmd, Hayabusa
- Registry: RECmd, ShellBagsExplorer
- Prefetch: PECmd
- MFT/USN: MFTECmd, UsnJrnl2Csv
- SRUM/Windows.edb: SrumECmd, libesedb/esedbexport, WinSearchDBAnalyzer
- Browser: Hindsight 또는 NirSoft BrowsingHistoryView 계열
- Email: libpff/readpst, Outlook export

확인:

- [ ] RapidForensic row count와 trusted tool row count 차이를 기록한다.
- [ ] 누락 row, 추가 row, field mismatch를 CSV/JSON으로 남긴다.
- [ ] 불일치 artifact는 report-grade가 아닌 triage pivot으로 표시되는지 확인한다.

### Phase 4: 대량 데이터 성능

확인:

- [ ] 100k file 후보
- [ ] 1M file 후보
- [ ] 10M row SQLite/search fixture
- [ ] 10GB, 100GB, 1TB evidence run
- [ ] peak RSS
- [ ] elapsed time
- [ ] cancel/retry/resume
- [ ] UI scroll latency
- [ ] search p95 latency

합격 기준:

- 대량 run이 조용히 일부 누락하지 않는다.
- 제한에 걸릴 때 warning/resume/checkpoint가 남는다.

## 8. 우선적으로 보강해야 할 기능 리스트

1. 실제 Windows 11 E01 known-answer corpus를 확보하고 end-to-end 결과를 고정한다.
2. Windows native 또는 WSL2 E01 실행 가이드를 UI에서 더 분명히 표시한다.
3. EVTX를 EvtxECmd/Hayabusa와 record 단위 diff하는 검증 산출물을 만든다.
4. Registry를 RECmd/ShellBagsExplorer와 key/value/path 단위 diff한다.
5. MFT/USN을 MFTECmd/UsnJrnl2Csv와 대량 row 단위 diff한다.
6. Windows.edb/SRUM을 libesedb/SrumECmd/WinSearchDBAnalyzer와 비교한다.
7. Legacy Office `.doc/.xls/.ppt`는 분류만 되는 상태인지 본문 검색까지 되는지 UI limitation을 더 명확히 한다.
8. PST/OST는 full mailbox parser가 아니라 bounded/triage 수준이면 그 사실을 UI와 보고서에 강하게 표시한다.
9. AD1/L01/Lx01/AFF/AFF4는 탐지와 직접 분석을 UI에서 구분한다.
10. XVA, differencing disk, snapshot chain 제한을 evidence check에서 더 눈에 띄게 표시한다.
11. Korean OCR 정확도와 translation workflow를 실제 한글 이미지 corpus로 측정한다.
12. KakaoTalk Windows legacy/post-patch와 macOS DB를 별도 fixture로 회귀 테스트한다.
13. Source viewer에서 모든 report candidate가 source hash, offset/table/key/row locator를 갖는지 검사한다.
14. 10만~1000만 row 검색에서 truncation/resume 상태가 UI에 보이는지 검증한다.
15. Windows UI scaling 125%/150%에서 기능 카탈로그와 3단계 카드가 겹치지 않는지 확인한다.

## 9. Windows QC 결과 기록 템플릿

각 테스트마다 아래 항목을 남긴다.

```text
테스트 ID:
날짜/분석자:
Windows 버전:
RapidForensic commit:
입력 증거:
입력 크기:
명령 또는 UI 경로:
예상 결과:
실제 결과:
생성 output 경로:
row count:
hash 검증:
trusted tool 비교:
스크린샷:
로그 파일:
통과/실패:
실패 원인:
재현 방법:
수정 필요 여부:
```

## 10. 최종 판정 기준

상용급에 가깝다고 판단하려면 아래가 모두 필요하다.

- Windows 11 E01 한 개 이상에서 입력, 추출, 분석, 검색, 뷰어, 리뷰, 보고서가 end-to-end로 완료된다.
- 각 단계의 실패/제한이 조용히 숨겨지지 않는다.
- 주요 Windows artifact는 trusted tool과 row-level diff evidence가 있다.
- 추출 산출물은 SHA256과 원본 경로/provenance가 있다.
- 검색 결과는 source viewer에서 원본 재확인이 가능하다.
- 보고서 후보는 source hash, parser version, locator, limitation을 포함한다.
- 대량 데이터에서 truncation, pagination, resume, memory cap이 실제로 동작한다.
- Windows GUI에서 분석자가 세 가지 질문, 즉 “분석됐나, 추출되나, 검색되나”를 첫 화면과 완료 화면에서 바로 판단할 수 있다.
