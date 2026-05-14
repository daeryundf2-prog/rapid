# RapidForensic 한글 QC 체크리스트

최신화 기준: 2026-05-15  
목적: Windows/macOS 실제 테스트에서 “이미지 입력, 추출, 분석, 키워드 검색, 리뷰, 보고서”가 끊기지 않는지 확인한다.

## 1. QC 원칙

- 기능이 보인다고 통과가 아니다. 실제 입력, 실제 산출물, 실제 원본 근거 확인이 되어야 통과다.
- 검색 결과 0건은 무조건 통과가 아니다. `searched_rows`, `total_rows`, `truncated`, `resume_token`, extraction cap을 확인해야 한다.
- 상용급 판정은 내부 테스트만으로 하지 않는다. 실제 E01, trusted-tool diff, 독립 검증, 대형 성능 증거가 필요하다.
- 민감 키, 토큰, 패스워드, 복호 재료는 원문 로그에 남기지 않는다.
- QC 결과는 command, input hash, output path, expected, actual, pass/fail, screenshot, limitation을 남긴다.

## 2. 테스트 환경 기록

| 항목 | 기록 |
| --- | --- |
| QC 일시 | |
| 담당자 | |
| OS | |
| CPU/RAM | |
| 디스크 종류/여유공간 | |
| Python 버전 | |
| RapidForensic commit | |
| 브랜치 | |
| 설치 명령 | |
| GUI 주소 | |
| 테스트 evidence 이름 | |
| evidence hash | |
| 외부 도구 버전 | |

필수 명령:

```bash
git rev-parse HEAD
python --version
rapidtriage doctor --json
rapidtriage taxonomy-audit --strict --json
rapidtriage commercial-readiness --json
```

## 3. 설치 및 실행 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| SETUP-001 | macOS 설치 | README의 macOS 설치 명령 실행 | editable install 성공 | |
| SETUP-002 | Windows 설치 | README의 PowerShell 설치 명령 실행 | editable install 성공 | |
| SETUP-003 | GUI 실행 | `rapidtriage web --host 127.0.0.1 --port 8765` | 브라우저 접속 가능 | |
| SETUP-004 | launcher 실행 | `scripts/start-rapidtriage.sh` 또는 Windows ps1 실행 | GUI 자동 안내 표시 | |
| SETUP-005 | doctor | `rapidtriage doctor` | 필수 항목 pass, 선택 항목 warning 구분 | |
| SETUP-006 | web static | GUI 첫 화면 로드 | JS 오류 없음 | |
| SETUP-007 | dependency panel | GUI에서 의존성 확인 | missing tool이 기능별로 표시 | |

## 4. 증거 입력 QC

| ID | 입력 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| INPUT-001 | 일반 폴더 | 샘플 폴더 선택 후 run | manifest/files/docs/artifacts 생성 | |
| INPUT-002 | 마운트 이미지 | read-only mount root 선택 | source path와 input kind 표시 | |
| INPUT-003 | E01 | E01 선택 | dependency check, mount/export 안내, hash workflow 표시 | |
| INPUT-004 | Ex01 | Ex01 선택 | EWF 계열로 판정 | |
| INPUT-005 | RAW | `.dd` 또는 `.raw` 선택 | raw image adapter 판정 | |
| INPUT-006 | split image | split set 일부 누락 케이스 입력 | gap/missing segment warning | |
| INPUT-007 | VHD/VHDX | 가상 디스크 선택 | virtual disk workflow 표시 | |
| INPUT-008 | VMDK/VDI/QCOW | 가상 디스크 선택 | qemu-img 필요 여부 표시 | |
| INPUT-009 | ISO/DMG/WIM | archive image 선택 | archive image workflow 표시 | |
| INPUT-010 | ZIP | ZIP 선택 | bounded extraction/search profile 표시 | |
| INPUT-011 | 손상 파일 | corrupt archive/image 입력 | crash 없이 limitation/error row 기록 | |
| INPUT-012 | 암호화 볼륨 | BitLocker/FileVault/LUKS 후보 입력 | unlock 필요/미지원 상태 명확히 표시 | |

## 5. 추출 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| EXTRACT-001 | 파일 후보 추출 | `rapidtriage files` 후 `rapidtriage extract` | manifest와 복사 파일 수 일치 | |
| EXTRACT-002 | 문서 추출 | `rapidtriage docs` 후 extract | 문서별 text hit와 추출 manifest 생성 | |
| EXTRACT-003 | hash 기록 | 추출 산출물 확인 | source hash 또는 derived hash 기록 | |
| EXTRACT-004 | output contamination | evidence 내부 output 지정 | 경고 또는 차단 | |
| EXTRACT-005 | 대형 파일 | 1GB 이상 파일 후보 | chunk 처리, 메모리 폭증 없음 | |
| EXTRACT-006 | 압축폭탄 방어 | 큰 ZIP member fixture | cap hit와 warning 기록 | |
| EXTRACT-007 | resume | 중단 후 재시작 | 이미 완료된 stage 재사용 또는 명확한 재처리 | |

## 6. 파일 시스템 분석 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| FS-001 | manifest | 파일 수 known-answer 비교 | expected count 일치 | |
| FS-002 | hash | sha256 검증 | 외부 hash와 일치 | |
| FS-003 | category | 문서/실행/압축/미디어 분류 | 주요 확장자 분류 성공 | |
| FS-004 | signature mismatch | `.jpg`로 위장한 EXE | mismatch flag | |
| FS-005 | timestamp anomaly | SIA/FNA 불일치 fixture | anomaly flag | |
| FS-006 | Recycle Bin | `$I`/`$R` fixture | 원래 경로/삭제 시각 표시 | |
| FS-007 | MFT | MFT fixture | record count/path reconstruction 검증 | |
| FS-008 | USN | USN fixture | rename/delete replay 확인 | |
| FS-009 | LogFile | transaction fixture | 생성/이름변경/삭제 이벤트 표시 | |
| FS-010 | 대량 파일 | 100만 파일 synthetic | cursor/페이지/메모리 기준 통과 | |

## 7. Windows 아티팩트 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| WIN-001 | EVTX basic | Security/System/Application EVTX 입력 | 이벤트 row 생성 | |
| WIN-002 | EVTX message | provider manifest 가능 케이스 | rendered message 또는 unresolved warning | |
| WIN-003 | EVTX anti-forensic | 1102/104 이벤트 fixture | high-risk log clear 표시 | |
| WIN-004 | EVTX diff | EvtxECmd/Hayabusa 결과와 비교 | record 단위 차이 문서화 | |
| WIN-005 | Registry hive | NTUSER/SYSTEM/SOFTWARE/SAM 입력 | hive별 row 생성 | |
| WIN-006 | Registry transaction | LOG1/LOG2 fixture | replay 여부/미지원 warning 명확 | |
| WIN-007 | USB forensics | USBSTOR/setupapi fixture | 시리얼, vendor, drive letter, first/last seen | |
| WIN-008 | ShellBags | ShellBags fixture | path/bag relationship 표시 | |
| WIN-009 | RecentDocs | NTUSER fixture | 최근 문서 row 표시 | |
| WIN-010 | SAM/SECURITY | 계정 fixture | 계정/권한/alias membership | |
| WIN-011 | Prefetch | PF fixture | 실행 시간/volume/file metrics | |
| WIN-012 | LNK | LNK fixture | target, timestamps, tracker GUID | |
| WIN-013 | JumpList | automatic/custom destination | DestList row 표시 | |
| WIN-014 | Amcache | Amcache.hve fixture | execution/install semantics | |
| WIN-015 | ShimCache | OS version별 fixture | path/time, legal limitation | |
| WIN-016 | BAM/DAM | SYSTEM fixture | SID/path/timestamp | |
| WIN-017 | SRUM | SRUDB.dat fixture | table별 row 생성 | |
| WIN-018 | Windows.edb | ESE fixture | search/property/content row | |
| WIN-019 | Task/WMI | scheduler/WMI fixture | persistence 후보 표시 | |
| WIN-020 | Defender/Firewall | tampering fixture | exception/disable event 표시 | |

## 8. 브라우저/인터넷/AI QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| WEB-001 | Chrome history | profile 입력 | URL/title/time row | |
| WEB-002 | Edge history | profile 입력 | URL/title/time row | |
| WEB-003 | Firefox history | profile 입력 | URL/title/time row | |
| WEB-004 | Safari history | macOS profile 입력 | URL/title/time row | |
| WEB-005 | downloads | browser download DB | source/target/referrer 표시 | |
| WEB-006 | cache/session | cache/session fixture | 후보 row와 limitation | |
| WEB-007 | WebCacheV01 | ESE fixture | web communication row | |
| WEB-008 | incognito carving | pagefile/memory fixture | carved URL 후보와 confidence | |
| WEB-009 | AI web usage | ChatGPT/Claude/Gemini/Perplexity trace | service별 row | |
| WEB-010 | AI transcript | export fixture | 질문/답변 pairing | |
| WEB-011 | local LLM | Ollama/LM Studio fixture | model/prompt 후보 | |
| WEB-012 | Copilot/ChatGPT desktop | local DB fixture | app DB 후보 row | |

## 9. 문서/메일/DB 검색 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| DOC-001 | TXT 검색 | keyword fixture | hit 정확 | |
| DOC-002 | PDF 검색 | PDF fixture | hit와 stream cap 표시 | |
| DOC-003 | DOCX 검색 | DOCX fixture | XML member cap 표시 | |
| DOC-004 | XLSX/PPTX 검색 | Office fixture | sheet/slide text hit | |
| DOC-005 | EML | EML fixture | header/body/attachment metadata | |
| DOC-006 | MBOX | MBOX fixture | message count/hit | |
| DOC-007 | SQLite search | 10,001 row DB | 5,000 이후 hit도 resume으로 검색 | |
| DOC-008 | WAL/SHM | SQLite sidecar fixture | sidecar 표시 | |
| DOC-009 | PST/OST | mailbox export | workflow/limitation 명확 | |
| DOC-010 | Print Spooler | SPL/SHD fixture | document name/time/user 후보 | |
| DOC-011 | Sticky Notes | plum.sqlite fixture | note text row | |
| DOC-012 | macro risk | VBA 포함 문서 | macro risk flag | |

## 10. 메신저/모바일/클라우드 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| MSG-001 | KakaoTalk Windows legacy | legacy ZIP/folder | room/message preview | |
| MSG-002 | KakaoTalk Windows post-patch | post-patch fixture | DB 후보/키 필요 상태/성공 시 message | |
| MSG-003 | KakaoTalk macOS | macOS KakaoTalk data 후보 | DB 후보 탐지와 limitation | |
| MSG-004 | WhatsApp export | export fixture | chat/media row | |
| MSG-005 | Telegram export | export fixture | chat/media/account row | |
| MSG-006 | Signal | fixture | encrypted store warning/authority gate | |
| MSG-007 | LINE/Discord | export fixture | message/media row | |
| MOB-001 | iOS backup | Manifest.db fixture | domains/sms/media/app DB row | |
| MOB-002 | Android backup | sms/call/contact fixture | unified mobile view row | |
| MOB-003 | location | GPS/EXIF/app DB fixture | map marker candidate | |
| MOB-004 | health/screen time | export fixture | activity/app usage row | |
| CLOUD-001 | Google Takeout | sample export | Gmail/Drive/Photos/Activity row | |
| CLOUD-002 | iCloud export | sample export | Photos/album/share row | |
| CLOUD-003 | M365/Teams | eDiscovery export | message/attachment/permission row | |
| CLOUD-004 | AWS/Azure/GCP | audit log samples | cloud audit event row | |

## 11. 미디어/OCR/메모리/IR QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| MEDIA-001 | image gallery | 이미지 폴더 | thumbnail/list 로드 | |
| MEDIA-002 | EXIF GPS | GPS 이미지 | 좌표와 map marker 후보 | |
| MEDIA-003 | OCR queue | 이미지/PDF OCR 후보 | queue/retry/log 표시 | |
| MEDIA-004 | video/audio | media fixture | preview/transcript workflow 표시 | |
| MEDIA-005 | stego/deepfake | 의심 fixture | suspicion profile row | |
| MEM-001 | pagefile URL | pagefile fixture | URL carving hit | |
| MEM-002 | hiberfil | hiberfil fixture | 처리 가능/미지원 warning | |
| MEM-003 | memory dump | RAW memory fixture | import/carving workflow | |
| IR-001 | remote access | AnyDesk/TeamViewer/RustDesk logs | 접속 시간/IP/user row | |
| IR-002 | Defender tampering | event/registry fixture | tamper warning | |
| IR-003 | YARA/IOC | rule/hash list | match row와 source citation | |
| IR-004 | WebShell | webroot fixture | suspicious script row | |

## 12. 검색 UX QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| SEARCH-001 | 전체 검색 | known keyword 검색 | 모든 source type에서 hit | |
| SEARCH-002 | 현재 파일 검색 | source viewer에서 keyword | current file hit 표시 | |
| SEARCH-003 | 부분 검색 경고 | cap hit fixture | truncated/resume 표시 | |
| SEARCH-004 | SQLite cursor | 10k+ row DB | resume 후 누락 hit 발견 | |
| SEARCH-005 | regex/fuzzy/proximity | query fixture | mode별 결과/제한 표시 | |
| SEARCH-006 | keyword pack | pack import | pack version과 hit 표시 | |
| SEARCH-007 | zero result | 없는 keyword | searched scope 명확 표시 | |
| SEARCH-008 | 대량 결과 | 100k+ hit | UI freeze 없음 | |

## 13. 리뷰/보고서 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| REVIEW-001 | 상태 변경 | relevant/needs-review/excluded | case DB 반영 | |
| REVIEW-002 | note/tag | row에 note/tag 추가 | 저장/재조회 가능 | |
| REVIEW-003 | include-in-report | 보고서 포함 체크 | report candidate 포함 | |
| REVIEW-004 | evidence tray | 여러 row 선택 | tray count/source 유지 | |
| REVIEW-005 | source citation | source viewer에서 citation 생성 | path/hash/parser/offset 포함 | |
| REVIEW-006 | compare | A/B 또는 3-pane 비교 | 두 항목 오가며 비교 가능 | |
| REPORT-001 | report candidate | case-db-report 실행 | JSON 생성 | |
| REPORT-002 | submission bundle | bundle 실행 | manifest/hash 포함 | |
| REPORT-003 | limitation | 검증대기 artifact 포함 | limitation 문구 포함 | |
| REPORT-004 | reproducibility | 같은 입력 두 번 실행 | deterministic output 비교 | |

## 14. GUI 사용성 QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| GUI-001 | artifact tree | 좌측 tree 확인 | 기능 그룹이 분석관 언어로 노출 | |
| GUI-002 | result table | 10만 row mock | 스크롤/필터 freeze 없음 | |
| GUI-003 | preview panel | 이미지/문서/DB row 클릭 | 적절한 viewer 열림 | |
| GUI-004 | metadata 접기 | detail panel | 긴 metadata 접기/펴기 가능 | |
| GUI-005 | keyboard shortcut | next/prev/tag/search | 반복 리뷰 가능 | |
| GUI-006 | progress | run 실행 | stage/progress/cancel 표시 | |
| GUI-007 | failure UX | parser 실패 fixture | 실패 근거와 다음 행동 표시 | |
| GUI-008 | readiness panel | readiness API | usable/validated/commercial 분리 | |
| GUI-009 | Korean readability | 한글 row/본문 | 깨짐 없음, 너무 작은 글씨 없음 | |
| GUI-010 | dark/light contrast | 주요 패널 | WCAG 수준 가독성 | |

## 15. 대용량/성능 QC

| ID | 항목 | 목표 | 결과 |
| --- | --- | --- | --- |
| PERF-001 | 100k row table | GUI interaction p95 1초 이하 목표 | |
| PERF-002 | 1M row case DB | cursor search 정상 | |
| PERF-003 | 10M row synthetic | 메모리 cap/시간 기록 | |
| PERF-004 | 대형 SQLite | table scan resume 가능 | |
| PERF-005 | 대형 PDF | stream cap으로 DoS 방어 | |
| PERF-006 | 대형 ZIP | member/total cap 방어 | |
| PERF-007 | hash cache | 재실행 시 stage reuse | |
| PERF-008 | cancel/retry | long job 중단/재시도 | |
| PERF-009 | parser crash | subprocess 실패 격리 | |
| PERF-010 | output cleanup | partial output 표시/정리 | |

## 16. 보안/QC

| ID | 항목 | 절차 | 통과 기준 | 결과 |
| --- | --- | --- | --- | --- |
| SEC-001 | token header | API 인증 | query token 제한/경고 | |
| SEC-002 | secret redaction | key/token fixture | raw secret 미노출 | |
| SEC-003 | path traversal | archive fixture | output root 밖 쓰기 차단 | |
| SEC-004 | active content | HTML/Office preview | 실행하지 않음 | |
| SEC-005 | malicious file | parser crash fixture | sandbox/격리/오류 기록 | |
| SEC-006 | audit log | review/report action | action 기록 | |
| SEC-007 | dependency scan | CI 또는 local scan | advisory 기록 | |
| SEC-008 | SBOM | release build | SBOM 생성 또는 blocker 기록 | |

## 17. 최종 판정표

| 등급 | 조건 |
| --- | --- |
| Fail | 설치 불가, GUI 실행 불가, 기본 scan 불가 |
| Partial | scan/search는 되나 source viewer/review/report 연결이 끊김 |
| Usable | 단일 케이스에서 입력, 분석, 검색, 리뷰, 보고서 후보가 이어짐 |
| Validated | known-answer fixture와 핵심 regression test가 있음 |
| Commercial-ready candidate | 실제 E01, 대형 데이터, trusted-tool diff, 독립 검증, 보안 검토 증거가 붙음 |

## 18. QC 결과 기록 템플릿

```text
QC ID:
환경:
입력:
입력 hash:
명령/화면:
예상:
실제:
결과: PASS / PARTIAL / FAIL / BLOCKED
산출물 경로:
스크린샷:
로그:
제한사항:
다음 조치:
```

## 19. 릴리스 전 최소 통과 기준

- `rapidtriage doctor` 필수 항목 통과
- GUI 실행 및 샘플 케이스 분석 통과
- taxonomy-audit 51/51 covered
- source-search cap/truncation UX 확인
- case DB 검색/리뷰/report candidate 통과
- Windows E01 또는 E01-derived export 1건 end-to-end 통과
- macOS 폴더/마운트 케이스 1건 end-to-end 통과
- commercial readiness가 상용급 claim을 과장하지 않음
- README, 기능 명세서, QC checklist 최신 commit 기준과 일치
