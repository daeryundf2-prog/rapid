# R6 — 동등 달성 이후 후속 라운드: 실데이터 재검증 · 국내 사건 연기 기능 · 성능 · 검증 갭 (2026-10-19)

근거: `docs/plans/axiom-parity-roadmap-2026-10-17.md`(R1–R5 완료, §4 재검증 의무), `docs/plans/r5-residual-2026-10-18.md` §5(미확인·연기 목록), `docs/research/axiom-parity-matrix-2026-10-17.md`(있음 120 중 15행 실샘플 미검증), `docs/rapidtriage-known-limitations.md`의 `## R5 L1/L2/L3`, "R5 적대적 리뷰 후속 수정", "공개 미지원 (AXIOM 대비)"의 연기 표, "정책 제외". 브랜치 `feat/r6-followups`(main `02a59a4`).

사용자 결정(2026-10-19): 네 단계를 **순서대로** 진행한다. 단계마다 PR 하나, "머지해라"에만 병합.

| 단계 | 내용 | PR |
|---|---|---|
| 1 | 실데이터 재실행 + 15개 "실샘플 미검증" 파서 검증(국내 형식 우선) | `feat/r6-s1-realdata-validation` |
| 2 | 국내 사건 연기 기능(AhnLab V3, adb 백업 내부 DB, `$Boot` 추출, 이미지 미할당 URL 카빙, 소형 항목) | `feat/r6-s2-korean-deferred` |
| 3 | 성능(타임라인 조건 첫 페이지, `/files` 조건 페이징, 전체 아티팩트 지도 보기) | `feat/r6-s3-performance` |
| 4 | 검증 갭(A등급 규칙 실데이터·공개 데이터셋 검증, Windows T1 운영자 입력 정리) | `feat/r6-s4-validation-gaps` |

## 0. 공통 절차·제약(모든 단계에 적용)

- 절차: 이상 상태 → 갭 → 설계(갈래·파일 소유 분리) → QA 시나리오 표(타협 없음) → **Opus 구현**(워크트리 병렬) → **Sonnet 워커**(테스트 실행·실데이터 런·측정) → 적대적 리뷰(백/프런트) → 수정 → 게이트 → PR → "머지해라".
- 게이트(AGENTS.md): `python -m unittest discover -s tests`, `python -m ruff check rapidtriage tests scripts`, `python -m vulture rapidtriage tests scripts --min-confidence 80`, `python -m compileall -q rapidtriage tests scripts`, `python scripts/check-doc-refs.py`, OpenAPI 스냅샷(`scripts/update-api-snapshot.py` ↔ `tests/fixtures/api_openapi_snapshot.json`; 라우트·옵션 변경 시 갱신 diff를 PR에 첨부), `frontend`: `npm run typecheck`·`npm test`·`npm run lint`·`npm run check:contrast`·`npm run e2e`, `git diff --check`.
- 긴 테스트(전체 unittest 30–70분, Playwright 5–10분, 실데이터 런)는 `D:\rapid-qa\agy\README.md` 프로토콜로 Antigravity에 위임한다: 요청 파일 `D:\rapid-qa\agy\requests\NNN-<이름>.md`(대상 커밋 명시), 결과 `results\NNN-<이름>.md`.
- 증거 폴더는 읽기 전용: `D:\rapid-qa\bsh-subset`(19,029파일, 4.9 GB, attrib +R·icacls deny W), `D:\devin\bsh-e01\BSH.E01~E17`. 모든 출력은 `D:\rapid-qa\derived\r6-*`. 실데이터·PII·비밀 값·실제 표본 파일은 Git에 넣지 않는다(합성 픽스처만; 실표본은 "확인 결과"를 문서 문장으로만 남긴다).
- **이 기계의 사용자 프로필(`C:\Users\HP`)은 표본으로 수집하지 않는다**(PII). 실표본은 §1.4의 세 경로로만 확보한다.
- 정책 제외 유지: 자격 증명 복호·크래킹·원격 수집·제품 안에서 외부 프로그램 실행 없음. 단계 2의 `$Boot`·미할당 추출은 "증거 처리 단계의 선언된 도구 체인"(Sleuth Kit) 또는 순수 Python 경로만 쓴다.
- 공유 파일(`artifacts/__init__.py`, `core/artifact_domains.py`, `frontend/src/features/tree/domains.ts`, `known-limitations.md`, 카탈로그 YAML)은 갈래별 블록에 **추가만** 하고 코디네이터가 병합한다.
- 각 단계 완료 시 `docs/rapidtriage-known-limitations.md`에 `## R6 S<n>` 절과 이 문서 §"결과 기록"을 채운다. 매트릭스 Table A의 "실샘플 미검증" 표시는 단계 1 결과로 갱신한다.

---

## 1. 단계 1 — 실데이터 재실행 + 미검증 파서 검증

### 1.1 목표
1. main(`02a59a4`, R1–R5 포함)으로 `D:\rapid-qa\bsh-subset`을 다시 돌려 기준 런 `run-subset10`(런 ID `b5fabbe09f18`, 2026-10-15, 모드 `hacking`, 아티팩트 640,712행·타임라인 323,543 이벤트·파일 후보 4,935)과 비교한다. R2–R5에서 추가된 공급자(`windows-messenger`·`cloud-sync`·`email-clients`·`windows-phone-link`·`media-player`·`p2p`)의 행 수·오류·시간을 적고, 기존 kind의 행 수 회귀를 잡는다.
2. "실샘플 미검증" 15행(360 Safe Browser, Android Backups, Chromium 추가 루트, EGG, eMule, Facebook Messenger, Limewire/Frostwire, McAfee Logs, Office Backstage, Photoshop, Potential Browser Activity 오탐률, Viber, VLC, Windows Mail, Your Phone)과 국내 확장(EGG/ALZ, 팟플레이어, 곰플레이어, KMPlayer)을 실제 표본으로 검증하고, 미확인 세부(곰 식별자 해시, 팟플레이어·KMPlayer 값 이름, EGG LZMA 블록 배치)를 확정한다.

### 1.2 현재 상태(근거)
- 기준 런: `D:\rapid-qa\derived\run-subset10\rapidtriage-run-summary.json` `summary.provider_artifact_counts`(eventlog 294,456 · registry 251,138 · prefetch 70,946 · browser 8,681 · recent-files 5,692 · execution 4,492 · shellbags 1,386 · generic-documents 1,256 · media-image 1,007 · windows-system 865 · synthetic-media 513 · kakaotalk-windows 149 · filesystem 101 · os-account 22 · memory 6 · remote-access 2, 그 외 0). 당시 프로필 `artifacts_kinds`는 24종이라 R2–R5 kind는 **이 런에 없다**.
- 현재 `hacking` 모드(`rapidtriage/core/run/constants.py` `GENERAL_FORENSIC_ARTIFACT_KINDS`+`WINDOWS_FORENSIC_ARTIFACT_KINDS`+크로스 플랫폼)는 29 kind를 돌린다. **`p2p` kind는 어느 모드에도 없다**(`core/run/profiles.py` 주석 "p2p stays out with browser"는 `recovery` 모드 설명이며, `hacking`의 GENERAL 목록에도 빠져 있다) → `rapidtriage run`으로는 P2P 행이 절대 나오지 않는 결함. 단계 1에서 `GENERAL_FORENSIC_ARTIFACT_KINDS`에 `"p2p"`를 추가한다(코드 변경은 이 한 줄 + 테스트).
- R5 갈래별 실데이터는 공급자 단위 스크립트로만 쟀다(`D:\rapid-qa\derived\r5-l1-realdata`, `r5-l2-realdata\r5-l2-report.json`, `r5-l3-realdata\report.json`). 전체 `run` 재실행은 R5 이후 없다.
- 파서 검증 상태(코드 근거): `artifacts/windows/media_players.py`(`PlayerSpec.verification="unconfirmed"`, 경로형 값 스캔, 곰 `_RECENTMEDIANAME###`을 `location_kind: hash-only`), `core/egg_archive.py` `_lzma_block`(4바이트 접두 + 5바이트 속성 **추정**), `artifacts/p2p.py` `part_met_rows`(버전 0xE0/0xE2/0x0E/0x0F만, 0xE1은 오류 행), `artifacts/windows/phone_link.py`(표·열 별칭 매핑, `timestamp_encoding` 추정), `artifacts/windows/messenger.py` Viber(`viber_direction_raw` 보존)·Facebook(`schema_confidence: best-effort-msys`), `artifacts/email_clients.py` Windows 메일 `store.vol`(ESE 표 목록만), `artifacts/mobile/adb_backup.py`(합성 `.ab`만), `artifacts/windows/system_extras.py` McAfee(`field_extraction` 휴리스틱)·Backstage(`heuristic-keys`), `artifacts/windows/browser.py` Chromium 추가 루트(360·Yandex·CocCoc·QQ), `core/url_carving.py`(오탐률 미측정).
- 도구: 이 호스트에 Sleuth Kit(`mmls`·`icat`·`fls`·`blkls`)이 PATH에 없다. Python에는 `pyewf`·`pytsk3`·`dissect.ntfs`가 있다(`D:\rapid-qa\README-bsh-subset.txt` §4). 전체 이미지의 `$MFT` 덤프가 `D:\devin\bsh-e01\bsh-mft.bin`(1.46 GB)에 있다.

### 1.3 설계

#### 갈래 A — 재실행·비교 도구(파일 소유: `scripts/compare-runs.py`(신규), `tests/test_compare_runs.py`(신규), `core/run/constants.py`(p2p 한 줄))
- 재실행 명령(Antigravity 위임, 대상 커밋 = 단계 1 브랜치 HEAD):
  `python -m rapidtriage run D:\rapid-qa\bsh-subset --mode hacking --output-dir D:\rapid-qa\derived\r6-s1-run --read-only` (기준과 같은 모드·옵션; `--extract` 없음). 로그 `D:\rapid-qa\derived\r6-s1-run.log`.
- `scripts/compare-runs.py --baseline <run-subset10> --candidate <r6-s1-run> --json --output <report.json>`: 두 런의 `rapidtriage-run-summary.json`·`artifacts/*.json`·`rapidtriage-parser-scheduler.json`·`rapidtriage-run-progress.json`을 읽어 kind별 행 수·`artifact_type_counts`·공급자 오류(`parser_errors`·`collection_notes`)·단계 소요(progress `completed_stages` 시각 차)·타임라인 이벤트 수·파일 후보 수·지표 수를 표로 낸다. 판정: 기존 kind의 artifact_type별 행 수 변화는 **0**이어야 하고(허용 예외: 새 artifact_type 추가, R5 L3에서 확인한 `browser-analytics-cookie` 197행, 이벤트 채널 재분류처럼 합계가 같은 이동), 변화가 있으면 artifact_type·차이·표본 경로 5개를 보고한다. 새 kind는 행 수·시간·오류를 따로 표에 둔다. 표준 라이브러리만.
- 소요 비교: 기준 런 단계 시각은 `rapidtriage-run-progress.json`(prepare 11:54 → artifacts 12:15 → docs 12:22 → files 12:27 → timeline 12:28 → 완료 12:36, 약 42분). 새 런은 같은 기계에서 ±20% 안이어야 하고, 새 공급자 합계가 60 s를 넘지 않아야 한다(R5 Q-R5-5 연장).

#### 갈래 B — 표본 검증 하네스(파일 소유: `scripts/sample-check.py`(신규), `docs/validation/r6-sample-validation-2026-10-19.md`(신규), 파서 수정은 §1.6 확인 결과에 따라 갈래 C로)
- `python scripts/sample-check.py --parser <id> --input <표본 경로 또는 폴더> --expect <known-answer.json> --json`: 공급자 하나를 표본 폴더에 직접 돌려(`artifacts` CLI와 같은 `collect`) 행을 known-answer와 필드 단위로 대조한다. known-answer 파일은 표본을 만든 사람이 적는다(§1.5 수용 기준의 필드). 표본·known-answer는 `D:\rapid-qa\samples\<parser>\`(Git 밖)에 두고, 보고서에는 **행 수·필드 일치 여부·불일치 필드 이름**만 적는다(값·경로·PII 금지).
- 파서 ID: `media-player`(potplayer·gom·kmplayer·vlc), `egg`, `alz`, `p2p`(emule·qbittorrent·utorrent·frostwire), `windows-phone-link`, `windows-messenger`(viber·facebook), `email-clients`(windows-mail), `mobile-export`(adb), `url-carve`, `browser`(360·qq·yandex), `windows-system`(mcafee·backstage), `media-image`(psd).

#### 갈래 C — 확인 결과 반영(파일 소유: 해당 파서 모듈 + 그 테스트 + `known-limitations` R6 S1 절)
- 확정된 값 이름·배치는 `verification: confirmed`/`coverage_status: mapped`로 올리고 합성 픽스처를 실제 배치로 갱신(값은 가짜). 미확정은 그대로 두고 사유를 적는다.

### 1.4 실표본 확보 계획(합법 경로 3가지)

| 경로 | 내용 | 사용자 조치 |
|---|---|---|
| (a) 사용자 제공 | 사건과 무관한 본인·동의 받은 기기의 파일, 또는 사무실 테스트 PC 산출물. `D:\rapid-qa\samples\<parser>\`에 두고 known-answer를 함께 적는다 | **필요**: 제공 여부·출처 확인 |
| (b) 일회용 VM에서 실제 앱 생성 | VMware Workstation이 이 호스트에 있다(PATH에 `VMware Workstation\bin`). 새 Windows 11 평가판 VM(스냅샷 1개, 네트워크 NAT, 작업 후 폐기)에 앱을 설치·실행해 가짜 콘텐츠로 흔적을 만든 뒤 VM 안에서 `%APPDATA%`·`%LOCALAPPDATA%`·`NTUSER.DAT`(`reg save HKCU`)·`ProgramData`를 복사해 호스트 `D:\rapid-qa\samples\`로 옮긴다. 설치·실행은 **사용자 승인 후 사용자가 수행**하거나 승인된 범위에서 에이전트가 VM 안에서만 한다(호스트 프로필 접근 금지) | **필요**: VM 생성·앱 설치 승인, 라이선스 확인(평가판·무료 앱만) |
| (c) 공개 코퍼스 | 아래 표. 다운로드는 파일명·출처·크기를 적고 승인 후 `D:\rapid-qa\corpora\<name>\`(새 빈 폴더, Git 밖)에 둔다 | **필요**: 다운로드 승인(용량 큼) |

형식별 후보(우선순위: 국내 형식 먼저):

| 형식/파서 | (b) VM 생성 | (c) 공개 코퍼스 후보 | 비고 |
|---|---|---|---|
| EGG/ALZ(`core/egg_archive.py`) | 알집(ESTsoft, 개인 무료) 설치 → 저장·Deflate·bzip2·**LZMA**·AZO·솔리드·암호(ZIP2.0·AES-256·LEA)·분할 각 1개 생성. 작은 텍스트·PNG 가짜 파일로 | 공개 EGG 표본 거의 없음(`unegg`/`libarchive` 테스트 픽스처는 LZMA 블록 포함 여부 확인 필요) | **최우선**. LZMA 배치 확정은 (b)로만 가능 |
| 팟플레이어(`media_players.py`) | 팟플레이어 설치 → 로컬 파일 3개·URL 1개 재생, 재생 위치 중간에 종료 → `NTUSER.DAT` `Software\DAUM\PotPlayerMini64`·`%APPDATA%\PotPlayer*\*.ini`·`.dpl` | 없음 | 값 이름 미확인(웹 검색 2026-10-19로도 공개 문서 없음) → (b) 필수 |
| 곰플레이어 | 곰플레이어 설치 → 파일 재생 후 `Software\GRETECH\GomPlayer` 수집. 재생한 파일의 경로·크기·내용 해시(MD5/SHA-1/CRC32, 경로 문자열 해시 cp949/UTF-16)를 known-answer로 두어 `_RECENTMEDIANAME###` 32자리 값과 대조 | 없음 | bsh-subset에 실제 값 1건 있음(서브셋 NTUSER) — 해시 알고리즘 후보 대조는 그 값으로도 가능하나 원본 경로를 모르므로 (b)에서 확정 |
| KMPlayer | KMPlayer 설치 → `Software\KMPlayer`·`PandoraTV` 수집 | 없음 | (b) |
| Phone Link(`phone_link.py`) | Windows 11 VM + 테스트 Android 기기 연결(사용자 기기 사용 시 PII) | 없음 | **(a)만 권장**: 사용자가 테스트 기기를 쓸 수 있을 때. 아니면 "미검증" 유지 |
| VLC | VLC 설치 → 3개 재생 → `vlc-qt-interface.ini` | VLC 소스 문서 있음(이미 참조) | (b) 쉬움 |
| eMule(`p2p.py`) | eMule 설치, 검색어 입력·다운로드 시작 후 즉시 중단(실제 다운로드 완료 금지) → `known.met`·`*.part.met`(0xE0·**0xE1**·0xE2)·`AC_SearchStrings.dat`·`preferences.ini` | `sepinf-inc/IPED` 테스트 리소스(known.met 등), eMule GitHub 소스 `PartFile.cpp`의 `PARTFILE_VERSION*` 상수로 0xE1 레이아웃 확정 | 0xE1은 소스 확인 → 구현(단계 2) |
| qBittorrent·µTorrent·FrostWire | 설치 후 공개 도메인(예: Ubuntu ISO) 토렌트 추가·즉시 일시정지 → `BT_backup`·`resume.dat` | IPED 테스트 리소스 | 저작권 없는 토렌트만 |
| Viber PC | VM에 설치 시 전화번호 필요 | 없음 | (a) 또는 미검증 유지(방향 값 가정 명시) |
| Facebook Messenger 데스크톱 | 2025-12 종료 | 없음 | **미검증 유지**(known-limitations 그대로) |
| Windows 메일 `store.vol` | Windows 10 VM(메일 앱 지원 종료 전 빌드)에서 테스트 계정 | 없음 | (b) 가능하면, 아니면 유지 |
| adb 백업(`.ab`) | Android 에뮬레이터(Android Studio) 또는 테스트 기기에서 `adb backup -apk -shared -all` 가짜 계정 | digitalcorpora.org 모바일 이미지에 `.ab` 포함 여부 확인 필요 | 단계 2 내부 DB 작업의 입력이기도 함 |
| URL 카빙 오탐률 | VM의 `pagefile.sys` 복사(VM 안에서 브라우징한 URL 목록을 known-answer로) | **NIST CFReDS**(cfreds.nist.gov) 해킹 케이스·`digitalcorpora.org` `nps-2009-domexusers`(Windows XP, 브라우징 흔적 공개 문서 있음), `m57-patents`(2009, 여러 PC) | 측정: 후보 중 브라우저 기록·known-answer에 없는 URL 비율 |
| 360·QQ·Yandex 브라우저 루트 | VM 설치(중국 앱은 라이선스·네트워크 정책 확인) | 없음 | 경로만 확인하면 됨, 저우선 |
| McAfee 로그 | McAfee ENS 평가판 + EICAR 파일 탐지 | 없음 | 평가판 약관 확인 |
| Office Backstage JSON | Office 365 평가판 VM에서 파일 열기 → `BackstageInAppNavCache` | 없음 | 사용자 Office 라이선스 필요 |
| Photoshop PSD | 무료 도구(GIMP 내보내기, Krita)로 PSD 생성 — XMP 이력은 Photoshop만 | Adobe 공개 PSD 샘플·`psd-tools` 테스트 픽스처(GitHub) | (c)로 충분 |
| bsh 전체 이미지(`D:\devin\bsh-e01`) | — | 읽기 전용 실사건 이미지. 서브셋에 없는 앱 폴더가 전체 이미지에는 있을 수 있음(단계 2의 `$Boot`·미할당 작업에서 함께 확인) | 사용자 승인 하에 읽기만 |

권고: (b) VM 경로를 기본으로 하고(한 VM에서 알집·팟·곰·KMPlayer·VLC·eMule·qBittorrent·GIMP를 한 번에), Phone Link·Viber·Facebook·Office·McAfee는 사용자 제공이 없으면 "미검증" 상태를 유지한다. 공개 코퍼스는 URL 카빙 오탐률과 단계 4에만 쓴다.

### 1.5 파서별 수용 기준(필드 단위)

| 파서 | known-answer 항목 | 통과 기준 |
|---|---|---|
| EGG | 항목별 이름(cp949·UTF-8 혼합)·크기·압축 방식·CRC·수정 시각; LZMA·AZO·암호·솔리드·분할 각 1 | 목록 100% 일치, 비암호·비솔리드 저장/Deflate/bzip2/LZMA 항목 SHA-256 일치, AZO·암호·솔리드는 `decompress-skipped` 사유, 폭탄 상한 유지 |
| ALZ | 항목 이름·크기·DOS 시각 | 100% 일치 |
| 팟플레이어 | 재생 파일 경로 3·URL 1·마지막 위치·재생 순서 | 값 이름 확정 → `verification: confirmed`, 경로 4/4·위치 단위(ms/s) 확정; 설정 경로가 재생 기록으로 잘못 잡히지 않음 |
| 곰플레이어 | 재생 파일 경로·크기·해시 여러 종 | `_RECENTMEDIANAME###` = 후보 해시 중 하나와 일치(알고리즘 확정) 또는 "확인 불가" 명시; `_RECENTMEDIAPOS###` 단위 확정 |
| KMPlayer | 재생 파일 경로 | 값 이름 확정 또는 미확인 유지 |
| VLC | 목록·`times=` | 100% |
| eMule | known.met 파일명·크기·해시·전송량, part.met(3 버전) 이름·다운로드량, 검색어 목록 | 100%; 0xE1은 단계 2에서 구현 후 재검 |
| qBittorrent/µTorrent/FrostWire | 토렌트 이름·info-hash·추가 시각·저장 경로·상태 | 100% |
| adb 백업 | 패키지 수·구성원 수·SQLite 항목 수 | 100% |
| URL 카빙 | 기대 URL 목록 ≥ 20 | 재현율 ≥ 90%, 오탐률(기록·known-answer 밖 URL 비율) 측정값 기록(기준 없음, 문서화) |
| Phone Link·Viber·Facebook·Windows 메일·McAfee·Backstage·360/QQ/Yandex·PSD | 표본이 있을 때만: 메시지 수·방향·시각 단위 / 탐지 줄 수·위협명 / 항목 수 / 프로필 경로 / XMP 필드 | 100% 또는 "미검증 유지" |

미확인 세부의 해소 방법: 곰 식별자 → known-answer 해시 대조 스크립트(`scripts/sample-check.py --probe-hash`, MD5/SHA-1/SHA-256/CRC32 × 경로(cp949·UTF-16LE·소문자)·파일 내용 앞 N바이트); 팟·KM 값 이름 → VM 표본의 키·값 덤프(`reg export`) 전후 diff; EGG LZMA → 실제 블록 바이트를 `_lzma_block` 추정과 대조, 틀리면 ESTsoft 명세의 블록 헤더 재해석.

### 1.6 QA 시나리오

| # | 시나리오 | 기준 |
|---|---|---|
| Q-S1-1 | 전체 재실행(`hacking`, read-only) | 종료 코드 0, `parser_errors` 0, 30 kind 모두 `completed`, 소요 ≤ 기준 ×1.2 |
| Q-S1-2 | 기존 kind 회귀 | artifact_type별 행 수 변화 0(허용 예외 목록 외 변화는 사유 규명 후 수정 또는 문서화) |
| Q-S1-3 | 새 kind | windows-messenger·cloud-sync·email-clients·windows-phone-link·media-player·p2p 행 수·시간·오류 표; 합계 ≤ 60 s, 오류 0 |
| Q-S1-4 | `p2p` 모드 포함 | `run --mode hacking`에 `artifacts_p2p` 출력 존재, 단위 테스트가 모드별 kind 목록에 p2p를 단언 |
| Q-S1-5 | 비교 도구 | 합성 두 런(동일·행 수 차이·새 유형)에서 판정이 맞음, 표준 라이브러리만, 읽기 전용 |
| Q-S1-6 | 표본 검증 | §1.5 기준표의 각 행 통과 또는 "미검증 유지" 명시; 표본·값 Git 미포함(`git status` 확인, 테스트가 `D:\rapid-qa` 경로 참조 없음) |
| Q-S1-7 | 파서 수정 회귀 | 수정한 파서의 합성 픽스처 테스트 + 손상 입력 격리 유지, 비밀 비추출 단언 유지 |
| Q-S1-8 | 게이트 | §0 전체 통과, 적대적 리뷰 미해결 0 |

### 1.7 사용자 조치 필요
1. 표본 제공 여부와 출처 확인(Phone Link·Viber·Office·McAfee는 제공 없으면 미검증 유지).
2. 일회용 VM 생성·앱 설치(알집·팟플레이어·곰플레이어·KMPlayer·VLC·eMule·qBittorrent·GIMP) 승인과 라이선스 확인.
3. 공개 코퍼스 다운로드 승인(CFReDS·digitalcorpora `nps-2009-domexusers`, 수 GB).
4. 전체 재실행(약 45분)과 전체 unittest의 Antigravity 위임 실행.

### 1.8 완료 기준·규모
- Q-S1-1~8 충족, `docs/validation/r6-sample-validation-2026-10-19.md`에 파서별 결과표, 매트릭스 Table A "실샘플 미검증" 표시 갱신, known-limitations `## R6 S1`.
- 규모: 코드 소(`compare-runs.py`·`sample-check.py` 각 300줄 내외, p2p 한 줄, 파서 수정은 확인 결과에 따라 0–4 모듈), 실행 시간 대(런 45분 + 표본 생성 반나절).

---

## 2. 단계 2 — 국내 사건 연기 기능

### 2.1 목표
AhnLab V3 로그, adb 백업 내부 DB → 기존 앱 파서, 이미지에서 `$Boot` 추출(`ntfs-volume-information` 생성), 이미지 미할당 영역 URL 카빙, 소형 항목(eMule `.part.met` 0xE1, 카카오맵 WCONGNAMUL 좌표 변환, `p2p-parse-error` `reason_ko`, IconLayouts 결정).

### 2.2 현재 상태(근거)
- AhnLab V3: 코드에 없음(`system_extras.py`는 McAfee만). 웹 검색(2026-10-19)으로 탐지 로그의 파일 경로·형식을 확인하지 못했다. 확인된 것: 제품 내 "로그 뷰어"가 공식 열람 경로, 지원용 수집 도구 `AhnRpt.exe`가 설치 경로에서 로그를 모은다는 것(ask.ahnlab.com), 설치 폴더 `C:\Program Files\AhnLab\V3*`. 탐지 로그가 평문 파일인지 DB인지 미확인.
- adb 백업: `artifacts/mobile/adb_backup.py`는 tar 구성원을 메모리에서 흘려 읽고 64 MiB 이하 SQLite 200개만 임시 사본으로 **스키마·행 수** 인벤토리(`_sqlite_inventory`). 기존 앱 파서는 경로 기반이다: `mobile/collector.py` `MobileExportProvider._collect_file` → `is_chat_app_database_candidate(hint)` → `collect_chat_app_database_inventory(path, hint)`(읽기 전용 스냅샷 `open_sqlite_snapshot`), `artifacts/android.py` `collect_android_app_data_exports(root)`/`build_android_app_data_record(path, package)`.
- `$Boot`: `system_extras.collect_ntfs_volume_information`은 증거 트리의 `$Boot`·`$MFT`만 읽는다. `analysis_kinds.run_ntfs_meta`의 `NTFS_EXTRACTOR`(`core/ntfs_metadata.extract_ntfs_metadata`)는 Sleuth Kit `icat`으로 `$MFT`(inode 0)·`$UsnJrnl:$J`·`$LogFile`(inode 2)만 추출하고 `$Boot`(inode 7)는 없다. `ntfs_cluster_size`는 raw 이미지의 파티션 시작 512바이트 또는 추출 폴더의 `$Boot`/`Boot.bin`을 이미 읽는다. 네이티브 경로 `core/e01_native.py`(pyewf + dissect.ntfs, 선택 의존성)에는 `_dump_ntfs_system_record`가 있다.
- URL 카빙: `run_url_carve`는 `iter_evidence_files` 중 `source_kind(path)`가 pagefile·`unalloc|blkls|freespace` 이름·메모리 덤프인 **파일**만 읽는다. 이미지 미할당을 직접 자르지 않는다(known-limitations R5 L3). `core/carving.py`도 파일 단위(`iter_carving_sources`). 미할당 판정에 필요한 것은 NTFS `$Bitmap`(inode 6)과 클러스터 크기(`$Boot`).
- 소형: `p2p.part_met_rows` 0xE1 거부; `location_urls`/`core/derived/map_urls.py` `_kakao`는 `urlX`/`urlY`를 문자열로만(`plane_coordinate_system` 표기); `p2p._error`에 `reason_ko` 없음(R5 콘솔 리뷰에서 "동시 수정 중이라 미추가"); IconLayouts는 `desktop-wallpaper`에서 연기.

### 2.3 설계 — 4갈래(파일 소유 분리)

#### 갈래 A — AhnLab V3(소유: `artifacts/windows/av_ahnlab.py`(신규), `system_extras.py`는 등록 1줄, 카탈로그 `antiforensics.yaml` 블록, 테스트 `tests/test_r6_s2_ahnlab.py`)
- 결정(권고): **인벤토리 우선 접근**. 공개 자료로 형식을 확정할 수 없으므로 두 층으로 나눈다.
  1. `av-product-presence`(신규 artifact_type, kind `windows-system`): `Program Files\AhnLab\*`, `ProgramData\AhnLab\*`, `%LOCALAPPDATA%\AhnLab\*` 아래 제품 폴더·버전(`*.exe` 버전 리소스는 읽지 않고 폴더명·`version*.ini`·설치 프로그램 행 조인), 로그 후보 파일 목록(`*.log`·`*.txt`·`*.db`·`*.dat` 중 이름에 `log`·`history`·`detect`·`quarantine`·`event`가 든 것; 크기·시각·형식 스니핑: 텍스트/SQLite/ESE/알 수 없음). 격리 폴더(`Quarantine`·`Vault`)는 파일 수·크기만(내용 열지 않음, 악성 코드 복사 금지).
  2. `av-detection-log`(기존 유형)에 `product=ahnlab-v3`: 텍스트 로그이면 McAfee와 같은 줄 휴리스틱(시각 접두 + 탐지 단어: 탐지·치료·삭제·격리·차단·`Detected`·`Repaired`·`Quarantined` + 위협명·경로 패턴)을 `field_extraction=heuristic-lines`로, SQLite이면 표 이름·열에 `detect`·`threat`·`malware`·`path`·`date`가 있을 때만 행으로(`schema_confidence: heuristic-sqlite`), 그 밖은 1층 인벤토리에서 끝. 모든 행에 `verification: unconfirmed`를 두고 단계 1(b)의 VM 표본(V3 Lite 무료판 + EICAR)으로 확인되면 `confirmed`로 올린다.
- 상한: 로그 64 MiB·50만 줄(기존 `system_extras` 상한 재사용), 격리 폴더 파일 5,000개 셈.
- 규칙: 기존 `antiforensics`/AV 관련 규칙이 `av-detection-log`를 읽는다면 `product` 추가만. 새 규칙 없음.

#### 갈래 B — adb 백업 내부 DB 전달(소유: `artifacts/mobile/adb_backup.py`, `artifacts/mobile/collector.py`의 adb 분기, `artifacts/mobile/roots.py`(힌트), 테스트 `tests/test_r6_s2_adb_inner.py`)
- 결정(권고): **바운디드 임시 추출**(메모리 전용은 `open_sqlite_snapshot`이 경로를 요구하므로 부적합). 구현:
  - `collect_adb_backup(path, *, inner_dir: Path | None)`: 해제 중 구성원이 `apps/<package>/{db,f,r,sp}/...`이고 SQLite 머리글(`SQLite format 3\0`)이면 `inner_dir/<sha256(package)[:16]>/<safe name>`으로 기록(기존 64 MiB·200개 상한 재사용, 합계 1 GiB 새 상한 `MAX_INNER_EXTRACT_BYTES`). `-wal`·`-shm`·`-journal` 짝은 같은 폴더에 함께 쓴다(있을 때만).
  - 경로 안전: tar 이름은 쓰지 않고 `member_parts`(package, domain, relpath)에서 **기본 이름만** 취해 `_safe_component`(`e01_native._safe_component`와 같은 규칙: 영숫자·`._-`만, 길이 ≤ 120, `..`·절대 경로·드라이브·NTFS ADS(`:`)·널 금지)로 바꾸고, 충돌은 `-<n>` 접미. 심볼릭·하드링크 구성원·장치 파일은 건너뛴다(`member.isreg()`만).
  - `inner_dir`는 런 출력 폴더 아래 `mobile-inner/<backup sha256[:16]>/`(증거 트리 밖; `run_output_pruner`로 재스캔 제외). CLI `artifacts --kind mobile-export`는 `--output` 옆 폴더, 테스트는 `tempfile`. 런 종료 후 보존(행의 `inner_path`가 가리킴, 검토자가 열 수 있게)하되 `rapidtriage-manifest`에 "해제 사본, 증거 아님" 표시.
  - 전달: 추출된 각 DB에 대해 `hint = Path("apps")/package/domain/name`으로 (1) `is_chat_app_database_candidate(hint)`면 `collect_chat_app_database_inventory(inner_path, hint=hint)`(카카오톡·WhatsApp·Telegram·Signal 등 기존 메신저 프로필; 암호화면 기존대로 인벤토리), (2) 아니면 `build_android_app_data_record(inner_path, package)`(`android-app-data`). 두 경우 모두 행 details에 `container_backup_path`·`container_member`·`recovery_method=adb-backup-extracted`·`inner_path`를 붙인다.
  - 상한을 넘은 DB는 기존 인벤토리(스키마·행 수)만 유지하고 `inner_extract_skipped=cap`.
- 정책: 암호화 백업은 그대로(존재·헤더만). 비밀 비추출 단언(기존 `tests/test_r5_l3_recovery.py` 패턴) 유지.

#### 갈래 C — `$Boot` 추출 + 이미지 미할당 URL 카빙(소유: `core/ntfs_metadata.py`, `core/ntfs_unalloc.py`(신규), `api/app/analysis_kinds.py`의 ntfs-meta·url-carve 블록, `artifacts/windows/system_extras.py`의 `collect_ntfs_volume_information`(읽는 폴더 추가), `core/url_carving.py`(소스 종류 추가), 테스트 `tests/test_r6_s2_ntfs_boot.py`·`tests/test_r6_s2_unalloc_carve.py`)
- `$Boot`:
  - `extract_ntfs_metadata`에 `icat -o <sector> <image> 7` → `ntfs/$Boot`(512바이트 이상, 8 KiB 상한) 추가, 매니페스트 `outputs.boot`. 실패는 `skipped`에 사유(기존 패턴).
  - `source=mft`(추출 `$MFT` 입력)일 때 `_sibling_logfile`처럼 `$Boot`/`Boot.bin`/`$Boot.bin` 형제를 찾아 `outputs.boot`로 넣는다.
  - `run_ntfs_meta` 끝에 `outputs.boot`·`outputs.mft`로 `parse_ntfs_vbr`+`parse_volume_record`(system_extras의 함수 재사용, 임포트 방향은 `core` → `artifacts`를 피하기 위해 두 함수를 `core/ntfs_volume.py`로 옮기고 `system_extras`가 재수출)를 호출해 분석 행 `ntfs-volume-information`을 1행 기록하고 요약에 `volume_serial_number`·`cluster_size`를 둔다. 동시에 `windows-filesystem` kind의 `collect_ntfs_volume_information`이 **런의 분석 출력 폴더**(`analyses/*/ntfs/`)도 훑도록 해 통합 보기 장치 식별자(LNK 볼륨 시리얼)와 만나게 한다(런 → 분석 순서상 다음 런부터; 콘솔은 분석 행을 바로 보여줌).
  - `ntfs_cluster_size`는 이미 `$Boot` 형제를 읽으므로 `$LogFile` 해석이 EWF 이미지에서도 동작하게 된다(부수 효과, 테스트로 고정).
  - 네이티브 경로: Sleuth Kit이 없고 `pyewf`+`dissect.ntfs`가 있으면 `e01_native`에 `dump_boot_sector(partition)`(파티션 첫 섹터 512바이트 읽기, `EwfSectorReader`)를 추가해 같은 `outputs.boot`를 만든다. 둘 다 없으면 기존 한국어 안내 유지.
- 미할당 URL 카빙:
  - `core/ntfs_unalloc.py`: `$Boot`(클러스터 크기·총 섹터)와 `$Bitmap`(inode 6, `icat` 또는 dissect)으로 **미할당 클러스터 구간 목록**(연속 run 병합, 최대 200만 구간)을 만들고, 이미지(raw는 `open`, E01은 `EwfSectorReader`)에서 구간을 순서대로 읽어 `scan_url_source`와 같은 8 MiB 청크·8 KiB 겹침 스트림을 내는 반복자 `iter_unallocated_chunks(image, partition_offset, runs, read_limit)`. 오프셋은 **이미지 절대 바이트 오프셋**(`source_offset`)과 클러스터 번호(`cluster`)를 함께 낸다.
  - `UrlCarveOptions.sources`에 `"image-unallocated"` 추가(기본값에는 넣지 않음; 사용자가 켬), `image_path`·`partition_start_sector` 옵션(ntfs-meta와 같은 `resolve_input_path` 규칙), `max_scan_bytes` 기본 4 GiB 유지(미할당이 더 크면 `source_truncated=true`와 읽은 바이트 표시). 소스 행에 `source_kind="image-unallocated"`, `source_kind_label="이미지 미할당 영역"`, `source_path=<image>`. 기존 파일 소스 로직은 그대로.
  - `core/carving.py`(파일 카빙)는 이번에 건드리지 않는다(범위 통제; 같은 반복자를 `carve`에 붙이는 것은 후속 후보로 기록).
  - 도구가 없을 때: Sleuth Kit도 dissect도 없으면 분석 실패 메시지(한국어)로 `blkls` 덤프를 입력 트리에 두는 기존 방법을 안내.
- 측정: `D:\devin\bsh-e01\BSH.E01`(250 GB, NTFS 파티션 시작 섹터 567296, 클러스터 4096)에서 `$Boot`·`$Bitmap` 추출과 미할당 구간 계산 시간, 미할당 4 GiB 상한 카빙 시간·후보 수. 도구가 없으면 `pyewf`+`dissect` 경로로 측정(사용자 승인).

#### 갈래 D — 소형 항목(소유: `artifacts/p2p.py`, `core/derived/map_urls.py`, `artifacts/windows/location_urls.py`, 테스트 `tests/test_r6_s2_small.py`, 카탈로그 값 라벨)
- eMule `.part.met` 0xE1: eMule 소스 `PartFile.cpp`(GitHub `irwir/eMule` 등 공개 미러)에서 `PARTFILE_VERSION`(0xE0)·`PARTFILE_SPLITTEDVERSION`(0xE1)·`PARTFILE_VERSION_LARGEFILE`(0xE2) 상수와 0xE1 분기(split: 날짜 뒤 해시 세트가 별도 `hashsetneeded`로 저장되고 part 수 뒤 태그 수가 32비트) 레이아웃을 **소스 줄 번호로 인용**해 구현한다. 확인 전에는 구현하지 않고, 소스에서 확정 못 하면 오류 행 유지. 단계 1(b)의 실제 0xE1 표본이 있으면 대조.
- 카카오 WCONGNAMUL → WGS84: 카카오 JS API 문서(`kakao.maps.Coords`, `WCongNamul`)가 공개 변환 함수 이름만 제공하고 수식은 비공개라, 공개된 역공학 자료(WCONGNAMUL = WTM(Bessel/GRS80 TM, 원점 경도 127.5°·위도 38°, 축척 1, 가산 X 200,000·Y 500,000) × 2.5)를 근거 URL과 함께 YAML 주석에 적고 **표준 라이브러리 TM 역변환**으로 구현한다. 수용: 카카오맵 문서 예시 좌표 쌍 ≥ 3개(공개 문서 값)로 오차 ≤ 50 m; 변환 결과는 `latitude`/`longitude`에 넣되 `coordinate_basis="wcongnamul-converted"`·`conversion_confidence="public-reverse-engineered"` 표시, 한반도 범위 밖은 버림(네이버 `x/y` 규칙 재사용). 문서 예시로 검증 못 하면 변환을 넣지 않는다.
- `p2p-parse-error` `reason_ko`: 고정 사유(`part-met-unreadable`·`torrent-unreadable`·`known-met-unreadable`·`resume-unreadable`…)는 값 라벨, 가변 사유 `known-met-truncated-after-N-rows`는 `reason_code=known-met-truncated` + `truncated_after_rows=N`으로 분리해 라벨 가능하게.
- IconLayouts: **연기 유지(결정)**. 사유: `Shell\Bags\1\Desktop` `IconLayouts` 이진 포맷(헤더 + UTF-16 이름 배열 + 좌표)은 공개 역공학 자료만 있고, 바탕 화면 파일 목록은 이미 파일 인벤토리·쉘백(`windows-shellbags`)·LNK로 나오며 사건 가치가 낮다. known-limitations 연기 표에 "R6에서도 연기, 사유" 한 줄만 갱신.

### 2.4 QA 시나리오

| # | 시나리오 | 기준 |
|---|---|---|
| Q-S2-1 | AhnLab 인벤토리 | 합성 `Program Files\AhnLab\V3Lite` 트리(폴더·version ini·텍스트 로그·SQLite 로그·격리 폴더)에서 `av-product-presence` 1행 + 로그 후보 목록, 격리 파일 내용 미열람(열면 실패하는 가짜 바이트), 텍스트 탐지 줄 → `av-detection-log` `product=ahnlab-v3` `verification=unconfirmed`, 손상 로그 격리 |
| Q-S2-2 | adb 내부 DB 전달 | 합성 `.ab`(평문·압축) 안 `apps/com.kakao.talk/db/KakaoTalk.db`(가짜 스키마)·`apps/com.example/db/app.db`에서 `chat-app-database-inventory`·`android-app-data` 행이 `recovery_method=adb-backup-extracted`로 나옴, 추출 폴더가 출력 폴더 아래·증거 트리 밖 |
| Q-S2-3 | adb 경로 안전 | 구성원 이름 `../../x.db`, `C:\x.db`, `a:b.db`, 심볼릭 링크, 장치 파일, 중복 이름 → 모두 안전 이름 또는 건너뜀, 출력 폴더 밖 파일 0개(테스트가 폴더 밖 쓰기를 감시) |
| Q-S2-4 | adb 상한 | 64 MiB 초과 DB·201번째 DB·합계 1 GiB 초과 → `inner_extract_skipped`, 메모리 최고점 < 200 MiB(폭탄 픽스처) |
| Q-S2-5 | `$Boot` 추출 | 가짜 `icat` 러너(기존 `tests/test_rapidtriage_analyses.py` 패턴)로 `outputs.boot` 생성, `ntfs-volume-information` 분석 행 1개(VSN·클러스터·레이블), raw `$MFT` 입력 + 형제 `$Boot`도 동일; `$Boot` 없으면 `skipped` 사유, 분석은 계속 |
| Q-S2-6 | 미할당 구간 | 합성 NTFS 이미지(작은 raw: `$Boot`·`$Bitmap` 직접 생성)에서 미할당 run 목록이 기대와 일치, 겹침 청크 경계의 URL(청크 끝에 걸친 URL) 검출, 오프셋 = 이미지 절대 오프셋 |
| Q-S2-7 | 미할당 URL 카빙 옵션 | `sources=["image-unallocated"]` + `image_path` → `carved-url-candidate` `source_kind=image-unallocated`; 도구 없음·이미지 아님·파티션 아님 → 한국어 실패 메시지; 4 GiB 상한 `source_truncated` |
| Q-S2-8 | eMule 0xE1 | 소스 인용 레이아웃으로 만든 합성 0xE1 → `p2p-transfer`; 잘린 0xE1 → 오류 행 |
| Q-S2-9 | 카카오 좌표 | 공개 예시 좌표 쌍 ≥ 3개 오차 ≤ 50 m, 범위 밖 버림, `coordinate_basis` 표시, 지도 보기에 행이 나타남 |
| Q-S2-10 | reason_ko | 모든 `p2p-parse-error` 사유가 카탈로그 값 라벨로 한글 표시(콘솔 테스트) |
| Q-S2-11 | 실데이터 | `bsh-subset` 재실행 또는 공급자 단위: 기존 행 수 변화 0, 새 행(AhnLab 흔적은 서브셋에 없을 수 있음 → 0행·오류 0); `BSH.E01`에서 `$Boot` 추출 → VSN이 서브셋 LNK `volume_serial`과 일치; 미할당 카빙 후보 수·시간 기록 |
| Q-S2-12 | 게이트·비밀 | §0 게이트, adb·AhnLab 픽스처에 심은 비밀 바이트가 어떤 출력에도 없음, OpenAPI 스냅샷 갱신(url-carve·ntfs-meta 옵션) |

### 2.5 사용자 조치 필요
1. `D:\devin\bsh-e01\BSH.E01` 읽기 사용 승인(`$Boot`·`$Bitmap` 추출·미할당 4 GiB 스캔; 출력은 `D:\rapid-qa\derived\r6-s2-*`).
2. Sleuth Kit 설치 여부 결정(권고: 설치 — `winget` 또는 공식 바이너리; 없으면 `pyewf`+`dissect` 네이티브 경로로 측정).
3. 단계 1(b) VM에 V3 Lite(무료)·EICAR 탐지 생성 승인(AhnLab 형식 확정용). 없으면 인벤토리 층만 검증.
4. 카카오 좌표 변환 근거(역공학 공개 자료) 채택 여부 — 권고: 채택하되 `conversion_confidence` 표시.

### 2.6 완료 기준·규모
- Q-S2-1~12 충족, known-limitations `## R6 S2`(AhnLab 미확인 사항, adb 추출 사본 보존 정책, 미할당 카빙 범위·상한, 카카오 변환 근거, IconLayouts 연기), 매트릭스 연기 표 갱신.
- 규모: 중(신규 모듈 3: `av_ahnlab.py` ~400줄, `ntfs_unalloc.py` ~300줄, `core/ntfs_volume.py` 이동 ~150줄; 수정 6모듈; 테스트 5파일). 갈래 A·B·C·D는 파일이 겹치지 않아 4 워크트리 병렬 가능.

---

## 3. 단계 3 — 성능

### 3.1 목표과 목표치

| 항목 | 현재(근거) | 목표 |
|---|---|---|
| 타임라인 조건 첫 페이지 | 합성 50만 이벤트 약 5 s(known-limitations r4 V3; `filter_rows_page`가 전체 `events`를 Python 술어로 훑고 `MATCH_CACHE`에 위치 저장) | **≤ 1.0 s**(50만), 두 번째 페이지 ≤ 0.05 s 유지 |
| `/files` 조건 페이징 | 50만 행 약 1.3 s/페이지, 캐시 없음(`filter_files_by_category`가 매 페이지 전체 훑기; `routes_runs.py` 1200–1280) | 첫 페이지 ≤ 1.0 s, **다음 페이지 ≤ 0.05 s**(타임라인과 같은 LRU) |
| 전체 아티팩트 지도 보기 | run-subset10 64만 행 약 38 s(`MapView.tsx`가 `geo=-90,-180,90,180`으로 `_artifacts_across_kinds` → `filter_across_kinds`를 20만 행 scan_cap으로 반복 호출, `useAutoLoad` 2만 행) | **≤ 2 s**(위치 행 인덱스 사용 시), 인덱스 없을 때도 ≤ 10 s |

### 3.2 현재 구조(근거 파일)
- 타임라인: `rapidtriage-timeline.json`(run-subset10에서 281 MB 단일 JSON, `events` 배열)을 `core/jobs.py` `OutputJsonCache`(LRU)로 통째로 메모리에 올린다. 조건 판정은 `row_conditions.RowConditions.predicate("timeline")`가 행마다 `parse_moment`(ISO 파싱)·`row_content_types`(확장자 집합)·`row_is_partial`를 계산한다 — 비용의 대부분은 **문자열 시각 파싱과 details 탐색**.
- 파일: `rapidtriage-files.json`(30 MB) `candidates`/`inventory` 리스트; 취득 사본은 `files_ntfs.ntfs_si_modified_resolver`로 행마다 NTFS 조인 시각을 찾는다.
- 아티팩트: kind별 `.jsonl`(`jsonl_records.iter_artifact_records`, 오프셋 인덱스)과 정렬 인덱스(`paginate_sorted_artifact_output`), 플래그 조인(`flags_join`). 좌표는 `row_conditions.row_coordinates`(4가지 키 쌍 + `exif_gps_profile`).
- 캐시 키는 `(출력 경로, 크기, mtime)`(`output_stamp`) — 런 출력이 바뀌면 자동 무효.

### 3.3 설계 — 3갈래

#### 갈래 A — 타임라인 조건 인덱스(소유: `api/app/timeline_index.py`(신규), `row_conditions.py`의 `filter_rows_page`/`matched_indices` 호출부, `routes_runs.py` 타임라인 엔드포인트, 테스트 `tests/test_r6_s3_timeline_index.py`)
- 런당 1회, 첫 조건 요청(또는 런 완료 직후 백그라운드)에 **열 인덱스**를 만든다: `epoch_us: array('q')`(파싱 불가/없음은 `INT64_MIN`), `has_offset: bytearray`(naive 여부 — tz 변환 분기용), `content_mask: array('H')`(콘텐츠 유형 비트), `partial: bytearray`, `weekday/hour`는 tz별이라 저장하지 않고 epoch에서 계산. 메모리: 50만 × (8+1+2+1) ≈ 6 MB. 생성은 `SingleFlightIndexCache`(`index_cache.py`) 재사용, 키 `output_stamp(timeline)`. 생성 비용은 한 번의 전체 훑기(≈ 현재 5 s)이므로 **런 완료 시 `persist` 단계에서 `rapidtriage-timeline-index.bin`으로 저장**하고(헤더에 stamp), API는 파일이 있고 stamp가 맞으면 읽기만(≤ 0.1 s). 저장 파일이 없는 구 런은 첫 요청 때 만들고 디스크에 쓴다(출력 폴더에 쓸 수 없으면 메모리만).
- 조건 판정은 인덱스 벡터 연산(Python 루프라도 정수 비교만; 50만 → 약 0.2–0.4 s 측정 목표)으로 위치 배열을 만들고 기존 `MATCH_CACHE`에 넣는다(두 번째 페이지 동작 불변). `from/to`는 `parse_bound`+`bound_unit`을 epoch 경계로 바꾸고, tz 조건(weekday/hours/offhours)은 epoch + 오프셋(고정 오프셋) 또는 IANA 변환(변환 횟수를 줄이기 위해 날짜별 오프셋 캐시).
- 판정 동등성: 인덱스 결과와 기존 술어 결과가 **같은 집합**임을 테스트가 무작위 이벤트 2만 개로 단언(0001/9999년 경계·naive·오프셋·콘텐츠·부분 행 포함). 히스토그램(`timeline_hist.py`)은 이번 범위 밖(조건 미적용 표시 유지).

#### 갈래 B — `/files` 조건 LRU(소유: `api/app/artifact_filter.py` `filter_files_by_category`·`filter_files_rows`, `routes_runs.py` files 엔드포인트, `files_ntfs.py`(조인 시각 벡터), 테스트 `tests/test_r6_s3_files_cache.py`)
- 조건이 있을 때 `filter_files_by_category`가 매 페이지 훑는 대신 `row_conditions.matched_indices(rows, predicate, cache_key)`를 쓴다(키: `("files", run_id, collection, output_stamp(files), 조인 상태 stamp, categories, conditions.cache_key(), restrict)`). `matched`가 정확해지고(`truncated` 제거는 `scan_cap` 2,000,000 유지 시 `truncated=False`로 통일), 다음 페이지는 위치 배열 슬라이스.
- 첫 페이지: 파일 행도 타임라인과 같은 작은 열 인덱스(`mtime epoch`, `category mask`, `acquisition-copy 여부`)를 `files` 출력 stamp로 캐시해 1.3 s → ≤ 1.0 s. NTFS 조인 시각은 인덱스 생성 때 한 번만 해석(`ntfs_si_modified_resolver` 벡터화: 해시 키 → `NtfsIndex` 조회).
- 플래그 필터·경로 제한(`restrict`)과 결합된 경로(`filter_files_rows`)도 같은 캐시 키 체계를 쓴다.

#### 갈래 C — 위치 행 인덱스 + 지도 보기(소유: `api/app/geo_index.py`(신규), `routes_runs.py` `_artifacts_across_kinds` geo 분기, `core/run/persist.py`(런 완료 시 인덱스 생성), `frontend/src/features/views/MapView.tsx`·`useViewRows.ts`·`geo.ts`, 테스트 `tests/test_r6_s3_geo_index.py`·`frontend/src/features/views/MapView.test.tsx`)
- 서버: 런당 `rapidtriage-geo-index.json`(kind, record_index, lat, lon, time) — 런 완료 `persist` 단계에서 모든 kind `.jsonl`을 한 번 훑어 좌표 행만 적는다(`row_coordinates` 재사용, 상한 50만 행). 구 런은 첫 지도 요청에서 백그라운드 생성(`SingleFlightIndexCache`, 진행 중이면 응답 `geo_index: building`과 기존 경로로 부분 결과).
- `/artifacts?geo=…`에 kind가 여러 개(또는 전체)일 때 `geo` 조건이 있으면 **인덱스에서 상자 안 행을 고르고** `iter_records_at`로 해당 레코드만 읽어 페이지를 만든다(다른 조건·검색어·플래그가 함께 있으면 그 행들만 추가 판정). 응답에 `cross_kind.geo_index=true`, `located_total`.
- 새 엔드포인트 `GET /api/runs/{run_id}/geo-clusters?cell=0.01&geo=…`: 서버가 0.01° 격자 묶음(개수·첫/마지막 시각·대표 행 1개)을 돌려줘 콘솔이 2만 행을 내려받지 않아도 묶음을 그린다(OpenAPI 스냅샷 갱신).
- 콘솔: `MapView`는 먼저 `geo-clusters`로 묶음을 그리고, 좌표 표는 `geo=`로 500행씩만 가져온다(`MAP_AUTOLOAD_ROWS` 2만 제거 또는 묶음 선택 시에만). 인덱스가 없을 때(`geo_index: building`)는 "위치 색인 만드는 중" 상태 표시 후 재조회.
- 정책 불변: 타일·외부 호출 없음.

### 3.4 측정 방법
- 합성: `tests/perf/`(단위 테스트와 분리, `python -m rapidtriage benchmark`와 별도) `scripts/perf-r6.py --synthetic --events 500000 --files 500000 --artifacts 640000 --located 2000 --output <json>`: 임시 런 출력을 만들어 API를 TestClient로 호출하고 첫 페이지·두 번째 페이지·지도 묶음 응답 시간을 5회 중앙값으로 적는다. 목표 미달이면 실패(CI에는 넣지 않고 Antigravity 요청으로 실행).
- 실데이터: run-subset10(기존 런, 인덱스 없음 → 첫 요청 때 생성 경로)과 단계 1의 `r6-s1-run`(런 완료 시 인덱스 생성 경로)에서 `python scripts/perf-r6.py --run <dir>`로 같은 지표 측정(타임라인 32만 이벤트, 파일 4,935·인벤토리 전체, 아티팩트 64만). 웹 서버는 `rapidtriage web`를 읽기 전용 런 폴더에 붙이며 출력 폴더에 인덱스를 쓸 수 없으면 메모리 캐시 경로가 동작해야 한다(둘 다 측정).

### 3.5 QA 시나리오

| # | 시나리오 | 기준 |
|---|---|---|
| Q-S3-1 | 타임라인 동등성 | 무작위 2만 이벤트 × 조건 조합 40개에서 인덱스 판정 = 기존 술어 판정 |
| Q-S3-2 | 타임라인 성능 | 합성 50만: 첫 페이지 ≤ 1.0 s(인덱스 파일 있음 ≤ 0.3 s), 다음 페이지 ≤ 0.05 s; 메모리 증가 ≤ 30 MB |
| Q-S3-3 | 인덱스 무효화 | 타임라인 파일 재작성(stamp 변경) 후 인덱스 재생성, 구 인덱스 파일 헤더 불일치 시 무시 |
| Q-S3-4 | `/files` 캐시 | 두 번째 페이지 ≤ 0.05 s, `matched` 정확, 조인 상태 변화(ntfs-meta 분석 완료) 후 캐시 무효 |
| Q-S3-5 | `/files` 동등성 | 카테고리·조건·플래그·경로 제한 조합에서 기존 결과와 행 집합·순서 동일 |
| Q-S3-6 | 지도 인덱스 | 합성 64만 행·위치 2,000행: `geo-clusters` ≤ 0.5 s, 전체 아티팩트 지도 첫 표시 ≤ 2 s; 인덱스 없는 구 런 ≤ 10 s + `building` 상태 |
| Q-S3-7 | 지도 정확성 | 인덱스 경로와 전체 훑기 경로의 위치 행 집합 동일, 격자 경계·날짜 변경선 규칙(known-limitations r4) 유지 |
| Q-S3-8 | 읽기 전용 출력 폴더 | 인덱스 파일을 쓸 수 없어도 500 없음, 메모리 캐시로 동작 |
| Q-S3-9 | 콘솔 | vitest: MapView가 묶음 API → 표 500행 순으로 호출, 상태 문구; e2e: 지도 보기 전환 후 묶음 클릭 → 열 보기 `geo` 필터 |
| Q-S3-10 | 실데이터 | run-subset10·r6-s1-run 두 런에서 §3.1 목표치 충족(표로 기록) |
| Q-S3-11 | 게이트 | §0, OpenAPI 스냅샷(geo-clusters 추가), 적대적 리뷰 0 |

### 3.6 사용자 조치 필요
- 실데이터 측정(웹 서버를 `D:\rapid-qa\derived\run-subset10`·`r6-s1-run`에 붙여 측정)과 합성 50만 측정의 Antigravity 위임 승인. 그 외 승인 사항 없음.

### 3.7 완료 기준·규모
- Q-S3-1~11 충족, known-limitations r4 V3 문단의 수치 갱신("첫 페이지 약 5 s" → 새 측정값, 파일 목록 조건 캐시 설명, 지도 인덱스·`building` 상태).
- 규모: 중(신규 `timeline_index.py`·`geo_index.py`·`perf-r6.py` 각 200–400줄, 수정 6파일, 프런트 3파일). 갈래 A·B·C 파일이 분리되나 `routes_runs.py`는 세 갈래가 각각 다른 엔드포인트 블록을 만지므로 코디네이터가 병합.

---

## 4. 단계 4 — 검증 갭

### 4.1 목표
1. A등급 규칙 7개(`antiforensics.wiper_run_after_incident`, `cloud.bulk_upload`, `eventlog.rdp_external_ip`, `eventlog.log_cleared`, `ntfs.si_before_fn`, `ntfs.ads_executable`, `rdp.external_ip`; `core/triage_rules/catalog/*.yaml`)를 합성 픽스처(`tests/triage_cases/*.py`, 이미 있음) 밖의 **실데이터·공개 데이터셋**으로 검증한다. 서브셋에는 `$MFT`·Security 1102·외부 IP 로그온이 없다.
2. Windows T1 릴리스 증거(`docs/validation/windows-t1-*.md`)는 운영자 게이트로 남긴다: 필요한 운영자 입력을 정확히 나열하고, 자동으로 채울 수 있는 것은 채운다.

### 4.2 현재 상태(근거)
- 규칙 테스트: `tests/test_rapidtriage_triage_rules.py` + `tests/triage_cases/{antiforensics,cloud,eventlog,ntfs,rdp}.py`(합성). 실데이터 플래그 수는 run-subset10 `rapidtriage-indicators.json`(4,712 지표)과 플래그 조인에서 읽을 수 있으나 A등급 적중 표가 없다.
- 실데이터 가용: 전체 이미지 `$MFT` 덤프 `D:\devin\bsh-e01\bsh-mft.bin`(1.46 GB) → `ntfs-meta` `source=mft`로 **`ntfs.si_before_fn`·`ntfs.ads_executable`을 실데이터로 검증 가능**(MFT 레코드 상한 800만 이내). 서브셋 `Windows\System32\winevt\Logs\Security.evtx`·`System.evtx`·`TerminalServices-LocalSessionManager%4Operational.evtx`가 있어 `eventlog.log_cleared`(1102/104)·`rdp_external_ip`(4624 type 10, 21/25)는 **음성 대조**(서브셋에 없음 → 0 적중, 오탐 0)만 가능.
- T1: `windows-t1-operator-inputs.md`는 2026-08-30 상태(`operator_name`·`reviewer_name`·`acquisition_tool`·`review_ticket` 등 `<pending>`, 승인 체크 12개 중 4개), 런북은 "prepared, not executed". 호스트에 `ewfacquire`/`ftkimager` 없음.

### 4.3 설계 — 3갈래

#### 갈래 A — 실데이터·공개 데이터셋 규칙 검증 하네스(소유: `scripts/rule-validation.py`(신규), `docs/validation/triage-rules-a-grade-2026-10-19.md`(신규), `tests/test_rule_validation_script.py`)
- `python scripts/rule-validation.py --run <dir> --rules A --expect <expected.json> --json`: 런의 플래그 조인(`flags_join`)·지표를 읽어 규칙별 적중 수·등급·표본 근거(경로·시각만)를 내고 기대값(양성 n건 이상·음성 0건)과 대조한다.
- 데이터 소스(각각 사용자 승인):
  - `bsh-mft.bin`: `rapidtriage ntfs-meta --source mft`(CLI `ntfs_meta` 서브커맨드) → `ntfs.si_before_fn`·`ads_executable` 적중·오탐 검토. 기대: 적중 행마다 `$SI`<`$FN` 근거 시각이 실제 레코드와 일치(MFTECmd 등 신뢰 도구 출력이 있으면 `scripts/mft-reference-diff.py`로 교차; `D:\devin\bsh-e01\bsh-ils.txt`·`bsh-fls.txt`도 있음).
  - 서브셋 이벤트 로그: `log_cleared`·`rdp_external_ip` 0 적중(음성). 양성은 공개 데이터셋에서:
    - **NIST CFReDS "Hacking Case"**(Windows XP, 공개 답안 포함)·**digitalcorpora `nps-2009-domexusers`**: 1102 여부는 데이터셋마다 달라 다운로드 후 `evtx`에서 1102/104·4624 로그온 유형 10 외부 IP를 먼저 `grep`해 **양성 보유 데이터셋만** 쓴다. 후보 추가: `digitalcorpora.org/corpora/scenarios/2018-lone-wolf`(Windows 10, 이벤트 로그 포함), `2019-narcos`, `2012-ngdc`(Windows 7). 각 데이터셋에 어떤 양성이 있는지는 다운로드 전에는 확정할 수 없으므로 "확인 후 선택"으로 둔다.
    - 외부 IP 로그온·1102·와이퍼·대량 업로드 양성이 공개 데이터셋에 없으면 **합성 보강**: 단계 1(b) VM에서 실제 Windows가 쓴 이벤트(원격 데스크톱으로 공인 IP 유사 주소 — VM NAT에서는 사설이라 1102·104 생성만 현실적: `wevtutil cl Security`로 1102 생성)와 wiper 흔적(SDelete 실행 → Prefetch·Amcache)을 만들어 실제 OS 산출 포맷으로 검증. `rdp.external_ip`·`eventlog.rdp_external_ip`는 실데이터 양성 확보가 어려우면 "합성+음성만"으로 등급 근거를 문서에 명시.
    - `cloud.bulk_upload`: 공개 데이터셋에 OneDrive/Dropbox 동기화 로그가 드묾 → VM에서 OneDrive 테스트 계정으로 파일 50개 업로드(사용자 계정 필요) 또는 합성 유지 명시.
- 결과 문서: 규칙 × (합성 / 서브셋 음성 / bsh-mft / 공개 데이터셋 / VM 생성) 표, 적중·오탐·근거, 등급 유지 여부 권고(실데이터 양성이 전혀 없는 규칙은 등급을 내리지 않되 "합성 근거만" 표시를 카탈로그 `validation` 필드로 추가 — 카탈로그 YAML에 `validation: {synthetic: true, real: <list>}` 키와 콘솔 근거 팝오버 한 줄).

#### 갈래 B — 카탈로그 검증 메타·콘솔 표시(소유: `core/triage_rules/catalog/*.yaml`의 7개 규칙 블록, `core/triage_rules/catalog.py`(필드 로드), `frontend/src/features/flags/*`(팝오버 한 줄), 테스트)
- 위 `validation` 필드. 규칙 버전은 올리지 않는다(판정 로직 불변).

#### 갈래 C — Windows T1 운영자 입력 정리(소유: `docs/validation/windows-t1-operator-inputs.md`, `windows-t1-execution-runbook.md`의 "현재 상태" 절, `scripts/external-release-evidence-template.py`는 손대지 않음)
- 자동으로 갱신 가능한 값: `rapid_commit`(단계 4 HEAD), `python_version`, `windows_version`, `timezone`, `trusted_tool_paths` 버전 재확인, `long_path_policy`. 실행 없이 채울 수 없는 값은 아래 표로 **운영자 입력 목록**을 문서 맨 위에 둔다.

운영자 입력(정확한 목록):

| 입력 | 종류 | 상태 |
|---|---|---|
| `operator_name`, `reviewer_name` | 사람 지정 | 미정 |
| `review_ticket` | 추적 ID | 미정 |
| `acquisition_tool`(+ 버전, 승인) | 도구 설치·승인(ewfacquire/FTK Imager/다른 E01 생성 도구) | 호스트에 없음 |
| `ex01_capable_tool` 또는 "Ex01 생략" 명시 | 결정 | 미정 |
| 디스크 생성·포맷 명령 승인 | 승인 체크 | 미승인 |
| E01 취득 명령 승인 / Ex01 취득 승인 또는 생략 | 승인 체크 | 미승인 |
| 신뢰/참조 도구 내보내기 명령 승인(EvtxECmd·LECmd·JLECmd·RECmd·PECmd·MFTECmd·SrumECmd; 관리자 권한 필요 항목 포함) | 승인 체크 + 관리자 권한 세션 | 부분(비관리자 3종만 실행됨) |
| `license_restrictions` 재확인(Zimmerman 도구 라이선스 → 출력 보관 가능 여부) | 법무 확인 | 미정 |
| `evidence_storage_access_control`(공유 저장소면 ACL 기록) | 기록 | 단일 운영자 가정 |
| `ntfs_volume_id`(취득 시 VSN) | 취득 후 기록 | 미기록 |
| `e01_image_path`·`ex01_image_path`·`trusted_export_path`·`rapid_results_path`·`diff_result_path` | 실행 후 경로 | 미실행 |
| 기술·방법론·운영자·법무 검토 담당 지정 | 사람 지정 | 미정 |
| EVTX 레코드 식별자(BinXML EventRecordID) 불일치 해소 여부 확인(2026-08-30 발견) | 코드 상태 확인 → 현재 코드로 재실행 | 재확인 필요(R3 O2 이후 `eventlog` 파서가 EventRecordID를 내는지 단계 4에서 확인하고 문서 갱신) |

- 릴리스 증거는 운영자가 위 항목을 채우고 승인할 때까지 **차단 유지**("Engineering Baseline"과 "Release Evidence"를 분리 보고, AGENTS.md).

### 4.4 QA 시나리오

| # | 시나리오 | 기준 |
|---|---|---|
| Q-S4-1 | 하네스 | 합성 런(양성·음성 심은 플래그 조인)에서 규칙별 적중·오탐·기대 대조가 맞음, 읽기 전용 |
| Q-S4-2 | bsh-mft | `ntfs-meta --source mft`로 `bsh-mft.bin` 파싱(800만 레코드 상한 안, 시간 기록) → `ntfs.si_before_fn`·`ads_executable` 적중 ≥ 1 또는 0이면 사유(실제 레코드 수동 확인 3건), 오탐 표본 검토 10건 |
| Q-S4-3 | 서브셋 음성 | `log_cleared`·`rdp_external_ip`·`rdp.external_ip` 0 적중, 지표에 사설 IP 로그온이 외부로 오분류되지 않음(`is_public_ip` 표본) |
| Q-S4-4 | 공개 데이터셋 | 선택한 데이터셋에서 양성이 있는 규칙마다 적중 ≥ 1·근거 시각이 원본 레코드와 일치; 없는 규칙은 "해당 데이터셋 양성 없음" 기록 |
| Q-S4-5 | VM 생성 양성 | `wevtutil cl` 1102 → `log_cleared` 적중, SDelete → `wiper_run_after_incident`(사건 기준 시각 옵션) 적중 |
| Q-S4-6 | 카탈로그 메타 | 7개 규칙에 `validation` 필드, 로드·스키마 테스트, 콘솔 팝오버 문구(vitest) |
| Q-S4-7 | T1 문서 | 운영자 입력 표가 문서 맨 위, 자동 값 갱신, `check-doc-refs` 통과, "Not Evidence" 문단 유지 |
| Q-S4-8 | 게이트 | §0, 적대적 리뷰 0 |

### 4.5 사용자 조치 필요
1. `bsh-mft.bin` 사용 승인(읽기, 출력 `D:\rapid-qa\derived\r6-s4-ntfs`).
2. 공개 데이터셋 다운로드 승인(CFReDS Hacking Case ≈ 4.5 GB, `nps-2009-domexusers` ≈ 40 GB E01 중 일부, `2018-lone-wolf` ≈ 수십 GB — **먼저 1개만** 권고: CFReDS Hacking Case).
3. VM에서 `wevtutil cl Security`·SDelete 실행 승인(일회용 VM 안에서만).
4. T1 운영자 입력 표의 사람·승인 항목 결정(릴리스 증거 진행 여부).

### 4.6 완료 기준·규모
- Q-S4-1~8 충족, `docs/validation/triage-rules-a-grade-2026-10-19.md`, 카탈로그 `validation` 필드, T1 문서 갱신, known-limitations `## R6 S4`(규칙별 실데이터 근거 범위).
- 규모: 소–중(스크립트 1, YAML 7블록, 콘솔 한 줄, 문서 3). 실행 시간은 데이터셋 크기에 좌우.

---

## 5. 순서·의존

1. 단계 1 → 2: 단계 1의 VM 표본(eMule 0xE1·AhnLab V3 Lite·adb)이 단계 2 수용 기준의 입력. 단계 1 재실행(`r6-s1-run`)은 단계 3 측정의 기준 런.
2. 단계 2 → 3: 단계 2가 `windows-filesystem`·`url-carve` 행을 늘려도 단계 3 인덱스는 출력 stamp로 무효화되므로 충돌 없음.
3. 단계 3 → 4: 단계 4 하네스는 플래그 조인만 읽어 단계 3과 독립. 단, `bsh-mft.bin` ntfs-meta 런은 단계 2의 `$Boot` 형제 읽기 덕을 보므로 단계 2 이후가 낫다.
4. 각 단계 PR은 이전 단계 병합 후 main에서 분기한다(`feat/r6-followups`는 계획 문서 PR로 먼저 닫는다 — 권고).

## 6. 사용자 조치·승인 총괄

| # | 항목 | 단계 |
|---|---|---|
| U1 | 실표본 제공 여부(Phone Link·Viber·Office·McAfee 등) | 1 |
| U2 | 일회용 VM 생성·앱 설치 승인(알집·팟·곰·KMPlayer·VLC·eMule·qBittorrent·GIMP·V3 Lite) + 라이선스 확인 | 1·2·4 |
| U3 | 공개 코퍼스 다운로드 승인(CFReDS Hacking Case 우선, digitalcorpora) | 1·4 |
| U4 | 전체 재실행·전체 unittest·성능 측정의 Antigravity 위임 실행 | 1·2·3·4 |
| U5 | `D:\devin\bsh-e01\BSH.E01`·`bsh-mft.bin` 읽기 사용 승인 | 2·4 |
| U6 | Sleuth Kit 설치 결정(없으면 pyewf+dissect 경로) | 2 |
| U7 | 카카오 WCONGNAMUL 역공학 근거 채택 여부 | 2 |
| U8 | VM에서 `wevtutil cl Security`·SDelete 실행 승인 | 4 |
| U9 | Windows T1 운영자 입력(사람·승인 체크) 결정 | 4 |
| U10 | 단계마다 PR 병합("머지해라") | 전체 |

## 7. 결과 기록
(구현 후 단계별로 채움)

### 단계 2 콘솔·카탈로그 적대 검토 수정(fix/r6-s2-console-review)
- url-carve `image-unallocated` 행: E01/Ex01/분할 이미지(서버 `image_format`/`image_media_kind`, 없으면 확장자 .dd/.raw/.img/.bin 외)는 컨테이너를 오프셋으로 열지 않고 오프셋·클러스터·파티션 시작 섹터를 메타로만 표시("E01 미디어 오프셋 — 파일 위치가 아님"). raw 이미지는 종전대로 헥스 이동.
- 요약 메모: 이미지 미할당 영역 실패(오류 문구)·일부만 스캔(스캔/전체 바이트)·URL 후보 상한, ntfs-meta `boot-only-native`(Sleuth Kit 설치 안내). 트리의 MFT/USN·불일치·$LogFile 빈 노드 사유는 `extraction_status`/`summary.skipped`에서 가져옴.
- ntfs-meta `volume-information` 행: 행 출처 필터(`source=volume-information`)·`source_row_ranges`·`source_counts`, 트리 노드 "NTFS 볼륨 정보(NTFS 메타 분석)", 카탈로그 계열 `ntfs-volume-information`, 콘솔 제목.
- 타임라인: `av-detection-log.detected_at`은 행의 `timestamp_timezone`(AhnLab SQLite epoch = UTC) 우선, 열 이름은 "탐지 시각"; `av-product-presence`는 타임라인 제외(미매핑 집계 없음). 트리 노드 "백신 제품 흔적"(AhnLab은 설명에).
- 한국어 라벨: carved-url `cluster`·`partition_start_sector`, adb 해제 사본 키(`inner_path` = "해제 사본(증거 아님)", `container_*`, `backup_domain` 코드, 해제 생략 사유), AhnLab `parse_error`·`schema_confidence`·`count_truncated`·`walk_truncated`, 미분류 DB 조치 값(파생 열 `av_action`, "DB 원본 값·조치 분류 안 됨"). adb 해석 행의 "파일 열기"는 원본 .ab(행 path)이며 해제 사본은 메타의 보조 항목.
- url-carve 양식: 최대 스캔 도움말에 이미지 미할당 총량 의미, 파티션 시작 섹터 오류는 해당 필드(aria-invalid/describedby).
- 남은 한계: 행 자체에 이미지 형식 플래그는 아직 없음(`_carve_image_unallocated`는 별도 견고성 작업 범위) — 확장자 판정이 기본. 파생 "조치" 열은 서버 정렬 대상이 아님.
