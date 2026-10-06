# AXIOM 카테고리 ↔ RapidTriage 아티팩트 커버리지 비교 (2026-10-06)

기준: `D:\윤제호` AXIOM보내기 139개 카테고리 (xlsx 1개 = 1카테고리).
우리 측 기준: `rapidtriage` 코드베이스에 정의된 `artifact_type` 리터럴 202개
(`discover_artifact_type_literals` 실측).

요약: 정의된 유형 수는 202 > 139이지만, **AXIOM이 실제 런에서 찾아낸 카테고리
일부는 우리 수집기에 아직 대응 파서가 없거나 후보 수준**이다. 아래는 정직한
3단계 분류: ✅ 구현됨 / ◐ 부분(후보·인벤토리 수준) / ❌ 미구현.

## 범주별 매핑

### 파일시스템 / 디스크

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type / 수집기 |
|---|---|---|
| 파일 시스템 정보 | ✅ | mft-file, mft-record, windows-filesystem |
| $LogFile 분석 | ◐ | ntfs-logfile-transaction-candidate (후보 수준) |
| 휴지통 | ✅ | recycle-bin-entry |
| 파일 연결 | ◐ | registry-user-activity (FileExts 부분) |
| LNK 파일 | ✅ | recent-shortcut |
| 로컬에서 접근한 파일 및 폴더 | ✅ | registry-user-activity, recent-shortcut |
| 애플 디스크 이미지 | ◐ | generic-documents/파일 시그니처 수준 |
| EGG Archives | ◐ | archive-file-inventory |

### 실행 / 프로그램 증거

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| 프리페치 파일 | ✅ | prefetch-file, prefetch-reference |
| Shim 캐시 | ✅ | shimcache-entry |
| AmCache 6종 (프로그램/드라이버/PNP/장치컨테이너/바로가기/바이너리) | ◐ | amcache-entry, amcache-hive (단일 플랫 타입) |
| UserAssist | ✅ | userassist-entry |
| MUICache | ◐ | registry-user-activity 계열 |
| BAM/DAM | ✅ | bam-entry |
| 점프 목록 | ✅ | jumplist-automatic, jumplist-custom |
| 시작 항목 / 자동 실행 항목 | ✅ | registry-run-key |
| 설치된 프로그램 / Microsoft 프로그램 | ◐ | registry-key/uwp-package 수준 |
| 알려진 DLL | ❌ | 없음 |
| 프로그램 호환성 지원 기록 | ◐ | shimcache/PCA 후보 |
| 기능 사용 | ❌ | 없음 |
| 예약된 작업 | ✅ | task-scheduler-task |
| 시스템 서비스 | ✅ | windows-service-config |
| 파워셀 히스토리 | ✅ | powershell-history-command |

### 레지스트리 / 시스템

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| 사용자 계정 / 사용자 계정-Windows | ✅ | windows-sam-account-candidate, windows-os-account-summary, windows-account-lifecycle, windows-group-membership |
| 운영 체제 정보 | ✅ | windows-system / registry-summary |
| 시간대 정보 | ◐ | registry-summary 계열 |
| 네트워크 인터페이스(레지스트리) / 네트워크 프로필 | ◐ | registry-hive-strings, wifi-profile |
| USB 장치 | ✅ | registry-usb, usb-setupapi-device-install-candidate, windows-mounted-device |
| 귀하의 휴대폰 장치 | ◐ | registry-usb/portable device 후보 |
| Windows 알림 센터 | ✅ | notification-database |
| Windows 타임라인 활동 | ✅ | activities-cache-db |
| MRU 4종 (실행 명령/열린_저장된/최근 파일/폴더 접근) | ✅ | registry-user-activity, recent-shortcut 계열 |
| Sticky Notes (AXIOM 미표시) | ✅ | sticky-note |
| Windows Recall (AXIOM 미표시) | ✅ | windows-recall-* |

### 이벤트 로그

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| Windows 이벤트 로그 (통합 + 채널별 8종) | ✅ | eventlog-file, eventlog-event, eventlog-chunk, eventlog-logon-session, eventlog-detection, eventlog-summary — 채널별 분리는 eventlog-event의 채널 필드로 가능 |

### 브라우저

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| Chrome/Edge 웹 기록·방문·다운로드·쿠키·북마크·세션·탭·확장·파비콘·캐시·GPU캐시·로컬스토리지·로그인 | ◐ | browser-history, browser-history-downloads, browser-cookie-store-inventory, browser-extension-inventory, browser-session-storage-inventory, browser-credential-store-inventory, browser-sync-inventory, browser-cache-inventory — 인벤토리/히스토리 위주, 파비콘·캐시 레코드 행 파싱은 부분 |
| IE 10-11 기록 (일일/주간/콘텐츠/쿠키) | ◐ | webcachev01-ese-file (파일 식별, ESE 파싱 제한적) |
| Safari 기록 | ◐ | macos-browser-* |
| 키워드 검색어 / Google 검색어 / 구문 분석된 검색 쿼리 | ◐ | browser-history 내 URL 쿼리 수준 |
| 기본 브라우저 | ◐ | registry-summary |
| 분류된 URL / 맬웨어_피싱 URL / 소셜 미디어 URL / 웹 채팅 URL / Facebook URL | ❌ | URL 분류기 없음 (indicators IOC는 별개) |
| 잠재적 브라우저 활동 / 웹 페이지 다시 작성 | ◐ | browser-cache-inventory |
| Google 지도 / 지도 타일 / 애널리틱스 쿠키 | ❌ | 없음 |

### 문서 / 미디어 / 통신

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| Office 문서 (Word/Excel/PPT/365 MRU) | ◐ | document-pattern (파일형 식별), Office 365 MRU 레지스트리 행은 부분 |
| PDF/RTF/CSV/텍스트/한글 문서 | ✅ | document-pattern |
| Photoshop/QuickBooks/WordPerfect Files | ◐ | document-pattern (확장자 식별) |
| EML(X) 파일 | ✅ | email-message, email-mailbox |
| Attachments | ✅ | email-message 첨부 |
| AMR 파일 / 오디오 / Carved Audio | ◐ | media-audio + carving 모듈 |
| QQ / Skype 통화 | ❌ | 없음 (카카오톡 전용 수집기만 존재) |
| 카카오톡 (AXIOM 미표시) | ✅ | kakaotalk-windows/macos 계열 6종 |
| 암호 및 토큰 / Cloud 암호 및 토큰 | ◐ | browser-credential-store-inventory, ios-keychain-inventory |

### 기타

| AXIOM 카테고리 | 우리 커버리지 | 우리 artifact_type |
|---|---|---|
| SRUM 6종 | ✅ | srum-network-usage, srum-database-file, srum-*, srum-schema-row |
| Shellbag | ✅ | shellbag-entry, shellbag-key |
| 식별자-사람/장치 | ◐ | windows-*-account/device 식별 수준 |
| 맬웨어_피싱 URL | ◐ | indicator-ioc-scanner-hit |

## 정량 비교

- AXIOM보내기 카테고리: **139**
- RapidTriage 정의 artifact_type 리터럴: **202**
- AXIOM 대비 명백한 갭 카테고리: 알려진 DLL, 기능 사용, QQ, Skype,
  URL 분류(맬웨어/피싱/소셜/웹채팅/Facebook), Google 지도·애널리틱스
  → 약 8~10개 카테고리
- 우리만 있는 영역: 카카오톡, Windows Recall, AI 데스크톱 대화
  (desktop-ai-*, browser-ai-*, local-llm-*), 합성미디어 스캔,
  웹셸 소스 후보, 컨테이너/리눅스/iOS 백업 계열

## 한계 명시

- 유형이 "정의됨"이지 모든 런에서 실제 행이 나온다는 뜻은 아님.
  실제 Windows NTFS 이미지(BSH 등)로 런해서 유형별 행 수를 대조하는
  검증은 별도 라운드 필요.
- AXIOM의 xlsx는 실데이터 행, 우리의 일부 타입은 candidate/인벤토리
  수준 — 법정 등가물로 보지 말 것.
