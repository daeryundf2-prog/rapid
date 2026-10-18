# AXIOM Examine 기능 전수 대조표 — RapidTriage 현황 (2026-10-17)

출처: 사용자 제공 AXIOM 9.x 케이스의 처리 설정에 기록된 검색 항목(Computer 플랫폼 199종; Mobile/Cloud는 이 케이스에서 꺼져 있어 미평가)과 Examine 실행 관찰(`axiom-case-model-2026-10-17.md` §7). 상태는 코드 판독 기준이며 실이미지 런으로 재확인이 필요하다. 고객 데이터는 포함하지 않는다.

# AXIOM Examine 기능 동등성 매트릭스 — RapidTriage (2026-10-17)

범위: 읽기 전용 조사. 근거는 RapidTriage 소스(`rapidtriage/artifacts/**`, `core/artifact_taxonomy.py`, `core/artifact_domains.py`, `core/triage_rules/catalog/*.yaml`, `frontend/src/features/**`)와 계획 문서(`docs/plans/maestro-gap-review-2026-10-12.md`, `axiom-adoption-2026-10-17.md`, `docs/research/axiom-case-model-2026-10-17.md`). 고객 사건 데이터는 포함하지 않는다(아티팩트 이름·건수만 사용, 건수는 AXIOM 한 사건에서 관찰한 것으로 순위 산정 참고용).

**플랫폼 범위**: 제공된 검색 항목 목록에는 `Computer` 199개만 있다. Mobile/Cloud 플랫폼 항목은 목록에 없어 이 매트릭스에서 판정하지 않았다(RapidTriage 모바일·클라우드는 내보내기 정규화 중심이라 별도 조사 필요).

**판정 규칙**: `있음` = 해당 데이터를 행 단위로 파싱해 kind/artifact_type을 낸다(바운디드·검증 블로커가 붙어도 행이 나오면 있음, 비고에 명시). `부분` = 인벤토리·후보·내보내기 의존·일부 앱/플랫폼·다른 메커니즘으로 대체. `없음` = 구현 흔적을 찾지 못함. `정책상 제외` = 암호 크래킹·원격·외부 실행·비밀 추출. `해당 없음` = macOS 전용 등으로 Windows 컴퓨터 이미지 범위 밖(RapidTriage macOS 지원은 사용자 프로필·브라우저 기록·격리 이벤트·TCC·LaunchAgent 기준선).

## Table A — 검색 항목(199) → RapidTriage 상태

열: 플랫폼 | AXIOM 항목 | 그룹(임의 배정) | 상태 | RapidTriage 근거(kind/type/파일) | AXIOM 사건 건수

| 플랫폼 | AXIOM 항목 | 그룹 | 상태 | 근거 / 빠진 것 | 사건 건수 |
|---|---|---|---|---|---|
| Computer | $LogFile Analysis | 운영체제 | 부분 | ntfs-logfile-transaction-candidate(windows-filesystem, 바운디드 후보; 트랜잭션 재생 미검증) | 10587 |
| Computer | 360 Safe Browser | 웹 관련 | 없음 | Chromium 루트는 Chrome/Edge/Brave 3개만(CHROMIUM_BROWSER_ROOTS) | - |
| Computer | Adium | 커뮤니케이션 | 해당 없음 | macOS 메신저, 파서 없음(macOS 지원 수준: 사용자 프로필·브라우저·격리·TCC·LaunchAgent 기준선만) | - |
| Computer | AIM | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | AmCache | 운영체제 | 있음 | amcache-entry / amcache-driver-binary·driver-package·device-pnp·device-container·application-shortcut·device-census (windows-execution) | 4522 |
| Computer | Android Backups | 추가 소스 | 부분 | adb 백업(.ab) 루트 서명 감지만(mobile/roots.py); .ab 내부 해제·파싱은 확인 못 함. 데이터 트리는 android-app-data 인벤토리 | - |
| Computer | Apple Disk Images | 추가 소스 | 부분 | DMG는 증거 입력으로 추출만(core/archive_image.py, 엣지 케이스 미검증); 내부 아티팩트 별도 노드 없음 | 4 |
| Computer | Application Install States | 애플리케이션 사용량 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Ares | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | Audio | 미디어 | 있음 | media-audio (media 공급자: .wav/.mp3/.m4a/.aac/.flac/.ogg/.wma/.amr) | 675 |
| Computer | AutoRun Items | 운영체제 | 있음 | registry-persistence-entry / registry-run-key (windows-registry; 트리 reg-persistence) | 443 |
| Computer | Bebo | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Bing Toolbar | 웹 관련 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Bitcoin | 암호화·자격 증명 | 없음 | 지갑·암호화폐 파서 없음 | - |
| Computer | BitLocker Recovery Key | 암호화·자격 증명 | 부분 | 메모리 덤프 스캔 후보만(artifacts/memory.py BITLOCKER_RECOVERY_KEY_RE, 체크섬 검증); 디스크 상의 복구 키 파일 파서 없음 | - |
| Computer | Calendar Events (ics) | 이메일·캘린더 | 없음 | .ics 파서 없음(PST 내 약속도 네이티브 디코드 없음) | - |
| Computer | Carbonite | 클라우드 저장소 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Carved Archives (content not searched) | 사용자 정의(Custom) | 부분 | core/carving.py 바운디드 카빙(zip/7z/rar + jpeg/png/pdf/gif/sqlite); CLI·분석 워크벤치 '카빙'. 카빙 결과는 별도 분석 노드(아티팩트 트리와 분리) | 3072 |
| Computer | Carved Audio | 미디어 | 없음 | 카빙 시그니처에 오디오 없음(SIGNATURES: jpeg,png,pdf,zip,sqlite,gif,7z,rar) | 1064 |
| Computer | Chatroulette | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Chatstep | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Chrome | 웹 관련 | 있음 | browser-visit/-download/-search/-cookie/-login/-autofill/-credit-card/-bookmark/-session-tab/-extension(windows-browser 행 단위) + 캐시/세션/저장소 인벤토리(browser-cache-inventory 등). 캐시 항목 디코딩·Favicons 없음 | 783 |
| Computer | Chromium Based Browsers | 웹 관련 | 부분 | Chrome·Edge·Brave만 경로 하드코딩. Opera·Whale·Vivaldi·360 등 미지원 | - |
| Computer | Cortana | 운영체제 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Crypto Currency | 암호화·자격 증명 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | CSV Documents | 문서 | 있음 | 문서 후보(.csv/.tsv) 본문 추출·색인(core/files.py, docs). 아티팩트 kind 아님 | 281 |
| Computer | Default Browser | 운영체제 | 없음 | UrlAssociations/UserChoice 파서 없음 | 2 |
| Computer | Discord | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Dropbox | 클라우드 저장소 | 부분 | cloud-export 협업 SaaS 내보내기 정규화만(artifacts/cloud.py). 로컬 Dropbox DB 파서 없음 | - |
| Computer | DS_Store | 추가 소스 | 해당 없음 | macOS .DS_Store 파서 없음(macOS 지원 수준 낮음) | - |
| Computer | Edge | 웹 관련 | 있음 | Chrome과 동일 행 파서(Chromium Edge): 방문·다운로드·쿠키·로그인·북마크·확장·세션 탭·Top Sites·omnibox 바로가기 | 22055 |
| Computer | Edge/Internet Explorer | 웹 관련 | 부분 | 레거시 Edge/IE는 WebCacheV01.dat ESE 구조 인벤토리·문자열 후보만(webcachev01-ese-file). 테이블 행 디코딩 없음 | 8751 |
| Computer | EGG Archives | 사용자 정의(Custom) | 부분 | 아카이브 인벤토리 확장자 목록에 .egg/.alz 포함(core/files.py). EGG 내용 열거 네이티브 파서는 확인 못 함 | 33 |
| Computer | EML(X) Files | 이메일·캘린더 | 있음 | email-message (EML/EMLX 파싱, 헤더·본문 해시·첨부) | 624 |
| Computer | Emule | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | Encrypted Files | 암호화·자격 증명 | 부분 | 암호화 아카이브·PDF/HWP/OOXML 암호 플래그만(archive-encrypted-*, doc_text 플래그). 복호 없음 | 208 |
| Computer | Encryption / Anti-forensics Tools | 암호화·자격 증명 | 부분 | 방어 설정·ADS·타임스톰프 지표만. VeraCrypt/CCleaner/Eraser 등 설치·흔적 시그니처 DB 없음(메모리 스캔 문자열 일부) | 1 |
| Computer | Facebook | 커뮤니케이션 | 없음 | 브라우저 URL 힌트(SOCIAL_HOST_HINTS)로 호스트 분류만. 앱/웹 캐시 디코딩 없음 | - |
| Computer | Facebook Messenger | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Feature Usage | 애플리케이션 사용량 | 없음 | NTUSER FeatureUsage 파서 없음 | 114 |
| Computer | File Signature Mismatch | 사용자 정의(Custom) | 있음 | file-signature-mismatch (windows-filesystem; 트리 fs-mismatch). AXIOM의 5개 유형 분리는 없음 | 286256 |
| Computer | File System Information | 운영체제 | 부분 | 파티션/fsstat 워크플로 요약(e01-partition-workflow)만. 볼륨 부트 레코드 행 아티팩트 없음 | 4 |
| Computer | Firefox | 웹 관련 | 있음 | Places 방문/다운로드(firefox_places_history) + 쿠키·로그인·세션 복원·확장 인벤토리. FormHistory·캐시 디코딩 없음 | 1473 |
| Computer | Flickr | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Gigatribe | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | Gmail | 이메일·캘린더 | 부분 | 웹메일 호스트 힌트(EMAIL_HOST_HINTS)·개인메일 전송 규칙(email.bcc_self_or_personal)·Takeout 내보내기 cloud-mail. 브라우저 캐시/웹메일 페이지 복원 없음 | - |
| Computer | GMX Webmail | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Google Analytics | 웹 관련 | 없음 | 쿠키(__utm/_ga) 해석 없음(쿠키 값은 정책상 목록화만) | - |
| Computer | Google Docs | 클라우드 저장소 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Google Drive | 클라우드 저장소 | 부분 | DriveFS 동기화 DB 바운디드 행(desktop-cloud-sync-db/-row-candidate) + Takeout 내보내기(cloud-file) | 1 |
| Computer | Google Maps | 위치·여행 | 부분 | Takeout 위치 JSON(cloud-location)만. 브라우저·앱 지도 검색 파서 없음 | 2 |
| Computer | Google Talk | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Google Toolbar | 웹 관련 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Google+ | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Hangul Word Processor | 문서 | 있음 | HWP/HWPX 본문·PrvText 추출(core/doc_text.py), 암호 HWP 플래그, document-metadata-risk | 5 |
| Computer | Hotmail Webmail | 이메일·캘린더 | 없음 | 개인 메일 도메인 규칙 외 웹메일 복원 없음 | - |
| Computer | Hushmail | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | iChat | 커뮤니케이션 | 해당 없음 | macOS 구형 메신저. CHAT_APP_PROFILES alias만 | - |
| Computer | ICQ | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | IME Suggestions | 운영체제 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | iMessage | 커뮤니케이션 | 부분 | iOS 백업/모바일 내보내기의 sms.db 계열만(mobile-message, 별칭 매칭). macOS chat.db 전용 파서 없음 | - |
| Computer | Instagram | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Installed Programs | 애플리케이션 사용량 | 있음 | windows-installed-program (Uninstall 레지스트리) + uwp-package (트리 os-installed) | 334 |
| Computer | iOS Backups | 추가 소스 | 있음 | ios-backup-source/-file/-metadata, ios-keychain-inventory (mobile-export). 암호화 백업은 목록화만 | - |
| Computer | IP Addresses - Audio/Video Calls | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | 5 |
| Computer | ISO Files | 추가 소스 | 부분 | ISO는 증거 입력으로 추출(core/archive_image.py). 케이스 내 ISO 파일의 별도 아티팩트 없음(파일 인벤토리 압축 분류) | - |
| Computer | Jump Lists | 운영체제 | 있음 | jumplist-automatic / jumplist-custom / jumplist-entry (windows-recent-files). DestList MRU·계정 메타 완전 디코딩은 블로커 | 28 |
| Computer | KakaoTalk | 커뮤니케이션 | 부분 | kakaotalk-windows-* (앱 DB 인벤토리·사용자 ID·키 재료 후보; 메시지 본문 복호는 별도 CLI kakaotalk-decrypt), macOS는 kakaotalk-macos-*. 공유 사진 행 아티팩트 없음 | 2 |
| Computer | Keyword Searches | 운영체제 | 있음 | 키워드 팩·통합 검색(search index)·저장 검색으로 대체(core/keyword_packs, /search). 아티팩트 kind 아님 | 6 |
| Computer | Known DLLs | 운영체제 | 없음 | 구현·분류 흔적 없음 | 32 |
| Computer | Latent Wireless | 연결된 장치 | 부분 | wifi-profile(WLAN 프로필 XML) + WLAN-AutoConfig 이벤트 탐지(RT-EVTX-WLAN-AUTOCONFIG). 레지스트리 무선 연결 이력 없음 | - |
| Computer | Limerunner | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | Limewire / Frostwire | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | LINE | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | LinkedIn | 커뮤니케이션 | 없음 | 브라우저 호스트 분류만 | - |
| Computer | LNK Files | 운영체제 | 있음 | recent-shortcut / shell-shortcut (+invalid-content); 트리 exec-lnk | 1543 |
| Computer | LogMeIn | 연결된 장치 | 없음 | 원격 제어 제품 목록(windows/system.py)에 AnyDesk·TeamViewer·RustDesk·Chrome Remote Desktop만 | - |
| Computer | Luckywire | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | Lync / Office Communicator | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Magnet Web Page Saver | 웹 관련 | 없음 | AXIOM 전용 수집물 | - |
| Computer | Mail.ru | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Mailinator | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Malware/Phishing URLs | 웹 관련 | 부분 | URL 위험 분류 없음. IOC 스캐너·TI enrichment(/indicators)·browser.dl_dangerous 규칙으로 부분 대응. E2 url_classes.yaml 계획 | 23 |
| Computer | MBOX E-mails | 이메일·캘린더 | 있음 | email-message (MBOX 바운디드 200통, 스레딩·헤더) | 14 |
| Computer | McAfee Logs | 애플리케이션 사용량 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Microsoft Excel | 문서 | 있음 | XLS/XLSX 본문·메타 추출(doc_text, document-metadata-risk) | 442 |
| Computer | Microsoft Office | 문서 | 부분 | Office 문서 본문·메타만. Backstage 항목·Office 연결 계정 없음 | 164 |
| Computer | Microsoft Office 365 MRU | 문서 | 부분 | 레지스트리 RecentDocs/OpenSavePidlMRU(registry-user-activity)만. Office File/Place MRU 전용 파서는 확인 못 함 | - |
| Computer | Microsoft PowerPoint | 문서 | 있음 | PPT/PPTX 본문·메타 추출 | 34 |
| Computer | Microsoft Sticky Notes | 문서 | 있음 | sticky-note / sticky-note-recovery-candidate (generic-documents) | 11 |
| Computer | Microsoft Teams | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES). M365 감사·Teams 내보내기(cloud-message)는 정규화 | - |
| Computer | Microsoft Word | 문서 | 있음 | DOC/DOCX 본문·메타 추출, 잠금 파일(document-lock-owner) | 157 |
| Computer | mIRC | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Most Recently Used | 운영체제 | 있음 | registry-user-activity (RecentDocs·OpenSavePidlMRU·LastVisitedPidlMRU·TypedPaths·MUICache 등) | 216 |
| Computer | MSN Plus! | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | MUICache | 운영체제 | 있음 | registry.py MUICache 분류(registry-user-activity; 약한 실행 지표) | 463 |
| Computer | MySpace | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Network Interfaces | 운영체제 | 있음 | windows-network-interface (windows-registry) | 2 |
| Computer | Network Profiles | 운영체제 | 없음 | NetworkList 레지스트리 파서 없음(상관 대상으로만 언급) | 9 |
| Computer | Network Share Information | 운영체제 | 없음 | 공유·매핑 드라이브 파서 없음(LNK 네트워크 대상 규칙 lnk.network_target만) | 10 |
| Computer | Network Usage | 운영체제 | 있음 | srum-network-usage (+srum-row-candidate, ESE 네이티브 디코드) | 8392 |
| Computer | Notification Center | 운영체제 | 있음 | activities-notifications-uwp / notification-database (wpndatabase.db; 트리 os-notifications) | 213 |
| Computer | NTFS Timestamp Mismatch | 운영체제 | 부분 | mft-record 위험 플래그 mft-sia-fna-timestamp-mismatch + 규칙 ntfs.si_before_fn 등. 별도 아티팩트 노드·SI/FN 8열 표 없음 | 903 |
| Computer | Numbers | 문서 | 해당 없음 | Apple iWork 파서 없음(macOS 지원 수준 낮음) | - |
| Computer | Omegle | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | OneDrive | 클라우드 저장소 | 부분 | OneDrive 동기화 DB 바운디드(desktop-cloud-sync-db) + M365 감사 내보내기. SyncEngine 전체 디코딩 없음 | - |
| Computer | ooVoo | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | OpenOffice Calc | 문서 | 있음 | ODS 본문 추출(core/files.py·docs 확장자 지원) | - |
| Computer | OpenOffice Impress | 문서 | 있음 | ODP 본문 추출 | - |
| Computer | OpenOffice Writer | 문서 | 있음 | ODT 본문 추출 | 4 |
| Computer | Opera | 웹 관련 | 없음 | Chromium 루트 목록에 Opera 없음 | - |
| Computer | Operating System Information | 운영체제 | 있음 | windows-os-version / windows-computer-name / windows-control-set / windows-os-account-summary | 1 |
| Computer | Outlook | 이메일·캘린더 | 부분 | PST/OST/MSG 바운디드 문자열 인벤토리(email-mailbox) + 외부 libpff/readpst 래퍼(artifacts/email_external.py). 네이티브 MAPI 디코드·약속/연락처 없음 | 23460 |
| Computer | Outlook Web App | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Outlook Webmail | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Pages | 문서 | 해당 없음 | Apple iWork 파서 없음(macOS 지원 수준 낮음) | - |
| Computer | Paltalk | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | PDF | 문서 | 있음 | PDF 본문·메타·암호/증분 업데이트 규칙(doc_text, documents.pdf_incremental_update) | 5073 |
| Computer | Photoshop Files | 미디어 | 부분 | 편집 도구 메타데이터 힌트만(media.py photoshop-editing-metadata). PSD 레이어·본문 파서 없음 | 327 |
| Computer | Pictures | 미디어 | 있음 | media-image (EXIF·GPS·pHash·갤러리·썸네일 보기). Skin tone·PhotoDNA 없음 | 223519 |
| Computer | Pidgin | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Pornography URLs | 웹 관련 | 없음 | URL 분류 없음(E2 url_classes 계획; 도메인 목록 출처 필요) | - |
| Computer | Potential Browser Activity (Incl. Private/ Incognito URLs) | 웹 관련 | 없음 | 미할당·메모리 URL 카빙 없음(browser.incognito_gap은 간접 규칙) | 85106 |
| Computer | PowerShell | 운영체제 | 있음 | powershell-history-command (ConsoleHost_history.txt) + 이벤트 4103/4104·RT-EVTX-PS-ENCODED | 1 |
| Computer | Prefetch Files | 운영체제 | 부분 | prefetch-file / prefetch-reference (실행 횟수·마지막 실행 오프셋 디코드). MAM 압축 해제·볼륨 테이블·8회 실행 시각 미완(P3) | 2483 |
| Computer | Program Compatibility Assistant Records | 애플리케이션 사용량 | 없음 | PcaAppLaunch.dic·PcaGeneralDb 파서 없음 | - |
| Computer | QQ | 커뮤니케이션 | 없음 | Tencent QQ 파서 없음(core/kakaotalk.py의 QQ 문자열은 무관) | 27 |
| Computer | QuickBooks Files | 문서 | 없음 | 구현·분류 흔적 없음 | 13 |
| Computer | RealPlayer | 미디어 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Rebuild Webpages | 웹 관련 | 없음 | 웹페이지 재구성 없음(캐시 디코딩 부재) | 294 |
| Computer | Rebuilt Desktops | 운영체제 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Recycle Bin | 운영체제 | 있음 | recycle-bin-entry ($I 파싱) | 52 |
| Computer | Remote Desktop Protocol | 연결된 장치 | 있음 | rdp-config / rdp-destination / rdp-cache-file(비트맵 캐시) + 이벤트 RT-EVTX-RDP-LOGON/SESSION. 방향 열은 E2 계획 | 244 |
| Computer | RTF Documents | 문서 | 있음 | RTF 본문 추출(core/docs.py) | 3110 |
| Computer | Safari | 웹 관련 | 부분 | macOS 전용(macos-browser-history-downloads, 격리 이벤트 상관). Windows용 Safari 프로필 미지원 | 24 |
| Computer | Scheduled Tasks | 운영체제 | 있음 | task-scheduler-task (작업 XML; 트리 os-tasks) | 243 |
| Computer | Second Life | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Services | 운영체제 | 있음 | windows-service-config (레지스트리 서비스) + 이벤트 서비스 설치 탐지 | 711 |
| Computer | Shareaza | 커뮤니케이션 | 없음 | P2P 파서 없음 | - |
| Computer | SharePoint | 클라우드 저장소 | 부분 | M365/SharePoint 내보내기 정규화(cloud-file 등). 로컬 캐시 파서 없음 | - |
| Computer | Shellbags | 운영체제 | 있음 | shellbag-entry / shellbag-key / shellbag-hive-summary (windows-shellbags) | 6087 |
| Computer | Shim Cache | 운영체제 | 있음 | shimcache-entry (windows-execution) | 1024 |
| Computer | Signal | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Sina Weibo | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Skype | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Slack | 커뮤니케이션 | 부분 | Slack 워크스페이스 내보내기(users.json+channels.json) cloud-message 정규화 + 모바일 내보내기. Windows 데스크톱 캐시 파서 없음 | - |
| Computer | SRUM | 운영체제 | 있음 | srum-database-file / srum-network-usage / srum-row-candidate / srum-table-candidate / srum-database-pivot (앱 리소스·에너지 마커 포함, 전용 정규화 열은 일부) | 36456 |
| Computer | SSH Keys | 암호화·자격 증명 | 부분 | Linux linux-ssh-authorized-key / known-host만. Windows ~/.ssh·PuTTY 파서 없음 | - |
| Computer | Startup Items | 운영체제 | 부분 | registry-run-key 자동 실행. 시작 프로그램 폴더·StartupApproved 없음 | 21 |
| Computer | TeamViewer | 연결된 장치 | 있음 | third-party-remote-control-artifact (TeamViewer/AnyDesk/RustDesk/CRD 로그 세션 프로필) | - |
| Computer | Telegram | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Text Documents | 문서 | 있음 | txt/log/ini/xml 등 문서 후보 본문 색인 | 4724 |
| Computer | Timezone Information | 운영체제 | 있음 | windows-timezone | 1 |
| Computer | TorChat | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Torrent URLs | 웹 관련 | 없음 | URL 분류 없음 | - |
| Computer | Trillian | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Twitter | 커뮤니케이션 | 부분 | 모바일 내보내기 DM 프로필(X/Twitter)만. 웹·데스크톱 없음 | - |
| Computer | USB Devices | 연결된 장치 | 있음 | windows-usb-device / registry-usb / windows-mounted-device / usb-setupapi-device-install-candidate + 이벤트 RT-EVTX-USB-* | 27 |
| Computer | Usenet Binary Files | 미디어 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | User Accounts | 운영체제 | 있음 | windows-sam-account(+candidate) / windows-sam-group / windows-account-lifecycle / windows-user-profile / windows-os-account-summary. 로그인 수·비활성·자동 로그온 열은 E2 계획 | 48 |
| Computer | UserAssist | 운영체제 | 있음 | userassist-entry | 41 |
| Computer | UsnJrnl | 운영체제 | 부분 | usn-record / usn-journal-file (내보내기 + 바운디드 네이티브). 전체 리플레이·상관은 로드맵 | 363950 |
| Computer | Viber | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Videos | 미디어 | 있음 | media-video (컨테이너 메타, 동영상 큐/프레임, frametrace 가져오기) | 1112 |
| Computer | Virtual Machines | 추가 소스 | 부분 | VHD/VHDX/VMDK 등은 증거 입력으로만(virtual-disk-workflow). 게스트 VM 구성·스냅샷 아티팩트 없음 | - |
| Computer | VK | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | VLC Media Player | 미디어 | 없음 | VLC 최근 재생 목록 파서 없음 | - |
| Computer | Volatile Artifacts | 운영체제 | 부분 | memory-process/-cmdline/-network/-malfind(Volatility 출력 정규화) + 덤프 문자열 스캔. 네이티브 프로세스 재구성은 연기 | - |
| Computer | Web Video Fragments | 웹 관련 | 없음 | 구현·분류 흔적 없음 | 1 |
| Computer | WebKit | 웹 관련 | 없음 | WebKit 브라우저 카빙 없음 | 2112 |
| Computer | Webpage Recovery | 웹 관련 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | WeChat | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | WhatsApp | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Wickr Me | 커뮤니케이션 | 부분 | Windows 데스크톱 앱 DB 파서 없음. 모바일 내보내기(루트 서명 필요) 안에서만 mobile-message/mobile-chat-database로 처리(CHAT_APP_PROFILES) | - |
| Computer | Windows Defender Logs | 애플리케이션 사용량 | 있음 | defender-support-log(MPLog) / defender-policy-artifact + Defender 이벤트 탐지(RT-EVTX-DEFENDER-*) | 3 |
| Computer | Windows Event Logs | 운영체제 | 있음 | eventlog-event / -file / -summary / -record-candidate(슬랙 복구) / -logon-session / -detection(30여 규칙). 네이티브 EVTX BinXML | 590810 |
| Computer | Windows Event Logs - Firewall Events | 운영체제 | 있음 | eventlog-event 중 Windows Firewall 채널 + RT-EVTX-FIREWALL-RULE-CHANGE, 방화벽 로그 firewall-log | 456 |
| Computer | Windows Event Logs - Networking Events | 운영체제 | 부분 | WLAN-AutoConfig·BITS-Client 탐지만. 전용 네트워킹 이벤트 분류 노드 없음 | - |
| Computer | Windows Event Logs - Office Alert Events | 운영체제 | 부분 | OAlerts 채널은 일반 EVTX 행으로만 포함. 전용 분류·규칙 없음 | 3662 |
| Computer | Windows Event Logs - Scheduled Task Events | 운영체제 | 있음 | eventlog-event + RT-EVTX-SCHEDULED-TASK, eventlog.task_created | 10618 |
| Computer | Windows Event Logs - Script Events | 운영체제 | 있음 | PowerShell 4103/4104 + RT-EVTX-PS-ENCODED, eventlog.encoded_powershell | 484 |
| Computer | Windows Event Logs - Service Events | 운영체제 | 있음 | RT-EVTX-SERVICE-INSTALLED, eventlog.new_service | 2122 |
| Computer | Windows Event Logs - Storage Device Events | 운영체제 | 있음 | RT-EVTX-USB-DEVICE / RT-EVTX-USB-PROVIDER (Kernel-PnP·USBSTOR 피벗) | 46 |
| Computer | Windows Event Logs - System Events | 운영체제 | 있음 | RT-EVTX-LOG-CLEARED / SYSTEM-TIME-CHANGED / AUDIT-POLICY-CHANGED | 44 |
| Computer | Windows Event Logs - User Events | 운영체제 | 있음 | RT-EVTX-FAILED-LOGON/ACCOUNT-*/EXPLICIT-CREDS/PRIVILEGED-LOGON + eventlog-logon-session. Subject/Target 분리 열은 부분 | 6658 |
| Computer | Windows Event Logs - User PNP Events | 운영체제 | 있음 | UserPnp/Kernel-PnP 이벤트 피벗(eventlog-usb-device-events) | 22 |
| Computer | Windows Live Messenger / MSN Messenger® | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Windows Logon Banner | 운영체제 | 없음 | LegalNotice 레지스트리 파서 없음 | - |
| Computer | Windows Mail | 이메일·캘린더 | 없음 | Windows Mail 스토어 파서 없음(EML 내보내기만) | - |
| Computer | Windows Search | 운영체제 | 있음 | windows-search-index-entry / windows-search-db / windows-search-edb-* (Windows.edb 바운디드 ESE) | 29555 |
| Computer | Windows Stored Credentials | 암호화·자격 증명 | 정책상 제외 | Credential Manager·DPAPI 복호·추출은 비밀 취급 정책상 범위 밖(목록화 원칙, BROWSER_SECRET_HANDLING 선례). 전용 파서도 없음 | - |
| Computer | Windows Timeline | 운영체제 | 있음 | activities-cache-db (ActivitiesCache.db 행) | 298 |
| Computer | WordPerfect Files | 문서 | 없음 | 구현·분류 흔적 없음 | 2 |
| Computer | World of Warcraft | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Xbox Internet Explorer History | 웹 관련 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Yahoo! Messenger | 커뮤니케이션 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Yahoo! Webmail | 이메일·캘린더 | 없음 | 구현·분류 흔적 없음 | - |
| Computer | Your Phone | 연결된 장치 | 없음 | YourPhone DB 파서 없음 | 2 |
| Computer | Zoom | 커뮤니케이션 | 부분 | Zoom은 협업 SaaS 내보내기 서비스 목록(cloud.py) 정규화만. 데스크톱 로그·DB 파서 없음 | - |


## Table B — AXIOM UI/워크플로 기능 → RapidTriage 상태

상태 표기는 Table A와 같다. "계획" 열은 진행 중 라운드(E1/E2/E3 = `docs/plans/axiom-adoption-2026-10-17.md`; 브랜치 `feat/axiom-e1-case`·`feat/axiom-e2-derived`·`feat/axiom-e3-review`가 존재, 병합 전)와 `maestro-gap-review-2026-10-12.md` 단계(P1~P5)를 가리킨다. P1(분석 워크벤치)·P4 일부(트리 도메인)·검색 S1·파서 품질 r1/r2는 main에 병합됨(프로젝트 메모 기준). 해당 판정은 코드 존재 확인이며 실행 QA 결과가 아니다.

### B1. 탐색기(Explorer)

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 케이스 대시보드 | 있음 | `features/dashboard`(접수 단계 카드: 런 요약·공개 고지·타임라인 제외 등). 사건 정보·증거 목록·처리 설정·처리 문제·메모 카드는 없음 | E1 |
| 레지스트리 탐색기 | 부분 | 트리 `reg-keytree`(registry-key-tree-node), 하이브 요약·셀 복구 노드. 네이티브 키/값 디코딩·트리 탐색 UI는 바운디드(P3 대상) | P3 |
| 미디어 탐색기(미디어 구축) | 부분 | 썸네일 보기·이미지 갤러리·pHash 유사 묶음·EXIF GPS 메타. 미디어 범주·스킨톤·"미디어 탐색기 구축" 배치 단계 없음 | E3(흐리게·관련 미디어) |
| 아티팩트 탐색기 | 있음 | 도메인 16개 트리(`features/tree/domains.ts`) + 계열 카탈로그 17개 YAML 열 + 가상 그리드 | — |
| 커넥션(연결) 탐색기 / 커넥션 빌드 | 없음 | 교차 케이스 상관(CLI/분석 노드 `cross-case`), 모바일 상관 요약만. 엔티티 연결 그래프 뷰 없음 | E2(통합 표가 기반, 그래프 뷰는 미계획) |
| 타임라인 탐색기 / 타임라인 구축 | 있음 | `/timeline`, `/timeline-histogram`, 타임라인 컬렉션. 시각 종류 칩(ts_kind). 시각 필드 매핑 `TIMELINE_FIELD_MAP`(미매핑 유형은 요약에 명시) | — |
| 파일 시스템 탐색기 | 부분 | `files` 컬렉션(인벤토리·NTFS 조인·삭제 상태·소스 이미지 경로 일부), 범주 노드. 폴더 계층 트리·슬랙/미할당 공간 노드 없음 | P1(행 메타), 미계획(계층 트리) |

### B2. 결과 뷰

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 열(Column) 뷰 | 있음 | `DataGrid`(열 머리 필터 `ColumnFilterRow`, 승격 필드 `usePromotedFields`) | — |
| 축소판(Thumbnail) 뷰 | 있음 | `views/ThumbnailView`(파일·media-image·synthetic-media 노드) | E3(흐리게) |
| 대화(Chat) 뷰 | 있음 | `views/ChatView`(kakaotalk-windows/-macos/mobile-export 노드 한정) | — |
| 히스토그램 뷰 | 있음 | `views/HistogramView`(타임라인·아티팩트·파일·문서·검색 노드) | — |
| 히스토그램 기준선 저장/비교 | 없음 | — | E3 |
| 클래식(격자 위·세부 아래) 뷰 | 없음 | 세부는 뷰어 시트/팝아웃(`viewer/popout`) | E3 |
| 행(카드) 뷰 | 없음 | — | 미계획(U-F8 일부: 혼합 kind 라벨 2줄 셀) |
| 세계지도 뷰 / 지도 새로 고침 | 없음 | EXIF GPS는 메타 필드로만(media exif_gps_map_pivot 메타), 지도 UI 없음 | 미계획 |
| 행 좌측 태그 스트라이프 | 부분 | 리뷰 상태 칩(`reviewMap`). 스트라이프 형태는 U-F8 계획 | viewer-families U-F8 |

### B3. 필터 바·검색

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 증거 필터 | 부분 | 런 단위 선택(케이스 › 증거 구조 없음) | E1 |
| 아티팩트 필터 | 있음 | 트리 노드·`artifact_type=` 서버 필터·유형 열 필터 | — |
| 콘텐츠 유형 필터 | 부분 | 확장자·파일 범주 필터(`filterModel`). 의미 태그(content type) 없음 | E2(`semantic:` 태그) |
| 날짜/시간 필터(절대) | 있음 | 시간 범위 + 최근 3개 조건 기억(`conditionMemory`, localStorage) | — |
| 날짜/시간 필터(상대) | 없음 | 절대 범위만 | 미계획 |
| 태그/주석 필터 | 있음 | 태그·리뷰 상태 필터 | E3(사용자 정의 태그 건수) |
| 프로필 필터 | 부분 | 런 모드(`fraud/hacking/recovery/seizure`)·사용자 프로필 귀속 필드 | — |
| 부분 결과(Partial results) 필터 | 없음 | 행 완전성 개념 없음(AXIOM importance 열 기반) | 미계획 |
| 키워드 목록 필터 | 부분 | 키워드 팩(`/keyword-packs`)·통합 검색 옵션·저장 검색 | — |
| 스킨톤·미디어 범주·VICS | 없음 | 해시 집합 API(`/api/hash-sets`, `core/search_index/hashsets.py`)만. 스킨톤·Project VIC 연동 없음 | 미계획(P5 밖) |
| 키워드 검색 + 고급 검색 | 있음 | FTS5 통합 검색 + 질의 문법(`search_index/query.py`), NFC/casefold, 문서 인덱스 | — |
| 필터 세트 저장/관리 | 부분 | 서버 저장 검색(`/search/saved`) + 브라우저 저장 조건(`SAVED_CONDITIONS_MAX=10`). 케이스 전역 관리 UI 없음 | — |

### B4. 검토(Tags/Notes)

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 시스템 태그(북마크/증거/관심) | 부분 | 고정 4종(관련/재검토/제외/보고서 포함) + `북마크` 문자열 태그 | E3 |
| 사용자 정의 태그(색·단축키) | 없음 | `review_mark.tags_json` 자유 문자열만 | E3 |
| 같은 해시 행에 태그 전파 | 없음 | — | E3(`propagate_by_hash`) |
| 메모(작성자·시각·삭제 표시) | 부분 | 케이스 메모 PUT(`/case-notes`), 세션 메모. 작성자·이력 없음 | E1(케이스 메모), E3(행 메모) |
| 태그·주석 병합(케이스 간) | 없음 | — | 미계획 |

### B5. 파일·도구·프로세스 메뉴

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 내보내기/보고서 생성 | 있음 | `/case-report`(MD/HTML/DOCX/PDF), 리뷰어 번들, 제출 매니페스트, 검증 패키지; 한국어 보고서 | — |
| 그리드 선택 CSV/엑셀 내보내기(고정 꼬리 열) | 부분 | 추출(`/extract` ≤2 GB zip)·통합 타임라인 내보내기(JSON, `core/timeline_export.py`). 그리드 선택 CSV·꼬리 열(소스·위치·복구 방법·증거 번호) 없음 | E3 |
| 내보내기/보고서 설정 | 부분 | 보고서 다이얼로그 옵션(`ReportDialog`) | — |
| 휴대용 케이스 생성/병합 | 부분 | 리뷰어 번들(원본 이미지 미포함), `/runs/import`, 케이스 카탈로그 `add-run`. 병합 없음 | 미계획 |
| Magnet REVIEW 업로드 | 정책상 제외 | 외부 서비스 전송(데이터 반출) — 제한 문서·보안 모델 | — |
| 날짜/시간 형식·시간대 설정 | 부분 | 시간대 표시·UTC/로컬 쌍(`ts_kind`), 설정 화면 일부 | — |
| 미디어 범주·키워드·프로필·태그 관리 | 부분 | 키워드 팩 관리 O, 태그/범주/프로필 관리 UI 없음 | E3(태그) |
| 사진 비교 / 유사 사진 찾기 | 부분 | pHash 유사 묶음·`media.phash_dup_cross_folder`·갤러리(duplicate_content_groups). 두 장 대비 비교 UI 없음 | E3(관련 미디어 배지) |
| 증거 추가/제거 | 없음 | 증거는 런 생성 시 1개 | E1(`POST /cases/{id}/evidence`) |
| 카빙 재처리 | 있음 | 분석 노드 `카빙`(바운디드 시그니처 8종) | P1 완료 |
| 키워드 추가(처리 후 재검색) | 있음 | 키워드 팩·통합 검색 즉시 재질의(처리 재실행 불필요) | — |
| 해시로 사진·비디오 분류 / 미디어 분류 해시 집합 업데이트 | 부분 | 해시 집합 가져오기(`hash-sets`)·`/search/hashes`. 범주 라벨(VICS) 없음 | 미계획 |
| CPS 내보내기 | 없음 | 아동 보호 시스템 연동, 기업·법무 범위 밖 | 계획 없음 |
| Magnet.AI 채팅 분류·사진 범주화 | 없음 | 규칙 기반 시각 분류·OCR/번역 힌트만(`known-limitations`: 힌트일 뿐) | 미계획 |
| 처리 옵션 스냅샷·처리 문제 집계 | 부분 | `rapidtriage-run-summary.json`(profile/safety/resource_caps), `warnings` 평문 | E1 |
| 그룹/태스크 단위 진행·부분 완료·개별 취소 | 부분 | 단계·공급자 진행, 런 취소/재시도. 계획 문서 `run-model-p2` 있으나 `rapidtriage-run-plan.json`/그룹 취소 구현 흔적 없음 | P2 |
| 외부 도구 연동(원격 수집·외부 프로그램 실행·암호 해독) | 정책상 제외 | 제한 문서: remote-agent·암호 크래킹·외부 직접 실행 연기/제외 | — |

### B6. 세부 정보 창·썸네일 막대

| AXIOM 기능 | 상태 | RapidTriage 대응 / 빠진 것 | 계획 |
|---|---|---|---|
| 세부: 소스(경로·파티션) | 있음 | 뷰어 메타 탭 출처(경로·오프셋·런 id), `evidenceInfo.ts` | U-F8 꼬리 섹션 |
| 세부: 복구 방법(파싱/카빙) | 부분 | `recovery_method`(parsed|carved|recovered|unknown)는 특이사항 API 출처 정보(`api/app/triage_flags.py`)에서만 파생. 그리드 공통 열 아님 | E3 CSV 꼬리 열 / A3 |
| 세부: 삭제된 출처 | 부분 | 파일 인벤토리 삭제 상태(NTFS 조인), 행 공통 아님 | A3 |
| 세부: 위치(오프셋) | 부분 | 소스 뷰어 헥스 오프셋·`source_offset` 일부 kind | A3 |
| 세부: 증거 번호 | 없음 | 증거 번호 개념 없음 | E1 |
| 세부: 원본 아티팩트 링크 | 부분 | 피벗(`viewer/pivots.ts`)·같은 출처의 다른 행 명령(`navigate.rows-for-source`). 파생 표→원본 링크는 없음 | E2 |
| 미디어 흐리게·음향·리마인더 | 없음 | — | E3(흐리게만) |
| 미리 보기(확대/축소)·OCR | 있음 | `ImageView`(OCR·번역)·`MediaView`·`DocumentView`·`EmailView`·헥스·SQLite 뷰 | — |

### B7. 상세 결과(Refined Results, 파생 아티팩트)

AXIOM 사건에서 관찰한 14종(건수: 로컬 접근 파일 5,341 · 사람 식별자 3,680 · Google 검색 399 · 소셜 URL 348 · 재구성 웹페이지 294 · 파싱된 검색어 164 · 클라우드 URL 141 · 장치 식별자 140 · 암호·토큰 131 · 구인·광고 URL 126 · 웹채팅 URL 87 · 사용자 계정 38 · 악성/피싱 URL 23 · Facebook URL 16). 파생 계층 자체가 RapidTriage에는 없다(`axiom-case-model` §2 "가장 큰 구조 격차"). E2가 `core/derived/`에 6개 표를 만든다.

| AXIOM Refined Result | 상태 | RapidTriage 현재 | 계획 |
|---|---|---|---|
| Identifiers - People | 없음 | 계열별 열에 흩어짐(메신저 발화자·메일 주소·SAM 사용자) | E2 `people` |
| Identifiers - Device | 없음 | USB·장치 계열에 분산 | E2 `devices` |
| Locally Accessed Files and Folders | 없음 | LNK·Jump List·Shellbags·MRU를 각각 열람, 통합 표 없음 | E2 `paths` |
| Google Searches / Parsed Search Queries | 부분 | `browser-search`(검색어 행), `browser.search_sensitive` 규칙, 레지스트리 검색어. 통합 표 없음 | E2(`search_term` 태그) |
| Social Media / Classifieds / Web Chat / Cloud / Malware URLs / Facebook URLs | 부분 | 브라우저 호스트 힌트 상수(SOCIAL/CLOUD/EMAIL/SEARCH_HOST_HINTS) + P4 U-P4-5 호스트군 계획. URL 분류 표·악성 도메인 목록 없음 | E2 `urls`(url_classes.yaml) |
| Rebuilt Webpages | 없음 | 캐시 디코딩 부재 | 미계획 |
| Passwords and Tokens | 부분(정책) | 브라우저 로그인·쿠키는 인벤토리·마스킹만(비밀 값 비추출 정책). 통합 표는 가린 값+길이+해시만 저장 계획 | E2 `credentials` |
| User Accounts (통합) | 부분 | SAM/프로필/계정 수명 계열 분산, 통합 표 없음 | E2(계정 열 보강) |
| Email Attachments (통합) | 없음 | 메일 계열별 첨부 필드 | E2 `attachments` |

### B8. AXIOM이 못 한 것(재현하지 않는 항목, 참고)

AXIOM 열람 관찰(`axiom-case-model` §7.3)에서 접근성 이름 부재·격자 셀 단위 Tab·영문 원명 순 정렬·상태 전환 공백·대표 값만 있는 제목이 확인됨. RapidTriage는 a11y 체크리스트(`docs/console-a11y-checklist.md`)·DisabledReason·한국어 정렬 규칙으로 막는 방침이며, 이 매트릭스는 그 준수 여부를 판정하지 않았다.

## 3. 집계

### 3.1 플랫폼별

| 플랫폼 | 항목 | 있음 | 부분 | 없음 | 정책상 제외 | 해당 없음 |
|---|---|---|---|---|---|---|
| Computer | 199 | 59 | 51 | 83 | 1 | 5 |
| Mobile | (목록 없음) | - | - | - | - | - |
| Cloud | (목록 없음) | - | - | - | - | - |

가중치 없는 동등성: 있음 59/199 = 30%, 있음+부분 110/199 = 55%. 해당 없음(5)·정책상 제외(1)를 분모에서 빼면 있음 31%.

### 3.2 그룹별(그룹은 AXIOM 15그룹에 맞춘 임의 배정, 검색 항목 목록에는 그룹 정보가 없음)

| 그룹 | 항목 | 있음 | 부분 | 없음 | 정책상 제외 | 해당 없음 | 사건 건수 합(참고) |
|---|---|---|---|---|---|---|---|
| 커뮤니케이션 | 54 | 0 | 17 | 35 | 0 | 2 | 34 |
| 운영체제 | 49 | 32 | 9 | 8 | 0 | 0 | 1,083,269 |
| 웹 관련 | 21 | 3 | 4 | 14 | 0 | 0 | 120,622 |
| 문서 | 18 | 12 | 2 | 2 | 0 | 2 | 14,020 |
| 이메일·캘린더 | 14 | 2 | 2 | 10 | 0 | 0 | 24,098 |
| 미디어 | 8 | 3 | 1 | 4 | 0 | 0 | 226,697 |
| 암호화·자격 증명 | 7 | 0 | 4 | 2 | 1 | 0 | 209 |
| 추가 소스 | 6 | 1 | 4 | 0 | 0 | 1 | 4 |
| 애플리케이션 사용량 | 6 | 2 | 0 | 4 | 0 | 0 | 451 |
| 클라우드 저장소 | 6 | 0 | 4 | 2 | 0 | 0 | 1 |
| 연결된 장치 | 6 | 3 | 1 | 2 | 0 | 0 | 273 |
| 사용자 정의(Custom) | 3 | 1 | 2 | 0 | 0 | 0 | 289,361 |
| 위치·여행 | 1 | 0 | 1 | 0 | 0 | 0 | 2 |

### 3.3 사건 건수 가중(참고)

AXIOM 사건 건수가 있는 항목만 합산(하위 아티팩트를 항목에 묶음). 건수 크기는 중요도가 아니라 노이즈 양이므로 순위 근거로 쓰지 않았다.

| 상태 | 건수 합 | 비율 |
|---|---|---|
| 있음 | 1,252,566 | 71.2% |
| 부분 | 417,682 | 23.7% |
| 없음 | 88,793 | 5.0% |
| 정책상 제외 | 0 | 0.0% |
| 해당 없음 | 0 | 0.0% |

AXIOM 결과 중 이 목록에 연결되지 않은 그룹: Refined Results(14종 파생), Operating System의 File Associations·Windows Search 일부, Documents의 Office Backstage 일부 — 아래 Table B 및 갭 목록 참고.

### 3.4 정책상 제외·해당 없음 목록

- Adium — 해당 없음: macOS 메신저, 파서 없음(macOS 지원 수준: 사용자 프로필·브라우저·격리·TCC·LaunchAgent 기준선만)
- DS_Store — 해당 없음: macOS .DS_Store 파서 없음(macOS 지원 수준 낮음)
- iChat — 해당 없음: macOS 구형 메신저. CHAT_APP_PROFILES alias만
- Numbers — 해당 없음: Apple iWork 파서 없음(macOS 지원 수준 낮음)
- Pages — 해당 없음: Apple iWork 파서 없음(macOS 지원 수준 낮음)
- Windows Stored Credentials — 정책상 제외: Credential Manager·DPAPI 복호·추출은 비밀 취급 정책상 범위 밖(목록화 원칙, BROWSER_SECRET_HANDLING 선례). 전용 파서도 없음


## 4. 우선순위 갭 목록 (한국 기업·법무 검사관: 정보 유출(DLP)·내부자·침해사고 대응)

순위 기준: (1) 한국 사건에서 실제로 나오는 증거인가, (2) 유출 경로(메신저·웹메일·클라우드·USB·인쇄)·내부자 행위·침해 흔적을 직접 답하는가, (3) 지금 코드 기반에서 구현 비용이 낮은가. AXIOM 사건 건수는 노이즈 양이라 순위에 쓰지 않았다. 정책 경계(암호 크래킹·원격 수집·외부 실행·비밀 값 추출)는 침범하지 않는 항목만 올렸다.

| 순위 | 갭 | 시나리오 | 한 줄 구현 노트 |
|---|---|---|---|
| 1 | Windows 데스크톱 메신저(Teams·Slack·Discord·Telegram Desktop·WhatsApp Desktop·Skype·LINE PC·WeChat PC·Zoom) | DLP·내부자: 업무 채팅·파일 전송 | `artifacts/mobile/messengers.py`의 CHAT_APP_PROFILES·`extended_messenger_*` 프로필을 재사용하되 모바일 루트 서명 대신 `AppData\Roaming\<app>` 경로 서명을 가진 새 `windows-messenger` 공급자를 둔다. SQLite 기반(Skype·LINE·WhatsApp Desktop)부터, Teams·Slack은 LevelDB/IndexedDB 인벤토리→문자열 후보 순. 암호화(Telegram tdata·WeChat)는 목록화만 |
| 2 | 카카오톡 PC 메시지 본문·공유 사진·첨부 | 한국 사건 1순위 채팅 증거 | 현재 앱 DB 인벤토리·키 재료 후보만(`kakaotalk-message-db-decryption-not-implemented`). 이미 있는 CLI `kakaotalk-decrypt`(`core/kakaotalk.py`) 결과를 `kakaotalk-message` 행(카탈로그 messenger 계열에 유형 이미 등록)으로 런 단계에 연결하고, 공유 사진은 `pvi_v2`/`img_v2` 인덱스 기반 첨부 행으로 낸다 |
| 3 | 브라우저 캐시 항목 디코딩 + 웹메일·클라우드 업로드 페이지 복원 + 레거시 Edge/IE(WebCacheV01) 행 | DLP: 웹메일(Naver·Daum·Gmail) 첨부 업로드, 웹하드 | Chromium simple-cache/blockfile 항목 디코드(URL·헤더·본문 해시)를 `browser-cache-inventory` 위에 `browser-cache-entry`로 추가하고, `ese_native.py`로 WebCacheV01 컨테이너 행(`Container_n`) 디코드. URL 힌트 상수(EMAIL/CLOUD_HOST_HINTS)에 naver·daum·mybox를 넣어 `urls` 표와 연결 |
| 4 | 통합 상세 결과 6표(사람·장치·접근 경로·첨부·자격 증명 마스킹·URL 분류) | 전 시나리오: "이 계정/이메일/USB/경로가 어디에 나오나" | 이미 E2 진행 중. 우선 `paths`(LNK·JumpList·Shellbags·MRU 병합)와 `people`부터 낸다. 자격 증명은 가린 값+길이+해시만 |
| 5 | 로컬 클라우드 동기화 클라이언트 심화(OneDrive SyncEngine·로그, Dropbox, Google Drive DriveFS 전량, 네이버 MYBOX) | DLP: 개인 클라우드로 대량 복사 | `desktop-cloud-sync-db`의 바운디드 행을 계정·동기화 폴더·업로드/삭제 이벤트 열로 정규화하고 `cloud.bulk_download`류 규칙과 같은 방식의 `cloud.bulk_upload` 규칙 추가. Dropbox `.dbx`·Naver MYBOX는 경로 서명 인벤토리부터 |
| 6 | Outlook PST/OST 네이티브(폴더·약속·연락처·첨부) + ICS | DLP·내부자: 메일 전송·삭제 메일 | 이미 `email_external.py`의 libpff/readpst 래퍼가 있으므로 외부 도구 출력을 정식 `email-message`/`calendar-event`/`contact` 행으로 정규화하고 번들 도구 유무를 `/doctor`에 표시. 네이티브 디코드는 이후 |
| 7 | NetworkList(네트워크 프로필)·네트워크 공유/매핑 드라이브·무선 연결 이력 | IR·내부자: 어느 네트워크·공유에 접속했나 | `windows/registry.py` 키 분류 표에 `NetworkList\Profiles/Signatures`, `MountPoints2`·`Map Network Drive MRU`, WLAN 연결 이력을 추가(내보내기·하이브 양쪽). 레지스트리 코드 변경 없이 분류 항목 추가 수준 |
| 8 | Prefetch 완전 디코딩(MAM 압축 해제·실행 시각 8개·볼륨 테이블)과 PCA/FeatureUsage/Application Install States | IR: 실행·삭제된 도구 입증 | P3. `prefetch.py`에 Win10 MAM(XPRESS Huffman) 해제 후 파일 메트릭 디코드 → `execution.runcount_spike` 규칙이 이미 있어 값만 채우면 활성. PCA(`PcaAppLaunch.dic`)·FeatureUsage는 NTUSER/텍스트 파서 소형 |
| 9 | 안티 포렌식 도구·암호화 도구 흔적(VeraCrypt·CCleaner·Eraser·sdelete·BitLocker 복구 키 파일) | 내부자: 증거 인멸 | 설치 프로그램(`windows-installed-program`)·Prefetch·Amcache·서비스 이름에 대한 시그니처 목록 규칙(`other.yaml`에 `antiforensics.tool_present`)과 BitLocker `.BEK`/복구 키 텍스트 파일 파서. 목록은 출처 명시 |
| 10 | NTFS Timestamp Mismatch를 별도 노드·표로 승격 + $LogFile/USN 리플레이 | 내부자: 타임스톰핑 | 이미 `ntfs.si_before_fn`·`mft-sia-fna-timestamp-mismatch` 플래그가 있으므로 `fs` 도메인에 "타임스탬프 불일치" 노드(플래그 필터)와 SI/FN 8열 표를 추가. $LogFile은 트랜잭션 후보 검증 후 |
| 11 | Windows 이벤트 로그 채널 분류 노드(네트워킹·Office Alerts·스토리지) + 요약 문장 열 | IR 가독성 | E2 `summary_ko` 상위 60 ID. 채널 기반 서브노드는 `eventlog` 도메인 노드에 `channel` 필터 링크 추가 |
| 12 | 카빙 확장(오디오·Office/HWP·이메일·실행 파일) + 카빙 결과를 아티팩트 노드로 노출 | 삭제 증거 복구 | `core/carving.py` SIGNATURES에 시그니처 추가(검증기 포함)·`windows-filesystem`과 같은 `recovery_method=carved` 행으로 통합. 현재는 분석 노드 결과만 |
| 13 | 사용자 정의 태그·해시 전파·클래식 분할·기준선·CSV 꼬리 열 | 검토 생산성 | E3 진행 중. 태그는 사건별 분류("DLP 후보")가 핵심이므로 단축키·해시 전파 우선 |
| 14 | 케이스 만들기(사건 번호·증거 번호·처리 설정 스냅샷·처리 문제 집계) | 보고서·인용·재현성 | E1 진행 중. 보고서 인용에 사건/증거 번호 포함이 법정 제출 요건 |
| 15 | Office MRU/Backstage·Windows Mail·Thunderbird·VLC·Your Phone·Known DLLs | 보조 사용자 활동 | 레지스트리 분류 표 추가(Office File MRU/Place MRU)·소형 파서. 낮은 우선순위 |
| 16 | 그룹/태스크 단위 진행·부분 완료·개별 취소 | 장시간 런(3일 BSH 경험) | P2 계획(`run-model-p2-2026-10-12.md`). 코드 흔적은 `core/run/scheduler.py`·`progress.py` 수준이라 신규 구현 |
| 17 | 지도 뷰(EXIF GPS·위치 아티팩트)·행 카드 뷰·커넥션 그래프 | 시각화 보조 | 위치 데이터가 있는 사건에서만. 지도는 로컬 타일 없이 좌표 표/클러스터 목록으로 대체 가능 |
| 18 | P2P·구형 메신저(Ares·eMule·LimeWire·mIRC·AIM·MSN 등 30여 개) | 레거시 | 기업 사건 빈도 낮음. 구현하지 않고 "미지원" 목록(한국어 사유)으로 공개하는 편이 낫다(`known-limitations`) |
| — | 스킨톤·PhotoDNA·Project VIC·CPS·Magnet.AI 분류 | 아동 성착취물 사건 전용 | 기업·법무 범위 밖. 해시 집합 가져오기(`/api/hash-sets`)로 일반 해시 매칭은 이미 지원 |
| — | Windows 저장 자격 증명·브라우저 비밀번호 복호, 암호 파일 크래킹, Magnet REVIEW 업로드, 원격 수집 | 정책 제외 | 구현하지 않음. 존재 여부·위치만 목록화 |

### 한 줄 요약

Computer 목록 199개 중 행 단위로 파싱되는 항목은 59개(30%), 부분 51개(26%), 없음 83개(42%), 정책 제외 1·해당 없음 5. 없음 83개 중 커뮤니케이션 그룹이 35개(레거시 메신저·P2P·SNS)이고 한국 기업 사건 영향은 대체로 작다. 커뮤니케이션 그룹은 `있음`이 0개(54개 중 부분 17)라 가장 취약하다. 반대로 운영체제 그룹은 49개 중 32개가 `있음`이다. 반면 **데스크톱 메신저·웹메일/캐시·클라우드 클라이언트·PST** 네 영역은 유출 사건에 직접 영향이 커서 1·3·5·6위로 올렸고, 한국 특수 요건인 **카카오톡 본문**은 2위다. 구조 격차로는 Refined Results(통합 표)가 가장 크고 E2가 이미 겨냥한다.

### 방법과 한계

- 판정은 소스 검색(`rg`)과 공급자·카탈로그 읽기로 했고, 실제 이미지에서 돌려 행이 나오는지 확인하지 않았다. 바운디드·검증 블로커가 붙은 파서(`known-limitations` Parser Coverage)는 행이 나오면 `있음`으로 두고 비고에 한계를 적었다. 실제 E01 출력으로 재확인이 필요하다.
- 사건 건수 열은 AXIOM 하위 아티팩트를 항목에 묶은 합이라 일부는 중복 가능성이 있다(예: Windows Search 하위 6종은 Windows Search 한 항목에 합산, Email Attachments는 Outlook에 합산).
- "그룹" 열은 검색 항목 목록에 그룹이 없어 AXIOM 15그룹을 기준으로 임의 배정했다.
- Mobile/Cloud 플랫폼 항목은 제공 목록에 없어 판정하지 않았다.
