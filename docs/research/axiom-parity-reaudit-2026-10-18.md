# R5 감사 — AXIOM Table A(Computer 199) 재검증 (2026-10-18)

범위: 읽기 전용. 브랜치 `feat/r4-runplan-explorers-views`(R1–R4 포함, HEAD 325e111). 근거는 코드 판독(`rapidtriage/artifacts/**`, `core/artifact_domains.py`, `core/triage_rules/catalog/*.yaml`, `core/carving.py`, `core/eventlog_channels.py`, `core/derived/url_classes.yaml`, `frontend/src/features/tree/domains.ts`)이다. 실이미지 런 재확인은 하지 않았다. 원본 매트릭스 Table A는 R2–R4 이후 갱신되지 않았다(문서 커밋 3e1b89f, b143f2e는 UI 표 B만 수정).

판정 규칙은 원 매트릭스와 같다. `있음`은 행 단위 kind/artifact_type이 나오는 경우(바운디드·후보·외부 도구 조건 포함, 비고에 표시)다. `표 대체`는 전용 파서 없이 기존 표(통합 보기 URL 분류, 캐시 항목 Content-Type, Volatility 정규화 등)가 같은 질문에 답하는 경우다. 원 매트릭스는 `표 대체`를 Table A에서 쓰지 않았다. 이번에는 R5 종료 범주로 이 값을 쓴다.

## 1. 집계

| 상태 | 작성 시(2026-10-17) | 현재(R4 브랜치) | R5 계획 완료 후(목표) |
|---|---|---|---|
| 있음 | 59 | 92 | 120 |
| 표 대체 | 0 | 11 | 23 |
| 부분 | 51 | 26 | 0 |
| 없음 | 83 | 64 | 0 |
| 정책상 제외 | 1 | 1 | 10 |
| 공개 미지원 | 0 | 0 | 38 |
| 해당 없음 | 5 | 5 | 8 |
| 합계 | 199 | 199 | 199 |

- 있음+표 대체: 59(30%) → 103(52%). R5를 마치면 143(72%)이고 나머지 56행은 공개 미지원·정책 제외·해당 없음으로 닫힌다.
- 미종결(없음+부분): 134 → 90. 분류는 (a) R5 파서 41, (b) 공개 미지원 39, (c) 정책 제외 7, (d) 해당 없음 9다. (d)에는 이미 해당 없음인 5행이 포함된다. (c)에는 이미 정책상 제외인 Windows Stored Credentials가 포함되며, 이 행은 존재·위치 행 추가가 필요하다.
- 목표 열의 "있음/공개 미지원 혼합" 행(Limewire/Frostwire, Safari, iMessage)은 첫 범주로 셌다. 혼합 행 4개는 known-limitations에 분리 사유를 적어야 한다.
- 그룹별 현재 상태:
  - 운영체제: 있음 41/49(R3 목표 ≥45에는 미달). 남은 행은 Startup Items, Networking Events, Cortana, IME, Logon Banner, Rebuilt Desktops, File System Information이며, Volatile은 표 대체다.
  - 커뮤니케이션: 있음 7 + 표 대체 6 = 13/54. R2 목표 ≥30에는 미달이다. 남은 대부분이 죽은 앱이라 (b)로 닫는 것이 맞다.
  - 이메일·캘린더: 있음 4/14다. 웹메일 8행은 URL 분류(표 대체)로 닫을 수 있다.

### 재판정 주의(코드 변화 없이 규칙만 재적용)
- UsnJrnl(부분→있음): 바운디드 네이티브 행이 원래부터 나왔다. 원 판정이 규칙과 어긋났다.
- Facebook·LinkedIn·VK·Sina Weibo·Twitter·Instagram·Malware/Phishing·Pornography URLs(없음/부분→표 대체): E2 `url_classes.yaml`(R1)이 원 매트릭스 작성 후 병합되었다. 단 adult 분류는 4개 도메인뿐이라 목록 보강이 필요하다.
- Volatile Artifacts(부분→표 대체): RapidTriage는 외부 도구를 실행하지 않는다. Volatility 출력 정규화로 대체한다.
- Outlook(부분→있음): pffexport/readpst가 PATH에 있을 때만 행이 나온다. 도구가 없으면 `email-container-inventory`와 `/doctor` 안내만 나온다. 네이티브 PST 파서는 R5 범위 밖(L)이다.

## 2. 재검증 표(199행, 원 순서)

열: AXIOM 항목 | 그룹 | 작성 시 | 현재 | 근거(artifact_type / 파일) | R5 분류 | R5 종료 목표

| AXIOM 항목 | 그룹 | 작성 시 | 현재 | 근거 | R5 | 목표 |
|---|---|---|---|---|---|---|
| $LogFile Analysis | 운영체제 | 부분 | 있음 | logfile-transaction 행(core/ntfs_logfile.py, R3 O3; RCRD·LSN·op 바운디드, 재생 없음) | — | 있음 |
| 360 Safe Browser | 웹 관련 | 없음 | 없음 | CHROMIUM_BROWSER_ROOTS=chrome/edge/brave/whale/vivaldi + opera/opera-gx; 360 루트 없음 | a | 있음 |
| Adium | 커뮤니케이션 | 해당 없음 | 해당 없음 | (변동 없음) macOS 메신저 | d | 해당 없음 |
| AIM | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| AmCache | 운영체제 | 있음 | 있음 | (변동 없음) amcache-* | — | 있음 |
| Android Backups | 추가 소스 | 부분 | 부분 | mobile/roots.py `ANDROID BACKUP` 서명 감지만; .ab 해제 없음 | a | 있음 |
| Apple Disk Images | 추가 소스 | 부분 | 부분 | core/archive_image.py 증거 입력 추출(7z/bsdtar)만 | d | 해당 없음(증거 입력 추출로 대체) |
| Application Install States | 애플리케이션 사용량 | 없음 | 있음 | registry-install-state(App Paths·MSI Products; registry_depth.py, R3 O1) | — | 있음 |
| Ares | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Audio | 미디어 | 있음 | 있음 | (변동 없음) media-audio | — | 있음 |
| AutoRun Items | 운영체제 | 있음 | 있음 | (변동 없음) registry-run-key | — | 있음 |
| Bebo | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Bing Toolbar | 웹 관련 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Bitcoin | 암호화·자격 증명 | 없음 | 없음 | 지갑 파서·경로 서명 없음 | a | 정책 제외(존재·위치 행) |
| BitLocker Recovery Key | 암호화·자격 증명 | 부분 | 있음 | bitlocker-recovery-key-file(windows/antiforensics.py; 키 가림·해시) + 메모리 스캔 | — | 있음 |
| Calendar Events (ics) | 이메일·캘린더 | 없음 | 있음 | calendar-event(email_pst.py ICS RFC5545 + PST 내보내기) | — | 있음 |
| Carbonite | 클라우드 저장소 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Carved Archives (content not searched) | 사용자 정의(Custom) | 부분 | 있음 | carving zip/7z/rar + 카빙 행 recovery_method=carved로 계열 노드 통합(R3 O3) | — | 있음 |
| Carved Audio | 미디어 | 없음 | 있음 | core/carving.py wav/mp3/m4a(+mp4) 시그니처(R3 O3) | — | 있음 |
| Chatroulette | 커뮤니케이션 | 없음 | 없음 | 웹 전용 서비스 | b | 공개 미지원 |
| Chatstep | 커뮤니케이션 | 없음 | 없음 | 웹 전용 서비스 | b | 공개 미지원 |
| Chrome | 웹 관련 | 있음 | 있음 | (변동 없음) browser-* + browser-cache-entry(R2 M3) | — | 있음 |
| Chromium Based Browsers | 웹 관련 | 부분 | 있음 | Chrome·Edge·Brave·Whale·Vivaldi·Opera·Opera GX(browser.py R2 M3). 360·Yandex·Chromium 등은 360 행에서 추가 | — | 있음 |
| Cortana | 운영체제 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Crypto Currency | 암호화·자격 증명 | 없음 | 부분 | url_classes.yaml finance에 거래소 도메인(upbit·bithumb·binance 등)만; 지갑 없음 | a | 표 대체 + 정책 제외(지갑 존재·위치) |
| CSV Documents | 문서 | 있음 | 있음 | (변동 없음) 문서 본문 색인 | — | 있음 |
| Default Browser | 운영체제 | 없음 | 있음 | registry-default-browser(registry_depth.py) | — | 있음 |
| Discord | 커뮤니케이션 | 부분 | 있음 | chat-message/-contact/-attachment(windows/messenger.py discord, LevelDB 카빙 후보·신뢰도 낮음) | — | 있음 |
| Dropbox | 클라우드 저장소 | 부분 | 있음 | cloud-sync-account/-file/-inventory(cloud_sync.py info.json·host.db; .dbx 암호화는 인벤토리) | — | 있음 |
| DS_Store | 추가 소스 | 해당 없음 | 해당 없음 | (변동 없음) macOS | d | 해당 없음 |
| Edge | 웹 관련 | 있음 | 있음 | (변동 없음) Chromium 행 파서 | — | 있음 |
| Edge/Internet Explorer | 웹 관련 | 부분 | 있음 | browser_webcache.py WebCacheV01 → browser-history/-cache-entry/-cookie/-download(ese_native) | — | 있음 |
| EGG Archives | 사용자 정의(Custom) | 부분 | 부분 | core/files.py 확장자 인벤토리(.egg/.alz)만, 항목 열거 없음 | a | 있음 |
| EML(X) Files | 이메일·캘린더 | 있음 | 있음 | (변동 없음) email-message | — | 있음 |
| Emule | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | a | 있음 |
| Encrypted Files | 암호화·자격 증명 | 부분 | 부분 | archive-encrypted-*·문서 암호 플래그(감지 행 있음), 복호 없음 | c | 정책 제외(복호) — 감지는 있음 |
| Encryption / Anti-forensics Tools | 암호화·자격 증명 | 부분 | 있음 | antiforensics.tool_present / wiper_run_after_incident(catalog/antiforensics.yaml 14종, R3 O1) | — | 있음 |
| Facebook | 커뮤니케이션 | 없음 | 표 대체 | url_classes.yaml social(facebook.com·fb.com) → 통합 보기 URL 분류 | — | 표 대체 |
| Facebook Messenger | 커뮤니케이션 | 부분 | 부분 | 모바일 내보내기만; 데스크톱 앱 없음 | a | 있음 |
| Feature Usage | 애플리케이션 사용량 | 없음 | 있음 | execution-feature-usage(registry_depth.py) | — | 있음 |
| File Signature Mismatch | 사용자 정의(Custom) | 있음 | 있음 | (변동 없음) file-signature-mismatch | — | 있음 |
| File System Information | 운영체제 | 부분 | 부분 | e01-partition-workflow 요약 + R4 파일 시스템 탐색기; 볼륨($Volume/VBR) 행 없음 | a | 있음 |
| Firefox | 웹 관련 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Flickr | 커뮤니케이션 | 없음 | 없음 | url_classes social에 flickr 없음 | a | 표 대체 |
| Gigatribe | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Gmail | 이메일·캘린더 | 부분 | 부분 | web-upload-candidate(Gmail 첨부 업로드 패턴, R2 M3)·Takeout cloud-mail; webmail URL 분류 없음 | a | 표 대체 |
| GMX Webmail | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Google Analytics | 웹 관련 | 없음 | 없음 | 쿠키 값 비해석(정책) | a | 있음(정책 승인 시) / 정책 제외 |
| Google Docs | 클라우드 저장소 | 없음 | 부분 | url_classes cloud(docs.google.com) + DriveFS 항목 mime; .gdoc 스텁 파서 없음 | a | 있음 |
| Google Drive | 클라우드 저장소 | 부분 | 있음 | cloud-sync-*(DriveFS metadata/mirror SQLite, Backup and Sync) + Takeout | — | 있음 |
| Google Maps | 위치·여행 | 부분 | 부분 | Takeout cloud-location만; 브라우저 지도 URL 해석 없음 | a | 있음 |
| Google Talk | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Google Toolbar | 웹 관련 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Google+ | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Hangul Word Processor | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Hotmail Webmail | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Hushmail | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| iChat | 커뮤니케이션 | 해당 없음 | 해당 없음 | (변동 없음) macOS | d | 해당 없음 |
| ICQ | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| IME Suggestions | 운영체제 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| iMessage | 커뮤니케이션 | 부분 | 부분 | PC의 iOS 백업 sms.db → mobile-message(있음); macOS chat.db 파서 없음 | d | 있음(iOS 백업) / 해당 없음(macOS) |
| Instagram | 커뮤니케이션 | 부분 | 표 대체 | url_classes social(instagram.com) + 모바일 내보내기 메시지; Windows 앱 없음 | — | 표 대체 |
| Installed Programs | 애플리케이션 사용량 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| iOS Backups | 추가 소스 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| IP Addresses - Audio/Video Calls | 커뮤니케이션 | 없음 | 없음 | 통화 IP 추출 없음(memory-network는 Volatility 출력) | b | 공개 미지원 |
| ISO Files | 추가 소스 | 부분 | 부분 | 증거 입력 추출(7z)만; 케이스 내 ISO 항목 열거 없음 | a | 있음 |
| Jump Lists | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| KakaoTalk | 커뮤니케이션 | 부분 | 있음 | kakaotalk-message·kakaotalk-shared-picture(kakaotalk_messages.py, 키 재료 있을 때) + 인벤토리 사유 | — | 있음 |
| Keyword Searches | 운영체제 | 있음 | 있음 | (변동 없음) 키워드 팩·통합 검색 | — | 있음 |
| Known DLLs | 운영체제 | 없음 | 있음 | registry-known-dll(registry_depth.py) | — | 있음 |
| Latent Wireless | 연결된 장치 | 부분 | 있음 | registry-wlan-profile + wifi-profile + WLAN 이벤트 | — | 있음 |
| Limerunner | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Limewire / Frostwire | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | a | 있음(FrostWire 토렌트) / 공개 미지원(LimeWire) |
| LINE | 커뮤니케이션 | 부분 | 부분 | chat-app-inventory(inventory_only, 암호화 저장소; messenger.py line) | c | 정책 제외 |
| LinkedIn | 커뮤니케이션 | 없음 | 표 대체 | url_classes social(linkedin.com) | — | 표 대체 |
| LNK Files | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| LogMeIn | 연결된 장치 | 없음 | 없음 | remote_access.py 제품: TeamViewer/AnyDesk/RustDesk/CRD | a | 있음 |
| Luckywire | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Lync / Office Communicator | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Magnet Web Page Saver | 웹 관련 | 없음 | 없음 | AXIOM 전용 수집물 | d | 해당 없음 |
| Mail.ru | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Mailinator | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Malware/Phishing URLs | 웹 관련 | 부분 | 표 대체 | url_classes suspicious(남용 빈발 도메인) + IOC/TI + browser.dl_dangerous | — | 표 대체 |
| MBOX E-mails | 이메일·캘린더 | 있음 | 있음 | (변동 없음) .mbox 확장자만(Thunderbird 확장자 없는 mbox 미탐지 → a) | — | 있음 |
| McAfee Logs | 애플리케이션 사용량 | 없음 | 없음 | 흔적 없음 | a | 있음 |
| Microsoft Excel | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Microsoft Office | 문서 | 부분 | 부분 | 문서 본문·메타 + registry-office-mru; Office 연결 계정·Backstage 없음 | a | 있음 |
| Microsoft Office 365 MRU | 문서 | 부분 | 있음 | registry-office-mru(File/Place MRU, User MRU\<account>) | — | 있음 |
| Microsoft PowerPoint | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Microsoft Sticky Notes | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Microsoft Teams | 커뮤니케이션 | 부분 | 있음 | chat-*(messenger.py teams-classic/teams-new, LevelDB 카빙 후보) | — | 있음 |
| Microsoft Word | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| mIRC | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Most Recently Used | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| MSN Plus! | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| MUICache | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| MySpace | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Network Interfaces | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Network Profiles | 운영체제 | 없음 | 있음 | registry-network-profile(NetworkList Profiles+Signatures) | — | 있음 |
| Network Share Information | 운영체제 | 없음 | 있음 | registry-network-share(MountPoints2·Map Network Drive MRU·Network\<drive>) | — | 있음 |
| Network Usage | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Notification Center | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| NTFS Timestamp Mismatch | 운영체제 | 부분 | 있음 | timestamp-mismatch 행·노드(ntfs_metadata.py, R3 O3) + ntfs.* 지표 | — | 있음 |
| Numbers | 문서 | 해당 없음 | 해당 없음 | (변동 없음)  | d | 해당 없음 |
| Omegle | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| OneDrive | 클라우드 저장소 | 부분 | 있음 | cloud-sync-*(ini·SyncEngineDatabase.db·.odl 로그 카빙) | — | 있음 |
| ooVoo | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| OpenOffice Calc | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| OpenOffice Impress | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| OpenOffice Writer | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Opera | 웹 관련 | 없음 | 있음 | CHROMIUM_SINGLE_PROFILE_ROOTS opera/opera-gx | — | 있음 |
| Operating System Information | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Outlook | 이메일·캘린더 | 부분 | 있음 | email-message/calendar-event/contact/email-attachment(email_pst.py, pffexport/readpst 있을 때) + email-container-inventory·/doctor | — | 있음(외부 도구 조건) |
| Outlook Web App | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Outlook Webmail | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Pages | 문서 | 해당 없음 | 해당 없음 | (변동 없음)  | d | 해당 없음 |
| Paltalk | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| PDF | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Photoshop Files | 미디어 | 부분 | 부분 | photoshop-editing-metadata 힌트만 | a | 있음 |
| Pictures | 미디어 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Pidgin | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Pornography URLs | 웹 관련 | 없음 | 표 대체 | url_classes adult(4 도메인, 목록 작음) | — | 표 대체 |
| Potential Browser Activity (Incl. Private/ Incognito URLs) | 웹 관련 | 없음 | 없음 | 미할당·pagefile URL 카빙 없음 | a | 있음 |
| PowerShell | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Prefetch Files | 운영체제 | 부분 | 있음 | prefetch.py + xpress_huffman.py MAM 해제·8 실행 시각·볼륨·참조 파일(R3 O2) | — | 있음 |
| Program Compatibility Assistant Records | 애플리케이션 사용량 | 없음 | 있음 | execution-pca(pca.py PcaAppLaunchDic/PcaGeneralDb + 레지스트리 Store) | — | 있음 |
| QQ | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | a | 정책 제외(존재·위치 행) |
| QuickBooks Files | 문서 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| RealPlayer | 미디어 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Rebuild Webpages | 웹 관련 | 없음 | 없음 | 캐시 본문 미저장(BODY_POLICY: 해시·크기·앞 256바이트) | c | 정책 제외 |
| Rebuilt Desktops | 운영체제 | 없음 | 없음 | 흔적 없음 | a | 있음 |
| Recycle Bin | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Remote Desktop Protocol | 연결된 장치 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| RTF Documents | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Safari | 웹 관련 | 부분 | 부분 | macOS Safari 있음(macos-browser-history-downloads); Windows Safari 없음 | b | 있음(macOS) / 공개 미지원(Windows) |
| Scheduled Tasks | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Second Life | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Services | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Shareaza | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| SharePoint | 클라우드 저장소 | 부분 | 표 대체 | M365 내보내기(cloud-file) + OneDrive Business 라이브러리 동기화 행(cloud-sync) | — | 표 대체 |
| Shellbags | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Shim Cache | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Signal | 커뮤니케이션 | 부분 | 부분 | 모바일 내보내기만; messenger.py APPS에 Signal Desktop 없음 | a | 정책 제외(존재·위치 행) |
| Sina Weibo | 커뮤니케이션 | 없음 | 표 대체 | url_classes social(weibo.com) | — | 표 대체 |
| Skype | 커뮤니케이션 | 부분 | 있음 | chat-*(messenger.py skype: main.db SQLite + IndexedDB 카빙) | — | 있음 |
| Slack | 커뮤니케이션 | 부분 | 있음 | chat-*(messenger.py slack) + 워크스페이스 내보내기 | — | 있음 |
| SRUM | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| SSH Keys | 암호화·자격 증명 | 부분 | 부분 | Linux만(linux.py); Windows ~/.ssh·PuTTY 없음 | a | 있음 |
| Startup Items | 운영체제 | 부분 | 부분 | registry-run-key만; 시작 프로그램 폴더·StartupApproved 없음 | a | 있음 |
| TeamViewer | 연결된 장치 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Telegram | 커뮤니케이션 | 부분 | 부분 | chat-app-inventory(tdata 암호화) + Downloads\Telegram Desktop 파일(app-file-store) | c | 정책 제외 |
| Text Documents | 문서 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Timezone Information | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| TorChat | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Torrent URLs | 웹 관련 | 없음 | 없음 | url_classes에 torrent 분류 없음 | a | 표 대체 |
| Trillian | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Twitter | 커뮤니케이션 | 부분 | 표 대체 | url_classes social(twitter.com·x.com·t.co) + 모바일 DM | — | 표 대체 |
| USB Devices | 연결된 장치 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Usenet Binary Files | 미디어 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| User Accounts | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| UserAssist | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| UsnJrnl | 운영체제 | 부분 | 있음 | usn-record 행(바운디드 네이티브) — 코드 변화 없음, 판정 규칙(행 출력=있음) 재적용 | — | 있음 |
| Viber | 커뮤니케이션 | 부분 | 부분 | 모바일 내보내기만; ViberPC viber.db 없음 | a | 있음 |
| Videos | 미디어 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Virtual Machines | 추가 소스 | 부분 | 부분 | 증거 입력(virtual-disk-workflow)만; .vmx/.vbox 구성 행 없음 | a | 있음 |
| VK | 커뮤니케이션 | 없음 | 표 대체 | url_classes social(vk.com) | — | 표 대체 |
| VLC Media Player | 미디어 | 없음 | 없음 | 흔적 없음 | a | 있음 |
| Volatile Artifacts | 운영체제 | 부분 | 표 대체 | memory-process/-cmdline/-network/-malfind(Volatility 출력 정규화) + 덤프 문자열 스캔 | — | 표 대체 |
| Web Video Fragments | 웹 관련 | 없음 | 표 대체 | browser-cache-entry content_type video/*(browser_cache.py; 본문 미저장) | — | 표 대체 |
| WebKit | 웹 관련 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Webpage Recovery | 웹 관련 | 없음 | 없음 | 캐시 본문 미저장 | c | 정책 제외 |
| WeChat | 커뮤니케이션 | 부분 | 부분 | chat-app-inventory(SQLCipher) + FileStorage 파일(app-file-store) | c | 정책 제외 |
| WhatsApp | 커뮤니케이션 | 부분 | 있음 | chat-*(Electron 클라이언트 LevelDB 카빙); Store 신 클라이언트는 인벤토리 | — | 있음 |
| Wickr Me | 커뮤니케이션 | 부분 | 부분 | 모바일 내보내기만 | b | 공개 미지원(데스크톱) |
| Windows Defender Logs | 애플리케이션 사용량 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Windows Event Logs | 운영체제 | 있음 | 있음 | (변동 없음) + 채널 노드(eventlog_channels.py) | — | 있음 |
| Windows Event Logs - Firewall Events | 운영체제 | 있음 | 있음 | (변동 없음) + firewall 채널 그룹 | — | 있음 |
| Windows Event Logs - Networking Events | 운영체제 | 부분 | 부분 | CHANNEL_GROUPS에 networking 없음(WLAN/BITS 탐지만, 나머지는 '기타 채널') | a | 있음 |
| Windows Event Logs - Office Alert Events | 운영체제 | 부분 | 있음 | channel_group office-alerts(OAlerts) 노드(R3 O2) | — | 있음 |
| Windows Event Logs - Scheduled Task Events | 운영체제 | 있음 | 있음 | (변동 없음) + task-scheduler 채널 | — | 있음 |
| Windows Event Logs - Script Events | 운영체제 | 있음 | 있음 | (변동 없음) + powershell 채널 | — | 있음 |
| Windows Event Logs - Service Events | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Windows Event Logs - Storage Device Events | 운영체제 | 있음 | 있음 | (변동 없음) + storage 채널 | — | 있음 |
| Windows Event Logs - System Events | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Windows Event Logs - User Events | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Windows Event Logs - User PNP Events | 운영체제 | 있음 | 있음 | (변동 없음) + user-pnp 채널 | — | 있음 |
| Windows Live Messenger / MSN Messenger® | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Windows Logon Banner | 운영체제 | 없음 | 없음 | LegalNotice 파서 없음 | a | 있음 |
| Windows Mail | 이메일·캘린더 | 없음 | 부분 | Mail 앱 폴더의 .eml은 범용 email-message로 파싱(계정·폴더 귀속 없음); store.vol 미해석 | a | 있음 |
| Windows Search | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| Windows Stored Credentials | 암호화·자격 증명 | 정책상 제외 | 정책상 제외 | 복호 없음; Credentials/Vault 파일 존재·위치 목록도 아직 없음 | c | 정책 제외(존재·위치 행 추가) |
| Windows Timeline | 운영체제 | 있음 | 있음 | (변동 없음)  | — | 있음 |
| WordPerfect Files | 문서 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| World of Warcraft | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Xbox Internet Explorer History | 웹 관련 | 없음 | 없음 | Xbox 콘솔 이미지 | d | 해당 없음 |
| Yahoo! Messenger | 커뮤니케이션 | 없음 | 없음 | 흔적 없음 | b | 공개 미지원 |
| Yahoo! Webmail | 이메일·캘린더 | 없음 | 없음 | webmail URL 분류 없음 | a | 표 대체 |
| Your Phone | 연결된 장치 | 없음 | 없음 | 흔적 없음 | a | 있음 |
| Zoom | 커뮤니케이션 | 부분 | 있음 | chat-*(messenger.py zoom: zoomus.db·meeting_saved_chat.txt; *.enc.db 인벤토리) + 협업 내보내기 | — | 있음 |

## 3. (a) R5 소형 파서: 순수 표준 라이브러리 + 합성 픽스처로 가능 (41행, 28 작업 항목)

순위는 검사관 가치(한국 기업·형사 사건) × 노력(S ≤1일, M 2–4일, L 1주+)으로 매겼다. 모든 항목은 바운디드이고 손상 입력을 격리한다. 각 행에는 `recovery_method`·`parser_version`·`source_path`를 붙인다. 비밀 값(키·시드·비밀번호·토큰)은 추출하지 않는다.

| 순위 | 항목(닫는 행) | 형식 · 대표 Windows 경로 | 행 유형 · 주요 열 | 노력 | 검사관 가치 |
|---|---|---|---|---|---|
| 1 | **URL 분류 확장: 웹메일·토렌트·Flickr**(Gmail, GMX, Hotmail, Hushmail, Mail.ru, Mailinator, Outlook Web App, Outlook Webmail, Yahoo! Webmail, Torrent URLs, Flickr = 11행) | `core/derived/url_classes.yaml`에 `webmail` 분류(mail.google.com, outlook.live.com/office.com/office365.com, mail.yahoo.com, gmx.*, e.mail.ru, hushmail.com, mailinator.com, mail.naver.com, mail.daum.net, mail.kakao.com)와 `torrent` 분류(thepiratebay·1337x·nyaa·yts 등, 출처 명시)를 추가하고 social에 flickr.com을 넣는다. `url_classes.py`에 경로 패턴(on-prem OWA `/owa/`)과 `magnet:` 스킴 지원을 소량 추가한다. | 통합 보기 › URL 분류(호스트·분류·첫/마지막 방문·출처 행) | S | 높음. 개인 웹메일 사용·유출 경로(기업)와 토렌트 유포(형사)를 한 표에서 본다. 국내 토렌트 사이트는 도메인이 자주 바뀌므로 목록 갱신 절차가 필요하다. |
| 2 | **VLC 최근 재생**(+ 국내 확장 PotPlayer·곰플레이어·KMPlayer) | VLC: `%APPDATA%\vlc\vlc-qt-interface.ini`([RecentsMRU] list=·times=), `vlcrc`. PotPlayer: `%APPDATA%\PotPlayerMini64\PotPlayerMini64.ini` [RememberFiles] 또는 NTUSER `Software\DAUM\PotPlayer64`. 곰: NTUSER `Software\GRETECH\GomPlayer`(키·값 이름은 공개 자료로 확인해야 함) | `media-player-recent`: 플레이어·파일 경로/URL(디코드)·재생 위치·드라이브(이동식 피벗)·ini 수정 시각(기록 시각 상한) | S | 매우 높음(형사). 불법촬영물·음란물 재생, 이동식 매체 파일 열람 흔적. 국내는 PotPlayer 점유율이 높아 VLC만으로는 부족하다(AXIOM 밖 확장). |
| 3 | **Your Phone / 휴대폰과 연결(Phone Link)** | `%LOCALAPPDATA%\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalCache\Indexed\<GUID>\System\Database\` `phone.db`(message, mms, conversation), `contacts.db`, `calling.db`(call_history), `photos.db`, `settings.db`·deviceData. 평문 SQLite이며 버전별로 열이 다르다. | `phone-link-message`(상대·방향·본문·시각·첨부), `phone-link-call`(번호·유형·지속), `phone-link-contact`, `phone-link-photo`, `phone-link-device` | M | 매우 높음. 휴대폰을 확보하지 못했을 때 PC에서 문자·통화·사진 동기 흔적을 본다(보이스피싱·마약·성범죄 연락, 기업 개인폰 문자 유출). |
| 4 | **Google Maps 등 지도 URL → 위치**(Google Maps) | 브라우저 방문 URL: `google.com/maps/place/…/@lat,lng,z`, `/maps/search/<q>`, `/maps/dir/<a>/<b>`, 네이버 `map.naver.com`(`c=` EPSG:3857 → 위경도 변환), 카카오 `map.kakao.com/link/map/…,lat,lng` | 파생 `location-url-candidate`(위도·경도·검색어·출발/도착·방문 시각·원본 URL) → R4 지도 대체 보기 | S | 높음. 범행 현장 검색, 동선, 도주 경로 확인. |
| 5 | **암호화폐 지갑 존재·위치**(Bitcoin, Crypto Currency) | Bitcoin Core `%APPDATA%\Bitcoin\wallet.dat`·`wallets\*`(BDB/SQLite 헤더), Electrum `%APPDATA%\Electrum\wallets\*`(평문 JSON이면 공개 주소만), Exodus `%APPDATA%\Exodus\exodus.wallet`, Ledger Live `%APPDATA%\Ledger Live\app.json`, 확장 지갑 ID(MetaMask·Phantom·Kaikas 등) `Local Extension Settings\<id>` | `crypto-wallet-presence`: 지갑·경로·파일 수/크기·수정 시각·암호화 표시·공개 주소 수(키·시드는 저장 안 함, 정책) + 기존 finance URL 분류(거래소) | S | 높음(형사). 마약·도박·보이스피싱 자금 추적의 출발점이다. |
| 6 | **시작 프로그램**(Startup Items) | NTUSER/SOFTWARE `Explorer\StartupApproved\{Run,Run32,StartupFolder}`(12바이트: 첫 바이트 02/06 사용·03/07 사용 안 함, 4–12바이트 FILETIME 비활성화 시각). `%APPDATA%\…\Start Menu\Programs\Startup`, `%ProgramData%\…\StartUp`의 LNK는 기존 LNK 파서를 재사용한다. | `startup-item`: 이름·대상·사용 여부·비활성화 시각·범위(사용자/시스템) | S | 높음. 지속성(침해사고), 감시·원격 프로그램 자동 실행. |
| 7 | **SSH 키·세션**(SSH Keys) | `%USERPROFILE%\.ssh\known_hosts`·`authorized_keys`·`config`·`id_*`(공개키 지문·개인키 존재만), `%ProgramData%\ssh\sshd_config`·`administrators_authorized_keys`. PuTTY NTUSER `Software\SimonTatham\PuTTY\SshHostKeys`·`Sessions\*`(HostName·UserName·Port). WinSCP `Martin Prikryl\WinSCP 2\Sessions`(비밀번호 값은 복사하지 않음). linux.py의 known_hosts 파서를 재사용한다. | `ssh-known-host`, `ssh-authorized-key`, `ssh-client-session` | S | 높음. 서버 접속·측면 이동(침해), 기술 유출 사건의 외부 서버 경로. |
| 8 | **Office 연결 계정·Backstage**(Microsoft Office) | NTUSER `Software\Microsoft\Office\16.0\Common\Identity\Identities\*`(EmailAddress·FriendlyName·ProviderId: AD/MSA). `%LOCALAPPDATA%\Microsoft\Office\16.0\BackstageInAppNavCache\**\*.json`(최근 폴더·파일 URL·수정자) | `office-identity`, `office-backstage-item` | S | 중상. 회사 PC에 연결된 개인 MSA 계정과 원격 SharePoint/OneDrive 파일 열람(기업 유출) 확인. |
| 9 | **EGG(알집) 항목 열거** + ALZ(EGG Archives) | ESTsoft가 공개한 EGG 명세: `EGGA` 헤더, 파일·파일명·시각·암호화 헤더, split/solid 플래그. 저장·deflate(zlib)·bzip2(bz2)·LZMA(lzma)는 해제할 수 있고 AZO는 목록만 낸다. ALZ(`ALZ\x01`)는 목록만 낸다. | 아카이브 항목 인벤토리(경로·크기·압축 크기·수정 시각·암호화 여부) + `archive-encrypted-*` 감지 연결 | M | 높음(국내 특화). 유출 패키징과 암호 압축 감지. 국내 사건에서 흔한 형식이다. |
| 10 | **P2P: 토렌트 클라이언트·FrostWire + eMule**(Limewire / Frostwire, Emule) | bencode를 순수 파이썬으로 구현한다. qBittorrent `%LOCALAPPDATA%\qBittorrent\BT_backup\*.fastresume|*.torrent`, uTorrent/BitTorrent `%APPDATA%\uTorrent\resume.dat`, FrostWire `%APPDATA%\FrostWire\`·`Documents\FrostWire\Torrents`, 임의의 `.torrent`(info-hash SHA-1·파일 목록). eMule `config\known.met`(공유·완료 파일, ed2k 해시, 업로드 통계), `AC_SearchStrings.dat`(검색어), `preferences.ini`(IncomingDir·Nick), `*.part.met` | `p2p-torrent`, `p2p-transfer`(추가/완료 시각·저장 경로·업/다운 바이트), `p2p-shared-file`, `p2p-search-term` | M | 높음(형사). 불법촬영물·CSAM·저작권 유포. eMule은 국내에서 '당나귀'로 남아 있다. |
| 11 | **Thunderbird + Windows Mail**(Windows Mail; MBOX E-mails 깊이) | Thunderbird `%APPDATA%\Thunderbird\Profiles\<p>\`: `Mail|ImapMail\<server>\Inbox`(확장자 없는 mbox, `.msf` 짝으로 판별), `global-messages-db.sqlite`(messages·conversations·identities·contacts), `abook.sqlite`, `calendar-data\local.sqlite`, `prefs.js`(identity 이메일·서버; logins.json·key4.db는 존재만). Windows Mail `%LOCALAPPDATA%\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\Indexed\LiveComm\<acct>\<ver>\Mail\*.eml`·`Att\`·`store.vol`(ESE, `ese_native` 바운디드 후보). Windows Live Mail `%LOCALAPPDATA%\Microsoft\Windows Live Mail\**\*.eml` | 기존 `email-message`/`contact`/`calendar-event`에 `mail_client`·계정·폴더 귀속, `email-client-account` | M | 중상. 개인 IMAP 메일 반출, 회사 메일 외부 전달. Windows Mail은 2024-12에 지원이 끝났지만 기존 이미지에는 남아 있다. |
| 12 | **Viber 데스크톱**(Viber) | `%APPDATA%\ViberPC\<전화번호>\viber.db`(평문 SQLite: Events, Messages, Contact, ChatInfo). `mobile/constants.py` `CHAT_APP_PROFILES` "Viber"를 재사용하고 `messenger.py` APPS에 추가한다. | `chat-message/-contact/-attachment` | S | 중. 외국인이 연루된 사건(마약·사기). |
| 13 | **Signal·QQ 인벤토리 전용**(Signal, QQ) | Signal `%APPDATA%\Signal\sql\db.sqlite`(SQLCipher), `config.json`(키는 읽지 않음), `attachments.noindex`. QQ `Documents\Tencent Files\<QQ번호>\Msg3.0.db`·NTQQ `nt_qq\nt_db\*.db`(암호화), `FileRecv\`(수신 파일) | `chat-app-inventory`(inventory_only·한국어 사유) + `app-file-store` 파일 목록 → 종료 범주 "정책 제외(존재·위치)" | S | 중. 은닉 메신저 사용 사실, 중국 연계 조직(QQ). |
| 14 | **LogMeIn**(LogMeIn) | `%ProgramData%\LogMeIn\*.log`(연결 IP·사용자), HKLM `SOFTWARE\LogMeIn`, LogMeIn Rescue/GoTo 앱 폴더. `remote_access.py` 제품 목록에 추가한다(국내 확장 후보: 알서포트 RemoteCall은 경로 확인 필요). | `third-party-remote-control-artifact` | S | 중. 원격 접속 사기, 침해. |
| 15 | **네트워킹 이벤트 채널**(Windows Event Logs - Networking Events) | `eventlog_channels.py` CHANNEL_GROUPS에 `networking`(NetworkProfile/Operational 10000/10001, WLAN-AutoConfig, Dhcp-Client, DNS-Client, BITS-Client, RasClient/VPN) 추가 + domains.ts `evt-ch-networking` | 기존 eventlog-event 채널 노드 | S | 중. 네트워크 접속·VPN 시각. |
| 16 | **Windows 로그온 배너**(Windows Logon Banner) | SOFTWARE `Microsoft\Windows\CurrentVersion\Policies\System` legalnoticecaption/legalnoticetext, `Windows NT\CurrentVersion\Winlogon` LegalNotice* | `registry-logon-banner`(캡션·본문·키 마지막 기록) | S | 중(기업). 보안 서약·모니터링 고지가 있었음을 입증한다. |
| 17 | **볼륨 정보**(File System Information) | NTFS `$Boot`(VBR: OEM, 섹터/클러스터, 총 섹터, MFT LCN, 8바이트 VSN), `$Volume`($VOLUME_NAME 0x60, $VOLUME_INFORMATION 0x70 버전·dirty) | `ntfs-volume-information`. VSN을 LNK·Prefetch 볼륨 일련번호와 피벗한다. | S | 중. USB·볼륨 귀속 상관. |
| 18 | **케이스 내 ISO 항목**(ISO Files) | ISO9660 PVD(섹터 16 `CD001`)·Joliet SVD(UTF-16 이름) 디렉터리 레코드. UDF는 목록 없이 표시만 한다. | 아카이브 항목 인벤토리 + Zone.Identifier(MOTW) 피벗 | S | 중. ISO를 이용한 MOTW 우회 초기 침투. |
| 19 | **가상 머신 구성**(Virtual Machines) | VMware `.vmx`(displayName·guestOS·vmdk·MAC), `%APPDATA%\VMware\preferences.ini`(mruVM), `inventory.vmls`. VirtualBox `%USERPROFILE%\.VirtualBox\VirtualBox.xml`, `*.vbox` XML. Hyper-V `.vmcx`는 존재만. | `vm-config`(제품·이름·게스트 OS·디스크 경로·MAC·마지막 상태 변경) | S | 중. VM 안에서 은닉 작업한 정황(안티 포렌식). |
| 20 | **Google Docs 스텁**(Google Docs) | `.gdoc/.gsheet/.gslides/.gdraw` JSON(url·doc_id·email), DriveFS 항목 mime `application/vnd.google-apps.*` | `cloud-sync-file`에 `google_doc_type`·URL 보강 | S | 중. 클라우드 문서 열람·소유 계정. |
| 21 | **잠재 브라우저 활동: URL 카빙**(Potential Browser Activity) | `pagefile.sys`·미할당 영역(기존 carving 인프라)에서 `https?://` ASCII/UTF-16LE 바운디드 스캔, 중복 제거, URL 분류 연결. hiberfil은 R5 밖이다. | `carved-url-candidate`(URL·오프셋·소스·인코딩·분류; 본문 없음) | M | 높음, 다만 오탐이 많다. 시크릿 모드·삭제된 기록 복구 후보(형사). |
| 22 | **AV 로그: McAfee**(McAfee Logs) | `%ProgramData%\McAfee\Endpoint Security\Logs\*_Activity.log`(OnDemandScan·AccessProtection·ThreatPrevention), 구 VirusScan `DesktopProtection\OnAccessScanLog.txt` | `av-detection-log`(제품·시각·동작·위협명·경로·사용자) | S | 중하. 국내는 AhnLab V3 비중이 커서 V3 로그 추가를 권장한다(AXIOM 밖, 경로 확인 필요). |
| 23 | **Chromium 루트 추가**(360 Safe Browser) | `AppData\Roaming\360se6\User Data`, `AppData\Local\360Chrome\Chrome\User Data`, Yandex `Yandex\YandexBrowser\User Data`, `Chromium\User Data`, CocCoc, QQBrowser `Tencent\QQBrowser\User Data` → `CHROMIUM_BROWSER_ROOTS` | 기존 browser-* 행 | S | 중하(중국·러시아·베트남 연루 사건). |
| 24 | **Android adb 백업 해제**(Android Backups) | `.ab`: 헤더 4줄(버전·압축·암호화) → zlib → tar. 해제된 트리는 기존 android-app-data 경로로 넘긴다. AES 암호화 백업은 존재와 사유만 낸다(대입 금지). | `android-backup-member` + 기존 모바일 행 | M | 중하(구형 기기 백업). |
| 25 | **바탕화면 재구성**(Rebuilt Desktops) | `%APPDATA%\Microsoft\Windows\Themes\TranscodedWallpaper`(확장자 없는 JPEG)·`CachedFiles`, NTUSER `Control Panel\Desktop\WallPaper`, Desktop 폴더 목록, `Shell\Bags\1\Desktop` IconLayouts(아이콘 위치는 M) | `desktop-wallpaper` 이미지 행 + 바탕화면 항목 표 | S | 저중. 사용자 귀속·화면 진술 검증. |
| 26 | **PSD 메타데이터**(Photoshop Files) | `8BPS` 헤더(크기·채널·색상 모드) + 이미지 리소스 0x0424 XMP(CreatorTool·History·DocumentAncestors), 0x040C 썸네일 | `media-image`/`document-metadata` 보강 + 썸네일 | S | 저중. 문서·이미지 위조 편집 이력. |
| 27 | **Facebook Messenger 데스크톱**(Facebook Messenger) | `%LOCALAPPDATA%\Packages\FacebookInc.Messenger_*\LocalState\msys_*.db`(평문 SQLite, 스키마 변동 큼) | `chat-*` | M | 저. 2025-12 앱이 종료되어 기존 이미지에만 남는다. 끝까지 미루면 (b)로 전환한다. |
| 28 | **Google Analytics 쿠키**(Google Analytics) | 쿠키 이름 허용 목록 `__utma`(첫/이전/현재 방문 시각·세션 수), `__utmz`(유입 출처·검색어), `_ga`(첫 방문 시각) | `browser-analytics-cookie` | S | 저. **정책 결정 필요**: 현재 쿠키 값은 목록화만 한다. 승인되지 않으면 (c) 정책 제외로 닫는다. |

### 순위 요약(가치 × 노력)
- 1군(먼저): 1 URL 분류(11행/S), 2 미디어 플레이어, 4 지도 URL, 5 지갑, 6 시작 프로그램, 7 SSH, 8 Office 계정이 모두 S이고, 3 Phone Link와 9 EGG는 M이지만 가치가 매우 높다.
- 2군: 10 P2P, 11 Thunderbird/Windows Mail, 12 Viber, 13 Signal·QQ, 14 LogMeIn, 15 네트워킹 채널, 16 로그온 배너, 17 VSN, 18 ISO, 19 VM, 20 Google Docs, 21 URL 카빙.
- 3군(여력 있을 때, 아니면 known-limitations로 연기): 22–28.

## 4. (b) 공개 미지원(39행): known-limitations에 실을 한국어 사유

| 항목 | 사유(한 줄) |
|---|---|
| AIM | 2017-12 서비스 종료, 국내 사용 사례 희소 |
| Ares | Ares Galaxy P2P 개발 중단, 국내 사용 희소(토렌트·eMule 흔적으로 대체) |
| Bebo | 메신저 기능 종료, 국내 미사용 |
| Bing Toolbar | IE 툴바, 배포 종료·IE 지원 종료(2022) |
| Carbonite | 국내 사용이 드문 미국 백업 서비스, 설치 사실은 설치 프로그램·Prefetch 행으로 확인 |
| Chatroulette | 웹 전용이라 로컬 앱 흔적이 없음, 브라우저 기록·URL 분류로 확인 |
| Chatstep | 웹 전용, 서비스 사실상 종료 |
| Cortana | Windows 11에서 제거됨, 검색 흔적은 Windows Search·브라우저 행으로 확인 |
| Gigatribe | P2P 서비스 종료 |
| Google Talk | 서비스 종료(Hangouts·Chat으로 이관) |
| Google Toolbar | IE 툴바 배포 종료 |
| Google+ | 2019 서비스 종료 |
| ICQ | 2024-06 서비스 종료 |
| IME Suggestions | 중국어·일본어 IME 학습 사전 대상, 한국어 IME에는 해당 추천 기록이 없음 |
| IP Addresses - Audio/Video Calls | 통화 상대 IP는 디스크에 남지 않는 휘발성 정보, 메모리 분석(memory-network) 행으로 확인 |
| Limerunner | P2P 클라이언트 단종 |
| Limewire (Limewire / Frostwire 행의 LimeWire 부분) | 2010 법원 명령으로 서비스 중단 (FrostWire는 R5 토렌트 파서로 지원) |
| Luckywire | P2P 클라이언트 단종 |
| Lync / Office Communicator | Skype for Business·Teams로 대체됨, 대화 기록은 Outlook '대화 기록' 폴더로 저장되어 PST 경로로 확인 |
| mIRC | 국내 사용 희소, 평문 로그는 문서 색인으로 검색 가능 |
| MSN Plus! | Windows Live Messenger 애드온, 메신저 종료(2013)와 함께 소멸 |
| MySpace | 메시징 기능 소멸, 국내 미사용 |
| Omegle | 2023-11 서비스 종료, 웹 전용 |
| ooVoo | 2017 서비스 종료 |
| Paltalk | 국내 사용 희소 |
| Pidgin | 국내 사용 희소, HTML/텍스트 로그는 문서 색인으로 검색 가능, accounts.xml 비밀번호는 정책상 비추출 |
| QuickBooks Files | 국내 회계는 더존 등 국산 ERP 중심, .qbw는 파일 인벤토리로만 확인 |
| RealPlayer | 구형·국내 사용 희소 |
| Safari (Windows) | Windows용 Safari 2012 개발 중단(macOS Safari는 지원) |
| Second Life | 국내 사건 관련성 낮은 가상세계 앱 |
| Shareaza | P2P 클라이언트 개발 중단 |
| TorChat | 개발 중단, Tor 사용은 Tor Browser(Firefox 계열) 흔적으로 확인 |
| Trillian | 국내 사용 희소 |
| Usenet Binary Files | 국내 사용 희소(NZB 뉴스그룹) |
| WebKit | Windows용 WebKit 브라우저(Safari) 단종 |
| Wickr Me | 2023-12-31 서비스 종료(모바일 내보내기 경로는 유지) |
| Windows Live Messenger / MSN Messenger | 2013 서비스 종료 |
| WordPerfect Files | 국내 사용 희소, 파일은 인벤토리·문자열 색인으로만 확인 |
| World of Warcraft | 게임 채팅 로그는 기본 비활성, 국내 사건 관련성 낮음 |
| Yahoo! Messenger | 2018-07 서비스 종료 |

(표의 Limewire 행은 혼합 행이라 39에 따로 세지 않는다.)

## 5. (c) 정책 제외: 존재·위치만 목록화

| 항목 | 현재 | 사유 · R5에서 할 일 |
|---|---|---|
| Encrypted Files | 감지 행 있음 | 비밀번호 대입·키 추출로 복호하는 것은 범위 밖이다. 감지(`archive-encrypted-*`, 문서 암호 플래그)는 이미 있으므로 문서화만 하면 된다. |
| LINE | `chat-app-inventory` | 앱 저장소 복호·키 추출 금지. 인벤토리와 사유가 이미 있다. |
| Telegram | 인벤토리 + Downloads 파일 | tdata 로컬 키 복호 금지. 이미 있다. |
| WeChat | 인벤토리 + FileStorage 파일 | SQLCipher 키 추출 금지. 이미 있다. |
| Rebuild Webpages | 없음 | 캐시 본문을 저장하지 않는다(BODY_POLICY: 해시·크기·앞 256바이트 서명). 유해물·개인정보가 재배포될 위험 때문이며, 페이지 재구성은 하지 않는다. |
| Webpage Recovery | 없음 | 위와 같다. |
| Windows Stored Credentials | 없음(목록도 없음) | DPAPI 복호는 금지한다. **R5 작업(S)**: `%APPDATA%|%LOCALAPPDATA%\Microsoft\Credentials\*`, `Microsoft\Vault\*`, `Microsoft\Protect\<SID>` 파일의 존재·크기·수정 시각·GUID 행(`credential-store-presence`)을 추가한다. browser-credential-store-inventory가 선례다. |
| (a)에서 정책 제외로 닫히는 행 | | Bitcoin·Crypto Currency(지갑 키·시드 비추출), Signal·QQ(복호 금지)는 R5 코드가 존재·위치 행을 만든 뒤 "정책 제외"로 닫는다. Google Analytics는 정책 결정에 따라 정한다. |
| (Table B) 자격 증명 복호·크래킹·원격 수집·외부 프로그램 실행·Magnet REVIEW | 정책상 제외 | Table A 행은 아니다. known-limitations "정책 제외" 절에 한 곳으로 모아 공개한다. |

## 6. (d) 해당 없음

| 항목 | 사유 |
|---|---|
| Adium, iChat, DS_Store, Numbers, Pages | macOS 전용(이미 해당 없음) |
| Apple Disk Images | DMG 내부 아티팩트는 macOS 범위다. Windows 사건에서 DMG는 증거 입력 추출(7z/bsdtar)로 처리한다. |
| iMessage | macOS `chat.db`는 macOS 범위다. PC의 iOS 백업 sms.db는 이미 있다(mobile-message). 혼합 행이다. |
| Magnet Web Page Saver | Magnet 전용 수집 포맷이다(타사 도구 산출물). |
| Xbox Internet Explorer History | Xbox 콘솔 이미지로, Windows 컴퓨터 범위 밖이다. |

## 7. R5 구현 3갈래 제안(파일 분리)

공통: 순수 표준 라이브러리, 합성 픽스처(실데이터·PII 금지), 새 artifact_type마다 카탈로그 계열·domains.ts 노드(추가만)·known-limitations 절을 둔다.

### L1 — 통신·미디어 앱(닫는 행 8: Your Phone, VLC, Windows Mail, Viber, Signal, QQ, Facebook Messenger, Photoshop + MBOX 깊이)
- 새 모듈:
  - `rapidtriage/artifacts/windows/phone_link.py`: `WindowsPhoneLinkProvider`, kind `windows-phone-link`.
  - `rapidtriage/artifacts/windows/media_players.py`: `WindowsMediaPlayersProvider`, kind `media-player`. VLC·PotPlayer ini를 읽고, PotPlayer·곰의 NTUSER 값은 `registry_depth`의 키 소스 인터페이스를 import만 해서 읽는다(수정하지 않음).
  - `rapidtriage/artifacts/email_clients.py`: Thunderbird와 Windows Mail/Live Mail. `ese_native`는 import만 한다.
- 수정:
  - `artifacts/email.py`: 확장자 없는 mbox 판별, Mail 앱·Thunderbird 루트 아래 .eml 중복 방지.
  - `artifacts/windows/messenger.py` `APPS`: viber, signal, qq, facebook-messenger 추가.
  - `artifacts/media.py`: PSD 처리.
- 카탈로그: `messenger.yaml`, `email.yaml`, `media.yaml`, 새 `phone_link.yaml`. mobile.yaml은 L3 소유라 쓰지 않는다.
- `core/artifact_domains.py`: `("mobile","windows-phone-link",None)`, `("media","media-player",None)` 추가.
- `domains.ts`: messaging(메신저 앱·메일 클라이언트), media(재생 기록), mobile(휴대폰과 연결) 블록.

### L2 — 운영체제·시스템·정책 존재 목록(닫는 행 12 + 정책 1: Startup Items, Windows Logon Banner, SSH Keys, Microsoft Office, Networking Events, File System Information, LogMeIn, McAfee Logs, Virtual Machines, Bitcoin, Crypto Currency, Rebuilt Desktops + Windows Stored Credentials 존재 행)
- 수정:
  - `artifacts/windows/registry_depth.py`: 디코더 추가(`registry-startup-approved`, `registry-logon-banner`, `registry-putty-session`/`ssh-known-host`, `office-identity`, 바탕화면 WallPaper 값).
  - `artifacts/windows/remote_access.py`: LogMeIn.
  - `core/eventlog_channels.py`: networking 그룹.
  - `core/ntfs_metadata.py` 또는 `artifacts/windows/filesystem.py`: `ntfs-volume-information`.
- 새 모듈 `rapidtriage/artifacts/windows/system_extras.py`: `WindowsSystemExtrasProvider`가 Startup 폴더 LNK, OpenSSH 파일, Backstage JSON, VM 구성, 지갑 존재, Credentials/Vault 존재, McAfee 로그, TranscodedWallpaper를 담당한다. `system.py`에 붙이면 L2만 수정하므로 그것도 가능하다.
- 카탈로그: `registry.yaml`, `execution.yaml`, `other.yaml`, `antiforensics.yaml`(VM·지갑), `rdp.yaml`(LogMeIn), `eventlog.yaml`, `ntfs.yaml`.
- `artifact_domains.py`: windows-system·windows-registry 타입 라우팅 행 추가(지갑·VM → anti-forensics, Startup → execution, 배너·Office → registry).
- `domains.ts`: os, registry, eventlog(`evt-ch-networking`), devices, anti-forensics, filesystem 블록.

### L3 — 웹·URL 분류·아카이브·P2P·복구(닫는 행 21: 웹메일 9, Torrent URLs, Flickr, Google Maps, 360 Safe Browser, EGG, ISO, Emule, Limewire/Frostwire, Potential Browser Activity, Android Backups, Google Docs, Google Analytics)
- 수정:
  - `core/derived/url_classes.yaml` + `url_classes.py`: 경로·스킴 규칙.
  - `core/derived/engine.py`/`stage.py`: 지도 URL 훅.
  - `artifacts/windows/browser.py`: Chromium 루트, (승인 시) GA 쿠키.
  - `core/files.py`: 아카이브 인벤토리에 EGG·ISO 연결.
  - `artifacts/cloud_sync.py`: .gdoc.
  - `artifacts/mobile/roots.py`.
  - `api/app/analysis_kinds.py`: URL 카빙 분석 노드. OpenAPI 재생성이 필요할 수 있다.
- 새 모듈: `core/derived/map_urls.py`, `core/egg_archive.py`, `core/iso9660.py`, `core/url_carving.py`, `artifacts/p2p.py`(`P2PArtifactsProvider`, kind `p2p`), `artifacts/mobile/adb_backup.py`.
- 카탈로그: `browser.yaml`, `archives.yaml`, `cloud.yaml`, `mobile.yaml`, 새 `p2p.yaml`.
- `artifact_domains.py`: `("web","p2p",None)` 추가.
- `domains.ts`: web(P2P·토렌트, URL 카빙), cloud, derived(통합 보기 위치) 블록.

### 공유 지점(코디네이터가 병합)
- `rapidtriage/artifacts/__init__.py` `_builtin_providers()`: 각 갈래가 한 줄씩 추가한다(L1 3개, L2 1개, L3 1개). 이름순으로 넣는다.
- `core/artifact_domains.py` `ARTIFACT_DOMAIN_TABLE`: 갈래별 주석 블록에 추가만 한다.
- `frontend/src/features/tree/domains.ts`: 갈래별 도메인 블록을 위에 적은 대로 분리한다. 같은 배열에 넣지 않는다.
- `docs/rapidtriage-known-limitations.md`: 갈래별 `## R5 Lx` 절에 추가만 한다.
- 매트릭스 Table A 갱신, §4 (b) 공개 미지원 목록, §5 (c) 정책 제외 절은 코디네이터가 병합 후 문서만 작업하거나, 별도 문서 전용 갈래로 병렬 진행한다. 혼합 행 4개(Limewire/Frostwire, Safari, iMessage, Crypto Currency)는 분리 사유를 함께 적는다.

### 검증 시나리오 요지
- 각 작업 항목: 양성 합성 픽스처 1개 이상 + 손상 입력 1개(격리하고 런은 계속).
- 비밀 비추출 단언: 지갑 키·시드, SSH 개인키, PuTTY/WinSCP 비밀번호, Signal 키, Credentials blob 내용.
- run-subset10에서 새 공급자의 추가 시간 ≤60 s, 오류 0.
- 매트릭스 재집계에서 없음 0, 부분 0.

## 8. 참고: 원 라운드 목표 대비
- R2 목표 "커뮤니케이션 있음 ≥30/54"는 달성하지 못했다(현재 있음 7 + 표 대체 6). 남은 41행은 (b) 28행(죽었거나 국내에서 쓰지 않는 앱), (a) 7행(Viber·Facebook Messenger·Emule·Frostwire·Flickr·Signal·QQ), (c) 3행(LINE·Telegram·WeChat), (d) 3행(Adium·iChat·iMessage)이다. R5 완료 기준(모든 행 종결)이 이 수치 목표를 대신한다고 문서에 명시해야 한다.
- R3 목표 "운영체제 있음 ≥45/49": 현재 41이다. L2의 시작 프로그램·네트워킹 이벤트·로그온 배너·볼륨 정보·바탕화면(5행)을 더하면 46으로 달성한다. Cortana·IME는 (b), Volatile은 표 대체다.
- 이 감사는 코드 판독만 했다. Phone Link·Thunderbird·PotPlayer 등의 경로와 스키마는 공개 자료 기준이며, 픽스처를 만들기 전에 버전별로 확인해야 한다.
