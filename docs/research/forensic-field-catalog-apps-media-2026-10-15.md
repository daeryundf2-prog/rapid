# 아티팩트 그리드 필드 카탈로그 — 메신저·이메일·브라우저·클라우드·이미지·문서·압축·모바일 (조사 2026-10-15)

검증 범례: [V] 웹 출처로 확인, [K] 일반 지식(웹 미확인, 구현 전 샘플로 확인), [!] 출처 부족/상충.
공통 원칙: 모든 시각열은 "원본 값 + 종류(kind) + 변환 후 UTC + 시간대 근거"를 함께 보관. 타임스탬프 에폭은 DB/앱 버전별로 다르므로 값 크기(자릿수)로 단위를 판별하고 샘플로 검증할 것.

공통 타임스탬프 에폭 (환산식)
| 종류 | 단위 | 환산 | 상태 |
|---|---|---|---|
| Chrome/Chromium/Edge (urls, visits, downloads, logins) | 1601-01-01 이후 마이크로초 | (v/1e6) − 11,644,473,600 → Unix 초 | [V] |
| Firefox moz_historyvisits.visit_date, moz_cookies.lastAccessed/creationTime | 1970 이후 마이크로초 | v/1e6 | [V] |
| Firefox moz_cookies.expiry | Unix 초로 알려짐 | — | [K] |
| Apple Core Data (sms.db, chat.db 등) | 2001-01-01 이후 초(구버전) 또는 나노초(신버전) | +978,307,200초. 자릿수로 판별 | [V] 오프셋, 단위 전환은 [K] |
| WhatsApp messages.timestamp | Unix UTC (밀리초로 알려짐) | — | [V] UTC 여부, 단위는 [!] |
| Exif 일반 시각 | 현지 시각(시간대 없음) | OffsetTimeOriginal로 보정 | [V] |
| EXIF GPS 시각 (GPSDateStamp+GPSTimeStamp) | UTC | — | [V] |
| OLE 속성집합 날짜 | UTC | — | [V] |

---
## 1. 메신저 (KakaoTalk PC/모바일, Telegram, WhatsApp, Slack/Teams, SMS/iMessage)

### 핵심 열 (순서)
| # | 키 | 설명 / 비고 |
|---|---|---|
| 1 | `msg_time` | 발송/수신 시각. kind: sent / received / server / read 구분 보관. WhatsApp은 `timestamp`, `received_timestamp`, `receipt_server_timestamp` 별도 [V]. Telegram은 `date`(Unix) [K] |
| 2 | `app` | KakaoTalk / Telegram / WhatsApp / Slack / Teams / SMS / iMessage |
| 3 | `chat_room` | 대화방/스레드 (WhatsApp `chat_row_id`→jid, `key_remote_jid` 구버전 [V]; Kakao chatId [K]) |
| 4 | `sender` | 발화자 (WhatsApp `sender_jid_row_id` [V]; 그룹에서만 의미) |
| 5 | `counterpart` | 상대방(1:1이면 상대, 그룹이면 방 멤버 수) |
| 6 | `direction` | in/out. WhatsApp `key_from_me`(구) / `from_me`(신) [V]; Telegram `out` [K]; iMessage `is_from_me` [K] |
| 7 | `body` | 본문 (Telegram 본문은 바이너리 직렬화 BLOB이라 역직렬화 필요 [V]) |
| 8 | `attachment` | 첨부 유무/파일명/MIME/해시 |
| 9 | `deleted` | 삭제 여부 (live / 삭제 흔적 WAL·free-page·journal 복구 / 앱 내 "삭제된 메시지" 표식) |
| 10 | `read_state` | 읽음/전달 상태. WhatsApp `status` 정수 의미는 버전별 상이 [!]; receipt 시각 `receipt_device_timestamp` [V] |

### 보조 열
`msg_id`(WhatsApp key_id 등), `msg_type`(텍스트/이미지/통화/시스템), `reply_to`, `forwarded`, `edited`, `quoted_text`, `link_url`, `geo`, `service`(iMessage/SMS), `source_db`+`row_id`(출처 추적), `wal_origin`(WAL 유래 여부), `app_version`.

### 시간대/에폭 주의
- KakaoTalk 시각은 에폭/단위를 버전별로 샘플 검증 필요 [!]. 근거: 카카오톡 DB는 Android에서 KakaoTalk.db / KakaoTalk2.db(9.1.7까지) [V Magnet]; PC는 암호화 DB이며 키 도출 연구 존재 [V DFRWS/SKKU]. chatLogs 스키마와 type 코드는 웹 출처로 확인하지 못함.
- Telegram: 동일 메시지가 WAL에 여러 번 존재 → message id로 중복 제거 [V]. 버전마다 스키마 변경 [V].
- iMessage/SMS: Cocoa 초 vs 나노초 혼재 [V/K].
- Slack/Teams 내보내기: 보통 Unix 초(문자열) 또는 ISO-8601 UTC [K]; 워크스페이스 TZ가 아닌 UTC로 가정하고 검증.
- 서버시각 vs 단말시각 차이를 별도 열로 유지(단말 시계 조작 탐지).

### 특이사항 지표
| 이름 | 규칙(평문) | 의미 | 오탐 주의 |
|---|---|---|---|
| `time_regression` | 같은 방에서 msg_id 순서와 시각 순서가 역전 | 단말 시계 변경/DB 편집 | 서버 재전송, 오프라인 후 동기화 |
| `server_client_skew` | server 시각과 단말 시각 차 > 5분 | 시계 조작, 타임존 설정 오류 | 오프라인 큐 지연 |
| `id_gap` | 방 내 연속 ID에 결번 | 삭제 가능성 | ID가 전역 증가인 앱은 항상 결번 발생 |
| `deleted_recovered` | live가 아닌 WAL/free page에서만 복구된 행 | 삭제 은닉 정황 | 앱 자체 정리(auto-delete) |
| `disappearing_on` | 자동삭제/사라지는 메시지 설정 존재 | 증거 보존 한계 설명 | 정상 개인정보 설정 |
| `external_share_link` | 본문에 파일공유/단축 URL | 유출 경로 | 일반 링크 공유 |
| `late_night_burst` | 현지 야간(예 00–05시)에 짧은 시간 다수 발신 | 조사 우선순위 | 시간대 오판, 야간 근무 |
| `attachment_missing` | 메시지에 첨부 메타 있으나 로컬 파일 없음 | 미수집 또는 삭제 | 미다운로드(썸네일만) |
| `app_reinstall_gap` | DB 최초 행 시각 이후 큰 공백/초기화 | 앱 재설치/데이터 삭제 | 백업 복원 |

### 출처
- https://www.group-ib.com/blog/whatsapp-forensic-artifacts/ (WhatsApp msgstore.db 필드, 구 스키마)
- https://belkasoft.com/android-whatsapp-forensics-analysis (신 스키마 from_me, timestamp UTC)
- https://www.magnetforensics.com/blog/the-lesser-talked-about-messaging-apps/ (KakaoTalk.db/KakaoTalk2.db)
- https://dfrws.org/presentation/digital-forensic-analysis-of-encrypted-database-files-in-instant-messaging-applications-on-windows-operating-systems/ (Windows KakaoTalk 암호화 DB)
- https://www.forensicfocus.com/webinars/cracking-the-code-of-ios-messages-a-guide-to-storage-and-analysis-techniques-for-forensic-examiners/ (iOS sms.db)
- https://dfrws.org/wp-content/uploads/2025/03/Forensic-analysis-of-Telegram-Messeng_2025_Forensic-Science-International-D.pdf (Telegram cache4.db)

---
## 2. 이메일 (EML/MBOX/PST/OST/MSG)

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `date_header` | RFC 5322 `Date:` (발신자 주장, 오프셋 포함). 별도로 `received_first/last`(Received 체인 최상/최하 시각) |
| 2 | `from` | `From:` (display name + 주소 분리) |
| 3 | `to_cc_bcc` | To/Cc/Bcc (Bcc는 보낸편지함 사본에만) |
| 4 | `subject` | 제목 |
| 5 | `message_id` | `Message-ID:` (도메인부가 From과 불일치하면 지표) |
| 6 | `auth_results` | `Authentication-Results:` 의 spf / dkim / dmarc 판정 [V RFC 8601] |
| 7 | `return_path` | `Return-Path:` (SPF 검사 대상인 envelope MAIL FROM) [V] |
| 8 | `reply_to` | `Reply-To:` |
| 9 | `attachments` | 개수/파일명/MIME/해시/크기 |
| 10 | `folder` | 폴더/보관함(받은편지함, 삭제된 항목 등) |

### 보조 열
`received_chain`(홉 목록, 첫 외부 IP), `x_originating_ip`/`X-Mailer`/`User-Agent`, `in_reply_to`/`References`, `dkim_signature`(d=, s=), `received_spf`(구 헤더 [V]), `arc_*`, `list_id`, `importance`, `read_flag`, `flags`(deleted/draft), `size`, `body_text/html`, `source_container`(EML/MBOX/PST/OST/MSG)+`item_id`.
PST/OST/MSG 전용(MAPI): `PR_CLIENT_SUBMIT_TIME`(0x00390040), `PR_MESSAGE_DELIVERY_TIME`(0x0E060040), `PR_TRANSPORT_MESSAGE_HEADERS`(0x007D001E/문자열) [V Microsoft/Slipstick]. 헤더가 없는 내부(Exchange) 메일은 이 MAPI 시각만 존재.

### 시간대 주의
- `Date:`는 발신 클라이언트 값(조작 가능). 신뢰도 순: 수신 서버가 기록한 최상단 `Received` > `Date`. MAPI submit/delivery 시각이 transport header와 1초 등 어긋날 수 있고 이는 작성 도구 오류일 수 있음 [V Aspose]. Microsoft 365로 마이그레이션 후 delivery time이 이전 날짜로 덮어써진 사례 [V] → 마이그레이션 의심 시 submit time 우선.
- `Authentication-Results`는 수신측이 기록, 헤더 존재 자체가 내용의 진위를 보증하지 않음 [V RFC 8601]. 신뢰하는 authserv-id(자사 수신 서버)의 것만 채택.

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `spf_fail` | spf= fail/softfail | 발신 서버 비인가 | 포워딩/메일링리스트는 SPF가 깨지는 게 정상 |
| `dkim_fail` | dkim= fail/none | 변조 또는 서명 없음 | 리스트 서버가 제목/본문 수정 시 실패 |
| `dmarc_fail` | dmarc= fail | 정렬(alignment) 실패: Return-Path/DKIM d=와 From 도메인 불일치 [V] | 제3자 발송(마케팅 SaaS) |
| `display_name_spoof` | 표시명에 다른 도메인/임원명, 주소는 외부 | 사칭 | 정상 개인 메일 별칭 |
| `reply_to_differs` | Reply-To 도메인 ≠ From 도메인 | 회신 탈취(BEC) | 지원센터/비서 대행 |
| `returnpath_from_mismatch` | Return-Path 도메인 ≠ From 도메인 | 대리 발송 | ESP 사용 |
| `msgid_domain_mismatch` | Message-ID 도메인 ≠ From 도메인 [K] | 위조/다른 시스템 | 클라우드 메일 |
| `attach_double_ext` | 파일명 `.pdf.exe` `.docx.js` 등 | 확장자 위장 | 드물게 정상 파일명 |
| `attach_ext_mime_mismatch` | 확장자와 MIME/매직 불일치 | 위장 | 서버 변환 |
| `attach_exec_or_archive_enc` | 실행형/암호화 압축 첨부 | 악성 또는 유출 | 업무상 암호화 zip |
| `date_vs_received_skew` | Date와 첫 Received 차 > 1일 | 시계 조작/백데이트 | 큐 지연, 시계 오류 |
| `external_forward_auto` | 외부 주소로 대량 전달 | 유출 | 퇴사자 인수인계 |
| `bcc_self_or_personal` | 사내 발신 + 개인 도메인 수신 | 유출 정황 | 정당한 개인 연락 |

### 출처
- https://www.rfc-editor.org/rfc/rfc8601 (Authentication-Results)
- https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/pidtagtransportmessageheaders-canonical-property
- https://technet.microsoft.com/en-us/library/cc815404(v=office.14) (PidTagOriginalSubmitTime), https://forums.slipstick.com/threads/8124-cant-modify-pr_client_submit_time/
- https://mxtoolbox.com/dmarc/spf/spf-alignment (정렬 개념)

---
## 3. 웹 브라우저 (Chrome/Edge/Firefox)

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `visit_time` | 방문 시각 (Chromium `visits.visit_time`, Firefox `moz_historyvisits.visit_date`) [V] |
| 2 | `browser_profile` | 브라우저+프로필 경로 |
| 3 | `url` | URL (`urls.url`, `moz_places.url`) [V] |
| 4 | `title` | 페이지 제목 |
| 5 | `transition` | 이동 유형. Chromium `visits.transition & 0xFF` [V]; Firefox `visit_type` [V] |
| 6 | `referrer_visit` | `from_visit` (Chromium/Firefox 공통 필드) [V] |
| 7 | `visit_count_typed` | `visit_count` / `typed_count` (Firefox `typed`) [V] |
| 8 | `artifact_kind` | history / download / search_term / cookie / login / autofill / cache / extension / session |
| 9 | `download_target` | `target_path`, `received_bytes/total_bytes`, `state`, `danger_type` [V] |
| 10 | `search_term` | `keyword_search_terms` 조인 [V] |

### 보조 열
다운로드: `start_time`,`end_time`,`tab_url`,`referrer`,`mime_type`,`interrupt_reason`,`current_path` [V]. 쿠키: host, name, creation/last_access/expiry (Firefox moz_cookies: name,value,host,expiry,lastAccessed,creationTime [V]). 로그인(Login Data `logins`): `origin_url`,`action_url`,`username_value`,`date_created`,`date_last_used`,`times_used` — 비밀번호는 DPAPI/키체인 암호화라 파일 단독 복호 불가 [V]. 자동완성: Web Data(`autofill` name/value/count/date_created) [K]. 캐시/세션: Cache_Data, Sessions/Session Storage, Current Session [K]. 확장: 각 확장의 `permissions`/`host_permissions` [V], Secure Preferences [V]. `wal_origin`.

### 시간 주의
- Chromium 1601 µs vs Firefox 1970 µs 혼동 금지 [V]. Safari/WebKit은 2001 초 [V].
- DB는 `-wal` 포함 사본으로 분석(최근 레코드가 WAL에 있음) [K, 일부 V 일반 SQLite 원칙].
- 브라우저는 동기화(Sync) 시 다른 기기의 방문도 로컬 DB에 합침 → 기기 구분 필요 [K].

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `dl_from_filesharing` | 다운로드 referrer/tab_url이 파일공유·일회용 도메인 | 유출/악성 반입 | 업무용 클라우드 |
| `dl_dangerous` | `danger_type` ≠ 0 또는 Mark-of-the-Web ZoneId=3 [K] | 보호 기능 경고 | 오래된 값 의미 변화 |
| `dl_missing_file` | downloads 행 있으나 target_path 파일 없음 | 삭제/이동 | 이동/정리 |
| `incognito_gap` | 장시간 활동(프로세스·네트워크)에도 history 공백 | 시크릿 모드/삭제 | 단순 비활성 |
| `history_cleared` | history 시작 시점이 브라우저 설치/프로필 생성보다 훨씬 이후, 또는 id 결번 | 기록 삭제 | 자동 만료(보관기간) |
| `ext_broad_perm` | 확장 `<all_urls>` 또는 `https://*/*` + `webRequest` [V Velociraptor] | 전체 트래픽 열람 | 광고차단·번역기 등 합법 확장 |
| `ext_sideloaded` | 스토어 외 설치/Secure Preferences 불일치 | 악성 확장, 정책 위반 | 개발자 확장. 단, Secure Preferences HMAC 우회 가능하므로 무결성 증거 아님 [V Chalmers] |
| `search_sensitive` | 검색어가 사건 키워드(삭제 방법, 와이핑, 해외 송금 등) | 의도 정황 | 일반 정보 검색 |
| `cred_first_use_new_site` | 로그인 date_created가 사건 직전 | 신규 계정 사용 | 정상 사용 |
| `typed_url_direct` | typed 전이로 민감 URL 직접 입력 | 사전 인지 | 즐겨찾기/자동완성 |

### 출처
- https://forensics.wiki/mozilla_firefox/ , https://forensics.wiki/mozilla_firefox_3_history_file_format
- https://sleuthkit.org/autopsy/docs/api-docs/4.19.0/_firefox_8java_source.html (Firefox 쿼리, 쿠키)
- https://developer.chrome.com/docs/extensions/declare_permissions (permissions/host_permissions)
- https://research.chalmers.se/publication/521711 (Secure Preferences HMAC)
- https://docs.velociraptor.app/exchange/artifacts/pages/detection.application.cursedchrome (webRequest+all_urls)
- 주의: Chromium 스키마의 1차 문서(소스 `history_types`, `download_types`)는 확인하지 못함 [!]. 제3자 정리 기반이므로 `.schema`로 실제 열 확인.

---
## 4. 클라우드 내보내기 / 동기화 클라이언트

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `event_time` | 활동/수정/업로드 시각 (kind 명시) |
| 2 | `service` | Google / iCloud / M365(OneDrive, SharePoint, Teams) |
| 3 | `account` | 계정 식별자/UPN |
| 4 | `item_path` | 클라우드 상 경로/이름 |
| 5 | `activity` | 업로드/다운로드/공유/삭제/동기화/링크생성 (M365 Audit: FileDownloaded 등) |
| 6 | `size_hash` | 크기, 해시 |
| 7 | `shared_with` | 공유 대상/외부 공유 여부 |
| 8 | `client_ip_device` | IP, 기기/UserAgent |
| 9 | `taken_time` | (Takeout 사진) `photoTakenTime`, `creationTime` |
| 10 | `geo` | Takeout `geoData`/`geoDataExif` |

### 보조 열
Takeout 사이드카 JSON 필드: `title`, `creationTime`, `photoTakenTime`, `geoData`, `geoDataExif`, `people`, `url` [V]. iCloud: 파일 목록(이름, 경로, 크기, 수정시각) [V Elcomsoft, 벤더 도구 설명]. M365: Purview 감사 로그 CSV의 `AuditData` JSON 분리 컬럼 [V]. 동기화 클라이언트(OneDrive/Google Drive/iCloud Drive) 로컬 DB·로그: 위치·스키마는 웹 출처로 확인하지 못함 [!], 샘플 분석 필요. `retention_limit`.

### 시간 주의
- Takeout JSON 시각은 UTC라 현지 촬영시각과 어긋남 [V]. 임베디드 EXIF가 있으면 EXIF 우선, JSON은 웹 편집/EXIF 없는 파일 보완 [V]. JSON GPS와 EXIF GPS가 다를 수 있음 [V].
- M365 감사 보존: Entra/Exchange/OneDrive/SharePoint 기본 1년, 기타 180일 [V] → 기간 초과 공백은 "부재 증거" 아님.
- iCloud는 단일 내보내기 없음, 앱별 개별 내보내기 [V] → 수집 완전성 열(`export_scope`) 필요.

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `bulk_download` | 짧은 시간 내 다수 파일 다운로드/동기화 | 대량 유출 | 초기 동기화, 신규 기기 |
| `external_share` | 외부/익명 링크 공유 생성 | 유출 경로 | 정상 협업 |
| `new_device_login` | 처음 보는 기기/IP/국가 | 계정 탈취 또는 개인기기 | VPN, 출장 |
| `delete_after_share` | 공유/다운로드 직후 삭제 | 흔적 제거 | 정리 |
| `taken_vs_creation_gap` | photoTakenTime과 creationTime 차 큼 | 오래된 사진 업로드 | 사진 일괄 백업 |
| `json_exif_gps_mismatch` | JSON geoData와 EXIF GPS 상이 [V] | 편집 정황 | 위치 수정 기능 |
| `audit_retention_gap` | 보존기간 밖 조회 | 한계 표기 | 해당 없음 |

### 출처
- https://learn.microsoft.com/purview/audit-solutions-overview (감사 보존/내보내기)
- https://exiftool.org/forum/index.php?msg=90811 (Takeout JSON, photoTakenTime), https://pkg.go.dev/github.com/fulgidus/revoco@v0.1.5/metadata (JSON 필드 모델, 비공식)
- https://support.apple.com/en-qa/108306 (iCloud 데이터 사본)
- 한계: Google/Apple 공식 스키마 문서 및 OneDrive 동기화 클라이언트 로그 문서는 확인하지 못함 [!].

---
## 5. 이미지 & 비디오

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `capture_time` | `ExifIFD:DateTimeOriginal` (현지, 시간대 없음) [V] + `OffsetTimeOriginal`, `SubSecTimeOriginal` [V]; 비디오는 QuickTime CreateDate(UTC로 흔함) [K] |
| 2 | `fs_times` | 파일시스템 생성/수정/접근 (MAC) |
| 3 | `camera` | `Make` / `Model` (IFD0) [V] |
| 4 | `gps` | `GPSLatitude`+`GPSLatitudeRef`, `GPSLongitude`+Ref [V]; GPS UTC 시각 = `GPSDateStamp`+`GPSTimeStamp` [V] |
| 5 | `software` | `Software` (IFD0), XMP `xmp:CreatorTool` [V/K] |
| 6 | `dimensions` | 해상도, 방향 |
| 7 | `format_container` | JPEG/HEIC/PNG, 비디오 코덱/컨테이너 |
| 8 | `phash` | 지각 해시 (유사 이미지 그룹) |
| 9 | `is_screenshot` | 스크린샷 판정 (EXIF Make/Model 없음 + 화면 해상도 + 파일명 패턴) [K] |
| 10 | `thumb_present` | 임베디드 썸네일/원본 대조 가능 여부 |

### 보조 열
`xmp_dates`(`xmp:CreateDate`, `xmp:ModifyDate`, `photoshop:DateCreated`), `iptc_date_created/time_created`(IPTC는 Lightroom 등이 추가) [V], `lens`, `exposure`, `maker_notes` 유무(제조사 블록, 노출 정밀값 포함 [V]), `serial_number`, `live_photo_id`(HEIC+MOV 페어링 ContentIdentifier [K!]), `video_duration/fps/bitrate`, `qt_creation_date`, `sha256`, `icc_profile`, `orig_filename`, `mwg` 일치 여부(메타 형식 간 불일치 시 MWG 우선 권고 [V]).

### 시간 주의
- Exif 일반 시각은 현지시간, GPS 시각은 UTC [V] → GPS UTC와 DateTimeOriginal−Offset 비교로 시계 설정 검증 가능.
- `OffsetTimeOriginal`은 정보용일 뿐 값 계산에 쓰이지 않음 [V]; 없는 파일 다수.
- XMP 날짜는 ISO 8601이며 SubSec 포함 [V]. 같은 파일에 EXIF/XMP/IPTC/QuickTime 시각이 불일치할 수 있음.

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `exif_vs_fs_time` | DateTimeOriginal과 FS 생성/수정 차 > 1일 | 복사/재저장/시간 조작 | 파일 복사(FS 생성시각이 복사 시점), 다운로드 |
| `exif_future_or_pre_device` | 촬영 시각이 수정/수집 이후, 또는 기기 출시 이전 | 날조 | 카메라 시계 오설정 |
| `gps_present` | GPS 태그 존재 | 위치 증거/유출 위험 | 폰 촬영은 흔함 |
| `gps_time_tz_inconsistent` | GPS UTC ≠ (현지−Offset) | 시계 조작/시간대 오류 | 카메라 시계 오차 |
| `editing_software` | `Software`/CreatorTool에 Photoshop, GIMP, Lightroom 등 | 편집 가능성 | 단순 크기조절/뷰어 저장 |
| `exif_stripped` | Make/Model/DateTimeOriginal 모두 없음 | 메신저/SNS 업로드, 스크러빙 | 스크린샷, 웹 이미지 |
| `phash_dup_cross_folder` | 서로 다른 폴더에 pHash 거리 ≤ 임계(예 ≤ 8/64) | 은닉 복사본/재인코딩 | 썸네일, 템플릿류 |
| `thumb_mismatch` | 임베디드 썸네일이 본 이미지와 다름 | 편집 후 썸네일 미갱신(편집 정황) | 일부 도구는 썸네일 제거만 함 |
| `screenshot_flag` | 스크린샷 판정 | 원본 사진 아님 | 판정 휴리스틱 오류 |
| `live_photo_orphan` | HEIC만 있고 짝 MOV 없음(또는 반대) | 일부 삭제/전송 | 메신저 전송 시 분리 |
| `metadata_conflict` | EXIF/XMP/IPTC 날짜 서로 불일치 [V] | 후처리/동기화 도구 개입 | MWG 규칙 적용 도구 |

### 출처
- https://exiftool.org/TagNames/EXIF.html (EXIF 태그 — 본 조사에서는 MIT 미러 https://web.mit.edu/graphics/src/Image-ExifTool-6.99/html/TagNames/EXIF.html 로 확인, 구버전)
- https://exiftool.org/forum/index.php?msg=85494 (-time:all 우선순위), https://exiftool.org/forum/index.php?msg=89351
- https://exiftool.org/TagNames/Composite.html (SubSecDateTimeOriginal, GPS 합성)
- Live Photo ContentIdentifier는 출처 미확인 [!].

---
## 6. 문서 (Office / HWP / PDF)

### 핵심 열
| # | 키 | 소스 필드 |
|---|---|---|
| 1 | `doc_type` | docx/xlsx/pptx/doc/xls/hwp/hwpx/pdf |
| 2 | `author` | OOXML `dc:creator` / OLE `PIDSI_AUTHOR` / PDF Info `Author` |
| 3 | `last_saved_by` | OOXML `cp:lastModifiedBy` [V] / OLE `PIDSI_LASTAUTHOR` [V] |
| 4 | `created` | OOXML `dcterms:created` / PDF `CreationDate`(=`xmp:CreateDate`) [V] |
| 5 | `modified` | OOXML `dcterms:modified` / PDF `ModDate`(=`xmp:ModifyDate`) [V] |
| 6 | `revision` | OOXML `cp:revision` (정수) [V] / OLE `PIDSI_REVNUMBER`(저장 호출 횟수) [V] |
| 7 | `total_edit_time` | app.xml `TotalTime`(분) [V] / OLE `PIDSI_EDITTIME` |
| 8 | `last_printed` | OOXML `cp:lastPrinted` [K] / OLE `PIDSI_LASTPRINTED` |
| 9 | `application_template` | app.xml `Application`, `Template`(예 Normal.dotm) [V]; PDF `Creator`/`Producer`(`xmp:CreatorTool`/`pdf:Producer`) [V] |
| 10 | `embedded_active` | 매크로(vbaProject.bin), OLE 개체, 외부 링크, 첨부 |

### 보조 열
`company`, `manager`, `pages/words/characters`(app.xml [V]), `title/subject/keywords`, `custom_props`, `tracked_changes/comments`(작성자 목록), `hidden_text/sheets`, `external_rels`(원격 템플릿 URL), `pdf_incremental_updates`(%%EOF 개수), `pdf_xmp_history`(xmpMM:History — 출처 미확인 [!]), `pdf_encrypted`, `hwp_file_header_flags`(압축/암호/배포용 [V pyhwp]), `hwp_summary`(HWP 요약정보: 제목·주제·작성자·날짜·키워드 고정 레이아웃 [V LibreOffice hwpfilter]), `doc_id`(PDF ID/XMP DocumentID).

### 주의
- 값은 앱이 자동 기록하나 쓰기 도구가 임의 값으로 채움(예: TotalTime=1 고정, lastModifiedBy에 도구명) [V TEI]. 사용자·도구가 편집 가능하므로 "단서"이지 증명 아님.
- PDF Info 사전은 PDF 2.0에서 deprecated, XMP와 불일치 가능 → 둘 다 열로 [V].
- HWP는 표준 OLE PIDSI 속성집합이 아니라 HWP 고유 요약 구조라서 일반 PIDSI 파서가 작성자 등을 놓침 [V]; 마지막 저장자/편집시간/인쇄일 필드 매핑은 확인하지 못함 [!] → `hwp5proc summaryinfo` 출력으로 검증. 암호 여부는 FileHeader 플래그 [V].
- OLE 날짜는 UTC [V].

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `lastsaved_ne_author` | last_saved_by ≠ author | 제3자 수정/전달 | 협업, 템플릿 재사용 |
| `edit_time_zero_many_rev` | TotalTime = 0(또는 1) & revision 큼 | 자동 생성/변환/메타 조작 | 도구가 TotalTime 고정 기록 [V] |
| `created_after_modified` | created > modified | 시간 조작/복사 도구 | 시계 오차, 변환 |
| `modified_vs_fs` | 내부 modified와 FS 수정 차 큼 | 복사/재저장 | 이메일 첨부 저장 |
| `meta_tool_name_user` | lastModifiedBy가 라이브러리/도구명 [V] | 프로그램 생성 | 자동화 보고서 |
| `macro_or_ole` | vbaProject.bin/OLE/DDE 존재 | 악성/자동화 | 업무 매크로 |
| `external_template_url` | 원격 템플릿/링크 | 템플릿 인젝션 | 사내 서버 템플릿 |
| `printed_present` | last_printed 존재 | 인쇄 사실 | 인쇄 후 저장 |
| `pdf_creator_producer_odd` | Creator는 Word, Producer는 편집기/온라인 변환기 | 재작성/편집 정황 [V 의미] | 정상 PDF 변환 파이프라인 |
| `pdf_incremental_update` | %%EOF 다수 | 사후 수정 | 서명/양식 |
| `tracked_authors_many` | 변경추적 작성자 다수/이름 불일치 | 협업/타인 개입 | 정상 검토 |
| `meta_scrubbed` | 작성자/회사 모두 공란 | 메타 제거 | 익명 템플릿 |

### 출처
- https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2007/bb447589(v=office.12) (OOXML 확장 속성)
- https://python-pptx.readthedocs.io/en/latest/dev/analysis/pkg-coreprops.html (코어 속성)
- https://learn.microsoft.com/en-us/windows/win32/stg/implementing-the-summary-information-property-set (OLE 요약정보)
- https://pyhwp.readthedocs.io/en/develop/_sources/hwp5proc.rst.txt , https://docs.libreoffice.org/hwpfilter/html/classHWPInfo.html (HWP)
- https://api-reference.pdf-tools.com/pdfsdk/1.20/dotnet/html/T_PdfTools_Pdf_Metadata.htm (PDF Info↔XMP 매핑)

---
## 7. 압축파일 & 암호화 컨테이너

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `archive_path` | 컨테이너 경로 + 형식(ZIP/7z/RAR/TAR/ISO/VHD/BitLocker/VeraCrypt) |
| 2 | `entry_name` | 내부 파일명(목록 암호화 시 불가) |
| 3 | `entry_size_comp` | 원본/압축 크기 |
| 4 | `entry_mtime` | 항목 수정시각 (ZIP은 DOS 현지시각, 시간대 없음 [K]) |
| 5 | `encrypted` | 암호화 여부 (ZIP general purpose bit 0 [V]) |
| 6 | `enc_method` | ZipCrypto / AES (bit 0+6 또는 extra field AES [V]) / 7z AES-256 [V] |
| 7 | `header_encrypted` | 파일 목록 암호화 (ZIP bit 13 [V], 7z `-mhe=on` [V]) |
| 8 | `crc_hash` | CRC32/해시 |
| 9 | `nested_depth` | 중첩 단계 |
| 10 | `container_signature` | 시그니처/엔트로피 판정 |

### 보조 열
`comment`, `split_volume`, `creator_tool`(ZIP version made by), `ratio`, `path_traversal`, `sfx`(자동압축 해제), `entropy`, `size_multiple_of_64`(VeraCrypt 후보 힌트 [V]), `fs_times_container`, `password_found`.

### 탐지 메모
- BitLocker: 볼륨 헤더 `-FVE-FS-` (부트 레코드 오프셋 3) [V]; BitLocker To Go는 FAT/exFAT 부트레코드 + GUID로 식별 [V].
- VeraCrypt/TrueCrypt: 시그니처 없음, 고엔트로피 + 크기가 64의 배수 [V Truehunter] → 확률적 판정, 헤더 부재만으로 단정 금지 [V].
- 7z 헤더 암호화 시 구조 불가시, 정확한 탐지 바이트는 출처 미확인 [!].

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `enc_archive_with_exfil` | 암호화 아카이브가 외부 매체/업로드 직전 생성 | 유출 준비 | 업무용 압축 |
| `header_encrypted_list_hidden` | 목록 암호화 | 의도적 은닉 | 보안 관행 |
| `high_entropy_no_sig` | 시그니처 없음+고엔트로피+64 배수 | 암호화 컨테이너 후보 | 압축/난수 데이터, 디스크 이미지 |
| `ext_mismatch_container` | 확장자(.dat/.jpg 등)와 달리 아카이브 매직 | 위장 | 이름만 틀림 |
| `nested_deep` | 중첩 ≥ 3단계 | 탐지 회피 | 설치 파일 |
| `zip_bomb_ratio` | 압축 해제 비율 극단 | 분석 방해 | 로그 등 반복 데이터 |
| `sfx_exe` | SFX 실행파일 | 은닉 실행 | 정상 설치기 |
| `entry_time_later_than_container` | 항목 mtime이 컨테이너 FS 시각보다 미래 | 시계 조작 | DOS 시각/시간대 |

### 출처
- https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-8-3-3-encrypting-files-with-winrar-or-7z.html (암호화 아카이브 탐지 규칙)
- https://pds-ppi.igpp.ucla.edu/volume/PV01_0001/SOFTWARE/SOURCE/ZIP_WARE/APPNOTE.TXT (ZIP APPNOTE 사본; 최신 원본은 PKWARE)
- https://host-aws.elcomsoft.com/presentations/20190504_forensic_anlysis_cryptocontainers_en.pdf (암호 컨테이너 포렌식)
- https://www.forensicfocus.com/articles/how-to-process-a-clear-key-bitlocker-image-file-to-generate-a-decrypted-raw-image/ (BitLocker 시그니처)

---
## 8. 모바일 내보내기 (iOS 백업 / Android)

### 핵심 열
| # | 키 | 설명 |
|---|---|---|
| 1 | `event_time` | 통화/메시지/위치 시각 (iOS Core Data 2001 에폭, 초↔나노초 [V]) |
| 2 | `data_class` | contact / call / sms / app / location / media |
| 3 | `counterpart` | 번호/이름 |
| 4 | `direction` | in / out / missed |
| 5 | `duration_or_body` | 통화 시간 또는 메시지 본문 |
| 6 | `app_bundle` | 앱 ID(`com.…`)/설치·사용 시각 |
| 7 | `lat_lon_acc` | 위치 좌표+정확도 |
| 8 | `device` | 기기 모델, OS 버전, 백업 시각 |
| 9 | `source_file` | 원본 DB (iOS: Manifest.db 도메인-상대경로 → 해시 파일명 [V]) |
| 10 | `deleted` | 삭제 복구 여부 |

### 소스 위치 [V 출처 있음 / K]
- iOS: 백업 폴더 내 Info.plist, Status.plist, Manifest.plist, Manifest.db [V]; 파일명 = SHA-1(domain-path), 예: `HomeDomain-Library/SMS/sms.db` [V]; SMS/MMS/iMessage는 sms.db 하나(macOS는 chat.db) [V]; 통화 `CallHistory.storedata` [V 비공식]; 연락처 `AddressBook.sqlitedb` [V 비공식]. 암호화 안 된 백업은 Safari/Health/Keychain 제외 [V]. BFU 추출에서는 sms.db 없음 [V].
- Android: `contacts2.db`, `calllog.db`(일부 기기는 contacts2.db 내 Calls, 삼성은 logs.db), `mmssms.db`(`icing_mmssms.db` 변형) [V]. 삭제 레코드는 미할당/journal에 남음 [V].
- Android 앱/위치(`packages.xml`, Google Maps Timeline 등)는 출처 미확인 [!].

### 보조 열
`contact_org/email/address`, `call_type`, `sim/account`, `app_version/install_time/last_used`, `wifi_ssid/bt_device`(연결 이력) [K], `photo_exif_link`, `backup_encrypted`, `iOS_build`, `last_backup_date`, `lockdown/pairing` [K].

### 특이사항 지표
| 이름 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| `backup_encrypted_partial` | 비암호화 백업 → 민감 영역 누락 [V] | 증거 부재가 아니라 수집 한계 | 정상 설정 |
| `deleted_calls_sms` | 활성 DB엔 없고 free page/journal에만 존재 [V] | 삭제 정황 | 자동 정리 |
| `call_to_unsaved_number` | 반복 통화하는 번호가 연락처에 없음 | 은닉 연락 | 일반 사업자 번호 |
| `call_burst_event` | 사건 시각 전후 통화/메시지 급증 | 연관 정황 | 우연 |
| `app_installed_recent` | 사건 직전 메신저/VPN/삭제앱 설치 | 의도 정황 | 일반 앱 설치 |
| `location_outlier` | 평소 반경 밖 위치, 야간 이동 | 동선 단서 | 위치 오차 |
| `time_epoch_mismatch` | 한 DB 내 초/나노초 혼재 [V] | 변환 오류 방지 | 버전 전환 |
| `factory_reset_gap` | 백업 내 데이터가 특정 시점 이후만 존재 | 초기화/마이그레이션 | 새 기기 복원 |

### 출처
- https://theapplewiki.com/wiki/ITunes_Backup (iOS 백업 구조)
- https://imazing.com/guides/use-imazing-for-ios-digital-forensic-analysis-and-e-discovery (Manifest 체크섬, 암호화)
- https://www.magnetforensics.com/blog/android-messaging-forensics-sms-mms-and-beyond/ (Android SMS/MMS DB)
- https://epochconverter.com/coredata (Core Data 에폭 오프셋 978307200)
- 참고 파서: iLEAPP (iOS 백업 오픈소스)

---
## 검증 요약 / 한계
- 완전 확인: Chromium/Firefox 시각 에폭 및 history·downloads·places 열 이름, Authentication-Results/Received-SPF/Return-Path와 DMARC 정렬, EXIF OffsetTimeOriginal/SubSecTimeOriginal/GPS UTC 성질, OOXML cp:lastModifiedBy·revision·TotalTime·Template, PDF Info↔XMP 매핑, ZIP bit 0/6/13, BitLocker `-FVE-FS-`, iOS Manifest.db 해시 규칙, Android DB 경로, M365 감사 보존기간.
- 미확인(구현 전 샘플 검증 필수): KakaoTalk chatLogs 열/type 코드/에폭, Telegram messages 열 상세(일반 지식), WhatsApp status 정수 의미, Chromium 스키마 1차 문서, HWP 마지막 저장자/편집시간/인쇄일 매핑, Live Photo ContentIdentifier, xmpMM:History, OneDrive/Google Drive 동기화 클라이언트 로그, 7z 암호화 탐지 바이트, Android 앱/위치 아티팩트.
- 지표 임계값(1일, pHash 거리, 5분, 야간 시간대 등)은 제안값이며 사건별 조정 가능한 파라미터로 둘 것.
