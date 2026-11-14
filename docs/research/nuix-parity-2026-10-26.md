# Nuix 기능 대조 — RapidTriage 현황과 R7 제안 (2026-10-26)

사용자 요청(2026-10-26): "nuix 기능검토해서 더잘 만들어줘라". 범위는 Nuix Workstation(엔진 9.x/100.x 온라인 도움말)·Nuix Investigate·Nuix Neo(1.3 릴리스 노트)가 **검사관에게 보이는 기능** 중 AXIOM 대조표(`docs/research/axiom-parity-matrix-2026-10-17.md`)가 다루지 않은 것이다. AXIOM이 "어떤 아티팩트를 파싱하는가"의 카탈로그였다면 Nuix는 "항목(item)을 어떻게 구조화·중복 제거·검색·내보내는가"의 모델이라, 이 문서는 파서 목록이 아니라 **데이터 모델·검토 워크플로·검색 문법·내보내기** 축으로 대조한다. 읽기 전용 조사이며 고객 데이터는 포함하지 않는다.

판정 규칙(AXIOM 대조표와 동일): `있음` = 같은 질문에 답하는 기능이 코드에 있음(바운디드여도 결과가 나오면 있음, 비고에 한계) · `부분` = 일부 소스·다른 메커니즘·후보 수준 · `없음` = 구현 흔적 없음 · `정책 제외` = 암호 크래킹·원격 수집·외부 프로그램 실행·비밀 값 추출·외부 서비스 전송 · `해당 없음` = eDiscovery 법률 프로덕션 전용이거나 아동 성착취물 사건 전용이라 RapidTriage(한국 형사·기업 사건, 로컬 우선, 표준 라이브러리 백엔드) 범위 밖. 판정은 코드 판독(`rapidtriage/core`, `rapidtriage/api/app`, `frontend/src/features`, 카탈로그 YAML, `docs/rapidtriage-known-limitations.md`)이며 실행 QA 결과가 아니다.

## 0. 한 줄 결론

RapidTriage는 Nuix의 **처리 폭**(이미지·컨테이너·카빙·해시·OCR 큐·키워드·FTS)은 대체로 갖췄고 국내 형식(HWP·EGG/ALZ·카카오톡·네이버/카카오 지도·AhnLab)에서는 Nuix보다 앞선다. 반면 Nuix의 핵심인 **항목 모델 네 가지 — 계열(family: 상위 항목·하위 항목), 항목 단위 중복 제거(item set), 개체(named entity) 검색, 통신 연결(Connections) 그래프** — 는 없거나 후보 수준이다. 이 넷과 **이메일 스레딩·예외 항목(irregular) 통계·법률 내보내기(load file)** 가 R7의 몸통이다. Nuix가 약한 곳(한국어 분석 언어 없음, 한글 OCR은 ABBYY 라이선스 의존, HWP·카카오톡 공개 지원 확인 불가)은 RapidTriage의 비교 우위로 유지한다.

## 1. Nuix 검사관 기능 카탈로그 (AXIOM 대조표 밖)

출처는 §6의 번호로 표시한다. 공개 문서에서 확인하지 못한 항목은 "(미확인)"으로 적었다.

### 1.1 수집·처리(ingestion/processing)

| # | Nuix 기능 | 요지 | 출처 |
|---|---|---|---|
| P1 | 항목 단위 컨테이너 처리 | PST·OST·EDB·NSF·MBOX·압축·포렌식 이미지(E01·L01·dd·AD1)·로드 파일을 모두 "항목 트리"로 펼침. 1,000종 이상 MIME 유형 | [1][12][13] |
| P2 | 순회 깊이(traversal) | 전체 순회 / 느슨한 파일만 / 느슨한 파일+이미지만(내용 추출 없이) | [5] |
| P3 | 다이제스트 | MD5 기본 + SHA-1·SHA-256·**SSDeep**·PhotoDNA, 다이제스트 상한 250 MB, 이메일 다이제스트 옵션(Bcc·통신일 포함, EDRM MIH 메시지 ID) | [5] |
| P4 | 삭제·미할당·슬랙 | 디스크 이미지 삭제 파일 복구(Forensic Mode), 미할당 색인, 미할당 카빙(블록 크기), 파일 끝 슬랙, **메일박스 슬랙(PST/OST/EDB 삭제 조각)**, 레지스트리 스마트 처리 | [5] |
| P5 | 텍스트 처리 | 본문 추출 on/off, 분석 언어 **영어/일본어만**, 불용어·어간, 정확 질의, 텍스트 요약, 텍스트 스트리핑(미지원 파일에서 3자 이상 문자열) | [5][4] |
| P6 | 계열 검색 필드·비중요 항목 숨김 | 하위 텍스트를 상위에 합친 계열 필드, 비중요(immaterial) 항목을 상위로 롤업 | [5] |
| P7 | 근사 중복(near-duplicate) | 단어 shingle 기반 유사도·클러스터, OCR 대화상자에서도 활성 | [5][4] |
| P8 | 개체 추출(named entities) | 본문·속성(IIS/Apache/Windows 이벤트 로그)·통신 메타(전화·이메일)에서 정규식 개체, 커스텀 개체 프로필, 1.3에서 Luhn·SSN·인명 검증기 | [3][5][9] |
| P9 | 이미지 분석 | 썸네일, 피부톤·색상 분석, 얼굴 탐지, 딥러닝 분류, 인쇄 이미지 | [5] |
| P10 | OCR | ABBYY 기반, OCR 프로필, 처리 중/후 OCR, 성공·실패 보고는 9.10+에서 수동 스위치 | [4][10] |
| P11 | 처리 프로필·메타데이터 내보내기 | 설정 저장·재사용, 처리 중 외부 DB로 메타 내보내기 | [5] |
| P12 | 워커 측 스크립트(WSS) | 처리 중 항목별 Ruby/Python 콜백으로 필터·태그·커스텀 메타 부여 | [7] |
| P13 | 예외·비정상 항목 | 잘못된 확장자·손상·삭제·빈 파일·암호화·비검색 PDF·텍스트 스트립·미인식·미지원 9범주를 통계 뷰에 표시, `flag:` 질의로 재검색 | [10] |
| P14 | 복호 | 복호 키·비밀번호 워드리스트, Passware 연동 | [10] |
| P15 | 타사 케이스 수용 | AXIOM 휴대용 케이스(태그 승계), Oxygen v16, EnCase v22 논리 이미지, Nuix Imager(메일·SharePoint·Dropbox·Drive·S3 원격 수집) | [9] |

### 1.2 검토(review)

| # | Nuix 기능 | 요지 | 출처 |
|---|---|---|---|
| R1 | 계열 모델 | 상위 항목(top-level)·하위 항목(descendants)·계열(families), 중요/비중요 항목; "Show All" 피벗 | [2][8] |
| R2 | 항목 집합(item set) | 집합 단위 중복 제거: 항목별·계열별·배치 내·보관자 순위별, 원본/중복 폴더, 배치 추가·제거 | [2] |
| R3 | 보관자(custodian) | 항목 소유자(메일박스·컴퓨터), 처리 시 배정, 보관자별 중복 제거 | [1][11] |
| R4 | 태그·커스텀 메타·메타 프로필 | 태그 계층, 커스텀 메타데이터 템플릿, 결과 열 프로필(.profile 이동 가능), 파생 메타(수식) | [11] |
| R5 | 클러스터 실행 | 이메일 스레드(헤더 기반) + 근사 중복(shingle) 조합, 스레드 종단(endpoint)·포괄(inclusive) | [1][4] |
| R6 | 컨텍스트 탭 | 분석 그래프(항목·개체·클리크, 자유/타임라인/지리/네트워크 레이아웃)·분석 표, 시간 ±30초~1일 피벗, 위치 피벗 | [6] |
| R7 | Connections(Investigate) | 이메일·Skype·Facebook·Slack·Teams·통화·문자·채팅 채널의 "누가 누구와" 그래프, 링크 뒤 항목 열람 | [8] |
| R8 | 일괄 코딩·제외·커스텀 메타·보관자 지정 | 결과/분석 표에서 우클릭 일괄 적용 | [6] |
| R9 | 마크업·교정(redaction) | PDF 마크업 세트, 인쇄 이미지 교정 | [1] |
| R10 | 통계 뷰 | 유형·예외 항목·크기 분포 | [10] |

### 1.3 검색(search)

| # | Nuix 기능 | 요지 | 출처 |
|---|---|---|---|
| S1 | 질의 문법 | AND/OR/NOT·+/−, `W/n`·`PRE/n` 근접, `~n` 슬롭, `~` 퍼지(Levenshtein), 와일드카드, 괄호, `\` 이스케이프, `field:` 접두 | [14][15] |
| S2 | 필드 | `kind:`, `mime-type:`, `flag:`(encrypted·deleted·text_stripped·irregular_file_extension…), `tag:`, `properties:`, `content:`, `name:`, `path:`, `has-text:`/`has-image:`/`has-embedded-data:` 등 | [10][14] |
| S3 | 필터(facet) 네비게이터 | 종류·MIME·날짜·언어·개체·태그·항목 집합·보관자·예외 항목 | [1][10] |
| S4 | 해시 집합 | MD5/SHA 다이제스트 목록 매칭, PhotoDNA | [5] |
| S5 | Investigate 질의 빌더·관련 항목 검색 | 공통/태그 조건 빌더, 피벗 검색, 디렉터리 브라우저, Connections | [8] |

### 1.4 내보내기·보고(export/reporting)

| # | Nuix 기능 | 요지 | 출처 |
|---|---|---|---|
| E1 | 법률 내보내기(load file) | Concordance DAT(기본 ASCII, UTF-8 스위치)·Summation DII·Opticon OPT, 기본 필드(DOCID·PARENT_DOCID·BEGINBATES·ENDBATES·BEGINGROUP·ENDGROUP·MD5HASH·ITEMPATH…), 네이티브/TIFF/PDF/텍스트 폴더, summary-report·top-level-MD5-digests | [16] |
| E2 | 번호 매기기 | 고정 폭 DOCID(Page/Folder-Page/Box-Folder-Page), 상위 항목+하위 항목 확장, 상위 항목 MD5 중복 제거(보관자별 옵션) | [17][18] |
| E3 | 프로덕션 세트·프로필 | 세트 생성 시 번호 고정, 내보내기 후 동결, 프로필 이동 | [19] |
| E4 | 네이티브 내보내기 | PST·NSF·EML·MSG·MHTML, 메타 CSV | [13] |
| E5 | 보고서 | 케이스 요약·항목 집합 통계·보관자 보고 등 "Generate reports" | [20] |
| E6 | Discover 승격 | 번호·배서 PDF·OCR 텍스트를 Nuix Discover로, 채팅을 대화 스레드로 | [9] |

### 1.5 규모·아키텍처

| # | Nuix 기능 | 요지 | 출처 |
|---|---|---|---|
| A1 | 분산 워커 | 워커 수 = 라이선스, 처리·이미징·내보내기 작업 분산(6.2 이후) | [7] |
| A2 | 케이스 형식 | 단순(simple)/복합(compound) 케이스, 증거 저장소 재사용, 이진 저장 옵션 | [5][9] |
| A3 | 스크립팅·API | Ruby/Python 콘솔·워커 스크립트, 엔진 API, GitHub 공개 스크립트(Light Index Dedupe·Deduplicate By Profile·Annotate From CSV·Bulk Ingestron) | [7][21] |

### 1.6 한국 시장 관점 — Nuix의 강·약(솔직하게)

- **분석 언어가 영어·일본어뿐**이다([5] "Analysis language"). 한국어 형태소·불용어·어간 처리가 없으므로 한국어 본문은 토큰 단위 검색에 의존한다. RapidTriage는 NFC+casefold·트라이그램 FTS로 한국어 부분 문자열 검색을 이미 한다(`core/search_index/textutil.py`, known-limitations "Search And OCR").
- **한글 OCR은 ABBYY 라이선스**와 CJK 팩에 의존한다([4]; ABBYY CJK 팩은 별도). RapidTriage는 Tesseract 로컬 OCR 큐(`core/ocr_queue.py`)로 kor 언어 힌트를 쓴다 — 품질은 이미지에 따라 다르다(known-limitations).
- **HWP·EGG/ALZ·카카오톡·네이버/카카오 지도·AhnLab**: Nuix 공개 지원 파일 유형 안내([12])에서 확인하지 못했다(미확인). RapidTriage는 모두 행 단위 파서가 있다(`core/doc_text.py`, `core/egg_archive.py`, `artifacts/windows/kakaotalk_messages.py`, `artifacts/windows/location_urls.py`, `artifacts/windows/av_ahnlab.py`).
- Nuix가 앞서는 국내 관련 항목: 이메일 스레딩·근사 중복(기업 내부 감사에서 메일 10만 건 검토량 감축), 개체 추출(주민등록번호·카드번호·전화번호를 사건 전체에서 한 번에), 법률 내보내기(국내 대형 로펌·회계법인이 Relativity/Discover로 넘길 때).
- 국내 규제 산출물(수사기관 **전자정보 상세목록**, 압수목록, 법원 제출 증거목록)은 Nuix에도 RapidTriage에도 전용 형식이 없다. 공개된 기계 가독 표준이 없으므로(수사기관 서식은 문서 양식) R7에서는 "파일명·경로·해시·크기·시각·출처" 열을 가진 CSV/DOCX 템플릿으로 답한다(§4 갈래 D).

## 2. 대조 매트릭스 — Nuix 기능 → RapidTriage 상태

열: Nuix 항목 | 상태 | RapidTriage 대응(모듈) | 빠진 것 | R7 갈래.

### 2.1 수집·처리

| Nuix | 상태 | RapidTriage 대응 | 빠진 것 | 갈래 |
|---|---|---|---|---|
| P1 컨테이너 항목화(PST/OST) | 부분 | `artifacts/email_pst.py`(pffexport/readpst, `RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1`일 때만) → email-message·email-attachment·calendar-event·contact; 기본은 `email-container-inventory` | 네이티브 PST 디코드 없음(정책: 외부 실행 기본 off). 항목 트리가 아니라 평면 행 | A(계열) |
| P1 NSF | 없음 | — | Lotus Notes 국내 사용 희소 → 공개 미지원 후보 | — |
| P1 MBOX/EML/EMLX | 있음 | `artifacts/email.py`, `email_clients.py`(Thunderbird) | — | — |
| P1 압축·ISO·EGG | 있음 | `core/files.py` 아카이브 멤버(20개 미리보기), `core/archive_image.py`, `core/egg_archive.py`, `core/iso9660.py`, `archive-file-inventory` | 멤버가 **별도 항목 행**이 아니라 상위 행의 `archive_members[:20]` | A |
| P1 이미지(E01·dd·VHD) | 있음 | `core/e01.py`·`e01_native.py`·`virtual_disk.py`·Sleuth Kit 체인 | AD1·L01·AFF는 어댑터 감지만(known-limitations) | — |
| P1 로드 파일 입력 | 없음 | — | Concordance DAT/OPT 가져오기 없음. 국내 사건에서 입력 빈도 낮음 | 해당 없음(연기) |
| P1 클라우드·모바일 | 있음 | Takeout·M365·Cellebrite/XRY/AXIOM CSV·JSON·adb `.ab`(`artifacts/mobile/*`, `cloud.py`) | UFDR 네이티브 없음(벤더 내보내기 먼저) | — |
| P2 순회 깊이 | 부분 | 런 모드(`core/run/profiles.py`)·kind 선택·`--extract` | "느슨한 파일만" 같은 깊이 스위치 없음(모드로 대체) | — |
| P3 MD5/SHA-1/SHA-256 | 있음 | `core/files.py` `hashes_by_path`, `evidence_source.hash_*`, 검색 `md5:`/`sha1:`/`sha256:` | — | — |
| P3 SSDeep·PhotoDNA | 없음 / 해당 없음 | pHash만(`media.py`, `similar:` S3 미구현) | 퍼지 해시 없음. PhotoDNA는 아동 성착취물 전용 | 연기(§3 비고) |
| P3 이메일 다이제스트 옵션 | 없음 | `email_thread_profile`에 Message-ID만 | 메일 중복 키(정규화 제목+시각+발신+본문 해시) 없음 | A |
| P4 삭제 복구·미할당 카빙·슬랙 | 있음 | `core/carving.py`(R3), `core/ntfs_unalloc.py`(R6 S2), `url_carving.py`, tsk_recover, ADS | 메일박스 슬랙(PST 삭제 조각) 없음(네이티브 PST 없음) | — |
| P5 본문 추출·언어 | 부분 | `core/doc_text.py`(HWP/OOXML/PDF/RTF/XLS), 한글·CJK 비율로 쓰레기 걸러냄(`_is_word_char`), NFC 색인 | **문서별 언어·문자계(script) 비율 필드 없음** → "한국어 문서만" 필터 불가 | B |
| P5 텍스트 스트리핑 | 부분 | `salvage_text`(UTF-16 런), 헥스·문자열 뷰 | 미지원 파일 전역 문자열 색인은 분석 노드(문자열 스캔)에만 | — |
| P6 계열 검색 필드·비중요 숨김 | 없음 | — | 첨부 본문을 메일 행에서 검색 불가 | A |
| P7 근사 중복 | 없음 | `analysis.py`에 "near-duplicate … required" 블로커 상수만 | shingle/minhash 없음 | C |
| P8 개체 추출 | 부분 | `core/indicators.py`(URL·IP·해시), `core/derived/normalize.py`(이메일·전화·SID·MAC·GUID·호스트), 통합 보기 6표 | 주민등록번호·카드(Luhn)·계좌·사업자번호·여권 없음; 검색 S2 필드(`rrn:`·`card:`·`phone:`·`ip:`·`email:`·`list:`)는 **선언만 되고 400 반환**(`search_index/query.py` 535행) | B |
| P9 썸네일 | 있음 | `api/app/thumbnail.py`, `views/ThumbnailView` | — | — |
| P9 피부톤·얼굴·딥러닝 분류 | 해당 없음 | 규칙 기반 시각 분류 힌트만 | 아동 성착취물 사건 전용·ML 모델(정책: 표준 라이브러리) | — |
| P10 OCR | 있음 | `core/ocr_queue.py`(Tesseract 로컬, kor 힌트, 사이드카), `viewer/views/ImageView` | 처리 중 자동 OCR 없음(큐 수동), 성공·실패 통계 없음 | B(통계만) |
| P11 처리 프로필 | 부분 | `processing_snapshot` 테이블, 런 모드, `RunOptionsFields` | **이름 붙여 저장·재사용하는 프로필 없음** | D |
| P11 메타 외부 DB 내보내기 | 해당 없음 | UCO JSON-LD(`core/case_export.py`) | — | — |
| P12 워커 측 스크립트 | 정책 제외(부분) | `core/plugins.py` 매니페스트(parser·viewer·report-exporter…) | 항목별 콜백 없음. 제품 안에서 임의 스크립트 실행은 정책상 하지 않음; 플러그인 매니페스트로 대체 | — |
| P13 예외 항목 9범주 | 부분 | `api/app/run_problems.py`(사유별 집계: 파서 오류·절단·건너뜀), `partial=1` 필터, `file-signature-mismatch`, `archive-encrypted-*`, 문서 암호 플래그, `empty_reason` | **항목 단위 예외 범주 집계·필터**(잘못된 확장자·손상·암호화·빈·비검색 PDF·텍스트 스트립·미인식·미지원) 없음 — 조각조각 흩어짐 | A |
| P14 복호·Passware | 정책 제외 | 감지 행만 | — | — |
| P15 AXIOM 케이스 수용 | 부분 | AXIOM 모바일 CSV 내보내기 정규화 | 휴대용 케이스(태그 승계) 없음, 낮은 우선 | — |

### 2.2 검토

| Nuix | 상태 | RapidTriage 대응 | 빠진 것 | 갈래 |
|---|---|---|---|---|
| R1 계열(상위·하위·중요) | 없음 | 첨부 행에 `message_id`·`export_item`(email_pst 492행), 아카이브 `archive_members[:20]`, adb `container_member`, 카빙 `recovery_method=carved` + `navigate.rows-for-source` 피벗 | **상위↔하위 관계 테이블·"계열 보기"·상위 항목 수 없음** | A |
| R2 항목 집합·중복 제거 | 부분 | `duplicate_content_groups`(파일 SHA-256, `core/files.py` 2521행), `similar` 갤러리, 리뷰보드·저장 검색 | 항목별/계열별/보관자별 **중복 제거 모드**, 원본/중복 구분 열, 중복 숨김 필터 없음 | A |
| R3 보관자 | 부분 | `evidence_source`(증거 단위), 행의 사용자 귀속(SAM·프로필·`actor:`), 카탈로그 `semantic: person/account` 127열 | **보관자 테이블·증거→보관자 배정·보관자 필터** 없음 | D |
| R4 사용자 태그·색·단축키 | 있음 | `case_tag`(색·단축키 1–9), `TagManagerDialog`, `review-batch` 해시 전파 | 태그 **계층** 없음(평면) | — |
| R4 커스텀 메타·열 프로필 | 부분 | `usePromotedFields`, 카탈로그 열, `review_mark.note` | 사용자 정의 필드(예: "유출 경로", "관련 인물") 없음 | 연기 |
| R5 이메일 스레드 | 부분 | `email_thread_profile`(Message-ID·References·In-Reply-To·정규화 제목, `thread_graph_validation_status: known-answer-required`) | **스레드 묶기·종단·포괄 판정·스레드 노드** 없음 | C |
| R6 컨텍스트(시간 피벗) | 부분 | 검색 `around:`, 타임라인 `사건 시각 ± n시간` 필터, `navigate.rows-for-source` | 행에서 "이 시각 전후 30초~1일" 1클릭 피벗 없음 | C(소형) |
| R6 그래프(개체·클리크·지리·네트워크) | 부분 | `DerivedGraph`(2홉·200노드, `api/app/derived_graph.py`), 지도 보기 | 통신 그래프 없음 | C |
| R7 Connections | 없음 | 통합 보기 사람 표(값→행) | 사람↔사람 엣지·채널·건수·기간 없음 | C |
| R8 일괄 코딩 | 있음 | `BatchBar`, `/case-db/review-batch`(태그·상태·해시 전파) | 보관자 지정·커스텀 메타 일괄은 D·연기 | — |
| R9 교정(redaction) | 부분 | 비밀 값 마스킹(`redact_secret_text`, 자격 증명 가린 값), PII 비노출 정책 | 문서 이미지 마크업·교정본 산출 없음 | 해당 없음(법률 프로덕션) |
| R10 통계 뷰 | 부분 | 대시보드·히스토그램·`review-counts` | 예외 항목 통계는 A | A |

### 2.3 검색

| Nuix | 상태 | RapidTriage 대응 | 빠진 것 | 갈래 |
|---|---|---|---|---|
| S1 불리언·괄호·NOT | 있음 | `search_index/query.py`(AND/OR/NOT/−, 깊이 32) | — | — |
| S1 근접 `W/n` | 있음 | `near:` | `PRE/n`(순서 지정) 없음 — 소형 | B |
| S1 퍼지 `~` | 있음 | fuzzy 모드(앞 절반 일치 제한) | — | — |
| S1 정규식 | 있음 | `re:/…/i`, `regex_guard` | — | — |
| S1 와일드카드 | 있음 | GLOB `*`/`?` | — | — |
| S2 `kind:`/`mime-type:` | 있음 | `in:`·`type:`·`ext:`·`extset:`·콘텐츠 칩 | MIME 문자열 필드는 없음(확장자·시그니처 기반) | — |
| S2 `flag:`(예외 항목) | 부분 | `deleted:`·`mismatch:`·`archive:`·`partial=` | `flag:encrypted`·`text_stripped`·`unrecognized` 상당 없음 | A |
| S2 `tag:`·리뷰 | 있음 | `tag:`·`review:`·`note:`·`bookmark:` | — | — |
| S2 개체 필드 | 없음 | S2 필드 선언만 | §2.1 P8 | B |
| S2 `has-text:`/`has-image:` | 부분 | `empty_reason`, 문서 색인 유무 | 필드 없음 | A(예외 범주로) |
| S3 필터 네비게이터 | 있음 | 트리 16도메인·조건 패널·열 필터 | 개체·중복·예외 facet은 A·B | A·B |
| S4 해시 집합 | 있음 | `/api/hash-sets`(NSRL RDS·텍스트·CSV), `hashset:` | 알려진 나쁨/좋음 **범주 라벨**과 트리 노드 없음 — 소형 | B |
| S5 질의 빌더 | 부분 | `SearchOptionsPopover`, 칩 | 조건 빌더 UI 없음(문법 안내로 대체) | — |
| 저장 검색 | 있음 | `/search/saved`, `saved_search` | — | — |

### 2.4 내보내기·보고

| Nuix | 상태 | RapidTriage 대응 | 빠진 것 | 갈래 |
|---|---|---|---|---|
| E1 로드 파일 | 없음 | 그리드 CSV(`review/csv.ts`, 1만 행, 꼬리 열), `/extract` zip(≤2 GB), 통합 타임라인 JSON, UCO JSON-LD | Concordance DAT/OPT·Summation DII, 네이티브+텍스트 폴더 | D |
| E2 DOCID 번호·계열 범위 | 없음 | `citation_id`(사건 내 인용 번호) | BEGINGROUP/ENDGROUP(계열)·고정 폭 번호 없음 | D(A의 계열 사용) |
| E3 프로덕션 세트 동결 | 해당 없음 | 제출 매니페스트(`submission.py`)·검증 패키지 해시 고정 | 법률 프로덕션 전용. 매니페스트가 "동결"을 대신함 | — |
| E4 네이티브 메일 내보내기(PST/MSG) | 없음 | `.eml` 원본은 `/extract`로 복사 | PST 쓰기 없음(정책: 외부 실행 없음) → EML+CSV로 답함 | D |
| E5 보고서(케이스 요약) | 있음 | `/case-report`(MD/HTML/DOCX/PDF), `korean_report.py`, 리뷰어 번들 | 항목 집합 통계·보관자별 표 없음 | D |
| E5 감사 로그·보관 연속성 | 있음 | `audit_event` 해시 체인, `custody.py`, `audit_trail.py` | — | — |
| E6 Discover 승격 | 정책 제외 | — | 외부 플랫폼 전송(Magnet REVIEW와 같은 분류) | — |

### 2.5 규모·아키텍처

| Nuix | 상태 | RapidTriage 대응 | 빠진 것 | 갈래 |
|---|---|---|---|---|
| A1 분산 워커 | 부분 | 로컬 병렬 스케줄러(`core/run/scheduler.py`, cpu 기반), Rust 워커(`core/worker.py`), 메모리 상한 | 다중 머신 분산 없음 — 로컬 우선 정책상 의도된 범위 | — |
| A2 케이스 형식·증거 재사용 | 부분 | 케이스 DB(SQLite)·런 링크·카탈로그·리뷰어 번들·`/runs/import` | 복합 케이스(여러 런 하나로 검색)는 cross-case 분석 노드만 | — |
| A3 스크립팅·API | 부분 | FastAPI OpenAPI 스냅샷, CLI, 플러그인 매니페스트 | 항목별 스크립트 콜백 없음(정책) | — |

### 2.6 집계

| 상태 | 수 |
|---|---|
| 있음 | 22 |
| 부분 | 25 |
| 없음 | 11 |
| 정책 제외 | 4 |
| 해당 없음 | 7 |
| 합계 | 69 |

없음 11: NSF, 로드 파일 입력, SSDeep, 이메일 다이제스트 옵션, 계열 검색 필드, 근사 중복, 계열 모델, Connections, 개체 검색 필드, 로드 파일 내보내기, DOCID 번호. 이 중 NSF·로드 파일 입력·SSDeep은 연기(국내 빈도·구현 비용), 나머지 8개가 R7 대상이다.

## 3. 상위 갭 — 한국 형사·기업 사건 검사관 가치 × 노력

순위 기준: (1) 국내 기업 내부 감사·유출·형사 사건에서 검토량을 줄이거나 증거를 직접 만드는가, (2) 지금 코드(통합 보기·검색 색인·케이스 DB)에 얹어 표준 라이브러리로 만들 수 있는가, (3) 정책 경계를 넘지 않는가. 노력: S(≤1 모듈·1일), M(2–4 모듈·수일), L(5+ 모듈·주 단위).

| 순위 | 갭 | 검사관 시나리오 | 노력 | 갈래 |
|---|---|---|---|---|
| 1 | **계열 모델**(상위·하위 항목, 계열 보기, 상위 항목 수) | "이 첨부가 어느 메일에 붙어 있었나", "이 압축에 뭐가 들었나", 검토 단위를 항목이 아니라 계열로 | M | A |
| 2 | **항목 단위 중복 제거**(MD5/SHA, 계열별, 보관자별) + 중복 숨김 필터 + 원본/중복 열 | 메일 3만 건 중 유일 항목만 검토, 같은 파일이 USB·메일·클라우드에 몇 번 나오나 | M | A |
| 3 | **개체 추출·검색 S2 필드**(주민등록번호·카드·전화·계좌·사업자번호·이메일·IP·목록) + 마스킹·공개 감사 | 개인정보 유출 사건: "사건 전체에서 주민번호가 든 파일·메일·채팅" 1질의 | L | B |
| 4 | **Connections 통신 그래프**(사람↔사람, 채널·건수·기간) | 내부자 공모 입증: 누가 누구와 몇 번, 어느 채널로 | M | C |
| 5 | **이메일 스레딩**(JWZ 알고리즘, 종단·포괄 판정) | 같은 스레드 40통을 포괄 메일 3통으로 | M | C |
| 6 | **예외 항목 9범주 통계·필터** | "처리 안 된 게 뭔가"를 한 화면에: 암호화·손상·빈·비검색 PDF·미인식 | S | A |
| 7 | **로드 파일 내보내기**(Concordance DAT/OPT·Summation DII, DOCID·BEGINGROUP) | 로펌·회계법인이 Relativity/Discover로 가져갈 때 | M | D |
| 8 | **근사 중복**(shingle MinHash, 문서·메일 본문) | 초안·수정본 묶음, 템플릿 메일 묶음 | M | C |
| 9 | **보관자 테이블**(증거→보관자, 행의 사용자 귀속→보관자, 보관자 필터·보고) | 다중 PC·메일박스 사건에서 "김○○ 소유 증거만" | M | D |
| 10 | **처리 프로필 저장·재사용** | 같은 로펌 의뢰 유형마다 같은 옵션 | S | D |
| 11 | **언어·문자계 필드**(문서별 한글/한자/영문/일문 비율) + 필터 | "한국어 문서만", "일본어 메일만" | S | B |
| 12 | **컨텍스트 시간 피벗**(행에서 ±30초~1일) | 실행 흔적 전후 1분의 이벤트 | S | C |
| 13 | **해시 집합 범주**(알려진 좋음/나쁨 라벨·트리 노드) | NSRL로 OS 파일 숨기기 1클릭, 악성 해시 노드 | S | B |
| 14 | **`PRE/n` 순서 근접·`has-text:`류 필드** | 문법 완성도 | S | B |
| 15 | **항목 집합 통계·보관자별 보고서 절** | 보고서에 "검토 모수·중복 제거 후·보관자별 건수" 표 | S | D |

순위 밖(사유 명시): SSDeep(표준 라이브러리로 rolling hash 구현은 가능하나 국내 사건 가치 낮음, 연기), NSF(공개 미지원 후보), 로드 파일 입력(연기), 커스텀 메타 템플릿(태그+메모로 대체, 연기), 피부톤·PhotoDNA·얼굴(해당 없음), Passware·Imager·Discover(정책 제외), 워커 측 스크립트(정책: 플러그인 매니페스트), 마크업 교정(법률 프로덕션 전용).

## 4. R7 — Nuix 동등 라운드 제안 (4갈래, 파일 소유 분리)

근거·절차는 `docs/plans/r6-followups-2026-10-19.md` §0을 그대로 따른다(계획 → QA 시나리오 → Opus 구현(워크트리 병렬) → Sonnet 워커 → 적대적 리뷰 → 게이트 → PR). 공유 파일(`artifacts/__init__.py`, `core/artifact_domains.py`, `frontend/src/features/tree/domains.ts`, `known-limitations.md`, 카탈로그 YAML, `routes_*`의 라우터 등록)은 갈래별 블록에 **추가만** 하고 코디네이터가 병합한다. 정책 유지: 자격 증명 복호·크래킹·원격 수집·제품 내 외부 실행 없음, PII 원값은 마스킹·공개 감사(`RAPIDTRIAGE_PII_REVEAL`) 경로로만.

브랜치: `feat/r7-nuix-parity`(main 기준), 갈래 브랜치 `feat/r7-a-families`·`feat/r7-b-entities`·`feat/r7-c-threads-graph`·`feat/r7-d-export-custodian`.

### 갈래 A — 계열·중복·예외 항목 (갭 1·2·6)

**소유 파일**: `rapidtriage/core/families.py`(신규), `rapidtriage/core/dedup.py`(신규), `rapidtriage/core/irregular.py`(신규), `rapidtriage/api/app/families.py`(신규), `rapidtriage/api/app/routes_families.py`(신규), `rapidtriage/api/app/row_conditions.py`(조건 `dup=`·`irregular=`·`family=` 추가), `rapidtriage/core/run/persist.py`(런 완료 시 `rapidtriage-families.jsonl`·`rapidtriage-dedup.json` 생성 블록), `frontend/src/features/viewer/views/FamilyView.tsx`(신규), `frontend/src/features/filters/conditionValues.ts`(중복·예외 칩), `frontend/src/features/grid/columns/`(원본/중복·계열 열), 테스트 `tests/test_r7_a_families.py`·`tests/test_r7_a_dedup.py`·`tests/test_r7_a_irregular.py`·`frontend/src/features/viewer/views/FamilyView.test.tsx`.

**설계**
- 계열(`core/families.py`): 런 출력에서 **상위↔하위 관계를 파생**한다(파서 변경 없음). 규칙: email-message → email-attachment(`message_id`+`export_item`+`folder` 일치), 파일 인벤토리 아카이브 행 → `archive_members`·EGG/ISO `archive-file-inventory` 멤버(멤버를 **가상 하위 항목** 로케이터 `<parent locator>#member:<index>`로), adb `android-backup` → `android-backup-member`·`container_member`, 카빙 행 → 소스 파일(`source_offset`), 메일박스(`email-mailbox`·PST 컨테이너) → 메시지, 메신저 메시지 → `chat-attachment`(`conversation_id`+`timestamp`). 출력 `rapidtriage-families.jsonl`(`parent_locator, child_locator, relation, material`)과 상위 항목 인덱스. 중요/비중요: 인라인 이미지·폴더·서명 첨부는 `material=false`.
- 중복(`core/dedup.py`): 항목 키 = SHA-256(파일·첨부) 또는 메일 키 `sha256(normalized_subject | date_utc(분) | from | sorted(to,cc) | body_sha256 or message_id)`; 모드 `item`·`family`(상위 항목 키 = 자기 키 + 정렬된 하위 키의 해시)·`custodian`(갈래 D의 보관자 배정이 있을 때 보관자 순위, 없으면 증거 순). 출력 `rapidtriage-dedup.json`(그룹·원본 로케이터·중복 수). 그리드 열 `중복`(원본/중복 n/—), 조건 `dup=original|duplicate|any`.
- 예외 항목(`core/irregular.py`): Nuix 9범주를 기존 필드에서 매핑 — bad-extension(`file-signature-mismatch`), corrupted(`parser_error`·`partial`·`truncated`), deleted(NTFS 조인 삭제 상태·카빙), empty(size 0·`empty_reason`), encrypted(`archive-encrypted-*`·문서 암호 플래그·EGG 암호화·`inventory_only` 암호화 저장소), non-searchable-pdf(PDF이면서 문서 색인 본문 0자), text-stripped(`salvage_text` 사용), unrecognized(시그니처·확장자 모두 미상), unsupported(파서 없음 kind). 조건 `irregular=<범주>`; 대시보드 카드 "예외 항목" + 트리 `처리 › 예외 항목` 9노드(`domains.ts` 블록 추가).
- API: `GET /api/runs/{id}/families/{locator}?direction=up|down|family`, `GET /api/runs/{id}/dedup/summary`, `GET /api/runs/{id}/irregular/summary`. `/artifacts`·`/files`·`/timeline`의 조건에 `family=`·`dup=`·`irregular=` 통과(R6 S3 인덱스 캐시 키에 포함).
- 콘솔: 뷰어 탭 "계열"(상위 1·형제·하위 트리, 클릭 → 그 행), 그리드 행 메뉴 "계열 보기"·"상위 항목으로"(단축키), 선택 → "상위 항목+하위 항목으로 확장" 명령(일괄 태그·CSV·갈래 D 내보내기가 이 확장을 사용).

**수용 기준**: 합성 런(메일 3통+첨부 5·ZIP 1(멤버 4)·adb 1·카빙 2)에서 관계 행 수·방향이 기대와 100% 일치; 중복 모드 3종이 Nuix 정의([2])와 같은 원본/중복 분할을 내고 보관자 순위가 결정적; 예외 9범주 합이 대시보드 카드와 같고 각 범주 클릭 → 조건 필터 → 행 수 일치; run-subset10(64만 행)에서 계열·중복·예외 파생 ≤ 90초, 메모리 ≤ 300 MB; 기존 행 수 변화 0.

**QA 시나리오**

| # | 시나리오 | 기준 |
|---|---|---|
| Q-A1 | 첨부 행에서 "상위 항목으로" | 메일 행 1개로 이동, 계열 탭에 형제 첨부 전부 |
| Q-A2 | ZIP 행 계열 보기 | 멤버 4개가 가상 하위 항목으로, 멤버 클릭 → 아카이브 미리보기 |
| Q-A3 | `dup=duplicate` + `in:email` | 원본 제외 건수 = 전체 − 그룹 수 |
| Q-A4 | 계열 모드 중복 | 첨부만 다른 두 메일은 중복 아님, 완전 동일 계열은 중복 |
| Q-A5 | 예외 항목 카드 | 9범주 건수 합, "암호화" 클릭 → `irregular=encrypted` 행에 EGG 암호 항목·암호 HWP 포함 |
| Q-A6 | 선택 확장 후 일괄 태그 | 상위+하위 모두 태그, `review-batch` 1회 |
| Q-A7 | 실데이터 | run-subset10 재파생 시간·메모리, 기존 artifact_type 행 수 변화 0 |
| Q-A8 | 게이트 | §0 전체, OpenAPI 스냅샷 갱신 |

### 갈래 B — 개체·검색 S2·언어·해시 범주 (갭 3·11·13·14)

**소유 파일**: `rapidtriage/core/search_index/patterns.py`(신규: 주민등록번호(생년·성별·검증 자리), 카드(Luhn, BIN 길이), 휴대전화·유선(E.164 KR), 계좌(은행별 자릿수 휴리스틱, 신뢰도 낮음 표시), 사업자등록번호(가중치 검증), 법인등록번호, 여권(M/R+8), 이메일, IPv4/IPv6/CIDR, 호스트), `rapidtriage/core/search_index/build.py`(`entity` 표: `kind, value_sha256, masked, locator, source_field`), `rapidtriage/core/search_index/schema.py`(표·인덱스·`INDEX_VERSION` v3), `rapidtriage/core/search_index/engine.py`(S2 필드 구현: `rrn:`·`card:`·`phone:`·`email:`·`ip:`·`host:`·`list:`·`account:`; `PRE/n`), `rapidtriage/core/search_index/query.py`(S2 가드 해제, `pre:` 추가), `rapidtriage/api/app/routes_search_index.py`(`/search/entities` facet, `/search/entities/reveal` 감사·`RAPIDTRIAGE_PII_REVEAL`), `rapidtriage/core/search_index/hashsets.py`(`category: known-good|known-bad|custom`), `rapidtriage/core/doc_text.py`(`script_profile`: 한글·한자·가나·라틴·키릴 비율, `language_hint`), `frontend/src/features/case/searchState.ts`·`SearchOptionsPopover.tsx`(개체 칩·언어 칩), `frontend/src/features/case/EntityPanel.tsx`(신규), 테스트 `tests/test_r7_b_patterns.py`·`tests/test_r7_b_search_s2.py`·`tests/test_r7_b_script_profile.py`.

**설계**
- 색인 빌드 때 행의 가변 텍스트·문서 본문·메일 헤더·채팅 본문에서 개체를 뽑아 **원값은 저장하지 않고** `value_sha256`+마스크(`901231-1******`, `**** **** **** 1234`, `010-****-5678`)만 저장한다. 검증 통과(주민번호 검증 자리·Luhn·사업자번호 가중치)만 `verified=true`, 그 밖은 `candidate`. 상한: 행당 64개, 전체 500만.
- 질의: `rrn:*`(존재), `rrn:901231*`(마스크 접두), `card:verified`, `phone:010-1234-5678`(정규화 후 해시 일치), `list:<keyword-pack id>`(키워드 팩·IOC 목록을 항목별 건수로), `email:@naver.com`(도메인 접미). 결과 facet `entities{kind: count}`. `reveal`은 감사 1건 + 세션 1회 + 행 로케이터 단위.
- 언어: `doc_text.finalize`에 `script_profile`(비율 dict)·`language_hint`(최다 문자계: ko/zh/ja/en/ru/mixed)를 붙이고 문서 행·메일 행에 전파. 조건 `lang=ko` 서버 필터(`row_conditions`는 갈래 A 소유 → 갈래 B는 `search_index`의 `lang:` 필드로만 구현하고 행 조건 칩은 R7 후속).
- 해시 집합: 가져오기 때 `category` 선택(NSRL은 자동 known-good), 검색 `hashset:known-good`·`-hashset:known-good`(OS 파일 숨김), 트리 `해시 집합` 노드 블록(`domains.ts` 추가).

**수용 기준**: 패턴 단위 known-answer 300개(참 100·검증 실패 100·비슷한 숫자열 100)에서 참 ≥ 99%, 오탐 ≤ 1%; 색인에 원값 문자열 0건(테스트가 DB 전체 grep); run-subset10 색인 증가 ≤ 15%, 빌드 시간 ≤ +20%; `rrn:*` 첫 페이지 ≤ 1초; 문자계 비율은 합성 HWP·DOCX·EML(한·중·일·영 혼합)에서 ±2%.

**QA 시나리오**

| # | 시나리오 | 기준 |
|---|---|---|
| Q-B1 | `rrn:verified in:docs` | 합성 문서 중 검증 통과만, 응답 본문에 원값 0건 |
| Q-B2 | `card:*` + `email:@naver.com` | AND 결합, facet 건수 = 집계 |
| Q-B3 | reveal | 감사 이벤트 1건·값 1회, `RAPIDTRIAGE_PII_REVEAL=off`면 403 |
| Q-B4 | `list:ioc-50` | 항목별 건수 ≤ 5초, CIDR ⊇ 개별 IP |
| Q-B5 | `lang:ko -lang:ja` | 문자계 비율 기준, 혼합 문서는 `mixed` |
| Q-B6 | `-hashset:known-good` | NSRL 집합 적용 전후 파일 수 차이 = 집합 적중 수 |
| Q-B7 | `pre:(계약 해지)/3` | 순서 근접만 적중 |
| Q-B8 | 실데이터 색인 재빌드 | 크기·시간 상한, 구 색인 버전 자동 재빌드 안내 |

### 갈래 C — 이메일 스레드·근사 중복·통신 그래프·시간 피벗 (갭 4·5·8·12)

**소유 파일**: `rapidtriage/core/email_threads.py`(신규, JWZ 알고리즘: Message-ID·References·In-Reply-To → 스레드 트리, 정규화 제목 병합, 종단(leaf)·포괄(inclusive: 본문 정규화 후 다른 메일을 포함) 판정), `rapidtriage/core/near_dup.py`(신규, 5-단어 shingle + 128 MinHash + LSH 밴드, 표준 라이브러리; 유사도 임계 0.8), `rapidtriage/core/derived/communications.py`(신규, 엣지 `a, b, channel, count, first, last, direction` — 소스: email from→to/cc, chat-message sender→대화방 참가자, phone-link call/message, mobile-message·mobile-call), `rapidtriage/core/derived/engine.py`(`TABLES`에 `communications` 추가 블록 1곳), `rapidtriage/api/app/routes_derived.py`(`/derived/communications/graph?who=&channel=&from=&to=&min=`), `rapidtriage/api/app/derived_graph.py`(통신 그래프 빌더 분기), `rapidtriage/core/run/persist.py`는 갈래 A 소유 → 갈래 C는 분석 노드(`api/app/analysis_kinds.py` `email-threads`·`near-dup` 블록)로 실행, `frontend/src/features/derived/CommunicationsGraph.tsx`(신규)·`graph.ts`(통신 엣지 타입), `frontend/src/features/viewer/views/EmailView.tsx`(스레드 패널 — 갈래 A의 `FamilyView.tsx`와 다른 파일), `frontend/src/features/grid/RowMenu.tsx`(시간 피벗 명령 "±30초/5분/1시간/1일"), 테스트 `tests/test_r7_c_threads.py`·`tests/test_r7_c_near_dup.py`·`tests/test_r7_c_communications.py`·`frontend/src/features/derived/communications.test.tsx`.

**설계**
- 스레드: 분석 노드 `email-threads` 출력 `thread_id, root_message_id, depth, is_endpoint, is_inclusive, member_count`를 메일 행에 조인(플래그 조인과 같은 `flags_join` 패턴). 트리 `이메일 › 스레드`(스레드별 노드, `is_inclusive` 필터), 뷰어 스레드 패널(트리 들여쓰기, 클릭 → 행).
- 근사 중복: 문서 색인 본문(`indexed_document`)과 메일 본문 대상, 그룹 `near_dup_group, resemblance`; 그리드 열·조건은 갈래 A의 `dup=` 체계와 충돌하지 않게 `neardup=<group>` 검색 필드(엔진 소유 갈래 B → 갈래 C는 분석 행과 뷰어 "유사 문서" 패널까지만, 검색 필드는 R7 후속으로 명시).
- 통신 그래프: 통합 보기 `communications` 표(사람 키는 `derived/normalize.person_key` 재사용). 그래프 뷰: 노드 = 사람 식별자, 엣지 굵기 = 건수, 색 = 채널, 기간 슬라이더, 노드 클릭 → `people` 값 행 → 원본 행(기존 피벗). 상한 노드 500·엣지 5,000(서버 집계 후 상위 N).
- 시간 피벗: 행 메뉴 "이 시각 전후…" → 타임라인 `사건 시각 ± n` 필터(기존 `conditionPanel` 상대 조건)로 이동, 기준 시각은 행의 대표 시각(`TIMELINE_FIELD_MAP` 첫 필드).

**수용 기준**: JWZ 테스트 코퍼스(합성 60통: 분기·References 누락·제목만 일치·Message-ID 중복)에서 스레드 수·포괄 메일 집합이 known-answer와 일치; 근사 중복은 합성 문서 쌍(10% 편집)에서 Jaccard 추정 오차 ≤ 0.05, 1만 문서 ≤ 60초; 통신 표는 합성 메일·카톡·전화 행에서 엣지 건수·방향 100%; 그래프 응답 ≤ 1초(run-subset10).

**QA 시나리오**

| # | 시나리오 | 기준 |
|---|---|---|
| Q-C1 | 스레드 노드 | 60통 → 스레드 7, 포괄 12; 포괄 필터 시 12행 |
| Q-C2 | References 없는 답장 | 정규화 제목+참가자+시각 창으로 같은 스레드에 병합, `merge_reason` 표시 |
| Q-C3 | 유사 문서 패널 | 초안·수정본 묶음, 유사도 표시, 원문 비교 열기 |
| Q-C4 | 통신 그래프 | 메일+카톡+전화 혼합에서 사람 A–B 엣지 채널 3종·건수, 기간 슬라이더로 변화 |
| Q-C5 | 노드 → 행 | 노드 클릭 → people 값 → 원본 행 2클릭 |
| Q-C6 | 시간 피벗 | Prefetch 행 "±5분" → 타임라인 조건 적용·행 수 > 0 |
| Q-C7 | 비밀·PII | 그래프 라벨에 자격 증명·마스킹 값 없음 |
| Q-C8 | 실데이터 | run-subset10 메일·카톡 행으로 표·그래프 생성 시간 |

### 갈래 D — 법률 내보내기·보관자·처리 프로필·보고서 절 (갭 7·9·10·15)

**소유 파일**: `rapidtriage/core/legal_export.py`(신규: Concordance DAT(þ/\x14 구분자, UTF-8 BOM·ASCII 옵션)·Opticon OPT(이미지 없으면 빈 파일)·Summation DII 최소 토큰, DOCID 고정 폭 번호(접두어+8자리), 계열 BEGINGROUP/ENDGROUP(갈래 A의 `families.jsonl`을 **읽기만**), 네이티브·텍스트 폴더 복사, `summary-report.txt`·`top-level-digests.txt`, 해시 매니페스트), `rapidtriage/core/case_db/custodian.py`(신규: `custodian`·`custodian_assignment` 표(증거·사용자 프로필·메일박스 → 보관자), 순위), `rapidtriage/core/case_db/schema.py`(마이그레이션 블록), `rapidtriage/api/app/routes_cases.py`(`/cases/{id}/custodians` CRUD·배정), `rapidtriage/api/app/routes_reports.py`(`POST /runs/{id}/legal-export`, 파일 다운로드), `rapidtriage/core/run/profiles.py`(이름 붙인 처리 프로필 저장·불러오기 `~/.rapidtriage/profiles/*.json`), `rapidtriage/api/app/routes_run_plan.py`(프로필 목록·적용), `rapidtriage/core/case_report.py`·`korean_report.py`(절 추가: 검토 모수·중복 제거 후·보관자별·예외 항목 표 — 갈래 A 출력 읽기만), `frontend/src/features/case/LegalExportDialog.tsx`(신규)·`exports.ts`·`RunOptionsFields.tsx`(프로필 선택)·`EvidenceFields.tsx`(보관자), 테스트 `tests/test_r7_d_legal_export.py`·`tests/test_r7_d_custodian.py`·`tests/test_r7_d_profiles.py`.

**설계**
- 법률 내보내기는 "선택 행(+계열 확장) → 번호 → 폴더 → 로드 파일 → 매니페스트" 한 흐름. 기본 필드는 Nuix Concordance 기본([16])과 이름을 맞춘다(DOCID·PARENT_DOCID·BEGINGROUP·ENDGROUP·FILENAME·FILEEXTENSION·CREATIONDATE·MODIFIEDDATE·FILESIZE·SENTONDATE·AUTHOREMAIL·TO·CC·BCC·SUBJECT·ORIGINALPATH·MD5HASH·SHA256HASH·CUSTODIAN·ITEMPATH·TEXTPATH·NATIVEPATH) + RapidTriage 꼬리 열(소스·위치·복구 방법·증거 번호·규칙@버전). PDF/TIFF 이미지 생성은 하지 않는다(OPT는 빈 파일, 문서에 명시). 상한 10만 항목·20 GB, PII 마스킹 옵션(갈래 B 마스크 재사용 — 없으면 기존 `redact_secret_text`).
- 국내 서식: 같은 엔진으로 "전자정보 상세목록" 템플릿(연번·파일명·경로·크기·해시(SHA-256·MD5)·생성/수정/접근 시각·출처 증거·비고) CSV/DOCX를 낸다(`korean_report.py`). 공식 기계 형식이 없음을 문서에 적는다.
- 보관자: 증거 추가 시 보관자 선택(없으면 "미지정"), 사용자 프로필 행(`windows-user-profile`·SAM)을 보관자에 매핑, 행의 보관자 = 증거 보관자(기본) 또는 프로필 매핑. 조건 `custodian=`은 `row_conditions`(갈래 A 소유) → 갈래 D는 케이스 DB 검색·보고서·내보내기에서만 쓰고 행 조건 칩은 후속.
- 처리 프로필: 런 옵션(모드·kind·캡·분석 노드·키워드 팩)을 이름으로 저장, 런 대화상자에서 선택, `processing_snapshot`에 프로필 이름·해시 기록.

**수용 기준**: 합성 런 내보내기 결과를 표준 라이브러리 파서로 다시 읽어 행 수·DOCID 연속성·계열 범위(BEGINGROUP ≤ DOCID ≤ ENDGROUP)·파일 존재·해시 일치 100%; Concordance 구분자·인코딩이 [16]과 일치; 보관자 배정 후 보고서 보관자별 표 건수 = 케이스 DB 집계; 프로필 저장→재적용 시 `processing_snapshot` 동일.

**QA 시나리오**

| # | 시나리오 | 기준 |
|---|---|---|
| Q-D1 | 메일 10통+첨부 선택 → 계열 확장 내보내기 | DOCID 연속, 첨부 PARENT_DOCID = 메일, BEGINGROUP/ENDGROUP 정확 |
| Q-D2 | DAT 재읽기 | 열 수·행 수·구분자, UTF-8 BOM, 한글 파일명 보존 |
| Q-D3 | 네이티브 누락(추출 불가 행) | 행은 남기고 NATIVEPATH 빈값 + 사유 열, summary-report에 집계 |
| Q-D4 | 전자정보 상세목록 | CSV/DOCX 연번·해시·시각, 100행 |
| Q-D5 | 보관자 | 증거 2개에 보관자 2명, 프로필 매핑 1건, 보고서 표·CSV CUSTODIAN 열 |
| Q-D6 | 프로필 | 저장·목록·적용·삭제, 런 스냅샷에 프로필 해시 |
| Q-D7 | 상한·안전 | 10만 행 초과 409, 경로 탈출 멤버 이름 안전 변환, CSV 수식 주입 방어 |
| Q-D8 | 게이트 | OpenAPI 스냅샷, 문서 참조 검사 |

### 갈래 간 의존·순서

- A의 `families.jsonl`·`dedup.json`은 C(통신 표의 첨부 제외)·D(BEGINGROUP·중복 제거 후 모수)가 **읽기만** 한다 → A를 먼저 병합하거나, C·D는 파일 없을 때 "계열 없음" 경로로 동작하게 만든다(테스트에 두 경우 모두).
- B의 마스크 함수는 D가 선택적으로 쓴다(없으면 기존 `redact_secret_text`).
- `row_conditions.py`는 A만 수정한다. B·D의 `lang=`·`custodian=` 행 조건 칩은 R7 후속(R7.5)으로 명시.
- 공유 파일 블록: `domains.ts`(A: 예외 항목·계열, B: 해시 집합, C: 스레드·통신), `derived/engine.py` `TABLES`(C), `routes` 등록(각 갈래 1줄), `known-limitations.md` `## R7 A/B/C/D` 절, OpenAPI 스냅샷은 코디네이터가 병합 후 1회 갱신.

### 완료 기준·규모

- §2 매트릭스의 R7 대상 8개 "없음"이 있음·부분(사유 명시)으로 닫히고, 상위 갭 1–15 중 1·2·3·4·5·6·7·9·10·12·13·15가 구현, 8(근사 중복 검색 필드)·11(언어 행 조건 칩)·14 일부는 R7.5로 이월 가능.
- 규모: 신규 모듈 12(백엔드 9·프런트 3), 수정 모듈 ~18, 테스트 ~14파일. 갈래 A·B·C·D 파일이 겹치지 않아 4 워크트리 병렬 가능. 실데이터: run-subset10 재파생(계열·중복·예외·색인 v3·통신 표)과 BSH 전체 이미지 런 1회(사용자 승인).
- 사용자 조치: (1) 개체 패턴의 국내 번호 체계 known-answer(가짜 값) 작성 검토, (2) 법률 내보내기 기본 필드명(영문 Concordance vs 한글) 결정 — 권고: 영문 기본 + 한글 라벨 옵션, (3) 보관자 개념을 케이스 마법사 2단계에 넣을지 결정, (4) BSH 전체 런 승인.

## 5. 방법과 한계

- Nuix 기능은 2026-10-26 기준 공개 온라인 도움말·릴리스 노트·교육 요강에서 읽었다. 로그인 전용 문서(지원 파일 유형 표 본문, 이메일 스레딩 가이드 본문, Investigate 타임라인 탭)는 열지 못해 "(미확인)"으로 두었고, HWP·카카오톡 지원 여부는 공개 자료로 확인하지 못했다.
- RapidTriage 판정은 코드 판독이다. 실행 QA·실데이터 확인은 R7 갈래별 Q 시나리오로 한다.
- Nuix의 분산 처리·라이선스 워커·Discover·Imager·Passware는 RapidTriage 정책(로컬 우선·외부 실행 없음·외부 전송 없음) 밖이라 "정책 제외"로 닫았고, 이 문서는 그 정책을 바꾸자고 제안하지 않는다.

## 6. 출처

1. Nuix Workstation 용어집 — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/book_-_glossary_of_terms_used_in_nuix_workstation.htm
2. Item Sets navigator — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/item_sets_navigator.htm
3. Enable settings to analyze named entities — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/extracting_named_entities/enable_settings_to_analyze_named_entities.htm
4. Perform OCR — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_ocr_processing/perform_ocr.htm
5. Configure data processing settings — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/configure_data_processing_settings.htm
6. Context tab — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/context_tab.htm
7. Guide to Worker Side Scripting — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_worker_side_scripting/guide_to_worker_side_scripting_1.htm ; Basic Ruby script examples — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_worker_side_scripting/basic_ruby_script_examples_and_their_usage.htm ; Nuix 6.2 distributed worker(역사적) — https://legaltechnology.com/?p=5284
8. Nuix Investigate: Search case data — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Investigate%20Online%20Help/User/Search_case_data.htm ; Investigate Connections — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Investigate%20Online%20Help/User/Investigate_Connections.htm
9. Nuix Neo 1.3 / Workstation 100.8 릴리스 노트 — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Neo%20Solutions/1_three/Nuix_Neo_v1.3_Release_Notes_(1).htm
10. Review and search for irregular file types — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/book_-_review_and_search_for_irregular_file_types.htm ; Check success or failure of OCRed items — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_ocr_processing/check_success_or_failure_of_ocred_items.htm ; Set decryption keys and a Word List — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/set_decryption_keys_and_a_word_list_of_passwords.htm
11. Configure Metadata Profiles — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/configure_metadata_profiles_and_their_templates.htm ; Forensic Practitioner Core Syllabus(보관자 관리) — https://nuix.com/sites/default/files/2024-10/Nuix%20Workstation%20Forensic%20Practitioner_Core_Syllabus.pdf ; Data Discovery Specialist Syllabus(근사 중복·스레딩·클러스터) — https://nuix.com/sites/default/files/2024-10/Nuix%20Workstation%20Data%20Discovery_Specialist_Syllabus.pdf
12. Nuix Supported File Types Guide — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/nuix_supported_file_types/nuix_supported_file_types_guide_1.htm
13. Nuix Workstation 제품 페이지 — https://www.nuix.com/products/nuixworkstation
14. Guide to Searching in Nuix Products — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_searching_nuix_products/guide_to_searching_in_nuix_products_1.htm ; Search operators — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_searching_nuix_products/search_operators.htm
15. Query types — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_searching_nuix_products/query_types.htm
16. Appendix A: Load file formats — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_working_with_legal_exports_and_load_files/appendix_a__load_file.htm
17. Define numbering and filenames for load file exports — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_working_with_legal_exports_and_load_files/define_numbering_and_filenames_for_load_file_exports.htm
18. Export a legal load file — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_working_with_legal_exports_and_load_files/export_a_legal_load_file.htm ; Export data to generate a legal load file — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/export_data_to_generate_a_legal_load_file.htm
19. Guide to Using Production Sets — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/guide_to_using_production_sets/guide_to_using_production_sets_1.htm
20. Generate reports — https://documentation.nuix.com/en/content/server/general/projects_frameless/Nuix%20Workstation%20Online%20Help/user_guide/book_-_generate_reports.htm
21. Nuix GitHub 공개 스크립트 — https://github.com/Nuix/Light-Index-Dedupe , https://github.com/Nuix/Deduplicate-By-Profile , https://github.com/Nuix/Annotate-From-CSV , https://github.com/Nuix/Bulk-Ingestron
22. 타사 참고(보조): Forensic Focus "Nuix Adds Powerful Context Interface" — https://www.forensicfocus.com/news/nuix-adds-powerful-context-interface-to-investigator-ediscovery-product-lines/ ; "Nuix Investigate: Giving Investigators Something To Talk About" — https://www.forensicfocus.com/news/nuix-investigate-giving-investigators-something-to-talk-about/ ; "Defeating Encryption And Password Protection"(Passware) — https://www.forensicfocus.com/webinars/nuix-digital-investigations-solutions-defeating-encryption-and-password-protection/
