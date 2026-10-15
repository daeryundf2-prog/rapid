# P4 — 마에스트로식 2차 분류 트리 (2026-10-12, P1 완료 후 착수)

상위: `docs/plans/maestro-gap-review-2026-10-12.md` §5 P4. 전제: P1(`analyses/`, `artifact_type=` 서버 필터, 트리 노드 상태)이 main에 있음.
범위: 파일 인벤토리 분류 규칙(`core/files.py` CATEGORY_RULES의 **추가**만, 기존 7범주 불변), 서버 트리(`api/app/tree.py`), 콘솔 트리/컬렉션 필터. 파서 불변.

## 1. 최종 사용자가 보는 문제

마에스트로 트리는 "파일 포렌식 › 스크립트 파일 › JS/JSE 47" 처럼 포맷·역할별로 바로 세어 준다. 우리 트리는 파일 7범주(문서·이미지·압축·DB·이메일·실행·메모리 덤프)에서 끝나서, 검사관이 "XML 설정 파일만", "DLL만", "SVG만", "ADS 달린 파일만", "웹셸 후보만"을 보려면 필터 바에서 확장자를 외워 입력해야 한다.

## 2. 이상 상태

- **U-P4-1 파일 포렌식 2차 노드**: 파일 › 환경·설정 파일(XML, JSON, INI/CFG/CONF, YAML, PLIST, REG) · 실행 파일(EXE, DLL, SYS/DRV, MSI, COM/SCR) · 스크립트 파일(JS/JSE, VBS/VBE, PS1/PSM1, BAT/CMD, SH, PY, HTA, WSF) · 이미지(JPG/JPEG/JFIF, PNG, GIF, BMP, SVG, WEBP, HEIC, TIFF, ICO) · 동영상/음성(MP4, AVI, MKV, MOV, MP3, WAV, M4A) · 문서(HWP/HWPX/CELL/SHOW, PDF, DOCX…, XLSX…, PPTX…, TXT/RTF) · 압축(ZIP, 7Z, RAR, TAR/GZ, ISO) · DB(SQLite/DB/DB-WAL, EDB, LDB, MDB/ACCDB) · 이메일(EML, MSG, PST/OST, MBOX). 각 노드 건수 배지, 선택 시 파일 그리드가 `ext=`(기존 필터 바 확장자 칩)로 걸러진다. 분류는 확장자 + 시그니처(`file_signature`) 둘 다 보고, 확장자-시그니처 불일치는 "시그니처 불일치" 노드로도 센다.
- **U-P4-2 스크립트 도메인 추출/검사**: 스크립트·HTML·URL 파일에서 도메인/URL 후보를 추출해 `script-domain-candidate` 행(파일, 도메인, 출현 수, IOC 매치 여부)을 만들고, "스크립트 파일 › 도메인 추출/검사" 노드로 노출한다. 런의 `--mode hacking|fraud` 에서 기본 활성, 그 외는 분석 작업(P1 `analyses`)으로 수동 실행.
- **U-P4-3 안티 포렌식 노드**: ADS(`ads-stream-candidate`) · 시그니처 불일치(`file-signature-mismatch`) · 숨김 속성/시스템 속성 파일(파일 인벤토리 `hidden` 플래그) · 타임스탬프 조작 의심(MFT 타임스탬프 스톰핑 플래그, P1 ntfs-meta 결과 있을 때) · 최근 삭제(USN 삭제 사유).
- **U-P4-4 침해사고 포렌식 노드**: 웹셸 탐지/추적(`webshell-source-candidate`) · 웹 서버 로그(`web-server-log`) · 원격 접속(RDP) · LotL/스크립트 실행 흔적(PowerShell 히스토리·실행 아티팩트 중 스크립트 호스트) · IOC 일치.
- **U-P4-5 클라우드/SNS 노드**: 브라우저 히스토리를 호스트 힌트로 묶어 유튜브 · 소셜(페이스북/인스타그램/X/스레드/링크드인) · 검색 · 웹메일 · 클라우드 저장소(드라이브/원드라이브/드롭박스/네이버 MYBOX) 노드로 센다(브라우저 공급자의 `SOCIAL_HOST_HINTS` 등을 확장).
- **U-P4-6 트리 UX**: 노드 검색(기존 type-ahead 유지 + 입력창), 섹션 접기 상태 기억, 건수 0 노드는 흐리게 + "해당 없음" 사유, 노드마다 설명 툴팁(용어집 연결).

## 3. 설계

### 3.1 서버
- `core/files.py`: `SUBCATEGORY_RULES`(확장자·시그니처 → 하위 범주 id) 추가, 후보 행에 `subcategory: str|null`, `hidden_attributes: ["hidden","system"]`(Windows 속성이 있을 때) 기록. 기존 `categories` 의미 불변(known-answer 픽스처가 깨지지 않도록 새 키만 추가; 픽스처 재생성 필요 시 `scripts/update-*`와 테스트 갱신).
- 새 아티팩트 `script-domain-candidate`(windows-system 공급자 안이 아니라 `generic-documents` 공급자에 `scripts` 하위 수집기로; 파일 크기 상한 2 MB, 도메인 정규식 + 공개 접미사 목록 없이 보수적 규칙, IOC 지표와 대조).
- `api/app/tree.py`: 파일 노드 아래 2차 노드(`files-sub:<id>` count), 안티 포렌식/침해사고/클라우드·SNS 섹션(각 자식은 기존 컬렉션 + 필터 라우트로 링크: `{collection, kind?, types?, ext?, hosts?}`), 브라우저 호스트 집계 엔드포인트 `GET /api/runs/{id}/browser-hosts`(히스토리 행을 한 번 훑어 호스트군 → 건수, LRU).
- `GET /api/runs/{id}/files?subcategory=&hidden=`, `GET /api/runs/{id}/artifacts?artifact_type=`(P1), `host_group=`(browser kind) 서버 필터.

### 3.2 프런트엔드
- 트리 섹션: 파일(2차 노드) · 안티 포렌식 · 침해사고 · 클라우드/SNS(브라우저 호스트군) — 노드 → 라우트(컬렉션 + 필터) 매핑 테이블 `features/tree/maestroNodes.ts`; 필터 바 칩이 노드 선택을 그대로 반영(양방향).
- 트리 검색 입력(`aria-label="트리 검색"`), 접기 상태 localStorage, 0건 노드 흐림 + 사유.
- 용어집(`docs/console-glossary.md`)에 새 노드 용어 추가, 툴팁은 aria-describedby.

## 4. QA (실데이터 run-subset7 / bsh-subset)
| # | 시나리오 | 기준 |
|---|---|---|
| Q-P4-1 | 파일 2차 노드 건수 | 노드 건수 합 = 파일 범주 건수(중복 제외), 각 노드 클릭 시 그리드 행 수 = 배지 |
| Q-P4-2 | XML 462 / JSON 90 / DLL / EXE 26 / JS 16 / PNG 547 / SVG | 실제 subset 확장자 분포와 일치(±시그니처 불일치) |
| Q-P4-3 | 도메인 추출 | JS/HTML 16+23개에서 도메인 행 생성, IOC 매치 열, 사유 없는 빈 결과 금지 |
| Q-P4-4 | 안티 포렌식 | ADS 노드 = `ads-stream-candidate` 수, 시그니처 불일치 = windows-filesystem 300행과 일치, ntfs 미실행 시 타임스탬프 노드에 "NTFS 메타 분석 필요" 사유 |
| Q-P4-5 | 침해사고 | 웹셸/웹 로그/RDP/IOC 노드가 artifact_type 서버 필터로 열림 |
| Q-P4-6 | 클라우드/SNS | 브라우저 히스토리 호스트군 건수, 노드 클릭 → `host_group=` 필터 |
| Q-P4-7 | 트리 UX | 검색·접기 기억·0건 사유·툴팁, a11y 규칙 0 |
| Q-P4-8 | 게이트 | P1과 동일 + known-answer QC(`scripts/known-answer-qc.py`) 통과 |
