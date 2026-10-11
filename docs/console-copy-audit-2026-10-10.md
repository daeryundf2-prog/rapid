# 콘솔 카피 감사 (2026-10-10, 읽기 전용)

범위: `frontend/src/**/*.ts(x)` (테스트·스펙 파일 제외). 소스는 수정하지 않았다.
방법: 사용자에게 보이는 문자열 리터럴과 JSX 텍스트를 스캔하고, `docs/console-glossary.md`의 금지 동의어를 검색했다.
제외: 이벤트 키 이름(Escape, ArrowLeft 등), CSS 선택자, 명령 ID, 기술 약어(SHA-256, IOC, MFT, SQLite, HTML, PDF), 브랜드명(RapidForensic).

결과 요약: 영문·혼용 카피 11건 + 금지 동의어 1건 = 12건. 필수 샘플 문구(Credentials, Web activity, Apply, Go, OK)는 `frontend/src`에서 발견되지 않았다. 금지 동의어 "증거 선별", "키워드 선별", "선별 보드", "인입", "아터팩트", "결과물"은 발견되지 않았다.

| # | file:line | 현재 텍스트 | 제안 (한국어) | 분류 |
|---|---|---|---|---|
| 1 | frontend/src/features/grid/columns/common.ts:117 | `선별` (열 헤더) | `리뷰 상태` | 금지 용법: 상태 집합 이름은 용어 사전상 "선별"로 쓰되, 열 헤더는 상태 값을 가리키므로 변경 권장 |
| 2 | frontend/src/features/case/RunDialog.tsx:200 | `known-good 해시 목록 경로 (한 줄에 하나)` | `알려진 정상 해시 목록 경로 (한 줄에 하나)` | 영문 혼용 |
| 3 | frontend/src/features/case/RunDialog.tsx:213 | `known-good 항목 숨기기` | `알려진 정상 항목 숨기기` | 영문 혼용 |
| 4 | frontend/src/features/case/SearchOptionsPopover.tsx:169 | `known-good 숨기기` | `알려진 정상 항목 숨기기` | 영문 혼용 |
| 5 | frontend/src/features/case/runForm.ts:72 | `known-good 해시 목록을 지정해야 숨길 수 있습니다.` | `알려진 정상 해시 목록을 지정해야 숨길 수 있습니다.` | 영문 혼용 (`features/case/case.test.tsx:64`가 같은 문자열을 검사하므로 함께 수정 필요) |
| 6 | frontend/src/api/client.ts:72 | `Request failed` (오류 메시지 기본값) | `요청에 실패했습니다` | 영문 |
| 7 | frontend/src/features/viewer/views/EmailView.tsx:74 | `Message-ID` (dt) | `메시지 ID` | 영문 |
| 8 | frontend/src/features/viewer/views/MetaView.tsx:131 | `위치(locator)` | `위치` | 영문 괄호 병기 |
| 9 | frontend/src/features/viewer/views/MetaView.tsx:135 | `케이스 DB ID` | `케이스 식별자` | 영문 혼용 |
| 10 | frontend/src/features/viewer/views/SqliteView.tsx:48 | `SQLite 사이드카(WAL) 상태` (aria-label) | `SQLite 보조 파일(WAL) 상태` | 외래어 혼용 |
| 11 | frontend/src/features/case/ReportDialog.tsx:16 | `Word (docx)` | `워드 (.docx)` | 영문 |
| 12 | frontend/src/features/case/ReportDialog.tsx:18 | `Markdown` | `마크다운 (.md)` | 영문 |

비고
- 항목 11·12는 형식 이름이라 원문을 유지해도 되나, 한국어 전용 카피 원칙(U10)에 따라 라벨을 한국어로 바꾸는 것을 제안한다.
- `SHA-256`(columns/common.ts:127, viewer/commands.ts:57, MetaView.tsx:104), `SHA-1`(MetaView.tsx:106), `rowid`(SqliteView.tsx:208), `MFT FILE`(viewer/hex.ts:25)은 표준 기술 용어이므로 변경하지 않는다.
- `Ctrl K`, `Esc`, `Alt+←` 등 키 표기는 단축키 체계 표기이므로 변경하지 않는다.
- 필수 샘플 문구(Credentials, Web activity 등)는 v1 콘솔 `rapidtriage/web/static/app.js`에 존재한다. v1은 이번 감사 범위 밖이며 `/legacy`로 한 릴리스 유지되므로 별도 처리한다.
