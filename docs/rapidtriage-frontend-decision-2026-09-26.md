# RapidTriage 프런트엔드 방향 결정 — 점진적 공존 (2026-09-26)

R3-2 로드맵의 조건부 게이트("R3-2 완료 후 React 전면 전환 비용 재측정")에 대한
측정 결과와 결정.

## 실측

### 기존 바닐라 워크벤치 (canonical, `/`)

- ES 모듈 20개. `app.js` 9,186줄 + 화면 모듈 4개(`init(deps)` 주입) +
  기능 모듈(kakao/hexview/heatmap/shortcuts/virtual/store/theme 등).
- 순환 참조 없음(`CYCLES: none`), 화면별 CSS 분리 완료(R3-3).
- 기능 표면: 인테이크/런 폼, 가상 스크롤 아티팩트·검색 테이블, 카카오
  말풍선, 헥스 뷰어, 타임라인 히트맵, 파워 리뷰어 단축키, 교차 장비 IOC,
  보고서 폼(감정서 포함), compare, 워크벤치 세션 복원, 듀얼 테마.
- Node 툴체인 없이 서빙 가능 — 폐쇄망 배포 제약에 정합.

### React v2 스캐폴드 (`frontend/`, `/v2` opt-in)

- 38 파일: React 19 + TypeScript + Vite + zustand + react-query +
  react-table/react-virtual. 생성된 TS 스키마 계층, TokenGate,
  EvidenceTree/CaseQueuePane/RunDetailPane/RunTablePane/
  CollectionTablePane.
- 검증 상태: `tsc --noEmit` 클린, `vitest` 6/6, `biome check` 클린,
  playwright e2e 설정 존재.
- 빌드 번들이 `rapidtriage/web/static/v2/`에 커밋돼 `/v2`에서 서빙됨
  (`factory.py`의 조건부 mount).
- 기능 커버리지: 런 탐색 골격 수준 — 바닐라 대비 대략 15~20% 표면.
  타임라인 히트맵, 헥스/카카오 뷰어, 단축키, IOC, 보고서, compare,
  인테이크, 세션 복원, 테마 미구현.

## 결정: 점진적 공존 (전면 전환 보류)

1. **원래 통증은 이미 해소됐다.** R3-1(순환 해소)/R3-2(화면 모듈)/
   R3-3(CSS 캡슐화)으로 바닐라 구조의 근본 문제—순환 바인딩과 모놀리스—가
   제거됐다. 전면 전환의 주된 동기가 소멸한 상태에서 재측정한 비용 대비
   이득이 맞지 않는다.
2. **폐쇄망 제약.** canonical UI가 Node 빌드를 요구하면 로컬-우선 배포
   스토리가 깨진다. v2는 빌드 번들을 커밋해 런타임 의존성 없이 opt-in으로
   제공한다.
3. **패리티 갭이 크다.** 도메인 뷰어군(카카오/헥스/히트맵)과 리뷰 액션을
   이식하기 전까지 v2는 보조 화면이다.

## 운영 규칙

- `/` (바닐라)가 canonical이며 모든 신규 기능은 우선 여기에 구현한다.
- `/v2`는 실험적 opt-in — `static/v2/` 번들은 커밋해 Node 없이 서빙.
- `frontend/`의 빌드 산출물(`node_modules`, `dist`, playwright 산출물)은
  gitignore 유지. 소스만 추적.
- v2 패리티 체크리스트(아래)가 모두 충족되면 canonical 전환을 재논의.

## 패리티 체크리스트 (v2 → canonical 전환 선행 조건)

- [ ] 런/아티팩트 가상 스크롤 테이블 (10만 행)
- [ ] 카카오톡 말풍선 뷰어
- [ ] 헥스 뷰어 (범위 API 소비)
- [ ] 타임라인 히트맵 + 범위 필터
- [ ] 파워 리뷰어 단축키 (j/k/b/r/e/숫자)
- [ ] 교차 장비 IOC 카드
- [ ] 보고서 폼 + 템플릿 선택(감정서 포함)
- [ ] compare 뷰
- [ ] 인테이크/런 폼 + 이미지 포맷 처리
- [ ] 워크벤치 세션 복원
- [ ] 듀얼 테마
- [ ] e2e 스모크 커버리지 동등
