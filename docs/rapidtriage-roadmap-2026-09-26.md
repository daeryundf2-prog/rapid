# RapidTriage 로드맵 재편 — 2026-09-26

외부 리뷰(고칠점/추가할점) 기반 재편 로드맵. 실측 검증 완료 항목:

- `app.js` 9,494줄, `styles.css` 17,617줄 (425KB) — `@media` 브레이크포인트
  36개, 10종 이상의 임의 px 값 혼재 확인 (1180px×12, 1540px×5, …)
- `e01.py` 4,016줄 — `ewfmount`/`mmls`/`tsk_recover` 외부 CLI 필수이나
  pyewf+dissect.ntfs 실험 경로(L1742~) 이미 존재
- `kakaotalk.py` 5,549줄 — 복호화 백엔드 완비, UI는 평문 표
- `engines/rust` 워크스페이스 존재하나 미연결, `dashcam_tools`/`opencv`가
  기본 의존성으로 번들
- 테스트 802건 그린 (기존 검증 게이트: unittest·ruff·vulture·compileall)

핵심 판단 한 가지: **LUMOS 리포(`D:\devin\lumos`)에 이미 TSK 대조 검증된
네이티브 E01 어댑터(`lumos_engine/adapters/e01_image_adapter.py`)가 있다.**
pyewf+pytsk3로 GPT/MBR·NTFS 카탈로그·삭제복구·카빙·APFS 감지까지 구현돼
있고, 실제 931GB FTK 이미지에서 icat과 SHA-256 bit-exact 복구를 확인했다.
Sprint 3의 "네이티브 E01 자립화"는 신규 개발이 아니라 **검증된 구현의 이식**
으로 접근할 수 있다 — 리스크와 공수가 크게 줄어든다.

---

## Phase R0 — 위생 (1~2일, 선행 필수) — ✅ 완료 (2026-09-26)

> 가장 싸고 부수 효과가 큰 정리. 이후 작업의 충돌면을 줄인다.

- **R0-1 dashcam 분리 ✅**: `pyproject.toml` 기본 deps에서
  `opencv-python`/`pytesseract`/`numpy`를 `[dashcam]` extra로 이동 완료,
  `fastapi`/`uvicorn`은 기본으로 격상. 물리적 레포 분리는 별도 승인 필요로
  유보 — 패키지 수준 분리(optional extra + `[test]`에 dashcam 포함)는 완료.
- **R0-2 미디어 쿼리 단일화 ✅**: 임의 브레이크포인트 10종을 표준으로 수렴
  — 720/760/780→768, 880/900/980→1024, 1180/1380→1280, 1420/1500/1540→1536.
  컴팩트 스타일이 더 일찍 적용되는(안전한) 방향으로 매핑. 잔여 미디어 쿼리:
  width 4종 + `prefers-reduced-motion` 2건.
- **R0-3 CSS 토큰 레이어 착수 ✅**: 10개소에 분산돼 있던 `:root` 블록(134개
  변수 선언)을 파일 선두 단일 토큰 블록으로 통합. `--rf-*` 신규 네이밍은
  기존 변수명(--ink/--muted/--accent-strong 등 87개 사용명)을 그대로 승계 —
  일괄 개명은 R2와 병행.

## Phase R1 — 네이티브 E01 코어 (최우선 기능)

> 사용자가 가장 원하는 "E01 넣으면 분석"을 폐쇄망 Windows에서도 동작하게.

- **R1-1 네이티브 경로를 기본으로 격상 ✅**: `extract_e01_to_directory`에
  `engine` 파라미터(`RAPIDTRIAGE_E01_ENGINE` env) 추가 — `auto`(기본,
  네이티브 우선→실패 시 외부 폴백)/`native`/`external`.
  `[native-e01]` extra 신설(dissect.ntfs + libewf-python). 결정 근거:
  `docs/rapidtriage-e01-engine-decision-2026-09-26.md`.
  - 판정: dissect.ntfs 채택 유지 — pytsk3는 FAT/exFAT 인프로세스 요구가
    생기기 전까지 보류(결정 문서 참조).
- **R1-2 LUMOS 어댑터 이식 평가 → 불이식으로 결정**: 사용자 지시
  "이식하지는말고 로드맵대로 진행해라"에 따라 이식 없이 rapidtriage 자체
  `e01_native.py` 경로로 진행. 검증 데이터(기준 수치)만 참조.
- **R1-3 세그먼트/손상 처리 게이트 ✅(유닛 게이트)**: 엔진 선택
  (native 강제/모듈 누락/external 강제/무효값/env), auto→외부 폴백 이력,
  중간 세그먼트 누락, 손상 헤더(네이티브+도구 이중 컨텍스트), 무효 파티션
  오프셋, 미지원 FS, $MFT 시스템 아티팩트 기록 — 총 11건 신규 테스트.
- **R1-4 검증 게이트 ✅(배선 완료)**: 네이티브 추출이 `<stage>/_system/MFT.bin`
  ($MFT 레코드 0 덤프)을 출력 → `mft-reference-diff.py` 입력 연결.
  복구 트리→run→`rapidtriage-files.json`→`fls-coverage-diff.py` 경로는
  기존 인프라 그대로. tier-0 known-answer(`known-answer-qc`,
  `trusted-diff`) PASS 확인 — 실증거/릴리스 증거는 별도 게이트 유지.

## Phase R2 — 뷰어 성능 & 도메인 UI (사용자 체감 최대)

> 리뷰 F-항목 중 실무 가치가 검증된 순서로.

- **R2-1 트루 가상 스크롤**: `app_state.js`의 slice 페이지네이션 제거.
  백엔드 keyset/cursor 페이지 + 프런트 가상 스크롤 (바닐라 유지 시
  `clusterize.js`/`virtual-list` 경량 채택 — React 도입과 무관하게
  독립 해결 가능한 문제로 분리). 목표: 10만 건 스크롤 60fps, DOM 50개 내.
- **R2-2 카카오톡 말풍선 뷰어**: 기 구축 복호화(`kakaotalk.py`) 위에
  발신/수신 정렬·프로필·썸네일·첨부 미리보기. 별도 렌더 모듈로 분리해
  app.js에 추가하지 않음.
- **R2-3 웹 헥스 뷰어**: Canvas 기반 오프셋/HEX/ASCII + 시그니처 하이라이트.
  `raw` 바이트 API 엔드포인트(범위 읽기)가 선행.
- **R2-4 인터랙티브 타임라인 히트맵**: 시간×아티팩트 밀도 + 드래그 교차 필터.
- **R2-5 파워 리뷰어 단축키**: J/K·B·R·E·1~5 — 가상 스크롤과 함께 설계.

## Phase R3 — 프런트엔드 구조 재편 (선택적, 판단 필요)

> 리뷰는 React 19 전면 전환을 제안하나, **점진적 분리가 현 리스크에 맞다**.

- **R3-1 순환 참조 해소 우선**: `app.js`↔`app_state.js`의 mutable live
  binding 20개+를 이벤트/스토어 계약으로 정리 — React 도입 여부와 무관하게
  선행되어야 하며, 정리 후에야 프레임워크 판단이 의미를 가짐.
- **R3-2 화면 단위 모듈 분리**: CaseHeader/ArtifactGrid/DetailPanel/
  TimelineView를 파일 단위 ES 모듈로 (기존 app_api/app_intake 분리 패턴
  연장). 전면 React 마이그레이션은 R3-2 완료 후 비용 재측정해 결정.
- **R3-3 스타일 캡슐화**: 분리된 모듈에 화면별 CSS 파일 매칭, styles.css는
  토큰+공용 베이스만 잔존하도록 축소.

## Phase R4 — 가속·확장 (후순위)

- **R4-1 Rust PyO3 바인딩**: 네이티브 E01(R1)과 파서 커버리지가 확정된
  뒤에야 가속 대상이 명확해짐 — R1 완료 전 착수 금지. MFT/EVTX/BinXML을
  maturin으로 `rapidtriage.native_accel` 빌드.
- **R4-2 교차 장비 IOC 추적**: 동일 USB 시리얼/파일 해시의 다중 케이스
  이동 그래프 — 케이스 스키마에 cross-case 조회 계층 필요.
- **R4-3 국내 감정서 양식**: 검찰/경찰 표준 양식 DOCX/PDF 생성
  (CoC·도구 검증 상태·법령 대조표 자동 삽입) — 증거 문서의 검증 상태 필드를
  R1의 검증 게이트와 연결.
- **R4-4 듀얼 테마**: Warm Paper Light + Nordic Slate Dark — R0-3 토큰
  위에 테마 스위치만으로 구현되도록 선행 조건화.

## 우선순위 요약 (기존 리뷰 대비 조정)

1. **R0** 위생(분리·쿼리·토큰) — 비용 최소·즉시 착수
2. **R1** 네이티브 E01 — 제품 핵심 약속 + LUMOS 검증 구현 이식 가능
3. **R2** 가상 스크롤·카톡 뷰어·헥스·타임라인·단축키 — 사용자 체감
4. **R3** 구조 재편 — R2로 가치 검증 후 React 여부 판단 (조기 전면 전환 비추천)
5. **R4** Rust 가속·IOC·감정서·테마 — 커버리지 확정 후

리뷰의 Sprint 3(네이티브 E01+Rust)는 **R1으로 당기고 Rust만 R4로 미룸**:
폐쇄망 E01 처리가 제품 존재 이유라 최우선이며, Rust 가속은 파싱 경로가
확정되기 전엔 대상이 없다.
