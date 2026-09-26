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

- **R2-1 트루 가상 스크롤 ✅**: `app_virtual.js`(clusterize 방식 동적 높이
  가상 tbody) 신설. 백엔드는 기존 keyset/cursor 페이징 재사용 — artifacts는
  무한 스크롤(`onNeedMore`→다음 커서 fetch), search는 인메모리 가상화.
- **R2-2 카카오톡 말풍선 뷰어 ✅**: `app_kakao.js` + `kakao.css` —
  발신/수신 정렬, 일자 구분, 발신자·시각·첨부 표기. 아티팩트 상세 카드에
  마운트.
- **R2-3 웹 헥스 뷰어 ✅**: `app_hexview.js` + `hexview.css` — Canvas
  오프셋/HEX/ASCII 렌더링, 기존 `source-hex-range` 범위 API 소비.
- **R2-4 인터랙티브 타임라인 히트맵 ✅**: 백엔드 `timeline_hist.py`
  (시간×소스 히스토그램) + `app_heatmap.js`/`heatmap.css`, 클릭 범위 필터.
- **R2-5 파워 리뷰어 단축키 ✅**: `app_shortcuts.js` — j/k 네비, b 북마크,
  r 리뷰 상태, e 보고 포함 토글, 숫자키 뷰 그룹(기존 계약 유지).
  백엔드 `remove_tags` 추가로 태그 토글 지원.

## Phase R3 — 프런트엔드 구조 재편 (선택적, 판단 필요)

> 리뷰는 React 19 전면 전환을 제안하나, **점진적 분리가 현 리스크에 맞다**.

- **R3-1 순환 참조 해소 ✅**: `app_store.js` 신설 — mutable 상태 소유 +
  콜백 레지스트리(`registerWorkbenchBinding`). `app_state.js`·
  `app_compare.js`가 app.js import를 제거하고 스토어 계약으로 전환.
  그래프 검증 `CYCLES: none` (20개 모듈).
- **R3-2 화면 단위 모듈 분리 ✅**: `app_case_header.js`/
  `app_artifact_grid.js`/`app_detail_panel.js`/`app_timeline_view.js`를
  `init(deps)` 주입 패턴으로 분리 — app.js 9,733→9,186줄, 무순환 유지.
  정적 테스트는 번들 인식 헬퍼로 갱신.
- **R3-3 스타일 캡슐화 ✅**: 화면별 CSS 추출 — `case_header.css`(119
  규칙)/`detail_panel.css`(61)/`artifact_grid.css`(17)/`timeline_view.css`(8).
  styles.css는 토큰+공용 베이스(17,617→15,542줄), index.html이 styles.css
  이후 로드로 캐스케이드 보존.

## Phase R4 — 가속·확장 (후순위)

- **R4-1 Rust PyO3 바인딩 ✅**: `engines/rust/crates/rapidcore`에 EVTX
  스캐너(`evtx.rs`) + PyO3 모듈(`py.rs`) 구현 —
  `rapidtriage/native/rapidcore_native.pyd` (v0.1.0).
  `rapidtriage/core/native_accel.py`가 PyO3→`rapid-worker evtx-scan`
  서브프로세스→순수 Python의 폴백 체인으로 디스패치.
  `scripts/build-native-accel.py` 빌드 스크립트, 6건 패리티 테스트.
- **R4-2 교차 장비 IOC 추적 ✅**: `core/cross_device.py` — 지표를 run/장비
  레코드 간 상관(장비·출처 수, 교차 장비 관계). API `routes_ioc.py` +
  UI `app_ioc.js`(indicators 탭 카드). 6건 테스트.
- **R4-3 국내 감정서 양식 ✅**: `core/korean_report.py` —
  `korean-expert` 템플릿(감정의 취지·감정물 인계인수 해시표·도구/검증
  상태·법적 검토 대조표·제한사항·부록 해시 목록, 초안 고지 포함).
  기존 case-report 파이프라인(MD/HTML/DOCX/PDF/manifest)에 템플릿 분기로
  통합 — 병렬 보고 시스템 아님. 7건 테스트.
- **R4-4 듀얼 테마 ✅**: `themes.css` — `:root`를 Nordic Slate(기본 다크)
  로 유지하고 `html[data-theme="warm-paper"]`가 Warm Paper 라이트로 전체
  토큰 오버라이드. `app_theme.js` 피커(brand-row, localStorage
  `rapidtriage.theme`) + index.html FOUC 방지 인라인 스크립트.

## 우선순위 요약 (기존 리뷰 대비 조정)

1. **R0** 위생(분리·쿼리·토큰) — 비용 최소·즉시 착수
2. **R1** 네이티브 E01 — 제품 핵심 약속 + LUMOS 검증 구현 이식 가능
3. **R2** 가상 스크롤·카톡 뷰어·헥스·타임라인·단축키 — 사용자 체감
4. **R3** 구조 재편 — R2로 가치 검증 후 React 여부 판단 (조기 전면 전환 비추천)
5. **R4** Rust 가속·IOC·감정서·테마 — 커버리지 확정 후

리뷰의 Sprint 3(네이티브 E01+Rust)는 **R1으로 당기고 Rust만 R4로 미룸**:
폐쇄망 E01 처리가 제품 존재 이유라 최우선이며, Rust 가속은 파싱 경로가
확정되기 전엔 대상이 없다.
