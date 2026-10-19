# 세션 인계 — RapidTriage AXIOM 동등성 이후 R6 (2026-10-19)

다른 세션에서 이어서 작업하기 위한 현재 상태 정리. 이 문서와 `docs/plans/r6-followups-2026-10-19.md`를 먼저 읽는다.

## 1. 지금까지 끝난 것
- **AXIOM 동등성 R1–R5 전부 main에 머지됨** (PR #11–#16, 머지 커밋, main `02a59a4`, main CI 통과).
  - R1 케이스·통합 보기·검토 도구, R2 메신저·메일·브라우저 캐시·클라우드, R3 레지스트리·이벤트 채널·NTFS·카빙, R4 실행 계획·탐색기 3종·뷰/필터, R5 잔여 파서·공개 미지원·정책 제외.
  - 매트릭스(`docs/research/axiom-parity-matrix-2026-10-17.md`) 199행 전부 종결: 있음 120 · 표 대체 22 · 정책 제외 11 · 공개 미지원 38 · 해당 없음 8 (없음 0, 부분 0). 있음 중 15행은 "(실샘플 미검증)".
  - 공개 미지원·정책 제외 목록: `docs/rapidtriage-known-limitations.md`.
- 각 라운드마다 적대적 리뷰(백엔드·콘솔)를 했고 확인된 지적은 전부 회귀 테스트와 함께 고쳤다.

## 2. 지금 진행 중인 것 — R6 후속 라운드
- 계획: `docs/plans/r6-followups-2026-10-19.md` (브랜치 `feat/r6-followups`, 커밋 `b835144`, 푸시됨, PR 아직 없음).
- 진행 방식(사용자 지시, 메모리 `feedback-model-roles`): **단계는 순차**, **계획 = Fable 모델**, **구현 = Opus 모델**, **워커(테스트 실행·실데이터 실행·측정) = Sonnet 모델**. 단계마다 구현 → 검증 → 적대적 리뷰 → 수정 → PR 하나, 머지는 사용자가 "머지해라"라고 할 때만.
- 단계 순서: 1 실데이터 재실행 + 미검증 파서 실샘플 검증 → 2 국내 사건 연기 기능(AhnLab V3, adb 내부 DB, `$Boot` 추출, 미할당 URL 카빙, eMule 0xE1, 카카오맵 좌표) → 3 성능(조건 타임라인 첫 페이지 5 s → ≤1 s, `/files` 조건 페이징 캐시, 지도 38 s → ≤2 s) → 4 A등급 규칙 검증·릴리스 증거 입력 목록.

### 단계 1의 현재 위치
- 1단계 도구 구현(Opus)을 2026-10-19 다시 시작했다(브랜치 `feat/r6-s1-realdata`, 에이전트 작업 트리). 첫 시도는 사용량 한도, 두 번째는 작업 트리 생성 실패로 멈췄고, 작업 트리 정리 후 재시작했다(§4).
- 해야 할 일(계획 §1.3 갈래 A·B):
  1. `rapidtriage/core/run/constants.py` `GENERAL_FORENSIC_ARTIFACT_KINDS`에 `"p2p"` 추가 — **현재 어떤 실행 모드도 p2p 수집기를 돌리지 않는 결함**(recovery 모드는 의도적으로 제외, 테스트가 단언). 출력 샘플 재생성(`python scripts/update-output-samples.py`).
  2. `scripts/compare-runs.py`(기준 런 vs 새 런 kind·artifact_type 행 수·단계 시간 비교, 회귀 판정) + `tests/test_compare_runs.py`.
  3. `scripts/sample-check.py`(표본 폴더에 공급자를 직접 돌려 known-answer JSON과 필드 대조, 곰플레이어 식별자 `--probe-hash`) + 테스트.
  4. `docs/validation/r6-sample-validation-2026-10-19.md`(표본 보관 규칙·known-answer 스키마·수용 기준표).
  5. 그다음 Sonnet 워커: `python -m rapidtriage run D:\rapid-qa\bsh-subset --mode hacking --output-dir D:\rapid-qa\derived\r6-s1-run --read-only`(약 45분) → `compare-runs.py --baseline D:\rapid-qa\derived\run-subset10 --candidate D:\rapid-qa\derived\r6-s1-run`.

## 3. 사용자 승인 대기(답 받기 전에는 해당 작업 금지)
- U1 휴대폰과 연결·Viber·Office·McAfee 표본 제공 여부(없으면 "미검증" 유지).
- U2 이 PC의 VMware로 일회용 Windows VM 생성 + 알집·팟플레이어·곰플레이어·KMPlayer·VLC·eMule·qBittorrent·GIMP 설치(가짜 콘텐츠로 흔적 생성, 작업 후 폐기). EGG LZMA 배치·팟플레이어 값 이름·곰 해시 확정에 필요.
- U3 공개 코퍼스 다운로드(NIST CFReDS, digitalcorpora `nps-2009-domexusers`, 수 GB) — URL 카빙 오탐률·단계 4.
- U5 `D:\devin\bsh-e01` 전체 이미지·`bsh-mft.bin` 읽기 전용 사용(단계 2·4).
- 이후 단계에서: U6 Sleuth Kit 설치 여부, U7 카카오 WCONGNAMUL 역공학 기준 수용, U8 VM 안 `wevtutil cl`·SDelete 실험, U9 Windows T1 운영자 입력.

## 4. 알려진 환경 문제
- **에이전트 작업 트리 생성 실패**: `.claude/worktrees/` 아래 R1–R5 에이전트 작업 트리가 30개 가까이 쌓여 새 작업 트리 생성(`isolation: worktree`)이 "git identity could not be verified"로 거부된다. 머지 끝난 깨끗한 작업 트리는 `git worktree remove`로 정리하고(변경 있는 것은 먼저 확인), 반쯤 생성된 작업 트리는 `git worktree remove --force --force`. node_modules 정션은 `cmd /c rmdir`로만 지운다(재귀 삭제 금지).
- 2026-10-19 정리 결과: 머지 끝난 깨끗한 작업 트리 20개를 정리했다(Git 등록은 해제됨). 그중 7개(`agent-a168…`, `a21b…`, `a3a4…`, `a55c…`, `a759…`, `a8f6…`, `aede…`)는 "Invalid argument / Permission denied"로 폴더 일부가 디스크에 남아 있다. **이 폴더들은 링크 여부를 확인하기 전에는 지우지 않는다.** 정리 중 메인 `frontend/node_modules` 일부가 지워져 `npm ci`로 복구했다(의존성 전부 확인, typecheck·lint·vitest 정상).
- 남아 있는 프로세스: R4 V2 에이전트가 띄운 Vite 개발 서버(포트 8942, `agent-a3a459bb…` 경로)가 아직 실행 중이다. 종료는 자동 모드에서 거부돼 사용자 판단이 필요하다. 이 서버가 잡고 있던 rolldown 바이너리는 `.claude/worktrees/rolldown-binding-inuse.node.old`로 옮겨 두었고, 서버를 끄면 지워도 된다.
- 등록 상태로 남은 작업 트리 4개(`agent-a2650…`·`af2cd…`는 locked, `aee34…`, `afc07…`)는 모두 main에 머지됐고 변경이 없다. 지우기 전에 `cmd /c dir /AL /S`로 링크가 없는지 먼저 확인한다.
- 메인 작업 트리에서 `git add -A`는 매우 느리다 → `git add -u` 또는 경로 지정.
- 셸 명령이 120 s를 넘으면 백그라운드로 넘어간다. 긴 테스트는 `run_in_background`로 실행.
- 사용량 한도(429)로 에이전트가 멈추면 같은 에이전트에 SendMessage로 재개(작업 트리가 확인 가능할 때만 됨).

## 5. 테스트·QA 자원
- 기준 QA 데이터: `D:\rapid-qa\bsh-subset`(읽기 전용, 19,029 파일), 기준 런 `D:\rapid-qa\derived\run-subset10`(런 `b5fabbe09f18`, 2026-10-15).
- Antigravity 위임: `D:\rapid-qa\agy\README.md` 규약, 요청 001(R2)–004(R5, 대상 main `02a59a4`) 대기 중, 결과 폴더 비어 있음. 사용자가 Antigravity에 "`D:\rapid-qa\agy\README.md` 를 읽고, `requests` 폴더에서 `results` 에 결과가 없는 요청을 번호 순서대로 처리해라."를 한 번 붙여넣어야 시작. (main CI가 전체 Python·E2E를 이미 통과했으므로 급하지 않다.)
- 게이트 명령은 `AGENTS.md`의 RapidForensic Validation Contract 참조.

## 6. 지켜야 할 제약
- 실제 E01·이미지·복구 증거·고객 데이터·PII·비밀·토큰을 Git에 넣지 않는다. 증거 폴더와 AXIOM 고객 케이스는 읽기 전용.
- GitHub 토큰을 출력·저장하지 않는다. Antigravity CSRF 토큰을 추출하지 않는다.
- 제품 정책 제외 유지: 자격 증명 복호·크래킹·원격 수집·외부 프로그램 실행(외부 도구는 옵트인만).
- 내가 시작하지 않은 프로세스는 종료하지 않는다.
- 커밋 트레일러: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, PR 본문 끝: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
