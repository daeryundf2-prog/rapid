# 세션 인계 — R7 (2026-10-27 저녁)

다른 세션에서 이어서 작업하기 위한 현재 상태. 먼저 이 문서 → `docs/plans/r7-master-2026-10-26.md`(전체 로드맵·단계별 결과 기록) → `docs/plans/r7-ai-usage-2026-10-27.md`(AI 사용 분석) 순으로 읽는다. 이전 인계: `session-handoff-2026-10-19.md`.

## 1. 진행 방식(사용자 지시, 변경 없음)
- 계획·적대적 리뷰 = **Fable**, 구현 = **Opus**(갈래별 워크트리, `isolation: worktree`), 워커(테스트·실데이터·측정) = **Sonnet**. 단계는 순차. 각 단계: 구현 → 워커 → 적대적 리뷰 → 수정 → 확인 패스 → PR 갱신. 머지는 사용자가 "머지해라"라고 할 때만.
- 완료 후 적대적 리뷰 필수, 지적은 묻지 않고 계속 고친다.
- 커밋 트레일러 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, PR 본문 끝 `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## 2. 브랜치·PR
- 작업 브랜치 `feat/r6-ux` = **9e16edf**(GitHub 동기). PR 스택 #18 → #19 → #20(feat/r6-ux) 전부 미머지, 사용자 "머지해라" 대기. PR #20 본문에 R7 단계 1 절이 있고, 단계 2·3·AI 절은 아직 안 넣었다.
- `main` = 216ae60(R6 S1–S2까지).
- 주의: 2026-10-27 한때 메인 워크트리가 `docs/ai-tool-catalog` 브랜치에 체크아웃된 채 머지가 쌓여 `feat/r6-ux`가 뒤처졌던 일이 있었다(해결됨, fast-forward). 머지 전 항상 `git branch --show-current`로 확인.

## 3. 끝난 것(feat/r6-ux에 포함)
| 단계 | 내용 | 기록 |
|---|---|---|
| 1 | 콘솔 S1·S2 결함 43건 전부 해결 + 구조 개선 | `docs/research/console-adversarial-review-2026-10-26.md`, `…-rereview-r7s1-2026-10-27.md` |
| 2 | 검색: v1 `계약` 3.5 s → 0.42 s; v2 색인 v4(2자 한글 bigram, 접은 본문, 행 시각, 문서 512K, `#entry:n`, 예산 접두, 정규식 가드, 비밀값 가림) `계약` 0.135 s; 콘솔 v2 라우팅·경고·32개 상한 | `docs/research/search-adversarial-review-r7s2-2026-10-27.md` |
| 3-A | Nuix 계열·중복·예외 항목(`core/families.py`·`dedup.py`·`irregular.py`, 조건 `family=`·`dup=`·`irregular=`, 뷰어 "계열" 탭, 트리 "처리 › 예외 항목") | r7-master §5, 실데이터 399 관계·709 중복·793 예외 |
| 3.5-A/B/D | AI 사용 분석: 카탈로그 단일 출처(`core/ai_catalog/`, 161도구, 브라우저 도메인 21→103), kind `ai-agent`(존재·설치·실행 대조·자격 증명 존재·미분류 후보), 어댑터 10종(claude_code·codex·cursor·antigravity·kiro·omo·zcode·claude_desktop·claude_swap·gemini_cli)+스텁 8, 콘솔 "AI 사용" 도메인 13노드·세션→대화 보기·접수 카드·런 옵션 | `docs/plans/r7-ai-usage-2026-10-27.md` §9(이 PC 실물 스캔 건수) |
| 보안 | 프레즌스 경로 이메일 가림, 자격 증명 행 중복 제거(5c5fd7e) | |

## 4. 지금 돌고 있는 레인(워크트리 `D:\devin\rapid\.claude\worktrees\agent-<id>`, 브랜치는 미푸시)
세션이 바뀌면 이 에이전트들은 더 못 깨운다. **워크트리의 브랜치 상태를 보고 이어서 하거나 새 Opus 에이전트에 같은 과제를 준다.**

| 레인 | 브랜치 | 워크트리 id | 남은 일 |
|---|---|---|---|
| Nuix 갈래 B 개체·검색 S2·언어·해시 집합 | `feat/r7-s3-b-entities` (bd3df77+) | agent-a55208e05adf5275a | feat/r6-ux 머지 → 게이트 → 번들 → 보고(Q-B1~B8, 색인 크기/시간, 원값 grep 0) |
| AI 갈래 C 규칙·통합 보기·보고서 | `feat/r7-ai-c-rules` (d0dd351+) | agent-aff9dd2987511ca80 | 갈래 D 연결(런 옵션 `collector_options["ai-agent"]`, `CaseReportCreateRequest.sections`, `GET /ai-usage/gaps`, 서버 도메인 `ai`) → 머지 → 게이트(OpenAPI 스냅샷) → 보고 |
| 자격 증명 파일 본문 색인 제외(보안) | `fix/r7-credential-files-index` (c1be684+) | agent-af672b93eb046896f | 전체 테스트 → 머지 → 보고(저장소별 grep 0) |
| 실물 스캔 결함 수정 | `fix/r7-ai-scan-findings` | agent-a164dc8ec68dd055c | 읽기 상한 4 GiB·최신 우선·skipped 사이드카·공개 사항, Codex ledger 도구 호출, `rapidtriage run --artifact-kinds`(fingerprint 샘플링), 본문 이메일 유지 결정 문서화 → 게이트 → 보고 |

레인이 끝나면: `git merge --no-ff <branch>`(known-limitations 충돌은 양쪽 블록 모두 유지), `git diff --stat` = `--ignore-cr-at-eol` 확인(LF), 번들 `frontend && npm run build` 후 `rapidtriage/web/static/v2` 커밋, push.

## 5. 다음 순서
1. 위 4개 머지 → Sonnet 워커: 전체 게이트(`AGENTS.md` 검증 계약 + typecheck/lint/vitest `--pool=forks` 청크/e2e) + 실데이터 읽기 전용 스윕(run-subset10 b5fabbe09f18, qa-case1 af54ff24ed5f) + 번들.
2. Fable 적대적 리뷰 2건: 단계 3(Nuix A·B)과 AI 사용 분석(어댑터·콘솔·보고서·개인정보). 방법 고정: 자체 포트, `RAPIDTRIAGE_INDEX_PERSIST=0`, 런 등록부 스크래치 사본, 비-GET 차단, 폴더 전/후 스냅샷, 쓰기 확인 대화상자 수락 0.
3. 수정 라운드 → 확인 패스 → `r7-master` 결과 기록·PR #20 본문(단계 2·3·AI 절) 갱신.
4. 그다음 단계: 4 의뢰 브리프(`r7-case-context-2026-10-26.md`, FTop 붙여넣기+북마클릿) → 5 Nuix C·D(스레드·근사 중복·통신 그래프·시간 피벗·법률 내보내기·보관자·처리 프로필) → 6 S3 잔여·접근성·용어 전면(검사관→분석관 등).

## 6. 사용자 결정(답 전까지 권고안으로 진행 중)
- PR 머지 순서 #18→#19→#20("머지해라").
- 개체 known-answer는 합성 가짜 값(진행 중), Concordance 필드명 영문+한글 라벨, 보관자 마법사 2단계.
- 의뢰 브리프 §10(이름·접수 방식·FTop 가명 표본·코퍼스·`event_window`·"시작할 곳" 카드·플레이북 검토).
- AI: 본문 포함(마스킹) 기본·git 트레일러는 `.git/logs/HEAD`만·조직 이메일 도메인 미제공(규칙 비활성). 실물 스캔은 승인됨("진행해라"); 원본 폴더 불변 증명은 AI 앱 실행 중이라 미확정 — 앱 닫고 재측정 가능.
- 정리 대기: run-subset10의 사용자 세션 썸네일 376개, 포트 8942·5352 잔여 Vite 서버(에이전트가 못 끔), Antigravity 요청 001–004 미실행.

## 7. 환경·제약(반복 사고 방지)
- 실데이터 읽기 전용, 결과 보고는 건수·필드명만. 고객 데이터·사건 식별자·비밀·토큰 Git 금지. 이 PC 스캔 출력 `D:\rapid-qa\derived\ai-self\`(507 MB, 경로 스냅샷 포함)은 Git 밖, 필요 없으면 삭제.
- 에이전트 규칙: 워크트리 `frontend\node_modules`는 `cmd /c mklink /J`, 삭제는 `cmd /c rmdir`만; 모든 파일 LF; vitest는 `--pool=forks --no-watch` 청크(전체 실행은 부하 중 멈춤); 전체 unittest는 백그라운드 60분; `git add -A` 금지(느림); 8710 사용자 서버 미접촉; 리뷰 하네스는 쓰기 차단(이전에 1클릭 내보내기가 런 폴더에 파일 씀).
- 에이전트가 자기 프로세스도 못 끄는 경우(권한 분류기) → 사용자에게 포트·PID 알리기.
- 사용량 한도(429)로 멈추면 같은 에이전트에 SendMessage로 재개; 세션이 바뀌면 워크트리 브랜치에서 이어간다.
- 알려진 플레이키: `test_rapidtriage_email_external…returns_nonzero_when_selected_tool_fails`는 PowerShell에서만 실패(POSIX `false` 가정, AI 갈래 C가 수정 중); 부하 중 vitest 2~3개 타임아웃은 단독 실행으로 확인.
