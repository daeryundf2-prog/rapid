# 이 PC AI 흔적 사전 조사

조사일: 2026-10-27 · 방식: 읽기 전용(폴더·파일 이름, 크기, 수정일만 확인) · **대화 내용과 자격증명 파일은 열지 않음**
상태: 초안. 파일 내용 검증과 스키마 확인은 하지 않았다.

## 1. 발견된 도구 (홈 `.폴더`, AppData, PATH 기준)

| 도구 | 흔적 | 최종 수정 | 카탈로그 |
|---|---|---|---|
| Claude Code | `~\.claude\` (projects, sessions, history.jsonl, file-history, shell-snapshots, plugins, skills, `.credentials.json`, `settings.json`, `CLAUDE.md`), `AppData\Local\claude-cli-nodejs`, npm 전역 `@anthropic-ai` | 2026-10-27 | cli_agents |
| Claude 데스크톱 | `AppData\Roaming\Claude`, `Roaming\Claude-NativeHost`, `Local\Claude`, `Local\Claude-3p`, `Local\Claude-Data`, `Local\Packages\Claude_pzs8sxrjxfjjc` | 2026-10-26 | chatbots |
| Claude 세션 전환 백업 | `~\.claude-swap-backup\` (configs, credentials, cache, `claude-swap.log`, `sequence.json`) | 2026-10-15 | **카탈로그 없음** |
| OpenAI Codex | `~\.codex\` (sessions, archived_sessions, sqlite, memories, attachments, browser, computer-use, mcp-oauth-locks, plugins, skills, `.sandbox*`), `Local\OpenAI\Codex`, `Local\Packages\OpenAI.Codex_2p2nqsd0c76g0` | 2026-10-27 | cli_agents |
| Cursor | `~\.cursor\` (agents, ai-tracking, browser-logs, projects, plans, plugins), `Roaming\Cursor`, `Local\Programs\cursor` | 2026-09-25 | ide_agents |
| Antigravity (Google) | `~\.antigravity`, `~\.antigravity-ide`, `~\.gemini\antigravity*`, `Roaming\Antigravity*`, `Local\antigravity*`, `Local\Programs\Antigravity*` | 2026-10-27 | ide_agents (부분) |
| Gemini | `~\.gemini\` (GEMINI.md, config, antigravity-browser-profile, `jetski-standalone-oauth-token`) 및 이중 점 폴더 `~\..gemini` | 2026-10-25 | cli_agents |
| Kiro | `~\.kiro\` (sessions, session-index, steering, powers, logs, skills), `Roaming\Kiro` | 2026-08-29 | ide_agents |
| OmO (oh-my-opencode) | `~\.omo\` (agent, memory, plans, ulw-loop, codegraph, lsp-daemon, `omo.jsonc` + 백업 2개, 마이그레이션 백업 `…-opencode-config`), `Local\oh-my-opencode\bin` | 2026-10-09 | harnesses (경로 미확인 항목) |
| Devin (데스크톱/IDE) | `~\.devin`, `~\.devin-shared`, `Roaming\Devin`, `Local\devin`, `Local\Programs\Devin` | 2026-10-10 | cloud_agents (로컬 항목 부족) |
| Windsurf/Codeium | `~\.codeium\windsurf` | 2026-09-14 | ide_agents (부분) |
| GitHub Copilot | `~\.copilot\` (logs, config.json), `Local\Packages\Microsoft.Copilot_8wekyb3d8bbwe` | 2026-10-01 | cli_agents / chatbots |
| zcode | `~\.zcode\` (cli, v2, workspace) | 2026-09-24 | **카탈로그 없음** |
| lazy-gravity | npm 전역 + `Local\lazyantigravity` | 2026-08-29 | **카탈로그 없음** |
| codegraph | `~\.codegraph` | 2026-07-01 | **카탈로그 없음** |
| lumos | `~\.lumos\` (cases, catalog.sqlite, review.sqlite, signing.key) | 2026-10-20 | 사용자 프로젝트 (AI 도구 아님) |

설치 확인된 실행 파일: `claude`(npm), `cursor`, `code`, `node`, `python`, `git`. 미설치: `codex`/`gemini`/`opencode`/`aider`/`ollama` CLI 명령은 PATH에 없음(앱·샌드박스 형태로만 존재).

## 2. 규모 (확인된 값)

| 위치 | 수량 |
|---|---|
| `~\.claude\projects` JSONL | 1,023개, 2026-10-08 ~ 2026-10-27 |
| `~\.codex\sqlite` | 11개 파일, 123.3MB, 2026-06-22 ~ 2026-10-27 |
| `~\.codex\sessions`, `archived_sessions` | JSONL 0개 (폴더만 있음) |
| `~\.cursor\ai-tracking` | 1개, 7.1MB |
| `~\.cursor\projects` | 339개, 6.2MB |
| `~\.kiro\sessions` | 1개 |
| `~\.omo\memory` | 비어 있음 |

(Claude 데스크톱 `Roaming\Claude`, 워크스페이스 DB 수치, 브라우저 프로필, Recall, PowerShell 히스토리 확인은 조사 명령이 시간 초과로 백그라운드에서 진행 중이라 이 문서에 반영하지 못했다.)

## 3. 카탈로그 대비 발견 사항

1. **카탈로그에 없는 도구**: `.claude-swap-backup`, `zcode`, `lazy-gravity`, `codegraph`, 이중 점 폴더 `~\..gemini`. 일반 탐지 규칙(홈 숨김 폴더 + 세션 구조 스캔)이 필요하다는 근거.
2. **Codex 저장 형식**: 이 PC는 JSONL이 아니라 `~\.codex\sqlite`(123MB)에 세션이 있는 것으로 보인다. 카탈로그의 "Codex rollout/SQLite = 서드파티"를 실물로 확인할 대상. (SQLite 내용은 열어 보지 않음)
3. **Claude Code**: 홈 `.claude`에 세션 JSONL 1,023개. 가장 풍부한 증거원이며 rapid 현재 파서 없음.
4. **자격증명 파일이 평문 위치에 존재**: `.claude\.credentials.json`, `.gemini\jetski-standalone-oauth-token`, `.claude-swap-backup\credentials\`, `.codex\.sandbox-secrets`, `mcp-oauth-locks`. rapid는 **존재·수정시각만 기록하고 값은 마스킹**해야 한다.
5. **OmO 경로 확인**: 카탈로그/검색에서는 임시폴더 `oh-my-opencode.log`였으나 이 PC에서는 `~\.omo\`와 `Local\oh-my-opencode\bin`이 확인됨. 버전별로 위치가 다르다는 증거 → 경로를 하드코딩하지 말고 후보 목록으로 관리.
6. **휘발성**: `~\.claude\.last-cleanup` 존재(Claude Code 자동 정리 이력). 가장 오래된 세션이 2026-10-08인 점은 보존 정책과 관련 있을 수 있으나 원인은 미확인.
7. **여러 도구가 같은 폴더를 공유**: `~\.gemini`에 Antigravity 데이터가 섞여 있음 → 폴더명만으로 도구를 단정하면 안 됨.

## 4. 스키마 검증 결과 (2026-10-27, 구조만 확인 · 메시지 본문 미열람)

방법: 읽기 전용(SQLite `mode=ro&immutable=1`), JSONL은 키 경로와 `type`/`role` 같은 열거형 값만 집계. 상세는 카탈로그의 `local_verification` 필드(`cli_agents.json`의 Claude Code·Codex, `ide_agents.json`의 Cursor)에 기록.

### 4.1 Claude Code (JSONL)
- 위치: `~\.claude\projects\<cwd-슬러그>\<sessionId>.jsonl`, 서브에이전트는 `…\<sessionId>\subagents\agent-*.jsonl`. **1,023개 중 995개가 서브에이전트 파일** → 서브에이전트 하위 폴더 순회가 필수.
- 기록 공통 키: `type, uuid, parentUuid, sessionId, timestamp(ISO), version, cwd, gitBranch, entrypoint, userType, isSidechain, requestId, promptId, permissionMode, slug`, 서브에이전트는 `agentId` 추가.
- `type` 값: `assistant, user, attachment, queue-operation, last-prompt, custom-title, agent-name, mode, system, file-history-snapshot, api-request, api-request-blob, atis-latch`.
- 메시지: `message.{role, model, id, content, stop_reason, usage.*}`. content 블록: `text, thinking, tool_use(name,input), tool_result, image(base64), tool_reference`.
- **증거 가치 최고**: `tool_use.input`(실행한 명령·경로)과 `toolUseResult`(실행 결과). `attachment`에는 MCP 서버 상태(실패·대기·인증 필요 목록)가 있어 MCP 사용 증거.
- 보조: `history.jsonl`(키: `display, pastedContents, project, sessionId, timestamp` — 붙여넣은 내용이 인라인), `sessions\<pid>.json|.key`, `file-history\`, `shell-snapshots\*.sh`, `.last-cleanup`.
- 클라이언트 버전이 파일마다 달라(2.1.293~2.1.308) **알 수 없는 `type`을 허용하는 파서**가 필요.

### 4.2 Codex (SQLite — JSONL 아님)
- `~\.codex\sessions`, `archived_sessions`에 JSONL **0개**. 세션은 `~\.codex\sqlite\`에 있음. `threads.rollout_path` 컬럼은 있으나 해당 파일은 찾지 못함 → **롤아웃 JSONL이 있다고 가정하면 안 됨**.
- `state_5.sqlite`: `threads`(22행; `id, cwd, title, model, tokens_used, git_sha/branch/origin_url, cli_version, first_user_message, preview, created/updated_at(_ms), archived, sandbox_policy, approval_mode …`), `thread_spawn_edges`(12행, 부모-자식 서브에이전트), `thread_dynamic_tools`, `agent_jobs`, `remote_control_enrollments`.
- `codex-dev.db`: `local_thread_catalog`(41행), `automations`, `automation_runs`(보관된 사용자·어시스턴트 메시지 컬럼), `thread_timeline_ledger(payload_json)`, `inbox_items`.
- `logs_2.sqlite`: `logs` 32,904행, **114.7MB** — `feedback_log_body`가 요청·응답 텍스트를 담을 가능성(열지 않음).
- `memories_1.sqlite`(`stage1_outputs.raw_memory, rollout_summary`), `goals_1.sqlite`(`thread_goals`).
- 전부 **WAL 모드**: `-wal`/`-shm`을 함께 확보해야 최근 기록이 빠지지 않음.

### 4.3 Cursor (state.vscdb)
- **대화는 전역 DB**에 있음: `%APPDATA%\Cursor\User\globalStorage\state.vscdb` (**399MB**). 워크스페이스 DB 13개는 `ItemTable`만 있고 `composerHeaders`, `cursorDiskKV`가 **비어 있음**.
- 전역 DB 테이블: `ItemTable`(285행), `composerHeaders`(44행: `composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, isSubagent, recency, checkpointAt, value, subagentTypeName`), `cursorDiskKV`(38,383행).
- `cursorDiskKV` 키 접두사: `agentKv` 18,165 · `bubbleId` 17,255 · `checkpointId` 591 · `codeBlockPartialInlineDiffFates` 375 · `ofsContent` 340 · `codeBlockDiff` 277 · `composerData` 91 · `inlineDiff` 85 · `messageRequestContext` 68.
- `ItemTable`에 `secret:*` 8개(암호화된 비밀 — 복호화·반출 금지), `aiCodeTracking.dailyStats.*`, `browserAutomation.history`, `cloudAgentRepository.agents.*`, `aicontext.personalContext` 등. 워크스페이스 쪽엔 `aiService.prompts`, `history.entries`.
- 미확인: `bubbleId` 키의 세부 구성, `agentKv`의 용도, 값(BLOB)의 인코딩.

### 4.4 이 검증이 바꾸는 것
1. Codex는 JSONL 파서가 아니라 **SQLite 파서**가 기본이어야 한다.
2. Claude Code는 서브에이전트 파일이 대다수라 **재귀 순회 + 부모-자식 연결**(`parentUuid`, `agentId`, `thread_spawn_edges`, `isSubagent`)이 필요하다.
3. Cursor는 **전역 DB 한 개가 핵심 증거**이며 크기가 커서 이미징·해시·복사 전략이 필요하다.
4. 세 도구 모두 **세션 목록(메타)과 본문이 분리**되어 있어, 본문이 없어도 메타(시각, cwd, git, 모델, 토큰)로 사용 사실은 입증 가능하다.
5. 세 도구 모두 마스킹 대상 필드가 있다(`.credentials.json`, `secret:*`, 인증 토큰 파일).

### 4.5 브라우저 프로필 (Chrome / Edge)
- **Chrome 프로필 11개**(Default, Profile 1·3·14~19·21·22), Edge 1개. AI 사용이 프로필마다 흩어져 있어 `Default`만 읽는 파서는 대부분을 놓친다 → `Profile N` 전부 열거 필수.
- 프로필 구조: `History`(SQLite), `Local Storage/leveldb`, `IndexedDB`, `Session Storage`, `Cache/Cache_Data`, `Network`, `Sessions`, `Extensions`. History 테이블은 `urls, visits, downloads, keyword_search_terms, segments, clusters, journeys …` (Edge는 `edge_urls, edge_visits, edge_downloads` 추가).
- History의 `urls`를 도메인 매칭해 확인된 AI 서비스: ChatGPT, OpenAI, Claude, Anthropic, Gemini, Grok/xAI, **OpenRouter, Z.ai, Devin, Kiro, Antigravity, Cursor, Windsurf**. (프로필당 방문 수는 1~160 수준)
- **rapid 격차 확인**: `browser.py`의 `AI_SERVICE_DOMAINS`에 `z.ai`, `openrouter.ai`, `devin.ai`, `kiro.dev`, `cursor.com`, `windsurf`가 없다.
- 일부 `urls` 행은 `last_visit_time = 0` → WebKit 에포크(1601) 변환 전 값 검증 필요.

### 4.6 Claude 데스크톱
- **실제 데이터 위치는 `%LOCALAPPDATA%\Claude-Data\claude_pzs8sxrjxfjjc\`** (`Roaming\Claude`는 표식 파일만, `Packages\Claude_*`는 MSIX 스텁). MSIX 가상화 때문에 두 위치를 모두 수집해야 한다.
- `claude-code-sessions\<계정uuid>\local_<uuid>.json`: 데스크톱 Code 탭 세션 메타(키: `cliSessionId, cwd, originCwd, model, effort, permissionMode, createdAt, lastActivityAt, completedTurns, isArchived, cliBinaryPin.*`). **`cliSessionId`로 `~\.claude\projects\*\<id>.jsonl`과 연결**된다.
- 그 외: `claude-code\<버전>\`(번들 CLI 2.1.304·2.1.308), `local-agent-mode-sessions\`, `scratch-workspaces\`, `git-worktrees.json`(원격 저장소 기록), `plan-usage-history.json`(사용량 표본), `IndexedDB\https_claude.ai_0.*`, `Cache_Data`(1,918개·281MB), `claude_desktop_config.json`(MCP 서버 0개).
- 로그: `%LOCALAPPDATA%\Claude\logs\main.log`(+`main1/2.log` 순환, 각 약 34k줄), `claude.ai-web.log`, `mcp.log` 등. 브라우저 확장 네이티브 호스트 `%APPDATA%\Claude-NativeHost\`가 있어 **Claude 크롬 확장 설치** 증거가 된다.
- 민감: `buddy-tokens.json`, `ssh-remote-server-state.json`, `Network\Cookies` → 존재·수정시각만.

### 4.7 Antigravity
- 에이전트 루트는 **`~\.gemini\antigravity`** (`~\.antigravity`가 아님). IDE 상태는 `%APPDATA%\Antigravity`, 확장은 `~\.antigravity(-ide)`로 **3곳에 분산**.
- **`conversations\<uuid>.db`: 대화당 SQLite 1개** (508개, 2.9GB, 중앙값 1.6MB). 테이블 `steps`(step_type, status, metadata/step_payload 등 BLOB), `gen_metadata`, `executor_metadata`, `trajectory_meta(trajectory_id, cascade_id)`, `parent_references`.
- `conversation_summaries.db`(34MB): `conversation_summaries`(609행: title, preview, step_count, workspace_uris, agent_name, **parent_conversation_id, nesting_depth**, last_user_input_time …) + **FTS5 전문 색인**(`user_body`, `agent_body`) → 개별 DB가 없어도 텍스트 검색 가능성.
- **평문 전사**: `brain\<uuid>\.system_generated\logs\transcript.jsonl`, `transcript_full.jsonl`(키: `content, created_at, source, status, step_index, tool_calls[].{name,args}`, 토큰 카운터), `messages\<uuid>.json`(에이전트 간 메시지: sender, recipient, sourceMetadata.tool.toolCall.*), `steps\<n>\`.
- `mcp\<서버>\<도구>.json`: 에이전트에 부여된 **MCP 서버·도구 목록 캐시**(이름이 바뀐 사본 포함). `scratch\`(1,794개·692MB)는 작업 산출물 = 사용자 데이터.
- `%APPDATA%\Antigravity\User\globalStorage\state.vscdb`는 0.4MB `ItemTable`만(`antigravity.notification.*`, `antigravityAuthStatus`(민감) 등) — **대화는 여기에 없다.**

### 4.8 Kiro
- `~\.kiro\sessions\<워크스페이스해시>\sess_<uuid>\session.json`(키: `id, title, createdAt, lastModifiedAt, modelId, agentMode, autopilot, rootPaths, workspacePaths, specWorkflow, …`) + `session-index\<해시>.jsonl`(키: `at, op, sessionPath`).
- 로그 `~\.kiro\logs\<시각>\{kiro.log,mcp.log,powers.log}`, `%APPDATA%\Kiro\User\globalStorage\state.vscdb`(51행; `chat.ChatSessionStore.index`, `kiro.kiroAgent`).
- 이 PC에서는 2026-08-29에 잠시 설치·사용된 흔적이라 **메시지 본문은 확인되지 않았다**(세션 폴더에 `session.json`만). 다른 저장 위치는 찾지 못함.

### 4.9 카탈로그에 없던 도구 (일반 탐지로 발견)
- **ZCode(`~\.zcode`)**: `cli\db\db.sqlite`(34.8MB)에 `session, message, part, input_history, model_usage(2,377), tool_usage(2,404; tool_name, exit_code, destructive, approval_status), turn_usage, todo, session_task_link, workflow_*` 등 완전한 스키마. `cli\rollout\*.jsonl`(3개, 161MB, 원시 요청·응답)과 `v2\tasks-index.sqlite`, `v2\config.json`(공급자·모델·baseURL; API 키 필드는 마스킹). 모델 설정이 Z.ai/GLM을 가리키나 **제조사 귀속은 미확인**.
- **claude-swap(`~\.claude-swap-backup`)**: Claude 계정 전환 도구 추정. `sequence.json`에 **PC에 등록된 계정 수·조직명·활성 계정**, `claude-swap.log`에 전환 시각. **회사 계정과 개인 계정을 한 PC에서 번갈아 썼다는 증거**가 되어 유출 조사에서 중요(파일명에 이메일이 들어 있으므로 보고서에는 필요한 만큼만).
- **codegraph(`~\.codegraph`, `~\.omo\codegraph`)**, **lazy-gravity**(npm 전역 + `Local\lazyantigravity\telemetry-diagnostics.jsonl`): 용도 미조사.

### 4.10 OmO, Cursor, Codex, 기타 추가 확인
- **OmO는 임시 폴더가 아니라 `~\.omo`**에 있다(앞서 검색 결과의 `oh-my-opencode.log` 임시 경로는 이 버전에 해당하지 않음, `Local\oh-my-opencode\bin`은 비어 있음). `agent\sessions\<cwd슬러그>\<시각>_<uuid>.jsonl`(Pi 스타일, 4개), `agent\logs\{session,config-reload,compaction}.log`, `ulw-loop\<run>\{brief.md, goals.json, ledger.jsonl}`(자율 작업 목표·진행 원장), `migration-backup-…-opencode-config`(OpenCode에서 이전한 흔적). 세션 폴더명이 **작업한 프로젝트 경로의 슬러그**라 내용을 열지 않고도 작업 대상 폴더를 알 수 있다.
- **Cursor 추가**: `~\.cursor\ai-tracking\ai-code-tracking.db`(7.1MB) — `ai_code_hashes`(17,479행: fileName, conversationId, model, timestamp), `scored_commits`(23행: 커밋별 AI·사람 라인 수, `v1/v2AiPercentage`). **대화 본문이 없어도 어떤 파일에 AI 생성 코드가 있었는지, 커밋의 AI 비중**을 입증할 수 있다.
- **Codex 추가**: `~\.codex\memories\`는 자체가 git 저장소(`.git`)이고 `rollout_summaries\*.md`가 과거 스레드별 요약, `~\.codex\attachments\`에 붙여넣은 텍스트가 별도 파일(`pasted-text.txt`)로 저장된다.
- **Devin(데스크톱/IDE)**: `Roaming\Devin`은 VS Code 포크 구조(Cache_Data 545MB), `~\.devin\extensions`. 클라우드 에이전트의 **세션 본문은 로컬에서 확인하지 못했다.**
- **Windsurf(`~\.codeium\windsurf`)**: 뼈대만 있고 `cascade`, `brain`, `database`가 비어 있음. **Copilot CLI(`~\.copilot`)**: `config.json`과 프로세스 로그 1개뿐이고 세션 저장소는 못 찾음.
- **OS 수준**: PowerShell 히스토리 존재(26KB·364줄, 2026-10-22 수정; 내용 미열람). Windows Recall은 이 PC에 **없음**(`CoreAIPlatform.00` 부재). 크롬 확장 네이티브 호스트와 npm 전역 패키지(`@anthropic-ai/claude-code`, `lazy-gravity`, `kordoc`)도 설치 증거.

### 4.11 보강된 시사점
6. **일반 탐지가 필수**: 연구한 카탈로그에 없던 도구 3개(ZCode, claude-swap, codegraph)를 홈 숨김 폴더 스캔으로 발견했다.
7. **저장소가 도구마다 다르다**: 대화당 SQLite(Antigravity), 단일 대형 SQLite(Cursor·ZCode·Codex), 세션 JSONL(Claude Code·OmO), 평문 전사+DB 병행(Antigravity). 파서는 어댑터 구조가 맞다.
8. **본문이 없어도 입증되는 증거**: 세션 메타, 토큰·도구 사용 통계, AI 코드 해시, 계정 전환 로그, MCP 도구 캐시, 브라우저 방문 기록.
9. **계정이 여러 개**일 수 있다(claude-swap, `claude-code-sessions\<계정>`, Chrome 프로필 11개). 보고서는 계정·프로필 단위로 분리해야 한다.

## 5. 남은 검증 (이 PC)
- Cursor `bubbleId`/`composerData`/`agentKv` 값 인코딩 (구조만)
- Antigravity `steps.step_payload` 등 BLOB 디코딩 가능성(프로토버프 추정, 시도하지 않음)
- ZCode 제조사 확인, codegraph·lazy-gravity 용도
- Windows Copilot 앱 `LocalState` 구조, Edge/Chrome IndexedDB·캐시 내 AI 흔적
- Devin 로컬 세션 저장 위치
- 어떤 확인이든 **메시지 본문은 열지 않고 구조만** 본다 (개인정보·업무 비밀 보호)

## 6. 보고서 취급 주의
이 PC에는 업무 관련 파일명(사건 폴더, 증거 파일, 녹취 파일 등)이 에이전트 작업 폴더에 다수 있었다. **카탈로그와 이 문서에는 그런 이름과 계정 이메일·UUID를 기록하지 않았다.** rapid가 이 PC를 실제 증거로 처리할 때도 같은 원칙(필요 최소 수집, 식별자 마스킹)을 적용해야 한다.
