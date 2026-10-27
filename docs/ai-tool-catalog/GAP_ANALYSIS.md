# AI 흔적 수집 격차 분석 (카탈로그 vs rapidtriage)

작성: 2026-10-27 · 상태: **초안(미검증)**
비교 대상: 같은 폴더의 카탈로그 JSON 7개 / `rapidtriage/artifacts/`, `core/{artifact_taxonomy,keyword_packs,visible_capabilities,timeline}.py`

> 확인 범위: 위 파일들을 키워드 검색으로 대조했다. `web/`, `api/`, 테스트, 나머지 `core/` 파일은 읽지 않았다.
> 카탈로그 값은 대부분 서드파티/미검증이므로, 아래 "추가 필요"는 **구현 전 실물 검증이 선행**되어야 한다.

## 1. rapid가 이미 하는 것

| 영역 | 위치 | 현황 |
|---|---|---|
| 브라우저 AI 도메인 방문 | `artifacts/windows/browser.py` `AI_SERVICE_DOMAINS` | 21개 도메인 (ChatGPT, Claude, Gemini, AI Studio, Perplexity, Copilot/Bing, Poe, Hugging Face, Grok, You, Phind, Mistral, DeepSeek, Meta AI, Character.AI, Notion) |
| 브라우저 저장소 스캔 | 동 `AI_STORAGE_DIRS` | Local Storage(leveldb), Session Storage, IndexedDB, Cache — 최대 80개 파일 / 파일당 5MB / 대화 200행 |
| AI 서비스 내보내기 | 동 `collect_ai_service_export_artifacts`, `cloud.py` | ChatGPT `conversations.json`, Claude/Gemini/Perplexity/Copilot/takeout 경로명 매칭 |
| 데스크톱 AI 앱 | `artifacts/generic.py` `DESKTOP_AI_APP_PATH_TERMS` | ChatGPT, OpenAI, Copilot, Claude, Anthropic, Gemini, Perplexity — SQLite 대화 후보 추출 (스키마 미검증 표시) |
| 로컬 LLM | 동 `LOCAL_LLM_PATH_TERMS` | Ollama, LM Studio, GPT4All + 모델 파일(.gguf/.ggml/.safetensors) + 프롬프트 후보 |
| 메모리 | `artifacts/memory.py` `AI_SERVICE_DOMAINS` | 7개 도메인 |
| 모바일 | `artifacts/mobile/*` | chatgpt/claude/gemini/perplexity/copilot 토큰 |
| Recall | `core/visible_capabilities.py` | Windows Recall 부분 지원 |
| 키워드 팩 | `core/keyword_packs.py` | 7개 용어 |
| 맥/리눅스 | `artifacts/macos.py`, `linux.py` | macOS는 브라우저 AI 사용 연결, 리눅스는 별도 AI 규칙 미확인 |

**내부 불일치**: AI 도메인 목록이 `browser.py`(21개)와 `memory.py`(7개)에 따로 하드코딩되어 있다. 카탈로그 기반 단일 소스로 통합이 필요하다.

## 2. 격차 (우선순위순)

### P0 — 완전히 비어 있음: 코딩 에이전트/하니스 로컬 세션
검색 범위 안에서 `.claude`, `.codex`, `.cursor`, `.gemini`, MCP, `jsonl` 세션 파서가 **하나도 없었다.** (`generic.py`의 `claude` 경로 용어가 홈 `.claude` 폴더를 우연히 잡는지는 미확인 — 구현 전 확인 필요.)

| 카탈로그 | 항목 수 | rapid |
|---|---|---|
| `cli_agents.json` | 37 (Claude Code, Codex, Gemini CLI, OpenCode, Aider, Goose …) | 없음 |
| `ide_agents.json` | 24 (Cursor, Copilot Chat, Cline, Kiro, Windsurf …) | 없음 |
| `harnesses.json` | 25 (OmO, ECC, Hermes, OpenClaw, MCP 설정, 지침 파일) | 없음 |

필요한 최소 구현:
1. JSONL 세션 파서 (Claude Code, Codex, OpenClaw 계열)
2. SQLite 세션 파서 (OpenCode, Hermes `state.db`, Cursor `state.vscdb` `cursorDiskKV`)
3. 메모리·지침 파일 수집 (`MEMORY.md`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, MCP 설정)
4. **자격증명 마스킹** (`.credentials.json`, `auth.json`, OAuth 토큰 — 존재만 기록, 값은 수집·표시 금지)
5. 휘발성 우선 수집 (임시 폴더 로그, 보존 기한 있는 요약 파일, Claude Code 자동 삭제 `cleanupPeriodDays`)

### P1 — 도메인/제품 목록 부족
- 브라우저 도메인 누락 후보: Kimi, Qwen, Doubao, Z.ai/GLM, Manus, Genspark, Felo, NotebookLM, Duck.ai, Brave Leo, OpenRouter, **API 도메인**(api.openai.com, api.anthropic.com 등), Cursor, Devin, Jules, Claude Code 웹, Lovable/Bolt/v0/Replit, **국내(CLOVA X, Wrtn, Kanana, Zeta, Liner)**
- 로컬 LLM: 카탈로그 27개 vs rapid 3개 제품 (Jan, Open WebUI, AnythingLLM, KoboldCpp, llama.cpp, llamafile, LocalAI, vLLM, Msty, Chatbox, Cherry Studio, ComfyUI, A1111, HF 캐시 등 누락)
- 데스크톱 앱: ChatGPT/Claude/Copilot/Gemini/Perplexity 외 없음
- `keyword_packs.py` 7개 용어 → 카탈로그 도구명·도메인·키 접두사로 확장

### P2 — 사용 사실 탐지(로컬 내용이 없을 때)
- 클라우드 에이전트(Devin, Manus, Codex 클라우드 등): 로컬 대화가 없으므로 **간접 증거** 필요 — 브라우저/DNS 도메인, 다운로드 산출물, git 커밋 트레일러(`Co-Authored-By`, `Agent-Logs-Url`), OAuth 앱 승인
- 설치 흔적: npm 전역 패키지, pip, winget, MSIX 패키지명, VS Code 확장 목록
- 실행 흔적: Prefetch/Amcache/SRUM에서 AI CLI 이름 매칭
- API 키 접두사 스캔 (`sk-ant-`, `sk-proj-`, `AIza`, `hf_` 등 — 카탈로그 infrastructure 참조, 일부 미검증)

### P3 — 보고서/법적 장치
- **갭 표시**: "로컬 증거 없음 = AI 미사용"으로 오해되지 않도록 서버 측 증거 요청 필요 항목을 보고서에 별도 표기
- 수집 범위·동의·영장 근거 메타데이터 (개인 계정·사적 대화 보호)
- 신뢰도 라벨(공식/서드파티/미검증)을 파서 출력의 `coverage_status`에 연동 — rapid의 기존 `*-schema-version-not-validated` 관례와 맞음
- 한국 법령 조항은 카탈로그에서 미확인 — 변호사 검토 필요

### P4 — OS 커버리지
- Windows는 풍부, macOS 부분, Linux 얇음(`linux.py` 1개). 에이전트 로그는 OS 공통 포맷이라 파서는 공용화 가능하나 경로 규칙은 OS별 정의 필요.

## 3. 권장 구현 순서
1. 카탈로그 → 단일 소스(YAML/JSON) 로더, `browser.py`/`memory.py` 도메인 통합
2. JSONL·SQLite 공용 에이전트 세션 파서 + 자격증명 마스킹
3. Claude Code, Codex, Cursor, OpenCode, OmO, Hermes, Kiro, Antigravity 우선 (이 PC에서 실물 검증 가능한 것부터)
4. 간접 증거(설치·실행·도메인·git 트레일러) 규칙
5. 보고서 갭 표시

## 4. 이 PC 사전 조사 → `PC_SURVEY.md` 참조
