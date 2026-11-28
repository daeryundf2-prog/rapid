# AI 사용 흔적 매트릭스 부록: GitHub 별 500개 이상 프로젝트

조사일 2026-11-28. [AI 사용 흔적 커버리지 매트릭스](ai-usage-coverage-matrix.md)의 부록이다. 별 수는 조사일 값이다.

- **싣는 범위.** 조사한 10,406개 중 본문 표와 연결된 저장소 88개와, X(제외 후보)를 뺀 별 5,000개 이상 저장소를 합쳐 1,561개만 싣는다. 설명문은 각 저장소 소유자의 글이라 싣지 않는다. 전체 목록(설명문 포함)은 `scripts/ai-usage-github-appendix.py`로 다시 만들며 Git에 넣지 않는다: `collect --out qc-runs/ai-usage-github`(GitHub 검색, `gh` 로그인 필요) 다음 `render --out qc-runs/ai-usage-github --survey-date 2026-11-28 --docs docs`가 `qc-runs/ai-usage-github/ai-usage-github-full.{json,csv}`과 이 부록을 쓴다.
- **흔적.** 본문 표에 행이 있는 저장소는 `본문` 열에 절과 행 이름을, `Rapid 현재` 열에 지원 상태를 적었다. 나머지(`본문` 열이 —)는 이름·별 수·분류만 있고, 어디에 무슨 흔적이 남는지는 아직 1차 출처로 확인하지 않았으므로 모두 [미확인]이다. 라이브러리·프레임워크는 그 자체로는 사용 흔적을 남기지 않고 그것으로 만든 앱이 남긴다.
- **수집.** 아래 토픽·키워드마다 `gh search repos`(별 500개 이상, 한 번에 1,000개). 1,000개에서 잘리는 검색은 별 수 구간으로 나눠 다시 조회한다. 포크는 뺀다. 본문에서 다룬 제품 중 주인이 이름을 댄 저장소(`scripts/ai-usage-github-matrix-links.json`의 `owner_named`)는 검색에 걸리지 않아도 넣고, 별이 500개 미만이면 `(주인 지정)`을 붙인다.
- **AI 관련성.** 키워드 검색은 AI와 무관한 저장소(마우스 커서, 모니터링 에이전트 등)도 걸러 오므로, AI 토픽이 있거나 이름·설명에 AI 용어가 있는 저장소만 남긴다. 이렇게 뺀 저장소: 1,610개.
- **분류.** `수동` = 본문 조사로 정함(`scripts/ai-usage-github-matrix-links.json`), `규칙` = 이름·설명 키워드 규칙, `토픽` = GitHub 토픽, `기본값` = 어느 규칙에도 걸리지 않아 K로 둠. 규칙은 스크립트에 있고 검토 전이라 틀린 칸이 있을 수 있다. X는 설치해서 쓰는 도구가 아닐 가능성이 큰 것(목록·교재·논문·예제·데이터셋)이며 이 부록에는 싣지 않는다.
- **토픽:** `agent-framework`, `agentic-ai`, `agents`, `ai-agent`, `ai-agents`, `ai-assistant`, `ai-chatbot`, `ai-coding`, `ai-tools`, `anthropic`, `autonomous-agents`, `browser-automation`, `browser-use`, `chatbot`, `chatgpt`, `chatgpt-api`, `claude`, `claude-code`, `codex`, `coding-agent`, `comfyui`, `computer-use`, `copilot`, `cursor`, `deepseek`, `discord-bot`, `gemini`, `gemini-cli`, `generative-ai`, `gpt-4`, `llama`, `llamacpp`, `llm`, `llm-agent`, `llm-inference`, `llm-ui`, `local-llm`, `mcp`, `mcp-server`, `multi-agent`, `ollama`, `openai`, `opencode`, `personal-assistant`, `qwen`, `stable-diffusion`, `telegram-bot`, `text-to-speech`, `vibe-coding`, `voice-assistant`, `workflow-automation`.
- **키워드:** `agent`, `ai assistant`, `anthropic`, `chatbot`, `chatgpt`, `claude`, `codex`, `coding assistant`, `comfyui`, `copilot`, `cursor`, `deepseek`, `gemini`, `gpt`, `llm`, `local llm`, `mcp`, `ollama`, `openai`, `qwen`, `stable diffusion`, `telegram bot`, `text to speech`, `whisper`.

| 분류 | 조사한 저장소 | 본문 연결 | 이 부록에 실음 |
|---|---|---|---|
| [B 데스크톱·웹 챗 클라이언트](ai-usage-coverage-github/b.md) | 529 | 0 | 83 |
| [C 브라우저·컴퓨터 사용 에이전트](ai-usage-coverage-github/c.md) | 90 | 5 | 15 |
| [D IDE·에디터 어시스턴트](ai-usage-coverage-github/d.md) | 183 | 6 | 34 |
| [E CLI 코딩 에이전트](ai-usage-coverage-github/e.md) | 687 | 20 | 134 |
| [F 하네스·플러그인·스킬·메모리 묶음](ai-usage-coverage-github/f.md) | 1,046 | 7 | 199 |
| [G 오케스트레이터·멀티에이전트](ai-usage-coverage-github/g.md) | 338 | 19 | 83 |
| [H 메신저 봇](ai-usage-coverage-github/h.md) | 185 | 4 | 36 |
| [I 자율·리서치 에이전트](ai-usage-coverage-github/i.md) | 119 | 0 | 30 |
| [J 로컬 LLM 런타임·UI](ai-usage-coverage-github/j.md) | 779 | 11 | 150 |
| [K API·SDK·프레임워크·RAG·자동화](ai-usage-coverage-github/k.md) | 2,619 | 10 | 437 |
| [L 이미지·음성·영상 생성](ai-usage-coverage-github/l.md) | 932 | 6 | 120 |
| [M 모바일 앱](ai-usage-coverage-github/m.md) | 72 | 0 | 11 |
| [N MCP 서버·도구 연결](ai-usage-coverage-github/n.md) | 1,354 | 0 | 229 |
| X 제외 후보(목록·교재·논문·예제·데이터셋) | 1,473 | 0 | 0 |
| 합계 | 10,406 | 88 | 1,561 |
