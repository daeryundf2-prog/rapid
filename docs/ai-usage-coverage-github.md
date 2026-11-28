# AI 사용 흔적 매트릭스 부록: GitHub 별 500개 이상 프로젝트

조사일 2026-11-28. [AI 사용 흔적 커버리지 매트릭스](ai-usage-coverage-matrix.md)의 부록이다. 별 수는 조사일 값이다.

- **흔적.** 본문 표에 행이 있는 저장소는 `본문` 열에 절과 행 이름을, `Rapid 현재` 열에 지원 상태를 적었다. 나머지(`본문` 열이 —)는 이름·별 수·분류만 있고, 어디에 무슨 흔적이 남는지는 아직 1차 출처로 확인하지 않았으므로 모두 [미확인]이다. 라이브러리·프레임워크는 그 자체로는 사용 흔적을 남기지 않고 그것으로 만든 앱이 남긴다.
- **수집.** `gh search repos --topic <토픽> --stars <범위> --limit 1000`과 `gh search repos <키워드> --stars <범위> --limit 1000`. 한 번에 1,000개에서 잘리는 검색은 별 수 구간으로 나눠 다시 조회했다(`codex` 키워드 검색 한 건만 1,000개에서 잘렸다). 포크는 뺐다. 본문에서 다룬 제품의 저장소는 검색에 걸리지 않아도 넣었고, 별이 500개 미만이면 `(주인 지정)`을 붙였다.
- **AI 관련성.** 키워드 검색은 AI와 무관한 저장소(마우스 커서, 모니터링 에이전트 등)도 걸러 오므로, AI 토픽이 있거나 이름·설명에 AI 용어가 있는 저장소만 남겼다. 이렇게 뺀 저장소: 1,610개.
- **분류.** `수동` = 본문 조사로 정함, `규칙` = 이름·설명 키워드 규칙, `토픽` = GitHub 토픽, `기본값` = 어느 규칙에도 걸리지 않아 K로 둠. 규칙 분류는 검토 전이라 틀린 칸이 있을 수 있다. X는 설치해서 쓰는 도구가 아닐 가능성이 큰 것(목록·교재·논문·예제·데이터셋)이다.
- **토픽:** `agent-framework`, `agentic-ai`, `agents`, `ai-agent`, `ai-agents`, `ai-assistant`, `ai-chatbot`, `ai-coding`, `ai-tools`, `anthropic`, `autonomous-agents`, `browser-automation`, `browser-use`, `chatbot`, `chatgpt`, `chatgpt-api`, `claude`, `claude-code`, `codex`, `coding-agent`, `comfyui`, `computer-use`, `copilot`, `cursor`, `deepseek`, `discord-bot`, `gemini`, `gemini-cli`, `generative-ai`, `gpt-4`, `llama`, `llamacpp`, `llm`, `llm-agent`, `llm-inference`, `llm-ui`, `local-llm`, `mcp`, `mcp-server`, `multi-agent`, `ollama`, `openai`, `opencode`, `personal-assistant`, `qwen`, `stable-diffusion`, `telegram-bot`, `text-to-speech`, `vibe-coding`, `voice-assistant`, `workflow-automation`.
- **키워드:** `agent`, `ai assistant`, `anthropic`, `chatbot`, `chatgpt`, `claude`, `codex`, `coding assistant`, `comfyui`, `copilot`, `cursor`, `deepseek`, `gemini`, `gpt`, `llm`, `local llm`, `mcp`, `ollama`, `openai`, `qwen`, `stable diffusion`, `telegram bot`, `text to speech`, `whisper`.

| 분류 | 저장소 수 |
|---|---|
| B 데스크톱·웹 챗 클라이언트 | 529 |
| C 브라우저·컴퓨터 사용 에이전트 | 90 |
| D IDE·에디터 어시스턴트 | 183 |
| E CLI 코딩 에이전트 | 687 |
| F 하네스·플러그인·스킬·메모리 묶음 | 1,046 |
| G 오케스트레이터·멀티에이전트 | 338 |
| H 메신저 봇 | 185 |
| I 자율·리서치 에이전트 | 119 |
| J 로컬 LLM 런타임·UI | 779 |
| K API·SDK·프레임워크·RAG·자동화 | 2,619 |
| L 이미지·음성·영상 생성 | 932 |
| M 모바일 앱 | 72 |
| N MCP 서버·도구 연결 | 1,354 |
| X 제외 후보(목록·교재·논문·예제·데이터셋) | 1,473 |
| 합계 | 10,406 |

## 분류별 목록

| 파일 | 저장소 수 |
|---|---|
| [B 데스크톱·웹 챗 클라이언트](ai-usage-coverage-github/b.md) | 529 |
| [C 브라우저·컴퓨터 사용 에이전트](ai-usage-coverage-github/c.md) | 90 |
| [D IDE·에디터 어시스턴트](ai-usage-coverage-github/d.md) | 183 |
| [E CLI 코딩 에이전트](ai-usage-coverage-github/e.md) | 687 |
| [F 하네스·플러그인·스킬·메모리 묶음](ai-usage-coverage-github/f.md) | 1,046 |
| [G 오케스트레이터·멀티에이전트](ai-usage-coverage-github/g.md) | 338 |
| [H 메신저 봇](ai-usage-coverage-github/h.md) | 185 |
| [I 자율·리서치 에이전트](ai-usage-coverage-github/i.md) | 119 |
| [J 로컬 LLM 런타임·UI](ai-usage-coverage-github/j.md) | 779 |
| [K API·SDK·프레임워크·RAG·자동화 (1/3, 별 1,430~288,036)](ai-usage-coverage-github/k-1.md) | 1,200 |
| [K API·SDK·프레임워크·RAG·자동화 (2/3, 별 562~1,426)](ai-usage-coverage-github/k-2.md) | 1,200 |
| [K API·SDK·프레임워크·RAG·자동화 (3/3, 별 500~561)](ai-usage-coverage-github/k-3.md) | 219 |
| [L 이미지·음성·영상 생성](ai-usage-coverage-github/l.md) | 932 |
| [M 모바일 앱](ai-usage-coverage-github/m.md) | 72 |
| [N MCP 서버·도구 연결 (1/2, 별 580~481,111)](ai-usage-coverage-github/n-1.md) | 1,200 |
| [N MCP 서버·도구 연결 (2/2, 별 500~580)](ai-usage-coverage-github/n-2.md) | 154 |
| [X 제외 후보(목록·교재·논문·예제·데이터셋) (1/2, 별 649~178,701)](ai-usage-coverage-github/x-1.md) | 1,200 |
| [X 제외 후보(목록·교재·논문·예제·데이터셋) (2/2, 별 500~647)](ai-usage-coverage-github/x-2.md) | 273 |
