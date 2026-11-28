# AI 사용 흔적 커버리지 매트릭스

조사일 2026-11-28. 시중 AI 사용 세팅마다 어떤 흔적이 어디에 남는지, Rapid가 지금 무엇을 잡는지 정리한 표다. 판정 규칙은 [§0](#0-읽는-법)에 있다. GitHub 별 500개 이상 프로젝트 조사(10,406개) 중 이 표와 연결된 저장소와 별 5,000개 이상 저장소는 부록 [ai-usage-coverage-github.md](ai-usage-coverage-github.md)에 있고, 전체 목록은 `scripts/ai-usage-github-appendix.py`로 다시 만든다.

## 요약 (분류별 한 쪽)

| 분류 | 정의 | 디스크 흔적 | Rapid 현재 | 다음 할 일 |
|---|---|---|---|---|
| A 웹 채팅 서비스 | 브라우저로 쓰는 대화형 AI 사이트 | 클라우드 전용. 방문 기록·쿠키·캐시·Local Storage·IndexedDB 조각과 내보내기 파일만 | 방문 기록 도메인 탐지(이번 PR로 13개 서비스 추가), 브라우저 저장소 대화 후보, ChatGPT 내보내기 | Copilot CSV·Takeout Gemini 활동 내보내기 |
| B 데스크톱 챗 앱 | 서비스 회사가 배포하는 설치형 채팅 앱 | 대부분 부분: 설정·로그·캐시는 로컬, 대화는 서버. Claude Cowork 세션과 Recall은 로컬 | 경로 용어 후보 인벤토리, Recall 저장소 인벤토리 | Claude Desktop 설정·MCP 로그·Cowork 세션 |
| C 브라우저 내장·확장·에이전트 브라우저 | Edge Copilot, Gemini in Chrome, Brave Leo, Comet, Dia, AI 확장 | Brave Leo는 로컬 SQLite. 에이전트 브라우저는 Chromium 프로필이 로컬. 나머지는 서버 + 정책·확장 폴더 | 확장 폴더 인벤토리. Leo·Comet·Dia 경로 미등록 | Brave Leo `AIChat`, Comet·Dia 프로필 경로 등록 |
| D IDE·에디터 어시스턴트 | 에디터 안의 채팅·에이전트 | 대부분 로컬(SQLite·JSON·JSONL) | Cursor·VS Code·Insiders·VSCodium(`editor-chat`) | Cline·Roo·Kilo·Continue·Windsurf·Zed |
| E CLI 코딩 에이전트 | 터미널에서 도는 코딩 에이전트 | 거의 전부 로컬 JSONL·SQLite | Claude Code·Codex·Gemini CLI, MCP 설정 | omp/pi 세션, OpenCode, Copilot CLI, Aider, Kimi·Qwen·Kiro |
| F 하네스·플러그인 묶음 | 에이전트 위에 얹는 스킬·훅·메모리 묶음(ECC, omo, claude-mem 등) | 설치 파일·상태 DB·메모리 파일·로그가 로컬 | 없음 | omo/senpi, ECC 상태·메모리 |
| G 오케스트레이터·멀티에이전트·허브 | 여러 에이전트 세션을 띄우고 관리하는 도구 | 로컬 상태 DB·로그·레지스트리 | 없음 | Cataly 허브, dori 상태, herdr, Orca |
| H 메신저 봇형 개인 에이전트 | 메신저·전화·앱으로 일을 시키는 개인 에이전트 | 서비스형(그록봇·피클·Dots·Muse·Duet)은 대부분 클라우드. 직접 운영 봇(Hermes, OpenClaw, dori, Cataly)은 토큰 파일·서비스 유닛·세션이 로컬 | 메신저 일반 수집만 | 직접 운영 봇은 G·F 수집기로, 서비스형은 도메인·앱 설치 흔적 |
| I 클라우드 자율 에이전트 | 서버 VM에서 도는 에이전트(Manus, Devin, Jules, Codex cloud) | 클라우드 전용. 브라우저 기록·알림 메일·GitHub PR 흔적만 | 도메인 일부 | 도메인 추가 |
| J 로컬 LLM 런타임 | 내 PC에서 모델을 돌리는 앱·서버 | 모델·로그·대화 DB가 로컬 | 경로 용어 기반 인벤토리와 프롬프트 후보, 이번 PR로 8개 앱 추가 | Ollama 데스크톱 `db.sqlite`, Open WebUI `chat` 테이블 전용 파서 |
| K API·SDK·자동화·프록시 | API 키, SDK 캐시, 구독 프록시, n8n 같은 자동화 | 환경 변수·`.env`·프록시 로그·자동화 DB가 로컬 | 없음(비밀값은 수집하지 않음) | 키 이름만 세는 인벤토리, claude-code-router, n8n |
| L 이미지·음성 생성 | SD WebUI·ComfyUI·Fooocus·InvokeAI 등 | 출력 파일 안 프롬프트 메타데이터, 로그, DB | 미디어 메타데이터 문자열 힌트 | PNG `parameters`·`prompt`·`workflow` 청크 파서 |
| M 모바일 앱 | 휴대폰 AI 앱(피클, Grok Bot·ChatGPT 모바일 등) | Windows 이미지에는 거의 없음. 휴대폰 추출본 쪽 | 모바일 내보내기의 AI 앱 표시 | 휴대폰 쪽은 yh-mobile-trace 담당 |

**디스크 이미지가 보여줄 수 없는 것.** A·I와 H의 서비스형, B의 대부분은 대화 본문이 서버에만 있다. Windows 디스크 이미지로 증명할 수 있는 것은 방문·로그인·설치·다운로드·알림·내보내기 파일까지다. 무슨 대화를 했고 에이전트가 무엇을 했는지는 서비스 내보내기나 법적 절차로 받은 서버 자료가 있어야 한다. 표의 `클라우드 전용`은 이 뜻이다. 클라우드 에이전트가 사용자 PC에서 명령을 실행하도록 허락한 경우(Grok Bot "Execution on this computer", Manus My Computer)에는 그 실행 흔적이 로컬에 남을 수 있지만 형식은 [미확인]이다.

## 0. 읽는 법

- **근거.** 경로·파일·테이블·도메인은 공식 문서, 공식 저장소 소스, 공식 도움말, 앱 스토어 공식 등록 정보에서 확인한 것만 적었다. 2차 출처(포렌식 블로그, 다른 사람의 이슈 글, 언론)는 `(2차)`를 붙였다. 확인하지 못한 경로는 `[미확인]`으로 두고 추측으로 채우지 않았다. 소스 코드 동작에서 끌어낸 경로는 `[추론]`으로 표시했다.
- **로컬 관찰.** 조사자 Mac(dori·Cataly·omp·omo·herdr 운영 환경)에서 **파일·폴더 이름만** 나열해 공개 문서와 맞춰 보았고, 문서에 없는 이름은 `(로컬 관찰: 이름만)`으로 표시했다. 세션 내용, 인증 파일, 토큰 파일은 열지 않았다.
- **분류.** `로컬` = 대화·작업 내용이 디스크에 있어 수집기를 만들 수 있다. `부분` = 설정·로그·캐시·참조는 로컬, 내용은 서버나 다른 도구에. `클라우드 전용` = 디스크에는 브라우저·알림·내보내기 흔적만 남는다.
- **Rapid 현재.** `있음` = 전용 수집기가 행을 낸다(수집기 kind와 코드 위치 표시). `부분` = 도메인만, 경로 용어 후보만, 범용 인벤토리만. `없음` = 잡지 않는다.
- **우선순위.** 실무 빈도(상·중·하) × 구현 난이도(쉬움·보통·어려움). `P1` = 빈도 상이고 쉬움~보통, `P2` = 빈도 중 또는 난이도 보통, `P3` = 빈도 하 또는 어려움(암호화·비공개 형식·클라우드 전용).
- **경로 표기.** `%APPDATA%` = `C:\Users\<user>\AppData\Roaming`, `%LOCALAPPDATA%` = `...\AppData\Local`, `~` = Windows에서 `%USERPROFILE%`. macOS는 `~/Library/...`, Linux는 XDG(`~/.config`, `~/.local/share`, `~/.local/state`).
- **비밀값.** 이 표는 비밀값을 적지 않는다. Rapid도 같은 원칙이다. 토큰·API 키·쿠키·세션 값은 출력하지 않고 키 **이름**과 파일 **존재**만 다룬다. 에이전트 수집기는 모든 텍스트 필드를 내보내기 전에 가린다([AI coding-agent artifacts](ai-agent-artifacts.md)의 Bounds and privacy). 브라우저 쿠키·비밀번호 저장소는 인벤토리만 하고 복호화하지 않는다(`rapidtriage/artifacts/windows/browser.py`의 `BROWSER_SECRET_HANDLING_WARNING`). 아래 표에서 `auth.json`, `secrets/`, `.env`, `credentials`, `access.key`, `credential_vault` 같은 파일은 **존재만** 기록할 대상이고 내용은 읽지 않는다. 새 수집기도 이 규칙을 따른다.

## A. 웹 채팅 서비스

정의: 브라우저로 접속해 쓰는 대화형 AI 사이트. 대화 본문은 계정(서버)에 있다. 모두 `클라우드 전용`이다.

Rapid 공통: 방문 기록에서 아래 호스트와 그 하위 도메인을 `browser-ai-usage` 행으로 낸다(`rapidtriage/core/ai_service_domains.py`, `rapidtriage/artifacts/windows/browser.py`의 `detect_ai_service`). 메모리 이미지 문자열의 URL도 같은 목록으로 분류한다(`rapidtriage/artifacts/memory.py`의 `classify_memory_url`). 브라우저 Local Storage·IndexedDB·Session Storage·Cache에서 역할·내용 형태의 조각을 `browser-ai-conversation` 후보로 낸다.

| 제품 | 호스트(방문 기록에서 찾는 이름) | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|
| ChatGPT | `chatgpt.com`, `chat.openai.com`; 업로드 `*.oaiusercontent.com`, 정적 `*.oaistatic.com` | [OpenAI 네트워크 권장](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps) | 있음 | P1 |
| ChatGPT Tasks·Pulse(종료 예정)·Agent(종료) | `chatgpt.com` 안의 기능. 알림·이메일 | [Tasks](https://help.openai.com/en/articles/10291617-tasks-in-chatgpt), [릴리스 노트](https://help.openai.com/en/articles/6825453-chatgpt-release-notes), [ChatGPT agent](https://help.openai.com/en/articles/11752874-chatgpt-agent) | 있음(ChatGPT 방문으로만) | P3 |
| Claude | `claude.ai` (`claude.com`은 회사·문서 사이트) | [Claude 다운로드](https://claude.com/download), [네트워크 설정](https://code.claude.com/docs/en/network-config) | 있음 | P1 |
| Gemini, Gems, 예약 작업 | `gemini.google.com` (구 `bard.google.com`). Project Mariner(`labs.google.com/mariner`)는 2026-05-04 종료 | [예약 작업](https://support.google.com/gemini/answer/16316416), [Mariner](https://labs.google.com/mariner/dashboard) | 있음 | P1 |
| Google AI Studio | `aistudio.google.com` | [AI Studio](https://aistudio.google.com/welcome) | 있음 | P2 |
| NotebookLM (2026-07 Gemini Notebook으로 이름 변경) | `notebooklm.google.com`(앱·노트북 `/notebook/<id>`), `notebooklm.google`(소개 페이지) | [notebooklm.google](https://notebooklm.google/) | 있음(이번 PR) | P2 |
| Perplexity | `perplexity.ai` | [perplexity.ai](https://www.perplexity.ai) | 있음 | P1 |
| Microsoft Copilot(개인) | `copilot.microsoft.com`, `copilot.com` | [copilot.microsoft.com](https://copilot.microsoft.com) (canonical `copilot.com`) | 있음(`copilot.com`은 이번 PR) | P1 |
| Microsoft 365 Copilot Chat | `copilot.cloud.microsoft`, `m365.cloud.microsoft/chat`. 뒤의 호스트는 Word·Outlook 웹도 함께 서비스하므로 브라우저 기록에서 경로가 `/chat`일 때만 잡고(`detect_ai_service`), 경로가 없는 메모리 URL 분류와 브라우저 저장소에는 넣지 않음 | [Manage Copilot Chat](https://learn.microsoft.com/en-us/copilot/manage/manage-copilot-chat) | 있음(이번 PR). `m365.cloud.microsoft/chat`은 브라우저 기록만 | P1 |
| Copilot Studio 에이전트 | `copilotstudio.microsoft.com` | [Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/agents-overview) | 없음 | P3 |
| Poe | `poe.com` | [poe.com](https://poe.com) | 있음 | P3 |
| DeepSeek | `chat.deepseek.com` (`deepseek.com` 하위로 매칭) | [chat.deepseek.com](https://chat.deepseek.com), [API 문서](https://api-docs.deepseek.com/) | 있음 | P1 |
| Grok | `grok.com`. `x.com/i/grok`은 X 전체와 호스트가 같아 경로 단위 탐지가 필요 [미확인] | [grok.com](https://grok.com), [X 도움말](https://help.x.com/en/using-x/about-grok) | 있음(`grok.com`) | P1 |
| Mistral Le Chat (2026-08 Vibe로 이름 변경, 주소 유지) | `chat.mistral.ai` | [Le Chat is now Vibe](https://help.mistral.ai/en/articles/682992-le-chat-is-now-vibe) | 있음 | P2 |
| Meta AI | `meta.ai` | [Meta 도움말](https://www.meta.com/help/artificial-intelligence/chat-with-meta-ai) | 있음 | P2 |
| Character.AI | `character.ai` | [character.ai](https://character.ai) | 있음 | P2 |
| 뤼튼(wrtn) | `wrtn.ai` | [wrtn.ai](https://wrtn.ai) | 있음(이번 PR) | P1 |
| 네이버 CLOVA X (2026-04-09 종료) | `clova-x.naver.com` | [clova-x.naver.com](https://clova-x.naver.com/), [네이버 고객센터](https://help.naver.com/service/30037/contents/25052) | 있음(이번 PR). 종료 전 기록 확인용 | P2 |
| 네이버 Cue: (2026-04-09 종료) | 네이버 검색 안 기능, 별도 호스트 [미확인] | (2차) [ZDNet Korea](https://zdnet.co.kr/view/?no=20260225180559) | 없음 | P3 |
| 에이닷(A.) | `adot.ai`(에이닷 노트 웹), 소개 `a.sktelecom.com` | [a.sktelecom.com](https://a.sktelecom.com/), [SKT 보도자료](https://news.sktelecom.com/207937) | 있음(이번 PR, `adot.ai`) | P2 |
| Kimi | `kimi.com`, `kimi.ai`, `kimi.moonshot.cn` | [kimi.com](https://www.kimi.com/) | 있음(이번 PR) | P2 |
| Qwen / 千问 | `chat.qwen.ai`, `qianwen.com`, `tongyi.aliyun.com` | [qwen.ai](https://qwen.ai/), [tongyi.aliyun.com/qianwen](https://tongyi.aliyun.com/qianwen) | 있음(이번 PR) | P2 |
| Doubao 豆包 | `doubao.com` | [doubao.com](https://www.doubao.com/) | 있음(이번 PR) | P3 |
| 智谱清言 ChatGLM | `chatglm.cn` | [chatglm.cn](https://chatglm.cn/) | 있음(이번 PR) | P3 |
| Genspark (Super Agent 포함) | `genspark.ai` | [Super Agent 도움말](https://www.genspark.ai/helpcenter/super-agent) | 있음(이번 PR) | P2 |
| Felo | `felo.ai` | [felo.ai](https://felo.ai/) | 있음(이번 PR) | P3 |
| You.com | `you.com` | [you.com](https://you.com/) | 있음 | P3 |
| Phind (2026-01 종료 (2차)) | `phind.com` | (2차) [felloai.com](https://felloai.com/phind-ai-answer-engine-everything-you-need-to-know/) | 있음 | P3 |
| HuggingChat(현재 Omni) | `huggingface.co/chat` — 경로 단위. 호스트 `huggingface.co`는 "Hugging Face"로만 잡힘 | [huggingface.co/chat](https://huggingface.co/chat/) | 부분 | P3 |
| Pi | `pi.ai` | [Inflection 상태 페이지](http://status.inflection.ai/) | 없음. 저장소 본문·경로 탐지(`likely_ai_storage_text`, `infer_ai_service_from_path`)가 부분 문자열로 찾던 동안에는 `api.airtable.com`에서 오탐했다. 이번 PR에서 호스트 경계 비교(`AI_SERVICE_DOMAIN_PATTERNS`)로 바꿨으므로 다음 PR에서 추가 | P3 |
| Liner | `liner.com` | [liner.com](https://liner.com/) (검색 요약 경유) | 없음. `airliner.com` 오탐은 호스트 경계 비교로 막힘. Pi와 함께 다음 PR에서 추가 | P3 |
| 카카오 Kanana / ChatGPT for Kakao | `kanana.kakao.com`, `kakaotalk-ai.kakao.com`, `mate.kanana.ai`. 카카오톡 안에서 쓰면 PC 카카오톡 DB에 남는지 [미확인] | [kanana.kakao.com](https://kanana.kakao.com/), [카카오 발표](https://www.kakaocorp.com/page/detail/11794?lang=ENG) | 없음 | P2 |
| Meta AI in WhatsApp·Instagram, ChatGPT in WhatsApp(2026-01 종료), LINE AI Assistant(종료), Telegram AI 요약 | 각 메신저 서버. PC 흔적은 메신저 앱 쪽 [미확인] | [Telegram AI summaries](https://telegram.org/blog/new-design-ai-summaries), [LINE 발표](https://www.linecorp.com/en/pr/news/global/2024/138/) | 메신저 일반 수집만 | P3 |
| 생성형 미디어 사이트 | Midjourney `midjourney.com`, Leonardo `leonardo.ai`, Ideogram `ideogram.ai`, Runway `runwayml.com`, Kling `klingai.com`, Sora `sora.com`(2026-04 웹 종료), Suno `suno.com`, Udio `udio.com`, ElevenLabs `elevenlabs.io`, Microsoft Designer `designer.microsoft.com`, Adobe Firefly | 각 공식 사이트, [Sora 종료 안내](https://help.openai.com/en/articles/20001152-what-to-know-about-the-sora-discontinuation), [Midjourney Creating on Web](https://docs.midjourney.com/hc/en-us/articles/33390732264589-Creating-on-Web) | 없음 | P2 |
| 노코드 자동화(클라우드) | Make `make.com`·웹훅 `hook.<region>.make.com`(2차), Zapier `zapier.com`·`hooks.zapier.com`, Lindy `lindy.ai`, Relevance AI `relevanceai.com` | [Make Webhooks](https://help.make.com/webhooks), [Zapier webhooks](https://help.zapier.com/hc/en-us/articles/8496288690317-Trigger-Zap-workflows-from-webhooks), [Relevance AI](https://relevanceai.com/docs/get-started/introduction) | 없음 | P3 |
| API 콘솔 | `platform.openai.com`, `platform.claude.com`, `console.x.ai`, `openrouter.ai`, `console.groq.com` | [OpenAI quickstart](https://platform.openai.com/docs/quickstart), [Anthropic API 키](https://platform.claude.com/docs/en/get-api-key), [xAI](https://docs.x.ai/docs/tutorial), [OpenRouter](https://openrouter.ai/docs/api_reference/authentication) | 부분(`openai.com`만 "OpenAI"로) | P2 |

**내보내기 파일.** 서비스가 내려주는 내보내기는 PC에 남는 가장 좋은 본문 증거다.

| 서비스 | 받는 곳·형식 | 근거 | Rapid 현재 |
|---|---|---|---|
| ChatGPT | 이메일 링크(24시간)로 ZIP. `index.html`(현재)·`chat.html`(이전) 뷰어와 JSON 대화. `conversations.json` 이름은 현재 도움말에 없음 [미확인] | [Exporting your ChatGPT history](https://help.openai.com/en/articles/7260999-exporting-your-chatgpt-history-and-data) | 있음: `ai-service-export-conversation`(`rapidtriage/artifacts/cloud.py`의 `openai-chatgpt-export`, `rapidtriage/artifacts/windows/browser.py`의 `collect_ai_service_export_artifacts`) |
| Claude | 설정 > Privacy > Export data, 이메일 링크(24시간). 파일 이름 [미확인] | [Export your Claude data](https://support.claude.com/en/articles/9450526-export-your-claude-data) | 부분: 경로에 `claude`·`anthropic`·`export`가 있으면 JSON을 후보로 읽음 |
| Gemini | Google Takeout "My Activity > Gemini Apps", 링크 7일. 내부 파일 이름 [미확인] | [Gemini 내보내기](https://support.google.com/gemini/answer/16920332) | 부분: Takeout 범용 수집, Gemini 활동 전용 파서 없음 |
| Microsoft Copilot(개인) | 개인정보 대시보드 > Copilot > 활동 기록 내보내기 → CSV | [Copilot 활동 기록](https://support.microsoft.com/en-us/privacy/manage-your-copilot-activity-history-in-the-privacy-dashboard) | 없음 |
| Perplexity | 계정 설정 > Export my data, 이메일. 파일 구성 [미확인] | [Self-serve data options](https://www.perplexity.ai/hub/legal/self-serve-data-options) | 부분(경로 용어) |
| Character.AI | 설정 > Export Data, 3~4주 후 이메일(7일). 파일 구성 [미확인] | [How do I download my data](https://support.character.ai/hc/en-us/articles/56967715028891-How-do-I-download-my-data) | 없음 |
| ElevenLabs | 서버 History에서 다시 내려받기, API `GET /v1/history` | [History](https://elevenlabs.io/docs/api-reference/history/list) | 없음 |

## B. 데스크톱 챗 앱

정의: 서비스 회사가 배포하는 설치형 채팅 앱. 대부분 대화는 서버에 있고 PC에는 설치 흔적(Store 패키지, 프로그램 폴더), 설정, 로그, 캐시가 남는다.

Rapid 공통: `AppData`·`Application Support`·`Packages`·`Local Storage`·`IndexedDB` 아래 경로에 제품 이름이 들어 있으면 `desktop-ai-app-artifact`로 인벤토리하고, SQLite면 메시지 테이블 후보를 `desktop-ai-conversation-candidate`로 낸다(`rapidtriage/artifacts/generic.py`의 `DESKTOP_AI_APP_PATH_TERMS`). 제품 전용 파서는 없다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| ChatGPT for Windows (Classic) | 부분 | Store ID `9NT1R1C2HH7J`. 앱 데이터 경로 [미확인]. 통신 호스트 `desktop.chat.openai.com`, `ws.chatgpt.com` | [Using the ChatGPT Windows app](https://help.openai.com/en/articles/9982051-using-the-chatgpt-windows-app) | 부분(경로 용어 `chatgpt`·`openai`) | P2 |
| ChatGPT for Windows (신규 통합 앱, Codex 포함) | 부분 | Store ID `9PLM9XGG6VKS`, AppX 이름 `OpenAI.Codex`, MSIX `ChatGPT-x64.msix`. Codex 모드 상태는 `%USERPROFILE%\.codex`(E 분류 Codex 행) | [Windows deployment](https://learn.chatgpt.com/docs/enterprise/windows-deployment) | 부분(경로 용어 `openai`), Codex 쪽은 `codex-cli` | P1 |
| ChatGPT for macOS | 부분 | 공식: 채팅 제목 등 일부 데이터를 Mac에 저장. `~/Library/Application Support/com.openai.chat/conversations-v2-<uuid>/`(Keychain 키로 암호화) (2차) | [Data retention in the ChatGPT macOS app](https://help.openai.com/en/articles/9268871-data-retention-in-the-chatgpt-macos-app), (2차) [pvieito.com](https://pvieito.com/2024/07/chatgpt-unprotected-conversations) | 부분(경로 용어) | P2 |
| Claude Desktop | 부분 | 설정 `%APPDATA%\Claude\claude_desktop_config.json`(mac `~/Library/Application Support/Claude/`, Linux `~/.config/Claude/`), `mcpServers` 키. 로그 `%APPDATA%\Claude\logs\mcp.log`, `mcp-server-<이름>.log`(mac `~/Library/Logs/Claude`). Windows 배포 `Claude.msix`. 일반 대화는 서버 | [Connect local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers), [Deploy Claude Desktop for Windows](https://support.claude.com/en/articles/12622703-deploy-claude-desktop-for-windows) | 부분(경로 용어 `claude`). `agent-mcp`는 이 설정 파일을 읽지 않음 | P1 |
| Claude Cowork(데스크톱 컴퓨터 사용) | 로컬 | `%APPDATA%\Claude\local-agent-mode-sessions\`(세션 기록·첨부·생성 파일), `%APPDATA%\Claude\vm_bundles\claudevm.bundle\`(`rootfs.img`, `sessiondata.img`). mac도 같은 구조 (2차) | (2차) [claude-code#65577](https://github.com/anthropics/claude-code/issues/65577), (2차) [mintstorage.app](https://mintstorage.app/build-journey/whats-inside-claudevm-bundle/) | 부분(경로 용어) | P1 |
| Microsoft Copilot 앱 | 부분 | Store ID `9NHT9RB2F4HD`, 패키지 `Microsoft.Copilot`, 정책 `TurnOffWindowsCopilot`(WindowsAI CSP). 대화는 서버(활동 기록). 앱 데이터 경로 [미확인] | [Manage Copilot in Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot) | 부분(경로 용어 `copilot`) | P1 |
| Microsoft Copilot Actions(Windows 에이전트 기능) | 부분 | 설정 > System > AI Components > Experimental agentic features. 별도 agent 계정과 agent workspace(별도 Windows 세션)를 만들고, EPM 환경에서는 `C:\Users\` 아래 `_$`로 끝나는 프로필이 남음. 문서·다운로드 등 폴더 ACL 변경 | [Experimental agentic features](https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features) | 없음(계정·프로필 목록은 범용 수집에 있음) | P2 |
| Microsoft Copilot Vision | 클라우드 전용 | 세션 데이터를 최대 47시간 보관(서버) | [Using Copilot Vision](https://support.microsoft.com/en-us/topic/using-copilot-vision-with-microsoft-copilot-3c67686f-fa97-40f6-8a3e-0e45265d425f) | 없음 | P3 |
| Windows Recall (Copilot+ PC) | 로컬 | 스냅샷과 OCR 텍스트가 기기에 저장(공식). `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}\ukg.db`, `ImageStore\` (2차) | [Manage Recall](https://learn.microsoft.com/en-us/windows/client-management/manage-recall), (2차) [Velociraptor Recall 아티팩트](https://docs.velociraptor.app/exchange/artifacts/pages/windows.system.recall.windowcaptureevent) | 있음: Recall 저장소 인벤토리(`rapidtriage/artifacts/windows/system.py`의 `RECALL_DB_NAMES`) | P1 |
| Gemini 데스크톱 앱 | 클라우드 전용 | Windows 10+/macOS 15+. 로컬 경로 [미확인]. 기록은 Google 계정 | [gemini.google/desktop](https://gemini.google/desktop/), [FAQ](https://support.google.com/gemini/answer/17011627) | 부분(경로 용어 `gemini`) | P3 |
| Perplexity 데스크톱 앱 | 부분 | Store ID `9P9XG917PWCJ`. 로컬 경로 [미확인] | [Get started](https://www.perplexity.ai/help-center/en/articles/19800002-get-started) | 부분(경로 용어) | P3 |
| Grok Bot 데스크톱 앱(xAI) | 부분 | macOS·Windows·Linux 앱, Cursor 계정 로그인. 작업은 클라우드 컴퓨터에서 돌고 대화는 계정에 동기화. 사용자가 허락하면 내 PC에서 명령 실행("Execution on this computer"). 앱 데이터 경로 [미확인] | [Grok Bot FAQ](https://docs.x.ai/grok-bot/faq), [x.ai/bot](https://x.ai/bot) | 없음 | P2 |
| Manus 데스크톱(My Computer) | 부분 | Windows·macOS 앱. 사용자가 고른 폴더에서 CLI 명령 실행. 앱 데이터 경로 [미확인]. 작업은 `manus.im` | [Manus 데스크톱 앱](https://help.manus.im/en/articles/14089011-how-to-download-the-manus-desktop-app), [My Computer](https://manus.im/blog/manus-my-computer-desktop) | 없음(`manus.im` 도메인만) | P2 |
| Kimi·Doubao·Qwen PC 앱 | 부분 | 데스크톱 앱 있음(공식 다운로드 페이지). 경로 [미확인] | [kimi.com 다운로드](https://www.kimi.com/products/download), [doubao.com 다운로드](https://www.doubao.com/download) | 없음 | P3 |
| Codex 앱(데스크톱) | 로컬 | `CODEX_HOME`(기본 `~/.codex`) 공유. E 분류 Codex 행 | [Codex 환경 변수](https://developers.openai.com/codex/environment-variables) | 있음(`codex-cli`, 일부) | P1 |

## C. 브라우저 내장 AI·확장·에이전트 브라우저

정의: 브라우저에 붙은 AI(사이드바, 내장 비서), AI 확장 프로그램, AI 에이전트를 앞세운 브라우저.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Copilot in Edge(사이드바) | 클라우드 전용 | 정책 레지스트리 `SOFTWARE\Policies\Microsoft\Edge`의 `HubsSidebarEnabled`, `CopilotPageContext`, `EdgeEntraCopilotPageContext`, `Microsoft365CopilotChatIconEnabled`. 사이드바 상태 파일 [미확인] | [HubsSidebarEnabled](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/hubssidebarenabled), [Manage Copilot Chat](https://learn.microsoft.com/en-us/copilot/manage/manage-copilot-chat) | 없음 | P2 |
| Gemini in Chrome (glic) | 클라우드 전용 | 정책 `GeminiSettings`, `GeminiActOnWebSettings`, `GenAiDefaultSettings`. 소스 `chrome/browser/glic/`. 로컬 대화 저장 [미확인] | [Chrome Enterprise 도움말](https://support.google.com/chrome/a/answer/16291696), [Chromium glic 소스](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/glic/gemini_act_on_web_settings_policy_handler.cc) | 없음 | P2 |
| Brave Leo | 로컬 | 프로필 폴더의 SQLite `AIChat`(암호화 저장). 테이블 `conversation`, `conversation_entry`, `associated_content`, `conversation_entry_uploaded_files` 등. 대화가 로컬에만 저장(공식), 사설·Tor 창은 저장 안 함 | [brave-core ai_chat_database.cc](https://raw.githubusercontent.com/brave/brave-core/master/components/ai_chat/core/browser/ai_chat_database.cc), [Chat History in Brave Leo](https://support.brave.app/hc/en-us/articles/32663367857549-How-do-I-use-Chat-History-in-Brave-Leo) | 없음 | P2 |
| Opera AI(구 Aria) | 클라우드 전용 | 대화는 Opera 계정에 1년(로그인)·6시간(비로그인). 로컬 경로 [미확인] | [Opera AI FAQ](https://help.opera.com/en/browser-ai-faq/) | 없음 | P3 |
| Perplexity Comet | 부분 | `%LOCALAPPDATA%\Perplexity\Comet\User Data\`(Chromium 프로필: History, Network\Cookies), mac `~/Library/Application Support/Comet/`. 에이전트 대화는 `perplexity.ai` | [Uninstalling Comet](https://www.perplexity.ai/help-center/comet/en/articles/11734832-uninstalling-comet), [Comet local data](https://www.perplexity.ai/help-center/comet/en/articles/11740986-local-data-device-storage) | 없음(Chromium 계열 경로 미등록) | P1 |
| Dia (The Browser Company) | 부분 | mac `~/Library/Application Support/Dia/User Data/`, Windows `%LOCALAPPDATA%\Packages\TheBrowserCompany.Dia_ttt1ap7aakyb4\LocalCache\Local\Dia\User Data` (2차) | (2차) [claude-code#34830](https://github.com/anthropics/claude-code/issues/34830) | 없음 | P2 |
| Opera Neon | 부분 | `%LOCALAPPDATA%\Opera Software\Opera Neon\User Data\Default` (2차) | (2차) [TechCrunch](https://techcrunch.com/2025/09/30/opera-launches-its-ai-centric-neon-browser/) | 없음 | P3 |
| Fellou | 부분 | 로컬에서 동작한다고 공식 블로그가 설명. 프로필 경로 [미확인]. `fellou.ai` | [Fellou 블로그](https://fellou.ai/blog/how-agentic-features-in-ai-browser-fellou-are-changing-work/) | 없음 | P3 |
| ChatGPT Atlas(macOS, 은퇴) | 부분 | 브라우저 기록·쿠키·브라우저 메모리가 Mac에 남을 수 있음(공식). 경로 [미확인] | [Atlas retirement](https://help.openai.com/en/articles/20001371-chatgpt-atlas-retirement) | 없음 | P3 |
| Claude in Chrome 확장 | 부분 | 확장 ID `fcoeoabgfenejglbffodgkkbkcdhcgfn`. 세션은 계정에 저장(공식) | [Chrome Web Store](https://chromewebstore.google.com/detail/claude/fcoeoabgfenejglbffodgkkbkcdhcgfn), [claude.com/claude-in-chrome](https://claude.com/claude-in-chrome) | 부분(확장 폴더 인벤토리) | P2 |
| AI 확장 프로그램 | 부분 | `<프로필>\Extensions\<ID>`, `<프로필>\Local Extension Settings\<ID>`(LevelDB). ID: Sider `difoiogjjojoaoomphldepapgpbgkhkb`, Monica `ofpnmcalabcbjgholdjcjblkibolbppb`, Merlin `camppjleccjaphfdbohjdohecfnoikec`, MaxAI `mhnlakgilnojmhinhkckjpncpbhabphi`, ChatGPT for Google `jgjaeacdkonaoafenlfkkkmbaopkbilf` | [Chromium constants.h](https://raw.githubusercontent.com/chromium/chromium/main/extensions/common/constants.h), 각 [Chrome Web Store](https://chromewebstore.google.com/detail/difoiogjjojoaoomphldepapgpbgkhkb) 페이지 | 부분: 확장 폴더 인벤토리는 있음, AI 확장 ID 표는 없음 | P2 |
| Browser Use(라이브러리·Cloud) | 부분 | `$XDG_CONFIG_HOME/browseruse`(기본 `~/.config/browseruse`, `BROWSER_USE_CONFIG_DIR`), 작업 폴더 `.env`. Cloud `cloud.browser-use.com` | [config.py](https://github.com/browser-use/browser-use/blob/main/browser_use/config.py), [CLOUD.md](https://github.com/browser-use/browser-use/blob/main/CLOUD.md) | 없음 | P3 |
| UI-TARS Desktop(ByteDance) | 부분 | Electron userData의 `ui_tars.setting.json`(productName `UI-TARS`, 폴더 이름 [미확인]). 대화 저장 [미확인] | [setting.ts](https://github.com/bytedance/UI-TARS-desktop/blob/main/apps/ui-tars/src/main/store/setting.ts), [electron-builder.yml](https://github.com/bytedance/UI-TARS-desktop/blob/main/apps/ui-tars/electron-builder.yml) | 없음 | P3 |
| Skyvern | 로컬 | `~/.skyvern/data.db`(로컬 SQLite 모드), `~/.skyvern/credential_vault`(열지 않음), `./log`, `./har`, `./video`, `artifacts/`. Cloud `api.skyvern.com` | [config.py](https://github.com/Skyvern-AI/skyvern/blob/main/skyvern/config.py), [.env.example](https://github.com/Skyvern-AI/skyvern/blob/main/.env.example) | 없음 | P3 |
| Anthropic computer-use 참조 구현 | 부분 | 호스트 `~/.anthropic/`(API 키·시스템 프롬프트, 컨테이너에 마운트) | [computer-use-demo README](https://github.com/anthropics/claude-quickstarts/blob/main/computer-use-demo/README.md) | 없음 | P3 |
| Agent S, MultiOn(피벗), Adept(인수) | [미확인]·종료 | 로컬 경로 확인 못 함 | [Agent S](https://github.com/simular-ai/Agent-S) | 없음 | P3 |

## D. IDE·에디터 어시스턴트

정의: 코드 에디터 안의 채팅·에이전트. VS Code 계열 사용자 데이터 루트는 Windows `%APPDATA%\<앱>\User`, macOS `~/Library/Application Support/<앱>/User`, Linux `~/.config/<앱>/User`다.

Rapid 공통: `editor-chat`이 Cursor·Code·Code - Insiders·VSCodium의 `state.vscdb`(`ItemTable`, `cursorDiskKV`)와 `chatSessions/*.json`을 읽고, `agent-mcp`가 `.cursor/mcp.json`, `.vscode/mcp.json`, 에디터 `User/mcp.json`을 읽는다([AI coding-agent artifacts](ai-agent-artifacts.md), `rapidtriage/artifacts/ai_agent_editor.py`). 확장 프로그램이 `globalStorage/<확장 ID>/` 아래 따로 쓰는 파일은 읽지 않는다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Cursor | 로컬 | `User/globalStorage/state.vscdb`(`ItemTable`, `cursorDiskKV`: `composerData:<id>`, `bubbleId:<cid>:<bid>`), `workspaceStorage/<md5>/state.vscdb`, `~/.cursor/mcp.json`, `~/.cursor/ai-tracking/ai-code-tracking.db`(2차), `~/.cursor/projects/<cwd>/agent-transcripts/<id>/<id>.jsonl`(2차). 스키마 공식 문서 없음 | [Cursor MCP](https://cursor.com/docs/mcp.md), (2차) [cursaves](https://github.com/Callum-Ward/cursaves/blob/main/docs/how-cursor-stores-chats.md) | 있음(`editor-chat`, `agent-mcp`). `~/.cursor` 아래 transcript·tracking DB는 없음 | P1 |
| Cursor CLI(cursor-agent) | 로컬 | `~/.cursor/cli-config.json`, `~/.cursor/chats/<md5(cwd)>/<session>/{store.db,meta.json,prompt_history.json}`(2차) | [CLI configuration](https://cursor.com/docs/cli/reference/configuration.md) | 없음 | P2 |
| VS Code GitHub Copilot Chat | 로컬 | `workspaceStorage/<id>/chatSessions/<session>.jsonl`(또는 `.json`), `globalStorage/emptyWindowChatSessions/`, `globalStorage/transferredChatSessions/`, `globalStorage/github.copilot-chat/session-store.db`(2차, 로컬 SQLite는 공식). `chat.sessionSync.enabled`면 GitHub에도 | [chatSessionStore.ts](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/contrib/chat/common/model/chatSessionStore.ts), [Session history](https://code.visualstudio.com/docs/agents/run/sessions/session-history) | 부분(`editor-chat`: `chatSessions/*.json`, `emptyWindowChatSessions/*.json`, `state.vscdb`). `.jsonl` 세션 로그, `transferredChatSessions/`, `session-store.db`는 없음 | P1 |
| Windsurf / Codeium (현재 Devin Desktop) | 로컬 | `~/.codeium/windsurf/cascade/<uuid>.pb`(대화, 형식 비공개), `~/.codeium/windsurf/memories/`, `~/.codeium/windsurf/mcp_config.json`; 새 구조 `~/.devin/rules`, `~/.config/devin/mcp_config.json`. 접속 도메인 `*.codeium.com`, `*.codeiumdata.com` | [Windsurf common issues](https://docs.devin.ai/desktop/troubleshooting/windsurf-common-issues.md), [Memories](https://docs.devin.ai/desktop/cascade/memories.md) | 없음 | P2 |
| JetBrains AI Assistant | 로컬 | IDE 설정 폴더 `%APPDATA%\JetBrains\<제품><버전>\workspace\*.xml`(대화, 요소 이름 (2차)), 로그 `%LOCALAPPDATA%\JetBrains\<제품><버전>\log` | [IDE 디렉터리](https://www.jetbrains.com/help/idea/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html) | 없음 | P2 |
| JetBrains Junie | 부분 | `~/.junie/`(`JUNIE_HOME`), `~/.junie/mcp/mcp.json`, 프로젝트 `.junie/`. 세션 저장 위치 [미확인] | [Junie CLI 설정](https://junie.jetbrains.com/docs/junie-cli-configuration.html) | 없음 | P3 |
| Zed | 로컬 | 데이터 폴더 Windows `%LOCALAPPDATA%\Zed`, mac `~/Library/Application Support/Zed`, Linux `~/.local/share/zed` → `threads/threads.db`(테이블 `threads`, `data`는 zstd 압축 JSON) | [agent/db.rs](https://github.com/zed-industries/zed/blob/a84689073d296dfd39987bc7dd478e43ef76d83a/crates/agent/src/db.rs#L444-L485), [paths.rs](https://github.com/zed-industries/zed/blob/a84689073d296dfd39987bc7dd478e43ef76d83a/crates/paths/src/paths.rs) | 없음 | P2 |
| Cline | 로컬 | `globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/{api_conversation_history.json,ui_messages.json,task_metadata.json}`, `state/taskHistory.json`, `settings/cline_mcp_settings.json`; 새 SDK 저장소 `~/.cline/data/{sessions/,db/sessions.db}` | [disk.ts](https://github.com/cline/cline/blob/39ff2359f7e08231281539696e48a166ce49270c/apps/vscode/src/core/storage/disk.ts#L17-L36) | 없음 | P1 |
| Roo Code | 로컬 | `globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/{api_conversation_history.json,ui_messages.json,task_metadata.json}`, `tasks/_index.json`, `settings/mcp_settings.json` | [globalFileNames.ts](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/shared/globalFileNames.ts#L1-L9) | 없음 | P1 |
| Kilo Code | 로컬 | `~/.local/share/kilo/kilo.db`(SQLite: sessions, messages, parts), `auth.json`, `log/`; 설정 `~/.config/kilo` | [session-history.md](https://github.com/Kilo-Org/kilocode/blob/main/packages/kilo-docs/pages/code-with-ai/agents/session-history.md) | 없음 | P2 |
| Continue | 로컬 | `~/.continue/`(`CONTINUE_GLOBAL_DIR`): `sessions/<id>.json`, `sessions/sessions.json`, `config.yaml`, `dev_data/devdata.sqlite`, `dev_data/<schema>/<event>.jsonl`, `logs/{core.log,prompt.log}` | [paths.ts](https://github.com/continuedev/continue/blob/5522c6f44ca0ac3528b37244818fbfa39b5af470/core/util/paths.ts#L78-L249) | 없음 | P2 |
| Trae | 로컬(암호화) | `%APPDATA%\Trae\ModularData\ai-agent\database.db`(SQLCipher (2차)), mac `~/Library/Application Support/Trae/ModularData` | [Trae troubleshoot](https://docs.trae.ai/ide/troubleshoot-general-issues) | 없음 | P3 |
| Kiro(IDE·CLI) | 부분 | 전역 `~/.kiro/`(`settings/{mcp.json,cli.json}`, `agents/`, `steering/`), 프로젝트 `.kiro/`(`specs/`). CLI 세션은 `~/.kiro/` 로컬 DB(공식), `--cloud`는 서버. IDE `%APPDATA%\Kiro\User\globalStorage\kiro.kiroagent\`(2차) | [Kiro configuration](https://kiro.dev/docs/configuration/), [Session management](https://kiro.dev/docs/cli/chat/session-management/) | 없음 | P2 |
| Amazon Q Developer(IDE) | 로컬 | 대화를 홈 폴더에 저장(공식). `~/.aws/amazonq/` | [IDE chat conversation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/ide-chat-conversation.html) | 없음 | P2 |
| Augment | 부분 | `~/.augment/settings.json`, `~/.augment/sessions/<id>.json`(2차) | [Augment CLI integrations](https://docs.augmentcode.com/cli/integrations) | 없음 | P3 |
| Void(지원 종료) | 로컬 | `state.vscdb`의 `void.chatThreadStorageII` 키 [추론] | [storageKeys.ts](https://github.com/voideditor/void/blob/main/src/vs/workbench/contrib/void/common/storageKeys.ts) | 없음 | P3 |
| Tabnine | 클라우드 전용 | 대화 맥락은 답변 직후 서버에서 삭제(공식). CLI 설정 `~/.tabnine/agent/` | [Tabnine 문서](https://docs.tabnine.com/main/llms-full.txt) | 없음 | P3 |
| Orca(에이전트 IDE) | G 분류 Orca 행 | — | — | 없음 | — |

## E. CLI 코딩 에이전트

정의: 터미널에서 도는 코딩 에이전트. 거의 모두 대화를 로컬 JSONL·SQLite에 남긴다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Claude Code | 로컬 | `~/.claude`(`CLAUDE_CONFIG_DIR`): `projects/<project>/<session>.jsonl`(+`subagents/`, `tool-results/`), `history.jsonl`, `file-history/<session>/`, `shell-snapshots/`, `todos/`, `tasks/`, `plans/`, `plugins/`, `settings.json`; `~/.claude.json`. 기본 30일 보관(`cleanupPeriodDays`) | [claude-directory](https://code.claude.com/docs/en/claude-directory.md), [settings](https://code.claude.com/docs/en/settings.md) | 있음(`claude-code`: projects JSONL, history, `.claude.json`, settings). `file-history/`, `plugins/`, `todos/`는 없음 | P1 |
| Codex CLI·Codex 앱 | 로컬 | `CODEX_HOME`(기본 `~/.codex`): `sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl`, `archived_sessions/`, `history.jsonl`, `config.toml`, `auth.json`(열지 않음), SQLite `state_5.sqlite`·`logs_2.sqlite`·`goals_1.sqlite`·`memories_1.sqlite`·`queue_1.sqlite`(버전에 따라 이름이 바뀜), `session_index.jsonl`·`generated_images/`·`browser/sessions/*.toml`(로컬 관찰: 이름만) | [config-advanced](https://developers.openai.com/codex/config-advanced), [state/sqlite.rs](https://github.com/openai/codex/blob/main/codex-rs/state/src/sqlite.rs) | 있음(`codex-cli`: sessions·history·config). SQLite 상태 DB는 없음 | P1 |
| Codex cloud | 클라우드 전용 | `chatgpt.com/codex`, GitHub PR·브랜치 | [Codex cloud](https://developers.openai.com/codex/cloud) | 부분(ChatGPT 방문으로만) | P3 |
| Gemini CLI | 로컬 | `~/.gemini/settings.json`, `~/.gemini/tmp/<project_hash>/chats/`, `checkpoints/`, `logs.json`, `shell_history`, `~/.gemini/history/`, `projects.json`, `oauth_creds.json`(열지 않음). 기본 30일 보관 | [storage.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/config/storage.ts), [session-management](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md) | 있음(`gemini-cli`: chats·logs·settings) | P1 |
| Google Antigravity(앱·CLI `agy`) | 로컬 | `~/.gemini/antigravity/`: `conversations/<uuid>.db`(과거 `.pb`), `conversation_summaries.db`, `brain/<uuid>/`, `annotations/`, `mcp/`(2차); CLI `~/.gemini/antigravity-cli/`(`settings.json` 공식, `history.jsonl`·`brain/<uuid>/.system_generated/logs/transcript_full.jsonl`은 (2차)); `~/.gemini/config/mcp_config.json`; `~/.gemini/tasks/c_<hash>/{workspace,backup}`(로컬 관찰: 이름만) | [Antigravity MCP](https://antigravity.google/docs/mcp?format=md), [features](https://antigravity.google/docs/features?format=md), (2차) [antigravity-cli#672](https://github.com/google-antigravity/antigravity-cli/issues/672) | 없음 | P1 |
| oh-my-pi (omp) | 로컬 | `~/.omp`(`PI_CONFIG_DIR`): `agent/sessions/<encoded-cwd>/<ts>_<sessionId>.jsonl`, `agent/blobs/<sha256>`, `agent/agent.db`(설정·인증), `agent/history.db`(프롬프트 기록, `session_titles`), `agent/transcripts.db`(대화 FTS 색인), `agent/models.db`, `agent/memories/`, `agent/terminal-sessions/`, `agent/custom-session-files/`, `agent/config.yml`, `agent/secrets.yml`·`.env`(열지 않음), `agent/extensions/`, `logs/omp.<date>.<pid>.log`, `run/session-owners/`, `run/daemon/`(SQLite, 파일 이름 `daemon.db`는 로컬 관찰: 이름만), `wt/`. JSONL은 `session` 헤더 → `message`(user·assistant·toolResult·bashExecution 등), `model_change`, `compaction`, `title_change` 등. `<encoded-cwd>`: 홈 아래 `-<상대경로>`, 그 밖 `--<절대경로>--` | [docs/session.md](https://github.com/can1357/oh-my-pi/blob/main/docs/session.md), [dirs.ts](https://github.com/can1357/oh-my-pi/blob/main/packages/utils/src/dirs.ts#L1021-L1116), [logger.ts](https://github.com/can1357/oh-my-pi/blob/main/packages/utils/src/logger.ts#L4), [secrets.md](https://github.com/can1357/oh-my-pi/blob/main/docs/secrets.md) | 없음 | P1 (다음 PR 1순위) |
| pi(earendil-works/pi, 구 badlogic/pi-mono) | 로컬 | `~/.pi/agent`(`PI_CODING_AGENT_DIR`): `sessions/--<path>--/<ts>_<id>.jsonl`(기록 유형 `session`, `message`, `model_change`, `thinking_level_change`, `compaction`, `branch_summary`, `custom`, `label`; `id`/`parentId` 트리), `settings.json`, `mcp.json`, `models.json`, `auth.json`(열지 않음), `extensions/`, `skills/` | [session-format.md](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/session-format.md#L7-L17), [configuration.md](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/configuration.md#L3-L23) | 없음 | P1 (omp와 같은 수집기) |
| OpenCode(anomalyco/opencode, 구 sst) | 로컬 | `~/.local/share/opencode/`(Windows도 `%USERPROFILE%\.local\share\opencode`): v2 `opencode.db`(session·message·part), v1 `storage/{session,message,part,project}/**/*.json`, `auth.json`(열지 않음), `snapshot/`, `tool-output/`, `log/opencode.log`; 설정 `~/.config/opencode/opencode.json[c]`; `~/.local/state/opencode/prompt-history.jsonl` | [global.ts](https://github.com/anomalyco/opencode/blob/bf544cd419c5f17535c0d5af929f7ecd41188320/packages/util/src/global.ts), [troubleshooting](https://opencode.ai/docs/troubleshooting/) | 없음 | P1 |
| Aider | 로컬 | 저장소(또는 작업 폴더) 안 `.aider.chat.history.md`, `.aider.input.history`, `.aider.llm.history`(선택), `.aider.tags.cache.v*/`, `.aider.conf.yml`; `~/.aider/` | [aider options](https://aider.chat/docs/config/options.html), [args.py](https://github.com/Aider-AI/aider/blob/5dc9490bb35f9729ef2c95d00a19ccd30c26339c/aider/args.py#L271-L301) | 없음 | P1 |
| GitHub Copilot CLI | 로컬 | `~/.copilot`(`COPILOT_HOME`): `session-state/<id>/events.jsonl`, `session-store.db`, `command-history-state/`, `logs/`, `config.json`, `mcp-config.json` | [CLI config dir reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference) | 없음 | P1 |
| Goose(aaif-goose, 구 block) | 로컬 | 설정 `~/.config/goose/config.yaml`(Windows `%APPDATA%\Block\goose\config\`), `secrets.yaml`(열지 않음); 데이터 `~/.local/share/goose/sessions/sessions.db`(+구 `sessions/*.jsonl`, Windows `%APPDATA%\Block\goose\data\`); 로그 `~/.local/state/goose/logs/llm_request.<N>.jsonl` | [paths.rs](https://github.com/aaif-goose/goose/blob/b23d21cabd9b4de0c045dcdd731821a3a15c2bfc/crates/goose/src/config/paths.rs#L22-L36) | 없음 | P2 |
| Amp(Sourcegraph) | 부분 | 스레드는 `ampcode.com` 서버. 로컬 `~/.config/amp/settings.json`, `~/.local/share/amp/history.jsonl`, `~/.cache/amp/logs/threads/<T-id>.log`(2차) | (2차) [DoubleAgent amp](https://seanthegeek.net/doubleagent/research/amp.html) | 없음 | P2 |
| Crush(charmbracelet) | 로컬 | 프로젝트 `<project>/.crush/{crush.db,logs/crush.log}`, 전역 `~/.config/crush/crush.json`, `~/.local/share/crush/`(Windows `%LOCALAPPDATA%\crush\`) | [load.go](https://github.com/charmbracelet/crush/blob/ca6ae26ce016b980407ce32f012a467ec10c1e2f/internal/config/load.go#L1212-L1281) | 없음 | P2 |
| Qwen Code | 로컬 | `~/.qwen`(`QWEN_HOME`): `settings.json`, `projects/<cwd>/`(대화), `tmp/<sha256(cwd)>/{logs.json,checkpoint-*.json,shell_history}`, `usage/token-usage-YYYY-MM.jsonl` | [storage.ts](https://github.com/QwenLM/qwen-code/blob/835b080f8567d8612effa248e1fafa11af0e244b/packages/core/src/config/storage.ts#L166-L238), [troubleshooting](https://qwenlm.github.io/qwen-code-docs/en/users/support/troubleshooting/) | 없음 | P2 |
| Kimi CLI(MoonshotAI) | 로컬 | `~/.kimi/`(`KIMI_SHARE_DIR`): `config.toml`, `mcp.json`, `credentials/`(열지 않음), `sessions/<md5(workdir)>/<id>/{context.jsonl,wire.jsonl,state.json}`, `user-history/<md5>.jsonl`, `logs/kimi.log` | [data-locations.md](https://github.com/MoonshotAI/kimi-cli/blob/main/docs/en/configuration/data-locations.md) | 없음 | P2 |
| Amazon Q Developer CLI(`q`, 유지보수 종료·Kiro로 대체) | 로컬 | `%LOCALAPPDATA%\amazon-q\data.sqlite3`(테이블 `conversations`; mac `~/Library/Application Support/amazon-q/`), `~/.aws/amazonq/{cli-agents,prompts,mcp.json,.cli_bash_history,profiles}`, 로그 Windows `%TEMP%\amazon-q\logs` | [paths.rs](https://github.com/aws/amazon-q-developer-cli/blob/main/crates/chat-cli/src/util/paths.rs) | 없음 | P2 |
| Factory Droid | 로컬 | `~/.factory/`: `settings.json`, `mcp.json`, `sessions/<projectKey>/<sessionId>.jsonl`(2차), `logs/`. `cloudSessionSync` 기본 켜짐 → `app.factory.ai`에도 | [Droid settings](https://docs.factory.ai/cli/configuration/settings.md) | 없음 | P2 |
| Warp(AI·Agent) | 로컬 | `warp.sqlite`: Windows `%LOCALAPPDATA%\warp\Warp\data\`, mac `~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/`(테이블 `agent_conversations`, `ai_queries` (2차)); `~/.warp/.mcp.json` | [Warp file locations](https://docs.warp.dev/terminal/settings/file-locations/) | 없음 | P2 |
| Open Interpreter | 로컬 | 현재 Rust 판(Codex 기반) `~/.openinterpreter`(Codex와 같은 구조); Python 판 `<user_config_dir>/open-interpreter/conversations/*.json` | [local_storage_path.py v0.3.4](https://github.com/OpenInterpreter/open-interpreter/blob/v0.3.4/interpreter/terminal_interface/utils/local_storage_path.py) | 없음 | P3 |
| OpenHands CLI | 로컬 | `~/.openhands/`(`OPENHANDS_PERSISTENCE_DIR`): `conversations/<id>/`, `projects/<sha256>/prompt_history.json`, `agent_settings.json`, `mcp.json` | [locations.py](https://github.com/OpenHands/OpenHands-CLI/blob/main/openhands_cli/locations.py) | 없음 | P3 |
| SWE-agent | 로컬 | `trajectories/<user>/<experiment>/<instance>/<instance>.traj`(JSON) | [trajectories.md](https://github.com/SWE-agent/SWE-agent/blob/main/docs/usage/trajectories.md) | 없음 | P3 |
| Grok Build(xAI CLI) | [미확인] | 로컬 경로 확인 못 함 | [xai-org/grok-build](https://github.com/xai-org/grok-build) | 없음 | P3 |
| MCP 서버 설정 전반 | 로컬 | 각 에이전트 설정 안 `mcpServers`·`mcp.json`. 서버 이름·명령·환경 변수 이름만 의미 있음 | [VS Code MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers) | 있음(`agent-mcp`: Claude Code·Codex·Gemini CLI·Cursor·VS Code). Claude Desktop·Windsurf·Cline·omp는 없음 | P2 |

## F. 하네스·플러그인·메모리 묶음

정의: 에이전트 위에 얹어 스킬·훅·서브에이전트·메모리를 더하는 묶음. 에이전트 자체 기록과 별도로 자기 상태 파일을 남긴다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| OmO / oh-my-openagent(구 oh-my-opencode), npm `oh-my-opencode`·`omo-ai`, 엔진 senpi | 로컬 | 설정 `~/.omo/omo.jsonc`(구 `config.jsonc`), 프로젝트 `.omo/omo.jsonc`. 엔진 상태 `~/.omo/agent/`: `settings.json`, `auth.json`(열지 않음), `mcp.json`, `session-stores/*.json`, 세션 `sessions/<cwd>/*.jsonl`, `OmO-debug.log`. 메모리 `~/.omo/memory/agents/<id>/{repo,runtime/{transcripts,reflection,worktrees,...}}`, `runtime/state.json`, `receipts.jsonl`. 팀 `~/.omo/teams/<name>/config.json`, `~/.omo/runtime/<teamRunId>/`. 프로젝트 `.omo/goal/<session>.json`, `.omo/ulw-execute/ledger.jsonl`. OpenCode 판은 Claude 호환 기록을 `~/.claude/transcripts/<sessionId>.jsonl`에 씀(관찰된 이름 `ses_*.jsonl`), 런타임 로그 `oh-my-opencode.log`(임시 폴더). Codex 판 `~/.codex/plugins/data/omo-sisyphuslabs/`. `agent/state.json`, `agent/projects/`, `agent/omo-senpi/otlp`, `memory/transient-runs/`는 (로컬 관찰: 이름만) | [README](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/README.md), [agent-dir.js](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/packages/omo-native/bin/lib/agent-dir.js), [memory layout.ts](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/packages/memory-core/src/identity/layout.ts), [transcript.ts](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/packages/omo-opencode/src/hooks/claude-code-hooks/transcript.ts#L9-L12), [configuration.md](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/docs/reference/configuration.md#L49-L50) | 없음. `~/.claude/transcripts/`는 `claude-code` 수집 범위 밖 | P1 |
| OmO Desktop | 로컬 | `~/.omo/desktop/`(`OMO_DESKTOP_HOME`): `userdata/state.sqlite`(+`-wal`, 테이블 `orchestration_events`), `userdata/omo-sessions/<id>/*.jsonl`, `userdata/settings.json`, `userdata/attachments/`, `userdata/logs/`, `worktrees/`, `scratch/`(`worktrees`·`scratch`는 로컬 관찰: 이름만) | [AGENTS.md L249](https://github.com/code-yeongyu/oh-my-openagent/blob/dev/AGENTS.md#L249), [이슈 #11652](https://github.com/code-yeongyu/oh-my-openagent/issues/11652), [senpi PR #6941](https://github.com/code-yeongyu/senpi/pull/6941) | 없음 | P1 |
| senpi(pi 포크) | 로컬 | `~/.senpi/agent/settings.json`, `senpi-debug.log`, 세션 `<agentDir>/sessions/<cwd>/*.jsonl`. OmO가 쓰면 agentDir은 `~/.omo/agent`. `~/.senpi/agent/senpi-crash.log`는 (로컬 관찰: 이름만) | [senpi README](https://github.com/code-yeongyu/senpi/blob/main/README.md), [senpi 이슈 #2000](https://github.com/code-yeongyu/senpi/issues/2000) | 없음 | P1 (omo와 같은 수집기) |
| ECC(Everything Claude Code) | 로컬 | 플러그인 `~/.claude/plugins/`와 `settings.json`의 `enabledPlugins."ecc@ecc"`; 수동 설치 `~/.claude/{agents,skills,commands,rules/ecc}/`, `~/.claude/ecc/install-state.json`; 상태 DB `~/.claude/ecc/state.db`; 세션 요약 `~/.claude/session-data/YYYY-MM-DD-<id>-session.tmp`(30일); `~/.claude/metrics/costs.jsonl`; 학습 기록 `~/.local/share/ecc-homunculus/`(`observations.jsonl`에 프롬프트·도구 호출, 구 `~/.claude/homunculus/`); 메모리 `~/.ecc/memory/`, `<repo>/.ecc/memory/`. Codex·Cursor·OpenCode·Kimi·Qwen·Gemini·Copilot 대상 설치는 각 폴더에 `ecc-install-state.json` | [README](https://github.com/affaan-m/ECC/blob/main/README.md), [claude-home.js](https://github.com/affaan-m/ECC/blob/main/scripts/lib/install-targets/claude-home.js), [state-store](https://github.com/affaan-m/ECC/blob/main/scripts/lib/state-store/index.js), [continuous-learning-v2](https://github.com/affaan-m/ECC/blob/main/skills/continuous-learning-v2/SKILL.md), [memory-vault.js](https://github.com/affaan-m/ECC/blob/main/scripts/lib/memory-vault.js) | 없음(설정 파일 일부만 `claude-code`가 읽음) | P2 |
| claude-mem | 로컬 | `~/.claude-mem/claude-mem.db`(세션·관찰·요약), Chroma 색인, `settings.json`, `media-v1/`(스크린샷). Cloud Sync는 선택 | [README](https://github.com/thedotmack/claude-mem/blob/main/README.md) | 없음 | P2 |
| Superpowers 등 Claude 플러그인 | 로컬 | `~/.claude/plugins/`, `settings.json`의 `enabledPlugins` | [claude-directory](https://code.claude.com/docs/en/claude-directory.md) | 없음 | P3 |
| Happy(happy coder) | 부분 | `~/.happy/`(`HAPPY_HOME_DIR`): `settings.json`, `access.key`(열지 않음), `daemon.state.json`, `logs/`. 서버 `app.happy.engineering`. 대화 원본은 `~/.claude` | [configuration.ts](https://github.com/slopus/happy-cli/blob/main/src/configuration.ts) | 없음 | P3 |
| ccusage | 로컬(읽기 전용 도구) | 자체 저장 없음. `~/.claude/projects/`, Codex 로그를 읽음 | [directory-detection](https://ccusage.com/guide/directory-detection) | 해당 없음 | — |

## G. 오케스트레이터·멀티에이전트·허브

정의: 여러 에이전트 세션을 띄우고 일감·상태·보고를 관리하는 도구. 에이전트 대화는 각 에이전트 저장소에 남고, 오케스트레이터는 누가 언제 무엇을 시켰는지(레지스트리·이벤트·보고)를 남긴다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Cataly(vntrevx/Cataly, OMP를 Discord·Telegram·Slack에서 부리는 허브) | 로컬 | 설정 `~/.config/cataly/config.toml`(`$XDG_CONFIG_HOME`), 토큰 `~/.config/cataly/secrets/{discord-token,telegram-token,slack-tokens,service.env}`(열지 않음). 상태 `~/.local/state/cataly/`(`$XDG_STATE_HOME`): `cataly.db`(SQLite WAL; 세션·수신 영수증·배달·lane·보고·단계·증거·질문·승인·요청 기록·작업·이벤트를 한 파일에. 테이블 이름은 문서에 `jobs`만 있음), `logs/hub.log`, `logs/events.jsonl`, `files/`, `backup/cataly-v<N>.db`, `hub.lock`, `omp-overlay.yml`, lane마다 OMP JSONL 세션 폴더. 프로그램 `~/.local/share/cataly/versions/<v>/`, 명령 `~/.local/bin/cataly`, OMP 확장 링크 `~/.omp/agent/extensions/cataly.ts`. 서비스 macOS `~/Library/LaunchAgents/dev.cataly.hub.plist`(Label `dev.cataly.hub`), Linux systemd 사용자 유닛. 홈 백업을 비공개 GitHub 저장소 `<gh 로그인>/cataly-home`으로 밀 수 있음. `sessions/lead/`, `sessions/lanes/`, `files/streams/`, `omp-overlay-lane.yml`, 다른 이름의 상태 폴더(`~/.local/state/<이름>/cataly/`)는 (로컬 관찰: 이름만). **Windows 미지원** | [docs/config.md](https://github.com/vntrevx/Cataly/blob/main/docs/config.md#L12-L16), [DESIGN.md §11.2](https://github.com/vntrevx/Cataly/blob/main/DESIGN.md), [README](https://github.com/vntrevx/Cataly/blob/main/README.md) | 없음 | P1 (다음 PR 2순위) |
| dori(sisyphuslabs/dori-superagent, 메신저 상주 에이전트 하네스) | 로컬 | `~/.dori`(`DORI_HOME`): `config.json`, `lanes/`, `inbox/`, `briefs/<key>.md`, `receipts/`, `backlog/`, `loop/`, `duty/`, `telemetry.json`. dori-mode 스킬 상태 `~/.dori/state`(`stateDir`): `lanes/<key>.json`(레지스트리), `lanes/<key>/{reports.jsonl,checkpoints.jsonl}`, `worklog.jsonl`·`worklog.md`, `slack-threads.json`, `telegram-offset`. 토큰은 환경 변수 `DORI_TELEGRAM_TOKEN`·`DORI_DISCORD_TOKEN`·`DORI_SLACK_TOKEN`. 사용 통계를 `t.omo.dev`로 보냄(`DORI_TELEMETRY=0`으로 끔). 운영 사본에서는 `lane-out/<lane>/`(조사 산출물), `inbox/media/*.jpg`(메신저 첨부), `collect/`, `disabled-launchd/*.plist`, `~/Library/LaunchAgents/com.<user>.dori-*.plist`(로컬 관찰: 이름만) | [README](https://github.com/sisyphuslabs/dori-superagent/blob/main/README.md), [dori-mode scripts.md](https://github.com/sisyphuslabs/dori-superagent/blob/main/skills/dori-mode/references/scripts.md), [sessions.md](https://github.com/sisyphuslabs/dori-superagent/blob/main/skills/dori-mode/references/sessions.md) | 없음 | P1 (다음 PR 3순위) |
| herdr(herdrdev/herdr, 에이전트용 터미널 멀티플렉서) | 부분 | 설정 폴더 `~/.config/herdr`(Windows `%APPDATA%\herdr`): `config.toml`, `session.json`(작업공간·탭·창·cwd와 에이전트 세션 ID 참조), `session-snapshots/`(최대 48개), `session-backups/`, `session-history.json`(`pane_history`를 켰을 때만, 화면 출력 포함), `plugins.json`, 로그 `herdr.log`·`herdr-client.log`·`herdr-server.log`, 소켓 `herdr.sock`(Windows named pipe). 상태 폴더 `~/.local/state/herdr`(Windows `%LOCALAPPDATA%\herdr`): `agent-detection/status.toml`, `agent-detection/remote/<agent>.toml`, `plugins/<id>/`. worktree `~/.herdr/worktrees/<repo>/<branch>`. 대화 내용은 각 에이전트 저장소 | [config/io.rs](https://github.com/herdrdev/herdr/blob/master/src/config/io.rs#L30-L92), [session.rs](https://github.com/herdrdev/herdr/blob/master/src/session.rs#L164-L187), [session-state 문서](https://herdr.dev/docs/session-state/), [configuration 문서](https://herdr.dev/docs/configuration/) | 없음 | P1 (다음 PR 5순위) |
| Orca / Orca Bots(stablyai/orca, 봇이 들어간 오픈소스 에이전트 IDE) | 로컬 | 앱 데이터 Electron `userData`(표준 프로필 `<appData>/orca`: Windows `%APPDATA%\orca`, mac `~/Library/Application Support/orca` [추론]): `orca-data.json`, `orca-github-cache.json`, `bot-work.sqlite`, `bot-items.sqlite`, `bot-look-around.json`, `bot-memory-history/<bot>.json`, `bot-access-requests-seen.json`. 봇 홈 `~/.orca/bots/<봇>/{SOUL.md,MEMORY.md,memory/,AGENTS.md,CLAUDE.md,bot.json}`. 봇이 시키는 worker(Claude Code·Codex)는 새 git worktree에서 돌고 대화는 각 에이전트 저장소에. Slack·GitHub·Linear 요청은 Orca Cloud 중계를 거치며 일부 텍스트가 클라우드에 최대 7일 남음 | 소스(HEAD `c46704e1`): [bot-home.ts](https://github.com/stablyai/orca/blob/c46704e1/src/main/bots/bot-home.ts), [user-data-path.ts](https://github.com/stablyai/orca/blob/c46704e1/src/main/persistence/loading-store/user-data-path.ts), [bot-work-store.ts](https://github.com/stablyai/orca/blob/c46704e1/src/main/bots/bot-work-store.ts), [bot-items-input.ts](https://github.com/stablyai/orca/blob/c46704e1/src/main/bots/bot-items-input.ts), [bot-memory-history.ts](https://github.com/stablyai/orca/blob/c46704e1/src/main/bots/bot-memory-history.ts); [orca.dev/docs/bots](https://orca.dev/docs/bots), [Security](https://orca.dev/docs/bots/security) | 없음 | P1 (다음 PR 6순위) |
| OrcaBot(orcabot.com, 다른 제품) | 클라우드 전용 | 브라우저에서 쓰는 웹 플랫폼. 샌드박스 Linux VM에서 Claude Code·Codex·Gemini CLI를 돌리고 Telegram 블록이 있음. PC에는 `orcabot.com` 방문 기록 정도 | [orcabot.com](https://orcabot.com/), [Telegram 문서](https://orcabot.com/docs/telegram) | 없음 | P3 |
| Claude Squad | 로컬 | `~/.claude-squad/config.json`, `state.json`(인스턴스 제목·경로·브랜치·worktree·diff). 대화는 `~/.claude` | [config.go](https://github.com/smtg-ai/claude-squad/blob/main/config/config.go), [state.go](https://github.com/smtg-ai/claude-squad/blob/main/config/state.go) | 없음 | P2 |
| Conductor(Melty Labs) | 로컬 | `~/Library/Application Support/com.conductor.app/`, `~/conductor/`(workspaces). macOS 전용 | [Conductor FAQ](https://www.conductor.build/docs/faq) | 없음 | P3 |
| Vibe Kanban(BloopAI) | 로컬 | `ProjectDirs("ai","bloop","vibe-kanban")` 데이터 폴더의 `db.v2.sqlite`, `config.json`, `profiles.json`, `credentials.json`(열지 않음). Windows `%APPDATA%\bloop\vibe-kanban\data` [추론] | [assets.rs](https://github.com/BloopAI/vibe-kanban/blob/main/crates/utils/src/assets.rs) | 없음 | P2 |
| ccmanager | 로컬 | `~/.config/ccmanager/{config.json,sessions.json}`(Windows `%APPDATA%\ccmanager\`), 저장소별 `.ccmanager.json` | [README](https://github.com/kbwo/ccmanager/blob/main/README.md) | 없음 | P3 |
| Opcode(구 Claudia) | 로컬 | Tauri app_data_dir `opcode.asterisk.so/agents.db` | [agents.rs](https://github.com/winfunc/opcode/blob/main/src-tauri/src/commands/agents.rs) | 없음 | P3 |
| Crystal(지원 종료) | 로컬 | `~/.crystal/sessions.db` | [crystalDirectory.ts](https://github.com/stravu/crystal/blob/main/main/src/utils/crystalDirectory.ts) | 없음 | P3 |
| CrewAI | 로컬 | `appdirs.user_data_dir(<프로젝트>, "CrewAI")`(Windows `%LOCALAPPDATA%\CrewAI\<project>\`): `latest_kickoff_task_outputs.db` 등 | [paths.py](https://github.com/crewAIInc/crewAI/blob/main/lib/crewai-core/src/crewai_core/paths.py) | 없음 | P3 |
| AutoGen Studio | 로컬 | `~/.autogenstudio/`: SQLite DB, `files/user/`, `.env` | [initialization.py](https://github.com/microsoft/autogen/blob/main/python/packages/autogen-studio/autogenstudio/web/initialization.py) | 없음 | P3 |
| LangGraph dev 서버 | 로컬 | 작업 폴더 `.langgraph_api/`(스레드·체크포인트) | [Data storage](https://docs.langchain.com/langgraph-platform/data-storage-and-privacy) | 없음 | P3 |
| Letta | 로컬 | `~/.letta/lc-local-backend/`, `memfs/<agent-id>/memory` | [Self-hosting](https://docs.letta.com/self-hosting) | 없음 | P3 |
| MetaGPT, AutoGPT(셀프 호스트) | 로컬 | MetaGPT `~/.metagpt/`, `workspace/`; AutoGPT Postgres·Docker 볼륨 | [const.py](https://github.com/FoundationAgents/MetaGPT/blob/main/metagpt/const.py), [docker-compose](https://github.com/Significant-Gravitas/AutoGPT/blob/master/autogpt_platform/docker-compose.platform.yml) | 없음 | P3 |
| Claude Code UI, Sculptor, Maestro, Omnara, Terragon(종료) | 부분·[미확인] | Claude Code UI는 `~/.claude`를 읽고 `auth.db`(위치 [미확인]); Sculptor `SCULPTOR_FOLDER`; Maestro·Omnara 경로 [미확인] | [claudecodeui README](https://github.com/siteboon/claudecodeui/blob/main/README.md), [Sculptor](https://github.com/imbue-ai/sculptor/blob/main/openhost.toml), [Omnara](https://github.com/omnara-ai/omnara) | 없음 | P3 |

## H. 메신저 봇형 개인 에이전트

정의: 메신저·전화·전용 앱으로 일을 맡기는 개인 에이전트. 서비스형은 작업이 회사 클라우드 VM에서 돌고, 직접 운영형은 사용자 PC·서버에 봇 프로세스·토큰·세션이 있다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Grok Bot(xAI) | 부분 | 데스크톱 앱(macOS·Windows·Linux)과 iOS·Android 앱, Cursor 계정 로그인. 봇 작업은 계정당 하나인 클라우드 컴퓨터에서 돌고 대화는 동기화. X Chat·Slack에서도 대화. 허락하면 내 PC에서 명령 실행. 사용량 `grok.com/dashboard`, 온보딩 `cursor.com/bot/onboarding` | [Grok Bot FAQ](https://docs.x.ai/grok-bot/faq), [x.ai/bot](https://x.ai/bot) | 부분(`grok.com` 방문만) | P2 |
| @GrokAI 텔레그램 봇 | 클라우드 전용 | Telegram 서버의 봇 대화. Telegram Desktop 로컬 캐시(`tdata`, 암호화)에 남는지 [미확인] | (2차) [TechCrunch](https://techcrunch.com/2025/05/28/xai-to-invest-300m-in-telegram-integrate-grok-into-app) | 메신저 일반 수집만 | P3 |
| 피클(Pickle, Pickle Inc.) | 클라우드 전용 | 휴대폰 앱(Android `com.pickle.client`, iOS)만 있고 웹 버전은 없음. 클라우드 브라우저로 연결 계정을 써서 사이트를 조작하고 전화도 대신 검. Gmail·Google Calendar·쇼핑몰 계정을 연결. Windows 이미지에서 볼 수 있는 것: 연결 계정 메일함의 주문·예약 확인 메일, `pickle.com` 방문, Stripe Link 결제 메일 [미확인]. 휴대폰 쪽은 yh-mobile-trace 담당 | [Google Play 등록 정보](https://play.google.com/store/apps/details?id=com.pickle.client), [App Store](https://apps.apple.com/us/app/pickle-your-personal-ai-agent/id6795790129), [pickle.com](https://pickle.com) | 없음(`pickle.com` 도메인 미등록: 일반 단어라 경로 단위 확인 후 추가) | P2 |
| OpenAI Dots | 클라우드 전용 | 클라우드 컴퓨터에서 실행, Slack·Teams 메시지와 `chatgpt.com` | (2차) [Fortune](https://fortune.com/2026/09/29/openai-takes-on-metas-muse-with-new-dot-agents-and-unveils-a-potential-google-workspace-competitor/) | 부분(ChatGPT 방문으로만) | P3 |
| Meta Muse | 클라우드 전용 | Muse Secure VM(클라우드), 웹·모바일 | [Meta 발표](https://about.fb.com/news/2026/09/introducing-muse-personal-ai-agent/) | 없음 | P3 |
| Claude Duet | 클라우드 전용 | Anthropic 클라우드 VM, 웹·iOS, 알림 | [Claude Duet](https://claude.com/resources/articles/claude-duet) | 부분(`claude.ai` 방문만) | P3 |
| Manus Cue(큐) | 클라우드 전용 | 에이전트마다 이메일·전화번호·클라우드 컴퓨터. 로컬 앱 흔적 [미확인] | (2차) [AI타임스](https://www.aitimes.com/news/articleView.html?idxno=215767) | 부분(`manus.im`) | P3 |
| Hermes Agent(NousResearch) | 로컬 | `~/.hermes`(Windows `%LOCALAPPDATA%\hermes`, `HERMES_HOME`): `state.db`(세션·메시지), `sessions/`, `config.yaml`, `.env`(열지 않음), `SOUL.md`, `memories/{MEMORY.md,USER.md}`, `skills/`, `cron/jobs.json`, `logs/{agent,errors,gateway}.log`. Telegram·Discord 게이트웨이 | [hermes_constants.py](https://github.com/NousResearch/hermes-agent/blob/6bb377a51d5c8e279a7a5e34d717d653d421d064/hermes_constants.py#L194-L201), [Configuration](https://hermes-agent.nousresearch.com/docs/user-guide/configuration) | 없음 | P1 |
| OpenClaw | 로컬 | `~/.openclaw`(`OPENCLAW_STATE_DIR`): `openclaw.json`, `state/openclaw.sqlite`, `agents/<agentId>/agent/openclaw-agent.sqlite`(세션·대화), `agents/<agentId>/sessions/{sessions.json,<id>.jsonl}`(이전 형식), `workspace/{AGENTS.md,SOUL.md,MEMORY.md,memory/}`, `credentials/`(열지 않음) | [state-dir.ts](https://github.com/openclaw/openclaw/blob/fc3490aa24e624f0182ae5e29482611fee5736fb/src/config/state-dir.ts#L23-L54), [Session 문서](https://docs.openclaw.ai/concepts/session) | 없음 | P1 |
| 직접 운영 ChatGPT·Claude 텔레그램 봇 | 로컬(서버 호스트) | 예: father-bot `chatgpt_telegram_bot`의 MongoDB(`./mongodb`), claude-code-telegram `data/bot.db`. 상주 실행은 macOS `~/Library/LaunchAgents/*.plist`, Linux `~/.config/systemd/user/*`, 토큰은 환경 변수·`.env` | [father-bot docker-compose](https://github.com/father-bot/chatgpt_telegram_bot/blob/main/docker-compose.yml), [claude-code-telegram .env.example](https://github.com/RichardAtCT/claude-code-telegram/blob/main/.env.example), [launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html), [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) | 부분(macOS LaunchAgents·Linux systemd 범용 수집) | P2 |
| dori, Cataly | G 분류 행 | 메신저 상주 운영. 토큰 파일·서비스 유닛·세션 | — | 없음 | — |

## I. 클라우드 자율 에이전트

정의: 회사 서버의 VM에서 사용자를 대신해 일하는 에이전트. 디스크에는 방문 기록, 알림 메일, GitHub PR·브랜치 같은 결과물만 남는다. 모두 `클라우드 전용`이다.

| 제품 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|
| Manus | `manus.im`, `help.manus.im` | [Manus 도움말](https://help.manus.im/en/articles/14089011-how-to-download-the-manus-desktop-app) | 있음(이번 PR) | P2 |
| Devin | `app.devin.ai`. Devin CLI·Desktop 로컬 경로 [미확인] | [Devin 소개](https://docs.devin.ai/get-started/devin-intro) | 없음 | P2 |
| Google Jules | `jules.google.com`, GitHub PR | (2차) [TechCrunch](https://techcrunch.com/2025/10/02/googles-jules-enters-developers-toolchains-as-ai-coding-agent-competition-heats-up) | 없음 | P2 |
| Codex cloud | `chatgpt.com/codex`, GitHub PR | [Codex cloud](https://developers.openai.com/codex/cloud) | 부분 | P3 |
| Genspark Super Agent | `genspark.ai` | [Super Agent](https://www.genspark.ai/helpcenter/super-agent) | 있음(이번 PR) | P3 |
| Lindy, Relevance AI, Copilot Studio | A 분류 노코드·Copilot Studio 행 | — | 없음 | P3 |

## J. 로컬 LLM 런타임·UI

정의: 사용자 PC에서 모델을 내려받아 돌리는 런타임과 채팅 UI. 모델 파일·로그·대화 DB가 로컬이다.

Rapid 공통: 경로에 제품 이름이 들어 있는 설정·로그·DB(`.json`, `.jsonl`, `.yaml`, `.toml`, `.log`, `.txt`, `.sqlite`, `.db`)와 GGUF·safetensors 모델을 `local-llm-artifact`로 인벤토리하고, 텍스트·SQLite에서 프롬프트 후보를 `local-llm-prompt-candidate`로 낸다(`rapidtriage/artifacts/generic.py`의 `LOCAL_LLM_PATH_TERMS`, `infer_local_llm_product`). 이번 PR에서 Jan·AnythingLLM·Msty·AI:GO·LocalAI·Open WebUI·text-generation-webui·KoboldCpp 경로 용어와 `.jsonl` 읽기를 더했다. `.jsonl`은 줄마다 `role`·`content`를 읽어 `user: …`/`assistant: …` 후보로 낸다(`local_llm_jsonl_prompt_fragments`).

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| Ollama(서버·CLI) | 로컬 | Windows `%LOCALAPPDATA%\Ollama\server.log`·`server-#.log`, 프로그램 `%LOCALAPPDATA%\Programs\Ollama`, 모델 `~/.ollama/models/{manifests,blobs}`, CLI 프롬프트 기록 `~/.ollama/history`(평문 한 줄씩), mac 로그 `~/.ollama/logs/server.log`. macOS Homebrew 서비스 `homebrew.mxcl.ollama.plist`(로컬 관찰: 이름만) | [troubleshooting](https://docs.ollama.com/troubleshooting), [FAQ](https://docs.ollama.com/faq.md), [history.go](https://github.com/ollama/ollama/blob/main/readline/history.go) | 있음(경로 용어 `ollama`). `history`는 확장자가 없어 읽지 않음 | P1 |
| Ollama 데스크톱 앱 | 로컬 | `%LOCALAPPDATA%\Ollama\db.sqlite`(+`-wal`), mac `~/Library/Application Support/Ollama/db.sqlite`. 테이블 `chats`, `messages`(role, content, thinking, model_name), `tool_calls`. WAL에 삭제한 대화가 남을 수 있음 | [schema.sql](https://github.com/ollama/ollama/blob/main/app/store/schema.sql), [app_state.go](https://github.com/ollama/ollama/blob/main/internal/onboarding/app_state.go), [이슈 #12452](https://github.com/ollama/ollama/issues/12452) | 부분(범용 SQLite 프롬프트 후보) | P1 |
| LM Studio | 로컬 | `~/.lmstudio/conversations/*.json`, `~/.lmstudio/models/`, `config-presets/`, CLI `~/.lmstudio/bin/lms` | [Chat 문서](https://lmstudio.ai/docs/app/basics/chat), [import-model](https://lmstudio.ai/docs/app/advanced/import-model) | 있음(경로 용어) | P1 |
| GPT4All | 로컬 | `%LOCALAPPDATA%\nomic.ai\GPT4All\gpt4all-<chatId>.chat`(바이너리 직렬화), mac `~/Library/Application Support/nomic.ai/GPT4All/` | [settings](https://docs.gpt4all.io/gpt4all_desktop/settings.html), [chatlistmodel.cpp](https://github.com/nomic-ai/gpt4all/blob/main/gpt4all-chat/src/chatlistmodel.cpp) | 부분(경로 용어, `.chat` 미파싱) | P2 |
| Jan | 로컬 | `%APPDATA%\Jan\data`(mac `~/Library/Application Support/Jan/data`, Linux `~/.local/share/Jan/data`): `threads/<id>/messages.jsonl`(줄마다 `ThreadMessage`: `role`, `content[].text.value`), `thread.json`, `logs/app.log`; Jan Agent `~/.jan/projects/<slug>/threads` | [Data folder](https://docs.jan.ai/llms.mdx/desktop/data-folder/content.md), [Agent sessions](https://docs.jan.ai/agent/sessions), [messageEntity.ts](https://github.com/janhq/jan/blob/main/core/src/types/message/messageEntity.ts) | 있음(이번 PR): 위 세 데이터 폴더와 `~/.jan`만 Jan으로 본다(사용자 이름이 Jan인 `C:\Users\Jan\data` 같은 폴더는 제외). `messages.jsonl`의 user·assistant 메시지를 프롬프트 후보로 냄 | P2 |
| AnythingLLM Desktop | 로컬 | `%APPDATA%\anythingllm-desktop\storage\anythingllm.db`, `documents/`, `lancedb/`, `logs/` | [Storage](https://docs.anythingllm.com/installation-desktop/storage) | 있음(이번 PR) | P2 |
| Msty(1.x) | 로컬 | `%APPDATA%\Msty`(mac `~/Library/Application Support/Msty`). 대화 DB 이름 [미확인]. Msty Studio 2.x 이상 경로는 (2차)라 넣지 않음 | [Msty 문서](https://docs.msty.app/how-to-guides/get-the-latest-version-of-local-ai-service) | 있음(이번 PR, `Msty` 폴더) | P3 |
| AI:GO(Lablup Backend.AI GO) | 로컬 | `%APPDATA%\ai.backend.go\`(mac `~/Library/Application Support/ai.backend.go/`, Linux `~/.local/share/ai.backend.go/`): `logs/`, `engines/`, 대화 JSON 파일. 구 `~/.backend-ai-go/`. 앱을 지워도 대화가 남음(FAQ) | [Logs](https://go.backend.ai/en/manual/core-features/logs/), [FAQ](https://go.backend.ai/en/manual/reference/faq) | 있음(이번 PR) | P2 |
| LocalAI | 로컬 | Windows `%LOCALAPPDATA%\LocalAI`(`LOCALAI_BASE_PATH`): `models/`, `data/`(채팅 파일), `backends/` | [CLI reference](https://localai.io/docs/reference/cli-reference) | 있음(이번 PR, Windows 기본 폴더) | P3 |
| Open WebUI | 로컬 | `${DATA_DIR}/webui.db`(테이블 `chat`), Docker `/app/backend/data/webui.db`, pip 설치 `site-packages/open_webui/data/` | [env-configuration](https://docs.openwebui.com/reference/env-configuration.md), [chats.py](https://github.com/open-webui/open-webui/blob/main/backend/open_webui/models/chats.py) | 있음(이번 PR, pip 경로). Docker 볼륨 경로는 없음 | P2 |
| text-generation-webui | 로컬 | `<설치>/user_data/logs/{instruct,chat/<character>}/<id>.json` | [chat.py](https://github.com/oobabooga/text-generation-webui/blob/main/modules/chat.py) | 있음(이번 PR) | P3 |
| KoboldCpp | 부분 | `--savedatafile`을 쓰면 `<name>.jsondb`, 아니면 브라우저 저장소 | [saves](https://koboldcpp.net/docs/features/multiplayer-and-saves/) | 있음(이번 PR, 경로에 `koboldcpp`가 있을 때) | P3 |
| llama.cpp | 부분 | 모델 캐시 `LLAMA_CACHE` → HF 캐시 순. 대화 기록 파일 없음 | [hf-cache.cpp](https://github.com/ggml-org/llama.cpp/blob/master/common/hf-cache.cpp) | 부분(GGUF 모델 인벤토리) | P3 |
| vLLM | 부분 | `~/.cache/vllm`, `~/.config/vllm`. 대화 저장 없음 | [envs.py](https://github.com/vllm-project/vllm/blob/main/vllm/envs.py) | 없음 | P3 |
| Hugging Face Hub 캐시 | 부분 | `~/.cache/huggingface/hub/models--*`, 토큰 파일 `$HF_HOME/token`(열지 않음) | [환경 변수](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables) | 부분(safetensors 모델 인벤토리) | P3 |

## K. API·SDK·자동화·프록시

정의: 사람이 채팅 화면 없이 API로 모델을 쓰는 흔적. 키 값 자체는 수집하지 않고 **어느 키 이름이 어디에 있는지**만 본다.

| 대상 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| API 키 환경 변수 이름 | 부분 | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`·`GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `XAI_API_KEY`, `HF_TOKEN`. 위치: `.env`, 셸 프로필, Windows `HKCU\Environment`(`setx`) [추론], launchd·systemd 유닛의 환경 변수 | [OpenAI](https://platform.openai.com/docs/quickstart), [Anthropic](https://platform.claude.com/docs/en/get-api-key), [Gemini](https://ai.google.dev/gemini-api/docs/api-key), [Mistral](https://docs.mistral.ai/getting-started/quickstarts/studio/activate-and-generate-api-key), [DeepSeek](https://api-docs.deepseek.com/), [Groq](https://console.groq.com/docs/quickstart), [OpenRouter](https://openrouter.ai/docs/api_reference/authentication), [xAI](https://docs.x.ai/docs/tutorial), [Hugging Face](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables) | 없음. 에이전트 수집기의 가림 규칙은 이 키 모양을 가림(`rapidtriage/artifacts/ai_agent_records.py`) | P2 |
| 키 접두사(가림·탐지용) | — | 공식 확인: Anthropic `sk-ant-`, Google `AIza`, Hugging Face `hf_`, Groq `gsk_`, OpenRouter `sk-or-v1-`. OpenAI `sk-proj-`, xAI `xai-`, DeepSeek `sk-`는 [미확인] | [Anthropic](https://platform.claude.com/docs/en/get-api-key), [Google API keys](https://docs.cloud.google.com/docs/authentication/api-keys), [HF tokens](https://huggingface.co/docs/hub/security-tokens), [Groq](https://console.groq.com/docs/production-readiness/security-onboarding), [OpenRouter](https://openrouter.ai/docs/api_reference/authentication) | 부분(가림 규칙에 `sk-`, `hf_` 등) | — |
| tiktoken 캐시 | 부분 | `TIKTOKEN_CACHE_DIR` → `DATA_GYM_CACHE_DIR` → `%TEMP%\data-gym-cache`(파일 이름은 원본 URL의 SHA1) | [load.py](https://github.com/openai/tiktoken/blob/main/tiktoken/load.py) | 없음 | P3 |
| LangChain SQLiteCache | 로컬 | 작업 폴더 `.langchain.db`(켰을 때만, 프롬프트·응답 저장) | [cache.py](https://github.com/langchain-ai/langchain-community/blob/main/libs/community/langchain_community/cache.py) | 없음 | P3 |
| claude-code-router(CCR) | 로컬 | `~/.claude-code-router/`(Windows `%APPDATA%\claude-code-router`): `config.sqlite`, `app-data/`(API 키·사용량·요청 로그), `service.json`(열지 않음), 포트 `127.0.0.1:3456` | [CCR CLI 문서](https://ccrdesk.top/en/guides/cli/), [README](https://github.com/musistudio/claude-code-router) | 없음 | P2 |
| CLIProxyAPI | 부분 | OAuth 토큰 폴더 `~/.cli-proxy-api`(열지 않음), `kv.db`, 요청 로그(설정 시) | [config.example.yaml](https://github.com/router-for-me/CLIProxyAPI/blob/main/config.example.yaml) | 없음 | P3 |
| LiteLLM 프록시, Meridian | [미확인] | 기본 경로 없음(사용자가 정함) | [Meridian](https://github.com/rynfar/meridian) | 없음 | P3 |
| n8n(셀프 호스트) | 로컬 | `~/.n8n/`(`N8N_USER_FOLDER`): `config`(암호화 키, 열지 않음), `database.sqlite`(워크플로·실행 기록·암호화된 자격 증명; 테이블 `execution_entity`·`workflow_entity`는 [추론]). Docker 볼륨 `n8n_data` | [Backup and restore](https://docs.n8n.io/deploy/host-n8n/keep-n8n-running/backup-and-restore), [database.config.ts](https://github.com/n8n-io/n8n/blob/master/packages/@n8n/config/src/configs/database.config.ts) | 없음 | P2 |
| Flowise | 로컬 | `~/.flowise`(SQLite, `DATABASE_PATH`), `~/.flowise/storage` | [환경 변수](https://docs.flowiseai.com/configuration/environment-variables) | 없음 | P3 |
| Langflow | 로컬 | Desktop Windows `%APPDATA%\com.LangflowDesktop\data\database.db`, mac `~/.langflow/data/database.db`; OSS `langflow.db` | [memory.mdx](https://github.com/langflow-ai/langflow/blob/main/docs/docs/Develop/memory.mdx) | 없음 | P3 |
| Dify(Docker) | 로컬(서버) | `docker/volumes/app/storage`, `volumes/db/data`(Postgres) | [docker-compose.yaml](https://github.com/langgenius/dify/blob/main/docker/docker-compose.yaml) | 없음 | P3 |
| Make·Zapier | 클라우드 전용 | A 분류 노코드 행 | — | 없음 | P3 |

## L. 이미지·음성·영상 생성

정의: 로컬에서 돌리는 생성 도구와 생성물 메타데이터. 로컬 도구는 프롬프트를 출력 파일 안이나 옆에 남긴다.

| 제품 | 분류 | 흔적 | 근거 | Rapid 현재 | 우선순위 |
|---|---|---|---|---|---|
| AUTOMATIC1111 SD WebUI, Forge | 로컬 | `outputs/txt2img-images/...`, PNG 텍스트 청크 `parameters`(프롬프트·시드·모델), `params.txt`(마지막 생성), Save 시 `log/images/log.csv` | [images.py](https://github.com/AUTOMATIC1111/stable-diffusion-webui/blob/master/modules/images.py), [shared_options.py](https://github.com/AUTOMATIC1111/stable-diffusion-webui/blob/master/modules/shared_options.py), [Forge shared_options.py](https://github.com/lllyasviel/stable-diffusion-webui-forge/blob/main/modules/shared_options.py) | 부분: 미디어 메타데이터 문자열 힌트(`rapidtriage/artifacts/media.py`의 `MEDIA_AUTHENTICITY_TEXT_HINTS`). 청크 파서 없음 | P2 |
| ComfyUI | 로컬 | `output/ComfyUI_#####_.png`, PNG tEXt `prompt`(API 그래프)·`workflow`(UI 그래프), `user/default/` 워크플로, 데스크톱 앱 `%APPDATA%\ComfyUI\user` | [workflow metadata](https://docs.comfy.org/development/api-development/workflow-metadata), [nodes.py](https://github.com/comfyanonymous/ComfyUI/blob/master/nodes.py) | 부분(문자열 힌트 `comfyui`) | P2 |
| Fooocus | 로컬 | `outputs/<YYYY-MM-DD>/log.html`(이미지별 생성 파라미터) | [private_logger.py](https://github.com/lllyasviel/Fooocus/blob/main/modules/private_logger.py) | 없음 | P3 |
| InvokeAI | 로컬 | 루트(`INVOKEAI_ROOT`, 기본 `~/invokeai`): `databases/invokeai.db`, `outputs/images/`, `invokeai.yaml` | [invokeai.yaml](https://invoke.ai/configuration/invokeai-yaml/) | 없음 | P3 |
| OpenAI 이미지(ChatGPT·API), Adobe Firefly | 로컬(파일) | C2PA Content Credentials(+OpenAI는 SynthID). 메타데이터에 사용자·프롬프트는 없음(공식) | [OpenAI provenance](https://help.openai.com/en/articles/8912793-provenance-signals-in-openai-generated-content), [Firefly Content Credentials](https://helpx.adobe.com/firefly/get-set-up/learn-the-basics/content-credentials-overview.html) | 부분(문자열 힌트 `dall-e`). C2PA 파서 없음 | P2 |
| Midjourney 다운로드 | 로컬(파일) | 다운로드 파일 이름 패턴 [미확인]. 웹 생성 기록은 서버 | [Creating on Web](https://docs.midjourney.com/hc/en-us/articles/33390732264589-Creating-on-Web) | 부분(문자열 힌트 `midjourney`) | P3 |
| Whisper(로컬) | 부분 | 모델 캐시 `~/.cache/whisper` | [whisper/__init__.py](https://github.com/openai/whisper/blob/main/whisper/__init__.py) | 없음 | P3 |
| Codex 생성 이미지 | 로컬 | `~/.codex/generated_images/<id>/ig_*.png`(로컬 관찰: 이름만) | — | 없음 | P3 |

## M. 모바일 앱

정의: 휴대폰 AI 앱. Windows 디스크 이미지에는 휴대폰 백업(iTunes·Finder 백업), 동기화 계정의 메일·알림 정도만 남는다. 휴대폰 추출본 분석은 yh-mobile-trace 담당이다.

| 제품 | 흔적(Windows에서 보이는 것) | 근거 | Rapid 현재 |
|---|---|---|---|
| 피클(Pickle) | 앱 전용(웹 없음). PC에는 연결 계정 메일·캘린더의 결과물 | [Google Play](https://play.google.com/store/apps/details?id=com.pickle.client) | 없음 |
| Grok Bot·ChatGPT·Claude·Gemini·Copilot·Perplexity 모바일 앱 | 서버 동기화. PC에는 같은 계정의 웹·데스크톱 흔적 | 각 공식 앱 페이지 | 모바일 내보내기의 AI 앱 표시(`rapidtriage/artifacts/mobile/helpers.py`) |
| 카카오톡 안 ChatGPT·Kanana, 에이닷 통화 요약 | 서버. PC 카카오톡에 남는지 [미확인] | [카카오 발표](https://www.kakaocorp.com/page/detail/11794?lang=ENG) | 없음 |

## '큐' 후보 정리

주인이 말한 "큐"는 아래 중 하나로 보인다. 근거로 확인한 것과 못 한 것을 나눴다.

| 후보 | 확인 | 흔적 위치 |
|---|---|---|
| Amazon Q Developer CLI(`q`)·IDE | 소스·공식 문서로 확인 | E·D 분류 Amazon Q 행 |
| Qwen Code CLI | 소스로 확인 | E 분류 Qwen Code 행 |
| Kiro(Amazon Q CLI 후속) | 공식 문서로 확인 | D 분류 Kiro 행 |
| Manus Cue(큐), 2026-09 출시 개인 에이전트 | 언론으로 확인(2차) | H 분류 Manus Cue 행 |
| 네이버 Cue:(큐:) | 2026-04-09 종료, 언론으로 확인(2차) | A 분류 네이버 Cue: 행 |
| LG 씽큐 클로 | 출시 예정 보도(2차), 흔적 [미확인] | — |

## 커뮤니티에서 두 번 이상 언급된 세팅

2026-11 기준 커뮤니티 글에서 두 번 이상 나온 세팅이다. 출처 대부분은 Hacker News "Ask HN: What's your current AI agentic setup?"(2026-11-04) 스레드와 GeekNews, Clien, DC인사이드 특이점갤(Clien·DC는 검색 요약 경유라 (2차))이다. Reddit은 로그인 요구로 읽지 못했고 Threads·X는 조사하지 않았다. 흔적은 위 분류 표에 있다.

| 세팅 | 분류 | 언급된 곳 |
|---|---|---|
| Claude Code | E | [Clien](https://www.clien.net/service/board/cm_app/19207203), [Clien](https://www.clien.net/service/board/park/19187039), [HN](https://news.ycombinator.com/item?id=50428201) |
| Codex CLI·앱 | E | [HN](https://news.ycombinator.com/item?id=50444232), [Clien](https://www.clien.net/service/board/cm_app/19207203), [HN](https://news.ycombinator.com/item?id=50399014) |
| OpenCode(+oh-my-opencode) | E·F | [HN](https://news.ycombinator.com/item?id=50444232), [HN](https://news.ycombinator.com/item?id=50385812), [HN](https://news.ycombinator.com/item?id=50380609) |
| pi | E | [HN](https://news.ycombinator.com/item?id=50428201), [HN](https://news.ycombinator.com/item?id=50445173), [GeekNews](https://news.hada.io/topic?id=36795) |
| Hermes Agent | H | [HN](https://news.ycombinator.com/item?id=50385812), [HN](https://news.ycombinator.com/item?id=50377697), [DC](https://gall.dcinside.com/mgallery/board/view/?id=thesingularity&no=1092848) |
| OpenClaw | H | [HN](https://news.ycombinator.com/item?id=50457219), [HN](https://news.ycombinator.com/item?id=50428201), [Clien](https://www.clien.net/service/board/park/19144622) |
| Ollama | J | [HN](https://news.ycombinator.com/item?id=50380609), [HN](https://news.ycombinator.com/item?id=47918768) |
| LM Studio | J | [HN](https://news.ycombinator.com/item?id=50377697), [HN](https://news.ycombinator.com/item?id=50657758) |
| OpenRouter | K | [HN](https://news.ycombinator.com/item?id=50428201), [HN](https://news.ycombinator.com/item?id=50385812) |
| claude-code-router | K | [HN](https://news.ycombinator.com/item?id=50151581), [HN](https://news.ycombinator.com/item?id=49914586) |
| CLIProxyAPI | K | [HN](https://news.ycombinator.com/item?id=49544323), [HN](https://news.ycombinator.com/item?id=48918022), [GeekNews](https://fr.news.hada.io/topic?id=33206) |
| Meridian | K | [HN](https://news.ycombinator.com/item?id=49544323), [HN](https://news.ycombinator.com/item?id=49355109) |
| LiteLLM | K | [HN](https://news.ycombinator.com/item?id=50368111), [HN](https://news.ycombinator.com/item?id=50619284) |
| ccusage | F | [HN](https://news.ycombinator.com/item?id=50341093), [HN](https://news.ycombinator.com/item?id=50287122), [GeekNews](https://news.hada.io/topic?id=26561) |
| claude-mem | F | [HN](https://news.ycombinator.com/item?id=50289137), [HN](https://news.ycombinator.com/item?id=49345976) |
| Superpowers 플러그인 | F | [HN](https://news.ycombinator.com/item?id=50377528), [HN](https://news.ycombinator.com/item?id=50662121), [DC](https://gall.dcinside.com/mgallery/board/view/?id=thesingularity&no=1238159) |
| Cursor | D | [HN](https://news.ycombinator.com/item?id=50399014), [HN](https://news.ycombinator.com/item?id=50434217) |
| Antigravity CLI·Gemini CLI | E | [HN](https://news.ycombinator.com/item?id=50368362), [HN](https://news.ycombinator.com/item?id=49914586), [DC](https://gall.dcinside.com/mgallery/board/view/?id=thesingularity&no=1219050) |
| Aider | E | [HN](https://news.ycombinator.com/item?id=50402364), [HN](https://news.ycombinator.com/item?id=50387654) |
| Conductor | G | [HN](https://news.ycombinator.com/item?id=50379292), [HN](https://news.ycombinator.com/item?id=50407925) |
| 텔레그램·디스코드 봇 인터페이스(Hermes·OpenClaw 게이트웨이) | H | [HN](https://news.ycombinator.com/item?id=50385812), [GeekNews](https://pt.news.hada.io/topic?id=28101) |

## 다음 PR 순서

이번 PR은 표와 웹 서비스 도메인·로컬 LLM 앱 경로 용어만 바꾼다. 남은 빈 곳은 아래 순서로 하나씩 연다. 1~6은 주인이 정한 순서다. 모든 수집기는 합성 fixture만 쓰고, 비밀 파일은 존재만 기록한다.

1. **omp·pi 세션 수집기**: `~/.omp/agent/sessions/**/*.jsonl`, `~/.pi/agent/sessions/**/*.jsonl`, `history.db`의 프롬프트 기록, `logs/omp.*.log`, `config.yml`의 MCP·모델 설정. senpi·OmO의 `<agentDir>/sessions`도 같은 형식이라 함께 읽는다.
2. **Cataly 허브 DB·로그**: `cataly.db`(읽기 전용 스냅샷, 테이블 목록과 lane·보고·이벤트 행), `logs/events.jsonl`, `logs/hub.log`, `sessions/{lead,lanes}/`, `config.toml`, 서비스 유닛(`dev.cataly.hub.plist`·systemd). 토큰 파일은 존재만.
3. **dori 상태·워크로그·lane-out**: `~/.dori/state/lanes/*.json`, `lanes/<key>/{reports,checkpoints}.jsonl`, `worklog.jsonl`, `~/.dori/{briefs,receipts,inbox,backlog}`, `lane-out/<lane>/`, `config.json`, LaunchAgents.
4. **omo·senpi**: `~/.omo/agent/sessions`, `~/.omo/memory/agents/*`, `~/.omo/desktop/userdata/state.sqlite`의 `orchestration_events`, `omo-sessions/*.jsonl`, `~/.claude/transcripts/*.jsonl`, `OmO-debug.log`, `~/.senpi/agent/`.
5. **herdr**: `session.json`·`session-snapshots/`(어느 창에서 어느 에이전트 세션이 돌았는지, 에이전트 세션 ID로 다른 수집기 행과 연결), `session-history.json`(있을 때), 로그, `agent-detection/`.
6. **Orca**: `~/.orca/bots/*/{SOUL.md,MEMORY.md,bot.json}`, userData의 `bot-work.sqlite`·`bot-items.sqlite`·`bot-memory-history/`·`orca-data.json`.
7. Claude Desktop 설정·MCP 로그·Cowork 세션(`local-agent-mode-sessions`).
8. Cline·Roo·Kilo 작업 폴더(`globalStorage/<확장 ID>/tasks`)와 Continue.
9. OpenCode(`opencode.db`, 구 `storage/`), GitHub Copilot CLI(`~/.copilot`), Aider 기록 파일.
10. Hermes Agent·OpenClaw(직접 운영 메신저 봇).
11. Antigravity(`~/.gemini/antigravity*`)와 Codex SQLite 상태 DB.
12. Ollama 데스크톱 `db.sqlite`·CLI `history`, Open WebUI `chat` 테이블, Jan 스레드 전용 파서.
13. Brave Leo `AIChat`, Comet·Dia 프로필 경로 등록, AI 확장 ID 표.
14. 생성 이미지 PNG 청크(`parameters`, `prompt`, `workflow`)와 C2PA.
15. API 키 이름 인벤토리(값 없이)와 claude-code-router·n8n.
16. Microsoft Copilot 활동 CSV, Takeout Gemini 활동, `pi.ai`·`liner.com`·`pickle.com`(저장소 탐지는 이번 PR에서 호스트 경계 비교로 바뀌어 막는 것이 없음).
