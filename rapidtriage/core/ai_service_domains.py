"""Web AI chat service hostnames shared by browser history and memory URL classification.

A hostname matches itself and its subdomains; the first matching entry wins, so a
specific host comes before a broader one of the same service. Every entry is
backed by the service's own site or help center: docs/ai-usage-coverage-matrix.md
lists the sources. Hosts that also serve unrelated pages (``bing.com``,
``notion.so``) or only corporate pages (``openai.com``, ``x.ai``) are not
chat services and stay with the browser collector's own filters.
"""

from __future__ import annotations

AI_CHAT_SERVICE_DOMAINS: tuple[tuple[str, str], ...] = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("aistudio.google.com", "Google AI Studio"),
    ("notebooklm.google", "NotebookLM"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("copilot.com", "Microsoft Copilot"),
    ("copilot.cloud.microsoft", "Microsoft 365 Copilot"),
    ("poe.com", "Poe"),
    ("grok.com", "Grok"),
    ("you.com", "You.com"),
    ("phind.com", "Phind"),
    ("chat.mistral.ai", "Mistral Le Chat"),
    ("deepseek.com", "DeepSeek"),
    ("meta.ai", "Meta AI"),
    ("character.ai", "Character.AI"),
    ("wrtn.ai", "뤼튼"),
    ("clova-x.naver.com", "CLOVA X"),
    ("adot.ai", "에이닷"),
    ("kimi.com", "Kimi"),
    ("kimi.ai", "Kimi"),
    ("kimi.moonshot.cn", "Kimi"),
    ("chat.qwen.ai", "Qwen"),
    ("qianwen.com", "Qwen"),
    ("tongyi.aliyun.com", "Qwen"),
    ("doubao.com", "Doubao"),
    ("chatglm.cn", "ChatGLM"),
    ("genspark.ai", "Genspark"),
    ("manus.im", "Manus"),
    ("felo.ai", "Felo"),
)
