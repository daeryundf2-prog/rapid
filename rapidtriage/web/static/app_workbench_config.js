const VIEW_GROUPS = [
  {
    id: "triage",
    label: "Triage",
    summary: "Inventory first, one bounded table at a time.",
    tabs: ["summary", "files", "docs", "artifacts", "timeline", "indicators"],
  },
  {
    id: "find",
    label: "Find",
    summary: "Search documents, logs, web artifacts, metadata, and OCR.",
    tabs: ["search"],
  },
  {
    id: "review",
    label: "Review",
    summary: "Classify hits, add notes, and separate evidence from noise.",
    tabs: ["review"],
  },
  {
    id: "deliver",
    label: "Deliver",
    summary: "Read generated reports and export submission material.",
    tabs: ["report"],
  },
];
const TAB_LABELS = {
  summary: "Overview",
  search: "Keyword search",
  review: "Review board",
  timeline: "Timeline",
  indicators: "Indicators",
  artifacts: "Artifacts",
  files: "Files",
  docs: "Documents",
  report: "Run report",
};
const FORENSIC_VIEW_MODES = [
  { tab: "summary", label: "Overview", hint: "case dashboard", icon: "⌂" },
  { tab: "artifacts", label: "Artifacts", hint: "parsed evidence", icon: "▦" },
  { tab: "files", label: "Files", hint: "filesystem grid", icon: "▤" },
  { tab: "docs", label: "Documents", hint: "text hits", icon: "▧" },
  { tab: "timeline", label: "Timeline", hint: "time view", icon: "◷" },
  { tab: "indicators", label: "Indicators", hint: "IOC pivots", icon: "◎" },
  { tab: "search", label: "Search", hint: "keyword/regex", icon: "⌕" },
  { tab: "review", label: "Review", hint: "tags/report", icon: "✓" },
  { tab: "report", label: "Export", hint: "bundle/report", icon: "⇩" },
];
const SHORTCUTS = [
  { keys: ["1", "2", "3", "4"], label: "Switch Triage / Find / Review / Deliver" },
  { keys: ["Ctrl K", "Cmd K"], label: "Open entire case search" },
  { keys: ["Ctrl F", "Cmd F"], label: "Search current file, or filter visible rows" },
  { keys: ["[", "]"], label: "Previous / next page in heavy tables" },
  { keys: ["Alt [", "Alt ]"], label: "Previous / next opened search hit" },
  { keys: ["Alt R"], label: "Mark the open viewer hit relevant and save" },
  { keys: ["Alt X"], label: "Reject the open viewer hit as not relevant and save" },
  { keys: ["Alt I"], label: "Toggle include-in-report for the open viewer hit" },
  { keys: ["/"], label: "Jump to global case search" },
  { keys: ["?"], label: "Show or hide this shortcut guide" },
];
const LAZYWEB_WORKBENCH_MODEL = {
  profile_version: "lazyweb-command-center-model-v1",
  checklist_item: 18,
  reference_patterns: [
    {
      label: "Lazyweb Raycast manage models",
      url: "https://www.lazyweb.com/canvas/flows/raycast/manage-models",
      pattern: "command-first model switcher",
    },
    {
      label: "Lazyweb flow gallery",
      url: "https://www.lazyweb.com/canvas/flows",
      pattern: "flow-backed screen references",
    },
  ],
  principles: [
    "case actions stay in one command center instead of separate screens",
    "artifact tree, virtual table, source preview, review, and report remain connected",
    "search opens the same source viewer before any report decision",
  ],
  commands: [
    {
      id: "intake",
      label: "Evidence intake",
      tab: "summary",
      shortcut: "1",
      hint: "E01, folder, mounted image, or imported run",
      filter: "case",
    },
    {
      id: "search",
      label: "Unified search",
      tab: "search",
      shortcut: "/",
      hint: "files, documents, web, AI, EVTX, Registry, OCR, mail, messenger",
      filter: "search",
    },
    {
      id: "verify",
      label: "Source verify",
      tab: "artifacts",
      shortcut: "Enter",
      hint: "open the source viewer, hash, offset, parser, limitation",
      filter: "windows",
    },
    {
      id: "review",
      label: "Review board",
      tab: "review",
      shortcut: "Alt R",
      hint: "relevant, needs-review, excluded, include-in-report",
      filter: "review",
    },
    {
      id: "deliver",
      label: "Report bundle",
      tab: "report",
      shortcut: "4",
      hint: "citations, hash manifest, exhibit-ready output",
      filter: "report",
    },
  ],
};
const FORENSIC_RIBBON_GROUPS = [
  {
    id: "case",
    label: "Case",
    tab: "summary",
    modules: ["Case info", "Evidence intake", "Validation", "Report"],
    terms: ["case", "report", "validation", "custody"],
  },
  {
    id: "core",
    label: "Core forensic",
    tab: "artifacts",
    modules: ["File system", "Timeline", "Registry", "Event logs", "Browser", "USB"],
    terms: ["file", "timeline", "registry", "event", "browser", "usb", "mft", "usn"],
  },
  {
    id: "apps",
    label: "Apps / SNS",
    tab: "artifacts",
    modules: ["SNS / CHAT", "Email", "AI usage", "Cloud", "Downloads"],
    terms: ["chat", "sns", "email", "ai", "cloud", "download", "kakao", "browser"],
  },
  {
    id: "media",
    label: "Media / OCR",
    tab: "files",
    modules: ["Image", "Video", "Audio", "OCR / translation", "Attachments"],
    terms: ["image", "video", "audio", "ocr", "media", "attachment", "jpg", "png"],
  },
  {
    id: "dfir",
    label: "DFIR",
    tab: "indicators",
    modules: ["LoL / fileless", "Scripts", "Threat intel", "Memory", "WebShell"],
    terms: ["powershell", "script", "threat", "indicator", "memory", "webshell", "lol"],
  },
];
const FORENSIC_ARTIFACT_TAXONOMY = [
  {
    label: "Windows artifacts",
    hint: "EVTX, Registry, Prefetch, MFT/USN, ShellBags",
    tab: "artifacts",
    terms: ["eventlog", "evtx", "registry", "prefetch", "mft", "usn", "shellbag", "lnk", "amcache", "shimcache"],
  },
  {
    label: "Web / AI usage",
    hint: "Browser history, downloads, AI service prompts and answers",
    tab: "artifacts",
    terms: ["browser", "download", "history", "cookie", "cache", "ai", "chatgpt", "claude", "gemini", "perplexity"],
  },
  {
    label: "SNS / chat / mobile",
    hint: "KakaoTalk, messengers, mobile imports, attachments",
    tab: "artifacts",
    terms: ["chat", "sns", "kakao", "telegram", "whatsapp", "signal", "line", "mobile", "message"],
  },
  {
    label: "Documents / DB / mail",
    hint: "Office/PDF/text, SQLite, PST/OST, mailbox exports",
    tab: "docs",
    terms: ["document", "pdf", "office", "sqlite", "database", "email", "pst", "ost", "mbox"],
  },
  {
    label: "Media / OCR",
    hint: "Images, video/audio, OCR text, thumbnails",
    tab: "files",
    terms: ["image", "photo", "video", "audio", "ocr", "thumbnail", "jpg", "png", "mp4"],
  },
  {
    label: "IR / threat traces",
    hint: "Scripts, LoL, indicators, suspicious execution",
    tab: "indicators",
    terms: ["indicator", "ioc", "powershell", "script", "execution", "malware", "webshell", "lol", "fileless"],
  },
];
const WORKBENCH_ARTIFACT_TREE_GROUPS = [
  {
    label: "Windows",
    hint: "EVTX, Registry, Prefetch, MFT/USN, ShellBags, execution",
    tab: "artifacts",
    terms: ["windows", "eventlog", "evtx", "registry", "prefetch", "mft", "usn", "shellbag", "lnk", "amcache", "shimcache", "bam"],
  },
  {
    label: "Browser / AI",
    hint: "History, downloads, cache, ChatGPT, Claude, Gemini, Perplexity",
    tab: "artifacts",
    terms: ["browser", "download", "history", "cookie", "cache", "ai", "chatgpt", "claude", "gemini", "perplexity", "copilot"],
  },
  {
    label: "Mail",
    hint: "EML, MBOX, PST/OST-style exports, attachments",
    tab: "docs",
    terms: ["email", "mail", "eml", "mbox", "pst", "ost", "attachment"],
  },
  {
    label: "Messenger",
    hint: "KakaoTalk, WhatsApp, Telegram, Signal, LINE, Discord",
    tab: "artifacts",
    terms: ["chat", "sns", "kakao", "whatsapp", "telegram", "signal", "line", "discord", "message"],
  },
  {
    label: "Mobile",
    hint: "iOS/Android backups, APKs, contacts, calls, SMS",
    tab: "artifacts",
    terms: ["mobile", "ios", "android", "apk", "sms", "call", "contact"],
  },
  {
    label: "Media / OCR",
    hint: "Images, video, audio, OCR, translation, thumbnails",
    tab: "files",
    terms: ["image", "photo", "video", "audio", "ocr", "translation", "thumbnail", "jpg", "png", "mp4"],
  },
  {
    label: "Timeline",
    hint: "Unified time view, filesystem, event, web, app activity",
    tab: "timeline",
    terms: ["timeline", "event", "time", "created", "modified", "accessed"],
  },
  {
    label: "Search",
    hint: "Case-wide keyword, current-file search, source hits",
    tab: "search",
    terms: ["search", "keyword", "hit", "docs", "index", "fts"],
  },
  {
    label: "Reports",
    hint: "Review candidates, citations, export bundle",
    tab: "report",
    terms: ["report", "citation", "export", "bundle", "custody"],
  },
  {
    label: "Validation",
    hint: "QC, trusted diffs, parser blockers, readiness",
    tab: "summary",
    terms: ["validation", "qc", "readiness", "diff", "blocker", "commercial"],
  },
];
const USER_WORKFLOW_STEPS = [
  {
    label: "Input",
    title: "증거를 작게 시작",
    text: "E01은 지원 여부를 먼저 확인하고, 대용량은 Fast first pass로 색인/요약부터 만듭니다.",
  },
  {
    label: "Find",
    title: "전체 검색으로 좁히기",
    text: "문서, 웹/AI 사용 흔적, 로그, OCR, 메타데이터를 같은 검색 창에서 찾습니다.",
  },
  {
    label: "Verify",
    title: "원본 뷰어에서 재확인",
    text: "결과 클릭 후 파일 내부 검색, 해시 계산, 비교 핀으로 판단 근거를 고정합니다.",
  },
  {
    label: "Report",
    title: "보고서 후보만 남기기",
    text: "relevant와 include-in-report만 제출 묶음으로 빼고 나머지는 제외 사유를 남깁니다.",
  },
];
const WORKBENCH_SMOKE_CHECKPOINTS = [
  { id: "open-workbench", selector: "[data-testid='workbench-shell']", label: "Open analyst console" },
  { id: "create-or-import-run", selector: "[data-testid='sample-run-button']", label: "Create or import run" },
  { id: "select-run", selector: "[data-testid='case-hero']", label: "Select completed run" },
  { id: "search-case", selector: "[data-testid='global-case-search']", label: "Search case" },
  { id: "open-source-viewer", selector: "[data-testid='source-viewer']", label: "Open source viewer" },
  { id: "mark-evidence", selector: "[data-testid='viewer-review-form']", label: "Mark evidence" },
  { id: "export-report", selector: "[data-testid='tab-report']", label: "Export report" },
];
const START_CHOICE_CONTRACT = {
  profile_version: "start-screen-choice-contract-v1",
  checklist_item: 9,
  required_choices: ["e01", "folder", "recent", "sample", "qc"],
};
const WORKBENCH_LAYOUT_CONTRACT = {
  profile_version: "single-case-workbench-layout-v1",
  checklist_item: 10,
  required_regions: ["artifact-tree", "result-table", "preview-detail", "evidence-tray", "report-tray"],
  large_case_policy: "paged-results-plus-virtual-dom-window",
};
const TABLE_CONTROL_CONTRACT = {
  profile_version: "large-result-table-control-contract-v1",
  checklist_item: 12,
  controls: ["pagination", "virtual-window", "visible-row-filter", "column-preset", "source-filter", "time-filter", "keyboard-navigation"],
};
const PREVIEW_DETAIL_CONTRACT = {
  profile_version: "analyst-preview-detail-contract-v1",
  checklist_item: 13,
  default_metadata_state: "collapsed",
  required_cards: ["analyst-summary", "source-locator", "hash-verification", "limitation-warning", "review-actions"],
};
const VIEWER_NAVIGATION_CONTRACT = {
  profile_version: "viewer-navigation-history-contract-v1",
  checklist_item: 14,
  storage_scope: "per-run-local-browser",
  controls: ["back", "forward", "current-position", "history-preserves-review-context", "compare-pin-compatible"],
};
const WORKBENCH_SESSION_CONTRACT = {
  profile_version: "workbench-session-restore-contract-v1",
  checklist_item: 15,
  persisted_fields: ["selectedRunId", "activeTab", "activeViewGroup", "tableControls", "virtualWindowOffsets", "compareTray"],
};
const SEARCH_SOURCE_VERIFICATION_CONTRACT = {
  profile_version: "search-source-verification-contract-v1",
  checklist_item: 16,
  required_row_controls: ["view-review", "open-source", "pin-compare", "mark-review"],
  report_rule: "search-hit-is-a-lead-until-source-viewer-citation-and-hash-are-checked",
};
const SEARCH_RESULT_SOURCE_ACTION_CONTRACT = {
  profile_version: "search-result-source-viewer-actions-v1",
  qc_prep_item: 6,
  required_row_controls: ["open-source-viewer", "open-source-file", "search-inside-source", "pin-compare", "save-review"],
  report_rule: "viewer-open-and-review-save-before-report",
};
const CURRENT_FILE_SEARCH_CONTRACT = {
  profile_version: "current-file-search-ui-contract-v1",
  checklist_item: 17,
  required_fields: ["match-count", "result-limit", "truncation-state", "sqlite-scan-state", "reportability-warning"],
};
