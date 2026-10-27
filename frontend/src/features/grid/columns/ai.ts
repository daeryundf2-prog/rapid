/**
 * AI 사용 columns (R7 단계 3.5 갈래 D, plan r7-ai-usage §3.3 / §3.5): the default columns of each
 * AI 사용 tree node (a family of `ai-agent` row types), Korean headers, every raw enum through the
 * AI value labels (도구 이름 · 역할 · 도구 종류 · 작업 · 흔적 종류 · 근거 수준 · 자격 증명 종류 · 상태),
 * time columns ≥ 180 px, paths tail first, and the row title of each AI type. No raw id is a
 * default cell: session ids stay in the 메타 tab and the 세션 ID column (off by default).
 */

import { type AiValueDomain, aiToolDisplay, aiValueLabel, isAiType, yesNo } from "../../ai/aiLabels";
import type { ArtifactSummary } from "./artifactSummary";
import type { KindColumnDef } from "./artifacts";
import { baseName, str } from "./common";

type Details = Record<string, unknown>;

const TIME_WIDTH = 190;

/** Reading of one value or a list of values (merged rows: `credential_kinds[]`). */
function labelOf(domain: AiValueDomain, value: unknown): string {
  if (Array.isArray(value)) return value.map((item) => aiValueLabel(domain, item)).join(", ");
  return aiValueLabel(domain, value);
}

/** A column whose raw value reads through an AI value domain (the raw value is the tooltip). */
function labelled(header: string, keys: string[], domain: AiValueDomain, width = 140): KindColumnDef {
  return {
    header,
    keys,
    width,
    display: (value) => labelOf(domain, value),
    tooltip: (details) => {
      const raw = keys.map((key) => details[key]).find((v) => v !== undefined && v !== null && v !== "");
      const shown = labelOf(domain, raw);
      const text = Array.isArray(raw) ? raw.join(", ") : String(raw);
      return raw !== undefined && text !== shown ? `${shown} (원래 값: ${text})` : shown;
    },
  };
}

const time = (header: string, keys: string[], presets?: KindColumnDef["presets"]): KindColumnDef => ({
  header,
  keys,
  width: TIME_WIDTH,
  time: true,
  ...(presets ? { presets } : {}),
});

const flag = (header: string, key: string, yes: string, no: string, width = 100): KindColumnDef => ({
  header,
  keys: [key],
  width,
  display: (value) => yesNo(value, yes, no),
  tooltip: (details) => yesNo(details[key], yes, no),
});

/** 도구: the adapter's label, else the catalog product name (never the catalog id). */
export const AI_TOOL_COLUMN: KindColumnDef = {
  header: "도구",
  keys: ["tool_label", "tool"],
  width: 150,
  get: (details) => aiToolDisplay(details),
  tooltip: (details) => {
    const shown = aiToolDisplay(details);
    const tool = str(details.tool);
    return tool && tool !== shown ? `${shown} (카탈로그 도구: ${tool})` : shown;
  },
};

const ACCOUNT_COLUMN: KindColumnDef = { header: "계정", keys: ["account_key", "user"], width: 120 };
const SESSION_ID_COLUMN: KindColumnDef = {
  header: "세션 ID",
  keys: ["session_id"],
  width: 200,
  mono: true,
  presets: [],
};
const COVERAGE_COLUMN = labelled("근거 수준", ["coverage_status"], "coverage", 130);
const SOURCE_PATH_COLUMN: KindColumnDef = { header: "위치", keys: ["source_path"], width: 320, path: true };

/** 흔적 종류 of a presence row: the install kind, else the session adapter's location kind. */
function presenceKind(details: Details): string {
  const install = str(details.install_kind);
  if (install) return aiValueLabel("installKind", install);
  return aiValueLabel("presenceKind", details.presence_kind);
}

/** 명령·대상 of a tool call: the (masked) command, else its target path / URL / search pattern. */
function callTarget(details: Details): string {
  for (const key of ["command", "target_path", "target_url", "pattern", "mcp_tool"]) {
    const value = str(details[key]).trim();
    if (value) return value;
  }
  return "";
}

/** AI 비율 "62.5%" (the attribution's ai_percent, 0–100). */
function percent(value: unknown): string {
  const n = typeof value === "number" ? value : Number(value);
  if (value === null || value === undefined || value === "" || !Number.isFinite(n)) return "";
  return `${Math.round(n * 10) / 10}%`;
}

/** Column sets of the AI 사용 nodes (grid TYPE_FAMILY_COLUMNS entries, one per node). */
export const AI_TYPE_FAMILY_COLUMNS: Record<string, { types: readonly string[]; columns: KindColumnDef[] }> =
  {
    "ai-presence": {
      types: ["ai-tool-presence"],
      columns: [
        AI_TOOL_COLUMN,
        {
          header: "흔적 종류",
          keys: ["install_kind", "presence_kind"],
          width: 160,
          get: presenceKind,
          tooltip: (d) => [str(d.install_kind), str(d.presence_kind)].filter(Boolean).join(" · "),
        },
        labelled("출처", ["source"], "source", 170),
        { header: "버전", keys: ["version"], width: 100 },
        ACCOUNT_COLUMN,
        COVERAGE_COLUMN,
        time("수정 시각", ["mtime", "modified_at", "timestamp"]),
        SOURCE_PATH_COLUMN,
        labelled("도구 분류", ["category"], "category", 140),
      ],
    },
    "ai-session": {
      types: ["ai-agent-session"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "제목", keys: ["title", "preview", "goal_objective"], width: 260 },
        time("시작", ["started_at"]),
        time("종료", ["ended_at"]),
        { header: "메시지", keys: ["messages"], width: 80, number: true },
        { header: "도구 호출", keys: ["tool_calls"], width: 90, number: true },
        { header: "모델", keys: ["model", "models"], width: 150 },
        { header: "작업 폴더", keys: ["cwd", "project_label"], width: 260, path: true },
        ACCOUNT_COLUMN,
        { header: "입력 토큰", keys: ["tokens_in"], width: 100, number: true, presets: [] },
        { header: "출력 토큰", keys: ["tokens_out"], width: 100, number: true, presets: [] },
        { header: "Git 브랜치", keys: ["git_branch"], width: 140, presets: [] },
        { header: "상위 세션", keys: ["parent_session_id"], width: 200, mono: true, presets: [] },
        SESSION_ID_COLUMN,
      ],
    },
    "ai-message": {
      types: ["ai-agent-message"],
      columns: [
        time("시각", ["ts", "timestamp"]),
        AI_TOOL_COLUMN,
        labelled("역할", ["role"], "role", 100),
        { header: "내용", keys: ["text"], width: 420 },
        { header: "도구 호출 수", keys: ["tool_use_count"], width: 100, number: true, presets: [] },
        flag("이미지", "has_image", "있음", "", 80),
        { header: "순번", keys: ["seq"], width: 70, number: true, presets: [] },
        SESSION_ID_COLUMN,
      ],
    },
    "ai-tool-call": {
      types: ["ai-agent-tool-call"],
      columns: [
        time("시각", ["ts", "timestamp"]),
        AI_TOOL_COLUMN,
        { header: "호출 도구", keys: ["tool_name"], width: 150 },
        labelled("호출 종류", ["tool_kind"], "toolKind", 110),
        {
          header: "명령·대상",
          keys: ["command", "target_path", "target_url", "pattern"],
          width: 360,
          mono: true,
          get: callTarget,
          unsortable: true,
        },
        flag("파괴적", "destructive", "예", "아니오", 80),
        labelled("승인", ["approval"], "approval", 100),
        { header: "종료 코드", keys: ["exit_code"], width: 80, number: true },
        labelled("상태", ["status"], "status", 90),
        { header: "MCP 서버", keys: ["mcp_server"], width: 130, presets: [] },
        SESSION_ID_COLUMN,
      ],
    },
    "ai-file-touch": {
      types: ["ai-agent-file-touch"],
      columns: [
        time("시각", ["ts", "timestamp"]),
        AI_TOOL_COLUMN,
        labelled("작업", ["op"], "op", 90),
        { header: "접촉 경로", keys: ["touched_path"], width: 360, path: true },
        flag("증거에 있음", "exists_in_evidence", "있음", "없음", 100),
        { header: "호출 도구", keys: ["tool_name"], width: 130 },
        labelled("판단 근거", ["op_source"], "opSource", 150),
        SESSION_ID_COLUMN,
      ],
    },
    "ai-mcp": {
      types: ["ai-mcp-server"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "MCP 서버", keys: ["server"], width: 160 },
        labelled("상태", ["status"], "status", 110),
        labelled("연결 방식", ["transport"], "transport", 140),
        { header: "명령·주소", keys: ["endpoint"], width: 260, mono: true },
        { header: "도구 수", keys: ["tool_count"], width: 80, number: true },
        labelled("기록 위치", ["source"], "source", 140),
        time("관측", ["ts", "timestamp", "last_seen"]),
        flag("원격", "remote", "원격", "로컬", 80),
      ],
    },
    "ai-instruction": {
      types: ["ai-instruction-file"],
      columns: [
        AI_TOOL_COLUMN,
        labelled("파일 종류", ["instruction_kind"], "instructionKind", 140),
        { header: "첫 부분", keys: ["head_text"], width: 300 },
        { header: "크기", keys: ["size"], width: 90, bytes: true },
        time("수정 시각", ["file_mtime", "modified_at"]),
        SOURCE_PATH_COLUMN,
      ],
    },
    "ai-credential": {
      types: ["ai-credential-presence"],
      columns: [
        AI_TOOL_COLUMN,
        labelled("자격 증명 종류", ["credential_kind"], "credentialKind", 180),
        { header: "키 이름", keys: ["key_name"], width: 160 },
        { header: "크기", keys: ["size"], width: 90, bytes: true },
        time("수정 시각", ["file_mtime", "mtime", "modified_at"]),
        SOURCE_PATH_COLUMN,
        {
          header: "값",
          keys: ["value_collected"],
          width: 90,
          get: () => "수집 안 함",
          unsortable: true,
          tooltip: () => "값과 해시는 수집하지 않습니다(경로·크기·수정 시각만)",
        },
        ACCOUNT_COLUMN,
      ],
    },
    "ai-account": {
      types: ["ai-account", "ai-account-switch"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "계정", keys: ["tool_account_key", "from_account"], width: 180, mono: true },
        { header: "조직", keys: ["org_label"], width: 150 },
        { header: "이메일 도메인", keys: ["email_domain"], width: 150 },
        flag("활성", "active", "활성", "비활성", 80),
        time("처음 확인", ["first_seen", "ts", "timestamp"]),
        time("마지막 확인", ["last_seen"]),
        labelled("기록 위치", ["source"], "source", 160),
        { header: "로그 줄", keys: ["log_line"], width: 320, presets: [] },
      ],
    },
    "ai-code": {
      types: ["ai-code-attribution"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "파일", keys: ["file"], width: 300, path: true },
        { header: "커밋", keys: ["commit"], width: 120, mono: true },
        { header: "AI 줄", keys: ["ai_lines"], width: 80, number: true },
        { header: "사람 줄", keys: ["human_lines"], width: 80, number: true },
        { header: "AI 비율", keys: ["ai_percent"], width: 80, display: percent },
        { header: "모델", keys: ["model", "models"], width: 150 },
        time("시각", ["ts", "timestamp"]),
        labelled("기록 위치", ["source"], "source", 150),
      ],
    },
    "ai-usage": {
      types: ["ai-usage-stat"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "기간", keys: ["period"], width: 120 },
        { header: "모델", keys: ["model"], width: 150 },
        { header: "토큰", keys: ["tokens", "tokens_total"], width: 100, number: true },
        { header: "요청", keys: ["requests"], width: 80, number: true },
        labelled("기록 위치", ["source"], "source", 180),
      ],
    },
    "ai-retention": {
      types: ["ai-retention-cleanup"],
      columns: [
        AI_TOOL_COLUMN,
        time("정리 시각", ["cleaned_at", "timestamp"]),
        { header: "보존 일수", keys: ["retention_days"], width: 90, number: true },
        ACCOUNT_COLUMN,
        SOURCE_PATH_COLUMN,
      ],
    },
    "ai-model-file": {
      types: ["ai-model-file"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "파일", keys: ["file_name"], width: 220 },
        { header: "형식", keys: ["format"], width: 90 },
        { header: "크기", keys: ["size"], width: 100, bytes: true },
        labelled("위치 종류", ["location"], "location", 130),
        time("수정 시각", ["mtime", "modified_at"]),
        SOURCE_PATH_COLUMN,
      ],
    },
    "ai-unknown": {
      types: ["unknown-ai-tool-candidate"],
      columns: [
        { header: "폴더", keys: ["folder_name"], width: 180 },
        { header: "파일 수", keys: ["file_count"], width: 80, number: true },
        { header: "크기", keys: ["total_bytes"], width: 100, bytes: true },
        { header: "JSONL", keys: ["jsonl_count"], width: 70, number: true },
        { header: "SQLite", keys: ["sqlite_count"], width: 70, number: true },
        time("최근 수정", ["newest_mtime"]),
        ACCOUNT_COLUMN,
        SOURCE_PATH_COLUMN,
      ],
    },
    "ai-error": {
      types: ["ai-agent-parse-error"],
      columns: [
        AI_TOOL_COLUMN,
        { header: "사유", keys: ["reason_ko", "error_message"], width: 360 },
        { header: "오류 형식", keys: ["error_type"], width: 140 },
        SOURCE_PATH_COLUMN,
      ],
    },
  };

/** Columns of the kind-wide AI 사용 기록 전체 node (every type: tool, account, row time). */
export const AI_KIND_COLUMNS: KindColumnDef[] = [
  AI_TOOL_COLUMN,
  ACCOUNT_COLUMN,
  COVERAGE_COLUMN,
  { ...SOURCE_PATH_COLUMN, presets: [] },
];

function clip(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Row title (항목) and second line of an AI row; undefined for other types. */
export function aiArtifactSummary(
  type: string,
  details: Details,
  path: string | null,
): ArtifactSummary | undefined {
  if (!isAiType(type)) return undefined;
  const tool = aiToolDisplay(details);
  const name = baseName(path);
  switch (type) {
    case "ai-agent-session": {
      const title = str(details.title) || str(details.preview) || str(details.goal_objective);
      const where = str(details.project_label) || baseName(str(details.cwd));
      return {
        title: clip(title || [tool, "세션", where].filter(Boolean).join(" ")),
        detail: [tool, where].filter(Boolean).join(" · "),
      };
    }
    case "ai-agent-message": {
      const role = aiValueLabel("role", details.role);
      const text = str(details.text);
      return {
        title: clip(text ? `${role ? `${role}: ` : ""}${text}` : `${role || "메시지"} (본문 없음)`),
        detail: tool,
      };
    }
    case "ai-agent-tool-call": {
      const target = callTarget(details);
      return {
        title: clip([str(details.tool_name), target].filter(Boolean).join(" ") || "도구 호출"),
        detail: tool,
      };
    }
    case "ai-agent-file-touch": {
      const touched = str(details.touched_path);
      return {
        title:
          [aiValueLabel("op", details.op), baseName(touched) || touched].filter(Boolean).join(" · ") || name,
        detail: touched,
      };
    }
    case "ai-mcp-server":
      return { title: `MCP ${str(details.server) || "서버"}`, detail: tool };
    case "ai-credential-presence":
      return { title: `${name || tool} (값 미수집)`, detail: tool };
    case "ai-account": {
      const who = str(details.org_label) || str(details.email_domain) || str(details.tool_account_key);
      return { title: [tool, who].filter(Boolean).join(" · ") || "AI 계정", detail: str(details.source) };
    }
    case "ai-account-switch":
      return { title: `${tool || "AI"} 계정 전환`, detail: str(details.from_account) };
    case "ai-code-attribution": {
      const file = baseName(str(details.file)) || str(details.commit) || name;
      const share = percent(details.ai_percent);
      return { title: [file, share ? `AI ${share}` : ""].filter(Boolean).join(" · "), detail: tool };
    }
    case "ai-usage-stat":
      return {
        title: [tool, str(details.period)].filter(Boolean).join(" · ") || "AI 사용량",
        detail: str(details.model),
      };
    case "ai-retention-cleanup":
      return {
        title: `${tool || "AI"} 보존 정리`,
        detail: str(details.retention_days) ? `보존 ${str(details.retention_days)}일` : "",
      };
    case "ai-tool-presence":
      return { title: [tool, presenceKind(details)].filter(Boolean).join(" · ") || name, detail: name };
    case "ai-model-file":
      return { title: str(details.file_name) || name, detail: tool };
    case "unknown-ai-tool-candidate":
      return { title: str(details.folder_name) || name, detail: "미분류 AI 도구 후보" };
    case "ai-agent-parse-error":
      return { title: str(details.reason_ko) || "AI 기록 읽기 오류", detail: tool };
    default:
      return { title: name || tool, detail: tool };
  }
}
