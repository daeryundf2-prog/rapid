/**
 * 대상 of a timeline event (F10): what the event is about — a file name, a URL's host and path,
 * an executable, a registry key — read from the event's structured fields (`details`, `path`,
 * core/timeline.py `compact_event_context`), so the column no longer repeats
 * "Artifact event: <family>" on every row. The event kind stays in the 이벤트 column.
 *
 * Without such a field the generated summary is kept, minus the generator's own fixed prefix
 * (core/timeline.py `build_artifact_summary`, file / document events): the prefix is matched
 * exactly (the artifact type is known from `details.artifact_type`), never guessed.
 */

import { baseName, isRecord, str, strOrNull } from "./common";

export interface TimelineTarget {
  /** Cell text, target first. */
  text: string;
  /** Hover / screen-reader text: the full target plus the event's original summary. */
  title: string;
  /** "field" = read from a structured field; "summary" = the summary minus its prefix. */
  basis: "field" | "summary";
}

/** "https://bank.example.test/account?x=1" → "bank.example.test/account"; unparsable → as written. */
export function urlTarget(value: string): string {
  try {
    const url = new URL(value);
    if (!url.host) return value;
    const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
    return `${url.host}${path}`;
  } catch {
    return value;
  }
}

/** "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" → "…\CurrentVersion\Run" (last two keys). */
export function keyTarget(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length > 2 ? `…\\${parts.slice(-2).join("\\")}` : path;
}

/** English / fixed prefixes the timeline builder writes in front of the target (core/timeline.py). */
const FIXED_PREFIXES = ["EventLog detection: ", "EventLog event: ", "AI usage: ", "문서 수정: "];

/**
 * The summary without the generator's prefix ("Artifact event: amcache-entry x.exe" → "x.exe").
 * The artifact type comes from `details.artifact_type`, else (a search hit's compact event has
 * no details) from the event type: "Artifact event: <t> " is removed only when the event type is
 * `artifact-<t>-…`, so a type is never guessed from the text alone.
 */
export function stripSummaryPrefix(summary: string, artifactType: string | null, eventType = ""): string {
  let text = summary.trim();
  const generic = /^Artifact event: (\S+) /.exec(text);
  const type =
    artifactType ?? (generic?.[1] && eventType.startsWith(`artifact-${generic[1]}-`) ? generic[1] : null);
  if (type) {
    for (const prefix of [`Artifact event: ${type} `, `${type}: `]) {
      if (text.startsWith(prefix)) return text.slice(prefix.length).trim() || text;
    }
  }
  for (const prefix of FIXED_PREFIXES) {
    if (text.startsWith(prefix)) return text.slice(prefix.length).trim() || text;
  }
  // File events: "파일 <time kind>: <name>" (core/timeline.py file events).
  const file = /^파일 [a-z0-9-]+: (.+)$/.exec(text);
  if (file?.[1]) text = file[1];
  return text;
}

function fieldTarget(raw: Record<string, unknown>, details: Record<string, unknown>): string | null {
  const eventType = str(raw.event_type);
  const ai = strOrNull(details.ai_service);
  if (ai) {
    const hint =
      strOrNull(details.query_hint) ??
      strOrNull(details.prompt_hint) ??
      (strOrNull(details.url) ? urlTarget(str(details.url)) : null);
    return hint ? `${hint} (${ai})` : ai;
  }
  // A download names the file it wrote; its URL stays in the tooltip.
  const target = strOrNull(details.target_path);
  if (target) return baseName(target);
  const url = strOrNull(details.url) ?? strOrNull(details.source_url);
  if (url) return urlTarget(url);
  const executable = strOrNull(details.executable_path);
  if (executable) return baseName(executable);
  const key = strOrNull(details.key_path);
  if (key) return keyTarget(key);
  const entry = strOrNull(details.entry_name);
  if (entry) return entry;
  if (eventType.startsWith("file-")) {
    const name = strOrNull(details.name);
    if (name) return name;
  }
  if (eventType === "document-modified") {
    const path = strOrNull(raw.path);
    if (path) return baseName(path);
  }
  return null;
}

/** Full text behind a field target (the URL, the whole target path, the key), for the tooltip. */
function fieldFull(details: Record<string, unknown>): string | null {
  return (
    strOrNull(details.target_path) ??
    strOrNull(details.url) ??
    strOrNull(details.source_url) ??
    strOrNull(details.executable_path) ??
    strOrNull(details.key_path)
  );
}

/** 대상 of a raw timeline event (`GET /timeline` row, or a search hit's `metadata`). */
export function timelineTarget(raw: Record<string, unknown>): TimelineTarget {
  const details = isRecord(raw.details) ? raw.details : {};
  const summary = strOrNull(raw.summary) ?? strOrNull(details.title) ?? "";
  const field = fieldTarget(raw, details);
  if (field) {
    const full = fieldFull(details);
    const title = [full && full !== field ? full : "", summary].filter(Boolean).join("\n");
    return { text: field, title: title || field, basis: "field" };
  }
  const text = summary
    ? stripSummaryPrefix(summary, strOrNull(details.artifact_type), str(raw.event_type))
    : "";
  return {
    text: text || strOrNull(raw.event_type) || "",
    title: summary || text,
    basis: "summary",
  };
}
