import { baseName, str, strOrNull } from "./common";

export interface ArtifactSummary {
  /** The record's own one-line summary (never just the artifact type). */
  title: string;
  /** Second line: message preview / secondary detail. */
  detail: string;
  eventId?: string;
  channel?: string;
}

export interface RecordHighlight {
  offset?: number;
  length?: number;
  table?: string;
  rowid?: number;
}

type Details = Record<string, unknown>;

function clip(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function firstStr(details: Details, keys: string[]): string | null {
  for (const key of keys) {
    const value = strOrNull(details[key]);
    if (value) return value;
  }
  return null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function eventChannel(details: Details): string {
  const tags = Array.isArray(details.event_tags) ? details.event_tags.map(str) : [];
  const tag = tags.find((t) => t.startsWith("channel:"));
  if (tag) return tag.slice("channel:".length);
  const fromMessage = /channel=([^|]+?)\s*(?:\||$)/.exec(str(details.event_message));
  return fromMessage?.[1]?.trim() ?? "";
}

/** event_message is "provider=… | channel=… | computer=… | user=… | …"; drop the leading key=value segments. */
function eventMessage(details: Details): string {
  const raw = firstStr(details, ["message", "rendered_message", "event_message"]) ?? "";
  return clip(raw.replace(/^(?:\s*\w+=[^|]*\|)+\s*/, ""));
}

/**
 * Registry cell kind label. The hive parser writes 0 / "nk" / "key" / "key-node" for key cells and
 * 1 / "vk" / "value" / "value-node" for value cells; anything else is 기타.
 */
export function registryCellKindLabel(value: unknown): string {
  if (value === undefined || value === null || value === "") return "";
  const v = String(value).toLowerCase();
  if (v === "0" || v === "nk" || v === "key" || v === "key-node") return "키";
  if (v === "1" || v === "vk" || v === "value" || v === "value-node") return "값";
  return "기타";
}

/** Summarise one artifact row by artifact_type; defaults to the path basename. */
export function summarizeArtifact(
  artifactType: string | null,
  details: Details,
  path: string | null,
): ArtifactSummary {
  const type = artifactType ?? "";
  const name = baseName(path);
  if (type === "eventlog-event") {
    const eventId = str(details.event_id);
    const channel = eventChannel(details);
    const provider = str(details.provider_name);
    const title = [eventId, channel, provider].filter(Boolean).join(" ") || name;
    return { title, detail: eventMessage(details), eventId, channel };
  }
  if (type === "prefetch-file") {
    const exe =
      firstStr(details, ["executable_hint", "header_executable_name", "filename_executable_hint"]) ?? name;
    const runs = num(details.run_count);
    const last = firstStr(details, ["last_run_at"]) ?? "";
    return {
      title: exe,
      detail: [runs !== null ? `실행 ${runs}회` : "", last ? `최근 ${last}` : ""].filter(Boolean).join(" · "),
    };
  }
  if (type === "prefetch-reference") {
    return {
      title: firstStr(details, ["referenced_file_name", "referenced_path"]) ?? name,
      detail: str(details.referenced_path),
    };
  }
  if (type === "registry-hive-cell") {
    const cellName = firstStr(details, ["name", "value_name"]);
    const cellKind = registryCellKindLabel(details.cell_kind);
    return {
      title: [cellName, cellKind].filter(Boolean).join(" · ") || firstStr(details, ["hive_name"]) || name,
      detail: str(details.hive_name),
    };
  }
  if (type === "wer-report") {
    const app = firstStr(details, ["application_name", "application_path"]);
    const fault = str(details.fault_module_name);
    return {
      title: [app ? baseName(app) || app : null, fault].filter(Boolean).join(" · ") || name,
      detail: str(details.report_id),
    };
  }
  if (type.startsWith("windows-sam-")) {
    const account = firstStr(details, ["user_name_candidate", "group_name_candidate", "user_name"]);
    const rid = firstStr(details, ["rid_decimal", "alias_rid_decimal"]);
    return {
      title: account ?? (rid ? `RID ${rid}` : name),
      detail: [rid ? `RID ${rid}` : "", str(details.candidate_role)].filter(Boolean).join(" · "),
    };
  }
  if (type === "file-signature-mismatch") {
    const detected = str(details.detected_signature_kind);
    const expected = Array.isArray(details.expected_extensions)
      ? details.expected_extensions.map(str).join(", ")
      : str(details.expected_extensions);
    return {
      title: name || firstStr(details, ["file_name"]) || "",
      detail: detected || expected ? `${detected || "?"} → ${expected || "?"}` : "",
    };
  }
  if (type === "document-metadata-risk") {
    return { title: name || firstStr(details, ["file_name"]) || "", detail: str(details.document_family) };
  }
  if (type.startsWith("kakaotalk-windows-")) {
    const kind = str(details.candidate_kind);
    const value = clip(str(details.candidate_value), 80);
    return { title: kind || name, detail: value };
  }
  if (type === "cloud-message") {
    const text = firstStr(details, ["message_text_preview", "message_text"]);
    const ids = [str(details.chat_id), str(details.message_id)].filter(Boolean).join(" · ");
    const what = [str(details.service), str(details.event_type)].filter(Boolean).join(" · ");
    return {
      title: text ? clip(text) : what || ids || name,
      detail: [text ? what : "", str(details.cloud_family), text || what ? ids : ""]
        .filter(Boolean)
        .join(" · "),
    };
  }
  if (type.startsWith("registry-")) {
    const key = firstStr(details, ["key_path", "source_key_path"]);
    const value = firstStr(details, ["name", "value_name"]);
    const title = [key, value].filter(Boolean).join(" \\ ") || firstStr(details, ["hive_name"]) || name;
    return { title, detail: [str(details.value_type), str(details.hive_name)].filter(Boolean).join(" · ") };
  }
  if (type.startsWith("shellbag")) {
    const paths = details.shellbag_path_candidates;
    const first = Array.isArray(paths) ? strOrNull(paths[0]) : null;
    return {
      title: first ?? firstStr(details, ["source_key_path"]) ?? name,
      detail: str(details.source_key_path),
    };
  }
  if (type === "recent-shortcut" || type.startsWith("jumplist")) {
    return {
      title: firstStr(details, ["target_path", "entry_hint", "entry_name"]) ?? name,
      detail: str(details.entry_name),
    };
  }
  if (type.startsWith("media-")) {
    const w = num(details.width);
    const h = num(details.height);
    return {
      title: firstStr(details, ["entry_name"]) ?? name,
      detail: w !== null && h !== null ? `${w}×${h}` : str(details.source_format),
    };
  }
  if (type.startsWith("file-") || type.includes("usn") || type.includes("mft")) {
    const reason = firstStr(details, ["reason", "usn_reason", "reason_flags"]) ?? "";
    const flags = Array.isArray(details.risk_flags) ? details.risk_flags.map(str).join(", ") : "";
    return { title: firstStr(details, ["file_name", "name"]) ?? name, detail: reason || flags };
  }
  if (type.endsWith("-entry") || type.endsWith("-schema-entry") || type.startsWith("amcache")) {
    const exe = firstStr(details, ["executable_path", "program_name", "decoded_name", "display_path"]);
    return { title: exe ? baseName(exe) || exe : name, detail: exe ?? "" };
  }
  if (type.startsWith("mobile-message")) {
    return {
      title: clip(firstStr(details, ["message_text_preview", "message_text"]) ?? name),
      detail: str(details.attachment_name),
    };
  }
  const generic = firstStr(details, [
    "title",
    "name",
    "entry_name",
    "file_name",
    "user_name",
    "app_name",
    "cache_name",
    "summary",
    "message",
  ]);
  return { title: generic ?? name, detail: generic && name !== generic ? name : "" };
}

const OFFSET_KEYS = [
  "evtx_record_offset",
  "record_offset",
  "source_offset",
  "chunk_offset",
  "cell_offset",
  "entry_offset",
  "offset",
];
const LENGTH_KEYS = ["evtx_record_size", "record_size", "candidate_length", "length"];

/** Byte/record locator the viewer can jump to; undefined when the row has none. */
export function recordHighlight(details: Details): RecordHighlight | undefined {
  const out: RecordHighlight = {};
  for (const key of OFFSET_KEYS) {
    const n = num(details[key]);
    if (n !== null) {
      out.offset = n;
      break;
    }
  }
  for (const key of LENGTH_KEYS) {
    const n = num(details[key]);
    if (n !== null) {
      out.length = n;
      break;
    }
  }
  const table = strOrNull(details.table);
  const rowid = num(details.rowid);
  if (table && rowid !== null) {
    out.table = table;
    out.rowid = rowid;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}
