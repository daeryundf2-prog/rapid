/**
 * Chat model (S9, plan X6). Pure: messenger artifact rows → conversations of
 * bubbles, plus keyword highlighting. Field names follow the parsers
 * (artifacts/mobile/messengers.py, kakaotalk_*.py): `details.message_text`
 * (or `_preview`), `conversation_id` / `conversation_title`, `timestamp`,
 * `participants`, `attachment_name`, `sender` / `recipient`, with the
 * vendor row under `details.raw` (sender/from/author, message/text/body).
 */

import type { GridRow } from "../../contracts/collection";

export interface ChatMessage {
  row: GridRow;
  conversationId: string;
  conversationLabel: string;
  service: string;
  sender: string;
  recipient: string;
  timestamp: string | null;
  text: string;
  attachments: string[];
  /** Sent by the device owner (drawn on the right). */
  outgoing: boolean;
}

export interface Conversation {
  id: string;
  label: string;
  service: string;
  participants: string[];
  messages: ChatMessage[];
  lastTimestamp: string | null;
}

type Rec = Record<string, unknown>;

const isRec = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);

function text(v: unknown): string {
  if (typeof v === "string") return v.trim();
  if (typeof v === "number") return String(v);
  return "";
}

function firstText(sources: Rec[], keys: string[]): string {
  for (const source of sources) {
    for (const key of keys) {
      const value = text(source[key]);
      if (value) return value;
    }
  }
  return "";
}

function baseName(path: string | null): string {
  if (!path) return "";
  return (
    path
      .replace(/[\\/]+$/, "")
      .split(/[\\/]/)
      .pop() ?? path
  );
}

/** Hint after a bare numeric id where a name is expected (KakaoTalk chat / user ids, m11). */
export const UNRESOLVED_NAME_HINT = "(이름 미해석)";

/** True for a bare numeric id (5+ digits): the parser could not resolve a name for it. */
export function isUnresolvedId(value: string): boolean {
  return /^-?\d{5,}$/.test(value.trim());
}

/** Message rows of messenger kinds (mobile-message, kakaotalk-*-message…), not summaries or inventories. */
export function isMessageRow(row: GridRow): boolean {
  const type = (row.artifactType ?? "").toLowerCase();
  return /message/.test(type) && !/summary|database|inventory|candidate/.test(type);
}

function serviceOf(details: Rec, row: GridRow): string {
  const direct = text(details.service) || text(details.app) || text(details.messenger);
  if (direct) return direct;
  const evidence = isRec(details.commercial_uplift_evidence) ? details.commercial_uplift_evidence : {};
  const refs = Array.isArray(evidence.source_refs) ? evidence.source_refs : [];
  for (const ref of refs) {
    const value = text(ref);
    if (value.startsWith("service:")) return value.slice("service:".length);
  }
  const kind = typeof row.fields.kind === "string" ? row.fields.kind : "";
  if (kind.startsWith("kakaotalk")) return "KakaoTalk";
  return row.provider ?? "";
}

function attachmentsOf(sources: Rec[]): string[] {
  const out: string[] = [];
  for (const source of sources) {
    for (const key of ["attachment_name", "attachment", "attachment_path", "media_name", "file_name"]) {
      const value = text(source[key]);
      if (value && !out.includes(value)) out.push(value);
    }
    const list = source.attachments;
    if (Array.isArray(list)) {
      for (const item of list) {
        const value = isRec(item) ? text(item.filename) || text(item.name) || text(item.path) : text(item);
        if (value && !out.includes(value)) out.push(value);
      }
    }
  }
  return out;
}

function isOutgoing(sources: Rec[]): boolean {
  for (const source of sources) {
    const direction = text(source.direction).toLowerCase();
    if (["outgoing", "sent", "out", "send", "발신"].includes(direction)) return true;
    if (["incoming", "received", "in", "receive", "수신"].includes(direction)) return false;
    for (const key of ["is_from_me", "from_me", "outgoing"]) {
      const flag = source[key];
      if (flag === true || flag === 1 || flag === "1" || flag === "true") return true;
    }
  }
  return false;
}

export function chatMessageFromRow(row: GridRow): ChatMessage {
  const details = isRec(row.fields.details) ? row.fields.details : {};
  const raw = isRec(details.raw) ? details.raw : {};
  const sources = [details, raw];
  const participants = Array.isArray(details.participants)
    ? details.participants.map(text).filter(Boolean)
    : [];
  const explicitId = firstText(sources, [
    "conversation_id",
    "chat_id",
    "thread_id",
    "chatroom_id",
    "room_id",
  ]);
  const title = firstText(sources, ["conversation_title", "conversation_name", "chat_name", "room_name"]);
  const fallback = participants.length ? participants.join(", ") : baseName(row.sourcePath) || "대화";
  const conversationId = explicitId || title || fallback;
  const label = title || explicitId || fallback;
  return {
    row,
    conversationId,
    conversationLabel: isUnresolvedId(label) ? `${label} ${UNRESOLVED_NAME_HINT}` : label,
    service: serviceOf(details, row),
    sender: firstText(sources, ["sender", "sender_name", "from", "author", "user_name", "remotejid"]),
    recipient: firstText(sources, ["recipient", "to", "receiver"]),
    timestamp: text(details.timestamp) || text(raw.timestamp) || text(raw.date) || row.timestamp || null,
    text:
      firstText(sources, ["message_text", "message_text_preview", "message", "text", "body", "content"]) ||
      row.title,
    attachments: attachmentsOf(sources),
    outgoing: isOutgoing(sources),
  };
}

function timeValue(value: string | null): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Group message rows into conversations. Messages are in time order (rows
 * without a time keep their source order after the timed ones of the same
 * position); conversations are newest-first, then by label.
 */
export function groupConversations(rows: readonly GridRow[]): Conversation[] {
  const map = new Map<string, Conversation>();
  rows.forEach((row) => {
    if (!isMessageRow(row)) return;
    const message = chatMessageFromRow(row);
    let conversation = map.get(message.conversationId);
    if (!conversation) {
      conversation = {
        id: message.conversationId,
        label: message.conversationLabel,
        service: message.service,
        participants: [],
        messages: [],
        lastTimestamp: null,
      };
      map.set(message.conversationId, conversation);
    }
    conversation.messages.push(message);
  });
  const conversations = [...map.values()];
  for (const conversation of conversations) {
    const indexed = conversation.messages.map((m, i) => ({ m, i, t: timeValue(m.timestamp) }));
    indexed.sort((a, b) => {
      if (a.t !== null && b.t !== null && a.t !== b.t) return a.t - b.t;
      return a.i - b.i;
    });
    conversation.messages = indexed.map((x) => x.m);
    // Participants in order of first appearance in the conversation.
    for (const message of conversation.messages) {
      for (const name of [message.sender, message.recipient]) {
        if (name && !conversation.participants.includes(name)) conversation.participants.push(name);
      }
    }
    const timed = indexed.filter((x) => x.t !== null);
    conversation.lastTimestamp = timed.length ? (timed[timed.length - 1]?.m.timestamp ?? null) : null;
  }
  return conversations.sort((a, b) => {
    const ta = timeValue(a.lastTimestamp) ?? -1;
    const tb = timeValue(b.lastTimestamp) ?? -1;
    return tb - ta || a.label.localeCompare(b.label);
  });
}

export interface TextPart {
  text: string;
  hit: boolean;
}

/** Query terms for highlighting (whitespace/comma separated, ≥ 1 char). */
export function highlightTerms(query: string | undefined): string[] {
  return (query ?? "")
    .split(/[\s,]+/)
    .map((t) => t.replace(/^"+|"+$/g, ""))
    .filter(Boolean);
}

/** Split `value` into plain / matched parts for every term (case-insensitive). */
export function highlightParts(value: string, terms: readonly string[]): TextPart[] {
  if (!value) return [];
  if (terms.length === 0) return [{ text: value, hit: false }];
  const escaped = [...terms]
    .sort((a, b) => b.length - a.length)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`(${escaped.join("|")})`, "gi");
  const parts: TextPart[] = [];
  let last = 0;
  for (const match of value.matchAll(pattern)) {
    const at = match.index ?? 0;
    if (!match[0]) continue;
    if (at > last) parts.push({ text: value.slice(last, at), hit: false });
    parts.push({ text: match[0], hit: true });
    last = at + match[0].length;
  }
  if (last < value.length) parts.push({ text: value.slice(last), hit: false });
  return parts;
}

export function messageMatches(message: ChatMessage, terms: readonly string[]): boolean {
  if (terms.length === 0) return false;
  const hay = `${message.text}\n${message.sender}\n${message.attachments.join("\n")}`.toLowerCase();
  return terms.some((t) => hay.includes(t.toLowerCase()));
}
