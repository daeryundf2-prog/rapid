// KakaoTalk chat-bubble renderer (R2-2).
//
// Pure render module: normalizes the various KakaoTalk payload shapes produced
// by rapidtriage (decrypt entries, message previews, attachment/media rows,
// chatlog exports) into bubble-view markup. No DOM events are bound here —
// the caller mounts the returned HTML and owns any interaction binding.

import { escapeHtml } from "./app_utils.js";

const DAY_MS = 86400000;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asList(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Detect whether an artifact/payload object carries KakaoTalk chat material.
 * Accepts artifact rows ({kind, artifact_type, details}) and raw payloads
 * ({command: "kakaotalk-*", entries: [...]}).
 */
export function isKakaoPayload(value) {
  if (!isPlainObject(value)) return false;
  const haystack = [
    value.kind,
    value.artifact_type,
    value.command,
    value.parser,
    value.path,
  ]
    .map((item) => String(item || "").toLowerCase())
    .join(" ");
  if (!/(kakao|chatlog|kakaotalk)/.test(haystack)) return false;
  return collectKakaoMessages(value).messages.length > 0
    || hasKakaoStatusMaterial(value);
}

function hasKakaoStatusMaterial(value) {
  const details = isPlainObject(value.details) ? value.details : value;
  return Boolean(
    details.message_content_status
      || details.decrypt_status
      || details.message_table_candidates
      || details.sqlite_status
      || (isPlainObject(details.summary) && details.summary.message_row_count !== undefined),
  );
}

function normalizeTimestamp(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "number" && Number.isFinite(value)) {
    // Kakao sendAt is epoch seconds; allow millisecond values too.
    const ms = value > 1e12 ? value : value * 1000;
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? "" : date.toISOString();
  }
  const text = String(value);
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text : date.toISOString();
}

function dayKey(iso) {
  if (!iso) return "";
  return iso.slice(0, 10);
}

function timeLabel(iso) {
  if (!iso || iso.length < 16) return iso || "";
  return iso.slice(11, 16);
}

function normalizeAttachment(item, row = {}) {
  if (!isPlainObject(item)) return null;
  const name = item.display_name || item.name || row.display_name || "첨부";
  return {
    name: String(name),
    mediaClass: String(item.media_class || row.media_class || mediaClassFromItem(item)),
    mime: String(item.mime || row.mime || ""),
    size: item.declared_size ?? item.size ?? row.declared_size ?? null,
    localPath: firstLocalMatch(row),
    reviewStatus: String(row.review_status || item.review_status || ""),
    thumbnail: String(item.thumbnail || item.thumb || row.thumbnail || ""),
  };
}

function firstLocalMatch(row) {
  const matches = asList(row.local_matches);
  const first = matches.find((match) => isPlainObject(match) && match.path);
  return first ? String(first.path) : "";
}

function mediaClassFromItem(item) {
  const mime = String(item.mime || item.mt || "").toLowerCase();
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  return "file";
}

function normalizeMessage(raw, sourceHint = {}) {
  if (!isPlainObject(raw)) return null;
  const fields = isPlainObject(raw.fields) ? raw.fields : {};
  const text = firstText([
    raw.message,
    raw.message_text,
    raw.message_preview,
    raw.text,
    fields.message,
    fields.text,
  ]);
  const authorId = firstText([
    raw.author_id,
    raw.authorId,
    fields.authorId,
    fields.sender,
    fields.author,
    sourceHint.authorId,
  ]);
  const author = firstText([
    raw.author_name,
    raw.sender_name,
    fields.nickname,
    fields.name,
    authorId,
  ]);
  const attachments = asList(raw.attachments)
    .map((item) => normalizeAttachment(item, raw))
    .filter(Boolean);
  // Attachment-inventory rows are messages whose body is the attachment itself.
  if (!attachments.length && (raw.media_class || raw.local_matches || raw.basename_candidates)) {
    const attachment = normalizeAttachment(raw, raw);
    if (attachment) attachments.push(attachment);
  }
  const outgoing = raw.outgoing === true
    || raw.is_outgoing === true
    || raw.sent_by_owner === true
    || raw.direction === "outgoing";
  const timestamp = normalizeTimestamp(
    raw.send_at ?? raw.sendAt ?? raw.timestamp ?? fields.sendAt ?? raw.created_at,
  );
  if (!text && !attachments.length) return null;
  return {
    id: firstText([raw.log_id, raw.logId, raw.id, raw.rowid]) || `${authorId}:${timestamp}:${text.slice(0, 16)}`,
    chatId: firstText([raw.chat_id, raw.chatId, sourceHint.chatId]) || "default",
    author,
    authorId,
    timestamp,
    text,
    outgoing,
    messageType: raw.message_type ?? raw.type ?? fields.type ?? 0,
    attachments,
    provenance: firstText([raw.source_sqlite, raw.table, sourceHint.source]) || "",
  };
}

function firstText(candidates) {
  for (const candidate of candidates) {
    if (candidate === null || candidate === undefined) continue;
    const text = String(candidate).trim();
    if (text) return text;
  }
  return "";
}

/**
 * Normalize every recognizable KakaoTalk message shape inside a payload into a
 * flat, chronologically sorted message list plus provenance/status notes.
 */
export function collectKakaoMessages(payload) {
  const messages = [];
  const notes = [];
  if (!isPlainObject(payload)) return { messages, notes };

  const details = isPlainObject(payload.details) ? payload.details : payload;

  for (const row of asList(details.message_previews)) {
    const message = normalizeMessage(row, { authorId: details.user_id });
    if (message) messages.push(message);
  }
  for (const row of asList(details.messages)) {
    const message = normalizeMessage(row);
    if (message) messages.push(message);
  }
  for (const row of asList(details.chat_messages)) {
    const message = normalizeMessage(row);
    if (message) messages.push(message);
  }
  for (const row of asList(details.attachments)) {
    const message = normalizeMessage(row);
    if (message) messages.push(message);
  }
  for (const row of asList(details.attachment_inventory)) {
    const message = normalizeMessage(row);
    if (message) messages.push(message);
  }
  for (const entry of asList(details.entries)) {
    for (const row of asList(entry.message_previews)) {
      const message = normalizeMessage(row, {
        chatId: entry.chat_id,
        source: entry.path || entry.source_sqlite,
      });
      if (message) messages.push(message);
    }
    for (const row of asList(entry.messages)) {
      const message = normalizeMessage(row, { chatId: entry.chat_id });
      if (message) messages.push(message);
    }
  }
  for (const room of asList(details.rooms || details.chats)) {
    for (const row of asList(room.messages)) {
      const message = normalizeMessage(row, { chatId: room.chat_id || room.id, authorId: room.user_id });
      if (message) messages.push(message);
    }
  }

  const status = firstText([
    details.message_content_status,
    details.decrypt_status,
    details.sqlite_status,
  ]);
  if (status) notes.push(`메시지 상태: ${status}`);
  const summary = isPlainObject(details.summary) ? details.summary : {};
  if (summary.commercial_grade_ready === false) {
    notes.push("검증 미완료 — 복호화 결과는 known-answer 검증 전까지 정황 자료로만 사용");
  }
  if (summary.message_row_count !== undefined) {
    notes.push(`메시지 행 수: ${summary.message_row_count}`);
  }

  const meId = firstText([details.user_id, details.owner_id, details.me_id]);
  messages.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || "") || a.id.localeCompare(b.id));
  return { messages, notes, meId };
}

function avatarHtml(author) {
  const initial = (author || "?").trim().slice(0, 1) || "?";
  return `<span class="kakao-avatar" aria-hidden="true">${escapeHtml(initial)}</span>`;
}

function attachmentIcon(mediaClass) {
  switch (mediaClass) {
    case "image": return "🖼";
    case "video": return "🎬";
    case "audio": return "🔊";
    case "multi-image": return "🖼";
    default: return "📎";
  }
}

function formatBytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size) || size <= 0) return "";
  if (size < 1024) return `${size}B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)}KB`;
  return `${(size / (1024 * 1024)).toFixed(1)}MB`;
}

function renderAttachment(attachment) {
  const sizeLabel = formatBytes(attachment.size);
  return `
    <div class="kakao-attachment kakao-attachment-${escapeHtml(attachment.mediaClass)}" ${attachment.localPath ? `data-viewer-row-path="${escapeHtml(attachment.localPath)}"` : ""}>
      <span class="kakao-attachment-icon" aria-hidden="true">${attachment.thumbnail ? `<img src="${escapeHtml(attachment.thumbnail)}" alt="" loading="lazy" />` : attachmentIcon(attachment.mediaClass)}</span>
      <span class="kakao-attachment-meta">
        <strong>${escapeHtml(attachment.name)}</strong>
        <small>${escapeHtml([attachment.mime, sizeLabel, attachment.reviewStatus].filter(Boolean).join(" · "))}</small>
      </span>
    </div>
  `;
}

/**
 * Render a KakaoTalk-style chat view. `messages` should be the normalized list
 * from collectKakaoMessages (or equivalent normalized rows). `meId` marks the
 * owner account id for right-aligned outgoing bubbles.
 */
export function renderKakaoChat({ title = "KakaoTalk", messages = [], meId = "", notes = [], emptyText = "표시할 메시지가 없습니다." } = {}) {
  if (!messages.length) {
    return `
      <section class="kakao-chat" aria-label="${escapeHtml(title)}">
        <header class="kakao-chat-header"><strong>${escapeHtml(title)}</strong></header>
        ${notes.length ? `<ul class="kakao-status-notes">${notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>` : ""}
        <p class="kakao-empty">${escapeHtml(emptyText)}</p>
      </section>
    `;
  }

  const bubbles = [];
  let lastDay = "";
  let lastAuthor = null;
  for (const message of messages) {
    const outgoing = message.outgoing || (meId && message.authorId && message.authorId === meId);
    const day = dayKey(message.timestamp);
    if (day && day !== lastDay) {
      bubbles.push(`<div class="kakao-day-separator" role="separator"><span>${escapeHtml(day)}</span></div>`);
      lastAuthor = null;
    }
    lastDay = day;
    const sameAuthor = lastAuthor === message.authorId;
    lastAuthor = message.authorId;
    bubbles.push(`
      <div class="kakao-row ${outgoing ? "kakao-row-out" : "kakao-row-in"}" data-kakao-message="${escapeHtml(message.id)}">
        ${outgoing ? "" : `${sameAuthor ? '<span class="kakao-avatar-spacer"></span>' : avatarHtml(message.author)}`}
        <div class="kakao-bubble-stack">
          ${!outgoing && !sameAuthor && message.author ? `<span class="kakao-author">${escapeHtml(message.author)}</span>` : ""}
          <div class="kakao-bubble">
            ${message.text ? `<p class="kakao-text">${escapeHtml(message.text)}</p>` : ""}
            ${message.attachments.map(renderAttachment).join("")}
            ${message.provenance ? `<small class="kakao-provenance">${escapeHtml(message.provenance)}</small>` : ""}
          </div>
          <time class="kakao-time" datetime="${escapeHtml(message.timestamp || "")}">${escapeHtml(timeLabel(message.timestamp))}</time>
        </div>
      </div>
    `);
  }

  return `
    <section class="kakao-chat" aria-label="${escapeHtml(title)}">
      <header class="kakao-chat-header">
        <strong>${escapeHtml(title)}</strong>
        <span class="kakao-count">${messages.length}개 메시지</span>
      </header>
      ${notes.length ? `<ul class="kakao-status-notes">${notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>` : ""}
      <div class="kakao-timeline" role="log">${bubbles.join("")}</div>
    </section>
  `;
}

/**
 * Convenience: artifact -> rendered chat card, or "" when no kakao material.
 */
export function renderKakaoArtifactChatCard(artifact) {
  const details = artifact?.details;
  if (!isPlainObject(details)) return "";
  const { messages, notes, meId } = collectKakaoMessages(details);
  if (!messages.length && !notes.length) return "";
  const title = details.chat_name || details.room_name || artifact.artifact_type || "KakaoTalk";
  return `
    <details class="kakao-card" open>
      <summary>채팅 보기 (${messages.length}개)</summary>
      ${renderKakaoChat({ title, messages, meId, notes })}
    </details>
  `;
}
