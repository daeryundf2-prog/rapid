// Compact dependency-free markdown renderer for server-generated run/case
// reports. Every text node is HTML-escaped; only a small structural subset
// (headings, lists, tables, code, quotes, links, hr, paragraphs) becomes markup.
import { escapeHtml } from "./app_utils.js";

const HEADING_PATTERN = /^(#{1,6})\s+(.+?)\s*#*\s*$/;
const HR_PATTERN = /^\s*(?:\*{3,}|-{3,}|_{3,})\s*$/;
const FENCE_PATTERN = /^```\s*[\w-]*\s*$/;
const UL_PATTERN = /^\s*[-*+]\s+(.+)$/;
const OL_PATTERN = /^\s*\d+[.)]\s+(.+)$/;
const QUOTE_PATTERN = /^\s*>\s?(.*)$/;
const TABLE_SEPARATOR_PATTERN = /^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$/;
// NUL sentinel cannot appear in report text, so extracted code spans never
// collide with literal content during inline rendering.
const CODE_SPAN_SENTINEL = String.fromCharCode(0);
const CODE_SPAN_RESTORE = new RegExp(`${CODE_SPAN_SENTINEL}(\\d+)${CODE_SPAN_SENTINEL}`, "g");

function safeLinkHref(url) {
  const value = String(url || "").trim();
  if (!value) return "";
  if (/^https?:\/\//i.test(value)) return value;
  // Block javascript:/data:/vbscript: and any other scheme; relative paths
  // and anchors stay allowed (same-tab navigation only).
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return "";
  return value;
}

function renderInline(text) {
  // Pull inline code out first so its contents stay literal through escaping.
  const codeSpans = [];
  const working = String(text ?? "").replace(/`([^`]+)`/g, (_, code) => {
    codeSpans.push(`<code>${escapeHtml(code)}</code>`);
    return `${CODE_SPAN_SENTINEL}${codeSpans.length - 1}${CODE_SPAN_SENTINEL}`;
  });
  let html = escapeHtml(working);
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\[([^\]]*)\]\(([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\)/g, (match, label, url) => {
    const href = safeLinkHref(url);
    if (!href) return label;
    return `<a href="${href}">${label}</a>`;
  });
  return html.replace(CODE_SPAN_RESTORE, (_, index) => codeSpans[Number(index)] || "");
}

function tableCells(line) {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((cell) => cell.trim());
}

function isTableStart(lines, index) {
  return (
    index + 1 < lines.length
    && lines[index].includes("|")
    && TABLE_SEPARATOR_PATTERN.test(lines[index + 1])
  );
}

function startsBlock(lines, index) {
  const line = lines[index];
  const trimmed = line.trim();
  return (
    FENCE_PATTERN.test(trimmed)
    || HR_PATTERN.test(trimmed)
    || HEADING_PATTERN.test(trimmed)
    || QUOTE_PATTERN.test(line)
    || UL_PATTERN.test(line)
    || OL_PATTERN.test(line)
    || isTableStart(lines, index)
  );
}

function renderTable(lines, index, blocks) {
  const head = tableCells(lines[index]).map((cell) => `<th>${renderInline(cell)}</th>`).join("");
  index += 2; // header row + separator row
  const rows = [];
  while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
    rows.push(tableCells(lines[index]).map((cell) => `<td>${renderInline(cell)}</td>`).join(""));
    index += 1;
  }
  const body = rows.map((row) => `<tr>${row}</tr>`).join("");
  blocks.push(`<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`);
  return index;
}

function renderList(lines, index, blocks) {
  let tag = "";
  let items = [];
  while (index < lines.length) {
    const unordered = UL_PATTERN.exec(lines[index]);
    const match = unordered || OL_PATTERN.exec(lines[index]);
    if (!match) break;
    const next = unordered ? "ul" : "ol";
    if (tag && next !== tag) {
      blocks.push(`<${tag}>${items.join("")}</${tag}>`);
      items = [];
    }
    tag = next;
    items.push(`<li>${renderInline(match[1])}</li>`);
    index += 1;
  }
  if (tag) blocks.push(`<${tag}>${items.join("")}</${tag}>`);
  return index;
}

export function renderMarkdownToHtml(markdown) {
  const lines = String(markdown ?? "").replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();
    if (!trimmed) {
      index += 1;
      continue;
    }
    if (FENCE_PATTERN.test(trimmed)) {
      const code = [];
      index += 1;
      while (index < lines.length && !FENCE_PATTERN.test(lines[index].trim())) {
        code.push(lines[index]);
        index += 1;
      }
      index += 1; // consume the closing fence (or run past EOF)
      blocks.push(`<pre><code>${escapeHtml(code.join("\n"))}</code></pre>`);
      continue;
    }
    if (HR_PATTERN.test(trimmed)) {
      blocks.push("<hr />");
      index += 1;
      continue;
    }
    const heading = HEADING_PATTERN.exec(trimmed);
    if (heading) {
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      index += 1;
      continue;
    }
    if (isTableStart(lines, index)) {
      index = renderTable(lines, index, blocks);
      continue;
    }
    if (QUOTE_PATTERN.test(line)) {
      const quote = [];
      while (index < lines.length && QUOTE_PATTERN.test(lines[index])) {
        quote.push(QUOTE_PATTERN.exec(lines[index])[1]);
        index += 1;
      }
      blocks.push(`<blockquote>${quote.map(renderInline).join("<br />")}</blockquote>`);
      continue;
    }
    if (UL_PATTERN.test(line) || OL_PATTERN.test(line)) {
      index = renderList(lines, index, blocks);
      continue;
    }
    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !startsBlock(lines, index)) {
      paragraph.push(lines[index]);
      index += 1;
    }
    blocks.push(`<p>${renderInline(paragraph.join("\n"))}</p>`);
  }
  return blocks.join("\n");
}
