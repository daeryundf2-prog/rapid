// Canvas-based interactive hex viewer (R2-3).
//
// Reads bounded byte ranges from the existing `source-hex-range` API and
// renders offset/HEX/ASCII columns on a <canvas> so multi-KB ranges stay
// cheap. File-signature magic bytes are scanned in the loaded range and
// highlighted with a legend. The viewer never loads the whole file — paging
// moves `offset` through range requests only.

import { escapeHtml } from "./app_utils.js";

export const BYTES_PER_ROW = 16;
export const DEFAULT_PAGE_LENGTH = 1024;
export const MAX_PAGE_LENGTH = 16384;

// Forensically relevant magic-byte signatures.
export const HEX_SIGNATURES = [
  { name: "PE/MZ", bytes: [0x4d, 0x5a] },
  { name: "ZIP", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: "SQLite", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65] },
  { name: "PNG", bytes: [0x89, 0x50, 0x4e, 0x47] },
  { name: "JPEG", bytes: [0xff, 0xd8, 0xff] },
  { name: "GIF", bytes: [0x47, 0x49, 0x46, 0x38] },
  { name: "PDF", bytes: [0x25, 0x50, 0x44, 0x46] },
  { name: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "RAR", bytes: [0x52, 0x61, 0x72, 0x21] },
  { name: "GZIP", bytes: [0x1f, 0x8b] },
  { name: "MFT FILE", bytes: [0x46, 0x49, 0x4c, 0x45] },
  { name: "EVTX", bytes: [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65] },
  { name: "regf", bytes: [0x72, 0x65, 0x67, 0x66] },
  { name: "BMP", bytes: [0x42, 0x4d] },
  { name: "7z", bytes: [0x37, 0x7a, 0xbc, 0xaf] },
  { name: "VHD", bytes: [0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78] },
  { name: "EWF", bytes: [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00] },
];

const SIGNATURE_COLORS = [
  "rgba(255, 213, 79, 0.45)",
  "rgba(129, 199, 132, 0.45)",
  "rgba(100, 181, 246, 0.45)",
  "rgba(186, 104, 200, 0.40)",
  "rgba(255, 138, 101, 0.45)",
];

/** Scan a byte array for signature offsets. Returns [{name, offset, length, colorIndex}]. */
export function scanSignatures(bytes, baseOffset = 0) {
  const hits = [];
  for (const signature of HEX_SIGNATURES) {
    const needle = signature.bytes;
    outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (bytes[i + j] !== needle[j]) continue outer;
      }
      hits.push({
        name: signature.name,
        offset: baseOffset + i,
        length: needle.length,
        colorIndex: hits.length % SIGNATURE_COLORS.length,
      });
    }
  }
  return hits.sort((a, b) => a.offset - b.offset);
}

/** Parse "aa bb cc" rows from the API into a Uint8Array. */
export function bytesFromHexRows(rows) {
  const out = [];
  for (const row of rows || []) {
    for (const token of String(row.hex || "").split(/\s+/)) {
      if (!token) continue;
      const value = Number.parseInt(token, 16);
      if (Number.isFinite(value)) out.push(value & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function parseOffsetInput(text) {
  const trimmed = String(text || "").trim().toLowerCase().replace(/^0x/, "");
  if (!trimmed) return null;
  const isHex = /[^0-9]/.test(trimmed) || String(text).trim().toLowerCase().startsWith("0x");
  const value = Number.parseInt(trimmed, isHex ? 16 : 10);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

const CELL = {
  rowHeight: 18,
  offsetWidthChars: 10,
  hexCellChars: 3,
  gapChars: 2,
  asciiStartPad: 1,
  font: "12px ui-monospace, Consolas, 'Courier New', monospace",
  colors: {
    offset: "#6b7280",
    hex: "#1f2937",
    ascii: "#374151",
    signatureText: "#7c2d12",
    rowDivider: "rgba(0,0,0,0.06)",
  },
};

/**
 * Draw one hex range onto a 2D context. Pure drawing — testable with a stub
 * ctx that records fillText/fillRect calls.
 */
export function drawHexRange(ctx, { bytes, baseOffset, signatures = [], charWidth = 7 }) {
  const rowCount = Math.ceil(bytes.length / BYTES_PER_ROW) || 1;
  const offsetX = 8;
  const hexX = offsetX + CELL.offsetWidthChars * charWidth;
  const asciiX = hexX + (BYTES_PER_ROW * CELL.hexCellChars + CELL.gapChars) * charWidth;
  const width = asciiX + BYTES_PER_ROW * charWidth + 16;
  const height = rowCount * CELL.rowHeight + 4;

  const hitByByte = new Map();
  for (const hit of signatures) {
    for (let i = 0; i < hit.length; i++) {
      hitByByte.set(hit.offset - baseOffset + i, hit);
    }
  }

  if (ctx.fillRect) {
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, width, height);
  }

  for (let row = 0; row < rowCount; row++) {
    const y = row * CELL.rowHeight;
    const rowBase = row * BYTES_PER_ROW;
    const absolute = baseOffset + rowBase;
    const rowBytes = bytes.slice(rowBase, rowBase + BYTES_PER_ROW);

    // Signature highlight bands (hex + ascii cells).
    if (ctx.fillRect) {
      for (let i = 0; i < rowBytes.length; i++) {
        const hit = hitByByte.get(rowBase + i);
        if (!hit) continue;
        ctx.fillStyle = SIGNATURE_COLORS[hit.colorIndex];
        ctx.fillRect(hexX + i * CELL.hexCellChars * charWidth - 1, y + 2, 2 * charWidth + 4, CELL.rowHeight - 3);
        ctx.fillRect(asciiX + i * charWidth - 1, y + 2, charWidth + 2, CELL.rowHeight - 3);
      }
      ctx.fillStyle = CELL.colors.rowDivider;
      ctx.fillRect(0, y + CELL.rowHeight - 1, width, 1);
    }

    if (ctx.fillText) {
      ctx.fillStyle = CELL.colors.offset;
      ctx.fillText(absolute.toString(16).padStart(8, "0"), offsetX, y + 13);
      ctx.fillStyle = CELL.colors.hex;
      for (let i = 0; i < rowBytes.length; i++) {
        const hit = hitByByte.get(rowBase + i);
        if (hit) ctx.fillStyle = CELL.colors.signatureText;
        ctx.fillText(rowBytes[i].toString(16).padStart(2, "0"), hexX + i * CELL.hexCellChars * charWidth, y + 13);
        if (hit) ctx.fillStyle = CELL.colors.hex;
      }
      ctx.fillStyle = CELL.colors.ascii;
      let ascii = "";
      for (let i = 0; i < rowBytes.length; i++) {
        const b = rowBytes[i];
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
      }
      ctx.fillText(ascii, asciiX, y + 13);
    }
  }
  return { width, height, rowCount };
}

export function renderHexViewerShell({ path, initialOffset = 0, pageLength = DEFAULT_PAGE_LENGTH } = {}) {
  return `
    <div class="hex-viewer" data-hex-viewer
         data-hex-path="${escapeHtml(path || "")}"
         data-hex-offset="${escapeHtml(String(initialOffset))}"
         data-hex-page="${escapeHtml(String(pageLength))}"
         role="region" aria-label="Interactive hex viewer">
      <div class="hex-toolbar">
        <button type="button" class="icon-action" data-hex-prev title="이전 범위">◀</button>
        <input type="text" class="hex-offset-input" data-hex-goto
               value="0x${Number(initialOffset).toString(16).padStart(8, "0")}"
               aria-label="오프셋 (hex 또는 10진수)" />
        <button type="button" class="icon-action" data-hex-go>이동</button>
        <button type="button" class="icon-action" data-hex-next title="다음 범위">▶</button>
        <select data-hex-size aria-label="범위 크기">
          ${[256, 512, 1024, 2048, 4096].map((n) => `<option value="${n}" ${n === pageLength ? "selected" : ""}>${n}B</option>`).join("")}
        </select>
        <span class="hex-status" data-hex-status aria-live="polite"></span>
      </div>
      <div class="hex-canvas-wrap">
        <canvas data-hex-canvas></canvas>
      </div>
      <div class="hex-legend" data-hex-legend></div>
      <p class="help-text">범위 읽기 전용 뷰어 — 파일 전체를 로드하지 않습니다. 시그니처 하이라이트: MZ·ZIP·SQLite·EVTX·FILE(MFT)·regf·EWF 등.</p>
    </div>
  `;
}

export class HexCanvasViewer {
  constructor({ root, fetchRange }) {
    this.root = root;
    this.fetchRange = fetchRange;
    this.path = root.dataset.hexPath || "";
    this.offset = Number(root.dataset.hexOffset) || 0;
    this.pageLength = Number(root.dataset.hexPage) || DEFAULT_PAGE_LENGTH;
    this.canvas = root.querySelector("[data-hex-canvas]");
    this.status = root.querySelector("[data-hex-status]");
    this.legend = root.querySelector("[data-hex-legend]");
    this.gotoInput = root.querySelector("[data-hex-goto]");
    this.bytes = new Uint8Array(0);
    this.signatures = [];
    this.destroyed = false;
    this._bind();
  }

  _bind() {
    const on = (sel, ev, fn) => this.root.querySelector(sel)?.addEventListener(ev, fn);
    on("[data-hex-prev]", "click", () => this.move(-this.pageLength));
    on("[data-hex-next]", "click", () => this.move(this.pageLength));
    on("[data-hex-go]", "click", () => this.goto(this.gotoInput?.value));
    on("[data-hex-goto]", "keydown", (event) => {
      if (event.key === "Enter") this.goto(this.gotoInput?.value);
    });
    on("[data-hex-size]", "change", (event) => {
      this.pageLength = Math.min(Number(event.target.value) || DEFAULT_PAGE_LENGTH, MAX_PAGE_LENGTH);
      this.load();
    });
  }

  async move(delta) {
    this.offset = Math.max(0, this.offset + delta);
    await this.load();
  }

  async goto(text) {
    const value = parseOffsetInput(text);
    if (value === null) {
      this._setStatus("오프셋 형식 오류");
      return;
    }
    this.offset = value;
    await this.load();
  }

  _setStatus(text) {
    if (this.status) this.status.textContent = text;
  }

  async load() {
    this._setStatus("로딩…");
    try {
      const payload = await this.fetchRange(this.path, this.offset, this.pageLength);
      if (this.destroyed) return;
      this.bytes = bytesFromHexRows(payload.rows);
      this.baseOffset = Number(payload.offset) || this.offset;
      this.signatures = scanSignatures(this.bytes, this.baseOffset);
      this.draw();
      this._setStatus(
        `${payload.offset_hex || ""} – ${payload.end_offset_exclusive_hex || ""} · ` +
        `${payload.length_returned ?? this.bytes.length}B · sha256 ${String(payload.range_hashes?.sha256 || "").slice(0, 12)}…`,
      );
      if (this.gotoInput) this.gotoInput.value = `0x${this.baseOffset.toString(16).padStart(8, "0")}`;
      this._renderLegend();
    } catch (error) {
      this._setStatus(`오류: ${error.message || error}`);
    }
  }

  draw() {
    const ctx = this.canvas?.getContext?.("2d");
    if (!ctx) return;
    const probe = ctx.measureText ? ctx.measureText("0").width : 0;
    const charWidth = probe > 2 ? probe : 7;
    const { width, height } = drawHexRange(ctx, {
      bytes: this.bytes,
      baseOffset: this.baseOffset ?? this.offset,
      signatures: this.signatures,
      charWidth,
    });
    this.canvas.width = Math.ceil(width);
    this.canvas.height = Math.ceil(height);
    // Redraw after resize (canvas resize clears pixels).
    drawHexRange(ctx, {
      bytes: this.bytes,
      baseOffset: this.baseOffset ?? this.offset,
      signatures: this.signatures,
      charWidth,
    });
  }

  _renderLegend() {
    if (!this.legend) return;
    if (!this.signatures.length) {
      this.legend.innerHTML = "";
      return;
    }
    this.legend.innerHTML = this.signatures
      .slice(0, 12)
      .map(
        (hit) => `<button type="button" class="hex-sig-chip" data-hex-sig-offset="${hit.offset}">
          <i style="background:${SIGNATURE_COLORS[hit.colorIndex]}"></i>${escapeHtml(hit.name)} @ 0x${hit.offset.toString(16)}
        </button>`,
      )
      .join("");
    for (const chip of this.legend.querySelectorAll("[data-hex-sig-offset]")) {
      chip.addEventListener("click", () => this.goto(`0x${Number(chip.dataset.hexSigOffset).toString(16)}`));
    }
  }

  destroy() {
    this.destroyed = true;
  }
}

/** Mount all declarative hex viewers under a container. Returns instances. */
export function mountHexViewers(container, fetchRange) {
  const viewers = [];
  for (const root of container.querySelectorAll("[data-hex-viewer]")) {
    const viewer = new HexCanvasViewer({ root, fetchRange });
    viewers.push(viewer);
    viewer.load();
  }
  return viewers;
}
