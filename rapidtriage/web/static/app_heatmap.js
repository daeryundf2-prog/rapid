// Interactive timeline density heatmap (R2-4).
//
// Renders the backend `timeline-histogram` response as a time x source
// density grid on <canvas>. Drag-selecting a horizontal span produces a
// time-range callback so the timeline/artifact views can be cross-filtered.
// Keyboard fallback: explicit start/end inputs plus apply/clear buttons.

import { escapeHtml } from "./app_utils.js";

const CELL_HEIGHT = 20;
const CELL_GAP = 1;
const AXIS_LEFT_CHARS = 14;
const AXIS_TOP = 26;
const PAD = 8;
const FONT = "11px ui-monospace, Consolas, 'Courier New', monospace";

const DENSITY_COLORS = [
  "rgba(219, 234, 254, 0.35)",
  "rgba(147, 197, 253, 0.55)",
  "rgba(96, 165, 250, 0.70)",
  "rgba(59, 130, 246, 0.85)",
  "rgba(29, 78, 216, 0.95)",
];

export function densityColor(count, maxCount) {
  if (!count || !maxCount) return DENSITY_COLORS[0];
  const ratio = Math.min(1, Math.log10(count + 1) / Math.log10(maxCount + 1));
  return DENSITY_COLORS[Math.min(DENSITY_COLORS.length - 1, Math.round(ratio * (DENSITY_COLORS.length - 1)))];
}

export function renderTimelineHeatmapShell() {
  return `
    <div class="timeline-heatmap" data-timeline-heatmap role="region" aria-label="타임라인 밀도 히트맵">
      <div class="heatmap-header">
        <strong>활동 밀도</strong>
        <span class="heatmap-hint">드래그로 시간 범위를 선택하면 현재 목록이 그 범위로 교차 필터됩니다.</span>
      </div>
      <canvas data-heatmap-canvas aria-label="시간 × 아티팩트 밀도"></canvas>
      <div class="heatmap-controls">
        <label>시작 <input type="text" data-heatmap-start placeholder="2024-01-01T00:00:00Z" /></label>
        <label>종료 <input type="text" data-heatmap-end placeholder="2024-01-02T00:00:00Z" /></label>
        <button type="button" class="icon-action" data-heatmap-apply>범위 적용</button>
        <button type="button" class="icon-action" data-heatmap-clear>해제</button>
        <span class="heatmap-status" data-heatmap-status aria-live="polite"></span>
      </div>
    </div>
  `;
}

/** Pure geometry: which bucket index does a canvas x coordinate map to? */
export function bucketIndexAtX(x, { bucketCount, cellWidth, axisLeft }) {
  const index = Math.floor((x - axisLeft) / (cellWidth + CELL_GAP));
  return index < 0 ? 0 : Math.min(bucketCount - 1, index);
}

export class TimelineHeatmap {
  /**
   * @param {HTMLElement} root  container from renderTimelineHeatmapShell()
   * @param {function} fetchHistogram  () -> Promise<histogram payload>
   * @param {function(string,string)} onRangeSelect  (startIso, endIso) -> void
   * @param {function} onRangeClear  () -> void
   */
  constructor({ root, fetchHistogram, onRangeSelect, onRangeClear }) {
    this.root = root;
    this.fetchHistogram = fetchHistogram;
    this.onRangeSelect = onRangeSelect;
    this.onRangeClear = onRangeClear;
    this.canvas = root.querySelector("[data-heatmap-canvas]");
    this.status = root.querySelector("[data-heatmap-status]");
    this.startInput = root.querySelector("[data-heatmap-start]");
    this.endInput = root.querySelector("[data-heatmap-end]");
    this.histogram = null;
    this.selection = null;
    this._dragStart = null;
    this.destroyed = false;
    this._bind();
  }

  _bind() {
    const applyBtn = this.root.querySelector("[data-heatmap-apply]");
    const clearBtn = this.root.querySelector("[data-heatmap-clear]");
    applyBtn?.addEventListener("click", () => this.applyInputs());
    clearBtn?.addEventListener("click", () => this.clear());
    for (const input of [this.startInput, this.endInput]) {
      input?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") this.applyInputs();
      });
    }
    this.canvas?.addEventListener("pointerdown", (event) => this._onPointerDown(event));
    this.canvas?.addEventListener("pointermove", (event) => this._onPointerMove(event));
    this.canvas?.addEventListener("pointerup", (event) => this._onPointerUp(event));
  }

  async load() {
    this._setStatus("히스토그램 로딩…");
    try {
      this.histogram = await this.fetchHistogram();
      if (this.destroyed) return;
      if (!this.histogram?.bucket_count) {
        this._setStatus("표시할 타임라인 이벤트 없음");
        this.root.classList.add("heatmap-empty");
        return;
      }
      this.draw();
      this._setStatus(
        `${this.histogram.parsed_events}건 / 버킷 ${this.histogram.bucket_count}개 (${this.histogram.bucket_seconds}s)`,
      );
    } catch (error) {
      this._setStatus(`오류: ${error.message || error}`);
    }
  }

  _layout() {
    const histogram = this.histogram || {};
    const sources = histogram.sources || [];
    const probe = this._ctx()?.measureText ? this._ctx().measureText("0").width : 0;
    const charWidth = probe > 2 ? probe : 7;
    const axisLeft = PAD + AXIS_LEFT_CHARS * charWidth;
    const cellWidth = 14;
    const width = axisLeft + (histogram.bucket_count || 1) * (cellWidth + CELL_GAP) + PAD;
    const height = AXIS_TOP + Math.max(1, sources.length) * (CELL_HEIGHT + CELL_GAP) + PAD;
    return { axisLeft, cellWidth, width, height, charWidth, sources };
  }

  _ctx() {
    return this.canvas?.getContext ? this.canvas.getContext("2d") : null;
  }

  draw() {
    const ctx = this._ctx();
    if (!ctx || !this.histogram) return;
    const { axisLeft, cellWidth, width, height, charWidth, sources } = this._layout();
    this.canvas.width = Math.ceil(width);
    this.canvas.height = Math.ceil(height);
    if (ctx.font !== undefined) ctx.font = FONT;

    const maxCount = this.histogram.max_bucket_count || 1;
    const buckets = this.histogram.buckets || [];
    const bucketCount = this.histogram.bucket_count || buckets.length;
    this._cellWidth = cellWidth;
    this._axisLeft = axisLeft;

    // Source row labels.
    sources.forEach((source, row) => {
      const y = AXIS_TOP + row * (CELL_HEIGHT + CELL_GAP);
      if (ctx.fillText) {
        ctx.fillStyle = "#475569";
        ctx.fillText(String(source.name || "").slice(0, AXIS_LEFT_CHARS - 1), PAD, y + 14);
      }
    });

    // Density cells.
    for (const bucket of buckets) {
      const x = axisLeft + bucket.index * (cellWidth + CELL_GAP);
      if (ctx.fillRect) {
        ctx.fillStyle = densityColor(bucket.count, maxCount);
        ctx.fillRect(x, AXIS_TOP - CELL_HEIGHT, cellWidth, CELL_HEIGHT);
      }
      sources.forEach((source, row) => {
        const count = (bucket.by_source || {})[source.name] || 0;
        if (ctx.fillRect) {
          ctx.fillStyle = densityColor(count, maxCount);
          ctx.fillRect(x, AXIS_TOP + row * (CELL_HEIGHT + CELL_GAP), cellWidth, CELL_HEIGHT);
        }
      });
    }

    // Time axis labels (start / end / mid).
    if (ctx.fillText) {
      ctx.fillStyle = "#64748b";
      const start = (this.histogram.range_start || "").slice(0, 10);
      const end = (this.histogram.range_end || "").slice(0, 10);
      ctx.fillText(start, axisLeft, AXIS_TOP - CELL_HEIGHT - 8);
      const endWidth = end.length * charWidth;
      ctx.fillText(end, axisLeft + bucketCount * (cellWidth + CELL_GAP) - endWidth - CELL_GAP, AXIS_TOP - CELL_HEIGHT - 8);
    }

    this._drawSelection();
  }

  _drawSelection() {
    const ctx = this._ctx();
    if (!ctx?.fillRect || !this.selection || !this.histogram) return;
    const { axisLeft, cellWidth, sources } = this._layout();
    const height = AXIS_TOP + Math.max(1, sources.length) * (CELL_HEIGHT + CELL_GAP);
    const x1 = axisLeft + this.selection.startIndex * (cellWidth + CELL_GAP);
    const x2 = axisLeft + (this.selection.endIndex + 1) * (cellWidth + CELL_GAP);
    ctx.fillStyle = "rgba(249, 115, 22, 0.22)";
    ctx.fillRect(x1, AXIS_TOP - CELL_HEIGHT, x2 - x1, height - AXIS_TOP + CELL_HEIGHT);
    if (ctx.strokeRect) {
      ctx.strokeStyle = "#f97316";
      ctx.strokeRect(x1, AXIS_TOP - CELL_HEIGHT, x2 - x1, height - AXIS_TOP + CELL_HEIGHT);
    }
  }

  _eventX(event) {
    const rect = this.canvas.getBoundingClientRect
      ? this.canvas.getBoundingClientRect()
      : { left: 0 };
    return event.clientX - rect.left;
  }

  _indexForEvent(event) {
    return bucketIndexAtX(this._eventX(event), {
      bucketCount: this.histogram?.bucket_count || 1,
      cellWidth: this._cellWidth || 14,
      axisLeft: this._axisLeft || 0,
    });
  }

  _onPointerDown(event) {
    if (!this.histogram?.bucket_count) return;
    this._dragStart = this._indexForEvent(event);
    event.preventDefault?.();
  }

  _onPointerMove(event) {
    if (this._dragStart === null) return;
    const current = this._indexForEvent(event);
    this.selection = {
      startIndex: Math.min(this._dragStart, current),
      endIndex: Math.max(this._dragStart, current),
    };
    this.draw();
  }

  _onPointerUp(event) {
    if (this._dragStart === null) return;
    this._onPointerMove(event);
    this._dragStart = null;
    this._emitSelection();
  }

  _emitSelection() {
    if (!this.selection || !this.histogram) return;
    const buckets = this.histogram.buckets || [];
    const start = buckets[this.selection.startIndex]?.start;
    const end = buckets[this.selection.endIndex]?.end;
    if (!start || !end) return;
    if (this.startInput) this.startInput.value = start;
    if (this.endInput) this.endInput.value = end;
    this._setStatus(`선택 범위 ${start.slice(0, 19)} ~ ${end.slice(0, 19)}`);
    this.onRangeSelect?.(start, end);
  }

  applyInputs() {
    const start = this.startInput?.value.trim();
    const end = this.endInput?.value.trim();
    if (!start || !end) {
      this._setStatus("시작/종료 시간을 모두 입력하세요.");
      return;
    }
    this.onRangeSelect?.(start, end);
    this._setStatus(`적용 범위 ${start.slice(0, 19)} ~ ${end.slice(0, 19)}`);
  }

  clear() {
    this.selection = null;
    if (this.startInput) this.startInput.value = "";
    if (this.endInput) this.endInput.value = "";
    this.draw();
    this._setStatus("범위 해제됨");
    this.onRangeClear?.();
  }

  _setStatus(text) {
    if (this.status) this.status.textContent = text;
  }

  destroy() {
    this.destroyed = true;
  }
}

export function mountTimelineHeatmap(container, fetchHistogram, { onRangeSelect, onRangeClear } = {}) {
  const root = container.querySelector("[data-timeline-heatmap]");
  if (!root) return null;
  const heatmap = new TimelineHeatmap({ root, fetchHistogram, onRangeSelect, onRangeClear });
  heatmap.load();
  return heatmap;
}
