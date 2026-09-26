// True DOM virtualization for large result tables.
//
// Clusterize-style approach that keeps <table> semantics: the tbody holds a
// top spacer row, a rendered window (~overscan beyond the viewport), and a
// bottom spacer row. Unmounted rows cost zero DOM nodes, so a 100k-row
// result set scrolls at display rate while only ~40-80 <tr> elements exist.
//
// Row heights are dynamic: unmeasured rows use estimatedRowHeight, mounted
// rows are measured after insertion and their real heights flow back into
// the height model on the next window calculation.

const DEFAULT_ESTIMATED_ROW_HEIGHT = 64;
const DEFAULT_OVERSCAN = 8;
const SPACER_ATTR = "data-virtual-spacer";

export class VirtualTable {
  /**
   * @param {HTMLTableSectionElement} tbody   Table body to virtualize.
   * @param {HTMLElement} scroller            Scrollable ancestor (overflow-y).
   * @param {number} colCount                 Column count for spacer cells.
   * @param {function(any, number): string} renderRow  index -> "<tr>...</tr>".
   * @param {object} options
   *   estimatedRowHeight, overscan, filter(item)->bool,
   *   onNeedMore(visibleEndIndex)->void (infinite paging hook),
   *   onRendered(startIndex,endIndex)->void.
   */
  constructor({ tbody, scroller, colCount, renderRow, ...options }) {
    this.tbody = tbody;
    this.colCount = Math.max(1, Number(colCount) || 1);
    this.renderRow = renderRow;
    this.estimatedRowHeight = Number(options.estimatedRowHeight) || DEFAULT_ESTIMATED_ROW_HEIGHT;
    this.overscan = Math.max(1, Number(options.overscan) || DEFAULT_OVERSCAN);
    this.filter = typeof options.filter === "function" ? options.filter : null;
    this.onNeedMore = typeof options.onNeedMore === "function" ? options.onNeedMore : null;
    this.onRendered = typeof options.onRendered === "function" ? options.onRendered : null;

    this.items = [];
    this.filtered = [];
    this.heights = new Float64Array(0);
    this.positions = new Float64Array(0);
    this.dirtyPositions = true;
    this.scrollTop = 0;
    this.viewportHeight = 0;
    this.renderedRange = { start: -1, end: -1 };
    this.destroyed = false;
    this._rafId = 0;
    this._resizeObserver = null;

    this.scroller = scroller || this._findScroller();
    this._onScroll = () => this._scheduleRender();
    if (this.scroller) {
      this.scroller.addEventListener("scroll", this._onScroll, { passive: true });
    }
    if (typeof ResizeObserver !== "undefined" && this.scroller) {
      this._resizeObserver = new ResizeObserver(() => this._scheduleRender());
      this._resizeObserver.observe(this.scroller);
    }
  }

  _findScroller() {
    let node = this.tbody.parentElement;
    while (node) {
      const style = window.getComputedStyle(node);
      if (/(auto|scroll)/.test(style.overflowY)) return node;
      node = node.parentElement;
    }
    return null;
  }

  setItems(items) {
    this.items = Array.isArray(items) ? items : [];
    this._applyFilter();
  }

  appendItems(items) {
    if (!items?.length) return;
    this.items = this.items.concat(items);
    this._applyFilter();
  }

  setFilter(predicate) {
    this.filter = typeof predicate === "function" ? predicate : null;
    this._applyFilter();
    this.refresh();
  }

  get count() {
    return this.filtered.length;
  }

  _applyFilter() {
    this.filtered = this.filter ? this.items.filter(this.filter) : this.items.slice();
    this.heights = new Float64Array(this.filtered.length).fill(this.estimatedRowHeight);
    this.positions = new Float64Array(this.filtered.length + 1);
    this.dirtyPositions = true;
    this.renderedRange = { start: -1, end: -1 };
    this._renderWindow();
  }

  _ensurePositions() {
    if (!this.dirtyPositions) return;
    const positions = this.positions;
    const heights = this.heights;
    positions[0] = 0;
    for (let i = 0; i < heights.length; i++) {
      positions[i + 1] = positions[i] + heights[i];
    }
    this.dirtyPositions = false;
  }

  _indexAtOffset(offset) {
    this._ensurePositions();
    const positions = this.positions;
    let lo = 0;
    let hi = this.filtered.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (positions[mid + 1] <= offset) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  _scheduleRender() {
    if (this.destroyed || this._rafId) return;
    this._rafId = window.requestAnimationFrame(() => {
      this._rafId = 0;
      this._renderWindow();
    });
  }

  refresh() {
    this.renderedRange = { start: -1, end: -1 };
    this._renderWindow();
  }

  scrollToIndex(index) {
    this._ensurePositions();
    const target = Math.max(0, Math.min(index, this.filtered.length - 1));
    if (this.scroller) {
      this.scroller.scrollTop = this.positions[target];
    }
    this._renderWindow();
  }

  _renderWindow() {
    if (this.destroyed || !this.tbody.isConnected) return;
    this._ensurePositions();
    const total = this.filtered.length;
    const scrollTop = this.scroller ? this.scroller.scrollTop : 0;
    const viewportHeight = this.scroller ? this.scroller.clientHeight : 600;
    this.scrollTop = scrollTop;
    this.viewportHeight = viewportHeight;

    if (!total) {
      this.tbody.innerHTML = "";
      this.renderedRange = { start: 0, end: 0 };
      if (this.onRendered) this.onRendered(0, 0);
      return;
    }

    const firstVisible = this._indexAtOffset(scrollTop);
    let endIndex = this._indexAtOffset(scrollTop + viewportHeight);
    endIndex = Math.min(total - 1, endIndex + 1);
    const start = Math.max(0, firstVisible - this.overscan);
    const end = Math.min(total - 1, endIndex + this.overscan);

    if (start === this.renderedRange.start && end === this.renderedRange.end) {
      return;
    }

    const top = this.positions[start];
    const bottom = this.positions[total] - this.positions[end + 1];
    const rows = [];
    for (let i = start; i <= end; i++) {
      rows.push(this.renderRow(this.filtered[i], i));
    }
    this.tbody.innerHTML = `
      <tr ${SPACER_ATTR} aria-hidden="true"><td colspan="${this.colCount}" style="height:${top}px;padding:0;border:0"></td></tr>
      ${rows.join("")}
      <tr ${SPACER_ATTR} aria-hidden="true"><td colspan="${this.colCount}" style="height:${bottom}px;padding:0;border:0"></td></tr>
    `;
    this.renderedRange = { start, end };

    // Feed measured heights back into the model so positions converge on
    // real row heights even when content height varies per row.
    let measured = false;
    const mounted = this.tbody.querySelectorAll(`tr:not([${SPACER_ATTR}])`);
    mounted.forEach((row, i) => {
      const index = start + i;
      if (index > end) return;
      const actual = row.getBoundingClientRect().height;
      if (actual > 0 && Math.abs(actual - this.heights[index]) > 1) {
        this.heights[index] = actual;
        measured = true;
      }
    });
    if (measured) this.dirtyPositions = true;

    if (this.onRendered) this.onRendered(firstVisible, endIndex);
    if (this.onNeedMore && endIndex >= total - this.overscan * 2) {
      this.onNeedMore(endIndex, this);
    }
  }

  destroy() {
    this.destroyed = true;
    if (this._rafId) window.cancelAnimationFrame(this._rafId);
    if (this.scroller) this.scroller.removeEventListener("scroll", this._onScroll);
    if (this._resizeObserver) this._resizeObserver.disconnect();
  }
}

/** Registry so workbench filter reruns can refresh live virtual tables. */
const registry = new Map();

export function registerVirtualTable(key, table) {
  const existing = registry.get(key);
  if (existing && existing !== table) existing.destroy();
  registry.set(key, table);
  return table;
}

export function getVirtualTable(key) {
  return registry.get(key) || null;
}

export function refreshVirtualTables() {
  for (const table of registry.values()) table.refresh();
}

export function applyVirtualTableFilter(key, predicate) {
  const table = registry.get(key);
  if (table) table.setFilter(predicate);
}

export function clearVirtualTables() {
  for (const table of registry.values()) table.destroy();
  registry.clear();
}
