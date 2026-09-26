// Power-reviewer keyboard workflow (R2-5): J/K·B·R·E·1~5.
//
// A single "current row" cursor moves through the active result list —
// including virtualized tables, where the cursor is a filtered-list index and
// the table is scrolled to mount the target row. Row actions reuse the same
// bookmark/review API the on-screen buttons call, so keyboard and mouse paths
// stay consistent.
//
//   J / K   — next / previous review row
//   B       — bookmark (선별) current row
//   R       — mark relevant + include in report
//   E       — open evidence/source preview for current row
//   1 ~ 5   — toggle priority tag p1..p5 on current row (view-group switch
//             remains active when no row cursor exists)

export const REVIEWER_PRIORITY_TAGS = ["p1", "p2", "p3", "p4", "p5"];
const FOCUS_CLASS = "kb-focus";

export class PowerReviewer {
  /**
   * @param {object} deps
   *   detailPanel() -> HTMLElement
   *   activeTab()   -> string
   *   runId()       -> string|null
   *   api(path, options) -> Promise
   *   getVirtualTable(key) -> VirtualTable|null
   *   openPreview(path, reviewContext) -> void
   *   onStatus(text) -> void
   */
  constructor(deps) {
    this.deps = deps;
    this.cursor = -1; // first j selects row 0, vim-style
    this.tagState = new Map(); // pointer -> Set(active priority tags)
  }

  /** Reset cursor when the list surface changes. */
  reset() {
    this.cursor = -1;
  }

  _key() {
    return `${this.deps.activeTab()}`;
  }

  _virtualTable() {
    const tab = this.deps.activeTab();
    if (tab === "artifacts" || tab === "search") {
      return this.deps.getVirtualTable(tab);
    }
    return null;
  }

  /** Row elements that belong to the active list (mounted rows only). */
  _mountedRows() {
    const panel = this.deps.detailPanel();
    if (!panel) return [];
    return [...panel.querySelectorAll(".selectable-result-row, tbody tr[data-filter]")].filter(
      (row) => !row.hidden && !row.dataset.virtualSpacer,
    );
  }

  _rowCount() {
    const table = this._virtualTable();
    if (table) return table.count;
    return this._mountedRows().length;
  }

  _rowAtCursor() {
    const table = this._virtualTable();
    if (table) {
      return this.deps
        .detailPanel()
        ?.querySelector(`tr[data-vindex="${this.cursor}"]`) || null;
    }
    const rows = this._mountedRows();
    return rows[Math.min(this.cursor, rows.length - 1)] || null;
  }

  _focusRow(row) {
    const panel = this.deps.detailPanel();
    if (!panel) return;
    for (const el of panel.querySelectorAll(`.${FOCUS_CLASS}`)) {
      el.classList.remove(FOCUS_CLASS);
      el.removeAttribute("aria-current");
    }
    if (row) {
      row.classList.add(FOCUS_CLASS);
      row.setAttribute("aria-current", "true");
      row.scrollIntoView?.({ block: "nearest" });
    }
  }

  async move(delta) {
    const count = this._rowCount();
    if (!count) return false;
    this.cursor = Math.max(0, Math.min(this.cursor + delta, count - 1));
    const table = this._virtualTable();
    if (table) {
      table.scrollToIndex(this.cursor);
      // Row mounts on the next render pass; highlight once it lands.
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    this._focusRow(this._rowAtCursor());
    this._announce(`행 ${this.cursor + 1}/${count}`);
    return true;
  }

  /** Extract bookmark/review context from the focused row. */
  currentContext() {
    const row = this._rowAtCursor();
    if (!row) return null;
    let context = null;
    if (row.dataset.reviewContext) {
      try {
        context = JSON.parse(row.dataset.reviewContext);
      } catch {
        context = null;
      }
    }
    const bookmark = row.querySelector("[data-bookmark-source]");
    const path = row.dataset.viewerRowPath || "";
    return {
      path,
      source: context?.source || bookmark?.dataset.bookmarkSource || "",
      pointer: context?.pointer || bookmark?.dataset.bookmarkPointer || "",
      note: context?.note || bookmark?.dataset.bookmarkNote || "",
      title: context?.title || "",
      row,
    };
  }

  async bookmark() {
    const context = this.currentContext();
    if (!context?.source || !context?.pointer) return false;
    // Prefer the row's own bookmark button so mouse/keyboard semantics match.
    const button = context.row.querySelector("[data-bookmark-source]");
    if (button) {
      button.click();
      this._announce("선별");
      return true;
    }
    await this._postBookmark({ source: context.source, pointer: context.pointer, note: context.note });
    this._announce("선별");
    return true;
  }

  async markRelevantForReport() {
    const context = this.currentContext();
    if (!context?.source || !context?.pointer) return false;
    await this._postBookmark({
      source: context.source,
      pointer: context.pointer,
      note: context.note,
      review_status: "relevant",
      include_in_report: true,
    });
    this._announce("관련 있음 · 보고서 포함");
    return true;
  }

  openPreview() {
    const context = this.currentContext();
    if (!context?.path) return false;
    this.deps.openPreview(context.path, {
      source: context.source,
      pointer: context.pointer,
      title: context.title,
      note: context.note,
    });
    this._announce("원본 미리보기");
    return true;
  }

  /** Toggle priority tag pN on the current row. Returns true when consumed. */
  async togglePriorityTag(digit) {
    const context = this.currentContext();
    if (!context?.source || !context?.pointer) return false;
    const tag = REVIEWER_PRIORITY_TAGS[digit - 1];
    if (!tag) return false;
    const key = `${context.source}:${context.pointer}`;
    const active = this.tagState.get(key) || new Set();
    const request = { source: context.source, pointer: context.pointer, note: context.note };
    if (active.has(tag)) {
      active.delete(tag);
      request.remove_tags = [tag];
    } else {
      active.add(tag);
      request.tags = [tag];
    }
    await this._postBookmark(request);
    this.tagState.set(key, active);
    this._announce(`태그 ${tag} ${active.has(tag) ? "설정" : "해제"}`);
    return true;
  }

  async _postBookmark(request) {
    const runId = this.deps.runId();
    if (!runId) return;
    await this.deps.api(`/api/runs/${encodeURIComponent(runId)}/bookmarks`, {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  _announce(text) {
    this.deps.onStatus?.(text);
  }

  /**
   * Route a bare (no-modifier) keypress. Returns true when the key was
   * consumed by the power-reviewer workflow.
   */
  async handleKey(key) {
    const lowered = key.toLowerCase();
    if (lowered === "j") return this.move(1);
    if (lowered === "k") return this.move(-1);
    if (lowered === "b") return this.bookmark();
    if (lowered === "r") return this.markRelevantForReport();
    if (lowered === "e") return this.openPreview();
    if (/^[1-5]$/.test(lowered)) return this.togglePriorityTag(Number(lowered));
    return false;
  }
}
