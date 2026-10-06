// ES module — server-side filesystem browser for picking evidence roots and
// output directories. Talks to GET /api/browse (token-gated like every API).
import { api } from "./app_api.js";
import { escapeHtml, formatBytes } from "./app_utils.js";

let overlay = null;
let currentPath = "";
let selectMode = "any"; // "any" = files+dirs (evidence), "dir" = dirs only (output)
let onSelect = null;

function ensureOverlay() {
  if (overlay) return overlay;
  overlay = document.createElement("div");
  overlay.id = "browseOverlay";
  overlay.className = "browse-overlay";
  overlay.hidden = true;
  overlay.innerHTML = `
    <div class="browse-dialog" role="dialog" aria-modal="true" aria-label="경로 선택">
      <div class="browse-head">
        <button type="button" id="browseUp" class="secondary-button" title="상위 폴더">↑ 상위</button>
        <span id="browsePath" class="browse-path" title=""></span>
        <button type="button" id="browseClose" class="secondary-button">닫기</button>
      </div>
      <div id="browseStatus" class="browse-status"></div>
      <ul id="browseList" class="browse-list" tabindex="0"></ul>
      <div class="browse-foot">
        <button type="button" id="browseSelect" class="primary-button">선택</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector("#browseClose").addEventListener("click", closeBrowse);
  overlay.querySelector("#browseUp").addEventListener("click", () => {
    const parent = overlay.dataset.parent || "";
    if (parent) loadDir(parent);
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeBrowse();
  });
  overlay.querySelector("#browseSelect").addEventListener("click", () => {
    if (!currentPath || !onSelect) return;
    onSelect(currentPath);
    closeBrowse();
  });
  return overlay;
}

function closeBrowse() {
  if (overlay) overlay.hidden = true;
  onSelect = null;
}

async function loadDir(path) {
  const el = ensureOverlay();
  const list = el.querySelector("#browseList");
  const status = el.querySelector("#browseStatus");
  status.textContent = "불러오는 중…";
  list.innerHTML = "";
  try {
    const data = await api(`/api/browse${path ? `?path=${encodeURIComponent(path)}` : ""}`);
    currentPath = data.path || "";
    el.dataset.parent = data.parent || "";
    el.querySelector("#browsePath").textContent = currentPath || "내 컴퓨터";
    el.querySelector("#browsePath").title = currentPath;
    el.querySelector("#browseUp").disabled = !data.parent;
    const entries = Array.isArray(data.entries) ? data.entries : [];
    if (!entries.length) {
      status.textContent = "폴더가 비어 있습니다";
      return;
    }
    status.textContent = `${entries.length}개 항목`;
    for (const entry of entries) {
      const li = document.createElement("li");
      const isDir = Boolean(entry.is_dir);
      li.className = `browse-entry ${isDir ? "is-dir" : "is-file"}`;
      const sizeText = isDir ? "" : `<span class="browse-size">${escapeHtml(formatBytes(entry.size || 0))}</span>`;
      li.innerHTML = `<span class="browse-icon" aria-hidden="true">${isDir ? "📁" : "📄"}</span><span class="browse-name">${escapeHtml(entry.name)}</span>${sizeText}`;
      if (isDir) {
        li.addEventListener("dblclick", () => loadDir(entry.path));
        li.addEventListener("click", () => loadDir(entry.path));
      } else {
        li.addEventListener("click", () => {
          if (selectMode === "dir") return;
          currentPath = entry.path;
          list.querySelectorAll(".browse-entry.selected").forEach((n) => n.classList.remove("selected"));
          li.classList.add("selected");
        });
        li.addEventListener("dblclick", () => {
          if (selectMode === "dir") return;
          currentPath = entry.path;
          if (onSelect) {
            onSelect(currentPath);
            closeBrowse();
          }
        });
      }
      if (isDir && selectMode === "dir") {
        // allow choosing the folder itself via a pick affordance
        li.title = "폴더 열기 — 이 폴더를 선택하려면 하단 '선택' 버튼";
      }
      list.appendChild(li);
    }
  } catch (error) {
    status.textContent = `불러오기 실패: ${error.message || error}`;
  }
}

/** Open the browser. opts.mode: "any" (file or dir) | "dir". */
export function openBrowse(targetInput, opts = {}) {
  const el = ensureOverlay();
  selectMode = opts.mode === "dir" ? "dir" : "any";
  el.querySelector("#browseSelect").textContent =
    selectMode === "dir" ? "이 폴더 선택" : "선택";
  onSelect = (path) => {
    if (targetInput) {
      targetInput.value = path;
      targetInput.dispatchEvent(new Event("input", { bubbles: true }));
      targetInput.dispatchEvent(new Event("change", { bubbles: true }));
    }
  };
  el.hidden = false;
  const seed = (targetInput && targetInput.value.trim()) || "";
  loadDir(seed || "");
}

export function bindBrowseButton(button, targetInput, opts = {}) {
  if (!button || !targetInput) return;
  button.addEventListener("click", () => openBrowse(targetInput, opts));
}
