// Cross-device IOC card (R4-2). Loads /api/ioc/cross-device for the current
// run set and renders shared indicators + movement hints with per-run source
// provenance. Correlation candidates only — not attribution.
import { escapeHtml, formatNumber } from "./app_utils.js";

export function renderCrossDeviceIocShell() {
  return `
    <details class="cross-device-ioc-card" data-testid="cross-device-ioc" aria-label="Cross-device IOC correlation">
      <summary>
        <span>
          <em>교차 장비 IOC</em>
          <strong data-ioc-summary>실행 간 공통 지표 상관 분석</strong>
        </span>
      </summary>
      <div class="cross-device-ioc-body">
        <p class="empty-state" data-ioc-empty>Cross-device correlation has not been loaded.</p>
        <div class="ioc-shared-list" data-ioc-shared hidden></div>
        <div class="ioc-movement-list" data-ioc-movement hidden></div>
        <p class="help-text" data-ioc-boundary hidden></p>
      </div>
    </details>
  `;
}

function renderSharedIoc(item) {
  const sightings = (item.sightings || [])
    .map(
      (sighting) => `
        <li>
          <strong>${escapeHtml(sighting.device_label || sighting.run_id)}</strong>
          <span>${escapeHtml(`×${sighting.count}`)}</span>
          ${(sighting.sources || [])
            .slice(0, 2)
            .map((source) => `<code>${escapeHtml(source.path || source.pointer || source.artifact || "")}</code>`)
            .join("")}
        </li>`,
    )
    .join("");
  return `
    <article class="ioc-shared-item" data-ioc-type="${escapeHtml(item.type)}">
      <header>
        <strong>${escapeHtml(item.value)}</strong>
        <span>${escapeHtml(item.type)} · ${formatNumber(item.run_count)}개 실행 · ${formatNumber(item.total_count)}건</span>
        ${item.movement_significant ? '<em class="ioc-movement-flag">이동 단서 후보</em>' : ""}
      </header>
      <ul class="ioc-sightings">${sightings}</ul>
    </article>
  `;
}

export function mountCrossDeviceIoc(container, fetchPackage) {
  const card = container.querySelector("[data-testid='cross-device-ioc']");
  if (!card) return;
  const empty = card.querySelector("[data-ioc-empty]");
  const sharedBox = card.querySelector("[data-ioc-shared]");
  const movementBox = card.querySelector("[data-ioc-movement]");
  const boundary = card.querySelector("[data-ioc-boundary]");
  const summary = card.querySelector("[data-ioc-summary]");
  card.addEventListener(
    "toggle",
    () => {
      if (!card.open || card.dataset.loaded) return;
      card.dataset.loaded = "1";
      Promise.resolve(fetchPackage())
        .then((payload) => {
          const shared = payload.shared_iocs || [];
          const hints = payload.movement_hints || [];
          summary.textContent = `공통 IOC ${formatNumber(shared.length)}건 · 이동 힌트 ${formatNumber(hints.length)}건 · 대상 실행 ${formatNumber(payload.summary?.run_count || 0)}개`;
          if (!shared.length) {
            empty.textContent = "실행 간 공통 IOC가 없습니다. 단일 실행이거나 공유 지표가 없습니다.";
            return;
          }
          empty.hidden = true;
          sharedBox.hidden = false;
          sharedBox.innerHTML = shared.map(renderSharedIoc).join("");
          if (hints.length) {
            movementBox.hidden = false;
            movementBox.innerHTML = hints
              .map(
                (hint) => `
                  <div class="ioc-movement-item">
                    <strong>${escapeHtml(hint.hint)}</strong>
                    <span>${escapeHtml((hint.devices || []).join(" ↔ "))}</span>
                  </div>`,
              )
              .join("");
          }
          if (payload.report_use_boundary) {
            boundary.hidden = false;
            boundary.textContent = payload.report_use_boundary;
          }
        })
        .catch(() => {
          empty.textContent = "교차 장비 IOC 로드 실패 — 서버 상태를 확인하세요.";
        });
    },
    { once: false },
  );
}
