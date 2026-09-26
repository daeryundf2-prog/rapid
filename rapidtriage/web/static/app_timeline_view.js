// TimelineView screen module (R3-2). Timeline table plus review-lane filters.
// Heatmap shell comes from app_heatmap.js directly; other helpers are injected
// via initTimelineView to keep this module acyclic.
import { escapeHtml, formatNumber } from "./app_utils.js";
import { renderTimelineHeatmapShell } from "./app_heatmap.js";

let bookmarkButton, compactRowFilterText, renderPaginationControls,
  renderPaginationNotice, rowInspectorAttributes, rowText;

export function initTimelineView(deps) {
  ({
    bookmarkButton, compactRowFilterText, renderPaginationControls,
    renderPaginationNotice, rowInspectorAttributes, rowText,
  } = deps);
}

export function renderTimeline(payload) {
  const rows = payload.events || [];
  const offset = payload.pagination?.offset || 0;
  if (!rows.length) return '<p class="empty-state">No timeline events.</p>';
  return `
    ${renderPaginationNotice(payload.pagination, "timeline")}
    ${renderTimelineHeatmapShell()}
    ${renderTimelineReviewLanes(payload)}
    <div class="review-list-shell" role="region" aria-label="Timeline result list">
      <table class="data-table">
        <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Summary</th><th></th></tr></thead>
        <tbody>
          ${rows.map((event, index) => {
            const pointer = `/events/${offset + index}`;
            const context = { source: "timeline", pointer, title: event.summary || "timeline event", note: event.summary || "", path: event.path || "", tags: ["timeline", event.source, event.event_type].filter(Boolean) };
            const inspector = {
              title: event.summary || "Timeline event",
              source: event.source || "timeline",
              kind: event.event_type || "event",
              timestamp: event.timestamp || "",
              path: event.path || "",
              pointer,
              preview: event.summary || "",
              chips: ["timeline", event.source, event.event_type].filter(Boolean),
              reviewContext: context,
            };
            return `
              <tr class="selectable-result-row" data-filter="${rowText(event)}" data-timeline-ts="${escapeHtml(event.timestamp || "")}" ${rowInspectorAttributes(inspector)} ${event.path ? `data-viewer-row-path="${escapeHtml(event.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}>
                <td>${escapeHtml(event.timestamp)}</td>
                <td>${escapeHtml(event.source)}</td>
                <td>${escapeHtml(event.event_type)}</td>
                <td><strong>${escapeHtml(event.summary)}</strong><span>${escapeHtml(event.path || "")}</span></td>
                <td>${bookmarkButton("timeline", pointer, event.summary)}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>
    ${renderPaginationControls(payload.pagination, "timeline")}
  `;
}

export function renderTimelineReviewLanes(payload) {
  const rows = payload.events || [];
  const lanes = [
    {
      label: "파일 생성/수정",
      filter: "file path modified created",
      terms: ["file", "path", "modified", "created", "mft", "usn"],
      hint: "문서 작성, 복사, 삭제 직전 파일 활동을 먼저 봅니다.",
    },
    {
      label: "웹·AI 활동",
      filter: "browser url ai chatgpt claude gemini perplexity",
      terms: ["browser", "url", "web", "ai", "chatgpt", "claude", "gemini", "perplexity"],
      hint: "검색, 다운로드, AI 프롬프트, 웹 접속 흐름을 모읍니다.",
    },
    {
      label: "윈도우 이벤트",
      filter: "evtx eventlog logon powershell defender",
      terms: ["evtx", "eventlog", "logon", "powershell", "defender", "wmi", "task"],
      hint: "로그온, 실행, 보안 이벤트를 시간순으로 확인합니다.",
    },
    {
      label: "외부장치/반출",
      filter: "usb shellbag mount drive external download",
      terms: ["usb", "shellbag", "mount", "drive", "external", "download"],
      hint: "USB 연결, 다운로드, 외부 저장장치 관련 단서를 봅니다.",
    },
    {
      label: "메신저/메일",
      filter: "chat kakao telegram whatsapp mail email attachment",
      terms: ["chat", "kakao", "telegram", "whatsapp", "mail", "email", "attachment"],
      hint: "대화, 메일, 첨부파일 흐름을 사건 시간에 맞춰 봅니다.",
    },
    {
      label: "삭제/위험",
      filter: "delete removed warning risk validation",
      terms: ["delete", "deleted", "removed", "warning", "risk", "validation"],
      hint: "삭제 흔적과 검증 경고가 있는 타임라인만 좁힙니다.",
    },
  ];
  return `
    <details class="tab-assist-drawer timeline-review-lanes" aria-label="타임라인 사건 재구성 레인" data-testid="timeline-review-lanes">
      <summary>
        <span>
          <em>시간 재구성</em>
          <strong>행위별 필터 ${formatNumber(lanes.length)}개 · 이벤트 ${formatNumber(rows.length)}개</strong>
        </span>
      </summary>
      <div class="tab-assist-body timeline-lane-grid">
        ${lanes.map((lane) => {
          const count = rows.filter((row) => lane.terms.some((term) => compactRowFilterText(row).includes(term))).length;
          return `
            <button class="secondary-button timeline-lane-card" type="button" data-timeline-lane-filter="${escapeHtml(lane.filter)}" title="${escapeHtml(lane.hint)}">
              <span>${escapeHtml(lane.label)}</span>
              <b>${formatNumber(count)}</b>
              <em>${escapeHtml(lane.hint)}</em>
            </button>
          `;
        }).join("")}
      </div>
    </details>
  `;
}
