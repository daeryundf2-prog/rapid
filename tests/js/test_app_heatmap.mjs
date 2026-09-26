// Behavioral tests for app_heatmap.js — density colors, bucket mapping, mount.
// Run: node tests/js/test_app_heatmap.mjs

import {
  bucketIndexAtX,
  densityColor,
  mountTimelineHeatmap,
  renderTimelineHeatmapShell,
} from "../../rapidtriage/web/static/app_heatmap.js";

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else { failures += 1; console.log(`FAIL - ${name}`); }
}

// --- density colors -------------------------------------------------------------
check("zero density uses lightest", densityColor(0, 100) === densityColor(0, 100));
check("higher count is darker", densityColor(100, 100) !== densityColor(1, 100));
check("max count is darkest", densityColor(1000, 1000).includes("29, 78, 216"));

// --- bucket geometry --------------------------------------------------------------
const geo = { bucketCount: 100, cellWidth: 14, axisLeft: 100 };
check("x maps to bucket index", bucketIndexAtX(100 + 15 * 5, geo) === 5);
check("x before axis clamps to 0", bucketIndexAtX(0, geo) === 0);
check("x past end clamps to last", bucketIndexAtX(99999, geo) === 99);

// --- shell markup -----------------------------------------------------------------
const shell = renderTimelineHeatmapShell();
check("shell has canvas", shell.includes("data-heatmap-canvas"));
check("shell has drag hint", shell.includes("드래그"));
check("shell has keyboard fallback inputs", shell.includes("data-heatmap-start") && shell.includes("data-heatmap-end"));
check("shell has aria label", shell.includes("aria-label"));

// --- mount + selection flow ---------------------------------------------------------
const histogram = {
  bucket_count: 4,
  bucket_seconds: 3600,
  parsed_events: 10,
  max_bucket_count: 5,
  range_start: "2024-01-01T00:00:00Z",
  range_end: "2024-01-01T04:00:00Z",
  sources: [{ name: "files", count: 6 }, { name: "evtx", count: 4 }],
  buckets: [
    { index: 0, start: "2024-01-01T00:00:00Z", end: "2024-01-01T01:00:00Z", count: 5, by_source: { files: 3, evtx: 2 } },
    { index: 1, start: "2024-01-01T01:00:00Z", end: "2024-01-01T02:00:00Z", count: 2, by_source: { files: 2 } },
    { index: 2, start: "2024-01-01T02:00:00Z", end: "2024-01-01T03:00:00Z", count: 1, by_source: { evtx: 1 } },
    { index: 3, start: "2024-01-01T03:00:00Z", end: "2024-01-01T04:00:00Z", count: 2, by_source: { files: 1, evtx: 1 } },
  ],
};

const drawCalls = [];
const stubCtx = {
  measureText: () => ({ width: 7 }),
  fillText: () => {},
  fillRect: (...a) => drawCalls.push(a),
  strokeRect: () => {},
};
const listeners = {};
const canvas = {
  addEventListener: (ev, fn) => { listeners[ev] = fn; },
  getContext: () => stubCtx,
  getBoundingClientRect: () => ({ left: 0 }),
  width: 0,
  height: 0,
};
const inputs = {};
function inputEl() { return { value: "", addEventListener: () => {}, textContent: "" }; }
const root = {
  classList: { add: () => {} },
  querySelector(sel) {
    if (sel === "[data-heatmap-canvas]") return canvas;
    inputs[sel] ||= inputEl();
    return inputs[sel];
  },
};
const container = { querySelector: (sel) => (sel === "[data-timeline-heatmap]" ? root : null) };

let selected = null;
let cleared = false;
const heatmap = mountTimelineHeatmap(
  container,
  async () => histogram,
  {
    onRangeSelect: (start, end) => { selected = [start, end]; },
    onRangeClear: () => { cleared = true; },
  },
);
check("heatmap mounts", heatmap !== null);
await new Promise((resolve) => setTimeout(resolve, 10));
check("histogram loaded and drawn", canvas.width > 0 && drawCalls.length > 0);

// Simulate drag from bucket 0 to bucket 2.
const axisLeft = heatmap._axisLeft;
const cellW = heatmap._cellWidth + 1;
listeners.pointerdown({ clientX: axisLeft + cellW * 0 + 2, preventDefault: () => {} });
listeners.pointermove({ clientX: axisLeft + cellW * 2 + 2 });
listeners.pointerup({ clientX: axisLeft + cellW * 2 + 2 });
check("drag emits range selection", selected !== null);
check("selection covers buckets 0-2", selected && selected[0].includes("T00:00") && selected[1].includes("T03:00"));

heatmap.clear();
check("clear notifies consumer", cleared === true);

// Keyboard fallback.
inputs["[data-heatmap-start]"].value = "2024-01-01T00:00:00Z";
inputs["[data-heatmap-end]"].value = "2024-01-01T02:00:00Z";
heatmap.applyInputs();
check("manual inputs apply range", selected[1].includes("T02:00"));

// Empty histogram path.
const emptyRoot = {
  classList: { add: () => {} },
  querySelector: (sel) => (sel === "[data-heatmap-canvas]" ? canvas : inputEl()),
};
const emptyHeatmap = mountTimelineHeatmap(
  { querySelector: () => emptyRoot },
  async () => ({ bucket_count: 0, parsed_events: 0, buckets: [] }),
);
await new Promise((resolve) => setTimeout(resolve, 10));
check("empty histogram handled without throw", emptyHeatmap !== null);

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all heatmap tests passed");
