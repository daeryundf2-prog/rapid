// Behavioral tests for app_shortcuts.js — J/K/B/R/E/1~5 power reviewer flow.
// Run: node tests/js/test_app_shortcuts.mjs

import { PowerReviewer, REVIEWER_PRIORITY_TAGS } from "../../rapidtriage/web/static/app_shortcuts.js";

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else { failures += 1; console.log(`FAIL - ${name}`); }
}

function makeRow({ path = "", source = "search", pointer = "/x/0", note = "n", vindex = null } = {}) {
  const classes = new Set(["selectable-result-row"]);
  const el = {
    hidden: false,
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
    },
    dataset: {
      viewerRowPath: path,
      reviewContext: JSON.stringify({ source, pointer, note, title: "t" }),
    },
    scrollTop: 0,
    attrs: {},
    setAttribute(k, v) { this.attrs[k] = v; },
    removeAttribute(k) { delete this.attrs[k]; },
    scrollIntoView() {},
    querySelector() { return null; },
  };
  if (vindex !== null) el.dataset.vindex = String(vindex);
  return el;
}

// --- DOM stub: static rows -------------------------------------------------
const rows = [
  makeRow({ path: "a.txt", pointer: "/docs/0" }),
  makeRow({ path: "b.txt", pointer: "/docs/1" }),
  makeRow({ path: "c.txt", pointer: "/docs/2" }),
];
const panel = {
  querySelectorAll(sel) {
    if (sel.includes("selectable-result-row") || sel.includes("tr[data-filter]")) return rows;
    if (sel === ".kb-focus") return rows.filter((r) => r.classList.contains("kb-focus"));
    return [];
  },
  querySelector() { return null; },
};

const posts = [];
let previewed = null;
const reviewer = new PowerReviewer({
  detailPanel: () => panel,
  activeTab: () => "docs",
  runId: () => "run-1",
  api: async (path, options) => { posts.push({ path, body: JSON.parse(options.body || "{}") }); return {}; },
  getVirtualTable: () => null,
  openPreview: (path, ctx) => { previewed = { path, ctx }; },
  onStatus: () => {},
});

// --- J/K navigation ------------------------------------------------------------
check("j moves cursor down", await reviewer.handleKey("j") === true);
check("row gets kb-focus", rows[0].classList.contains("kb-focus"));
await reviewer.handleKey("j");
check("second j focuses next row", rows[1].classList.contains("kb-focus") && !rows[0].classList.contains("kb-focus"));
await reviewer.handleKey("k");
check("k moves cursor up", rows[0].classList.contains("kb-focus"));

// --- B bookmark -------------------------------------------------------------------
await reviewer.handleKey("b");
check("b posts bookmark", posts.length === 1 && posts[0].body.source === "search" && posts[0].body.pointer === "/docs/0");

// --- R report -----------------------------------------------------------------------
await reviewer.handleKey("r");
check("r posts relevant+report", posts.at(-1).body.review_status === "relevant" && posts.at(-1).body.include_in_report === true);

// --- E preview ------------------------------------------------------------------------
await reviewer.handleKey("e");
check("e opens preview", previewed?.path === "a.txt" && previewed?.ctx.pointer === "/docs/0");

// --- digits: tag toggle ---------------------------------------------------------------
posts.length = 0;
await reviewer.handleKey("3");
check("digit posts priority tag", posts[0].body.tags?.includes("p3"));
await reviewer.handleKey("3");
check("second digit removes tag", posts[1].body.remove_tags?.includes("p3"));

// --- virtual table navigation ---------------------------------------------------------
const vRows = Array.from({ length: 500 }, (_, i) => makeRow({ vindex: i, path: `f${i}.bin`, pointer: `/files/${i}` }));
let scrolledTo = -1;
const vPanel = {
  querySelectorAll(sel) {
    if (sel.includes("selectable-result-row") || sel.includes("tr[data-filter]")) return vRows;
    if (sel === ".kb-focus") return vRows.filter((r) => r.classList.contains("kb-focus"));
    return [];
  },
  querySelector(sel) {
    const match = sel.match(/data-vindex="(\d+)"/);
    return match ? vRows[Number(match[1])] : null;
  },
};
const vTable = { count: 500, scrollToIndex: (i) => { scrolledTo = i; } };
const vReviewer = new PowerReviewer({
  detailPanel: () => vPanel,
  activeTab: () => "artifacts",
  runId: () => "run-1",
  api: async () => ({}),
  getVirtualTable: (key) => (key === "artifacts" ? vTable : null),
  openPreview: () => {},
  onStatus: () => {},
});
vReviewer.cursor = 200;
await vReviewer.handleKey("j");
check("virtual move scrolls table", scrolledTo === 201);
check("virtual row focused", vRows[201].classList.contains("kb-focus"));

// --- no rows -> keys unconsumed -----------------------------------------------------------
const empty = new PowerReviewer({
  detailPanel: () => ({ querySelectorAll: () => [], querySelector: () => null }),
  activeTab: () => "docs",
  runId: () => "run-1",
  api: async () => ({}),
  getVirtualTable: () => null,
  openPreview: () => {},
});
check("j unconsumed on empty list", (await empty.handleKey("j")) === false);
check("digit unconsumed on empty list", (await empty.handleKey("2")) === false);
check("priority tags p1-p5 defined", REVIEWER_PRIORITY_TAGS.join(",") === "p1,p2,p3,p4,p5");

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all shortcut tests passed");
