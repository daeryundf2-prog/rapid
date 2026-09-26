// Behavioral test for app_virtual.js VirtualTable using a minimal DOM stub.
// Run: node tests/js/test_virtual_table.mjs
//
// The stub implements only the DOM surface VirtualTable touches:
//   innerHTML (row-count via <tr> count), querySelector("tr"), appendChild,
//   insertBefore, ownerDocument.createElement, scrollTop/clientHeight,
//   addEventListener/removeEventListener, classList, dataset.

import { VirtualTable, registerVirtualTable, getVirtualTable, applyVirtualTableFilter } from "../../rapidtriage/web/static/app_virtual.js";

let failures = 0;
function check(name, cond) {
  if (cond) {
    console.log(`ok - ${name}`);
  } else {
    failures += 1;
    console.log(`FAIL - ${name}`);
  }
}

class StubElement {
  constructor(doc, tag = "div") {
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.dataset = {};
    this.classList = new Set();
    this.style = {};
    this._innerHTML = "";
    this.clientHeight = 600;
    this.scrollTop = 0;
    this._listeners = {};
    this.isConnected = true;
  }
  set innerHTML(html) {
    this._innerHTML = html;
    this._rowCount = (html.match(/<tr/g) || []).length;
    this._dataRowCount = (html.match(/<tr(?![^>]*data-virtual-spacer)/g) || []).length;
  }
  get innerHTML() { return this._innerHTML; }
  get childElementCount() { return this.children.length; }
  querySelector(sel) {
    if (sel === "tr" && this._rowCount > 0) {
      const tr = new StubElement(this.ownerDocument, "tr");
      tr.getBoundingClientRect = () => ({ height: 40 });
      return tr;
    }
    return null;
  }
  querySelectorAll(sel) {
    // Only tr:not([data-virtual-spacer]) is queried for height measurement.
    if (!sel.includes("tr")) return [];
    return Array.from({ length: this._dataRowCount || 0 }, () => {
      const tr = new StubElement(this.ownerDocument, "tr");
      tr.getBoundingClientRect = () => ({ height: 40 });
      return tr;
    });
  }
  appendChild(el) { this.children.push(el); return el; }
  insertBefore(el, ref) {
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i < 0) this.children.push(el); else this.children.splice(i, 0, el);
    return el;
  }
  addEventListener(ev, fn) { (this._listeners[ev] ||= []).push(fn); }
  removeEventListener(ev, fn) {
    this._listeners[ev] = (this._listeners[ev] || []).filter((f) => f !== fn);
  }
  dispatch(ev) { for (const fn of this._listeners[ev] || []) fn(); }
  contains(el) { return this.children.includes(el); }
}
class StubDocument {
  createElement(tag) { return new StubElement(this, tag); }
}
const document = new StubDocument();
globalThis.document = document;
const windowStub = new StubElement(document, "window");
globalThis.window = windowStub;
windowStub.requestAnimationFrame = (fn) => { fn(); return 1; };
windowStub.cancelAnimationFrame = () => {};
globalThis.requestAnimationFrame = windowStub.requestAnimationFrame;
globalThis.cancelAnimationFrame = windowStub.cancelAnimationFrame;

function makeScroller() {
  const scroller = new StubElement(document, "div");
  scroller.classList = new Set(["review-list-shell", "virtual-scroll"]);
  return scroller;
}

// --- bounded DOM mount -------------------------------------------------------
const scroller = makeScroller();
const tbody = new StubElement(document, "tbody");
const items = Array.from({ length: 5000 }, (_, i) => ({ n: i, filterText: `row-${i}` }));
const table = new VirtualTable({
  tbody,
  scroller,
  colCount: 3,
  renderRow: (item) => `<tr><td>${item.n}</td></tr>`,
  overscan: 8,
});
table.setItems(items);

const mounted = (tbody.innerHTML.match(/<tr/g) || []).length;
check("5000 items mount < 80 DOM rows", mounted > 0 && mounted < 80);
check("count reports logical total", table.count === 5000);
check("spacer markup present", tbody.innerHTML.includes("data-virtual-spacer"));

// --- scroll keeps DOM bounded ------------------------------------------------
scroller.scrollTop = 40000;
scroller.dispatch("scroll");
const mountedAfterScroll = (tbody.innerHTML.match(/<tr/g) || []).length;
check("scrolling keeps DOM bounded", mountedAfterScroll > 0 && mountedAfterScroll < 80);

// --- filter ------------------------------------------------------------------
registerVirtualTable("t1", table);
check("registry lookup", getVirtualTable("t1") === table);
applyVirtualTableFilter("t1", (item) => item.n % 100 === 0);
check("filter narrows filtered set", table.count === 50);
applyVirtualTableFilter("t1", null);
check("clearing filter restores", table.count === 5000);

// --- append + onNeedMore -----------------------------------------------------
let needMoreCalls = 0;
const table2 = new VirtualTable({
  tbody: new StubElement(document, "tbody"),
  scroller: makeScroller(),
  colCount: 2,
  renderRow: (item) => `<tr><td>${item.n}</td></tr>`,
  onNeedMore: () => { needMoreCalls += 1; },
});
table2.setItems(items.slice(0, 20));
check("small set calls onNeedMore once", needMoreCalls === 1);
table2.appendItems([{ n: 99, filterText: "x" }]);
check("appendItems grows items", table2.items.length === 21);

// --- scrollToRow -------------------------------------------------------------
const t3 = new VirtualTable({
  tbody: new StubElement(document, "tbody"),
  scroller: makeScroller(),
  colCount: 1,
  renderRow: (item) => `<tr><td>${item.n}</td></tr>`,
});
t3.setItems(items);
t3.scrollToIndex(500);
check("scrollToIndex moves scrollTop", t3.scroller.scrollTop > 0);
t3.scrollToIndex(99999);
check("scrollToIndex clamps to last row", t3.scroller.scrollTop > 0);

// --- destroy -----------------------------------------------------------------
table.destroy();
check("destroy detaches scroll listener", (scroller._listeners["scroll"] || []).length === 0);

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all virtual-table tests passed");
