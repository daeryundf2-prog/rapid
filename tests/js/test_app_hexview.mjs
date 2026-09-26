// Behavioral tests for app_hexview.js — signature scan, range parsing, drawing.
// Run: node tests/js/test_app_hexview.mjs

import {
  BYTES_PER_ROW,
  bytesFromHexRows,
  drawHexRange,
  HEX_SIGNATURES,
  mountHexViewers,
  parseOffsetInput,
  renderHexViewerShell,
  scanSignatures,
} from "../../rapidtriage/web/static/app_hexview.js";

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else { failures += 1; console.log(`FAIL - ${name}`); }
}

// --- signature scanning --------------------------------------------------------
const mz = new Uint8Array([0x00, 0x4d, 0x5a, 0x90, 0x00]);
let hits = scanSignatures(mz, 0x1000);
check("MZ signature detected", hits.length === 1 && hits[0].name === "PE/MZ");
check("signature offset absolute", hits[0].offset === 0x1001);

const sqlite = new Uint8Array(64);
"SQLite format 3".split("").forEach((c, i) => { sqlite[i] = c.charCodeAt(0); });
hits = scanSignatures(sqlite, 0);
check("SQLite signature detected", hits.some((h) => h.name === "SQLite"));

hits = scanSignatures(new Uint8Array(32), 0);
check("no signatures in zeroed range", hits.length === 0);
check("signature table covers EVTX/MFT/regf/EWF",
  ["EVTX", "MFT FILE", "regf", "EWF"].every((n) => HEX_SIGNATURES.some((s) => s.name === n)));

// --- row parsing ----------------------------------------------------------------
const rows = [
  { offset_hex: "0x00000000", hex: "4d 5a 90 00", ascii: "MZ.." },
  { offset_hex: "0x00000004", hex: "ff d8", ascii: ".." },
];
const bytes = bytesFromHexRows(rows);
check("rows parse to bytes", bytes.length === 6 && bytes[0] === 0x4d && bytes[1] === 0x5a);
check("empty rows parse empty", bytesFromHexRows([]).length === 0);

// --- offset input ----------------------------------------------------------------
check("hex offset input", parseOffsetInput("0x1000") === 4096);
check("bare hex letters", parseOffsetInput("ff") === 255);
check("decimal input", parseOffsetInput("4096") === 4096);
check("invalid input null", parseOffsetInput("xyz!") === null);
check("empty input null", parseOffsetInput("") === null);

// --- drawing ----------------------------------------------------------------------
const calls = { fillText: [], fillRect: [] };
const stubCtx = {
  fillStyle: "",
  measureText: () => ({ width: 7 }),
  fillText: (t, x, y) => calls.fillText.push({ t, x, y }),
  fillRect: (x, y, w, h) => calls.fillRect.push({ x, y, w, h }),
};
const range = new Uint8Array(BYTES_PER_ROW * 4);
range.set([0x4d, 0x5a], 0);
const sigs = scanSignatures(range, 0x2000);
const { width, height, rowCount } = drawHexRange(stubCtx, {
  bytes: range,
  baseOffset: 0x2000,
  signatures: sigs,
  charWidth: 7,
});
check("draw returns geometry", width > 0 && height > 0 && rowCount === 4);
check("offset column drawn", calls.fillText.some((c) => c.t === "00002000"));
check("hex cells drawn", calls.fillText.some((c) => c.t === "4d"));
check("signature highlight rects drawn", calls.fillRect.length > 4);

// --- shell markup -----------------------------------------------------------------
const shell = renderHexViewerShell({ path: "evidence/mft.bin", initialOffset: 4096, pageLength: 1024 });
check("shell carries path", shell.includes('data-hex-path="evidence/mft.bin"'));
check("shell carries offset", shell.includes('data-hex-offset="4096"'));
check("shell has canvas + toolbar", shell.includes("data-hex-canvas") && shell.includes("data-hex-goto"));

// --- mount -------------------------------------------------------------------------
class FakeRoot {
  constructor() { this.innerHTML = shell; }
  querySelectorAll(sel) {
    // Minimal emulation: report one hex-viewer root only for [data-hex-viewer].
    if (sel === "[data-hex-viewer]") return [makeViewerRoot()];
    return [];
  }
}
function makeViewerRoot() {
  const listeners = {};
  const el = {
    dataset: { hexPath: "a.bin", hexOffset: "0", hexPage: "256" },
    _els: {},
    querySelector(sel) {
      if (!this._els[sel]) {
        this._els[sel] = {
          addEventListener: (ev, fn) => { (listeners[sel + ":" + ev] ||= []).push(fn); },
          getContext: sel === "[data-hex-canvas]" ? () => stubCtx : undefined,
          querySelectorAll: () => [],
          textContent: "",
          value: "",
          innerHTML: "",
        };
      }
      return this._els[sel];
    },
  };
  return el;
}
const mounted = mountHexViewers(new FakeRoot(), async () => ({ rows, offset: 0, offset_hex: "0x0", end_offset_exclusive_hex: "0x6", length_returned: 6, range_hashes: { sha256: "abc" } }));
check("viewer mounts declaratively", mounted.length === 1);

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all hex-viewer tests passed");
