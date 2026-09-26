import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "rapidtriage", "web", "static");

function makeElement(tag) {
  return {
    tagName: tag.toUpperCase(),
    children: [],
    attrs: {},
    value: "",
    textContent: "",
    id: "",
    className: "",
    listeners: {},
    setAttribute(name, value) { this.attrs[name] = value; },
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
  };
}

function makeDoc() {
  return {
    documentElement: makeElement("html"),
    createElement: (tag) => makeElement(tag),
  };
}

function makeStorage(initial = {}) {
  const data = { ...initial };
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v); },
    data,
  };
}

const { THEMES, readStoredTheme, applyTheme, initThemePicker, THEME_STORAGE_KEY } =
  await import(new URL(`file:///${ROOT.replace(/\\/g, "/")}/app_theme.js`));

// theme catalog
assert.deepEqual(THEMES.map((t) => t.id), ["nordic-slate", "warm-paper"]);
assert.ok(THEMES.every((t) => t.label.length > 0));

// readStoredTheme
assert.equal(readStoredTheme(makeStorage()), "nordic-slate");
assert.equal(readStoredTheme(makeStorage({ [THEME_STORAGE_KEY]: "warm-paper" })), "warm-paper");
assert.equal(readStoredTheme(makeStorage({ [THEME_STORAGE_KEY]: "bogus" })), "nordic-slate");
assert.equal(readStoredTheme({ getItem: () => { throw new Error("denied"); } }), "nordic-slate");

// applyTheme
const doc = makeDoc();
assert.equal(applyTheme("warm-paper", doc), "warm-paper");
assert.equal(doc.documentElement.attrs["data-theme"], "warm-paper");
assert.equal(applyTheme("bogus", doc), "nordic-slate");

// initThemePicker builds a select with both themes and persists changes
const storage = makeStorage({ [THEME_STORAGE_KEY]: "warm-paper" });
const doc2 = makeDoc();
const select = initThemePicker({ doc: doc2, storage });
assert.equal(select.tagName, "SELECT");
assert.equal(select.id, "themePicker");
assert.equal(select.children.length, 2);
assert.equal(select.value, "warm-paper");
assert.equal(doc2.documentElement.attrs["data-theme"], "warm-paper");

select.value = "nordic-slate";
select.listeners.change();
assert.equal(doc2.documentElement.attrs["data-theme"], "nordic-slate");
assert.equal(storage.data[THEME_STORAGE_KEY], "nordic-slate");

// storage failure on write does not throw
const select2 = initThemePicker({ doc: makeDoc(), storage: { getItem: () => null, setItem: () => { throw new Error("denied"); } } });
select2.value = "warm-paper";
select2.listeners.change();

// static contract: themes.css defines both theme surfaces
const css = readFileSync(resolve(ROOT, "themes.css"), "utf8");
assert.ok(css.includes('data-theme="warm-paper"'), "warm-paper override block missing");
assert.ok(css.includes("--bg:"), "core tokens not overridden");
assert.ok(css.includes("--ink:"), "ink token not overridden");

// index.html loads themes.css and applies stored theme early
const html = readFileSync(resolve(ROOT, "index.html"), "utf8");
assert.ok(html.includes("themes.css"), "themes.css not linked");
assert.ok(html.includes('document.documentElement.setAttribute("data-theme"'), "early theme script missing");

console.log("test_app_theme: all assertions passed");
