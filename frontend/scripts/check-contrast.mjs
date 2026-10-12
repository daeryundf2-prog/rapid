#!/usr/bin/env node
// WCAG 2.1 contrast gate for src/tokens/tokens.css (plan §4.4 / Q-A6).
// Text pairs need >= 4.5:1; large text, UI borders, focus rings and status/tag
// indicators (non-text) need >= 3:1. Exit code 1 when any pair fails.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cssPath = resolve(here, process.argv[2] ?? "../src/tokens/tokens.css");

const TEXT = 4.5;
const UI = 3;

/** [label, foreground token, background token, minimum ratio, kind] */
const STATUSES = ["relevant", "bookmark", "excluded", "needs-review", "report"];
// Forensic Slate surfaces (U-V1): app bg, panels, raised controls, popovers/toasts.
const SURFACES = ["--surface-0", "--surface-1", "--surface-2", "--surface-3"];
const ROWS = [...SURFACES, "--bg-selected"];
const PAIRS = [
  ...ROWS.map((b) => ["text", "--text", b, TEXT, "text"]),
  ...ROWS.map((b) => ["muted text", "--text-muted", b, TEXT, "text"]),
  ...ROWS.map((b) => ["subtle text (placeholders, hints)", "--text-subtle", b, TEXT, "text"]),
  ...SURFACES.map((b) => ["accent (links)", "--accent", b, TEXT, "text"]),
  ...ROWS.map((b) => ["focus ring / selected-row bar", "--focus", b, UI, "ui"]),
  ...["--accent", "--accent-hover", "--accent-active", "--danger"].map((b) => [
    "on-accent text",
    "--on-accent",
    b,
    TEXT,
    "text",
  ]),
  ["disabled text", "--disabled-text", "--disabled-bg", TEXT, "text"],
  ...SURFACES.map((b) => ["border/line (controls)", "--line", b, UI, "ui"]),
  ...["--ok", "--warn", "--danger", "--info", "--deleted"].flatMap((f) =>
    ROWS.map((b) => [`status ${f.slice(2)}`, f, b, TEXT, "text"]),
  ),
  ...STATUSES.flatMap((n) => [
    ...ROWS.map((b) => [`status-${n} (dot / UI colour)`, `--status-${n}`, b, UI, "ui"]),
    ["status chip text", `--status-${n}-on`, `--status-${n}`, TEXT, "text"],
  ]),
  ...[1, 2, 3, 4, 5, 6, 7, 8].flatMap((n) => ROWS.map((b) => [`tag-${n}`, `--tag-${n}`, b, UI, "ui"])),
];

function stripComments(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, "");
}

/** Theme of one rule: `@media print` → print, `:not([data-theme])` → light-os, `[data-theme="light"]` → light, else dark. */
function themeOf(selector, ancestors) {
  if (ancestors.some((a) => /^@media\s+print\b/.test(a))) return "print";
  if (selector.includes(":not([data-theme])")) return "light-os";
  if (selector.includes('data-theme="light"')) return "light";
  return "dark";
}

/**
 * Custom properties per theme. Base `:root` aliases (values that are only `var(--x)`)
 * cascade into every theme as they do in the browser; literal colours do not —
 * each theme block must define all of its own. Themes with no block are omitted.
 */
export function parseThemes(css) {
  const raw = {};
  const stack = [];
  let buf = "";
  for (const ch of stripComments(css)) {
    if (ch === "{") {
      stack.push(buf.trim());
      buf = "";
    } else if (ch === "}") {
      const selector = stack.pop() ?? "";
      if (!selector.startsWith("@")) {
        const theme = themeOf(selector, stack);
        for (const decl of buf.split(";")) {
          const i = decl.indexOf(":");
          if (i < 0) continue;
          const name = decl.slice(0, i).trim();
          if (!name.startsWith("--")) continue;
          raw[theme] ??= {};
          raw[theme][name] = decl.slice(i + 1).trim();
        }
      }
      buf = "";
    } else {
      buf += ch;
    }
  }
  const aliases = Object.fromEntries(
    Object.entries(raw.dark ?? {}).filter(([, v]) => /^var\(--[\w-]+\)$/.test(v)),
  );
  const themes = {};
  for (const name of ["dark", "light", "light-os", "print"]) {
    if (raw[name]) themes[name] = name === "dark" ? raw[name] : { ...aliases, ...raw[name] };
  }
  return themes;
}

function resolveToken(vars, name, depth = 0) {
  const v = vars[name];
  if (v === undefined || depth > 10) return undefined;
  const ref = /^var\((--[\w-]+)\)$/.exec(v);
  if (ref) return resolveToken(vars, ref[1], depth + 1);
  return v;
}

export function hexToRgb(hex) {
  let h = hex.replace("#", "");
  if (h.length === 3) h = [...h].map((c) => c + c).join("");
  if (!/^[0-9a-f]{6}$/i.test(h)) throw new Error(`unsupported color: ${hex}`);
  return [0, 2, 4].map((i) => Number.parseInt(h.slice(i, i + 2), 16));
}

export function luminance([r, g, b]) {
  const lin = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

export function contrast(fg, bg) {
  const a = luminance(hexToRgb(fg));
  const b = luminance(hexToRgb(bg));
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function main() {
  const themes = parseThemes(readFileSync(cssPath, "utf8"));
  // Every non-dark theme must redefine every literal colour token of the dark theme.
  let failures = 0;
  let missing = 0;
  const colours = Object.entries(themes.dark ?? {})
    .filter(([, v]) => /^#[0-9a-f]{3,8}$/i.test(v))
    .map(([k]) => k);
  for (const [theme, vars] of Object.entries(themes)) {
    for (const name of colours) {
      if (!/^#[0-9a-f]{3,8}$/i.test(vars[name] ?? "")) {
        missing++;
        console.log(`MISSING  ${theme}: ${name} is not redefined (theme blocks must be complete)`);
      }
    }
  }
  for (const [theme, vars] of Object.entries(themes)) {
    console.log(`\n== ${theme} ==`);
    console.log("status  ratio  min   kind  pair");
    for (const [label, fgTok, bgTok, min, kind] of PAIRS) {
      const fg = resolveToken(vars, fgTok);
      const bg = resolveToken(vars, bgTok);
      if (!fg || !bg) {
        missing++;
        console.log(`MISSING  -     ${min}   ${kind}  ${label}: ${fgTok} on ${bgTok}`);
        continue;
      }
      const ratio = contrast(fg, bg);
      const ok = ratio >= min;
      if (!ok) failures++;
      console.log(
        `${ok ? "PASS   " : "FAIL   "} ${ratio.toFixed(2).padStart(5)}  ${min.toFixed(1)}   ${kind.padEnd(4)}  ${label}: ${fgTok} ${fg} on ${bgTok} ${bg}`,
      );
    }
  }
  console.log(`\n${failures} failing pair(s), ${missing} missing token(s).`);
  process.exit(failures > 0 || missing > 0 ? 1 : 0);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
