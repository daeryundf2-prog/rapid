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
const bgs = ["--bg", "--bg-panel", "--bg-raised"];
const PAIRS = [
  ...bgs.map((b) => ["text", "--text", b, TEXT, "text"]),
  ...bgs.map((b) => ["muted text", "--text-muted", b, TEXT, "text"]),
  ...bgs.map((b) => ["accent (links)", "--accent", b, TEXT, "text"]),
  ...bgs.map((b) => ["focus ring", "--accent", b, UI, "ui"]),
  ...["--accent", "--accent-hover", "--accent-active"].map((b) => [
    "on-accent text",
    "--on-accent",
    b,
    TEXT,
    "text",
  ]),
  ...["--bg", "--bg-panel"].map((b) => ["border/line", "--line", b, UI, "ui"]),
  ...["--ok", "--warn", "--danger", "--info", "--deleted"].flatMap((f) =>
    ["--bg", "--bg-panel"].map((b) => [`status ${f.slice(2)}`, f, b, TEXT, "text"]),
  ),
  ...STATUSES.flatMap((n) => [
    ...bgs.map((b) => [`status-${n} (UI colour)`, `--status-${n}`, b, UI, "ui"]),
    ["status chip text", `--status-${n}-on`, `--status-${n}`, TEXT, "text"],
  ]),
  ...[1, 2, 3, 4, 5, 6, 7, 8].flatMap((n) =>
    ["--bg", "--bg-panel"].map((b) => [`tag-${n}`, `--tag-${n}`, b, UI, "ui"]),
  ),
];

function stripComments(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, "");
}

export function parseThemes(css) {
  const themes = { dark: {}, light: {}, "light-os": {} };
  const re = /([^{}]+)\{([^{}]*)\}/g;
  for (let m = re.exec(stripComments(css)); m; m = re.exec(stripComments(css))) {
    const selector = m[1].trim();
    if (selector.startsWith("@")) continue;
    let theme = "dark";
    if (selector.includes(":not([data-theme])")) theme = "light-os";
    else if (selector.includes('data-theme="light"')) theme = "light";
    for (const decl of m[2].split(";")) {
      const i = decl.indexOf(":");
      if (i < 0) continue;
      const name = decl.slice(0, i).trim();
      if (name.startsWith("--")) themes[theme][name] = decl.slice(i + 1).trim();
    }
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
  // light-os (prefers-color-scheme block) inherits nothing from dark; it must be complete.
  let failures = 0;
  let missing = 0;
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
