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
// Derived tints (tokens.css aliases, color-mix of theme tokens): the selected row / tree item, and
// the hover tint composited over the surfaces it is used on (grid = surface-0, tree = surface-1).
// `--x@--y` = token --x painted over --y.
const HOVERS = ["--bg-hover@--surface-0", "--bg-hover@--surface-1"];
const ROWS = [...SURFACES, "--bg-selected", ...HOVERS];
// Dialog caution box (tokens.css --caution-bg): body text, its title and the warn icon.
const CAUTION = "--caution-bg";
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
  // Disabled outlined buttons (controls.css) sit on the bare surface, not on a fill.
  ...SURFACES.map((b) => ["disabled text (outlined button)", "--disabled-text", b, TEXT, "text"]),
  ["caution text", "--text", CAUTION, TEXT, "text"],
  ["caution muted text", "--text-muted", CAUTION, TEXT, "text"],
  ["caution icon / bar", "--warn", CAUTION, UI, "ui"],
  ...SURFACES.map((b) => ["border/line (controls)", "--line", b, UI, "ui"]),
  ...["--ok", "--warn", "--danger", "--info", "--deleted"].flatMap((f) =>
    ROWS.map((b) => [`status ${f.slice(2)}`, f, b, TEXT, "text"]),
  ),
  ...STATUSES.flatMap((n) => [
    ...ROWS.map((b) => [`status-${n} (dot / UI colour)`, `--status-${n}`, b, UI, "ui"]),
    ["status chip text", `--status-${n}-on`, `--status-${n}`, TEXT, "text"],
  ]),
  ...[1, 2, 3, 4, 5, 6, 7, 8].flatMap((n) => ROWS.map((b) => [`tag-${n}`, `--tag-${n}`, b, UI, "ui"])),
  // Scrollbars and pane resize grips (scroll review C3/C4): non-text UI on every surface.
  ...["--sb-thumb", "--sb-thumb-hover", "--resize-grip"].flatMap((f) =>
    SURFACES.map((b) => [`scrollbar / resize grip ${f.slice(2)}`, f, b, UI, "ui"]),
  ),
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
    Object.entries(raw.dark ?? {}).filter(([, v]) => /^var\(--[\w-]+\)$/.test(v) || /^color-mix\(/.test(v)),
  );
  const themes = {};
  for (const name of ["dark", "light", "light-os", "print"]) {
    if (raw[name]) themes[name] = name === "dark" ? raw[name] : { ...aliases, ...raw[name] };
  }
  return themes;
}

/** Split "a, b(c, d), e" at top-level commas. */
function splitArgs(text) {
  const out = [];
  let depth = 0;
  let cur = "";
  for (const ch of text) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** A colour expression → { rgb, alpha }: hex, var(--x), `transparent`, color-mix(in srgb, A p%, B). */
function resolveColor(vars, expr, depth = 0) {
  if (expr === undefined || depth > 10) return undefined;
  const v = expr.trim();
  if (v === "transparent") return { rgb: [0, 0, 0], alpha: 0 };
  if (/^#[0-9a-f]{3,8}$/i.test(v)) return { rgb: hexToRgb(v), alpha: 1 };
  const ref = /^var\((--[\w-]+)\)$/.exec(v);
  if (ref) return resolveColor(vars, vars[ref[1]], depth + 1);
  const mix = /^color-mix\(\s*in srgb\s*,([\s\S]*)\)$/.exec(v);
  if (mix) {
    const parts = splitArgs(mix[1]).map((part) => {
      const pct = /\s+(\d+(?:\.\d+)?)%$/.exec(part);
      return { color: pct ? part.slice(0, pct.index) : part, pct: pct ? Number(pct[1]) / 100 : undefined };
    });
    if (parts.length !== 2) return undefined;
    const [a, b] = parts;
    const pa = a.pct ?? (b.pct !== undefined ? 1 - b.pct : 0.5);
    const ca = resolveColor(vars, a.color, depth + 1);
    const cb = resolveColor(vars, b.color, depth + 1);
    if (!ca || !cb) return undefined;
    // CSS Color 5: premultiplied interpolation in sRGB.
    const alpha = ca.alpha * pa + cb.alpha * (1 - pa);
    if (alpha === 0) return { rgb: [0, 0, 0], alpha: 0 };
    const rgb = [0, 1, 2].map((i) => (ca.rgb[i] * ca.alpha * pa + cb.rgb[i] * cb.alpha * (1 - pa)) / alpha);
    return { rgb, alpha };
  }
  return undefined;
}

function toHex(rgb) {
  return `#${rgb.map((c) => Math.round(c).toString(16).padStart(2, "0")).join("")}`;
}

/** Token (or `--x@--base`: token --x painted over --base) → opaque hex. */
function resolveToken(vars, name) {
  const [token, base] = name.split("@");
  const color = resolveColor(vars, `var(${token})`);
  if (!color) return undefined;
  if (color.alpha >= 1) return toHex(color.rgb);
  const under = base ? resolveColor(vars, `var(${base})`) : undefined;
  if (!under) return undefined;
  return toHex(color.rgb.map((c, i) => c * color.alpha + under.rgb[i] * (1 - color.alpha)));
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
