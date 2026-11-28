#!/usr/bin/env node
// WCAG 2.1 contrast gate for src/tokens/tokens.css (plan §4.4 / Q-A6).
// Text pairs need >= 4.5:1; large text, UI borders, focus rings and status/tag
// indicators (non-text) need >= 3:1. Status colours must also stay apart under colour-vision
// deficiency (F1, see STATUS_SEPARATION below). Exit code 1 when any check fails.
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
  // Input / select / textarea edges (tokens.css --field-edge, F5).
  ...SURFACES.map((b) => ["input edge", "--field-edge", b, UI, "ui"]),
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

// --- Status separation under colour-vision deficiency (F1) -------------------------------
// The five review-status colours must be told apart from each other and from the semantic
// danger / warn / accent colours, also by deuteranopes and protanopes. Each pair is simulated
// with the Machado, Oliveira & Fernandes (2009) matrices at severity 1.0 (applied to linear
// sRGB) and compared with CIEDE2000 ΔE00:
//   - normal vision ≥ 20 (clearly different hues side by side),
//   - deuteranopia and protanopia ≥ 10 (a small glyph still reads as a different colour; ΔE00
//     ≈ 2 is a just-noticeable difference, ≈ 10 a plainly different swatch at 13–14px),
//   - 관련 있음 vs danger ≥ 25 under normal vision (red stays the error colour).
// Tritanopia is printed for information only (rare; the glyph shapes carry the meaning).
export const CVD_MATRICES = {
  deutan: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
  protan: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  tritan: [
    [1.255528, -0.076749, -0.178779],
    [-0.078411, 0.930809, 0.147602],
    [0.004733, 0.691367, 0.3039],
  ],
};
export const STATUS_SEPARATION = { normal: 20, deutan: 10, protan: 10, relevantVsDanger: 25 };
const SEPARATION_OTHERS = ["--danger", "--warn", "--accent"];

const toLinear = (c) => {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const fromLinear = (c) => {
  const s = Math.max(0, Math.min(1, c));
  return 255 * (s <= 0.0031308 ? 12.92 * s : 1.055 * s ** (1 / 2.4) - 0.055);
};

/** sRGB [0-255] as seen with a colour-vision deficiency ("normal" = unchanged). */
export function simulateCvd(rgb, kind) {
  if (kind === "normal") return rgb;
  const lin = rgb.map(toLinear);
  return CVD_MATRICES[kind].map((row) => fromLinear(row[0] * lin[0] + row[1] * lin[1] + row[2] * lin[2]));
}

/** sRGB [0-255] → CIE L*a*b* (D65). */
export function toLab(rgb) {
  const [r, g, b] = rgb.map(toLinear);
  const x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047;
  const y = 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
  const z = (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883;
  const f = (t) => (t > 216 / 24389 ? Math.cbrt(t) : ((24389 / 27) * t + 16) / 116);
  return [116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))];
}

const rad = (d) => (d * Math.PI) / 180;

/** CIEDE2000 colour difference of two L*a*b* colours (Sharma, Wu & Dalal 2005). */
export function deltaE2000([l1, a1, b1], [l2, a2, b2]) {
  const c7 = ((Math.hypot(a1, b1) + Math.hypot(a2, b2)) / 2) ** 7;
  const g = 0.5 * (1 - Math.sqrt(c7 / (c7 + 25 ** 7)));
  const a1p = (1 + g) * a1;
  const a2p = (1 + g) * a2;
  const c1p = Math.hypot(a1p, b1);
  const c2p = Math.hypot(a2p, b2);
  const hue = (b, a) => ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360;
  const h1p = c1p === 0 ? 0 : hue(b1, a1p);
  const h2p = c2p === 0 ? 0 : hue(b2, a2p);
  let dhp = 0;
  if (c1p * c2p !== 0) {
    dhp = h2p - h1p;
    if (dhp > 180) dhp -= 360;
    else if (dhp < -180) dhp += 360;
  }
  const dLp = l2 - l1;
  const dCp = c2p - c1p;
  const dHp = 2 * Math.sqrt(c1p * c2p) * Math.sin(rad(dhp / 2));
  const lbp = (l1 + l2) / 2;
  const cbp = (c1p + c2p) / 2;
  let hbp = h1p + h2p;
  if (c1p * c2p !== 0) {
    if (Math.abs(h1p - h2p) <= 180) hbp = (h1p + h2p) / 2;
    else hbp = h1p + h2p < 360 ? (h1p + h2p + 360) / 2 : (h1p + h2p - 360) / 2;
  }
  const t =
    1 -
    0.17 * Math.cos(rad(hbp - 30)) +
    0.24 * Math.cos(rad(2 * hbp)) +
    0.32 * Math.cos(rad(3 * hbp + 6)) -
    0.2 * Math.cos(rad(4 * hbp - 63));
  const dTheta = 30 * Math.exp(-(((hbp - 275) / 25) ** 2));
  const cbp7 = cbp ** 7;
  const rc = 2 * Math.sqrt(cbp7 / (cbp7 + 25 ** 7));
  const sl = 1 + (0.015 * (lbp - 50) ** 2) / Math.sqrt(20 + (lbp - 50) ** 2);
  const sc = 1 + 0.045 * cbp;
  const sh = 1 + 0.015 * cbp * t;
  const rt = -Math.sin(rad(2 * dTheta)) * rc;
  return Math.sqrt((dLp / sl) ** 2 + (dCp / sc) ** 2 + (dHp / sh) ** 2 + rt * (dCp / sc) * (dHp / sh));
}

/** ΔE00 between two hex colours as seen with `kind` vision. */
export function cvdDelta(hexA, hexB, kind) {
  return deltaE2000(toLab(simulateCvd(hexToRgb(hexA), kind)), toLab(simulateCvd(hexToRgb(hexB), kind)));
}

/**
 * Every status pair and every status × danger/warn/accent pair of one theme, with ΔE00 per
 * vision and whether it meets STATUS_SEPARATION. A missing token gives `missing: true`.
 */
export function statusSeparation(vars) {
  const statuses = STATUSES.map((n) => `--status-${n}`);
  const pairs = [];
  statuses.forEach((a, i) => {
    for (const b of [...statuses.slice(i + 1), ...SEPARATION_OTHERS]) pairs.push([a, b]);
  });
  return pairs.map(([a, b]) => {
    const ha = resolveToken(vars, a);
    const hb = resolveToken(vars, b);
    if (!ha || !hb) return { a, b, missing: true, ok: false };
    const delta = Object.fromEntries(
      ["normal", "deutan", "protan", "tritan"].map((kind) => [kind, cvdDelta(ha, hb, kind)]),
    );
    const relevantDanger = a === "--status-relevant" && b === "--danger";
    const ok =
      delta.normal >= (relevantDanger ? STATUS_SEPARATION.relevantVsDanger : STATUS_SEPARATION.normal) &&
      delta.deutan >= STATUS_SEPARATION.deutan &&
      delta.protan >= STATUS_SEPARATION.protan;
    return { a, b, ha, hb, delta, ok };
  });
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
  for (const [theme, vars] of Object.entries(themes)) {
    console.log(`\n== ${theme}: status separation (ΔE00; normal ≥ ${STATUS_SEPARATION.normal}, `);
    console.log(
      `   deutan/protan ≥ ${STATUS_SEPARATION.deutan}, relevant vs danger ≥ ${STATUS_SEPARATION.relevantVsDanger}; tritan informative) ==`,
    );
    for (const r of statusSeparation(vars)) {
      if (r.missing) {
        missing++;
        console.log(`MISSING  ${r.a} / ${r.b}`);
        continue;
      }
      if (!r.ok) failures++;
      const d = r.delta;
      console.log(
        `${r.ok ? "PASS   " : "FAIL   "} normal ${d.normal.toFixed(1).padStart(5)}  deutan ${d.deutan.toFixed(1).padStart(5)}  protan ${d.protan.toFixed(1).padStart(5)}  tritan ${d.tritan.toFixed(1).padStart(5)}  ${r.a} ${r.ha} / ${r.b} ${r.hb}`,
      );
    }
  }
  console.log(`\n${failures} failing check(s), ${missing} missing token(s).`);
  process.exit(failures > 0 || missing > 0 ? 1 : 0);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
