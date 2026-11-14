#!/usr/bin/env node
// Design-token ratchet (R8 T-002). Counts values written outside the token system in
// src/**/*.css and in TSX inline `style={{…}}` objects, and compares them with
// scripts/token-baseline.json. Existing violations are tolerated (T-061 / T-117 fix them);
// any file whose count grows in any category, or a new z-index value, fails.
//
//   node scripts/check-tokens.mjs            # check against the baseline (exit 1 on growth)
//   node scripts/check-tokens.mjs --json     # machine-readable report
//   node scripts/check-tokens.mjs --update   # rewrite the baseline (only when violations were fixed)
//
// Categories (custom-property declarations `--x: …` are token definitions and never count;
// `var(--x)` and `var(--x, fallback)` are tokenised values):
//   color         hex colour literal in a declaration value
//   radius        border-*radius with a length/percent literal
//   px-spacing    margin* / padding* / gap / row-gap / column-gap with a non-zero px literal
//   font-size     font-size with a literal (number, px, rem, em, %)
//   box-shadow    box-shadow with any literal (not `none`)
//   z-index       z-index declarations with a literal; distinct values are tracked too
//   important     `!important`
//   inline-style  TSX `style={…}` attributes (non-test files)
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const srcDir = join(root, "src");
const baselinePath = join(here, "token-baseline.json");
export const CATEGORIES = [
  "color",
  "radius",
  "px-spacing",
  "font-size",
  "box-shadow",
  "z-index",
  "important",
  "inline-style",
];

const HEX = /#[0-9a-f]{3,8}\b/i;
const SPACING_PROP = /^(margin|padding)(-[a-z]+)*$|^(row-|column-)?gap$/;
const RADIUS_PROP = /^border(-[a-z]+)*-radius$/;
const LENGTH = /(^|[^\w-])\d*\.?\d+(px|%|rem|em)(?![\w%])/;
const NONZERO_PX = /(^|[^\w.])-?(?!0+(\.0+)?px)\d*\.?\d+px(?![\w%])/;
const ANY_NUMBER = /(^|[^\w-])\d*\.?\d+/;

/** Remove `var(--x)` and `var(--x, fallback)` (balanced) so only literals remain. */
export function stripVars(value) {
  let out = "";
  let i = 0;
  while (i < value.length) {
    if (value.startsWith("var(", i)) {
      let depth = 0;
      let j = i;
      for (; j < value.length; j++) {
        if (value[j] === "(") depth++;
        else if (value[j] === ")" && --depth === 0) break;
      }
      out += " ";
      i = j + 1;
    } else {
      out += value[i++];
    }
  }
  return out;
}

/** Category hits of one declaration (CSS property name, kebab-case). */
export function classify(prop, rawValue) {
  const hits = [];
  if (prop.startsWith("--")) return hits;
  if (/!important/i.test(rawValue)) hits.push("important");
  const value = stripVars(rawValue.replace(/!important/i, "")).trim();
  if (HEX.test(value)) hits.push("color");
  if (RADIUS_PROP.test(prop) && LENGTH.test(value)) hits.push("radius");
  if (SPACING_PROP.test(prop) && NONZERO_PX.test(value)) hits.push("px-spacing");
  if (prop === "font-size" && ANY_NUMBER.test(value)) hits.push("font-size");
  if (prop === "box-shadow" && value !== "none" && value !== "" && /[\d#]|rgb|hsl/.test(value))
    hits.push("box-shadow");
  if (prop === "z-index" && /^-?\d+$/.test(value)) hits.push("z-index");
  return hits;
}

/** Declarations of a stylesheet: [{ prop, value, line }]. Handles nesting and @media. */
export function cssDeclarations(css) {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, " "));
  const decls = [];
  let buf = "";
  let bufLine = 1;
  let line = 1;
  const flush = (chunk, startLine, keepLast) => {
    const parts = chunk.split(";");
    const last = keepLast ? parts.pop() : undefined;
    let l = startLine;
    for (const part of parts) {
      const lead = part.match(/^\s*/)[0];
      const declLine = l + (lead.match(/\n/g) ?? []).length;
      l += (part.match(/\n/g) ?? []).length;
      const i = part.indexOf(":");
      if (i > 0) {
        const prop = part.slice(0, i).trim().toLowerCase();
        if (/^-{0,2}[a-z][a-z0-9-]*$/.test(prop))
          decls.push({ prop, value: part.slice(i + 1).trim(), line: declLine });
      }
    }
    return last;
  };
  for (const ch of text) {
    if (ch === "{") {
      flush(buf, bufLine, true);
      buf = "";
      bufLine = line;
    } else if (ch === "}") {
      flush(buf, bufLine, false);
      buf = "";
      bufLine = line;
    } else {
      if (buf === "") bufLine = line;
      buf += ch;
    }
    if (ch === "\n") line++;
  }
  return decls;
}

const kebab = (name) => name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);

/** TSX inline styles: the `style={…}` count plus token categories inside each object literal. */
export function tsxStyleHits(source) {
  const hits = [];
  const re = /\bstyle=\{/g;
  for (let m = re.exec(source); m; m = re.exec(source)) {
    const line = source.slice(0, m.index).split("\n").length;
    hits.push({ category: "inline-style", line, value: "style={…}" });
    let depth = 0;
    let j = m.index + m[0].length - 1;
    for (; j < source.length; j++) {
      if (source[j] === "{") depth++;
      else if (source[j] === "}" && --depth === 0) break;
    }
    const body = source.slice(m.index + m[0].length, j);
    const prop = /([A-Za-z]+)\s*:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|-?\d*\.?\d+)/g;
    for (let p = prop.exec(body); p; p = prop.exec(body)) {
      const name = kebab(p[1]);
      let value = p[2].replace(/^["']|["']$/g, "");
      // React adds px to bare numbers on length properties.
      if (/^-?\d*\.?\d+$/.test(value) && name !== "z-index" && Number(value) !== 0) value = `${value}px`;
      for (const category of classify(name, value)) hits.push({ category, line, value: `${p[1]}: ${p[2]}` });
    }
  }
  return hits;
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

/** Scan src/ → { files: { relPath: { category: [{ line, value }] } }, zIndexValues }. */
export function scan(dir = srcDir) {
  const files = {};
  const zIndexValues = new Set();
  const add = (rel, category, line, value) => {
    files[rel] ??= {};
    files[rel][category] ??= [];
    files[rel][category].push({ line, value });
  };
  for (const path of walk(dir).sort()) {
    const rel = relative(root, path).split("\\").join("/");
    if (path.endsWith(".css")) {
      for (const d of cssDeclarations(readFileSync(path, "utf8"))) {
        for (const category of classify(d.prop, d.value)) {
          add(rel, category, d.line, `${d.prop}: ${d.value}`);
          if (category === "z-index") zIndexValues.add(stripVars(d.value).trim());
        }
      }
    } else if (path.endsWith(".tsx") && !/\.test\.tsx$/.test(path)) {
      for (const h of tsxStyleHits(readFileSync(path, "utf8"))) {
        add(rel, h.category, h.line, h.value);
        if (h.category === "z-index") zIndexValues.add(h.value.split(":").pop().trim());
      }
    }
  }
  return { files, zIndexValues: [...zIndexValues].sort((a, b) => Number(a) - Number(b)) };
}

export function summarize(result) {
  const totals = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  const perFile = {};
  for (const [file, cats] of Object.entries(result.files)) {
    for (const [category, items] of Object.entries(cats)) {
      totals[category] += items.length;
      perFile[category] ??= {};
      perFile[category][file] = items.length;
    }
  }
  return { totals, perFile, zIndexValues: result.zIndexValues };
}

/** Growth against the baseline: [{ category, file, baseline, current, items }]. */
export function compare(result, baseline) {
  const now = summarize(result);
  const growth = [];
  for (const category of CATEGORIES) {
    for (const [file, count] of Object.entries(now.perFile[category] ?? {})) {
      const allowed = baseline.perFile?.[category]?.[file] ?? 0;
      if (count > allowed) {
        growth.push({
          category,
          file,
          baseline: allowed,
          current: count,
          items: result.files[file][category],
        });
      }
    }
  }
  const knownZ = new Set(baseline.zIndexValues ?? []);
  const newZ = now.zIndexValues.filter((v) => !knownZ.has(v));
  return { growth, newZ, now };
}

function main(argv) {
  const result = scan();
  if (argv.includes("--update")) {
    const { totals, perFile, zIndexValues } = summarize(result);
    const data = {
      note: "R8 T-002 token ratchet baseline. Counts may only go down; regenerate with `node scripts/check-tokens.mjs --update` after fixing violations.",
      totals,
      zIndexDistinct: zIndexValues.length,
      zIndexValues,
      perFile,
    };
    writeFileSync(baselinePath, `${JSON.stringify(data, null, 2)}\n`);
    console.log(`baseline written: ${relative(root, baselinePath)}`);
    console.log(JSON.stringify(totals));
    return 0;
  }
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
  const { growth, newZ, now } = compare(result, baseline);
  const ok = growth.length === 0 && newZ.length === 0;
  if (argv.includes("--json")) {
    console.log(JSON.stringify({ ok, totals: now.totals, baseline: baseline.totals, growth, newZ }, null, 2));
    return ok ? 0 : 1;
  }
  console.log("category      now  baseline");
  for (const c of CATEGORIES) {
    console.log(
      `${c.padEnd(12)} ${String(now.totals[c]).padStart(4)}  ${String(baseline.totals?.[c] ?? 0).padStart(8)}`,
    );
  }
  console.log(
    `z-index distinct values: ${now.zIndexValues.length} (baseline ${baseline.zIndexDistinct ?? 0})`,
  );
  for (const g of growth) {
    console.log(`\nFAIL ${g.category} grew in ${g.file}: ${g.baseline} -> ${g.current}`);
    for (const item of g.items) console.log(`  ${g.file}:${item.line}  ${item.value}`);
  }
  if (newZ.length)
    console.log(`\nFAIL new z-index value(s): ${newZ.join(", ")} — use the z-index scale tokens`);
  console.log(ok ? "\ntoken check passed (no growth over baseline)." : "\ntoken check failed.");
  return ok ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
