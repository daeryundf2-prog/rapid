/**
 * The bundled family catalogue as a ready object (families.fallback.json, generated from the
 * backend YAML by scripts/gen-families-fallback.mjs), for unit tests that check it. The console
 * itself never imports this module: it fetches the JSON asset only when the server has no
 * catalogue (`loadBundledFallback` in catalog.ts, T-116), so the ~0.3 MB stays out of the JS.
 */

import { type FamilyCatalog, normalizeCatalog } from "./catalog";
import fallbackJson from "./families.fallback.json";

export const FALLBACK_CATALOG: FamilyCatalog = normalizeCatalog(fallbackJson) as FamilyCatalog;
