// Vitest setup: unit tests read the stable families mock (scripts/families-mock.mjs), not the
// bundled copy of the backend YAML, so catalogue edits never change unrelated test expectations.
import { familiesMock } from "../scripts/families-mock.mjs";
import { type FamilyCatalog, normalizeCatalog, pinFallbackCatalogForTests } from "./features/flags/catalog";

pinFallbackCatalogForTests(normalizeCatalog(familiesMock) as FamilyCatalog);
