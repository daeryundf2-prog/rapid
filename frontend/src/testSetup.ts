// Vitest setup: unit tests read the stable families mock (scripts/families-mock.mjs), not the
// bundled copy of the backend YAML, so catalogue edits never change unrelated test expectations.
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { familiesMock } from "../scripts/families-mock.mjs";
import { type FamilyCatalog, normalizeCatalog, pinFallbackCatalogForTests } from "./features/flags/catalog";

pinFallbackCatalogForTests(normalizeCatalog(familiesMock) as FamilyCatalog);

// T-154: Testing Library only auto-cleans when vitest `globals` is on (it is not here), so a file
// that forgets `afterEach(cleanup)` keeps every rendered tree mounted and each later query scans a
// growing DOM. Unmount after every test, drop pending fake timers and hand real timers back, so no
// test inherits another's DOM or clock and no timer keeps a worker alive past the run.
afterEach(() => {
  cleanup();
  if (vi.isFakeTimers()) {
    vi.clearAllTimers();
    vi.useRealTimers();
  }
});
