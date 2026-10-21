# Console accessibility checklist (WCAG 2.1 AA)

Plan: `docs/plans/console-redesign-2026-10-10.md` (U9, section 4.4, gate Q-A6).
Verification legend: **U** = vitest unit (`frontend/src/a11y/a11y.test.tsx` and component tests), **E** = Playwright
(`frontend/e2e/a11y.spec.ts`), **C** = `npm run check:contrast`, **M** = manual NVDA pass recorded for Q-A6.

| WCAG SC | Requirement | Plan item | Mechanism | Verified by |
|---|---|---|---|---|
| 1.1.1 Non-text content | Images have `alt`; icon-only buttons have `aria-label` | 4.4 icon buttons | `img-alt`, `accessible-name` rules | E, M |
| 1.3.1 Info and relationships | Landmarks banner/navigation/main/complementary/contentinfo; grid, row, tree, tab roles and `aria-*` correct | 4.4 landmarks, grid, tree, viewer | `main-landmark`, `grid-*`, `tab-*`, `treeitem-*` rules | E, M |
| 1.3.2 Meaningful sequence | DOM order matches visual order (tree, grid, viewer) | 4.4 | Review in DOM, tab order walk | M |
| 1.3.4 Orientation | No orientation lock; 1024 px narrow layout works | Q-A7 | Viewport run | E, M |
| 1.3.5 Identify input purpose | Search/filter inputs named | 4.4 | `field-name` rule | E |
| 1.4.1 Use of color | Review status, deleted marker and tags also carry text or icon | 4.5 tokens | Component review | M |
| 1.4.3 Contrast (minimum) | Text >= 4.5:1 in dark, light, light-OS themes | 4.4 contrast | Pair table in `check-contrast.mjs` | C |
| 1.4.4 Resize text | 200% zoom without loss | Q-A7 | rem-based font tokens, manual zoom | M |
| 1.4.10 Reflow | No 2-D scroll at 320 CSS px except grid/hex viewer; below 900 px the left panel is a drawer (stage-rail 탐색 / Esc), the top bar and filter line wrap below 640 px, and the document never scrolls (`scrollWidth` ≤ viewport) | Q-A7, scroll review C2 | `treePane.test.tsx`, Playwright scroll probe (400×950, 800×600) | U, M |
| 1.4.11 Non-text contrast | Focus ring, control borders, status/tag indicators, scrollbar thumbs (`--sb-thumb`) and pane resize grips (`--resize-grip`) >= 3:1 | 4.4 contrast, scroll review C3/C4 | `ui` pairs in `check-contrast.mjs` | C |
| 2.1.1 Keyboard (scroll) | Every list that does not fit scrolls in its own box (tree list, stage panels, help body, chip strip): focus moves (End, Tab) reveal items without scrolling a clipped frame; pane handles are focusable separators (arrows resize, double-click resets) | scroll review C1/C3/C6 | `scrollLayout.test.ts`, Playwright scroll probe | U, M |
| 1.4.12 Text spacing | No clipping with user spacing overrides | Q-A7 | Manual bookmarklet | M |
| 1.4.13 Content on hover/focus | Disabled-reason tooltip shows on focus and hover, dismissible with Esc, stays while hovered | U3 / 4.4 | `DisabledReason` | U, M |
| 2.1.1 Keyboard | Every function reachable: tree, grid, viewer tabs, palette, review marks | Q-A1 | Roving tabindex, shortcut map | U, E |
| 2.1.2 No keyboard trap | Palette, dialogs and overlay viewer trap only while open; Esc exits | 4.4 | `useFocusTrap`, `useEscape` | U, E |
| 2.1.4 Character key shortcuts | Single-key shortcuts (J/K, R/X/I/B, 1-5) disabled while typing in inputs; `?` lists them | U5 | `isTextEntry` guard in roving, command registry | U, E |
| 2.2.2 Pause, stop, hide | No auto-moving content; progress is not animated under reduced motion | 4.4 | Reduced-motion media rule | E |
| 2.3.3 / animation | `prefers-reduced-motion` zeroes animations and transitions | 4.4 | e2e computed-style scan | E |
| 2.4.1 Bypass blocks | Skip link is the first Tab stop, targets `main` (`tabindex=-1`) | 4.4 skip link | `SkipLink` | U, E |
| 2.4.2 Page titled | Document title set; updates with case/collection | 4.4 | `document-title` rule | E |
| 2.4.3 Focus order | Tree, grid, viewer, status bar in logical order; overlay returns focus | 4.4 | `useRestoreFocus`, `useFocusTrap` return | U, E, M |
| 2.4.6 Headings and labels | Regions and grids have accessible names (`원본 뷰어`, grid label) | 4.4 viewer | `grid-name`, region name assertions | E |
| 2.4.7 Focus visible | Global `:focus-visible` ring on every control | 4.4 | e2e focus scan | E, M |
| 3.1.1 Language of page | `html[lang]` set | 4.4 | `html-lang` rule | E |
| 3.2.1 / 3.2.2 On focus/input | Focus or typing never changes context; type-ahead and roving only move focus | 4.4 | Roving tests | U |
| 3.3.1 / 3.3.3 Errors | Errors announced assertively with the correction hint | 4.4 live | `announce(..., {politeness: "assertive"})` | U, M |
| 3.3.2 Labels or instructions | Palette, filter and search inputs labelled | 4.4 | `field-name` rule | E |
| 4.1.2 Name, role, value | All controls named; `aria-selected`, `aria-expanded`, `aria-sort`, `aria-busy`, `aria-disabled` accurate | 4.4 | `accessible-name`, `row-selected`, `tab-selected` rules | U, E, M |
| 4.1.3 Status messages | Result counts and progress in one polite region; failures in one assertive region; short sentences only | 4.4 grid count | `LiveRegion` + `announce` | U, E, M |

## Project gates

| Gate | Check | Command |
|---|---|---|
| Q-A1 | Keyboard-only loop completes with no mouse and state reaches `case-db/review` | `npm run e2e -- a11y.spec.ts -g Q-A1` |
| Q-A3 | Every control responds or is disabled with a reason | `npm run e2e -- a11y.spec.ts -g Q-A3` |
| Q-A6 | 0 critical/serious rule violations on all 9 collection routes | `npm run e2e -- a11y.spec.ts` |
| Q-A6 | Contrast table passes for dark, light and light-OS | `npm run check:contrast` |
| Q-A6 | NVDA walkthrough recorded (below) | manual |

## Manual NVDA pass (record per release)

Browser: Firefox and Chrome on Windows with NVDA. Record date, versions, tester and results.

1. Tab from page load: skip link announced, Enter lands on the grid (main).
2. Tree: arrows move, level and expanded state announced, Enter opens a collection.
3. Grid: row selection and column header context read; Down announces next row; result count announced once after search.
4. Viewer: Enter on a row moves focus to the viewer title; mode tabs announce "tab, 2 of N, selected"; arrows switch mode.
5. Disabled control: focus it, the reason is read as a description, activating it does nothing.
6. Palette: opens with Ctrl+K, focus trapped, Esc returns focus to the previous control.
7. Review mark (R): confirmation announced politely; failure announced assertively.
8. Light and dark theme, 200% zoom: no loss of content or focus indicator.

Known open items are tracked in the S5 report (contrast failures for `--line`, light `--text-muted` on `--bg-raised`, light `--accent` on `--bg-raised`, light `--warn` on `--bg`).
