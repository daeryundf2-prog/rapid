/**
 * testid constants (D.3, D65; T-157). testids are NOT part of the user contract: they are a
 * constants module that components and e2e specs both import, so renaming one is caught by the
 * type checker on both sides. Renaming is free as long as the component and its tests change in
 * the same PR. No release prefix (`r8-` …) on new ids.
 *
 * The full list of ids in the source is the extractor's reference output
 * (`node scripts/extract-ui-contract.mjs --json` → `testIds`); this module grows as specs and
 * components move onto it (T-157 first three specs, T-263 the rest).
 */
export const TEST_IDS = {
  // shell
  workbenchShell: "workbench-shell",
  popoutShell: "popout-shell",
  // grid
  gridRegion: "grid-region",
  gridFooterTotal: "grid-footer-total",
  filterPopoverButton: "filter-popover-button",
  // tree
  treeEmptyToggle: "tree-empty-toggle",
  // viewer
  viewerRail: "viewer-rail",
  viewerPopoutRail: "viewer-popout-rail",
  viewerActionsMenu: "viewer-actions-menu",
  evidenceInfo: "evidence-info",
  imageView: "image-view",
  imageStrip: "image-strip",
  mediaBlurToggle: "media-blur-toggle",
  // review tools
  tagNew: "tag-new",
  tagSave: "tag-save",
  baselineSave: "baseline-save",
  histCompare: "hist-compare",
  histCompareRow: "hist-compare-row",
  // chat / AI usage
  chatThread: "chat-thread",
  chatMessage: "chat-message",
  chatSender: "chat-sender",
  aiSessionLinks: "ai-session-links",
  aiToolCall: "ai-tool-call",
  aiToolCommand: "ai-tool-command",
  aiToolTarget: "ai-tool-target",
  aiFileTouch: "ai-file-touch",
  caseAiUsage: "case-ai-usage",
  aiUsageFacts: "ai-usage-facts",
  aiUsageCredentials: "ai-usage-credentials",
  aiUsageRetention: "ai-usage-retention",
  processAi: "process-ai",
  processAiRows: "process-ai-rows",
  processAiScope: "process-ai-scope",
} as const;

export type TestIdKey = keyof typeof TEST_IDS;
export type TestId = (typeof TEST_IDS)[TestIdKey];

/** CSS attribute selector for a testid (for compound selectors such as `[data-testid=…][data-x]`). */
export function testIdSelector(id: TestId): string {
  return `[data-testid="${id}"]`;
}
