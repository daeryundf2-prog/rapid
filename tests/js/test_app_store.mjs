// Contract tests for app_store.js — state sync, bindings, subscriptions.
// Run: node tests/js/test_app_store.mjs

import {
  hasWorkbenchBinding,
  registerWorkbenchBinding,
  subscribeWorkbenchState,
  syncWorkbenchState,
  workbenchInvoke,
  workbenchState,
} from "../../rapidtriage/web/static/app_store.js";

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else { failures += 1; console.log(`FAIL - ${name}`); }
}

// --- state sync ---------------------------------------------------------------
const seen = [];
const unsubscribe = subscribeWorkbenchState((state) => seen.push({ ...state }));
syncWorkbenchState({ selectedRunId: "run-9", activeTab: "artifacts" });
check("sync writes scalar state", workbenchState.selectedRunId === "run-9" && workbenchState.activeTab === "artifacts");
check("subscribers notified", seen.length === 1 && seen[0].selectedRunId === "run-9");
unsubscribe();
syncWorkbenchState({ activeTab: "search" });
check("unsubscribe stops notifications", seen.length === 1);

// --- virtual window slice is app_state-owned ------------------------------------
workbenchState.virtualWindowOffsets.search = 42;
check("virtual window offsets writable", workbenchState.virtualWindowOffsets.search === 42);

// --- binding registry -------------------------------------------------------------
check("unregistered binding returns undefined", workbenchInvoke("nope") === undefined);
check("hasWorkbenchBinding false", !hasWorkbenchBinding("nope"));
registerWorkbenchBinding("add", (a, b) => a + b);
check("binding invokes with args", workbenchInvoke("add", 2, 3) === 5);
check("hasWorkbenchBinding true", hasWorkbenchBinding("add"));
registerWorkbenchBinding("add", () => 99);
check("re-registration replaces", workbenchInvoke("add") === 99);
registerWorkbenchBinding("detailPanel", () => ({ fake: true }));
check("element-provider binding works", workbenchInvoke("detailPanel").fake === true);

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all store-contract tests passed");
