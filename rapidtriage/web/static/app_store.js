// Workbench store/event contract (R3-1).
//
// Breaks the app.js <-> app_state.js circular dependency: instead of importing
// mutable live bindings across module boundaries, shared state lives in this
// single store and cross-module callbacks go through a named binding registry.
//
// Ownership rules:
//   - app.js is the sole WRITER of scalar state (run id, tab, group, filter,
//     stage ids) via syncWorkbenchState().
//   - app_state.js (session/window persistence) may WRiTE virtualWindowOffsets
//     directly — it owns that slice.
//   - Any module may invoke registered bindings; registrations happen once at
//     app.js init through registerWorkbenchBindings().

export const workbenchState = {
  selectedRunId: null,
  activeTab: "summary",
  activeViewGroup: "triage",
  activeArtifactFilter: "",
  activeStageId: "",
  activeStageSubactionId: "",
  virtualWindowOffsets: { search: 0, caseDb: 0 },
};

/** Copy the scalar app-owned state into the store after a mutation. */
export function syncWorkbenchState(patch) {
  Object.assign(workbenchState, patch);
  for (const listener of stateListeners) {
    listener(workbenchState);
  }
}

const stateListeners = new Set();
export function subscribeWorkbenchState(listener) {
  stateListeners.add(listener);
  return () => stateListeners.delete(listener);
}

// --- Named binding registry --------------------------------------------------
// Cross-module calls use names so the dependency graph stays acyclic even
// when two modules need each other's functions.

const bindings = new Map();

export function registerWorkbenchBinding(name, fn) {
  bindings.set(name, fn);
}

export function workbenchInvoke(name, ...args) {
  const fn = bindings.get(name);
  return typeof fn === "function" ? fn(...args) : undefined;
}

export function hasWorkbenchBinding(name) {
  return bindings.has(name);
}
