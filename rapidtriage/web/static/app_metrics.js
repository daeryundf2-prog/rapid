// Canonical run counters.
//
// Every headline number shown in the UI must come from runCounts(). The backend
// writes `summary.counts` in the run summary (and the API backfills it for
// summaries created before the block existed); the fallbacks below mirror the
// backend formulas in `rapidtriage/core/run/summary.py:derive_counts` so a
// locally cached payload still resolves to the same numbers.
//
// Do not re-derive counters at call sites — add a field here instead.

const numberOr = (value, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

function asNormalizedPayload(source) {
  if (!source || typeof source !== "object") return {};
  // Job objects wrap the run payload under `.summary`.
  if (source.summary?.summary) return source.summary;
  return source;
}

export function runCounts(source) {
  const payload = asNormalizedPayload(source);
  const summary = payload.summary || {};
  const processing = payload.processing || {};
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  const canonical = summary.counts && typeof summary.counts === "object" ? summary.counts : null;
  const breakdown = canonical?.validation_issue_breakdown || {};
  const outputs = payload.outputs && typeof payload.outputs === "object" ? payload.outputs : {};
  const artifactGroups = summary.artifacts && typeof summary.artifacts === "object" ? summary.artifacts : {};
  const indicatorStep = steps.find((step) => step?.name === "indicators") || {};

  const stepWarnings = numberOr(processing.warning_count);
  const parserErrors = steps.reduce((total, step) => total + numberOr(step?.parser_error_count), 0);
  const derivedArtifacts = Object.values(artifactGroups).reduce(
    (total, group) => total + numberOr(group?.artifact_count),
    0,
  );

  return {
    validationIssues: numberOr(canonical?.validation_issues, stepWarnings + parserErrors),
    validationIssueBreakdown: {
      stepWarnings: numberOr(breakdown.step_warnings, stepWarnings),
      parserErrors: numberOr(breakdown.parser_errors, parserErrors),
    },
    outputs: numberOr(canonical?.outputs, Object.keys(outputs).length),
    artifacts: numberOr(canonical?.artifacts, derivedArtifacts),
    docs: numberOr(canonical?.docs, summary.document_match_count),
    files: numberOr(canonical?.files, summary.file_candidate_count),
    timelineEvents: numberOr(canonical?.timeline_events, summary.timeline_event_count),
    reviewItems: numberOr(canonical?.review_items, summary.report_item_count),
    indicators: numberOr(canonical?.indicators, indicatorStep.indicator_count),
  };
}
