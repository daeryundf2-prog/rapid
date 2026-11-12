// Shared fixtures of the 접수 case-card tests (caseCards.test.tsx, caseMemo.test.tsx): a case-linked
// run with one memo, its processing problems, and the mocked routes (`routes(false)` = caseless run).

import { screen } from "@testing-library/react";
import type { RecordedCall } from "../case/testUtils";

const run = {
  run_id: "r1",
  status: "completed",
  created_at: "2026-10-17T00:00:00Z",
  request: { root: "D:/ev/a.E01", mode: "fraud" },
};

const caseDetail = {
  case_id: "case-1",
  case_number: "2026-고단-1234",
  name: "법인 자금 유출",
  case_type: "횡령·배임",
  examiner: "홍길동",
  requester: "서울중앙지검",
  organization: "",
  description: "",
  case_root: "",
  citation_prefix: "2026-고단-1234",
  status: "open",
  created_at: "2026-10-17T00:00:00Z",
  updated_at: "2026-10-17T00:00:00Z",
  evidence_count: 2,
  run_count: 1,
  note_count: 1,
  evidence: [
    {
      citation_id: "2026-고단-1234-EVID-000002",
      evidence_number: "E-10",
      display_name: "b.E01",
      source_type: "e01",
      path: "D:/ev/b.E01",
      size_bytes: 10,
      hash_status: "mismatched",
      hash_status_label: "해시 불일치",
      hash_message: "MD5 기대값 … / 계산값 …",
      hashes: {},
      runs: [],
    },
    {
      citation_id: "2026-고단-1234-EVID-000001",
      evidence_number: "E-2",
      display_name: "a.E01",
      source_type: "e01",
      path: "D:/ev/a.E01",
      size_bytes: 10,
      hash_status: "matched",
      hash_status_label: "해시 일치",
      hash_message: "",
      hashes: { md5: "a" },
      runs: [{ run_id: "r1", exists: true, status: "completed" }],
    },
  ],
};

const snapshotLinked = {
  source: "case-db",
  run_id: "r1",
  case_id: "case-1",
  evidence_citation_id: "2026-고단-1234-EVID-000001",
  captured_at: "2026-10-17T00:00:00Z",
  snapshot: {
    origin: "case-run",
    evidence: { evidence_number: "E-2", path: "D:/ev/a.E01" },
    request: { root: "D:/ev/a.E01", mode: "fraud", read_only: true, max_file_count: 500, case_db: true },
    profile: { keywords: ["송금", "invoice"], artifacts_kinds: ["browser", "eventlog"] },
  },
  case: caseDetail,
  evidence: caseDetail.evidence[1],
};

const problems = {
  run_id: "r1",
  total: 23,
  by_level: { warning: 3, notice: 20 },
  limit: 20,
  groups: [
    {
      reason_id: "row-truncated",
      label_ko: "행 단위 절단 (원문 일부만 보존)",
      level: "warning",
      count: 3,
      steps: [],
      items: [
        { source: "warning", step: "artifacts-recent-files", level: "warning", message: "행 단위 절단 10행" },
      ],
    },
    {
      reason_id: "no-rows",
      label_ko: "수집된 행 없음",
      level: "notice",
      count: 22,
      steps: [],
      items: Array.from({ length: 20 }, (_, i) => ({
        source: "warning",
        step: `artifacts-k${i}`,
        level: "notice",
        message: `No k${i} artifact rows were collected.`,
      })),
    },
  ],
};

export let notes = {
  notes: [
    {
      id: 1,
      case_id: "case-1",
      author: "홍길동",
      text: "압수 목록 확인",
      created_at: "2026-10-17T01:00:00Z",
      updated_at: "2026-10-17T01:00:00Z",
      deleted_at: null,
      deleted_by: "",
    },
  ],
  count: 1,
  deleted_count: 0,
  history: [
    {
      id: 1,
      note_id: 1,
      action: "created",
      actor: "홍길동",
      at: "2026-10-17T01:00:00Z",
      text: "압수 목록 확인",
    },
  ],
};

export function routes(linked: boolean) {
  return {
    "GET /api/runs/r1": run,
    "GET /api/runs/r1/processing-snapshot": linked
      ? snapshotLinked
      : {
          source: "run-request",
          run_id: "r1",
          case_id: null,
          evidence_citation_id: null,
          captured_at: "2026-10-17T00:00:00Z",
          snapshot: {
            origin: "run-request",
            request: { root: "D:/ev/a.E01", mode: "fraud", read_only: true },
          },
          case: null,
          evidence: null,
        },
    "GET /api/cases/case-1": { case: caseDetail },
    "GET /api/cases/case-1/notes": () => notes,
    "POST /api/cases/case-1/notes": (call: RecordedCall) => {
      const body = call.body as { text: string; author: string };
      const note = {
        ...notes.notes[0],
        id: 2,
        text: body.text,
        author: body.author,
        created_at: "2026-10-17T02:00:00Z",
      };
      notes = { ...notes, notes: [note as (typeof notes.notes)[0], ...notes.notes], count: 2 };
      return { note };
    },
    "GET /api/runs/r1/problems": problems,
    "GET /api/runs/r1/dashboard": {
      run_id: "r1",
      completed: true,
      profile: { mode: "fraud", description: "", keywords: [] },
      evidence_source: {
        path: "D:/ev/a.E01",
        name: "a.E01",
        kind: "image",
        image_output: "e01",
        size_bytes: 10,
        partitions: [],
        selected_partition: null,
      },
      exports: [],
    },
    "GET /api/runs/r1/case-notes": {
      run_id: "r1",
      examiner: "",
      summary: "",
      updated_at: null,
      exists: false,
    },
  };
}

export const cardOf = (title: string) =>
  screen.getByRole("heading", { name: title }).closest("section") as HTMLElement;
