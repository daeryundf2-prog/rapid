/**
 * First screen (visual-polish S10 / U-V6, F29): the brand, one primary start (케이스 만들기) with
 * the other ways to start grouped beside it as quieter buttons, then the recent cases — each row
 * leads with the case number and name (never cut), the last activity under it and the evidence
 * path last. Without an API token the same panel asks for the token instead.
 */

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { type CaseDetail, listCases } from "../../api/cases";
import { setAuthToken } from "../../api/client";
import type { RunWithProgress } from "../../api/runsProgress";
import { RUN_MODE_LABEL, runDisplayName } from "../../app/collections";
import { CommandButton } from "../../commands/CommandButton";
import { StatusBadge } from "../../components/Badge";
import { MiddlePath } from "../../components/MiddlePath";
import { serializeRoute } from "../../router";
import { BrandMark } from "../../shell/BrandMark";
import { keyLabel } from "../../shortcuts";
import { useRuns, useTimezone } from "../../state/hooks";
import { formatTimestamp } from "../../utils/time";
import "./case.css";

/** Recent cases listed on the landing (latest activity first). */
export const LANDING_RECENT_COUNT = 6;

/** Text of the run without a case (quick runs, samples). */
export const NO_CASE_LABEL = "케이스 없음";

function TokenForm({ onSaved }: { onSaved: () => void }) {
  const [value, setValue] = useState("");
  const hintId = useId();
  return (
    <form
      className="landing-token"
      data-testid="token-gate"
      onSubmit={(event) => {
        event.preventDefault();
        if (!value.trim()) return;
        setAuthToken(value.trim());
        onSaved();
      }}
    >
      <p id={hintId} className="landing-note">
        서버를 시작한 콘솔에 출력된 API 토큰을 붙여넣으세요. 토큰은 이 브라우저 세션에만 저장됩니다.
      </p>
      <div className="landing-token-row">
        <input
          type="password"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="API 토큰"
          aria-label="API 토큰"
          aria-describedby={hintId}
          // biome-ignore lint/a11y/noAutofocus: the token is the only thing this screen asks for
          autoFocus
        />
        <button type="submit" className="button primary roomy">
          연결
        </button>
      </div>
    </form>
  );
}

type CaseRunLink = { caseNumber: string; caseName: string; evidenceNumber: string };

/** Case number, name and evidence number of every run started for a case (AXIOM adoption E1). */
export function caseIndex(
  cases: readonly Pick<CaseDetail, "case_number" | "name" | "evidence">[] | undefined,
): Map<string, CaseRunLink> {
  const index = new Map<string, CaseRunLink>();
  for (const item of cases ?? []) {
    for (const evidence of item.evidence ?? []) {
      for (const run of evidence.runs ?? []) {
        index.set(run.run_id, {
          caseNumber: item.case_number,
          caseName: item.name,
          evidenceNumber: evidence.evidence_number,
        });
      }
    }
  }
  return index;
}

export interface RecentCaseRow {
  /** Case number (사건 번호), or "케이스 없음" for a quick run; "" while the case list loads. */
  number: string;
  /** What the analyst recognises: the case name, else the evidence folder name. Never cut. */
  name: string;
  /** Evidence number (E-001) of a case run. */
  evidence: string;
  /** Last activity: the run's last update, else its start (ISO). */
  activeAt: string;
  mode: string;
}

/**
 * One recent-case row (F29): the case number and name first, the run's mode and last activity
 * second, the evidence path last. A case named like its number shows the evidence folder as the
 * name, so the line never repeats itself.
 */
export function recentCaseRow(
  run: Pick<RunWithProgress, "run_id" | "created_at" | "updated_at" | "request">,
  cases: ReadonlyMap<string, CaseRunLink> | null,
): RecentCaseRow {
  const link = cases?.get(run.run_id);
  const folder = runDisplayName(run);
  const caseName = link?.caseName?.trim() ?? "";
  return {
    number: cases ? (link?.caseNumber ?? NO_CASE_LABEL) : "",
    name: caseName && caseName !== link?.caseNumber ? caseName : folder,
    evidence: link?.evidenceNumber ?? "",
    activeAt: String(run.updated_at || run.created_at || ""),
    mode: RUN_MODE_LABEL[String(run.request?.mode ?? "")] ?? String(run.request?.mode ?? ""),
  };
}

function RecentCases() {
  const { runs } = useRuns();
  const { timezone } = useTimezone();
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  const index = cases.data ? caseIndex(cases.data) : null;
  const recent = [...runs]
    .map((run) => ({ run, row: recentCaseRow(run, index) }))
    .sort((a, b) => b.row.activeAt.localeCompare(a.row.activeAt))
    .slice(0, LANDING_RECENT_COUNT);
  return (
    <section className="landing-recent" aria-labelledby="landing-recent-title">
      <h2 id="landing-recent-title" className="landing-section-title">
        최근 케이스
      </h2>
      {recent.length === 0 ? (
        <p className="landing-note">
          아직 케이스가 없습니다. 케이스를 만들거나 케이스 없이 빠른 런·샘플로 시작하세요.
        </p>
      ) : (
        <ul className="landing-cases">
          {recent.map(({ run, row }) => {
            const when = row.activeAt ? formatTimestamp(row.activeAt, timezone, { precision: "minute" }) : "";
            return (
              <li key={run.run_id}>
                <a
                  className="landing-case"
                  href={serializeRoute({ runId: run.run_id, collection: "intake" })}
                  title={run.request?.root ?? run.run_id}
                >
                  <span className="landing-case-title">
                    {row.number ? <span className="landing-case-number">{row.number}</span> : null}
                    <span className="landing-case-name">{row.name}</span>
                  </span>
                  <StatusBadge status={String(run.status)} />
                  <span className="landing-case-meta">
                    {when ? <span>마지막 활동 {when}</span> : null}
                    {row.mode ? <span>{row.mode}</span> : null}
                    <span className="mono">런 {run.run_id.slice(0, 8)}</span>
                  </span>
                  {/* The evidence (number + root) last, the path cut in the middle (review #21). */}
                  {run.request?.root ? (
                    <span className="landing-case-evidence">
                      {row.evidence ? <span className="landing-case-evidence-no">{row.evidence}</span> : null}
                      <MiddlePath path={run.request.root} whole className="landing-case-path" />
                    </span>
                  ) : null}
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export function Landing({
  tokenRequired = false,
  onTokenSaved,
}: {
  tokenRequired?: boolean;
  onTokenSaved?: () => void;
}) {
  return (
    <div className="landing" data-testid="landing">
      <section className="landing-panel" aria-labelledby="landing-title">
        <div className="landing-head">
          <BrandMark size={40} />
          <div>
            <h1 id="landing-title" className="landing-title">
              RapidForensic
            </h1>
            <p className="landing-sub">디지털 증거 선별·분석 콘솔</p>
          </div>
        </div>
        {tokenRequired ? (
          <TokenForm onSaved={() => onTokenSaved?.()} />
        ) : (
          <>
            {/* One primary start; the other ways to start are grouped, quieter (F29). */}
            <div className="landing-actions">
              <CommandButton
                command="case.create"
                label="케이스 만들기"
                variant="primary"
                className="roomy"
                testId="landing-create"
              />
              <fieldset className="landing-secondary" aria-label="다른 시작 방법">
                <CommandButton
                  command="case.switch"
                  label="케이스 열기"
                  variant="ghost"
                  className="roomy"
                  testId="landing-open"
                />
                <CommandButton
                  command="case.run"
                  label="케이스 없이 빠른 런"
                  variant="ghost"
                  className="roomy"
                  testId="landing-run"
                />
                <CommandButton
                  command="case.sample"
                  label="샘플"
                  variant="ghost"
                  className="roomy"
                  testId="landing-sample"
                />
              </fieldset>
            </div>
            <RecentCases />
          </>
        )}
        {/* Key hints only once the console is usable (not on the token panel, review #21). */}
        {tokenRequired ? null : (
          <p className="landing-keys">
            <span>
              <kbd>{keyLabel("Ctrl+K")}</kbd> 명령 팔레트
            </span>
            <span>
              <kbd>?</kbd> 단축키 도움말
            </span>
          </p>
        )}
      </section>
    </div>
  );
}
