/**
 * First screen (visual-polish S10 / U-V6): a centred card with the brand mark, the three ways
 * to start (케이스 만들기 · 케이스 열기 · 케이스 없이 빠른 런 · 샘플), the recent cases and the key hints. Without an API
 * token the same card asks for the token instead (the token gate lives inside the card).
 */

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { listCases } from "../../api/cases";
import { setAuthToken } from "../../api/client";
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

/** Recent cases listed on the card (newest first). */
export const LANDING_RECENT_COUNT = 6;

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

function RecentCases() {
  const { runs } = useRuns();
  const { timezone } = useTimezone();
  // 사건 번호 › 증거 번호 of runs started for a case (AXIOM adoption E1); others read "케이스 없음".
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  const caseOfRun = new Map<string, string>();
  for (const item of cases.data ?? []) {
    for (const evidence of item.evidence) {
      for (const run of evidence.runs)
        caseOfRun.set(run.run_id, `${item.case_number} › ${evidence.evidence_number}`);
    }
  }
  const recent = [...runs]
    .sort((a, b) => String(b.created_at ?? "").localeCompare(String(a.created_at ?? "")))
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
          {recent.map((run) => {
            const mode = RUN_MODE_LABEL[String(run.request?.mode ?? "")] ?? run.request?.mode ?? "";
            const when = run.created_at
              ? formatTimestamp(run.created_at, timezone, { precision: "minute" })
              : "";
            return (
              <li key={run.run_id}>
                <a
                  className="landing-case"
                  href={serializeRoute({ runId: run.run_id, collection: "intake" })}
                  title={run.request?.root ?? run.run_id}
                >
                  <span className="landing-case-line">
                    <span className="landing-case-name">{runDisplayName(run)}</span>
                    <span className="landing-case-meta">
                      {[
                        cases.data ? (caseOfRun.get(run.run_id) ?? "케이스 없음") : "",
                        mode,
                        when,
                        run.run_id.slice(0, 8),
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                  </span>
                  <StatusBadge status={String(run.status)} />
                  {/* The evidence path on the second line (review #21). */}
                  {run.request?.root ? (
                    <MiddlePath path={run.request.root} whole className="landing-case-path" />
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
      <section className="landing-card" aria-labelledby="landing-title">
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
            <div className="landing-actions">
              <CommandButton
                command="case.create"
                label="케이스 만들기"
                variant="primary"
                className="roomy"
                testId="landing-create"
              />
              <CommandButton
                command="case.switch"
                label="케이스 열기"
                className="roomy"
                testId="landing-open"
              />
              <CommandButton
                command="case.run"
                label="케이스 없이 빠른 런"
                className="roomy"
                testId="landing-run"
              />
              <CommandButton command="case.sample" label="샘플" className="roomy" testId="landing-sample" />
            </div>
            <RecentCases />
          </>
        )}
        {/* Key hints only once the console is usable (not on the token card, review #21). */}
        {tokenRequired ? null : (
          <p className="landing-keys">
            <kbd>{keyLabel("Ctrl+K")}</kbd> 명령 팔레트 <span aria-hidden="true">·</span> <kbd>?</kbd> 단축키
            도움말
          </p>
        )}
      </section>
    </div>
  );
}
