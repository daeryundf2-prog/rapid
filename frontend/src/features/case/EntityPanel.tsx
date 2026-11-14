import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { announce } from "../../a11y";
import { ApiError } from "../../api/client";
import {
  type AdvancedQueryResult,
  type EntityValue,
  entityKindLabel,
  fetchEntitySummary,
  languageLabel,
  QUERY_SYNTAX_HELP,
  revealEntity,
  runAdvancedQuery,
  type SearchRow,
} from "../../api/searchEntities";
import { useWriteBlock } from "../../shell/readOnly";
import { useRoute } from "../../state/hooks";
import { evidencePathOf } from "../../utils/pathDisplay";
import { ensureRunCaseDb } from "../grid/reviewActions";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { useSearchState } from "./searchState";

/**
 * 개체·언어 검색 (R7 lane B): the run's named entities (주민등록번호·카드·전화·계좌·사업자/법인
 * 등록번호·여권·이메일·IP·호스트) and document languages as chips with counts, an advanced query
 * box with its syntax help, the matching rows with their masked values, and the audited reveal of
 * one value of one row. Personal numbers are only ever masks here; a revealed value lives in this
 * panel's state until it closes (never in a store, a URL or storage).
 *
 * Reveal: the first reveal of a browser session asks for a reason and says what is written (one
 * audit record per reveal in the run's case DB, created if missing); later reveals of the session
 * reuse the reason. Each reveal is one row's one value.
 */

/** Console field tokens the top-bar search understands (hits.py CONSOLE_FIELD_RE). */
const CONSOLE_FIELD =
  /^-?(?:rrn|corpno|card|bizno|phone|account|passport|email|ip|host|lang|hashset|list):[^\s()"]+$/;
const SESSION_REASON_KEY = "rapidtriage.reveal-reason";
export const REVEAL_NOTE =
  "값을 공개할 때마다 이 런의 케이스 DB에 감사 기록 1건(누가·언제·어느 행의 어떤 개체·사유, 값은 기록하지 않음)이 남습니다. 케이스 DB가 없으면 먼저 만듭니다.";

function sessionReason(): string | null {
  try {
    return window.sessionStorage.getItem(SESSION_REASON_KEY);
  } catch {
    return null;
  }
}

function rememberReason(reason: string): void {
  try {
    window.sessionStorage.setItem(SESSION_REASON_KEY, reason);
  } catch {
    // Without storage the next reveal asks again.
  }
}

/** The query as top-bar keywords (fields + words), or null when it uses grammar the bar lacks. */
export function consoleKeywords(q: string): string | null {
  const tokens = q.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  const ok = tokens.every(
    (token) => CONSOLE_FIELD.test(token) || (!/[():"]/.test(token) && !/^(AND|OR|NOT)$/.test(token)),
  );
  return ok ? tokens.join(" ") : null;
}

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "요청을 처리하지 못했습니다.";
}

interface RevealTarget {
  row: SearchRow;
  entity: EntityValue;
}

function revealKey(row: SearchRow, entity: EntityValue): string {
  return `${row.collection}\u0000${row.kind}\u0000${row.locator}\u0000${entity.value_sha256}`;
}

export function EntityPanel({ runId, onClose }: { runId: string; onClose: () => void }) {
  const preset = useSearchState((s) => s.entityQuery);
  const [draft, setDraft] = useState(preset);
  const [query, setQuery] = useState(preset);
  const [helpOpen, setHelpOpen] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<RevealTarget | null>(null);
  const [reason, setReason] = useState("");
  const writeBlock = useWriteBlock("run"); // T-348: a reveal writes an audit record
  const [revealError, setRevealError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { openCollection } = useRoute();

  const summary = useQuery({
    queryKey: ["search-entities", runId],
    queryFn: ({ signal }) => fetchEntitySummary(runId, {}, signal),
    retry: false,
  });
  const result = useQuery<AdvancedQueryResult>({
    queryKey: ["search-advanced", runId, query],
    queryFn: ({ signal }) => runAdvancedQuery(runId, query, {}, signal),
    enabled: query.trim().length > 0,
    retry: false,
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setQuery(draft.trim());
  };
  const runPreset = (q: string) => {
    setDraft(q);
    setQuery(q);
  };

  const doReveal = async (target: RevealTarget, why: string) => {
    setBusy(true);
    setRevealError(null);
    try {
      const response = await revealEntity(runId, target.row, target.entity.value_sha256, why).catch(
        async (error: unknown) => {
          // No case DB yet: make it (the confirmation said so), then reveal once more.
          if (error instanceof ApiError && error.status === 409 && /케이스 DB/.test(error.message)) {
            const handle = await ensureRunCaseDb(runId);
            if (!handle) throw new Error("이 런은 케이스 DB를 만들 수 없어 값을 공개할 수 없습니다.");
            return revealEntity(runId, target.row, target.entity.value_sha256, why);
          }
          throw error;
        },
      );
      setRevealed((current) => ({ ...current, [revealKey(target.row, target.entity)]: response.value }));
      announce(`${entityKindLabel(target.entity.kind)} 값을 공개했습니다(감사 기록 ${response.audit_id})`);
    } catch (error) {
      setRevealError(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const askReveal = (target: RevealTarget) => {
    const saved = sessionReason();
    if (saved) {
      void doReveal(target, saved);
      return;
    }
    setReason("");
    setConfirming(target);
  };

  const confirmReveal = (event: FormEvent) => {
    event.preventDefault();
    if (!confirming || !reason.trim()) return;
    rememberReason(reason.trim());
    const target = confirming;
    setConfirming(null);
    void doReveal(target, reason.trim());
  };

  const keywords = consoleKeywords(query);
  const kinds = summary.data?.kinds ?? [];
  const languages = summary.data?.languages ?? [];
  const rows = result.data?.rows ?? [];
  const lists = result.data?.lists ?? [];
  const warnings = result.data?.query.parsed.warnings ?? [];

  return (
    <Modal title="개체·언어 검색" onClose={onClose} wide>
      <form className="entity-query" onSubmit={submit}>
        <div className="case-field">
          <label htmlFor="entity-q">고급 검색 질의</label>
          <input
            id="entity-q"
            type="search"
            value={draft}
            placeholder="예: rrn:verified in:docs"
            onChange={(event) => setDraft(event.target.value)}
          />
        </div>
        <div className="case-actions">
          <button
            type="button"
            className="button"
            aria-expanded={helpOpen}
            onClick={() => setHelpOpen(!helpOpen)}
          >
            문법 도움말
          </button>
          <ReasonButton
            reason={
              keywords ? undefined : "괄호·OR·pre: 같은 문법은 검색 창으로 옮길 수 없습니다. 이 창에서 보세요"
            }
            onClick={() => {
              if (!keywords) return;
              openCollection("search", { q: keywords });
              onClose();
            }}
          >
            검색 결과 그리드로
          </ReasonButton>
          <button type="submit" className="button primary" disabled={!draft.trim()}>
            검색
          </button>
        </div>
      </form>
      {helpOpen && (
        <dl className="entity-syntax" aria-label="검색 문법">
          {QUERY_SYNTAX_HELP.map((item) => (
            <div key={item.example}>
              <dt>
                <button type="button" className="button link" onClick={() => runPreset(item.example)}>
                  <code>{item.example}</code>
                </button>
              </dt>
              <dd>{item.text}</dd>
            </div>
          ))}
        </dl>
      )}

      <section aria-label="개체 요약" className="entity-summary">
        <h3>개체</h3>
        {summary.isPending && <p aria-busy="true">개체를 세는 중…</p>}
        {summary.isError && <ErrorText>{errorText(summary.error)}</ErrorText>}
        {summary.data && kinds.length === 0 && (
          <p className="case-reason">이 런의 검색 색인에서 찾은 개체가 없습니다.</p>
        )}
        <ul className="entity-chips">
          {kinds.map((item) => (
            <li key={item.kind}>
              <button type="button" className="chip" onClick={() => runPreset(`${item.kind}:*`)}>
                {entityKindLabel(item.kind)}{" "}
                <span className="chip-count">{item.rows.toLocaleString()}행</span>
                {item.verified_values > 0 && item.verified_values < item.values && (
                  <span className="chip-note"> · 검증 {item.verified_values.toLocaleString()}개</span>
                )}
              </button>
            </li>
          ))}
        </ul>
        {languages.length > 0 && (
          <>
            <h3>언어</h3>
            <ul className="entity-chips">
              {languages.map((item) => (
                <li key={item.key}>
                  <button type="button" className="chip" onClick={() => runPreset(`lang:${item.key}`)}>
                    {languageLabel(item.key)}{" "}
                    <span className="chip-count">{item.count.toLocaleString()}행</span>
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section aria-label="검색 결과" className="entity-results">
        {result.isFetching && <p aria-busy="true">검색하는 중…</p>}
        {result.isError && <ErrorText>{errorText(result.error)}</ErrorText>}
        {result.data && (
          <p className="entity-total">
            {result.data.page.total === null ? "결과" : `결과 ${result.data.page.total.toLocaleString()}건`}
            {result.data.truncated && " (시간 예산이 끝나 일부만)"}
          </p>
        )}
        {warnings.map((warning) => (
          <p key={warning} className="case-reason">
            {warning}
          </p>
        ))}
        {lists.map((list) => (
          <table key={list.id} className="entity-list-counts">
            <caption>검색 목록 {list.name} 항목별 건수</caption>
            <thead>
              <tr>
                <th scope="col">항목</th>
                <th scope="col">건수</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((item) => (
                <tr key={item.item}>
                  <td>{item.item}</td>
                  <td>{item.count === null ? "—" : item.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
        {revealError && <ErrorText>{revealError}</ErrorText>}
        <ul className="entity-rows" data-testid="entity-rows">
          {rows.map((row) => (
            <li key={`${row.collection}:${row.kind}:${row.locator}`} data-testid="entity-row">
              <div className="entity-row-title">{row.title || evidencePathOf(row.path).path}</div>
              {row.snippet?.text && <div className="entity-row-snippet">{row.snippet.text}</div>}
              {(row.entities ?? []).length > 0 && (
                <ul className="entity-values" aria-label="이 행의 개체">
                  {(row.entities ?? []).map((entity) => {
                    const shown = revealed[revealKey(row, entity)];
                    const sensitive = !["ip", "host"].includes(entity.kind);
                    return (
                      <li key={`${entity.kind}:${entity.value_sha256}`}>
                        <span className="entity-kind">{entityKindLabel(entity.kind)}</span>{" "}
                        <code data-raw-ok>{shown ?? entity.masked}</code>
                        {!entity.verified && <span className="chip-note"> 후보</span>}
                        {sensitive && shown === undefined && (
                          <button
                            type="button"
                            className="button link"
                            disabled={busy || Boolean(writeBlock)}
                            title={writeBlock}
                            onClick={() => askReveal({ row, entity })}
                          >
                            값 보기
                          </button>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </section>

      {confirming && (
        <form className="entity-reveal-confirm" onSubmit={confirmReveal} aria-label="값 공개 확인">
          <p>
            {entityKindLabel(confirming.entity.kind)} <code>{confirming.entity.masked}</code>의 값을
            공개합니다.
          </p>
          <p className="case-reason">{REVEAL_NOTE}</p>
          <div className="case-field">
            <label htmlFor="entity-reveal-reason">공개 사유(이 세션의 다음 공개에도 씁니다)</label>
            <input
              id="entity-reveal-reason"
              type="text"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <div className="case-actions">
            <button type="button" className="button" onClick={() => setConfirming(null)}>
              취소
            </button>
            <ReasonButton
              reason={writeBlock ?? (reason.trim() ? undefined : "공개 사유를 입력하세요.")}
              type="submit"
              className="button primary"
            >
              감사 기록 남기고 공개
            </ReasonButton>
          </div>
        </form>
      )}
    </Modal>
  );
}
