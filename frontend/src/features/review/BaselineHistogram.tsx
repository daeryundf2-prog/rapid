/**
 * 히스토그램 기준선 (AXIOM E3, research §7.1 "기준선 저장/로드 비교"): above the artifact-kind
 * histogram, save the run's category counts as a named baseline (server computes them:
 * files · documents · timeline · indicators · each artifact kind) and compare the run with a
 * saved baseline — two bars per category (current, baseline) with the delta. The chosen
 * baseline is remembered per run (localStorage, never throws).
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from "react";
import { announce, useRovingTabindex } from "../../a11y";
import { getReviewCounts } from "../../api/caseDb";
import {
  createHistogramBaseline,
  getRunHistogram,
  type HistogramBar,
  listHistogramBaselines,
} from "../../api/reviewTools";
import { useRoute, useTimezone } from "../../state/hooks";
import { readStored, writeStored } from "../../state/storage";
import { formatTimestamp } from "../../utils/time";
import { ErrorText } from "../case/ErrorText";
import { ReasonButton } from "../case/ReasonButton";
import { currentReviewer } from "./author";
import { tagHandle } from "./tagStore";
import "./review.css";

const collator = new Intl.Collator("ko", { numeric: true });
const baselineKey = (runId: string) => `rapidtriage.histBaseline.${runId}`;

export function deltaText(delta: number): string {
  if (delta > 0) return `+${delta.toLocaleString("ko-KR")}`;
  if (delta < 0) return `−${Math.abs(delta).toLocaleString("ko-KR")}`;
  return "0";
}

/** Bars by current count (then baseline count, then Korean label). */
export function sortCompareBars(bars: readonly HistogramBar[]): HistogramBar[] {
  return [...bars].sort(
    (a, b) =>
      b.count - a.count ||
      (b.baseline_count ?? 0) - (a.baseline_count ?? 0) ||
      collator.compare(a.label, b.label),
  );
}

const COLLECTION_KEYS = new Set(["files", "docs", "timeline", "indicators"]);

/** What clicking a compare bar opens (the same as the plain bars: the kind node / the collection). */
export function compareBarTarget(
  key: string,
):
  | { collection: "artifacts"; kind: string }
  | { collection: "files" | "docs" | "timeline" | "indicators" }
  | null {
  const [group, id = ""] = key.split(/:(.*)/s);
  if (group === "kind" && id) return { collection: "artifacts", kind: id };
  if (group === "collection" && COLLECTION_KEYS.has(id))
    return { collection: id as "files" | "docs" | "timeline" | "indicators" };
  return null;
}

export function CompareBars({
  bars,
  baselineName,
  onOpen,
}: {
  bars: readonly HistogramBar[];
  baselineName: string;
  /** Click / Enter on a category (Q-A3 click-to-filter kept in compare mode). */
  onOpen?: (bar: HistogramBar) => void;
}) {
  const sorted = sortCompareBars(bars);
  const listRef = useRef<HTMLUListElement | null>(null);
  const roving = useRovingTabindex(listRef, {
    orientation: "vertical",
    itemSelector: "button.hist-compare-row",
  });
  const max = Math.max(1, ...sorted.map((bar) => Math.max(bar.count, bar.baseline_count ?? 0)));
  const total = sorted.reduce((sum, bar) => sum + bar.count, 0);
  const baseTotal = sorted.reduce((sum, bar) => sum + (bar.baseline_count ?? 0), 0);
  return (
    <div className="hist-compare-view" data-testid="hist-compare">
      <p className="hist-legend">
        <span>
          <span className="tag-swatch" style={{ background: "var(--tag-5)" }} aria-hidden="true" />
          현재 런 {total.toLocaleString("ko-KR")}건
        </span>
        <span>
          <span className="tag-swatch" style={{ background: "var(--tag-8)" }} aria-hidden="true" />
          기준선 '{baselineName}' {baseTotal.toLocaleString("ko-KR")}건
        </span>
        <span>증감 {deltaText(total - baseTotal)}</span>
      </p>
      <ul
        ref={listRef}
        className="hist-compare"
        aria-label={`기준선 '${baselineName}'과(와) 비교한 범주 ${sorted.length}개`}
        {...roving.containerProps}
      >
        {sorted.map((bar, index) => {
          const base = bar.baseline_count ?? 0;
          const delta = bar.delta ?? bar.count - base;
          const openable = Boolean(onOpen && compareBarTarget(bar.key));
          return (
            <li key={bar.key}>
              <button
                type="button"
                className="hist-compare-row"
                data-testid="hist-compare-row"
                aria-label={`${bar.label}: 현재 ${bar.count.toLocaleString("ko-KR")}건, 기준선 ${base.toLocaleString("ko-KR")}건, 증감 ${deltaText(delta)}${openable ? ", 노드 열기" : ""}`}
                disabled={!openable}
                {...roving.getItemProps(index)}
                onClick={() => onOpen?.(bar)}
              >
                <span className="hist-compare-label" title={bar.label} aria-hidden="true">
                  {bar.label}
                </span>
                <span className="hist-compare-tracks" aria-hidden="true">
                  <span className="hist-compare-track">
                    <span
                      className="hist-compare-fill is-current"
                      style={{ width: `${(bar.count / max) * 100}%` }}
                    />
                  </span>
                  <span className="hist-compare-track">
                    <span
                      className="hist-compare-fill is-baseline"
                      style={{ width: `${(base / max) * 100}%` }}
                    />
                  </span>
                </span>
                {/* Increase / decrease are facts, not good or bad: neutral tokens, sign in text. */}
                <span
                  className="hist-compare-delta"
                  data-sign={delta > 0 ? "up" : delta < 0 ? "down" : undefined}
                  aria-hidden="true"
                >
                  {bar.count.toLocaleString("ko-KR")} ({deltaText(delta)})
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function BaselineHistogram({ runId, children }: { runId: string; children: ReactNode }) {
  const queryClient = useQueryClient();
  const { timezone } = useTimezone();
  const selectId = useId();
  const nameId = useId();
  const [chosen, setChosen] = useState<number | null>(() => {
    const raw = Number(readStored(baselineKey(runId)) ?? "");
    return Number.isInteger(raw) && raw > 0 ? raw : null;
  });
  const [naming, setNaming] = useState(false);
  // Closing the name form (저장 · 취소 · Esc) hands focus back to the button that opened it.
  const openerRef = useRef<HTMLButtonElement>(null);
  const restoreFocus = useRef(false);
  const closeNaming = () => {
    restoreFocus.current = true;
    setNaming(false);
  };
  useEffect(() => {
    if (naming || !restoreFocus.current) return;
    restoreFocus.current = false;
    openerRef.current?.focus();
  }, [naming]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const listKey = useMemo(() => ["histogram-baselines", runId] as const, [runId]);
  const baselines = useQuery({
    queryKey: listKey,
    queryFn: async () => {
      const counts = await getReviewCounts(runId);
      if (!counts.exists) return [];
      return (await listHistogramBaselines(runId, counts.case_id)).baselines;
    },
    retry: false,
  });
  const known = baselines.data ?? [];
  const active = chosen !== null ? known.find((item) => item.id === chosen) : undefined;
  const compare = useQuery({
    queryKey: ["run-histogram", runId, active?.id ?? null],
    queryFn: ({ signal }) => getRunHistogram(runId, active?.id ?? null, signal),
    enabled: Boolean(active),
    retry: false,
  });

  const { openCollection } = useRoute();
  const openBar = (bar: HistogramBar) => {
    const target = compareBarTarget(bar.key);
    if (!target) return;
    if (target.collection === "artifacts") openCollection("artifacts", { kind: target.kind });
    else openCollection(target.collection);
  };

  const choose = (id: number | null) => {
    setChosen(id);
    writeStored(baselineKey(runId), id === null ? null : String(id));
    const item = id === null ? undefined : known.find((entry) => entry.id === id);
    announce(item ? `기준선 '${item.name}'과(와) 비교합니다` : "기준선 비교를 껐습니다");
  };

  const save = async () => {
    const clean = name.replace(/\s+/g, " ").trim();
    if (!clean) return;
    setBusy(true);
    setError(null);
    try {
      const handle = await tagHandle(runId);
      const { baseline } = await createHistogramBaseline(runId, handle.case_id, clean, currentReviewer());
      await queryClient.invalidateQueries({ queryKey: listKey });
      closeNaming();
      setName("");
      setChosen(baseline.id);
      writeStored(baselineKey(runId), String(baseline.id));
      announce(`기준선 '${baseline.name}'을(를) 저장했습니다 (범주 ${baseline.category_count}개)`);
    } catch (failure) {
      const text = failure instanceof Error ? failure.message : String(failure);
      setError(text);
    } finally {
      setBusy(false);
    }
  };

  const saveReason = !name.trim()
    ? "기준선 이름을 입력하세요"
    : known.some((item) => item.name === name.replace(/\s+/g, " ").trim())
      ? "같은 이름의 기준선이 이미 있습니다"
      : busy
        ? "저장하는 중입니다"
        : undefined;

  return (
    <div className="hist-baseline" data-testid="hist-baseline">
      <fieldset className="view-toolbar hist-baseline-bar">
        <legend className="sr-only">히스토그램 기준선</legend>
        <label className="view-field" htmlFor={selectId}>
          기준선 비교
        </label>
        <select
          id={selectId}
          value={active ? String(active.id) : ""}
          onChange={(event) => choose(event.target.value ? Number(event.target.value) : null)}
        >
          <option value="">비교 안 함</option>
          {known.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name} · {formatTimestamp(item.created_at, timezone)} · {item.created_by || "작성자 없음"}
            </option>
          ))}
        </select>
        {naming ? (
          <form
            className="hist-baseline-form"
            aria-label="기준선 저장"
            onSubmit={(event) => {
              event.preventDefault();
              if (!saveReason) void save();
            }}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.stopPropagation();
                closeNaming();
              }
            }}
          >
            <label className="sr-only" htmlFor={nameId}>
              기준선 이름
            </label>
            <input
              id={nameId}
              type="text"
              value={name}
              maxLength={80}
              placeholder="예: 처리 직후"
              // biome-ignore lint/a11y/noAutofocus: the form opens on request; typing the name is the next step
              autoFocus
              onChange={(event) => setName(event.target.value)}
            />
            <ReasonButton
              type="submit"
              className="button primary"
              reason={saveReason}
              data-testid="baseline-save"
            >
              저장
            </ReasonButton>
            <button type="button" className="button ghost" onClick={closeNaming}>
              취소
            </button>
          </form>
        ) : (
          <button ref={openerRef} type="button" className="view-link" onClick={() => setNaming(true)}>
            현재 건수를 기준선으로 저장…
          </button>
        )}
      </fieldset>
      {error ? <ErrorText key={error}>기준선 저장 실패: {error}</ErrorText> : null}
      {active ? (
        compare.isPending ? (
          <p className="view-help">기준선과 비교하는 중…</p>
        ) : compare.error ? (
          <ErrorText>비교하지 못했습니다. {(compare.error as Error).message}</ErrorText>
        ) : compare.data ? (
          <CompareBars bars={compare.data.bars} baselineName={active.name} onOpen={openBar} />
        ) : null
      ) : (
        children
      )}
    </div>
  );
}
