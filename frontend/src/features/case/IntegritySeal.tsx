/**
 * Evidence integrity seal (design overhaul F8): the top-bar state of the open run's evidence
 * hashes — a shape and a word, never colour alone — plus the per-evidence details with the time of
 * each last check and the existing hash action ([검증 실행] / [다시 검증], POST …/evidence/{eid}/hash).
 * State comes from `sealState` (./integrity) over the shared `["case", id]` query, so the dashboard
 * and the seal read one response. Runs without a case DB render nothing.
 */

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { announce } from "../../a11y";
import { type CaseEvidence, rehashEvidence } from "../../api/cases";
import { Popover } from "../../components/Popover";
import { Icon, type IconName } from "../../icons";
import { useTimezone } from "../../state/hooks";
import { useAppStore } from "../../state/store";
import { formatGridTime } from "../../utils/time";
import { copyText } from "../grid/gridCommands";
import { useRunCaseLink } from "./caseLink";
import {
  canRehash,
  caseQueryKey,
  itemSeal,
  itemSealWord,
  runEvidence,
  SEAL_META,
  type Seal,
  type SealKind,
  sealSentence,
  sealStamp,
  sealState,
  unhashableSentence,
  useCaseDetail,
} from "./integrity";
import { ReasonButton } from "./ReasonButton";
import "./integrity.css";

/** One shape per state, so the state reads without colour (and in a monochrome print). */
export const SEAL_ICON: Readonly<Record<SealKind, IconName>> = {
  broken: "error",
  unverified: "alert",
  hashing: "clock",
  computed: "hash",
  matched: "check",
  na: "info",
};

/** Starts the existing evidence hash for each item (one POST per item). */
export function useRehash(caseId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (items: readonly CaseEvidence[]) =>
      Promise.all(items.map((item) => rehashEvidence(caseId, item.citation_id))),
    onSuccess: (_, items) => {
      void client.invalidateQueries({ queryKey: caseQueryKey(caseId) });
      announce(
        items.length === 1
          ? `증거 ${items[0]?.evidence_number} 해시 계산을 시작했습니다`
          : `증거 ${items.length}건 해시 계산을 시작했습니다`,
      );
    },
    onError: (error: unknown) =>
      announce(`해시 계산 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });
}

/**
 * "해시 계산" / "해시 다시 계산" (or the caller's `label`, e.g. 다시 검증) for a file evidence item.
 * Folder evidence and a running hash have no button; a match or a mismatch can be checked again.
 */
export function EvidenceHashButton({
  caseId,
  item,
  label,
  className = "button ghost",
}: {
  caseId: string;
  item: CaseEvidence;
  label?: string;
  className?: string;
}) {
  const rehash = useRehash(caseId);
  if (!canRehash(item)) return null;
  const text = label ?? (item.hash_status === "not-requested" ? "해시 계산" : "해시 다시 계산");
  return (
    <ReasonButton
      className={className}
      aria-label={`증거 ${item.evidence_number} ${text}`}
      reason={rehash.isPending ? "요청 중입니다" : undefined}
      onClick={() => rehash.mutate([item])}
    >
      {text}
    </ReasonButton>
  );
}

/** One evidence item's hash state: shape + word (the server's full label is the tooltip). */
export function ItemSealChip({ item }: { item: CaseEvidence }) {
  const kind = itemSeal(item);
  return (
    <span className="seal-item" data-seal={kind} title={item.hash_message || item.hash_status_label}>
      <Icon name={SEAL_ICON[kind]} size={14} className="seal-glyph" />
      <span>{itemSealWord(item)}</span>
      {kind === "matched" ? <span className="mono seal-stamp">{sealStamp(item)}</span> : null}
    </span>
  );
}

function CopyDigest({ label, value }: { label: string; value: string }) {
  return (
    <button
      type="button"
      className="button ghost icon-only"
      aria-label={`${label} 복사`}
      title={`${label} 복사`}
      onClick={() =>
        void copyText(value).then(
          () => announce(`${label}를 복사했습니다`),
          () => announce(`${label}를 복사하지 못했습니다`, { politeness: "assertive" }),
        )
      }
    >
      <Icon name="copy" />
    </button>
  );
}

const DIGESTS: ReadonlyArray<["sha256" | "sha1" | "md5", string]> = [
  ["sha256", "SHA-256"],
  ["sha1", "SHA-1"],
  ["md5", "MD5"],
];

/** Per-evidence hash details: state, check time, expected value, computed digests (copyable), hash action. */
export function SealDetails({ caseId, seal }: { caseId: string; seal: Seal }) {
  const rehash = useRehash(caseId);
  const { timezone } = useTimezone();
  if (seal.kind === "na") return null;
  const folders = unhashableSentence(seal);
  return (
    <div className="seal-details">
      <p className="seal-summary">{SEAL_META[seal.kind].description}</p>
      {folders ? (
        <p className="seal-summary" data-testid="seal-unhashable">
          {folders}
        </p>
      ) : null}
      {seal.checkedAt ? (
        <p className="seal-checked" data-testid="seal-checked">
          마지막 검증 {formatGridTime(seal.checkedAt, timezone)}
        </p>
      ) : null}
      <ul className="seal-list" aria-label="증거별 해시">
        {[...seal.items, ...seal.unhashable].map((item) => (
          <li key={item.citation_id} className="seal-entry">
            <div className="seal-entry-head">
              <span className="seal-entry-name">
                증거 {item.evidence_number}
                <span className="seal-entry-file"> {item.display_name}</span>
              </span>
              <ItemSealChip item={item} />
            </div>
            <dl className="seal-digests">
              {item.hash_checked_at ? (
                <div>
                  <dt>검증 시각</dt>
                  <dd>{formatGridTime(item.hash_checked_at, timezone)}</dd>
                </div>
              ) : null}
              {item.hash_expected ? (
                <div>
                  <dt>기대값</dt>
                  <dd className="mono">{item.hash_expected}</dd>
                </div>
              ) : null}
              {DIGESTS.filter(([key]) => item.hashes[key]).map(([key, label]) => (
                <div key={key}>
                  <dt>{label}</dt>
                  <dd className="mono">
                    {item.hashes[key]}
                    <CopyDigest
                      label={`증거 ${item.evidence_number} ${label}`}
                      value={item.hashes[key] ?? ""}
                    />
                  </dd>
                </div>
              ))}
            </dl>
            {item.hash_message ? <p className="seal-message">{item.hash_message}</p> : null}
            <EvidenceHashButton
              caseId={caseId}
              item={item}
              label={item.hash_checked_at ? "다시 검증" : "검증 실행"}
              className="button"
            />
          </li>
        ))}
      </ul>
      {seal.rehashable.length > 1 ? (
        <ReasonButton
          className="button"
          reason={rehash.isPending ? "요청 중입니다" : undefined}
          onClick={() => rehash.mutate(seal.rehashable)}
        >
          {`다시 검증 (증거 ${seal.rehashable.length}건)`}
        </ReasonButton>
      ) : null}
    </div>
  );
}

/** The seal of the open run's evidence (the case's when the snapshot names none); `null` while unknown. */
export function useRunSeal(runId: string | null): { caseId: string; seal: Seal } | null {
  const snapshot = useRunCaseLink(runId);
  const caseId = snapshot.data?.source === "case-db" ? snapshot.data.case_id : null;
  const detail = useCaseDetail(caseId);
  if (!caseId || !detail.data) return null;
  return {
    caseId,
    seal: sealState(runEvidence(detail.data.evidence, snapshot.data?.evidence_citation_id)),
  };
}

/** Top-bar seal (after the case picker): shape + word (+ SHA-256 prefix when matched). */
export function IntegritySeal() {
  const runId = useAppStore((s) => s.route.runId);
  const state = useRunSeal(runId);
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  const kind = state?.seal.kind ?? "na";
  const { timezone } = useTimezone();
  const checked = state?.seal.checkedAt
    ? `마지막 검증 ${formatGridTime(state.seal.checkedAt, timezone)}`
    : "";

  // A state change after the first reading is announced; a broken seal interrupts.
  const previous = useRef<SealKind | null>(null);
  useEffect(() => {
    if (!state) {
      previous.current = null;
      return;
    }
    if (previous.current !== null && previous.current !== kind)
      announce(sealSentence(state.seal), { politeness: kind === "broken" ? "assertive" : "polite" });
    previous.current = kind;
  }, [state, kind]);

  if (!state || kind === "na") return null;
  const meta = SEAL_META[kind];
  return (
    <span className="popover-anchor integrity-seal-anchor">
      <button
        ref={triggerRef}
        type="button"
        className="integrity-seal"
        data-seal={kind}
        data-testid="integrity-seal"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? popoverId : undefined}
        aria-label={`${sealSentence(state.seal)}${checked ? `, ${checked}` : ""} — 증거별 해시 보기`}
        title={checked || undefined}
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name={SEAL_ICON[kind]} size={14} className="seal-glyph" />
        <span className="seal-word-long">{meta.label}</span>
        <span className="seal-word-short">{meta.short}</span>
        {state.seal.stamp ? <span className="mono seal-stamp">{state.seal.stamp}</span> : null}
      </button>
      <Popover
        id={popoverId}
        open={open}
        onClose={() => setOpen(false)}
        triggerRef={triggerRef}
        label="증거 무결성"
        className="seal-popover"
      >
        <h2 className="popover-title seal-title">증거 무결성: {meta.label}</h2>
        <SealDetails caseId={state.caseId} seal={state.seal} />
      </Popover>
    </span>
  );
}
