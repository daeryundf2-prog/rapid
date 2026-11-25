/**
 * Wait panel: what a pane is loading and for how long ("트리 불러오는 중… 3초"). It appears only
 * after WAIT_DELAY_MS, so a fast load shows nothing; it then counts whole seconds and goes away
 * with the data. There is no percentage: none of these requests reports progress.
 *
 * It is not a live region (the shell keeps the single polite one): the label is announced once
 * through announce() when the panel appears, and the ticking seconds are never announced.
 */

import { type ReactNode, useEffect, useState } from "react";
import { announce } from "../a11y";
import { Icon } from "../icons";

export const WAIT_DELAY_MS = 300;

/** Whole seconds waited so far; null during the first WAIT_DELAY_MS. */
function useWaitSeconds(): number | null {
  const [seconds, setSeconds] = useState<number | null>(null);
  useEffect(() => {
    const started = Date.now();
    let timer = 0;
    const tick = () => {
      const waited = Date.now() - started;
      setSeconds(Math.floor(waited / 1000));
      // Wake at the next whole second.
      timer = window.setTimeout(tick, 1000 - (waited % 1000));
    };
    timer = window.setTimeout(tick, WAIT_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, []);
  return seconds;
}

/** "7초", "1분 5초". */
export function waitText(seconds: number): string {
  return seconds < 60 ? `${seconds}초` : `${Math.floor(seconds / 60)}분 ${seconds % 60}초`;
}

export function WaitPanel({
  label,
  className,
  testId,
  children,
}: {
  /** What is loading ("트리 불러오는 중…"). */
  label: string;
  /** `floating` lays it over the pane (the pane's CSS places it) instead of in the flow. */
  className?: string;
  testId?: string;
  /** Actions beside the text (취소). */
  children?: ReactNode;
}) {
  const seconds = useWaitSeconds();
  const shown = seconds !== null;
  // biome-ignore lint/correctness/useExhaustiveDependencies: said once when the panel appears; a label that counts (행 n개 확인) is not repeated
  useEffect(() => {
    if (shown) announce(label);
  }, [shown]);
  if (seconds === null) return null;
  return (
    <p className={className ? `wait-panel ${className}` : "wait-panel"} data-testid={testId}>
      <Icon name="spinner" className="wait-panel-spin" />
      <span className="wait-panel-label">{label}</span>
      <span className="wait-panel-elapsed">{waitText(seconds)}</span>
      {children}
    </p>
  );
}
