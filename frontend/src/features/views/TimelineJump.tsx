/**
 * 시각으로 이동 field of the 시간 개요 띠: a date opens that day, a date-time the 30 minutes
 * around it, both read in the console's display zone (the zone the grid shows).
 */

import { useId, useState } from "react";
import { Icon } from "../../icons";
import { type TimezoneChoice, zoneShort } from "../../utils/time";
import { applyRange, rangeText } from "./timelineCommands";
import { jumpRange, parseJumpTime } from "./timelineRange";

/** The input's format hint: a format, never a date that reads like an entered value. */
const JUMP_PLACEHOLDER = "YYYY-MM-DD HH:mm";

export function TimelineJump({ tz }: { tz: TimezoneChoice }) {
  const [jumpText, setJumpText] = useState("");
  const [jumpError, setJumpError] = useState("");
  const errorId = useId();
  const zone = zoneShort(tz, new Date());
  const submitJump = () => {
    const jump = parseJumpTime(jumpText, tz);
    if (!jump) {
      setJumpError(`날짜 또는 날짜 시:분 (${zone}) — 예: 2026-04-18 14:30`);
      return;
    }
    setJumpError("");
    const next = jumpRange(jump);
    applyRange(next, `${rangeText(next, tz)} 구간을 봅니다`);
  };

  return (
    <form
      className="tl-strip-jump"
      onSubmit={(event) => {
        event.preventDefault();
        submitJump();
      }}
    >
      <Icon name="clock" />
      <input
        type="text"
        inputMode="numeric"
        aria-label={`시각으로 이동 (날짜 또는 날짜 시:분, ${zone})`}
        title={`날짜(그날 하루) 또는 날짜 시:분(전후 30분), ${zone} 기준`}
        aria-invalid={jumpError ? true : undefined}
        aria-describedby={jumpError ? errorId : undefined}
        placeholder={JUMP_PLACEHOLDER}
        value={jumpText}
        onChange={(event) => setJumpText(event.target.value)}
      />
      {jumpError ? (
        <span id={errorId} className="tl-strip-error" role="alert">
          {jumpError}
        </span>
      ) : null}
    </form>
  );
}
