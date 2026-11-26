/** 시각으로 이동 field of the 시간 개요 띠: a date opens that day, a date-time the 30 minutes around it. */

import { useId, useState } from "react";
import { Icon } from "../../icons";
import { applyRange, fmt } from "./timelineCommands";
import { jumpRange, parseJumpTime } from "./timelineRange";

export function TimelineJump() {
  const [jumpText, setJumpText] = useState("");
  const [jumpError, setJumpError] = useState("");
  const errorId = useId();
  const submitJump = () => {
    const jump = parseJumpTime(jumpText);
    if (!jump) {
      setJumpError("예: 2026-04-18 14:30 또는 2026-04-18");
      return;
    }
    setJumpError("");
    const next = jumpRange(jump);
    applyRange(next, `${fmt(next.fromMs)} ~ ${fmt(next.toMs)} 구간을 봅니다`);
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
        aria-label="시각으로 이동 (날짜 또는 날짜 시:분)"
        aria-invalid={jumpError ? true : undefined}
        aria-describedby={jumpError ? errorId : undefined}
        placeholder="2026-04-18 14:30"
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
