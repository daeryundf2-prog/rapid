// Status-bar name the server records for this console's writes (`GET /api/whoami`): with
// per-user tokens it is the token's owner, else RAPIDTRIAGE_REVIEWER. The reviewer/author
// inputs are only a display value when the server names someone, so the console shows it.

import { useEffect, useState } from "react";
import { api } from "../api/client";

export interface Whoami {
  actor: string | null;
  source: "token" | "env" | null;
  per_user_tokens: boolean;
}

export const fetchWhoami = () => api<Whoami>("/api/whoami");

export function serverActorText(who: Whoami | undefined): { text: string; title: string } | null {
  if (!who) return null;
  if (who.actor) {
    return {
      text: `기록 이름 ${who.actor}`,
      title:
        who.source === "token"
          ? "내 토큰의 이름입니다. 검토 표시·메모·북마크·보고서에 이 이름이 남습니다."
          : "서버 설정(RAPIDTRIAGE_REVIEWER)의 이름입니다. 모든 기록에 이 이름이 남습니다.",
    };
  }
  return {
    text: "기록 이름 미지정",
    title: "서버가 이름을 정하지 않았습니다. 입력한 검토자 이름(없으면 local-user)이 기록됩니다.",
  };
}

/** Asked once per mount; a failed request (401, offline) shows nothing. */
export function ServerActor() {
  const [who, setWho] = useState<Whoami>();
  useEffect(() => {
    let live = true;
    fetchWhoami()
      .then((value) => {
        if (live) setWho(value);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  const label = serverActorText(who);
  if (!label) return null;
  return (
    <>
      <span className="status-actor" data-testid="status-actor" title={label.title}>
        {label.text}
      </span>
      <span className="status-sep" aria-hidden="true" />
    </>
  );
}
