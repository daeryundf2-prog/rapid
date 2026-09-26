import { useState } from "react";
import { setAuthToken } from "../api/client";

export function TokenGate({ onSaved }: { onSaved: () => void }) {
  const [value, setValue] = useState("");
  return (
    <div className="token-gate" data-testid="token-gate">
      <h1 style={{ fontSize: "var(--fs-screen-title)", margin: 0 }}>RapidForensic</h1>
      <p>
        API 토큰이 필요합니다. 서버를 시작한 콘솔에 출력된 토큰을 붙여넣으세요. 토큰은 이 브라우저 세션에만
        저장됩니다.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!value.trim()) return;
          setAuthToken(value.trim());
          onSaved();
        }}
      >
        <input
          type="password"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="API 토큰"
          aria-label="API 토큰"
          // biome-ignore lint/a11y/noAutofocus: token entry is the only control on this gate
          autoFocus
        />
        <button type="submit" className="button primary">
          연결
        </button>
      </form>
    </div>
  );
}
