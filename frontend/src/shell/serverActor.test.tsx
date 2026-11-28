// Status-bar recorded name (#92 P3): `GET /api/whoami` names who the server records; never a token.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerActor, serverActorText, type Whoami } from "./ServerActor";

function renderWith(body: Whoami | null, status = 200) {
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify(body ?? { detail: "x" }), {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  render(<ServerActor />);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("server actor in the status bar", () => {
  it("names the per-user token's owner", async () => {
    const fetchMock = renderWith({ actor: "kim", source: "token", per_user_tokens: true });
    const label = await screen.findByTestId("status-actor");
    expect(label.textContent).toBe("기록 이름 kim");
    expect(label.getAttribute("title")).toContain("내 토큰의 이름");
    expect(fetchMock).toHaveBeenCalledWith("/api/whoami", expect.anything());
  });

  it("says when the server names nobody", () => {
    expect(serverActorText({ actor: null, source: null, per_user_tokens: false })?.text).toBe(
      "기록 이름 미지정",
    );
    expect(serverActorText({ actor: "park", source: "env", per_user_tokens: false })?.title).toContain(
      "RAPIDTRIAGE_REVIEWER",
    );
    expect(serverActorText(undefined)).toBeNull();
  });

  it("shows nothing when the request fails", async () => {
    const fetchMock = renderWith(null, 401);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(screen.queryByTestId("status-actor")).toBeNull();
  });
});
