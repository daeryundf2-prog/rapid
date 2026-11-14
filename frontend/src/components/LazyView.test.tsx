// T-116: lazy screens — the Korean loading status, render after the chunk resolves, a Korean retry
// message (not a blank pane) when the chunk fails, a fresh import on 다시 시도, and render errors of
// the loaded screen left to the region boundary.
import { act, fireEvent, render, screen } from "@testing-library/react";
import { Component, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChunkLoadError, lazyView } from "./LazyView";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function Hello({ name }: { name: string }) {
  return <p>안녕 {name}</p>;
}

class Catch extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    return this.state.error ? <p role="alert">바깥 경계: {this.state.error.message}</p> : this.props.children;
  }
}

afterEach(() => vi.restoreAllMocks());

describe("lazyView", () => {
  it("shows 불러오는 중 (role=status) until the chunk resolves, then the screen with its props", async () => {
    const chunk = deferred<typeof Hello>();
    const LazyHello = lazyView("인사 보기", () => chunk.promise);
    render(<LazyHello name="세계" />);
    const status = screen.getByRole("status");
    expect(status.textContent).toContain("인사 보기 불러오는 중");
    expect(status.getAttribute("aria-live")).toBe("polite");
    await act(async () => chunk.resolve(Hello));
    expect(await screen.findByText("안녕 세계")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("a failed chunk shows a Korean retry message, and 다시 시도 imports again", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    let calls = 0;
    const LazyHello = lazyView("인사 보기", () => {
      calls++;
      return calls === 1
        ? Promise.reject(new TypeError("Failed to fetch dynamically imported module"))
        : Promise.resolve(Hello);
    });
    render(<LazyHello name="세계" />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("인사 보기 화면을 불러오지 못했습니다.");
    expect(screen.getByRole("button", { name: "새로 고침" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "다시 시도" }));
    expect(await screen.findByText("안녕 세계")).toBeTruthy();
    expect(calls).toBe(2);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("preload fetches the chunk once ahead of the first render", async () => {
    const load = vi.fn(() => Promise.resolve(Hello));
    const LazyHello = lazyView("인사 보기", load);
    LazyHello.preload();
    LazyHello.preload();
    render(<LazyHello name="미리" />);
    expect(await screen.findByText("안녕 미리")).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("an error while rendering the loaded screen goes to the boundary above, not the retry message", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    function Broken(): ReactNode {
      throw new Error("화면 오류");
    }
    const LazyBroken = lazyView("깨진 보기", () => Promise.resolve(Broken));
    render(
      <Catch>
        <LazyBroken />
      </Catch>,
    );
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("바깥 경계: 화면 오류");
    expect(screen.queryByRole("button", { name: "다시 시도" })).toBeNull();
  });

  it("ChunkLoadError keeps the import failure as its cause", () => {
    const cause = new Error("net::ERR");
    const error = new ChunkLoadError("지도 보기", cause);
    expect(error.message).toBe("지도 보기 화면 파일을 불러오지 못했습니다.");
    expect(error.cause).toBe(cause);
  });
});
