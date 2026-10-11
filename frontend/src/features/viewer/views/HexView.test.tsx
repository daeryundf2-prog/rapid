import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hexRangeHandler, installFetch } from "../testSupport";
import { HexView } from "./HexView";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const grid = () => screen.getByRole("grid");
const rowFor = (offsetHex: string) =>
  screen.getAllByRole("row").find((row) => row.getAttribute("aria-label")?.startsWith(offsetHex));

describe("HexView", () => {
  it("renders 16-byte rows with offset, hex and ascii columns", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(64, (i) => 0x41 + (i % 26)) });
    render(<HexView runId="r1" path="C:/e/a.bin" size={64} />);
    await waitFor(() => expect(rowFor("0x00000000")?.getAttribute("aria-label")).toContain("41 42 43"));
    const first = rowFor("0x00000000") as HTMLElement;
    expect(first.getAttribute("aria-label")).toBe(
      "0x00000000 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 ABCDEFGHIJKLMNOP",
    );
    expect(screen.getAllByRole("row")).toHaveLength(4);
    expect(grid().getAttribute("aria-rowcount")).toBe("4");
  });

  it("highlights target.highlight bytes in hex and ascii and starts the cursor there", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(256) });
    const { container } = render(
      <HexView runId="r1" path="C:/e/a.bin" size={256} highlight={{ offset: 0x20, length: 4 }} />,
    );
    await waitFor(() => expect(container.querySelectorAll(".hex-byte.is-hl")).toHaveLength(4));
    expect(container.querySelectorAll(".hex-char.is-hl")).toHaveLength(4);
    const highlighted = Array.from(container.querySelectorAll(".hex-byte.is-hl")).map((el) => el.textContent);
    expect(highlighted).toEqual(["20", "21", "22", "23"]);
    // Roving tabindex: the cursor row is the grid's single tab stop.
    expect(document.getElementById("hex-row-2")?.tabIndex).toBe(0);
    expect(screen.getAllByRole("row").filter((row) => row.tabIndex === 0)).toHaveLength(1);
    expect(screen.getByText(/커서 0x00000020/)).toBeTruthy();
  });

  it("moves the cursor with the keyboard", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(256) });
    render(<HexView runId="r1" path="C:/e/a.bin" size={256} />);
    await waitFor(() => expect(rowFor("0x00000000")?.getAttribute("aria-label")).toContain("00 01"));
    fireEvent.keyDown(grid(), { key: "ArrowDown" });
    fireEvent.keyDown(grid(), { key: "ArrowRight" });
    expect(screen.getByText(/커서 0x00000011/)).toBeTruthy();
    fireEvent.keyDown(grid(), { key: "End", ctrlKey: true });
    expect(screen.getByText(/커서 0x000000ff/)).toBeTruthy();
    fireEvent.keyDown(grid(), { key: "Home", ctrlKey: true });
    expect(screen.getByText(/커서 0x00000000/)).toBeTruthy();
  });

  it("loads only the 4 KiB chunks in view and jumps with goto-offset", async () => {
    const calls = installFetch({ "source-hex-range": hexRangeHandler(1_000_000) });
    render(<HexView runId="r1" path="C:/e/big.bin" size={1_000_000} />);
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(calls.map((c) => c.url.searchParams.get("offset"))).toEqual(["0"]);
    expect(calls[0]?.url.searchParams.get("length")).toBe("4096");

    fireEvent.change(screen.getByLabelText(/오프셋으로 이동/), { target: { value: "0x10000" } });
    fireEvent.click(screen.getByRole("button", { name: "이동" }));
    await waitFor(() => expect(rowFor("0x00010000")?.getAttribute("aria-label")).toContain("00 01 02"));
    expect(calls.some((c) => c.url.searchParams.get("offset") === String(0x10000))).toBe(true);
    await waitFor(() =>
      expect(document.activeElement).toBe(document.getElementById(`hex-row-${0x10000 / 16}`)),
    );
  });

  it("rejects malformed or out-of-range offsets with a Korean message", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(64) });
    render(<HexView runId="r1" path="C:/e/a.bin" size={64} />);
    fireEvent.change(screen.getByLabelText(/오프셋으로 이동/), { target: { value: "zz" } });
    fireEvent.click(screen.getByRole("button", { name: "이동" }));
    expect(document.getElementById("hex-goto-error")?.textContent).toContain("오프셋 형식");
    fireEvent.change(screen.getByLabelText(/오프셋으로 이동/), { target: { value: "0x100" } });
    fireEvent.click(screen.getByRole("button", { name: "이동" }));
    expect(document.getElementById("hex-goto-error")?.textContent).toContain("파일 크기");
  });

  it("marks file signatures and lists them in the legend", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(32, (i) => (i === 0 ? 0x4d : i === 1 ? 0x5a : 0)) });
    const { container } = render(<HexView runId="r1" path="C:/e/a.exe" size={32} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "PE/MZ @ 0x00000000" })).toBeTruthy());
    expect(container.querySelectorAll(".hex-byte.is-sig")).toHaveLength(2);
  });

  it("renders static preview rows for zip entries without calling the range API", () => {
    const calls = installFetch({});
    render(
      <HexView
        runId="r1"
        path="C:/a.zip::x.bin"
        size={0}
        staticRows={[{ offset: 0, offset_hex: "0x00000000", hex: "50 4b 03 04", ascii: "PK.." }]}
      />,
    );
    expect(rowFor("0x00000000")?.getAttribute("aria-label")).toBe("0x00000000 50 4b 03 04 PK..");
    expect(calls).toHaveLength(0);
  });

  it("gives the hex rows a roving tabindex: one tab stop that follows the cursor and keeps focus", async () => {
    installFetch({ "source-hex-range": hexRangeHandler(256) });
    render(<HexView runId="r1" path="C:/e/a.bin" size={256} />);
    await waitFor(() => expect(rowFor("0x00000000")?.getAttribute("aria-label")).toContain("00 01"));
    const stops = () => screen.getAllByRole("row").filter((row) => row.tabIndex === 0);
    expect(grid().tabIndex).toBe(-1);
    expect(stops()).toEqual([rowFor("0x00000000")]);
    const first = rowFor("0x00000000") as HTMLElement;
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).toBe(rowFor("0x00000010")));
    expect(stops()).toEqual([rowFor("0x00000010")]);
    expect(screen.getByText(/커서 0x00000010/)).toBeTruthy();
    // Focusing another row (click / Tab) moves the cursor onto it, keeping the column.
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowRight" });
    (rowFor("0x00000030") as HTMLElement).focus();
    await waitFor(() => expect(screen.getByText(/커서 0x00000031/)).toBeTruthy());
    expect(stops()).toEqual([rowFor("0x00000030")]);
  });
});
