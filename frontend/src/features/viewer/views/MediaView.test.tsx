import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../api/viewer", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../api/viewer")>()),
  fetchSourceBlob: vi.fn(async () => new Blob(["x"], { type: "video/mp4" })),
}));

import type { SourcePreview } from "../../../api/viewer";
import { formatMediaDuration, MEDIA_INLINE_MAX_BYTES, MediaView } from "./MediaView";

afterEach(cleanup);

function preview(duration: number | null | undefined): SourcePreview {
  return {
    path: "C:/case/clip.mp3",
    name: "clip.mp3",
    extension: "mp3",
    // Above the inline cap: the player is not loaded, only the metadata line renders.
    size: MEDIA_INLINE_MAX_BYTES + 1,
    mime_type: "audio/mpeg",
    preview_type: "media",
    media: { mime_type: "audio/mpeg", metadata: { duration_seconds: duration } },
  } as SourcePreview;
}

describe("formatMediaDuration (r8 T-017)", () => {
  it("formats m:ss / h:mm:ss and says so when the length is unknown", () => {
    expect(formatMediaDuration(62.4)).toBe("길이 1:02");
    expect(formatMediaDuration(0)).toBe("길이 0:00");
    expect(formatMediaDuration(5)).toBe("길이 0:05");
    expect(formatMediaDuration(3725)).toBe("길이 1:02:05");
    expect(formatMediaDuration(null)).toBe("길이 정보 없음");
    expect(formatMediaDuration(undefined)).toBe("길이 정보 없음");
    expect(formatMediaDuration(Number.NaN)).toBe("길이 정보 없음");
    expect(formatMediaDuration(-1)).toBe("길이 정보 없음");
  });
});

describe("MediaView duration line", () => {
  it("never renders '알 수 없음초'", () => {
    const { container, unmount } = render(
      <MediaView runId="run-1" preview={preview(undefined)} onCopy={() => undefined} />,
    );
    expect(screen.getByText(/audio\/mpeg · 길이 정보 없음/)).toBeTruthy();
    expect(container.textContent).not.toMatch(/알 수 없음초|초$/m);
    unmount();

    render(<MediaView runId="run-1" preview={preview(83)} onCopy={() => undefined} />);
    expect(screen.getByText(/audio\/mpeg · 길이 1:23/)).toBeTruthy();
  });
});

describe("MediaView player length (r8 verify F5)", () => {
  it("uses the player's loadedmetadata duration when the metadata has none", async () => {
    URL.createObjectURL = vi.fn(() => "blob:clip");
    URL.revokeObjectURL = vi.fn();
    const video = {
      path: "C:/case/clip.mp4",
      name: "clip.mp4",
      extension: "mp4",
      size: 1024,
      mime_type: "video/mp4",
      preview_type: "media",
      media: { mime_type: "video/mp4", metadata: {} },
    } as SourcePreview;
    render(<MediaView runId="run-1" preview={video} onCopy={() => undefined} />);
    const player = await screen.findByLabelText("clip.mp4 재생");
    expect(screen.getByText(/video\/mp4 · 길이 정보 없음/)).toBeTruthy();
    Object.defineProperty(player, "duration", { configurable: true, value: 10 });
    fireEvent.loadedMetadata(player);
    expect(await screen.findByText(/video\/mp4 · 길이 0:10/)).toBeTruthy();
  });

  it("keeps the metadata length when it is known", async () => {
    URL.createObjectURL = vi.fn(() => "blob:clip2");
    URL.revokeObjectURL = vi.fn();
    const video = {
      path: "C:/case/clip2.mp4",
      name: "clip2.mp4",
      extension: "mp4",
      size: 1024,
      mime_type: "video/mp4",
      preview_type: "media",
      media: { mime_type: "video/mp4", metadata: { duration_seconds: 83 } },
    } as SourcePreview;
    render(<MediaView runId="run-1" preview={video} onCopy={() => undefined} />);
    const player = await screen.findByLabelText("clip2.mp4 재생");
    Object.defineProperty(player, "duration", { configurable: true, value: 10 });
    fireEvent.loadedMetadata(player);
    expect(screen.getByText(/video\/mp4 · 길이 1:23/)).toBeTruthy();
  });
});
