import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
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
