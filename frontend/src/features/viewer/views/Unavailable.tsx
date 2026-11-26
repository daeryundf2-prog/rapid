import type { ReactNode } from "react";

interface UnavailableProps {
  /** Why the file is not shown here, in one or two sentences. */
  children: ReactNode;
  /** `error`: loading failed. `note` (default): this view cannot show the file. */
  tone?: "note" | "error";
  onOpenOriginal: () => void;
}

/** A view that cannot show the file here: the reason, then the way out (원본 열기 downloads the original). */
export function Unavailable({ children, tone = "note", onOpenOriginal }: UnavailableProps) {
  return (
    <div className="viewer-unavailable">
      <p className={tone === "error" ? "viewer-error" : "viewer-note"}>{children}</p>
      <button type="button" className="viewer-button" onClick={onOpenOriginal}>
        원본 열기
      </button>
    </div>
  );
}
