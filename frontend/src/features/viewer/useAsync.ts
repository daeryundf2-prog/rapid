import { useEffect, useRef, useState } from "react";

export type AsyncState<T> =
  | { status: "idle"; data: null; error: null }
  | { status: "loading"; data: null; error: null }
  | { status: "ok"; data: T; error: null }
  | { status: "error"; data: null; error: string };

const IDLE = { status: "idle", data: null, error: null } as const;
const LOADING = { status: "loading", data: null, error: null } as const;

export function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || "알 수 없는 오류");
}

/**
 * Load data for `key` (null = nothing to load). A new key aborts the
 * previous request, and stale results are never returned for a new key.
 */
export function useAsync<T>(key: string | null, load: (signal: AbortSignal) => Promise<T>): AsyncState<T> {
  const [entry, setEntry] = useState<{ key: string | null; state: AsyncState<T> }>({
    key: null,
    state: IDLE,
  });
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    if (key === null) {
      setEntry({ key: null, state: IDLE });
      return;
    }
    const controller = new AbortController();
    setEntry({ key, state: LOADING });
    loadRef.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setEntry({ key, state: { status: "ok", data, error: null } });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setEntry({ key, state: { status: "error", data: null, error: errorText(error) } });
        }
      },
    );
    return () => controller.abort();
  }, [key]);
  if (key === null) return IDLE;
  return entry.key === key ? entry.state : LOADING;
}

export interface BlobUrlState {
  url: string | null;
  status: AsyncState<unknown>["status"];
  error: string | null;
}

/**
 * URL for a blob loaded for `key`: an object URL, revoked on change/unmount. A loader may resolve
 * to a ready URL string instead (a `data:` URL), used as is.
 */
export function useBlobUrl(
  key: string | null,
  load: (signal: AbortSignal) => Promise<Blob | string>,
): BlobUrlState {
  const state = useAsync(key, load);
  const [url, setUrl] = useState<string | null>(null);
  const source = state.status === "ok" ? state.data : null;
  useEffect(() => {
    if (typeof source === "string") {
      setUrl(source);
      return;
    }
    if (!source || typeof URL.createObjectURL !== "function") {
      setUrl(null);
      return;
    }
    let next: string;
    try {
      next = URL.createObjectURL(source);
    } catch {
      setUrl(null);
      return;
    }
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [source]);
  return { url, status: state.status, error: state.error };
}
