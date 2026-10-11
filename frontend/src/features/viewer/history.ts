import type { ViewerTarget } from "../../contracts/viewer";

export const HISTORY_LIMIT = 50;

export function targetKey(target: ViewerTarget): string {
  const { ref } = target;
  return [target.runId, ref.collection, ref.kind ?? "", ref.locator, target.sourcePath ?? ""].join("|");
}

/** Bounded back/forward list over viewer targets (browser-history semantics). */
export class TargetHistory {
  private entries: ViewerTarget[] = [];
  private index = -1;

  constructor(private readonly limit = HISTORY_LIMIT) {}

  /** Record a newly shown target. Re-showing the current entry is a no-op. */
  visit(target: ViewerTarget): void {
    const current = this.entries[this.index];
    if (current && targetKey(current) === targetKey(target)) {
      this.entries[this.index] = target;
      return;
    }
    this.entries = this.entries.slice(0, this.index + 1);
    this.entries.push(target);
    if (this.entries.length > this.limit) this.entries = this.entries.slice(this.entries.length - this.limit);
    this.index = this.entries.length - 1;
  }

  canBack(): boolean {
    return this.index > 0;
  }

  canForward(): boolean {
    return this.index >= 0 && this.index < this.entries.length - 1;
  }

  back(): ViewerTarget | null {
    if (!this.canBack()) return null;
    this.index -= 1;
    return this.entries[this.index] ?? null;
  }

  forward(): ViewerTarget | null {
    if (!this.canForward()) return null;
    this.index += 1;
    return this.entries[this.index] ?? null;
  }

  get size(): number {
    return this.entries.length;
  }
}
