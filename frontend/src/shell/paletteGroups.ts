/** Command palette model (plan U2): palette items, their groups and order. Pure. */

import { fuzzyScore } from "../commands/fuzzy";
import { runCommand } from "../commands/registry";
import type { Command, CommandGroup } from "../contracts/command";

export const GROUP_ORDER: readonly CommandGroup[] = [
  "navigate",
  "search",
  "case",
  "grid",
  "viewer",
  "review",
  "export",
  "app",
];

export const GROUP_LABEL: Record<CommandGroup, string> = {
  navigate: "이동",
  search: "검색",
  case: "케이스",
  grid: "그리드",
  viewer: "뷰어",
  review: "리뷰",
  export: "내보내기",
  app: "앱",
};

/** Commands that only make sense as keys, not as palette entries. */
const HIDDEN_IN_PALETTE = new Set(["app.palette", "app.close"]);

export interface PaletteItem {
  key: string;
  label: string;
  group: CommandGroup;
  icon?: string;
  shortcut?: string;
  disabledReason?: string;
  score: number;
  /** Run this item (palette is already closing). */
  perform: () => void;
}

export interface PaletteGroup {
  id: string;
  label: string;
  items: PaletteItem[];
}

export function buildPaletteGroups(
  commands: readonly Command[],
  query: string,
  reasonOf: (command: Command) => string | undefined,
  extra: PaletteItem[] = [],
  lead: PaletteItem[] = [],
): PaletteGroup[] {
  const items: PaletteItem[] = [];
  // Two commands with the same label in one group lead to the same place (e.g. the
  // shell's navigate.* and the tree's tree.goto.*): show it once (plan U2).
  const seen = new Set<string>();
  for (const command of commands) {
    if (HIDDEN_IN_PALETTE.has(command.id)) continue;
    const dedupeKey = `${command.group}\u0000${command.label}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    const score = fuzzyScore(query, `${command.label} ${command.id}`);
    if (score === null) continue;
    items.push({
      key: command.id,
      label: command.label,
      group: command.group,
      icon: command.icon,
      shortcut: command.shortcut,
      disabledReason: reasonOf(command),
      score,
      perform: () => {
        void runCommand(command.id);
      },
    });
  }
  const groups: PaletteGroup[] = GROUP_ORDER.map((group) => ({
    id: group,
    label: GROUP_LABEL[group],
    items: items
      .filter((i) => i.group === group)
      // Runnable first: a list of "이 런에는 해당 데이터가 없습니다" rows buried the ones that run (fe-audit A3).
      .sort(
        (a, b) =>
          Number(Boolean(a.disabledReason)) - Number(Boolean(b.disabledReason)) ||
          (query ? b.score - a.score : 0) ||
          a.label.localeCompare(b.label, "ko"),
      ),
  })).filter((g) => g.items.length > 0);
  // A typed date / time opens the timeline there before any command (fe-audit A2).
  if (lead.length) groups.unshift({ id: "time", label: "시각으로 이동", items: lead });
  // Free-text actions come last so Enter on a matching command never turns into a search.
  if (extra.length) groups.push({ id: "free-text", label: "전체 검색", items: extra });
  return groups;
}
