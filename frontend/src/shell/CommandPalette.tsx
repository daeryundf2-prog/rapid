import { type KeyboardEvent, useId, useMemo, useRef, useState } from "react";
import { announce, useEscape, useFocusTrap } from "../a11y";
import { focusGridWhenReady } from "../commands/builtin";
import { fuzzyMatchIndexes, fuzzyScore } from "../commands/fuzzy";
import { disabledReasonOf, runCommand, useCommandContext, useCommands } from "../commands/registry";
import type { Command, CommandGroup } from "../contracts/command";
import { Icon, isIconName } from "../icons";
import { keyLabel } from "../shortcuts";
import { useAppStore } from "../state/store";

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

interface PaletteItem {
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

interface PaletteGroup {
  id: string;
  label: string;
  items: PaletteItem[];
}

export function buildPaletteGroups(
  commands: readonly Command[],
  query: string,
  reasonOf: (command: Command) => string | undefined,
  extra: PaletteItem[] = [],
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
      .sort((a, b) => (query ? b.score - a.score : 0) || a.label.localeCompare(b.label, "ko")),
  })).filter((g) => g.items.length > 0);
  // Free-text actions come last so Enter on a matching command never turns into a search.
  if (extra.length) groups.push({ id: "free-text", label: "전체 검색", items: extra });
  return groups;
}

/** The label with the characters the query matched in bold (review #12); plain text otherwise. */
function HighlightedLabel({ label, query }: { label: string; query: string }) {
  const hits = new Set(fuzzyMatchIndexes(query, label));
  if (hits.size === 0) return <>{label}</>;
  const parts: { text: string; hit: boolean }[] = [];
  for (let i = 0; i < label.length; i += 1) {
    const hit = hits.has(i);
    const last = parts.at(-1);
    if (last && last.hit === hit) last.text += label[i];
    else parts.push({ text: label[i] ?? "", hit });
  }
  return (
    <>
      {parts.map((part, i) =>
        part.hit ? (
          // biome-ignore lint/suspicious/noArrayIndexKey: parts are positional
          <b key={i} className="palette-hit">
            {part.text}
          </b>
        ) : (
          part.text
        ),
      )}
    </>
  );
}

/** Ctrl K command palette (plan U2): the keyboard entry point to every command. */
export function CommandPalette() {
  const open = useAppStore((s) => s.paletteOpen);
  if (!open) return null;
  return <PaletteDialog />;
}

function PaletteDialog() {
  const setOverlay = useAppStore((s) => s.setOverlay);
  const openCollection = useAppStore((s) => s.openCollection);
  const commands = useCommands();
  const ctx = useCommandContext();
  const [query, setQuery] = useState("");
  /** -1 = automatic: the first runnable option (a disabled match never captures Enter over a search). */
  const [active, setActive] = useState(-1);
  const dialogRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const baseId = useId();
  const titleId = `${baseId}-title`;
  const listId = `${baseId}-list`;

  const close = () => setOverlay("palette", false);
  useFocusTrap(dialogRef, { active: true, initialFocus: inputRef });
  useEscape(close);

  const groups = useMemo(() => {
    const trimmed = query.trim();
    const extra: PaletteItem[] = trimmed
      ? [
          {
            key: "search.query",
            label: `‘${trimmed}’ 전체 검색`,
            group: "search",
            icon: "search",
            disabledReason: ctx.runId ? undefined : "케이스를 먼저 선택하세요",
            score: Number.POSITIVE_INFINITY,
            perform: () => {
              openCollection("search", { q: trimmed });
              focusGridWhenReady();
            },
          },
        ]
      : [];
    return buildPaletteGroups(commands, trimmed, (c) => disabledReasonOf(c, ctx), extra);
  }, [commands, ctx, query, openCollection]);

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  const firstRunnable = Math.max(
    0,
    flat.findIndex((item) => !item.disabledReason),
  );
  const activeIndex = flat.length === 0 ? -1 : active < 0 ? firstRunnable : Math.min(active, flat.length - 1);
  const activeItem = activeIndex >= 0 ? flat[activeIndex] : undefined;
  const optionId = (key: string) => `${baseId}-opt-${key.replace(/[^\w-]/g, "_")}`;

  const choose = (item: PaletteItem | undefined) => {
    if (!item) return;
    if (item.disabledReason) {
      announce(`${item.label}: ${item.disabledReason}`);
      return;
    }
    close();
    item.perform();
  };

  const jump = (index: number) => {
    if (flat.length === 0) return;
    setActive(index);
    const item = flat[index];
    if (item) document.getElementById(optionId(item.key))?.scrollIntoView?.({ block: "nearest" });
  };
  const move = (delta: number) => jump((activeIndex + delta + flat.length) % Math.max(flat.length, 1));

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        event.preventDefault();
        move(-1);
        break;
      case "PageDown":
        event.preventDefault();
        jump(Math.min(activeIndex + 8, flat.length - 1));
        break;
      case "PageUp":
        event.preventDefault();
        jump(Math.max(activeIndex - 8, 0));
        break;
      case "Enter":
        if (event.nativeEvent.isComposing) return;
        event.preventDefault();
        choose(activeItem);
        break;
      default:
        break;
    }
  };

  return (
    <div className="overlay-scrim" data-testid="command-palette-scrim">
      <div
        ref={dialogRef}
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="command-palette"
      >
        <h2 id={titleId} className="visually-hidden">
          명령 팔레트
        </h2>
        <div className="palette-input">
          <Icon name="search" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={activeItem ? optionId(activeItem.key) : undefined}
            aria-label="명령 또는 검색어"
            placeholder="명령 또는 검색어 입력…"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(-1);
            }}
            onKeyDown={onKeyDown}
          />
        </div>
        <div id={listId} role="listbox" aria-label="명령" className="palette-list">
          {flat.length === 0 ? (
            <p className="palette-empty">일치하는 명령이 없습니다</p>
          ) : (
            groups.map((group) => (
              // biome-ignore lint/a11y/useSemanticElements: ARIA listbox groups are role=group, not <fieldset>
              <div key={group.id} role="group" aria-labelledby={`${baseId}-g-${group.id}`}>
                <div id={`${baseId}-g-${group.id}`} className="palette-group" role="presentation">
                  {group.label}
                </div>
                {group.items.map((item) => {
                  const index = flat.indexOf(item);
                  const selected = index === activeIndex;
                  return (
                    // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard is handled by the combobox input (aria-activedescendant)
                    <div
                      key={item.key}
                      id={optionId(item.key)}
                      role="option"
                      tabIndex={-1}
                      aria-selected={selected}
                      aria-disabled={item.disabledReason ? true : undefined}
                      className={`palette-option${selected ? " active" : ""}${item.disabledReason ? " disabled" : ""}`}
                      onMouseMove={() => setActive(index)}
                      onClick={() => choose(item)}
                    >
                      {item.icon && isIconName(item.icon) ? (
                        <Icon name={item.icon} />
                      ) : (
                        <span className="icon palette-icon-slot" aria-hidden="true" />
                      )}
                      <span className="palette-label">
                        <HighlightedLabel label={item.label} query={query} />
                      </span>
                      {item.disabledReason ? (
                        <span className="palette-reason">{item.disabledReason}</span>
                      ) : null}
                      {item.shortcut ? <kbd>{keyLabel(item.shortcut)}</kbd> : null}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>
        <div className="palette-footer" aria-hidden="true">
          ↑↓ 이동 · Enter 실행 · Esc 닫기
        </div>
      </div>
    </div>
  );
}
