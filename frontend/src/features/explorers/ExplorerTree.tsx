/**
 * Lazy ARIA tree of the 탐색기 panes (plan r4 §2.2): folders (파일 시스템) and keys (레지스트리).
 *
 * Children load on first expand, a page at a time (`loadChildren(id, after)`); a "더 보기" item
 * loads the next page. Keys (one tab stop, roving): ↑/↓ move, → expands (or moves to the first
 * child), ← collapses (or moves to the parent), Home/End, Enter / click opens the item (the caller
 * navigates). Expanding announces the child count through the shell's one polite live region.
 * Items are flat `treeitem`s with `aria-level` / `aria-setsize` / `aria-posinset` per sibling group.
 */

import { type KeyboardEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { Icon, type IconName } from "../../icons";
import { errorText } from "../viewer/useAsync";
import "../tree/tree.css";
import "./explorers.css";

export interface ExplorerTreeItem {
  id: string;
  label: string;
  /** Short count shown as a badge ("1,234"). */
  badge?: string;
  /** Extra words for the accessible name ("파일 1,234개, 12 MB"). */
  description?: string;
  hasChildren: boolean;
  icon?: IconName;
  /** Tooltip. */
  title?: string;
}

export interface ExplorerChildPage {
  items: ExplorerTreeItem[];
  nextAfter: string | null;
  total: number;
}

interface Branch {
  items: ExplorerTreeItem[];
  nextAfter: string | null;
  total: number;
  status: "loading" | "ready" | "error";
  error?: string;
  /** The load is a next page ("더 보기"): the more row stays (busy) instead of a status line. */
  paging?: boolean;
}

type Row =
  | {
      type: "item";
      item: ExplorerTreeItem;
      level: number;
      parentId: string | null;
      pos: number;
      size: number;
    }
  | { type: "more"; id: string; parentId: string; level: number; remaining: number; busy: boolean }
  | { type: "status"; id: string; level: number; text: string; error?: boolean; parentId: string };

export interface ExplorerTreeProps {
  label: string;
  roots: ExplorerTreeItem[];
  loadChildren: (id: string, after: string | null, signal: AbortSignal) => Promise<ExplorerChildPage>;
  selectedId: string | null;
  onOpen: (item: ExplorerTreeItem) => void;
  /** Ids expanded on mount / when they change (ancestors of the selected item). */
  expandIds?: readonly string[];
  /** A new value drops every loaded branch (another run / scope). */
  resetKey: string;
  testId?: string;
}

const MORE_PREFIX = "more:";
/** Pages loaded on their own to reveal a deep-linked item (then "더 보기" is left to the user). */
export const MAX_AUTO_PAGES = 5;
/** Note under a level when a deep-linked item was not found in it. */
export const DEEP_LINK_NOT_FOUND = "위치를 찾지 못했습니다";

export function ExplorerTree({
  label,
  roots,
  loadChildren,
  selectedId,
  onOpen,
  expandIds,
  resetKey,
  testId,
}: ExplorerTreeProps) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set(expandIds ?? []));
  const [branches, setBranches] = useState<ReadonlyMap<string, Branch>>(() => new Map());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const refs = useRef(new Map<string, HTMLElement>());
  const treeRef = useRef<HTMLUListElement | null>(null);
  const controllers = useRef(new Map<string, AbortController>());
  const loadRef = useRef(loadChildren);
  loadRef.current = loadChildren;
  const branchesRef = useRef(branches);
  branchesRef.current = branches;
  /** Bumped on every reset: a page that answers for an older generation is dropped. */
  const generation = useRef(0);
  /** Pages loaded on their own per parent (deep link); cleared on reset and on a new deep link. */
  const autoPages = useRef(new Map<string, number>());
  /** "더 보기" activated: focus the first newly added child of `parentId` once it is rendered. */
  const pendingMoreFocus = useRef<{ parentId: string; from: number } | null>(null);

  // Another run / scope: forget every branch (in-flight loads are aborted).
  // biome-ignore lint/correctness/useExhaustiveDependencies: resetKey is the trigger
  useEffect(() => {
    generation.current += 1;
    for (const controller of controllers.current.values()) controller.abort();
    controllers.current.clear();
    // Effects later in this pass read the ref: never resume an old run's cursor ("stalled").
    branchesRef.current = new Map();
    autoPages.current.clear();
    pendingMoreFocus.current = null;
    setBranches(new Map());
    setExpanded(new Set(expandIds ?? []));
  }, [resetKey]);

  useEffect(() => {
    const live = controllers.current;
    return () => {
      // An aborted branch stays "loading" without a controller: the load effect starts it again
      // when the tree mounts again (StrictMode, layout switches).
      for (const controller of live.values()) controller.abort();
      live.clear();
    };
  }, []);

  const load = useCallback((id: string, after: string | null) => {
    controllers.current.get(id)?.abort();
    const controller = new AbortController();
    controllers.current.set(id, controller);
    const gen = generation.current;
    setBranches((prev) => {
      const next = new Map(prev);
      const current = prev.get(id);
      next.set(id, {
        items: after ? (current?.items ?? []) : [],
        nextAfter: current?.nextAfter ?? null,
        total: current?.total ?? 0,
        status: "loading",
        paging: Boolean(after),
      });
      return next;
    });
    loadRef
      .current(id, after, controller.signal)
      .then((page) => {
        if (controller.signal.aborted || gen !== generation.current) return;
        setBranches((prev) => {
          const next = new Map(prev);
          const before = after ? (prev.get(id)?.items ?? []) : [];
          next.set(id, {
            items: [...before, ...page.items],
            nextAfter: page.nextAfter,
            total: page.total,
            status: "ready",
          });
          return next;
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || gen !== generation.current) return;
        setBranches((prev) => {
          const next = new Map(prev);
          const current = prev.get(id);
          next.set(id, {
            items: current?.items ?? [],
            nextAfter: current?.nextAfter ?? null,
            total: current?.total ?? 0,
            status: "error",
            error: errorText(error),
          });
          return next;
        });
      })
      .finally(() => {
        if (controllers.current.get(id) === controller) controllers.current.delete(id);
      });
  }, []);

  // New ancestors to reveal (deep link / breadcrumb): expand them.
  const expandKey = (expandIds ?? []).join("\u0000");
  // biome-ignore lint/correctness/useExhaustiveDependencies: expandKey stands for expandIds
  useEffect(() => {
    if (!expandIds?.length) return;
    setExpanded((prev) => (expandIds.every((id) => prev.has(id)) ? prev : new Set([...prev, ...expandIds])));
  }, [expandKey]);

  // Every expanded item with children gets its first page.
  const allItems = useMemo(() => {
    const map = new Map<string, ExplorerTreeItem>();
    for (const item of roots) map.set(item.id, item);
    for (const branch of branches.values()) for (const item of branch.items) map.set(item.id, item);
    return map;
  }, [roots, branches]);
  useEffect(() => {
    for (const id of expanded) {
      const item = allItems.get(id);
      if (!item?.hasChildren) continue;
      const branch = branchesRef.current.get(id);
      const stalled = branch?.status === "loading" && !controllers.current.has(id);
      if (!branch || stalled) load(id, stalled && branch.items.length ? branch.nextAfter : null);
    }
  }, [expanded, allItems, load]);

  // A deep link past the first page of a level (`expandIds` is the ancestor chain, the selected
  // item its last child): page on in the parent until the next link of the chain is loaded.
  // A new deep link gets its own page budget.
  // biome-ignore lint/correctness/useExhaustiveDependencies: expandKey / selectedId are the trigger
  useEffect(() => {
    autoPages.current.clear();
  }, [expandKey, selectedId]);
  /** Parent whose level does not hold the next link of the deep-link chain (budget spent / end). */
  const [notFoundIn, setNotFoundIn] = useState<string | null>(null);
  useEffect(() => {
    const chain = [...(expandIds ?? []), ...(selectedId ? [selectedId] : [])];
    let missing: string | null = null;
    for (let i = 1; i < chain.length; i += 1) {
      const wanted = chain[i] as string;
      if (allItems.has(wanted)) continue;
      const parent = chain[i - 1] as string;
      const branch = branches.get(parent);
      const pages = autoPages.current.get(parent) ?? 0;
      if (branch?.status === "ready") {
        if (branch.nextAfter && pages < MAX_AUTO_PAGES) {
          autoPages.current.set(parent, pages + 1);
          load(parent, branch.nextAfter);
        } else missing = parent;
      }
      break;
    }
    setNotFoundIn(missing);
  }, [expandIds, selectedId, allItems, branches, load]);

  // "더 보기" finished: move focus to the first child it added (the more row may be gone).
  useEffect(() => {
    const pending = pendingMoreFocus.current;
    if (!pending) return;
    const branch = branches.get(pending.parentId);
    if (!branch || branch.status === "loading") return;
    pendingMoreFocus.current = null;
    const first = branch.items[pending.from];
    // Nothing new (or the page failed: its status line is not focusable): the more row or the parent.
    const target =
      first?.id ??
      (branch.status === "ready" && branch.nextAfter
        ? `${MORE_PREFIX}${pending.parentId}`
        : pending.parentId);
    setFocusedId(target);
    refs.current.get(target)?.focus();
  }, [branches]);

  const rows = useMemo(() => {
    const out: Row[] = [];
    const walk = (items: ExplorerTreeItem[], level: number, parentId: string | null) => {
      items.forEach((item, index) => {
        out.push({ type: "item", item, level, parentId, pos: index + 1, size: items.length });
        if (!item.hasChildren || !expanded.has(item.id)) return;
        const branch = branches.get(item.id);
        if (!branch) {
          out.push({
            type: "status",
            id: `status:${item.id}`,
            level: level + 1,
            text: "불러오는 중…",
            parentId: item.id,
          });
          return;
        }
        walk(branch.items, level + 1, item.id);
        if (branch.status === "loading" && branch.paging) {
          // Keep the focused "더 보기" row in place (busy) while the next page loads.
          out.push({
            type: "more",
            id: `${MORE_PREFIX}${item.id}`,
            parentId: item.id,
            level: level + 1,
            remaining: Math.max(0, branch.total - branch.items.length),
            busy: true,
          });
        } else if (branch.status === "loading") {
          out.push({
            type: "status",
            id: `status:${item.id}`,
            level: level + 1,
            text: "불러오는 중…",
            parentId: item.id,
          });
        } else if (branch.status === "error") {
          out.push({
            type: "status",
            id: `status:${item.id}`,
            level: level + 1,
            text: `불러오지 못했습니다: ${branch.error ?? ""}`,
            error: true,
            parentId: item.id,
          });
        } else if (branch.nextAfter) {
          out.push({
            type: "more",
            id: `${MORE_PREFIX}${item.id}`,
            parentId: item.id,
            level: level + 1,
            remaining: Math.max(0, branch.total - branch.items.length),
            busy: false,
          });
        } else if (branch.items.length === 0) {
          out.push({
            type: "status",
            id: `status:${item.id}`,
            level: level + 1,
            text: "하위 항목이 없습니다",
            parentId: item.id,
          });
        }
        if (notFoundIn === item.id && branch.status === "ready") {
          out.push({
            type: "status",
            id: `notfound:${item.id}`,
            level: level + 1,
            text: branch.nextAfter
              ? `${DEEP_LINK_NOT_FOUND} · 더 보기로 계속 찾을 수 있습니다`
              : DEEP_LINK_NOT_FOUND,
            error: true,
            parentId: item.id,
          });
        }
      });
    };
    walk(roots, 1, null);
    return out;
  }, [roots, branches, expanded, notFoundIn]);

  // Reveal the selected item once it is rendered (deep link, breadcrumb, reload).
  const scrolledFor = useRef<string | null>(null);
  useEffect(() => {
    if (!selectedId || scrolledFor.current === selectedId) return;
    const element = refs.current.get(selectedId);
    if (!element) return;
    scrolledFor.current = selectedId;
    element.scrollIntoView?.({ block: "center" });
  });

  const focusable = useMemo(() => rows.filter((row) => row.type !== "status"), [rows]);
  const rowId = (row: Row) => (row.type === "item" ? row.item.id : row.id);
  const tabStop =
    (focusedId && focusable.some((row) => rowId(row) === focusedId) && focusedId) ||
    (selectedId && focusable.some((row) => rowId(row) === selectedId) && selectedId) ||
    (focusable[0] ? rowId(focusable[0]) : null);

  const focusRow = (id: string) => {
    setFocusedId(id);
    refs.current.get(id)?.focus();
  };

  const setOpen = (item: ExplorerTreeItem, open: boolean) => {
    setExpanded((prev) => {
      if (prev.has(item.id) === open) return prev;
      const next = new Set(prev);
      if (open) next.add(item.id);
      else next.delete(item.id);
      return next;
    });
    if (open) {
      const branch = branches.get(item.id);
      if (branch?.status === "ready") {
        announce(`${item.label} 펼침, 하위 ${branch.total.toLocaleString("ko-KR")}개`);
      } else announce(`${item.label} 펼침`);
    } else announce(`${item.label} 접음`);
  };

  const activateMore = (row: Extract<Row, { type: "more" }>) => {
    const branch = branches.get(row.parentId);
    if (branch?.nextAfter && branch.status !== "loading") {
      const active = typeof document !== "undefined" ? document.activeElement : null;
      // Move focus afterwards only when it is on the tree (the more row) or was lost.
      if (!active || active === document.body || treeRef.current?.contains(active)) {
        pendingMoreFocus.current = { parentId: row.parentId, from: branch.items.length };
      }
      load(row.parentId, branch.nextAfter);
      announce("다음 항목을 불러옵니다");
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    const id = (event.target as HTMLElement).closest<HTMLElement>("[data-explorer-id]")?.dataset.explorerId;
    const index = focusable.findIndex((row) => rowId(row) === id);
    if (index < 0) return;
    const row = focusable[index];
    if (!row) return;
    let handled = true;
    switch (event.key) {
      case "ArrowDown": {
        const next = focusable[index + 1];
        if (next) focusRow(rowId(next));
        break;
      }
      case "ArrowUp": {
        const prev = focusable[index - 1];
        if (prev) focusRow(rowId(prev));
        break;
      }
      case "Home":
        if (focusable[0]) focusRow(rowId(focusable[0]));
        break;
      case "End": {
        const last = focusable.at(-1);
        if (last) focusRow(rowId(last));
        break;
      }
      case "ArrowRight":
        if (row.type === "item" && row.item.hasChildren) {
          if (!expanded.has(row.item.id)) setOpen(row.item, true);
          else {
            const child = focusable[index + 1];
            if (child && child.parentId === row.item.id) focusRow(rowId(child));
          }
        }
        break;
      case "ArrowLeft":
        if (row.type === "item" && row.item.hasChildren && expanded.has(row.item.id))
          setOpen(row.item, false);
        else if (row.parentId) focusRow(row.parentId);
        break;
      case "Enter":
      case " ":
        if (row.type === "item") onOpen(row.item);
        else activateMore(row);
        break;
      default:
        handled = false;
    }
    if (handled) {
      event.preventDefault();
      event.stopPropagation();
    }
  };

  return (
    <ul
      ref={treeRef}
      // biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: ul is the ARIA tree container
      role="tree"
      aria-label={label}
      className="explorer-tree"
      data-testid={testId}
      onKeyDown={onKeyDown}
    >
      {rows.map((row) => {
        const indent = { paddingInlineStart: `calc(var(--space-2) + ${row.level - 1} * var(--space-4))` };
        if (row.type === "status") {
          return (
            <li
              key={row.id}
              role="none"
              className={`explorer-tree-status${row.error ? " is-error" : ""}`}
              style={indent}
            >
              {row.text}
            </li>
          );
        }
        if (row.type === "more") {
          return (
            // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard handled by the tree root
            <li
              key={row.id}
              role="treeitem"
              data-explorer-id={row.id}
              ref={(el) => {
                if (el) refs.current.set(row.id, el);
                else refs.current.delete(row.id);
              }}
              tabIndex={tabStop === row.id ? 0 : -1}
              aria-level={row.level}
              aria-selected={false}
              aria-busy={row.busy || undefined}
              className="case-tree-item explorer-tree-more"
              style={indent}
              onFocus={() => setFocusedId(row.id)}
              onClick={() => activateMore(row)}
            >
              <span className="case-tree-twisty" aria-hidden="true" />
              <span className="case-tree-label">
                {row.busy ? "더 불러오는 중…" : `더 보기 (${row.remaining.toLocaleString("ko-KR")}개 남음)`}
              </span>
            </li>
          );
        }
        const { item } = row;
        const isOpen = expanded.has(item.id);
        const isSelected = item.id === selectedId;
        return (
          // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard handled by the tree root
          <li
            key={item.id}
            role="treeitem"
            data-explorer-id={item.id}
            ref={(el) => {
              if (el) refs.current.set(item.id, el);
              else refs.current.delete(item.id);
            }}
            tabIndex={tabStop === item.id ? 0 : -1}
            aria-label={item.description ? `${item.label}, ${item.description}` : item.label}
            aria-level={row.level}
            aria-posinset={row.pos}
            aria-setsize={row.size}
            aria-expanded={item.hasChildren ? isOpen : undefined}
            aria-selected={isSelected}
            aria-current={isSelected ? "location" : undefined}
            title={item.title ?? item.label}
            className={`case-tree-item${isSelected ? " selected" : ""}`}
            style={indent}
            onFocus={() => setFocusedId(item.id)}
            onClick={() => {
              setFocusedId(item.id);
              onOpen(item);
            }}
          >
            {item.hasChildren ? (
              <span
                className="case-tree-twisty"
                aria-hidden="true"
                onClick={(event) => {
                  event.stopPropagation();
                  setOpen(item, !isOpen);
                }}
              >
                <Icon name={isOpen ? "chevron-down" : "chevron-right"} />
              </span>
            ) : (
              <span className="case-tree-twisty" aria-hidden="true" />
            )}
            {item.icon ? <Icon name={item.icon} className="case-tree-icon" /> : null}
            <span className="case-tree-label">{item.label}</span>
            {item.badge ? (
              <span className="badge muted" aria-hidden="true">
                {item.badge}
              </span>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
