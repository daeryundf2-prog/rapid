/**
 * Dashboard card shell (plan §9 X10): collapsible body, ⋯ menu (새로고침 /
 * 숨기기), loading card and explanatory empty state (X9/X18). Collapse and
 * hide state persist per browser (`rt.dashboard.layout.v1`).
 */

import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";
import { Icon, type IconName } from "../../icons";
import { readStoredJson, writeStored } from "../../state/storage";

const LAYOUT_KEY = "rt.dashboard.layout.v1";

export interface CardLayout {
  collapsed: string[];
  hidden: string[];
}

function isLayout(value: unknown): value is CardLayout {
  const v = value as CardLayout | null;
  return (
    !!v &&
    Array.isArray(v.collapsed) &&
    Array.isArray(v.hidden) &&
    v.collapsed.every((x) => typeof x === "string") &&
    v.hidden.every((x) => typeof x === "string")
  );
}

export function readCardLayout(): CardLayout {
  return readStoredJson(LAYOUT_KEY, isLayout) ?? { collapsed: [], hidden: [] };
}

/** Collapse / hide state for every card, persisted in localStorage (never throws). */
export function useCardLayout() {
  const [layout, setLayout] = useState<CardLayout>(readCardLayout);
  const update = useCallback((next: (prev: CardLayout) => CardLayout) => {
    setLayout((prev) => {
      const value = next(prev);
      writeStored(LAYOUT_KEY, JSON.stringify(value));
      return value;
    });
  }, []);
  const toggle = (list: string[], id: string, on: boolean) =>
    on ? [...new Set([...list, id])] : list.filter((x) => x !== id);
  return {
    layout,
    setCollapsed: (id: string, on: boolean) =>
      update((prev) => ({ ...prev, collapsed: toggle(prev.collapsed, id, on) })),
    setHidden: (id: string, on: boolean) =>
      update((prev) => ({ ...prev, hidden: toggle(prev.hidden, id, on) })),
    showAll: () => update((prev) => ({ ...prev, hidden: [] })),
  };
}

export interface CardProps {
  id: string;
  title: string;
  icon?: IconName;
  /** Short text after the title (e.g. a total). */
  meta?: ReactNode;
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  onHide: () => void;
  onRefresh?: () => void;
  children: ReactNode;
  className?: string;
}

function CardMenu({
  title,
  onRefresh,
  onHide,
}: {
  title: string;
  onRefresh?: () => void;
  onHide: () => void;
}) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    menu.current?.querySelector<HTMLElement>("[role='menuitem']")?.focus();
    const close = (event: PointerEvent) => {
      if (!menu.current?.contains(event.target as Node) && event.target !== trigger.current) setOpen(false);
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [open]);

  const choose = (action: () => void) => {
    setOpen(false);
    trigger.current?.focus();
    action();
  };

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = [...(menu.current?.querySelectorAll<HTMLElement>("[role='menuitem']") ?? [])];
    const index = items.indexOf(document.activeElement as HTMLElement);
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
      trigger.current?.focus();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      items[(index + step + items.length) % items.length]?.focus();
    } else if (event.key === "Tab") {
      setOpen(false);
    }
  };

  return (
    <div className="dash-menu-anchor">
      <button
        ref={trigger}
        type="button"
        className="button ghost icon-only"
        aria-label={`${title} 카드 메뉴`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name="more" />
      </button>
      {open ? (
        <div
          ref={menu}
          id={menuId}
          role="menu"
          aria-label={`${title} 카드 메뉴`}
          className="dash-menu"
          onKeyDown={onMenuKey}
        >
          {onRefresh ? (
            <button type="button" role="menuitem" tabIndex={-1} onClick={() => choose(onRefresh)}>
              <Icon name="refresh" /> 새로고침
            </button>
          ) : null}
          <button type="button" role="menuitem" tabIndex={-1} onClick={() => choose(onHide)}>
            <Icon name="close" /> 숨기기
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function Card({
  id,
  title,
  icon,
  meta,
  collapsed,
  onCollapsedChange,
  onHide,
  onRefresh,
  children,
  className,
}: CardProps) {
  const headingId = useId();
  const bodyId = useId();
  return (
    <section
      className={`dash-card${collapsed ? " collapsed" : ""}${className ? ` ${className}` : ""}`}
      aria-labelledby={headingId}
      data-card={id}
    >
      {/* A div, not <header>: the shell top bar is the page's only banner landmark. */}
      <div className="dash-card-head">
        <button
          type="button"
          className="dash-card-toggle"
          aria-expanded={!collapsed}
          aria-controls={bodyId}
          onClick={() => onCollapsedChange(!collapsed)}
        >
          <Icon name={collapsed ? "chevron-right" : "chevron-down"} />
          {icon ? <Icon name={icon} size={16} className="dash-card-icon" /> : null}
          <h2 id={headingId}>{title}</h2>
        </button>
        {meta !== undefined && meta !== null ? <span className="dash-card-meta">{meta}</span> : null}
        <CardMenu title={title} onRefresh={onRefresh} onHide={onHide} />
      </div>
      <div id={bodyId} className="dash-card-body" hidden={collapsed}>
        {collapsed ? null : children}
      </div>
    </section>
  );
}

/** X18 loading card body. */
export function CardLoading({ label = "불러오는 중…" }: { label?: string }) {
  return (
    // Not a live region: the shell's single polite region (announce()) carries status text.
    <p className="dash-loading">
      <Icon name="spinner" className="dash-spin" />
      {label}
    </p>
  );
}

/** X9 empty state: what the card is for and how to fill it. */
export function CardEmpty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="dash-empty">
      <p className="dash-empty-title">{title}</p>
      {children ? <p className="dash-empty-text">{children}</p> : null}
    </div>
  );
}

export function CardError({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return <p className="error-banner">불러오지 못했습니다: {message}</p>;
}
