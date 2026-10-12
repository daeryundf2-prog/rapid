/**
 * Layout slots: the shell owns the frame, other streams own the panes.
 *
 *   registerSlot("viewer", Viewer)        // S2
 *   registerSlot("grid", DataGridPane)    // S3
 *   registerSlot("tree", NavTree)         // S4
 *   registerSlot("run-dialog", RunDialog) // S4 — receives { open, onClose }
 *   registerSlot("case-picker", CasePicker) // S4 (optional; the shell has a default)
 *
 * Registrations stack: the last registered component renders; unregistering
 * restores the previous one. The legacy panes are registered first
 * (app/registerSlots.ts) so the app renders before S2–S4 land.
 */

import { type ComponentType, type ReactNode, useSyncExternalStore } from "react";

export interface SlotProps {
  tree: Record<never, never>;
  grid: Record<never, never>;
  /** `drawer` is true when the viewer is rendered as the < 1200 px overlay drawer. */
  viewer: { drawer: boolean };
  "run-dialog": { open: boolean; onClose: () => void };
  "case-picker": Record<never, never>;
  /** Extra status-bar chips (analysis job progress). */
  "status-extra": Record<never, never>;
}

export type SlotName = keyof SlotProps;

type AnySlotComponent = ComponentType<never>;

const stacks = new Map<SlotName, AnySlotComponent[]>();
const listeners = new Set<() => void>();
let version = 0;

function emit(): void {
  version++;
  for (const l of listeners) l();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

const getVersion = () => version;

export function registerSlot<N extends SlotName>(
  name: N,
  component: ComponentType<SlotProps[N]>,
): () => void {
  const stack = stacks.get(name) ?? [];
  const entry = component as AnySlotComponent;
  stack.push(entry);
  stacks.set(name, stack);
  emit();
  return () => {
    const current = stacks.get(name);
    if (!current) return;
    const index = current.lastIndexOf(entry);
    if (index >= 0) current.splice(index, 1);
    emit();
  };
}

export function getSlotComponent<N extends SlotName>(name: N): ComponentType<SlotProps[N]> | undefined {
  const stack = stacks.get(name);
  return stack?.[stack.length - 1] as ComponentType<SlotProps[N]> | undefined;
}

export function useSlotComponent<N extends SlotName>(name: N): ComponentType<SlotProps[N]> | undefined {
  useSyncExternalStore(subscribe, getVersion, getVersion);
  return getSlotComponent(name);
}

type SlotElementProps<N extends SlotName> = { name: N; fallback?: ReactNode } & SlotProps[N];

/** Render whatever is registered for `name` (or `fallback`). */
export function Slot<N extends SlotName>(props: SlotElementProps<N>) {
  const { name, fallback = null, ...rest } = props;
  const Component = useSlotComponent(name) as ComponentType<Record<string, unknown>> | undefined;
  if (!Component) return <>{fallback}</>;
  return <Component {...(rest as Record<string, unknown>)} />;
}

/** Tests only. */
export function resetSlots(): void {
  stacks.clear();
  emit();
}
