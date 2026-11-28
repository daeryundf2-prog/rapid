import type { StateCreator } from "zustand";
import { readStored, readStoredJson, writeStored } from "../storage";
import type { AppState } from "../store";

export type Theme = "dark" | "light";
/** Row height tokens: compact 24 px · default 28 px · comfortable 32 px. */
export type Density = "compact" | "default" | "comfortable";
/** react-resizable-panels layout: panel id → percentage. */
export type PanelLayout = Record<string, number>;

export const THEME_KEY = "rapidtriage.v2.theme";
export const DENSITY_KEY = "rapidtriage.v2.density";
export const PANELS_KEY = "rapidtriage.v2.panels";
export const TIMEZONE_KEY = "rapidtriage.v2.timezone";
export const TREE_PANEL_KEY = "rapidtriage.v2.treePanel";

/**
 * Which tree-fold memory a collection uses (F24, review X2): the event lists (timeline, search,
 * review board) start with the stage panel folded to a strip, the browsing views keep it open.
 * Each kind remembers the analyst's own choice.
 */
export type TreePanelKind = "timeline" | "search" | "review" | "browse";
export type TreePanelPins = Partial<Record<TreePanelKind, "hidden" | "shown">>;
export const TREE_PANEL_FOLDED_BY_DEFAULT: readonly TreePanelKind[] = ["timeline", "search", "review"];

export function treePanelKind(collection: string | null | undefined): TreePanelKind {
  return collection === "timeline" || collection === "search" || collection === "review"
    ? collection
    : "browse";
}

/** The wide stage panel is folded to its strip (never in the narrow drawer layout). */
export function treePanelHidden(
  state: Pick<PrefsSlice, "treePanelPins"> & { treeIsDrawer: boolean; route: { collection: string | null } },
): boolean {
  if (state.treeIsDrawer) return false;
  const kind = treePanelKind(state.route.collection);
  const pin = state.treePanelPins[kind];
  return pin ? pin === "hidden" : TREE_PANEL_FOLDED_BY_DEFAULT.includes(kind);
}

function isTreePanelPins(value: unknown): value is TreePanelPins {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([key, pin]) =>
        ["timeline", "search", "review", "browse"].includes(key) && (pin === "hidden" || pin === "shown"),
    )
  );
}

export const DENSITIES: readonly Density[] = ["compact", "default", "comfortable"];
export const DENSITY_LABEL: Record<Density, string> = {
  compact: "좁게 (24px)",
  default: "기본 (28px)",
  comfortable: "넓게 (32px)",
};
export const THEME_LABEL: Record<Theme, string> = { dark: "다크", light: "라이트" };

function storedTheme(): Theme | null {
  const value = readStored(THEME_KEY);
  return value === "dark" || value === "light" ? value : null;
}

function storedDensity(): Density {
  const value = readStored(DENSITY_KEY);
  return (DENSITIES as readonly string[]).includes(value ?? "") ? (value as Density) : "default";
}

function storedTimezone(): string | null {
  const value = readStored(TIMEZONE_KEY);
  return value && value.length <= 64 ? value : null;
}

function isPanelLayout(value: unknown): value is PanelLayout {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.values(value).every((v) => typeof v === "number" && Number.isFinite(v) && v >= 0)
  );
}

export function systemTheme(): Theme {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

/** The theme shown when the user has not chosen one: dark, whatever the OS says (visual-polish U-V1). */
export const DEFAULT_THEME: Theme = "dark";

/** Theme on screen: the user's choice, else dark. */
export function effectiveTheme(theme: Theme | null): Theme {
  return theme ?? DEFAULT_THEME;
}

/** `data-theme` only when the user chose one; without it tokens.css :root is the dark theme. */
export function applyThemeAttribute(theme: Theme | null): void {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

export function applyDensityAttribute(density: Density): void {
  document.documentElement.dataset.density = density;
}

export interface PrefsSlice {
  /** Explicit user choice (persisted); null = the default dark theme. */
  theme: Theme | null;
  /** Current OS preference (kept live by the shell's media listener); informational only — it never picks the theme. */
  systemTheme: Theme;
  density: Density;
  panelLayout: PanelLayout | null;
  /** Explicit display timezone ("utc" | "local" | IANA); null = default (evidence tz, else local). */
  timezone: string | null;
  setTimezone: (timezone: string | null) => void;
  setTheme: (theme: Theme | null) => void;
  toggleTheme: () => void;
  setSystemTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
  cycleDensity: () => void;
  setPanelLayout: (layout: PanelLayout | null) => void;
  /** Wide stage panel folded / shown per collection kind, the analyst's pins (persisted). */
  treePanelPins: TreePanelPins;
  /** Pin the current collection kind's stage panel folded (strip) or shown. */
  setTreePanelHidden: (hidden: boolean) => void;
}

export const createPrefsSlice: StateCreator<AppState, [], [], PrefsSlice> = (set, get) => ({
  theme: storedTheme(),
  systemTheme: systemTheme(),
  density: storedDensity(),
  panelLayout: readStoredJson(PANELS_KEY, isPanelLayout),
  timezone: storedTimezone(),
  treePanelPins: readStoredJson(TREE_PANEL_KEY, isTreePanelPins) ?? {},
  setTreePanelHidden: (hidden) => {
    const kind = treePanelKind(get().route.collection);
    const pins: TreePanelPins = { ...get().treePanelPins, [kind]: hidden ? "hidden" : "shown" };
    writeStored(TREE_PANEL_KEY, JSON.stringify(pins));
    set({ treePanelPins: pins });
  },
  setTimezone: (timezone) => {
    writeStored(TIMEZONE_KEY, timezone);
    set({ timezone });
  },
  setTheme: (theme) => {
    writeStored(THEME_KEY, theme);
    applyThemeAttribute(theme);
    set({ theme });
  },
  toggleTheme: () => {
    get().setTheme(effectiveTheme(get().theme) === "dark" ? "light" : "dark");
  },
  setSystemTheme: (theme) => set({ systemTheme: theme }),
  setDensity: (density) => {
    writeStored(DENSITY_KEY, density);
    applyDensityAttribute(density);
    set({ density });
  },
  cycleDensity: () => {
    const index = DENSITIES.indexOf(get().density);
    get().setDensity(DENSITIES[(index + 1) % DENSITIES.length] ?? "default");
  },
  setPanelLayout: (layout) => {
    writeStored(PANELS_KEY, layout ? JSON.stringify(layout) : null);
    set({ panelLayout: layout });
  },
});

/** Apply persisted theme/density attributes before first paint. */
export function initPrefs(): void {
  applyThemeAttribute(storedTheme());
  applyDensityAttribute(storedDensity());
}
