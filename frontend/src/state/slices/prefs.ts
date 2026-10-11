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

/** `data-theme` only when the user chose one, so tokens.css can follow the OS otherwise. */
export function applyThemeAttribute(theme: Theme | null): void {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

export function applyDensityAttribute(density: Density): void {
  document.documentElement.dataset.density = density;
}

export interface PrefsSlice {
  /** Explicit user choice; null = follow prefers-color-scheme. */
  theme: Theme | null;
  /** Current OS preference (kept live by the shell's media listener). */
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
}

export const createPrefsSlice: StateCreator<AppState, [], [], PrefsSlice> = (set, get) => ({
  theme: storedTheme(),
  systemTheme: systemTheme(),
  density: storedDensity(),
  panelLayout: readStoredJson(PANELS_KEY, isPanelLayout),
  timezone: storedTimezone(),
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
    const { theme, systemTheme: os } = get();
    get().setTheme((theme ?? os) === "dark" ? "light" : "dark");
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
