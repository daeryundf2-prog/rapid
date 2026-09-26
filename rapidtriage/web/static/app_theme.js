/* Dual-theme support (R4-4): Nordic Slate (default dark) and Warm Paper (light).
   Persists the choice in localStorage and applies <html data-theme>. */

export const THEME_STORAGE_KEY = "rapidtriage.theme";
export const THEMES = [
  { id: "nordic-slate", label: "Nordic Slate (dark)" },
  { id: "warm-paper", label: "Warm Paper (light)" },
];

const VALID = new Set(THEMES.map((theme) => theme.id));

export function readStoredTheme(storage) {
  try {
    const value = storage.getItem(THEME_STORAGE_KEY);
    return VALID.has(value) ? value : "nordic-slate";
  } catch (err) {
    return "nordic-slate";
  }
}

export function applyTheme(themeId, doc) {
  const theme = VALID.has(themeId) ? themeId : "nordic-slate";
  doc.documentElement.setAttribute("data-theme", theme);
  return theme;
}

export function initThemePicker({ doc = document, storage = window.localStorage } = {}) {
  const current = applyTheme(readStoredTheme(storage), doc);
  const select = doc.createElement("select");
  select.id = "themePicker";
  select.className = "theme-picker";
  select.setAttribute("aria-label", "Color theme");
  for (const theme of THEMES) {
    const option = doc.createElement("option");
    option.value = theme.id;
    option.textContent = theme.label;
    select.appendChild(option);
  }
  select.value = current;
  select.addEventListener("change", () => {
    const theme = applyTheme(select.value, doc);
    try {
      storage.setItem(THEME_STORAGE_KEY, theme);
    } catch (err) {
      /* storage unavailable — theme still applies for the session */
    }
  });
  return select;
}
