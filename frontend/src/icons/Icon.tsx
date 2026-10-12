/**
 * Inline SVG icon set (plan U10) — one stroke style, 24×24 grid, no external
 * dependency. Icons are decorative by default (`aria-hidden`); pass `label`
 * only when the icon is the sole content that carries meaning (prefer an
 * `aria-label` on the surrounding button instead).
 */

/** Circle helper expressed as a path so every glyph is a list of `d` strings. */
function circle(cx: number, cy: number, r: number): string {
  return `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
}

export const ICON_PATHS = {
  search: [circle(11, 11, 7), "M20 20l-4-4"],
  command: ["M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z"],
  sun: [
    circle(12, 12, 4),
    "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  ],
  moon: ["M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"],
  monitor: ["M3 4h18v12H3z", "M8 20h8M12 16v4"],
  help: [circle(12, 12, 9), "M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14", "M12 17h.01"],
  close: ["M6 6l12 12M18 6L6 18"],
  menu: ["M4 6h16M4 12h16M4 18h16"],
  "chevron-down": ["M6 9l6 6 6-6"],
  "chevron-up": ["M6 15l6-6 6 6"],
  "chevron-right": ["M9 6l6 6-6 6"],
  "chevron-left": ["M15 6l-6 6 6 6"],
  "arrow-left": ["M19 12H5M11 6l-6 6 6 6"],
  "arrow-right": ["M5 12h14M13 6l6 6-6 6"],
  play: ["M7 4l13 8-13 8z"],
  stop: ["M6 6h12v12H6z"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 4v7h-7"],
  upload: ["M12 16V4M7 9l5-5 5 5", "M4 16v4h16v-4"],
  download: ["M12 4v12M7 11l5 5 5-5", "M4 16v4h16v-4"],
  folder: ["M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"],
  file: ["M6 3h8l4 4v14H6z", "M14 3v4h4"],
  "file-text": ["M6 3h8l4 4v14H6z", "M14 3v4h4", "M9 12h6M9 16h6"],
  image: ["M3 5h18v14H3z", circle(8.5, 9.5, 1.5), "M21 16l-5-5-9 8"],
  database: [
    "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z",
    "M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6",
    "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  ],
  hash: ["M5 9h15M4 15h15M10 3L8 21M16 3l-2 18"],
  copy: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
  link: [
    "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1",
    "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  ],
  quote: ["M7 7h4v4c0 3-1.5 5-4 6", "M15 7h4v4c0 3-1.5 5-4 6"],
  external: ["M14 4h6v6M20 4l-9 9", "M18 14v6H4V6h6"],
  check: ["M5 12l5 5 9-10"],
  alert: ["M12 3l10 18H2z", "M12 10v4M12 17h.01"],
  error: [circle(12, 12, 9), "M9 9l6 6M15 9l-6 6"],
  info: [circle(12, 12, 9), "M12 11v6M12 7.5h.01"],
  bookmark: ["M6 3h12v18l-6-4-6 4z"],
  flag: ["M5 21V4M5 4h11l-2 4 2 4H5"],
  tag: ["M3 12V3h9l9 9-9 9z", "M7.5 7.5h.01"],
  filter: ["M3 5h18l-7 8v6l-4 2v-8z"],
  columns: ["M3 4h18v16H3z", "M9 4v16M15 4v16"],
  "bar-chart": ["M4 20h16", "M7 16v-5M12 16V6M17 16v-8"],
  density: ["M4 6h16M4 10h16M4 14h16M4 18h16"],
  clock: [circle(12, 12, 9), "M12 7v5l3 2"],
  shield: ["M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z", "M12 8v4M12 15h.01"],
  list: ["M9 6h12M9 12h12M9 18h12", "M4 6h.01M4 12h.01M4 18h.01"],
  inbox: ["M3 13l3-8h12l3 8v6H3z", "M3 13h5l1 3h6l1-3h5"],
  package: ["M12 3l9 5v8l-9 5-9-5V8z", "M3 8l9 5 9-5M12 13v8"],
  layers: ["M12 3l9 5-9 5-9-5z", "M3 13l9 5 9-5", "M3 17.5l9 5 9-5"],
  mail: ["M3 5h18v14H3z", "M3 6l9 7 9-7"],
  trash: ["M4 7h16M10 11v6M14 11v6", "M6 7l1 14h10l1-14M9 7V4h6v3"],
  eye: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z", circle(12, 12, 3)],
  settings: [
    circle(12, 12, 3),
    "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  ],
  more: ["M5 12h.01M12 12h.01M19 12h.01"],
  keyboard: ["M2 6h20v12H2z", "M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"],
  "panel-right": ["M3 4h18v16H3z", "M15 4v16"],
  sidebar: ["M3 4h18v16H3z", "M9 4v16"],
  report: ["M6 3h8l4 4v14H6z", "M14 3v4h4", "M9 17v-3M12 17v-6M15 17v-4"],
  // Artifact categories / evidence source (S7, plan §9 X2/X11).
  globe: [
    circle(12, 12, 9),
    "M3 12h18",
    "M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9s1.3-6.4 3.8-9z",
  ],
  message: ["M4 5h16v11H9l-5 4z", "M8 9h8M8 12h5"],
  film: ["M3 5h18v14H3z", "M7 5v14M17 5v14M3 9h4M3 15h4M17 9h4M17 15h4"],
  cloud: ["M7 18a4 4 0 0 1-.7-7.9A6 6 0 0 1 18 9a4.5 4.5 0 0 1-.5 9z"],
  app: ["M4 4h7v7H4z", "M13 4h7v7h-7z", "M4 13h7v7H4z", "M13 13h7v7h-7z"],
  cpu: ["M7 7h10v10H7z", "M10 10h4v4h-4z", "M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"],
  key: [circle(8, 15, 4), "M11 12l9-9M16 7l3 3M18 5l2 2"],
  smartphone: ["M7 2h10v20H7z", "M11 18h2"],
  "map-pin": ["M12 21s-7-6.2-7-12a7 7 0 0 1 14 0c0 5.8-7 12-7 12z", circle(12, 9, 2.5)],
  "hard-drive": ["M3 13l3-8h12l3 8v6H3z", "M3 13h18", "M7 16h.01M11 16h.01"],
  partition: [circle(12, 12, 9), "M12 3v9l6.4 6.4"],
  spinner: ["M12 3a9 9 0 1 0 9 9"],
} as const satisfies Record<string, readonly string[]>;

export type IconName = keyof typeof ICON_PATHS;

export const ICON_NAMES = Object.keys(ICON_PATHS) as IconName[];

export function isIconName(value: string | undefined): value is IconName {
  return value !== undefined && Object.hasOwn(ICON_PATHS, value);
}

export interface IconProps {
  name: IconName;
  /** Pixel size (square). Default 16. */
  size?: number;
  /** Accessible name; omit for decorative icons (the default). */
  label?: string;
  className?: string;
}

export function Icon({ name, size = 16, label, className }: IconProps) {
  const paths = ICON_PATHS[name];
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      data-icon={name}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
    >
      {label ? <title>{label}</title> : null}
      {paths.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}
