/**
 * Display of an evidence time in the viewer (r7 L4, console review C-W5): seconds by default, the
 * UTC side WITH its date ("UTC 2025-05-29 14:25:26", never a bare clock that may be the previous
 * day), and the source's sub-second digits (µs / 100 ns) only on hover.
 *
 * Built on the shared utils/time helpers (`evidenceTime`, `formatTimestamp`; lane L1): one format
 * with the rest of the console, the reading itself unchanged.
 */

import { type EvidenceTime, formatTimestamp } from "../../utils/time";

const FRACTION = /\.\d+$/;

export interface EvidenceTimeDisplay {
  /** "2025-05-29 23:25:26" — the display zone, seconds. */
  local: string;
  /** "UTC 2025-05-29 14:25:26"; null when the display zone is UTC already. */
  utc: string | null;
  /** One line at seconds: "2025-05-29 23:25:26 (KST+09:00) · UTC 2025-05-29 14:25:26". */
  text: string;
  /** The same line with the source's sub-second digits (hover / tooltip). */
  precise: string;
}

export function displayEvidenceTime(reading: EvidenceTime): EvidenceTimeDisplay {
  const tail = reading.local.match(FRACTION)?.[0] ?? "";
  const local = reading.local.replace(FRACTION, "");
  const utc = reading.utc === null ? null : `UTC ${formatTimestamp(reading.iso, "utc")}`;
  const text = `${local} (${reading.zone})${utc ? ` · ${utc}` : ""}`;
  const precise = `${local}${tail} (${reading.zone})${utc ? ` · ${utc}${tail}` : ""}`;
  return { local, utc, text, precise };
}
