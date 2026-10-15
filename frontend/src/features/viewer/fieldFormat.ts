/**
 * Readings of coded record values (viewer redesign §1/§4): EVTX level, logon type, detection
 * severity, byte sizes and offsets. Each returns the Korean reading with the raw value kept in
 * the text ("원격 대화형(RDP) (10)") so nothing the record says is replaced.
 */

import { flatValue } from "../../utils/flatValue";

/** EVTX `Level` (winmeta.xml): 0 LogAlways · 1 Critical · 2 Error · 3 Warning · 4 Informational · 5 Verbose. */
const EVENT_LEVELS: Record<string, string> = {
  "0": "로그 항상",
  "1": "위험",
  "2": "오류",
  "3": "경고",
  "4": "정보",
  "5": "자세히",
  logalways: "로그 항상",
  critical: "위험",
  error: "오류",
  warning: "경고",
  information: "정보",
  informational: "정보",
  info: "정보",
  verbose: "자세히",
};

export function eventLevelLabel(value: unknown): string {
  const text = flatValue(value).trim();
  if (!text) return "—";
  const label = EVENT_LEVELS[text.toLowerCase()];
  return label ? `${label}(${text})` : text;
}

/** Windows logon types (4624/4625/4634 `LogonType`). */
const LOGON_TYPES: Record<string, string> = {
  "0": "시스템",
  "2": "대화형",
  "3": "네트워크",
  "4": "일괄 처리",
  "5": "서비스",
  "7": "잠금 해제",
  "8": "네트워크(평문)",
  "9": "새 자격 증명",
  "10": "원격 대화형(RDP)",
  "11": "캐시된 대화형",
  "12": "캐시된 원격 대화형",
  "13": "캐시된 잠금 해제",
};

export function logonTypeLabel(value: unknown): string {
  const text = flatValue(value).trim();
  if (!text) return "—";
  const label = LOGON_TYPES[String(Number(text))] ?? LOGON_TYPES[text];
  return label ? `${text} — ${label}` : text;
}

/** Detection rule level (Sigma: informational · low · medium · high · critical). */
const SEVERITIES: Record<string, string> = {
  informational: "정보",
  info: "정보",
  low: "낮음",
  medium: "중간",
  high: "높음",
  critical: "심각",
};

export function severityLabel(value: unknown): string {
  const text = flatValue(value).trim();
  if (!text) return "—";
  const label = SEVERITIES[text.toLowerCase()];
  return label ? `${label}(${text})` : text;
}

export function bytesLabel(value: unknown): string {
  const n = typeof value === "number" ? value : Number(flatValue(value));
  if (!Number.isFinite(n)) return flatValue(value);
  const exact = `${n.toLocaleString("ko-KR")}바이트`;
  if (n < 1024) return exact;
  const units = ["KB", "MB", "GB", "TB"];
  let size = n / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${exact} (${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]})`;
}

export function hexLabel(value: unknown): string {
  const text = flatValue(value).trim();
  const n = /^0x[0-9a-f]+$/i.test(text) ? Number.parseInt(text, 16) : Number(text);
  if (!text || !Number.isFinite(n) || n < 0) return text;
  return `0x${Math.floor(n).toString(16).toUpperCase()} (${Math.floor(n).toLocaleString("ko-KR")})`;
}

export function numberLabel(value: unknown): string {
  if (typeof value === "number" && Number.isFinite(value)) return value.toLocaleString("ko-KR");
  return flatValue(value);
}
