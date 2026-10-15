/**
 * SID → account name (viewer redesign §5): well-known SIDs locally, machine accounts from the
 * run's own SAM rows (`windows-os-account` kind, types windows-sam-account / -candidate — their
 * `sid`, else machine-SID-less `rid` matched on the SID's last sub-authority). One request per
 * run, cached; a failure resolves to "unknown" and is retried on the next run switch.
 */

import { useEffect, useState } from "react";
import { fetchArtifactsPage } from "../../api/collections";

const WELL_KNOWN: Record<string, string> = {
  "S-1-0-0": "NULL SID",
  "S-1-1-0": "Everyone",
  "S-1-2-0": "LOCAL",
  "S-1-3-0": "CREATOR OWNER",
  "S-1-5-2": "NETWORK",
  "S-1-5-4": "INTERACTIVE",
  "S-1-5-6": "SERVICE",
  "S-1-5-7": "ANONYMOUS LOGON",
  "S-1-5-11": "Authenticated Users",
  "S-1-5-18": "SYSTEM (LocalSystem)",
  "S-1-5-19": "LOCAL SERVICE",
  "S-1-5-20": "NETWORK SERVICE",
  "S-1-5-32-544": "Administrators",
  "S-1-5-32-545": "Users",
  "S-1-5-32-546": "Guests",
  "S-1-5-32-555": "Remote Desktop Users",
};

/** RIDs of built-in machine accounts (S-1-5-21-<machine>-RID). */
const WELL_KNOWN_RID: Record<string, string> = {
  "500": "Administrator(기본 관리자)",
  "501": "Guest",
  "503": "DefaultAccount",
  "504": "WDAGUtilityAccount",
};

export interface SidName {
  name: string;
  /** "well-known" · "sam" (this run's SAM rows) · "rid" (built-in RID, machine SID unverified). */
  source: "well-known" | "sam" | "rid";
}

export const SAM_ACCOUNT_TYPES = ["windows-sam-account", "windows-sam-account-candidate"];

type SamMap = { bySid: Map<string, string>; byRid: Map<string, string> };
const cache = new Map<string, Promise<SamMap>>();

function str(value: unknown): string {
  return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

async function loadSam(runId: string): Promise<SamMap> {
  const out: SamMap = { bySid: new Map(), byRid: new Map() };
  const page = await fetchArtifactsPage(
    runId,
    "windows-os-account",
    0,
    1000,
    undefined,
    undefined,
    undefined,
    undefined,
    SAM_ACCOUNT_TYPES,
  );
  for (const raw of page.rows) {
    const details =
      raw && typeof raw === "object" && typeof (raw as { details?: unknown }).details === "object"
        ? ((raw as { details: Record<string, unknown> }).details ?? {})
        : {};
    const name = str(details.user_name) || str(details.user_name_candidate) || str(details.account_name);
    if (!name) continue;
    const sid = str(details.sid) || str(details.user_sid);
    if (sid) out.bySid.set(sid.toUpperCase(), name);
    const rid = str(details.rid) || str(details.rid_decimal);
    if (rid) out.byRid.set(rid, name);
  }
  return out;
}

export function samNames(runId: string): Promise<SamMap> {
  let hit = cache.get(runId);
  if (!hit) {
    hit = loadSam(runId).catch((error: unknown) => {
      cache.delete(runId);
      throw error;
    });
    cache.set(runId, hit);
  }
  return hit;
}

/** Tests: forget the cached SAM maps. */
export function clearSidNameCache(): void {
  cache.clear();
}

export function isSid(value: string): boolean {
  return /^S-1-\d+(-\d+)+$/i.test(value.trim());
}

/** Well-known reading of a SID without the run's SAM rows; null when it needs them. */
export function wellKnownSid(sid: string): SidName | null {
  const upper = sid.trim().toUpperCase();
  const known = WELL_KNOWN[upper];
  if (known) return { name: known, source: "well-known" };
  return null;
}

export function resolveSid(sid: string, sam: SamMap | null): SidName | null {
  const known = wellKnownSid(sid);
  if (known) return known;
  const upper = sid.trim().toUpperCase();
  const fromSam = sam?.bySid.get(upper);
  if (fromSam) return { name: fromSam, source: "sam" };
  const rid = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/i.exec(upper)?.[1];
  if (rid && sam?.byRid.get(rid)) return { name: sam.byRid.get(rid) as string, source: "sam" };
  if (rid && WELL_KNOWN_RID[rid]) return { name: WELL_KNOWN_RID[rid] as string, source: "rid" };
  return null;
}

/** The account name of a SID in this run (null while loading or when unknown). */
export function useSidName(runId: string, sid: string): SidName | null {
  const known = isSid(sid) ? wellKnownSid(sid) : null;
  const [resolved, setResolved] = useState<{ key: string; name: SidName | null } | null>(null);
  const key = `${runId}|${sid}`;
  useEffect(() => {
    if (!runId || !isSid(sid) || known) return;
    let alive = true;
    samNames(runId).then(
      (sam) => {
        if (alive) setResolved({ key, name: resolveSid(sid, sam) });
      },
      () => {
        if (alive) setResolved({ key, name: resolveSid(sid, null) });
      },
    );
    return () => {
      alive = false;
    };
  }, [runId, sid, key, known]);
  if (known) return known;
  return resolved?.key === key ? resolved.name : null;
}
