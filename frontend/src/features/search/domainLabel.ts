import { DOMAINS } from "../tree/domains";

const LABELS: ReadonlyMap<string, string> = new Map(DOMAINS.map((domain) => [domain.id, domain.label]));

/** Korean name of a search-index domain (the tree's domain ids); the id itself when it has none. */
export function domainLabel(id: string): string {
  return LABELS.get(id) ?? id;
}
