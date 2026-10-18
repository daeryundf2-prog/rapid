/**
 * R5 L2 (plan r5-residual §3 L2): OS / system / policy-presence types each have exactly one primary
 * node in the domain the server routes them to (core/artifact_domains.py), and 이벤트 로그 › 채널별
 * gains 네트워크 (core/eventlog_channels.py `networking`).
 */
import { describe, expect, it } from "vitest";
import { FALLBACK_CATALOG } from "../flags/catalog";
import { DOMAINS, type DomainNodeDef, EVENTLOG_CHANNEL_NODES, flattenDomainNodes } from "./domains";

/** (kind, type) -> server domain (artifact_domains.py R5 L2 block + kind defaults). */
const R5_L2_TYPES: ReadonlyArray<[string, string, string]> = [
  ["windows-registry", "startup-item", "os"],
  ["windows-system", "startup-item", "os"],
  ["windows-registry", "desktop-wallpaper", "os"],
  ["windows-system", "desktop-wallpaper", "os"],
  ["windows-system", "credential-store-presence", "os"],
  ["windows-registry", "registry-logon-banner", "registry"],
  ["windows-registry", "office-identity", "registry"],
  ["windows-system", "office-backstage-item", "registry"],
  ["windows-registry", "ssh-known-host", "devices"],
  ["windows-registry", "ssh-client-session", "devices"],
  ["windows-system", "ssh-known-host", "devices"],
  ["windows-system", "ssh-authorized-key", "devices"],
  ["windows-system", "ssh-client-session", "devices"],
  ["windows-system", "ssh-key-file", "devices"],
  ["windows-system", "ssh-server-config", "devices"],
  ["windows-system", "vm-config", "anti-forensics"],
  ["windows-system", "crypto-wallet-presence", "anti-forensics"],
  ["windows-system", "av-detection-log", "anti-forensics"],
  ["windows-filesystem", "ntfs-volume-information", "filesystem"],
];

const allNodes = (): Array<DomainNodeDef & { domain: string }> =>
  DOMAINS.flatMap((domain) =>
    flattenDomainNodes(domain.nodes).map((node) => ({ ...node, domain: domain.id })),
  );

function primaryNodes(kind: string, type: string) {
  return allNodes().filter(
    (node) =>
      node.target.collection === "artifacts" &&
      node.target.kind === kind &&
      node.target.types?.includes(type) &&
      !node.crossRef &&
      !node.children?.length &&
      !node.fieldChildren &&
      !node.target.fields &&
      !node.target.cf?.length,
  );
}

describe("R5 L2 domain nodes", () => {
  for (const [kind, type, domain] of R5_L2_TYPES) {
    it(`${kind} › ${type} has one primary node in ${domain}`, () => {
      const nodes = primaryNodes(kind, type);
      expect(nodes.map((node) => `${node.domain}/${node.id}`)).toHaveLength(1);
      expect(nodes[0]?.domain).toBe(domain);
      expect(nodes[0]?.nonEvidence).toBeFalsy();
    });
  }

  it("every R5 L2 type has a family in the bundled catalogue (families.fallback.json)", () => {
    const families: Record<string, string> = {
      "startup-item": "startup-item",
      "registry-logon-banner": "logon-banner",
      "office-identity": "office-identity",
      "office-backstage-item": "office-backstage",
      "ssh-known-host": "ssh-known-host",
      "ssh-authorized-key": "ssh-authorized-key",
      "ssh-client-session": "ssh-client-session",
      "ssh-key-file": "ssh-key-file",
      "ssh-server-config": "ssh-server-config",
      "vm-config": "vm-config",
      "crypto-wallet-presence": "crypto-wallet",
      "av-detection-log": "av-detection-log",
      "desktop-wallpaper": "desktop-wallpaper",
      "credential-store-presence": "credential-store-presence",
      "ntfs-volume-information": "ntfs-volume-information",
    };
    for (const [, type] of R5_L2_TYPES) {
      const family = FALLBACK_CATALOG.families.find((item) => item.types.includes(type));
      expect(family?.id, type).toBe(families[type]);
    }
  });

  it("이벤트 로그 › 채널별 lists 네트워크 first (Korean order) with the networking group filter", () => {
    const node = EVENTLOG_CHANNEL_NODES.find((item) => item.id === "evt-ch-networking");
    expect(node?.label).toBe("네트워크");
    expect(node?.target.channelGroup).toBe("networking");
    expect(EVENTLOG_CHANNEL_NODES[0]?.id).toBe("evt-ch-networking");
  });
});
