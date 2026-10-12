import { useEffect } from "react";
import { focusGridWhenReady } from "../../commands/builtin";
import type { Command } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import { navigate, registerCommand } from "./adapter";
import type { TreeModelNode } from "./model";
import { useTreeModel } from "./useTreeModel";

const NO_CASE = "열린 케이스가 없습니다";

function idOf(node: TreeModelNode): string {
  return `tree.goto.${node.id.replace(/:/g, ".")}`;
}

/** One `tree.goto.*` command per navigable tree node (saved searches excluded: they are search.* data). */
export function buildTreeCommands(runId: string | null, model: TreeModelNode[]): Command[] {
  const commands: Command[] = [];
  const visit = (nodes: TreeModelNode[], parentLabel?: string) => {
    for (const node of nodes) {
      if (!node.id.startsWith("search:saved:") && !node.toggleOnly) {
        const label = parentLabel ? `${parentLabel} › ${node.label}` : node.label;
        commands.push({
          id: idOf(node),
          label: `이동: ${label}`,
          group: "navigate",
          disabledReason: (ctx) => (ctx.runId ? node.disabledReason : NO_CASE),
          run: (ctx) => {
            // Saved searches open themselves; domain nodes navigate with their filters.
            if (node.activate) {
              node.activate();
              return;
            }
            const target = ctx.runId ?? runId;
            if (!target) return;
            if (node.target) {
              useAppStore.getState().navigate({ runId: target, ...node.target });
              focusGridWhenReady();
            } else navigate({ runId: target, ...node.route });
          },
        });
      }
      if (node.children) visit(node.children, node.label);
    }
  };
  visit(model);
  commands.push({
    id: "tree.focus",
    label: "탐색 트리로 포커스 이동",
    group: "navigate",
    disabledReason: (ctx) => (ctx.runId ? undefined : NO_CASE),
    run: () => {
      document.querySelector<HTMLElement>("[role='tree'] [role='treeitem'][tabindex='0']")?.focus();
    },
  });
  return commands;
}

/** Registers the tree.* commands for the open case; remount-safe (unregisters on change). */
export function useTreeCommands(runId: string | null): void {
  const model = useTreeModel(runId);
  useEffect(() => {
    const unregister = buildTreeCommands(runId, model).map((command) => registerCommand(command));
    return () => {
      for (const off of unregister) off();
    };
  }, [runId, model]);
}
