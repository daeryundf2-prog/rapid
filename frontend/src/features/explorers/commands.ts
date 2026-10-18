/**
 * `explorer.*` commands (plan r4 §2.2): open the 파일 시스템 / 레지스트리 탐색기 from the command
 * palette. Without a case they report the Korean reason instead of doing nothing.
 */

import { NO_RUN_REASON } from "../../commands/reasons";
import type { Command } from "../../contracts/command";
import { useAppStore } from "../../state/store";

export function explorerCommands(): Command[] {
  const app = useAppStore.getState;
  return [
    {
      id: "explorer.fs",
      label: "파일 시스템 탐색기 열기",
      group: "navigate",
      icon: "hard-drive",
      disabledReason: () => (app().route.runId ? undefined : NO_RUN_REASON),
      run: () => {
        const runId = app().route.runId;
        if (runId) app().navigate({ runId, collection: "files", dir: "" });
      },
    },
    {
      id: "explorer.registry",
      label: "레지스트리 탐색기 열기",
      group: "navigate",
      icon: "database",
      disabledReason: () => (app().route.runId ? undefined : NO_RUN_REASON),
      run: () => {
        const runId = app().route.runId;
        if (runId) app().navigate({ runId, collection: "registry" });
      },
    },
  ];
}
