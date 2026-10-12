/**
 * The column view's toolbar line (visual-polish S1): the view switch is not a row of its own —
 * ViewSwitch hands it to the grid's filter bar through this context, which renders it first
 * on the same line. Views without a filter bar (썸네일 · 대화 · 히스토그램) keep their own row.
 */

import { createContext, type ReactNode, useContext } from "react";

export const ToolbarLeadContext = createContext<ReactNode>(null);

export function useToolbarLead(): ReactNode {
  return useContext(ToolbarLeadContext);
}
