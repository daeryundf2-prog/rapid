import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FamilyNode, FamilyResponse } from "../../../api/families";
import { useAppStore } from "../../../state/store";
import { getViewerTarget, resetViewerAdapter } from "../adapter";
import { jsonResponse, target } from "../testSupport";
import { FamilyView, nodeTypeLabel } from "./FamilyView";

const E = "artifacts:email:/artifacts/";

function node(ref: string, extra: Partial<FamilyNode> = {}): FamilyNode {
  const [collection = "", kind = "", ...rest] = ref.split(":");
  return {
    ref,
    collection,
    kind,
    locator: rest.join(":"),
    title: "",
    artifact_type: "",
    relation: null,
    relation_label: null,
    material: true,
    virtual: false,
    navigable: true,
    row_ref: ref,
    children: 0,
    ...extra,
  };
}

const MAIL = node(`${E}1`, {
  title: "견적서 송부",
  artifact_type: "email-message",
  children: 2,
  relation: "message",
  relation_label: "메시지",
});
const PDF = node(`${E}2`, {
  title: "견적서.pdf",
  artifact_type: "email-attachment",
  relation: "attachment",
  relation_label: "첨부",
});
const LOGO = node(`${E}3`, {
  title: "logo.png",
  artifact_type: "email-attachment",
  relation: "attachment",
  relation_label: "첨부",
  material: false,
});
const BOX = node(`${E}0`, { title: "box.pst", artifact_type: "email-container-inventory", children: 3 });

const ATTACHMENT_FAMILY: FamilyResponse = {
  ref: `${E}2`,
  direction: "family",
  has_family: true,
  item: PDF,
  parent: MAIL,
  top: MAIL,
  is_top: false,
  ancestors: [MAIL, BOX],
  siblings: [LOGO],
  tree: {
    ...MAIL,
    items: [
      { ...PDF, items: [] },
      { ...LOGO, items: [] },
    ],
  },
  tree_truncated: false,
  counts: { members: 3, descendants: 2, material: 2, rows: 3 },
};

const ZIP = "artifacts:generic-documents:/artifacts/0";
const ZIP_FAMILY: FamilyResponse = {
  ref: ZIP,
  direction: "family",
  has_family: true,
  item: node(ZIP, { title: "bundle.zip", artifact_type: "archive-file-inventory", children: 2 }),
  parent: null,
  top: node(ZIP, { title: "bundle.zip", artifact_type: "archive-file-inventory", children: 2 }),
  is_top: true,
  ancestors: [],
  siblings: [],
  tree: {
    ...node(ZIP, { title: "bundle.zip", artifact_type: "archive-file-inventory", children: 2 }),
    items: [
      {
        ...node(`${ZIP}#entry:0`, {
          title: "보고서/",
          artifact_type: "archive-entry",
          virtual: true,
          navigable: false,
          material: false,
          relation: "member",
          relation_label: "압축 항목",
        }),
        items: [],
      },
      {
        ...node(`${ZIP}#entry:1`, {
          title: "보고서/1분기.xlsx",
          artifact_type: "archive-entry",
          virtual: true,
          navigable: false,
          relation: "member",
          relation_label: "압축 항목",
        }),
        source_path: "C:\\ev\\bundle.zip::보고서/1분기.xlsx",
        items: [],
      },
    ],
  },
  counts: { members: 3, descendants: 2, material: 2, rows: 1 },
};

let requests: URL[] = [];

function stub(body: (url: URL) => unknown, status = 200) {
  requests = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), "http://localhost");
      requests.push(url);
      return jsonResponse(body(url), status);
    }),
  );
}

beforeEach(() => {
  resetViewerAdapter();
  useAppStore.getState().navigate({ runId: "run-1", collection: "artifacts", kind: "email" });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("FamilyView (계열 tab, R7 갈래 A)", () => {
  it("shows the parent chain and the family tree with the row marked, in Korean only", async () => {
    stub(() => ATTACHMENT_FAMILY);
    render(
      <FamilyView
        target={target({ ref: { collection: "artifacts", kind: "email", locator: "/artifacts/2" } })}
      />,
    );
    await screen.findByText("견적서 송부", { selector: ".family-tree .family-node-title" });
    expect(decodeURIComponent(requests[0]?.pathname ?? "")).toBe(`/api/runs/run-1/families/${E}2`);
    expect(requests[0]?.searchParams.get("direction")).toBe("family");
    const view = screen.getByTestId("family-view");
    expect(view.textContent).toContain("계열 3개 항목 · 하위 2개 · 비중요 1개");
    const ancestors = screen.getByRole("navigation", { name: "상위 항목" });
    expect(ancestors.textContent).toContain("box.pst");
    expect(ancestors.textContent).toContain("견적서 송부");
    const current = view.querySelector("[aria-current='true']");
    expect(current?.textContent).toContain("견적서.pdf");
    expect(current?.textContent).toContain("첨부");
    expect(view.querySelector(".is-immaterial")?.textContent).toContain("비중요");
    // No raw ids on screen (types and relations read in Korean).
    expect(view.textContent).not.toMatch(/email-attachment|email-message|attachment|container-inventory/);
  });

  it("opens a row node as its family listing with the 계열 tab", async () => {
    stub(() => ATTACHMENT_FAMILY);
    render(
      <FamilyView
        target={target({ ref: { collection: "artifacts", kind: "email", locator: "/artifacts/2" } })}
      />,
    );
    const sibling = await screen.findByRole("button", { name: /logo\.png/ });
    fireEvent.click(sibling);
    const route = useAppStore.getState().route;
    expect(route.collection).toBe("artifacts");
    expect(route.kind).toBeUndefined();
    expect(route.family).toEqual([`${E}1`]);
    expect(route.row).toEqual({ collection: "artifacts", kind: "email", locator: "/artifacts/3" });
    expect(route.mode).toBe("family");
  });

  it("previews a ZIP entry and leaves a folder entry inert", async () => {
    stub(() => ZIP_FAMILY);
    render(
      <FamilyView
        target={target({
          ref: { collection: "artifacts", kind: "generic-documents", locator: "/artifacts/0" },
          sourcePath: "C:\\ev\\bundle.zip",
        })}
      />,
    );
    const folder = (await screen.findByText("보고서/")).closest("button") as HTMLButtonElement;
    expect(folder.getAttribute("aria-disabled")).toBe("true");
    expect(requests[0]?.searchParams.get("source_path")).toBe("C:\\ev\\bundle.zip");
    fireEvent.click(screen.getByRole("button", { name: /1분기/ }));
    await waitFor(() => expect(getViewerTarget()?.sourcePath).toBe("C:\\ev\\bundle.zip::보고서/1분기.xlsx"));
    expect(getViewerTarget()?.ref.locator).toBe("/artifacts/0#entry:1");
    expect(getViewerTarget()?.preferredMode).toBe("source");
  });

  it("says when a row has no family, and when the derivation fails", async () => {
    stub(() => ({ ...ZIP_FAMILY, has_family: false, tree: undefined }));
    const { unmount } = render(<FamilyView target={target()} />);
    await screen.findByText(/상위·하위 항목이 없습니다/);
    unmount();
    stub(() => ({ detail: "런이 끝난 뒤에 계열·중복·예외 항목을 볼 수 있습니다" }), 409);
    render(<FamilyView target={target()} />);
    expect((await screen.findByRole("alert")).textContent).toContain("런이 끝난 뒤에");
  });

  it("names node types in Korean and never shows an unknown id", () => {
    expect(nodeTypeLabel("archive-entry")).toBe("압축 항목");
    expect(nodeTypeLabel("source-file")).toBe("원본 파일");
    expect(nodeTypeLabel("totally-unknown-type")).toBe("");
  });
});
