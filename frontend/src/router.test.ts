import { afterEach, describe, expect, it } from "vitest";
import { authToken } from "./api/client";
import {
  captureLaunchToken,
  collectionChanged,
  parseHash,
  type Route,
  serializeRoute,
  stripTokenFromHash,
} from "./router";

describe("parseHash / serializeRoute", () => {
  it("parses the full route shape", () => {
    const route = parseHash(
      "#/case/run-1/artifacts/eventlog?q=powershell%20exe&row=artifacts%7Ceventlog%7Cartifacts_eventlog%3Arow%3A12%7C&mode=hex",
    );
    expect(route).toEqual({
      runId: "run-1",
      collection: "artifacts",
      kind: "eventlog",
      q: "powershell exe",
      row: {
        collection: "artifacts",
        kind: "eventlog",
        locator: "artifacts_eventlog:row:12",
        caseDbId: undefined,
      },
      mode: "hex",
    });
  });

  it("round-trips every collection, sub node and query", () => {
    const routes: Route[] = [
      { runId: null, collection: null },
      { runId: "r", collection: "intake" },
      { runId: "r 1/2", collection: "files", q: "a&b=c?#" },
      { runId: "r", collection: "artifacts", kind: "registry" },
      { runId: "r", collection: "review", status: "needs-review" },
      {
        runId: "r",
        collection: "timeline",
        row: { collection: "timeline", locator: "/events/278261", caseDbId: 7 },
        mode: "meta",
      },
    ];
    for (const route of routes) {
      const hash = serializeRoute(route);
      const back = parseHash(hash);
      expect(serializeRoute(back)).toBe(hash);
      expect(back.runId).toBe(route.runId);
      expect(back.collection).toBe(route.runId ? route.collection : null);
    }
  });

  it("defaults and ignores what does not belong", () => {
    expect(parseHash("#/case/r")).toEqual({ runId: "r", collection: "intake" });
    expect(parseHash("#/case/r/bogus").collection).toBe("intake");
    expect(parseHash("#/case/r/files/eventlog").kind).toBeUndefined();
    expect(parseHash("#/case/r/review/bogus").status).toBeUndefined();
    expect(parseHash("#/case/r/files?mode=nope&row=").mode).toBeUndefined();
    expect(parseHash("#token=abc")).toEqual({ runId: null, collection: null });
    expect(parseHash("")).toEqual({ runId: null, collection: null });
    expect(parseHash("#/other/x")).toEqual({ runId: null, collection: null });
  });

  it("drops mode without a row and serialises an empty route to #/", () => {
    expect(serializeRoute({ runId: "r", collection: "files", mode: "hex" })).toBe("#/case/r/files");
    expect(serializeRoute({ runId: null, collection: "files" })).toBe("#/");
  });

  it("detects grid-changing navigation", () => {
    const a: Route = { runId: "r", collection: "files" };
    expect(collectionChanged(a, { ...a, q: "x" })).toBe(false);
    expect(collectionChanged(a, { runId: "r", collection: "docs" })).toBe(true);
    expect(
      collectionChanged(
        { runId: "r", collection: "artifacts", kind: "a" },
        { runId: "r", collection: "artifacts", kind: "b" },
      ),
    ).toBe(true);
  });
});

describe("#token= handoff", () => {
  afterEach(() => {
    window.sessionStorage.clear();
    window.history.replaceState(null, "", "/v2/");
  });

  it("strips only the token and keeps the route", () => {
    expect(stripTokenFromHash("#token=abc")).toBe("");
    expect(stripTokenFromHash("#/case/r/files?token=abc&q=x")).toBe("#/case/r/files?q=x");
    expect(stripTokenFromHash("#/case/r/files?token=abc")).toBe("#/case/r/files");
  });

  it("stores the token and leaves the routed hash in the address bar", () => {
    window.history.replaceState(null, "", "/v2/#/case/run-9/docs?token=t0k&q=x");
    expect(captureLaunchToken()).toBe(true);
    expect(authToken()).toBe("t0k");
    expect(window.location.hash).toBe("#/case/run-9/docs?q=x");
    expect(parseHash(window.location.hash)).toEqual({ runId: "run-9", collection: "docs", q: "x" });
  });

  it("plain #token= launch leaves an empty hash", () => {
    window.history.replaceState(null, "", "/v2/#token=abc");
    expect(captureLaunchToken()).toBe(true);
    expect(window.location.hash).toBe("");
  });
});

describe("artifact server sort and promoted columns in the URL", () => {
  it("parses and serialises sort=<key>:<order> and cols= for one artifact kind", () => {
    const hash =
      "#/case/r1/artifacts/windows-prefetch?sort=details.run_count:desc&cols=details.run_count,details.last_run_at";
    const route = parseHash(hash);
    expect(route.sort).toEqual({ key: "details.run_count", order: "desc" });
    expect(route.cols).toEqual(["details.run_count", "details.last_run_at"]);
    expect(serializeRoute(route)).toBe(hash);
    expect(parseHash(serializeRoute(route))).toEqual(route);
    expect(parseHash("#/case/r1/artifacts/eventlog?sort=timestamp").sort).toEqual({
      key: "timestamp",
      order: "asc",
    });
  });

  it("ignores invalid keys/orders and other collections", () => {
    expect(parseHash("#/case/r1/artifacts/eventlog?sort=title:desc").sort).toBeUndefined();
    expect(parseHash("#/case/r1/artifacts/eventlog?sort=details.x:sideways").sort).toBeUndefined();
    expect(parseHash("#/case/r1/artifacts?sort=timestamp:asc").sort).toBeUndefined();
    expect(parseHash("#/case/r1/files?sort=timestamp:asc&cols=details.a").sort).toBeUndefined();
    expect(parseHash("#/case/r1/artifacts/eventlog?cols=title,details.a,details.a").cols).toEqual([
      "details.a",
    ]);
    expect(
      serializeRoute({
        runId: "r1",
        collection: "files",
        sort: { key: "timestamp", order: "asc" },
        cols: ["details.a"],
      }),
    ).toBe("#/case/r1/files");
  });

  it("sort / cols changes are not collection changes", () => {
    const a = parseHash("#/case/r1/artifacts/eventlog");
    const b = parseHash("#/case/r1/artifacts/eventlog?sort=timestamp:desc&cols=details.level");
    expect(collectionChanged(a, b)).toBe(false);
  });
});

describe("sort order case", () => {
  it("parses the order case-insensitively", () => {
    expect(parseHash("#/case/r1/artifacts/eventlog?sort=timestamp:DESC").sort).toEqual({
      key: "timestamp",
      order: "desc",
    });
  });
});
