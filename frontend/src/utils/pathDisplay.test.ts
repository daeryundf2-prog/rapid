import { describe, expect, it } from "vitest";
import { middlePathParts, parentDir, pathCellParts } from "./pathDisplay";

describe("path display (review #9: parent folder, one middle ellipsis)", () => {
  it("parentDir drops the file name and keeps roots", () => {
    expect(parentDir("C:\\a\\b\\messages.json")).toBe("C:\\a\\b");
    expect(parentDir("/var/log/syslog")).toBe("/var/log");
    expect(parentDir("/syslog")).toBe("/");
    expect(parentDir("C:\\boot.ini")).toBe("C:\\");
    expect(parentDir("C:\\dir\\")).toBe("C:\\");
    expect(parentDir("file.txt")).toBe("");
  });

  it("middlePathParts keeps the last segment whole after the ellipsizing head", () => {
    expect(middlePathParts("C:\\Users\\alice\\AppData")).toEqual({
      head: "C:\\Users\\alice\\",
      tail: "AppData",
    });
    expect(middlePathParts("/var/log")).toEqual({ head: "/var/", tail: "log" });
    expect(middlePathParts("evidence")).toEqual({ head: "", tail: "evidence" });
    expect(middlePathParts("/")).toEqual({ head: "", tail: "/" });
    expect(middlePathParts("C:\\")).toEqual({ head: "", tail: "C:\\" });
  });

  it("pathCellParts shows the parent folder, or a bare name as it is", () => {
    expect(pathCellParts("C:\\a\\b\\messages.json")).toEqual({ head: "C:\\a\\", tail: "b" });
    expect(pathCellParts("readme.txt")).toEqual({ head: "", tail: "readme.txt" });
    expect(pathCellParts(null)).toBeNull();
    expect(pathCellParts("")).toBeNull();
  });
});
