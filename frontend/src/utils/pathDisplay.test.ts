import { describe, expect, it } from "vitest";
import { middlePathParts, parentDir, pathCellParts, tailPathParts } from "./pathDisplay";

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

  it("tailPathParts keeps the file name and two parent folders; the head gives way (C-D8)", () => {
    expect(tailPathParts("C:\\Users\\kim\\AppData\\Local\\x.db")).toEqual({
      head: "C:\\Users\\kim\\",
      parents: "AppData\\Local\\",
      name: "x.db",
    });
    expect(tailPathParts("/var/log/syslog")).toEqual({ head: "/", parents: "var/log/", name: "syslog" });
    expect(tailPathParts("/a/b/c/d/")).toEqual({ head: "/a/", parents: "b/c/", name: "d" });
    expect(tailPathParts("C:\\")).toEqual({ head: "", parents: "", name: "C:\\" });
    expect(tailPathParts("evidence")).toEqual({ head: "", parents: "", name: "evidence" });
    // Every part joined is the path again.
    const path = "D:\\rapid-qa\\bsh-subset\\Users\\user\\NTUSER.DAT";
    const parts = tailPathParts(path);
    expect(parts.head + parts.parents + parts.name).toBe(path);
  });

  it("pathCellParts shows the whole path tail first, or a bare name as it is", () => {
    expect(pathCellParts("C:\\a\\b\\messages.json")).toEqual({
      head: "C:\\",
      parents: "a\\b\\",
      name: "messages.json",
    });
    expect(pathCellParts("readme.txt")).toEqual({ head: "", parents: "", name: "readme.txt" });
    expect(pathCellParts(null)).toBeNull();
    expect(pathCellParts("")).toBeNull();
  });
});
