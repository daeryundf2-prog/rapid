import { describe, expect, it } from "vitest";
import {
  evidenceFolderOf,
  evidencePathOf,
  middlePathParts,
  parentDir,
  pathCellParts,
  tailPathParts,
} from "./pathDisplay";

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

describe("evidencePathOf (r8 C.9.1, T-171)", () => {
  it("removes the result-folder prefix and roots the rest at the volume", () => {
    expect(evidencePathOf("D:\\out\\r1\\_e01\\fs\\Users\\kim\\a.txt")).toEqual({
      path: "\\Users\\kim\\a.txt",
      stripped: true,
      locationUnknown: false,
    });
    expect(evidencePathOf("D:\\out\\r1\\_E01\\FileSystem\\boot.ini", "c:").path).toBe("C:\\boot.ini");
    expect(evidencePathOf("/srv/out/_disk_image/filesystem/etc/passwd").path).toBe("/etc/passwd");
    expect(evidencePathOf("D:\\out\\_e01\\fs").path).toBe("\\");
  });

  it("keeps a path with no result folder (a folder input) and flags recovery pseudo folders", () => {
    expect(evidencePathOf("E:\\collect\\a.txt")).toEqual({
      path: "E:\\collect\\a.txt",
      stripped: false,
      locationUnknown: false,
    });
    // `fs` alone is not a stage: only `_e01\fs` etc.
    expect(evidencePathOf("E:\\fs\\a.txt").path).toBe("E:\\fs\\a.txt");
    expect(evidencePathOf("D:\\out\\_e01\\fs\\_deleted_mft\\12-a.doc")).toEqual({
      path: null,
      stripped: true,
      locationUnknown: true,
    });
    expect(evidencePathOf("E:\\tsk\\$OrphanFiles\\x").locationUnknown).toBe(true);
    expect(evidencePathOf(null)).toEqual({ path: null, stripped: false, locationUnknown: false });
  });

  it("evidenceFolderOf gives the in-evidence parent folder (root for a root file)", () => {
    expect(evidenceFolderOf("D:\\out\\_e01\\fs\\Users\\kim\\a.txt")).toBe("\\Users\\kim");
    expect(evidenceFolderOf("D:\\out\\_e01\\fs\\a.txt")).toBe("\\");
    expect(evidenceFolderOf("D:\\out\\_e01\\fs\\a.txt", "C")).toBe("C:\\");
    expect(evidenceFolderOf("D:\\out\\_e01\\fs\\_deleted_mft\\1-a")).toBeNull();
  });
});
