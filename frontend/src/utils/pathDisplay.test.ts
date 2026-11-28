import { describe, expect, it } from "vitest";
import { parentDir, pathDisplayParts, pathEndParts } from "./pathDisplay";

describe("path display (F28: the end kept, the middle elided)", () => {
  it("parentDir drops the file name and keeps roots", () => {
    expect(parentDir("C:\\a\\b\\messages.json")).toBe("C:\\a\\b");
    expect(parentDir("/var/log/syslog")).toBe("/var/log");
    expect(parentDir("/syslog")).toBe("/");
    expect(parentDir("C:\\boot.ini")).toBe("C:\\");
    expect(parentDir("C:\\dir\\")).toBe("C:\\");
    expect(parentDir("file.txt")).toBe("");
  });

  it("keeps the last two folders with the file name; the rest is the head that elides first", () => {
    expect(pathEndParts("/tmp/rd-data/evidence/Users/alice/Documents/breach-summary.docx")).toEqual({
      head: "/tmp/rd-data/evidence/Users/",
      dirs: "alice/Documents/",
      tail: "breach-summary.docx",
    });
    expect(
      pathEndParts("C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"),
    ).toEqual({
      head: "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\",
      dirs: "User Data\\Default\\",
      tail: "History",
    });
  });

  it("puts a root in the head and keeps short paths whole", () => {
    expect(pathEndParts("/a/b/c")).toEqual({ head: "/", dirs: "a/b/", tail: "c" });
    expect(pathEndParts("C:\\a\\b\\c")).toEqual({ head: "C:\\", dirs: "a\\b\\", tail: "c" });
    expect(pathEndParts("/var/log")).toEqual({ head: "/", dirs: "var/", tail: "log" });
    expect(pathEndParts("a/b")).toEqual({ head: "", dirs: "a/", tail: "b" });
    expect(pathEndParts("evidence")).toEqual({ head: "", dirs: "", tail: "evidence" });
    expect(pathEndParts("/")).toEqual({ head: "", dirs: "", tail: "/" });
    expect(pathEndParts("C:\\")).toEqual({ head: "", dirs: "", tail: "C:\\" });
    expect(pathEndParts("C:\\dir\\")).toEqual({ head: "C:\\", dirs: "", tail: "dir" });
  });

  it("the parts always join back into the path as written (no inserted gap)", () => {
    for (const path of ["/tmp/x/y/z/w.txt", "C:\\a\\b.txt", "rel/dir/file", "/one"]) {
      const parts = pathEndParts(path);
      expect(`${parts.head}${parts.dirs}${parts.tail}`).toBe(path);
    }
  });

  it("pathDisplayParts shows the whole path, or its parent folder for the viewer header", () => {
    expect(pathDisplayParts("C:\\a\\b\\messages.json")).toEqual({
      head: "C:\\",
      dirs: "a\\b\\",
      tail: "messages.json",
    });
    expect(pathDisplayParts("C:\\a\\b\\messages.json", true)).toEqual({
      head: "C:\\",
      dirs: "a\\",
      tail: "b",
    });
    expect(pathDisplayParts("readme.txt", true)).toEqual({ head: "", dirs: "", tail: "readme.txt" });
    expect(pathDisplayParts(null)).toBeNull();
    expect(pathDisplayParts("")).toBeNull();
  });
});
