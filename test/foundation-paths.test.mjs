import { test } from "node:test";
import assert from "node:assert/strict";
import { posix, win32 } from "node:path";
import { dist } from "./foundation-helpers.mjs";

const P = await import(dist("guard/paths.js"));

const linux = { platform: "linux", env: {}, home: "/home/kim" };
const windows = { platform: "win32", env: { ProgramData: "C:\\ProgramData", LOCALAPPDATA: "C:\\Users\\kim\\AppData\\Local" }, home: "C:\\Users\\kim" };

test("paths: Linux and macOS use /etc/nightsquawk-mcp", () => {
  for (const platform of ["linux", "darwin", "freebsd"]) {
    const o = { ...linux, platform };
    assert.deepEqual(P.policyRoot(o), { root: "/etc/nightsquawk-mcp", override: false });
    assert.equal(P.policyPath("column", o), "/etc/nightsquawk-mcp/column/policy.json");
    assert.deepEqual(P.killMarkers("column", o), { server: "/etc/nightsquawk-mcp/column/KILL", all: "/etc/nightsquawk-mcp/KILL" });
  }
});

test("paths: Windows uses ProgramData\\NightSquawk\\mcp", () => {
  assert.deepEqual(P.policyRoot(windows), { root: "C:\\ProgramData\\NightSquawk\\mcp", override: false });
  assert.equal(P.policyPath("column", windows), "C:\\ProgramData\\NightSquawk\\mcp\\column\\policy.json");
  assert.deepEqual(P.killMarkers("column", windows), {
    server: "C:\\ProgramData\\NightSquawk\\mcp\\column\\KILL",
    all: "C:\\ProgramData\\NightSquawk\\mcp\\KILL",
  });
  assert.equal(P.policyRoot({ platform: "win32", env: { PROGRAMDATA: "D:\\PD" } }).root, "D:\\PD\\NightSquawk\\mcp", "upper-case name");
  assert.equal(P.policyRoot({ platform: "win32", env: {} }).root, "C:\\ProgramData\\NightSquawk\\mcp", "default when unset");
});

test("paths: a blank ProgramData never yields a relative policy root", () => {
  for (const value of ["", "   "]) {
    const { root } = P.policyRoot({ platform: "win32", env: { ProgramData: value } });
    assert.ok(win32.isAbsolute(root), `ProgramData=${JSON.stringify(value)} gave ${JSON.stringify(root)}, which resolves against the working folder`);
  }
});

test("paths: programDataDir takes only a drive-absolute value, else C:\\ProgramData", () => {
  for (const value of ["", "  ", "pd", "C:pd", "\\pd", "\\\\server\\share\\pd", "/pd"]) {
    assert.equal(P.programDataDir({ ProgramData: value }), "C:\\ProgramData", JSON.stringify(value));
  }
  assert.equal(P.programDataDir({ ProgramData: "D:\\Data" }), "D:\\Data");
  assert.equal(P.programDataDir({ ProgramData: " D:/Data " }), "D:/Data", "trimmed");
  assert.equal(P.programDataDir({ PROGRAMDATA: "E:\\PD" }), "E:\\PD", "the upper-case spelling as a fallback");
  assert.equal(P.programDataDir({ ProgramData: "  ", PROGRAMDATA: "E:\\PD" }), "E:\\PD", "a blank ProgramData does not hide PROGRAMDATA");
});

test("paths: NST_MCP_POLICY_DIR overrides the root and is flagged", () => {
  assert.deepEqual(P.policyRoot({ ...linux, env: { NST_MCP_POLICY_DIR: "/srv/guard-tests" } }), { root: "/srv/guard-tests", override: true });
  assert.equal(P.policyPath("column", { ...linux, env: { NST_MCP_POLICY_DIR: "/srv/guard-tests" } }), "/srv/guard-tests/column/policy.json");
  const rel = P.policyRoot({ ...linux, env: { NST_MCP_POLICY_DIR: "relative/dir" } });
  assert.ok(posix.isAbsolute(rel.root) && rel.override, "a relative override is resolved to an absolute path");
  assert.deepEqual(P.policyRoot({ ...linux, env: { NST_MCP_POLICY_DIR: "   " } }), { root: "/etc/nightsquawk-mcp", override: false }, "blank is unset");
  assert.deepEqual(P.policyRoot({ ...windows, env: { ...windows.env, NST_MCP_POLICY_DIR: "D:\\guard-tests" } }), { root: "D:\\guard-tests", override: true });
  assert.equal(P.killMarkers("x", { ...linux, env: { NST_MCP_POLICY_DIR: "/t" } }).all, "/t/KILL", "markers follow the override");
});

test("paths: per-user state folder", () => {
  assert.equal(P.stateDir("column", linux), "/home/kim/.local/state/nightsquawk-mcp/column");
  assert.equal(P.stateDir("column", { ...linux, env: { XDG_STATE_HOME: "/xdg" } }), "/xdg/nightsquawk-mcp/column");
  assert.equal(P.stateDir("column", { ...linux, env: { XDG_STATE_HOME: " " } }), "/home/kim/.local/state/nightsquawk-mcp/column");
  assert.equal(P.stateDir("column", { ...linux, env: { NST_MCP_STATE_DIR: "/state", XDG_STATE_HOME: "/xdg" } }), "/state/column", "override wins");
  assert.equal(P.stateDir("column", windows), "C:\\Users\\kim\\AppData\\Local\\NightSquawk\\mcp\\column");
  assert.equal(P.stateDir("column", { ...windows, env: {} }), "C:\\Users\\kim\\AppData\\Local\\NightSquawk\\mcp\\column", "LOCALAPPDATA unset");
});

test("paths: server names are validated everywhere", () => {
  const good = ["column", "proxmox", "a", "a-b_c9", "9lives", "x".repeat(64)];
  const bad = ["", "Column", "..", "../etc", "a/b", "a\\b", "a b", "a.b", "-lead", "_lead", "x".repeat(65), "caf" + String.fromCodePoint(0xe9), "a\nb"];
  for (const name of good) {
    assert.doesNotThrow(() => P.assertServerName(name), name);
    assert.doesNotThrow(() => P.policyPath(name, linux), name);
  }
  for (const name of bad) {
    assert.throws(() => P.assertServerName(name), /Invalid server name/, JSON.stringify(name));
    assert.throws(() => P.policyPath(name, linux), /Invalid server name/, JSON.stringify(name));
    assert.throws(() => P.killMarkers(name, linux), /Invalid server name/, JSON.stringify(name));
    assert.throws(() => P.stateDir(name, linux), /Invalid server name/, JSON.stringify(name));
  }
});
