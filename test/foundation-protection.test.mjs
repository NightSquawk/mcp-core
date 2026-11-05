import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dist, tempDir } from "./foundation-helpers.mjs";

const P = await import(dist("guard/protection.js"));

// ------------------------------------------------------------------ fake probes

const dirStat = (uid = 0, mode = 0o40755) => ({ isFile: false, isDirectory: true, isSymbolicLink: false, uid, mode });
const fileStat = (uid = 0, mode = 0o100644) => ({ isFile: true, isDirectory: false, isSymbolicLink: false, uid, mode });
const linkStat = (uid = 0) => ({ isFile: false, isDirectory: false, isSymbolicLink: true, uid, mode: 0o120777 });

/**
 * Recorded OS answers. `runs` maps "cmd args..." (or just "cmd") to a result; unknown programs are ENOENT.
 * `links` maps a symlink's path to its target as stored; its `files` entry must be a linkStat().
 * `texts` (path -> text) and `owners` (an answer, or a function of the paths) add the optional readText and
 * windowsOwners probes; left out, the probe is missing, as in a hand-made double.
 */
function fakeProbes({ platform = "linux", files = {}, links = {}, runs = {}, uid = 1000, env = {}, writable = [], creatable = [], texts, owners } = {}) {
  const calls = { run: [], canCreateIn: [], readText: [], windowsOwners: [] };
  const optional = {};
  if (texts !== undefined) {
    optional.readText = (p) => {
      calls.readText.push(p);
      return Object.hasOwn(texts, p) ? texts[p] : null;
    };
  }
  if (owners !== undefined) {
    optional.windowsOwners = (paths) => {
      calls.windowsOwners.push([...paths]);
      return typeof owners === "function" ? owners(paths) : owners;
    };
  }
  return {
    ...optional,
    calls,
    platform,
    env,
    lstat: (p) => files[p] ?? null,
    readlink: (p) => (Object.hasOwn(links, p) ? links[p] : null),
    run(cmd, args) {
      const key = [cmd, ...args].join(" ");
      calls.run.push(key);
      const r = runs[key] ?? runs[cmd];
      return r ? { stdout: "", stderr: "", ...r } : { status: null, stdout: "", stderr: "", error: "ENOENT" };
    },
    getuid: () => uid,
    canOpenForWrite: (p) => writable.includes(p),
    canCreateIn(d) {
      calls.canCreateIn.push(d);
      return creatable.includes(d);
    },
  };
}

const POLICY = "/etc/nightsquawk-mcp/column/policy.json";
const rootTree = (overrides = {}) => ({
  "/": dirStat(),
  "/etc": dirStat(),
  "/etc/nightsquawk-mcp": dirStat(),
  "/etc/nightsquawk-mcp/column": dirStat(),
  [POLICY]: fileStat(),
  ...overrides,
});
const ID_OK = { "id -Gn": { status: 0, stdout: "kim wheel users\n" } };

// ------------------------------------------------------------------ POSIX part 1

test("posixPart1: root-owned file and folders, not group/other-writable, non-root process: ok", () => {
  assert.deepEqual(P.posixPart1(POLICY, fakeProbes({ files: rootTree() })), { ok: true, reasons: [] });
  assert.deepEqual(P.posixPart1(POLICY, fakeProbes({ files: rootTree({ [POLICY]: fileStat(0, 0o100600) }) })).ok, true, "0600 is fine");
});

test("posixPart1: each way the agent's user could change the policy is a reason", () => {
  const cases = [
    [{ [POLICY]: undefined }, /No policy file/],
    [{ [POLICY]: linkStat() }, /is a symlink/],
    [{ [POLICY]: dirStat() }, /is not a regular file/],
    [{ [POLICY]: fileStat(1000) }, /owned by uid 1000, not root/],
    [{ [POLICY]: fileStat(0, 0o100664) }, /writable by its group or others \(mode 664\)/],
    [{ [POLICY]: fileStat(0, 0o100646) }, /writable by its group or others \(mode 646\)/],
    [{ "/etc/nightsquawk-mcp/column": dirStat(1000) }, /\/etc\/nightsquawk-mcp\/column is owned by uid 1000/],
    [{ "/etc/nightsquawk-mcp": dirStat(0, 0o40775) }, /\/etc\/nightsquawk-mcp is writable by its group or others/],
    [{ "/etc": dirStat(0, 0o41777) }, /\/etc is writable/],
    [{ "/": dirStat(1000) }, /\/ is owned by uid 1000/],
    [{ "/etc/nightsquawk-mcp": undefined }, /^\/etc\/nightsquawk-mcp cannot be read\.$/],
  ];
  for (const [overrides, reason] of cases) {
    const files = rootTree();
    for (const [k, v] of Object.entries(overrides)) {
      if (v === undefined) delete files[k];
      else files[k] = v;
    }
    const part = P.posixPart1(POLICY, fakeProbes({ files }));
    assert.equal(part.ok, false, String(reason));
    assert.ok(part.reasons.some((r) => reason.test(r)), `${reason} not in ${JSON.stringify(part.reasons)}`);
  }
});

test("posixPart1: the folders a symlink leads to are checked", () => {
  const files = { ...rootTree(), "/etc/nightsquawk-mcp/column": linkStat(), "/home": dirStat(), "/home/kim": dirStat(1000), "/home/kim/fake": dirStat(1000) };
  const part = P.posixPart1(POLICY, fakeProbes({ files, links: { "/etc/nightsquawk-mcp/column": "/home/kim/fake" } }));
  assert.equal(part.ok, false);
  assert.ok(part.reasons.includes("/home/kim/fake is owned by uid 1000, not root."), JSON.stringify(part.reasons));
  assert.ok(part.reasons.includes("/home/kim is owned by uid 1000, not root."), JSON.stringify(part.reasons));
});

test("posixPart1: the folder holding a symlink is checked, even when the link leads to root's folders", () => {
  // Whoever can write /etc/nightsquawk-mcp can point column at another policy.
  const files = {
    ...rootTree(),
    "/etc/nightsquawk-mcp": dirStat(1000),
    "/etc/nightsquawk-mcp/column": linkStat(),
    "/opt": dirStat(),
    "/opt/real": dirStat(),
    "/opt/real/column": dirStat(),
  };
  for (const target of ["/opt/real/column", "../../opt/real/column"]) {
    const part = P.posixPart1(POLICY, fakeProbes({ files, links: { "/etc/nightsquawk-mcp/column": target } }));
    assert.deepEqual(part.reasons, ["/etc/nightsquawk-mcp is owned by uid 1000, not root."], target);
  }
});

test("posixPart1: every hop of a chain of symlinks is checked, however deep", () => {
  // column -> /home/kim/link -> /opt/real/column: kim can point the middle link anywhere.
  const files = {
    ...rootTree(),
    "/etc/nightsquawk-mcp/column": linkStat(),
    "/home": dirStat(),
    "/home/kim": dirStat(1000),
    "/home/kim/link": linkStat(1000),
    "/opt": dirStat(),
    "/opt/real": dirStat(),
    "/opt/real/column": dirStat(),
  };
  const links = { "/etc/nightsquawk-mcp/column": "/home/kim/link", "/home/kim/link": "/opt/real/column" };
  assert.deepEqual(P.posixPart1(POLICY, fakeProbes({ files, links })).reasons, ["/home/kim is owned by uid 1000, not root."]);
  const steps = P.lookupSteps("/etc/nightsquawk-mcp/column", fakeProbes({ files, links })).steps.map((s) => s.path);
  assert.deepEqual(steps, ["/", "/etc", "/etc/nightsquawk-mcp", "/etc/nightsquawk-mcp/column", "/home", "/home/kim", "/home/kim/link", "/opt", "/opt/real", "/opt/real/column"]);
});

test("posixPart1: root's symlinks in root's folders pass (macOS /etc -> private/etc)", () => {
  const files = {
    "/": dirStat(),
    "/etc": linkStat(),
    "/private": dirStat(),
    "/private/etc": dirStat(),
    "/private/etc/nightsquawk-mcp": dirStat(),
    "/private/etc/nightsquawk-mcp/column": dirStat(),
    [POLICY]: fileStat(),
  };
  const mac = fakeProbes({ platform: "darwin", files, links: { "/etc": "private/etc" } });
  assert.deepEqual(P.posixPart1(POLICY, mac), { ok: true, reasons: [] });
  const shared = { ...files, "/private/etc/nightsquawk-mcp": dirStat(0, 0o40777) };
  assert.ok(P.posixPart1(POLICY, fakeProbes({ platform: "darwin", files: shared, links: { "/etc": "private/etc" } })).reasons.includes("/private/etc/nightsquawk-mcp is writable by its group or others (mode 777)."));
});

test("posixPart1: a symlink loop, an unreadable link or a relative path fails closed", () => {
  const files = { ...rootTree(), "/etc/nightsquawk-mcp/column": linkStat() };
  const loop = P.posixPart1(POLICY, fakeProbes({ files, links: { "/etc/nightsquawk-mcp/column": "column" } }));
  assert.ok(loop.reasons.includes(`/etc/nightsquawk-mcp/column cannot be resolved: more than ${P.MAX_SYMLINKS} symlinks.`), JSON.stringify(loop.reasons));
  const unreadable = P.posixPart1(POLICY, fakeProbes({ files }));
  assert.ok(unreadable.reasons.includes("The symlink /etc/nightsquawk-mcp/column cannot be read."), JSON.stringify(unreadable.reasons));
  assert.deepEqual(P.lookupSteps("etc/x", fakeProbes({ files })), { steps: [], error: "etc/x is not an absolute path" });
  assert.equal(P.lookupSteps("/etc/../etc/./nightsquawk-mcp", fakeProbes({ files: rootTree() })).steps.at(-1).path, "/etc/nightsquawk-mcp", ". and .. are resolved");
});

test("posixPart1: a root process can always change the policy", () => {
  const part = P.posixPart1(POLICY, fakeProbes({ files: rootTree(), uid: 0 }));
  assert.equal(part.ok, false);
  assert.ok(part.reasons.some((r) => /runs as root/.test(r)));
  assert.equal(P.posixPart1(POLICY, fakeProbes({ files: rootTree(), uid: undefined })).ok, true, "no getuid (Windows) is not root");
});

test("posixPart1: a process inside a user namespace (rootless container, unshare -Ur) is never protected, since the owners it sees can be forged", () => {
  const files = rootTree();
  const identity = P.posixPart1(POLICY, fakeProbes({ files, texts: { "/proc/self/uid_map": "         0          0 4294967295\n" } }));
  assert.deepEqual(identity, { ok: true, reasons: [] }, "the identity map, whatever its spacing");
  for (const map of ["         0       1000          1\n         1     100000      65536\n", "0 1000 1\n", "0 0 4294967294\n"]) {
    const part = P.posixPart1(POLICY, fakeProbes({ files, texts: { "/proc/self/uid_map": map } }));
    assert.equal(part.ok, false, map);
    assert.ok(part.reasons.some((r) => /user namespace/.test(r)), JSON.stringify(part.reasons));
  }
  assert.equal(P.posixPart1(POLICY, fakeProbes({ files, texts: {} })).ok, false, "an unreadable uid_map fails closed");
  const mac = fakeProbes({ platform: "darwin", files, texts: {} });
  assert.equal(P.posixPart1(POLICY, mac).ok, true, "only Linux has /proc/self/uid_map");
  assert.deepEqual(mac.calls.readText, []);
  const real = P.realProbes();
  assert.equal(typeof real.readText, "function", "the real probes always carry the optional members");
  assert.equal(typeof real.windowsOwners, "function");
});

// ------------------------------------------------------------------ POSIX part 2

test("posixPart2: no sudo/doas rule and no root-equivalent group: ok", () => {
  const probes = fakeProbes({ runs: { ...ID_OK, sudo: { status: 1, stderr: "sudo: a password is required\n" } } });
  assert.deepEqual(P.posixPart2(probes), { ok: true, reasons: [] });
  assert.deepEqual(probes.calls.run, ["sudo -n true", "sudo -n -l", "doas -n true", "id -Gn"], "only non-interactive probes run");
  assert.deepEqual(P.posixPart2(fakeProbes({ runs: ID_OK })), { ok: true, reasons: [] }, "neither tool installed");
});

test("posixPart2: passwordless sudo or doas is a reason", () => {
  for (const tool of ["sudo", "doas"]) {
    const part = P.posixPart2(fakeProbes({ runs: { ...ID_OK, [tool]: { status: 0 } } }));
    assert.equal(part.ok, false);
    assert.ok(part.reasons.some((r) => r.startsWith(`Passwordless ${tool}`)), JSON.stringify(part.reasons));
  }
});

test("posixPart2: a sudo probe that times out or dies is not taken as 'no sudo' (fail closed)", () => {
  for (const r of [{ status: null, error: "ETIMEDOUT" }, { status: null, signal: "SIGKILL" }]) {
    const part = P.posixPart2(fakeProbes({ runs: { ...ID_OK, sudo: r } }));
    assert.equal(part.ok, false, `sudo probe result ${JSON.stringify(r)} was treated as safe`);
  }
  // A sudo this user may not execute (mode 4750, group wheel) is no path to root.
  assert.equal(P.posixPart2(fakeProbes({ runs: { ...ID_OK, sudo: { status: null, error: "EACCES" } } })).ok, true);
});

test("posixPart2: a narrow NOPASSWD rule (listed by sudo -n -l) is a reason even when sudo -n true asks for a password", () => {
  const listing = [
    "Matching Defaults entries for kim on host:",
    "    env_reset, mail_badpass",
    "",
    "User kim may run the following commands on host:",
    "    (ALL) ALL",
    "    (root) NOPASSWD: /usr/bin/tee /etc/hosts",
    "    (root) NOPASSWD: /usr/bin/systemctl restart nginx",
  ].join("\n");
  const asks = { status: 1, stderr: "sudo: a password is required\n" };
  const part = P.posixPart2(fakeProbes({ runs: { ...ID_OK, "sudo -n true": asks, "sudo -n -l": { status: 0, stdout: listing } } }));
  assert.equal(part.ok, false);
  const reason = part.reasons.find((r) => r.startsWith("sudo has NOPASSWD rule(s)"));
  assert.ok(reason?.includes("/usr/bin/tee /etc/hosts") && reason.includes("systemctl restart nginx"), JSON.stringify(part.reasons));
  // With the default listpw=any, sudo -n -l itself needs a password when no rule is NOPASSWD.
  assert.deepEqual(P.posixPart2(fakeProbes({ runs: { ...ID_OK, "sudo -n true": asks, "sudo -n -l": asks } })), { ok: true, reasons: [] });
  const dead = P.posixPart2(fakeProbes({ runs: { ...ID_OK, "sudo -n true": asks, "sudo -n -l": { status: null, error: "ETIMEDOUT" } } }));
  assert.equal(dead.ok, false, "a listing that times out is not an answer");
  const many = Array.from({ length: 5 }, (_, i) => `    (root) NOPASSWD: /usr/bin/tool${i}`).join("\n");
  const m = P.posixPart2(fakeProbes({ runs: { ...ID_OK, "sudo -n true": asks, "sudo -n -l": { status: 0, stdout: many } } }));
  assert.ok(m.reasons.some((r) => r.endsWith("(+2 more).")), JSON.stringify(m.reasons));
});

test("posixPart2: root-equivalent groups are reasons, matched exactly", () => {
  for (const g of P.ROOT_EQUIVALENT_GROUPS) {
    const part = P.posixPart2(fakeProbes({ runs: { "id -Gn": { status: 0, stdout: `kim ${g} users\n` } } }));
    assert.equal(part.ok, false, g);
    assert.ok(part.reasons.some((r) => r === `Member of root-equivalent group(s): ${g}.`), JSON.stringify(part.reasons));
  }
  const near = P.posixPart2(fakeProbes({ runs: { "id -Gn": { status: 0, stdout: "kim dockerx Docker diskusers\n" } } }));
  assert.equal(near.ok, true, JSON.stringify(near.reasons));
  const two = P.posixPart2(fakeProbes({ runs: { "id -Gn": { status: 0, stdout: "kim docker libvirt\n" } } }));
  assert.ok(two.reasons.includes("Member of root-equivalent group(s): docker, libvirt."));
  assert.ok(Object.isFrozen(P.ROOT_EQUIVALENT_GROUPS));
});

test("posixPart2: unknown group membership fails closed", () => {
  const part = P.posixPart2(fakeProbes({ runs: { "id -Gn": { status: 1, stderr: "id: cannot find name for group ID 4242\n" } } }));
  assert.equal(part.ok, false);
  assert.ok(part.reasons.some((r) => /id -Gn failed/.test(r)));
});

test("parseGroupNames: whitespace-separated names", () => {
  assert.deepEqual(P.parseGroupNames("kim wheel\tdocker\n"), ["kim", "wheel", "docker"]);
  assert.deepEqual(P.parseGroupNames(""), []);
});

// ------------------------------------------------------------------ Windows parsing

const csv = (...rows) => rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\r\n") + "\r\n";
const EVERYONE = ["Everyone", "Well-known group", "S-1-1-0", "Mandatory group, Enabled by default, Enabled group"];
const USERS = ["BUILTIN\\Users", "Alias", "S-1-5-32-545", "Mandatory group, Enabled by default, Enabled group"];
const ADMINS_FILTERED = ["BUILTIN\\Administrators", "Alias", "S-1-5-32-544", "Group used for deny only"];
const ADMINS_ENABLED = ["BUILTIN\\Administrators", "Alias", "S-1-5-32-544", "Mandatory group, Enabled by default, Enabled group, Group owner"];
const MEDIUM = ["Mandatory Label\\Medium Mandatory Level", "Label", "S-1-16-8192", ""];
const HIGH = ["Mandatory Label\\High Mandatory Level", "Label", "S-1-16-12288", ""];

test("parseWhoamiGroups: standard user, filtered admin, elevated admin, SYSTEM, low", () => {
  assert.deepEqual(P.parseWhoamiGroups(csv(EVERYONE, USERS, MEDIUM)), { isAdminMember: false, elevated: false, integrity: "medium" });
  assert.deepEqual(P.parseWhoamiGroups(csv(EVERYONE, ADMINS_FILTERED, USERS, MEDIUM)), { isAdminMember: true, elevated: false, integrity: "medium" });
  assert.deepEqual(P.parseWhoamiGroups(csv(EVERYONE, ADMINS_ENABLED, USERS, HIGH)), { isAdminMember: true, elevated: true, integrity: "high" });
  assert.equal(P.parseWhoamiGroups(csv(["Mandatory Label\\System Mandatory Level", "Label", "S-1-16-16384", ""])).integrity, "system");
  assert.equal(P.parseWhoamiGroups(csv(["Mandatory Label\\System Mandatory Level", "Label", "S-1-16-16384", ""])).elevated, true);
  assert.equal(P.parseWhoamiGroups(csv(["Mandatory Label\\Low Mandatory Level", "Label", "S-1-16-4096", ""])).integrity, "low");
  assert.equal(P.parseWhoamiGroups("").integrity, "unknown");
});

test("parseWhoamiGroups: SIDs decide, so names with quotes and non-English attributes still parse", () => {
  const quoted = ['NST\\The ""Ops"" group', "Group", "S-1-5-21-1-2-3-1104", "Enabled group"];
  assert.deepEqual(P.parseWhoamiGroups(csv(quoted, USERS, MEDIUM)), { isAdminMember: false, elevated: false, integrity: "medium" });
  const germanAdmins = ["VORDEFINIERT\\Administratoren", "Alias", "S-1-5-32-544", "Verbindliche Gruppe, Aktivierte Gruppe, Gruppenbesitzer"];
  const germanHigh = ["Verbindliche Beschriftung\\Hohe Verbindlichkeitsstufe", "Bezeichnung", "S-1-16-12288", ""];
  assert.deepEqual(P.parseWhoamiGroups(csv(germanAdmins, germanHigh)), { isAdminMember: true, elevated: true, integrity: "high" });
});

const UAC = (values) =>
  "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\r\n" +
  Object.entries(values)
    .map(([k, v]) => `    ${k}    REG_DWORD    0x${v.toString(16)}\r\n`)
    .join("") +
  "    legalnoticecaption    REG_SZ    \r\n\r\n";

test("parseRegDwords: REG_DWORD values only, CRLF output", () => {
  assert.deepEqual(P.parseRegDwords(UAC({ ConsentPromptBehaviorAdmin: 5, EnableLUA: 1, PromptOnSecureDesktop: 1, TypeOfAdminApprovalMode: 2, Big: 0xffffffff })), {
    ConsentPromptBehaviorAdmin: 5,
    EnableLUA: 1,
    PromptOnSecureDesktop: 1,
    TypeOfAdminApprovalMode: 2,
    Big: 4294967295,
  });
  assert.deepEqual(P.parseRegDwords(""), {});
});

// ------------------------------------------------------------------ Windows part 1

const WIN_POLICY = "C:\\ProgramData\\NightSquawk\\mcp\\column\\policy.json";
const winEnv = { ProgramData: "C:\\ProgramData" };

test("windowsPart1: probes each folder up to the policy root, ProgramData\\NightSquawk\\mcp, never NightSquawk or ProgramData", () => {
  const probes = fakeProbes({ platform: "win32", env: winEnv, files: { [WIN_POLICY]: fileStat() } });
  assert.deepEqual(P.windowsPart1(WIN_POLICY, probes), { ok: true, reasons: [] });
  assert.deepEqual(probes.calls.canCreateIn, ["C:\\ProgramData\\NightSquawk\\mcp\\column", "C:\\ProgramData\\NightSquawk\\mcp"]);
  const lower = fakeProbes({ platform: "win32", env: { ProgramData: "c:\\programdata" }, files: { [WIN_POLICY]: fileStat() } });
  P.windowsPart1(WIN_POLICY, lower);
  assert.equal(lower.calls.canCreateIn.length, 2, "the stop folder is compared case-insensitively");
});

test("windowsPart1: a writable file or a folder the user can create in is a reason", () => {
  const files = { [WIN_POLICY]: fileStat() };
  const w = P.windowsPart1(WIN_POLICY, fakeProbes({ platform: "win32", env: winEnv, files, writable: [WIN_POLICY] }));
  assert.equal(w.ok, false);
  assert.ok(w.reasons.some((r) => /can open .*policy\.json for writing/.test(r)));
  for (const dir of ["C:\\ProgramData\\NightSquawk\\mcp\\column", "C:\\ProgramData\\NightSquawk\\mcp"]) {
    const c = P.windowsPart1(WIN_POLICY, fakeProbes({ platform: "win32", env: winEnv, files, creatable: [dir] }));
    assert.equal(c.ok, false, dir);
    assert.ok(c.reasons.includes(`This user can create files in ${dir}.`), JSON.stringify(c.reasons));
  }
  // init gives NightSquawk ProgramData's own entries, so users may create folders in it. Only its owner counts.
  const above = P.windowsPart1(WIN_POLICY, fakeProbes({ platform: "win32", env: winEnv, files, creatable: ["C:\\ProgramData\\NightSquawk", "C:\\ProgramData"] }));
  assert.deepEqual(above, { ok: true, reasons: [] });
  assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ platform: "win32", env: winEnv })).ok, false, "missing file");
});

const ADMINS_SID = "S-1-5-32-544";
const ME_SID = "S-1-5-21-1-2-3-1001";
const WIN_CHAIN = [WIN_POLICY, "C:\\ProgramData\\NightSquawk\\mcp\\column", "C:\\ProgramData\\NightSquawk\\mcp", "C:\\ProgramData\\NightSquawk", "C:\\ProgramData", "C:\\"];
const ownedBy = (map = {}, reparse = [], rights = {}) => (paths) =>
  paths.map((p) => ({ path: p, owner: Object.hasOwn(map, p) ? map[p] : ADMINS_SID, reparse: reparse.includes(p), rights: Object.hasOwn(rights, p) ? rights[p] : 0 }));

test("windowsPart1: a user-owned file or folder is never protected, even when it is not writable right now (the owner can change the ACL back)", () => {
  const base = { platform: "win32", env: winEnv, files: { [WIN_POLICY]: fileStat() } };
  const probes = fakeProbes({ ...base, owners: ownedBy() });
  assert.deepEqual(P.windowsPart1(WIN_POLICY, probes), { ok: true, reasons: [] });
  assert.deepEqual(probes.calls.windowsOwners, [WIN_CHAIN], "one call covers the file and every folder up to the drive root");
  for (const sid of P.TRUSTED_OWNER_SIDS) assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: ownedBy({ [WIN_POLICY]: sid }) })).ok, true, sid);
  for (const p of WIN_CHAIN) {
    const owned = P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: ownedBy({ [p]: ME_SID }) }));
    assert.equal(owned.ok, false, p);
    assert.ok(owned.reasons.includes(`${p} is owned by ${ME_SID}, not SYSTEM, Administrators or TrustedInstaller.`), JSON.stringify(owned.reasons));
    const link = P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: ownedBy({}, [p]) }));
    assert.ok(link.reasons.includes(`${p} is a junction or symbolic link.`), JSON.stringify(link.reasons));
  }
  assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: null })).ok, false, "unreadable owners fail closed");
  assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: (paths) => ownedBy()(paths.slice(1)) })).ok, false, "a path missing from the answer fails closed");
  assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: ownedBy({ [WIN_POLICY]: null }) })).ok, false, "a null owner fails closed");
  const upper = (paths) => ownedBy()(paths).map((o) => ({ ...o, path: o.path.toUpperCase() }));
  assert.equal(P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: upper })).ok, true, "paths compare case-insensitively");
});

test("windowsPart1: a right to change the ACL or owner, or to delete, fails even with trusted owners and nothing writable now", () => {
  const base = { platform: "win32", env: winEnv, files: { [WIN_POLICY]: fileStat() } };
  const W = P.WINDOWS_CHANGE_RIGHTS;
  const READ = 0x1200a9; // ReadAndExecute, Synchronize
  const part = (rights) => P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: ownedBy({}, [], rights) }));
  assert.deepEqual(part(Object.fromEntries(WIN_CHAIN.map((p) => [p, READ]))), { ok: true, reasons: [] }, "read and execute is fine anywhere");
  // WRITE_DAC alone: the user grants itself write, changes the policy and puts the ACL back. The owner never changes.
  const dac = part({ [WIN_POLICY]: W.WRITE_DAC | READ });
  assert.deepEqual(dac, { ok: false, reasons: [`This user has WRITE_DAC on ${WIN_POLICY}, so it can change the policy or put another in its place.`] });
  for (const name of ["FILE_WRITE_DATA", "FILE_APPEND_DATA", "DELETE", "WRITE_OWNER", "GENERIC_ALL", "GENERIC_WRITE"]) assert.equal(part({ [WIN_POLICY]: W[name] }).ok, false, name);
  for (const dir of ["C:\\ProgramData\\NightSquawk\\mcp\\column", "C:\\ProgramData\\NightSquawk\\mcp"]) {
    for (const name of ["FILE_WRITE_DATA", "FILE_DELETE_CHILD", "DELETE", "WRITE_DAC", "WRITE_OWNER", "GENERIC_ALL", "GENERIC_WRITE"]) assert.equal(part({ [dir]: W[name] }).ok, false, `${name} on ${dir}`);
    assert.equal(part({ [dir]: W.FILE_APPEND_DATA | READ }).ok, true, `adding a subfolder to ${dir} changes no policy`);
  }
  assert.deepEqual(part({ "C:\\ProgramData\\NightSquawk\\mcp": W.FILE_WRITE_DATA | W.FILE_DELETE_CHILD }).reasons, [
    "This user has FILE_ADD_FILE, FILE_DELETE_CHILD on C:\\ProgramData\\NightSquawk\\mcp, so it can change the policy or put another in its place.",
  ]);
  // Above the policy root users may add files and folders (ProgramData's own entries), but not delete, re-ACL or take over a folder.
  const ADD = W.FILE_WRITE_DATA | W.FILE_APPEND_DATA | 0x110; // and write extended attributes and attributes
  assert.deepEqual(part({ "C:\\ProgramData\\NightSquawk": ADD | READ, "C:\\ProgramData": ADD | READ, "C:\\": W.FILE_APPEND_DATA | READ }), { ok: true, reasons: [] });
  for (const dir of ["C:\\ProgramData\\NightSquawk", "C:\\ProgramData", "C:\\"]) {
    for (const name of ["FILE_DELETE_CHILD", "DELETE", "WRITE_DAC", "WRITE_OWNER", "GENERIC_ALL"]) assert.equal(part({ [dir]: W[name] }).ok, false, `${name} on ${dir}`);
  }
  assert.deepEqual(part({ [WIN_POLICY]: null }), { ok: false, reasons: [`Could not read what this user may do to ${WIN_POLICY}.`] });
  const noRights = P.windowsPart1(WIN_POLICY, fakeProbes({ ...base, owners: (paths) => ownedBy()(paths).map(({ rights, ...rest }) => rest) }));
  assert.equal(noRights.ok, false, "an answer without rights, as from an older double, fails closed");
});

test("windowsPart1: the ProgramData variable cannot make a folder the user owns count as protected", () => {
  const env = { ProgramData: "D:\\Users\\kim\\pd" };
  const policy = "D:\\Users\\kim\\pd\\NightSquawk\\mcp\\column\\policy.json";
  const files = { [policy]: fileStat() };
  const mine = (paths) => paths.map((p) => ({ path: p, owner: ME_SID, reparse: false, rights: 0 }));
  const part = P.windowsPart1(policy, fakeProbes({ platform: "win32", env, files, owners: mine }));
  assert.equal(part.ok, false);
  assert.ok(part.reasons.some((r) => r.includes(`is owned by ${ME_SID}`)), JSON.stringify(part.reasons));
  const report = P.checkProtection(policy, { override: false, probes: fakeProbes({ platform: "win32", env, files, owners: mine, runs: winRuns([EVERYONE, USERS, MEDIUM], { EnableLUA: 1 }) }) });
  assert.equal(report.protected, false);
  assert.ok(report.notes.some((n) => n.startsWith("ProgramData is D:\\Users\\kim\\pd")), JSON.stringify(report.notes));
});

test("windowsOwnersScript: one line, every PowerShell single-quote character doubled; parseWindowsOwners: a strict shape", () => {
  const s = P.windowsOwnersScript(["C:\\it's\\x", "C:\\y"]);
  assert.ok(!/[\r\n]/.test(s), "one line");
  assert.ok(s.includes("'C:\\it''s\\x'"), s);
  // PowerShell also ends a single-quoted string at U+2018, U+2019, U+201A and U+201B. Undoubled, a ProgramData
  // value holding one injects code into the owner probe, which can then print trusted owners for any folder.
  for (const cp of [0x2018, 0x2019, 0x201a, 0x201b]) {
    const q = String.fromCodePoint(cp);
    const script = P.windowsOwnersScript([`C:\\a${q}b`]);
    assert.ok(script.includes(`C:\\a${q}${q}b`), `U+${cp.toString(16).toUpperCase()} is not doubled: ${JSON.stringify(script)}`);
  }
  assert.deepEqual(P.parseWindowsOwners('[{"path":"C:\\\\a","owner":"S-1-5-18","reparse":false,"rights":1179817}]'), [{ path: "C:\\a", owner: "S-1-5-18", reparse: false, rights: 1179817 }]);
  assert.deepEqual(P.parseWindowsOwners('{"path":"C:\\\\a","owner":"S-1-5-18","reparse":true,"rights":0}'), [{ path: "C:\\a", owner: "S-1-5-18", reparse: true, rights: 0 }], "PowerShell unwraps a one-item array");
  assert.deepEqual(P.parseWindowsOwners('[{"path":"C:\\\\a","owner":"BUILTIN\\\\Administrators","reparse":false}]'), [{ path: "C:\\a", owner: null, reparse: false, rights: null }], "a name is not a SID, and no rights is unreadable");
  for (const [raw, want] of [["\"2\"", null], ["1.5", null], ["null", null], ["-2147483648", -2147483648]]) {
    assert.equal(P.parseWindowsOwners(`[{"path":"C:\\\\a","owner":"S-1-5-18","rights":${raw}}]`)[0].rights, want, `rights ${raw}: an integer, negative when GENERIC_READ is set`);
  }
  for (const bad of ["", "not json", "5", "[5]", '[{"owner":"S-1-5-18"}]']) assert.equal(P.parseWindowsOwners(bad), null, JSON.stringify(bad));
});

test("windowsPowerShellEnv: the probe gets Windows PowerShell's own module folder, whatever module path the caller had", () => {
  const caller = { SystemRoot: "D:\\Win", Path: "C:\\bin", PSModulePath: "C:\\Program Files\\PowerShell\\7\\Modules", PSMODULEPATH: "C:\\evil" };
  const env = P.windowsPowerShellEnv(caller);
  assert.deepEqual(env, { SystemRoot: "D:\\Win", Path: "C:\\bin", PSModulePath: "D:\\Win\\System32\\WindowsPowerShell\\v1.0\\Modules" });
  assert.equal(caller.PSModulePath, "C:\\Program Files\\PowerShell\\7\\Modules", "the caller's object is not changed");
  assert.equal(P.windowsPowerShellEnv({}).PSModulePath, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules");
});

// ------------------------------------------------------------------ Windows part 2

const winRuns = (groups, uac) => ({
  "whoami /groups /fo csv /nh": { status: 0, stdout: csv(...groups) },
  [`reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`]: { status: 0, stdout: UAC(uac) },
});

test("windowsPart2: a standard user with UAC on is ok, with a note about the admin credential", () => {
  const notes = [];
  const part = P.windowsPart2(fakeProbes({ platform: "win32", runs: winRuns([EVERYONE, USERS, MEDIUM], { EnableLUA: 1 }) }), notes);
  assert.deepEqual(part, { ok: true, reasons: [] });
  assert.ok(notes.some((n) => /Standard user/.test(n)));
});

test("windowsPart2: an administrator needs a credential prompt (1 or 3) on the secure desktop, or Administrator protection", () => {
  const admin = [EVERYONE, ADMINS_FILTERED, USERS, MEDIUM];
  const check = (uac) => P.windowsPart2(fakeProbes({ platform: "win32", runs: winRuns(admin, uac) }), []);
  for (const consent of [0, 2, 4, 5]) {
    const part = check({ EnableLUA: 1, ConsentPromptBehaviorAdmin: consent, PromptOnSecureDesktop: 1 });
    assert.equal(part.ok, false, `consent ${consent}`);
    assert.ok(part.reasons.some((r) => r.includes(`ConsentPromptBehaviorAdmin=${consent}`)));
  }
  assert.equal(check({ EnableLUA: 1, PromptOnSecureDesktop: 1 }).ok, false, "unset means the default, 5");
  for (const consent of [1, 3]) assert.equal(check({ EnableLUA: 1, ConsentPromptBehaviorAdmin: consent, PromptOnSecureDesktop: 1 }).ok, true, `consent ${consent}`);
  const insecure = check({ EnableLUA: 1, ConsentPromptBehaviorAdmin: 1, PromptOnSecureDesktop: 0 });
  assert.equal(insecure.ok, false);
  assert.ok(insecure.reasons.some((r) => /PromptOnSecureDesktop=0/.test(r)));
  const notes = [];
  const ap = P.windowsPart2(fakeProbes({ platform: "win32", runs: winRuns(admin, { EnableLUA: 1, TypeOfAdminApprovalMode: 2 }) }), notes);
  assert.equal(ap.ok, true, JSON.stringify(ap.reasons));
  assert.ok(notes.some((n) => /Administrator protection is on/.test(n)));
});

test("windowsPart2: elevated, UAC off, or unreadable settings are never ok", () => {
  const elevated = P.windowsPart2(fakeProbes({ platform: "win32", runs: winRuns([EVERYONE, ADMINS_ENABLED, HIGH], { EnableLUA: 1, ConsentPromptBehaviorAdmin: 1, PromptOnSecureDesktop: 1 }) }), []);
  assert.equal(elevated.ok, false);
  assert.ok(elevated.reasons.some((r) => /elevated \(integrity high\)/.test(r)));
  const luaOff = P.windowsPart2(fakeProbes({ platform: "win32", runs: winRuns([EVERYONE, USERS, MEDIUM], { EnableLUA: 0 }) }), []);
  assert.equal(luaOff.ok, false);
  assert.ok(luaOff.reasons.some((r) => /EnableLUA=0/.test(r)));
  const noWhoami = P.windowsPart2(fakeProbes({ platform: "win32", runs: {} }), []);
  assert.equal(noWhoami.ok, false);
  const noReg = P.windowsPart2(fakeProbes({ platform: "win32", runs: { "whoami /groups /fo csv /nh": { status: 0, stdout: csv(EVERYONE, USERS, MEDIUM) } } }), []);
  assert.equal(noReg.ok, false);
  assert.ok(noReg.reasons.some((r) => /Could not read the UAC settings/.test(r)));
});

// ------------------------------------------------------------------ entry point

test("checkProtection: both parts must pass; the remote-paths note is always present", () => {
  const now = new Date("2026-11-04T12:00:00.000Z");
  const ok = P.checkProtection(POLICY, { override: false, probes: fakeProbes({ files: rootTree(), runs: ID_OK }), now });
  assert.equal(ok.protected, true);
  assert.equal(ok.platform, "linux");
  assert.equal(ok.policyPath, POLICY);
  assert.equal(ok.checkedAt, "2026-11-04T12:00:00.000Z");
  assert.match(ok.notes[0], /SSH or Tailscale SSH key/);
  const part2Only = P.checkProtection(POLICY, { override: false, probes: fakeProbes({ files: rootTree(), runs: { ...ID_OK, sudo: { status: 0 } } }), now });
  assert.equal(part2Only.protected, false);
  assert.equal(part2Only.part1.ok, true);
  const part1Only = P.checkProtection(POLICY, { override: false, probes: fakeProbes({ files: rootTree({ [POLICY]: fileStat(1000) }), runs: ID_OK }), now });
  assert.equal(part1Only.protected, false);
});

test("checkProtection: the NST_MCP_POLICY_DIR override is never protected", () => {
  const r = P.checkProtection(POLICY, { override: true, probes: fakeProbes({ files: rootTree(), runs: ID_OK }) });
  assert.equal(r.protected, false);
  assert.match(r.part1.reasons[0], /NST_MCP_POLICY_DIR is set/);
});

test("checkProtection: Windows probes run the Windows checks", () => {
  const probes = fakeProbes({ platform: "win32", env: winEnv, files: { [WIN_POLICY]: fileStat() }, runs: winRuns([EVERYONE, USERS, MEDIUM], { EnableLUA: 1 }) });
  const r = P.checkProtection(WIN_POLICY, { override: false, probes });
  assert.equal(r.protected, true, JSON.stringify([r.part1, r.part2]));
  assert.ok(probes.calls.run.includes("whoami /groups /fo csv /nh"));
  assert.ok(!probes.calls.run.includes("sudo -n true"));
});

test("staticProtection: fixed reports for tests", () => {
  assert.equal(P.staticProtection(true).protected, true);
  const off = P.staticProtection(false, "/x/policy.json");
  assert.equal(off.protected, false);
  assert.equal(off.policyPath, "/x/policy.json");
  assert.equal(off.part1.ok, false);
});

// ------------------------------------------------------------------ real probes (this machine)

test("real probes: a user-owned temp policy is never protected", { skip: process.platform === "win32" }, (t) => {
  const dir = tempDir(t);
  const file = join(dir, "policy.json");
  writeFileSync(file, "{}");
  chmodSync(file, 0o444);
  const part = P.posixPart1(file, P.realProbes());
  if (process.getuid() === 0) assert.ok(part.reasons.some((r) => /runs as root/.test(r)));
  else assert.ok(part.reasons.some((r) => r.includes(`owned by uid ${process.getuid()}`)), JSON.stringify(part.reasons));
  assert.equal(part.ok, false);
  assert.equal(P.realProbes().lstat(join(dir, "missing")), null);
  assert.equal(P.realProbes().lstat("/").uid, 0);
});

test("real probes: canOpenForWrite matches what the OS allows", { skip: process.platform === "win32" }, (t) => {
  const dir = tempDir(t);
  const file = join(dir, "f");
  writeFileSync(file, "x");
  assert.equal(P.realProbes().canOpenForWrite(file), true);
  chmodSync(file, 0o444);
  if (process.getuid() !== 0) assert.equal(P.realProbes().canOpenForWrite(file), false);
  assert.equal(P.realProbes().canOpenForWrite(join(dir, "missing")), false);
});

test("real probes: if passwordless sudo works here, part 2 says so", { skip: process.platform === "win32" }, (t) => {
  const r = spawnSync("sudo", ["-n", "true"], { stdio: "ignore", timeout: 5_000 });
  if (r.error?.code === "ENOENT") return t.skip("no sudo on this machine");
  const part = P.posixPart2(P.realProbes());
  if (r.status === 0) {
    assert.equal(part.ok, false);
    assert.ok(part.reasons.some((x) => x.startsWith("Passwordless sudo")));
  } else {
    assert.ok(!part.reasons.some((x) => x.startsWith("Passwordless sudo")), JSON.stringify(part.reasons));
  }
});

// ------------------------------------------------------------------ probe program lookup

test("resolveProbeProgram: never takes sudo, id or whoami from the inherited PATH", () => {
  const stats = {
    "/usr/bin": dirStat(),
    "/usr/bin/sudo": fileStat(0, 0o104755),
    "/usr/bin/id": fileStat(),
    "/home/u/bin": dirStat(1000),
    "/home/u/bin/sudo": fileStat(1000, 0o100755),
    "/home/u/bin/doas": fileStat(1000, 0o100755),
    "/usr/local/bin": dirStat(1000, 0o40755),
    "/usr/local/bin/id2": fileStat(1000, 0o100755),
  };
  const stat = (p) => stats[p] ?? null;
  const env = { PATH: "/home/u/bin:/usr/local/bin:/usr/bin" };
  assert.deepEqual(P.resolveProbeProgram("sudo", "linux", env, stat), { path: "/usr/bin/sudo" }, "the shim earlier on PATH is skipped");
  assert.deepEqual(P.resolveProbeProgram("id", "darwin", env, stat), { path: "/usr/bin/id" });
  assert.deepEqual(P.resolveProbeProgram("doas", "linux", env, stat), { error: "EUNTRUSTED" }, "found only in a user folder: unknown, not missing");
  assert.deepEqual(P.resolveProbeProgram("id2", "linux", env, stat), { error: "EUNTRUSTED" }, "a user-owned /usr/local/bin does not count");
  assert.deepEqual(P.resolveProbeProgram("nope", "linux", env, stat), { error: "ENOENT" });
  const writable = { ...stats, "/usr/bin": dirStat(0, 0o40777) };
  assert.deepEqual(P.resolveProbeProgram("sudo", "linux", {}, (p) => writable[p] ?? null), { error: "ENOENT" }, "a world-writable folder does not count");
  const win = { "C:\\Windows\\System32\\whoami.exe": fileStat() };
  assert.deepEqual(P.resolveProbeProgram("whoami", "win32", { PATH: "C:\\Users\\u\\bin", SystemRoot: "D:\\Evil" }, (p) => win[p] ?? null), {
    path: "C:\\Windows\\System32\\whoami.exe",
  });
});

test("POSIX part 2 fails closed when sudo is found only outside the trusted folders", () => {
  const probes = fakeProbes({ runs: { "sudo -n true": { status: null, stdout: "", stderr: "", error: "EUNTRUSTED" }, "id -Gn": { status: 0, stdout: "u\n", stderr: "" } } });
  const part = P.posixPart2(probes);
  assert.equal(part.ok, false);
  assert.match(part.reasons.join(" "), /EUNTRUSTED/);
});
