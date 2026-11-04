/**
 * Is the policy protected? (section 5.1). Both parts must pass:
 *
 *  1. the agent's OS user cannot change the policy;
 *  2. the agent's OS user cannot become admin without a factor it lacks.
 *
 * Every OS call goes through `ProtectionProbes`, so the logic is testable with
 * recorded outputs. The real probes run `sudo -n true`, `id -Gn`, `whoami` and
 * `reg query`; none of them changes anything.
 */
import { spawnSync } from "node:child_process";
import { closeSync, lstatSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { randomBytes } from "node:crypto";
import { DEFAULT_PROGRAM_DATA, programDataDir } from "./paths.js";

export interface StatInfo {
  isFile: boolean;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  uid: number;
  mode: number;
}

export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  /** Spawn error code (ENOENT when the program is missing, ETIMEDOUT after the timeout). */
  error?: string;
  /** The signal that ended the process, if any. */
  signal?: string;
}

/** Owner and reparse flag of one path (Windows). */
export interface WindowsOwnerInfo {
  path: string;
  /** Owner SID, or null when it could not be read. */
  owner: string | null;
  /** A junction, symlink or other reparse point. */
  reparse: boolean;
}

export interface ProtectionProbes {
  platform: NodeJS.Platform;
  lstat(path: string): StatInfo | null;
  realpath(path: string): string;
  run(cmd: string, args: readonly string[]): RunResult;
  getuid(): number | undefined;
  /** Windows: can the current user open the file for writing? */
  canOpenForWrite(path: string): boolean;
  /** Windows: can the current user create (and delete) a file in this folder? */
  canCreateIn(dir: string): boolean;
  env: NodeJS.ProcessEnv;
  /**
   * Read a small text file, or null when it cannot be read (Linux: /proc/self/uid_map).
   * Optional only so hand-made test doubles keep working; realProbes() always has it,
   * and a probe that has it but returns null fails the check closed.
   */
  readText?(path: string): string | null;
  /**
   * Windows: owner SID and reparse flag for each path, in one call; null when the
   * owners cannot be read (fails closed). Optional for the same reason as readText.
   */
  windowsOwners?(paths: readonly string[]): WindowsOwnerInfo[] | null;
}

export interface ProtectionPart {
  ok: boolean;
  reasons: string[];
}

export interface ProtectionReport {
  protected: boolean;
  platform: NodeJS.Platform;
  policyPath: string;
  part1: ProtectionPart;
  part2: ProtectionPart;
  notes: string[];
  checkedAt: string;
}

/** Groups that are root-equivalent on Linux. */
export const ROOT_EQUIVALENT_GROUPS = Object.freeze(["docker", "lxd", "incus-admin", "libvirt", "disk"]);

/** The uid_map of a process that is not in a user namespace. */
export const IDENTITY_UID_MAP = "0 0 4294967295";

/** Owners a protected policy file and its folders may have: SYSTEM, Administrators, TrustedInstaller. */
export const TRUSTED_OWNER_SIDS = Object.freeze(["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]);

/** Built-in groups whose members can get around file ACLs or become admin (Windows). */
export const ADMIN_EQUIVALENT_GROUP_SIDS: Readonly<Record<string, string>> = Object.freeze({
  "S-1-5-32-548": "Account Operators",
  "S-1-5-32-549": "Server Operators",
  "S-1-5-32-550": "Print Operators",
  "S-1-5-32-551": "Backup Operators",
});

/** One PowerShell line (stdin, no -EncodedCommand) that prints owner SID and reparse flag per path as JSON. */
export function windowsOwnersScript(paths: readonly string[]): string {
  const lit = (p: string) => `'${p.replace(/'/g, "''")}'`;
  return (
    `$out = foreach ($p in @(${paths.map(lit).join(", ")})) { try { $i = Get-Item -LiteralPath $p -Force -ErrorAction Stop; ` +
    "$o = (Get-Acl -LiteralPath $p -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value; " +
    "[pscustomobject]@{ path = $p; owner = $o; reparse = [bool]($i.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } } " +
    "catch { [pscustomobject]@{ path = $p; owner = $null; reparse = $false } } }; ConvertTo-Json -InputObject @($out) -Compress"
  );
}

/** Parse the JSON windowsOwnersScript() prints; null when it is not that shape. */
export function parseWindowsOwners(stdout: string): WindowsOwnerInfo[] | null {
  let v: unknown;
  try {
    v = JSON.parse(stdout.trim());
  } catch {
    return null;
  }
  const list = Array.isArray(v) ? v : v && typeof v === "object" ? [v] : null;
  if (!list) return null;
  const out: WindowsOwnerInfo[] = [];
  for (const x of list as Array<Record<string, unknown>>) {
    if (!x || typeof x !== "object" || typeof x.path !== "string") return null;
    out.push({ path: x.path, owner: typeof x.owner === "string" && /^S-1-[0-9-]+$/.test(x.owner) ? x.owner : null, reparse: x.reparse === true });
  }
  return out;
}

const REMOTE_PATHS_NOTE =
  "This check cannot see remote paths to admin: an SSH or Tailscale SSH key into root or an admin account, or an RMM API key " +
  "that can run scripts (they run as root/SYSTEM). The agent's user must not be able to read any of these (hardening SOP).";

export function realProbes(): ProtectionProbes {
  return {
    platform: process.platform,
    env: process.env,
    lstat(path) {
      try {
        const s = lstatSync(path);
        return { isFile: s.isFile(), isDirectory: s.isDirectory(), isSymbolicLink: s.isSymbolicLink(), uid: s.uid, mode: s.mode };
      } catch {
        return null;
      }
    },
    realpath: (p) => realpathSync(p),
    run(cmd, args) {
      const r = spawnSync(cmd, [...args], {
        encoding: "utf8",
        timeout: 5_000,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, LC_ALL: "C", LANG: "C" },
        windowsHide: true,
      });
      return {
        status: r.status,
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        ...(r.error ? { error: (r.error as NodeJS.ErrnoException).code ?? r.error.message } : {}),
        ...(r.signal ? { signal: r.signal } : {}),
      };
    },
    readText(path) {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return null;
      }
    },
    windowsOwners(paths) {
      const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "-"], {
        input: windowsOwnersScript(paths) + "\r\n",
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true,
      });
      if (r.error || r.status !== 0) return null;
      return parseWindowsOwners(r.stdout ?? "");
    },
    getuid: () => (typeof process.getuid === "function" ? process.getuid() : undefined),
    canOpenForWrite(path) {
      try {
        closeSync(openSync(path, "r+"));
        return true;
      } catch {
        return false;
      }
    },
    canCreateIn(dir) {
      const probe = win32.join(dir, `.mcp-guard-probe-${randomBytes(6).toString("hex")}`);
      try {
        writeFileSync(probe, "", { flag: "wx" });
      } catch {
        return false;
      }
      try {
        rmSync(probe, { force: true });
      } catch {
        // created but not deletable: still means the folder is writable
      }
      return true;
    },
  };
}

// ---------------------------------------------------------------- Linux / macOS

/** Part 1 on POSIX: the file and every directory up to / are root-owned and not group/other-writable. */
export function posixPart1(policyPath: string, probes: ProtectionProbes): ProtectionPart {
  const reasons: string[] = [];
  const file = probes.lstat(policyPath);
  if (!file) return { ok: false, reasons: [`No policy file at ${policyPath}.`] };
  if (file.isSymbolicLink) reasons.push(`${policyPath} is a symlink.`);
  else if (!file.isFile) reasons.push(`${policyPath} is not a regular file.`);
  if (file.uid !== 0) reasons.push(`${policyPath} is owned by uid ${file.uid}, not root.`);
  if (file.mode & 0o022) reasons.push(`${policyPath} is writable by its group or others (mode ${(file.mode & 0o777).toString(8)}).`);

  let dir: string;
  try {
    dir = probes.realpath(posix.dirname(policyPath));
  } catch {
    return { ok: false, reasons: [...reasons, `Cannot resolve ${posix.dirname(policyPath)}.`] };
  }
  for (;;) {
    const s = probes.lstat(dir);
    if (!s) {
      reasons.push(`Cannot stat ${dir}.`);
      break;
    }
    if (s.uid !== 0) reasons.push(`${dir} is owned by uid ${s.uid}, not root.`);
    if (s.mode & 0o022) reasons.push(`${dir} is writable by its group or others (mode ${(s.mode & 0o777).toString(8)}).`);
    const parent = posix.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const uid = probes.getuid();
  if (uid === 0) reasons.push("This process runs as root, so it can change the policy.");
  if (probes.platform === "linux" && probes.readText) {
    // Inside a user namespace (rootless podman, unshare -Ur) the owners this process sees can be forged.
    const map = probes.readText("/proc/self/uid_map");
    if (map === null) reasons.push("Cannot read /proc/self/uid_map, so a user namespace cannot be ruled out.");
    else {
      const norm = map.trim().split(/\s+/).join(" ");
      if (norm !== IDENTITY_UID_MAP) reasons.push(`This process runs in a user namespace (uid_map "${norm.slice(0, 80)}"), where file owners can be forged.`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

/** Parse `id -Gn` output into group names. */
export function parseGroupNames(stdout: string): string[] {
  return stdout.split(/\s+/).map((g) => g.trim()).filter(Boolean);
}

/** Part 2 on POSIX: no passwordless sudo/doas, no root-equivalent group. */
export function posixPart2(probes: ProtectionProbes): ProtectionPart {
  const reasons: string[] = [];
  for (const tool of ["sudo", "doas"] as const) {
    const r = probes.run(tool, ["-n", "true"]);
    // Not installed, or not executable by this user (mode 4750): no path to root through it.
    if (r.error === "ENOENT" || r.error === "EACCES") continue;
    if (r.status === 0) {
      reasons.push(`Passwordless ${tool}: "${tool} -n true" succeeded (a NOPASSWD rule or a cached credential).`);
      continue;
    }
    if (r.status === null) {
      // A timeout or a kill is not an answer (fail closed).
      reasons.push(`Could not tell whether ${tool} needs a password: "${tool} -n true" ${r.error ? `failed (${r.error})` : `was killed${r.signal ? ` (${r.signal})` : ""}`}.`);
      continue;
    }
    if (tool === "sudo") {
      // "sudo -n true" only covers ALL-style rules. With the default listpw=any, "sudo -n -l" lists the
      // rules without a password exactly when one of them is NOPASSWD (tee, vim, systemctl, ... reach root).
      const l = probes.run("sudo", ["-n", "-l"]);
      if (l.status === 0) {
        const nopw = l.stdout.split(/\r?\n/).map((x) => x.trim()).filter((x) => /\bNOPASSWD\s*:/.test(x));
        if (nopw.length) reasons.push(`sudo has NOPASSWD rule(s) for this user: ${nopw.slice(0, 3).join("; ")}${nopw.length > 3 ? ` (+${nopw.length - 3} more)` : ""}.`);
      } else if (l.status === null && l.error !== "ENOENT" && l.error !== "EACCES") {
        reasons.push(`Could not list this user's sudo rules: "sudo -n -l" ${l.error ? `failed (${l.error})` : "was killed"}.`);
      }
    }
  }
  const id = probes.run("id", ["-Gn"]);
  if (id.status !== 0) {
    reasons.push("Could not list this user's groups (id -Gn failed), so root-equivalent group membership is unknown.");
  } else {
    const groups = parseGroupNames(id.stdout);
    const bad = groups.filter((g) => ROOT_EQUIVALENT_GROUPS.includes(g));
    if (bad.length) reasons.push(`Member of root-equivalent group(s): ${bad.join(", ")}.`);
  }
  return { ok: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------- Windows

export interface WindowsGroupsInfo {
  isAdminMember: boolean;
  elevated: boolean;
  integrity: "low" | "medium" | "high" | "system" | "unknown";
}

/** Parse `whoami /groups /fo csv /nh`. */
export function parseWhoamiGroups(stdout: string): WindowsGroupsInfo {
  let isAdminMember = false;
  let adminEnabled = false;
  let integrity: WindowsGroupsInfo["integrity"] = "unknown";
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const cols = [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1].replace(/""/g, '"'));
    const sid = cols.find((c) => /^S-1-[0-9-]+$/.test(c)) ?? "";
    const attrs = cols.slice(cols.indexOf(sid) + 1).join(" ");
    if (sid === "S-1-5-32-544") {
      isAdminMember = true;
      adminEnabled = /Enabled group/i.test(attrs) && !/deny only/i.test(attrs);
    }
    if (sid === "S-1-16-4096") integrity = "low";
    if (sid === "S-1-16-8192") integrity = "medium";
    if (sid === "S-1-16-12288") integrity = "high";
    if (sid === "S-1-16-16384") integrity = "system";
  }
  const elevated = integrity === "high" || integrity === "system" || adminEnabled;
  return { isAdminMember, elevated, integrity };
}

/** Every SID in `whoami /groups /fo csv /nh` output. */
export function parseWhoamiSids(stdout: string): string[] {
  const out: string[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const cols = [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1]);
    const sid = cols.find((c) => /^S-1-[0-9-]+$/.test(c));
    if (sid) out.push(sid);
  }
  return out;
}

/** Parse `reg query <key>` output into name -> number for REG_DWORD values. */
export function parseRegDwords(stdout: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of stdout.matchAll(/^\s*(\S+)\s+REG_DWORD\s+0x([0-9a-fA-F]+)\s*$/gm)) out[m[1]] = parseInt(m[2], 16);
  return out;
}

const UAC_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

export function windowsPart1(policyPath: string, probes: ProtectionProbes): ProtectionPart {
  const reasons: string[] = [];
  if (!probes.lstat(policyPath)) return { ok: false, reasons: [`No policy file at ${policyPath}.`] };
  if (probes.canOpenForWrite(policyPath)) reasons.push(`This user can open ${policyPath} for writing.`);
  const top = win32.join(programDataDir(probes.env), "NightSquawk").toLowerCase();
  const chain = [policyPath];
  let dir = win32.dirname(policyPath);
  for (;;) {
    chain.push(dir);
    if (probes.canCreateIn(dir)) reasons.push(`This user can create files in ${dir}.`);
    if (dir.toLowerCase() === top) break;
    const parent = win32.dirname(dir);
    if (parent === dir || !parent.toLowerCase().startsWith(top)) break;
    dir = parent;
  }
  // "Not writable right now" is not enough: an owner can always change the ACL back (attrib -R,
  // removing a self-added deny entry). Every link must be owned by SYSTEM, Administrators or
  // TrustedInstaller, and none may be a junction or symlink.
  if (probes.windowsOwners) {
    const owners = probes.windowsOwners(chain);
    if (!owners) reasons.push("Could not read the owners of the policy file and its folders.");
    else {
      for (const p of chain) {
        const info = owners.find((o) => o.path.toLowerCase() === p.toLowerCase());
        if (!info || !info.owner) reasons.push(`Could not read the owner of ${p}.`);
        else if (!TRUSTED_OWNER_SIDS.includes(info.owner)) reasons.push(`${p} is owned by ${info.owner}, not SYSTEM, Administrators or TrustedInstaller.`);
        if (info?.reparse) reasons.push(`${p} is a junction or symbolic link.`);
      }
    }
  }
  return { ok: reasons.length === 0, reasons };
}

export function windowsPart2(probes: ProtectionProbes, notes: string[]): ProtectionPart {
  const reasons: string[] = [];
  const who = probes.run("whoami", ["/groups", "/fo", "csv", "/nh"]);
  if (who.status !== 0) return { ok: false, reasons: ["Could not read this user's groups (whoami /groups failed)."] };
  const groups = parseWhoamiGroups(who.stdout);
  if (groups.elevated) reasons.push(`This process is elevated (integrity ${groups.integrity}).`);
  const equivalent = [...new Set(parseWhoamiSids(who.stdout).filter((sid) => sid in ADMIN_EQUIVALENT_GROUP_SIDS).map((sid) => ADMIN_EQUIVALENT_GROUP_SIDS[sid]))];
  if (equivalent.length) reasons.push(`Member of admin-equivalent group(s): ${equivalent.join(", ")}.`);

  const reg = probes.run("reg", ["query", UAC_KEY]);
  if (reg.status !== 0) {
    reasons.push(`Could not read the UAC settings (${UAC_KEY}).`);
    return { ok: false, reasons };
  }
  const v = parseRegDwords(reg.stdout);
  if (v.EnableLUA === 0) reasons.push("UAC is off (EnableLUA=0).");
  if (groups.isAdminMember) {
    if (v.TypeOfAdminApprovalMode === 2) {
      notes.push("Administrator protection is on (TypeOfAdminApprovalMode=2). Make sure this build is patched for CVE-2026-42829.");
    } else {
      const consent = v.ConsentPromptBehaviorAdmin ?? 5;
      if (consent !== 1 && consent !== 3) {
        reasons.push(
          `This user is an administrator and elevation asks for no credential (ConsentPromptBehaviorAdmin=${consent}; needs 1 or 3, ` +
            "or Administrator protection)."
        );
      }
      if (v.PromptOnSecureDesktop === 0) reasons.push("Elevation prompts are not on the secure desktop (PromptOnSecureDesktop=0).");
    }
  } else {
    notes.push("Standard user: the admin account's credential must be one this agent cannot read.");
  }
  return { ok: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------- entry point

export function checkProtection(policyPath: string, opts: { override: boolean; probes?: ProtectionProbes; now?: Date }): ProtectionReport {
  const probes = opts.probes ?? realProbes();
  const notes: string[] = [REMOTE_PATHS_NOTE];
  let part1: ProtectionPart;
  let part2: ProtectionPart;
  if (probes.platform === "win32") {
    part1 = windowsPart1(policyPath, probes);
    part2 = windowsPart2(probes, notes);
    const pd = programDataDir(probes.env);
    if (pd.toLowerCase() !== DEFAULT_PROGRAM_DATA.toLowerCase()) notes.push(`ProgramData is ${pd}, not ${DEFAULT_PROGRAM_DATA}; the owner check still applies to every folder.`);
  } else {
    part1 = posixPart1(policyPath, probes);
    part2 = posixPart2(probes);
  }
  if (opts.override) {
    part1 = { ok: false, reasons: ["NST_MCP_POLICY_DIR is set (tests only): such a policy is never protected.", ...part1.reasons] };
  }
  return {
    protected: part1.ok && part2.ok,
    platform: probes.platform,
    policyPath,
    part1,
    part2,
    notes,
    checkedAt: (opts.now ?? new Date()).toISOString(),
  };
}

/** A fixed report for tests and for servers that run without a real check. */
export function staticProtection(isProtected: boolean, policyPath = "(test)"): ProtectionReport {
  const part = { ok: isProtected, reasons: isProtected ? [] : ["Static test report: unprotected."] };
  return {
    protected: isProtected,
    platform: process.platform,
    policyPath,
    part1: part,
    part2: { ok: isProtected, reasons: [] },
    notes: ["Static report: no OS check was run."],
    checkedAt: new Date(0).toISOString(),
  };
}
