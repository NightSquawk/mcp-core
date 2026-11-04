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
import { closeSync, lstatSync, openSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { randomBytes } from "node:crypto";

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
  /** Spawn error code (ENOENT when the program is missing). */
  error?: string;
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
      };
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
    if (r.error === "ENOENT") continue;
    if (r.status === 0) reasons.push(`Passwordless ${tool}: "${tool} -n true" succeeded (a NOPASSWD rule or a cached credential).`);
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
  const programData = (probes.env.ProgramData ?? probes.env.PROGRAMDATA ?? "C:\\ProgramData").trim();
  const top = win32.join(programData, "NightSquawk").toLowerCase();
  let dir = win32.dirname(policyPath);
  for (;;) {
    if (probes.canCreateIn(dir)) reasons.push(`This user can create files in ${dir}.`);
    if (dir.toLowerCase() === top) break;
    const parent = win32.dirname(dir);
    if (parent === dir || !parent.toLowerCase().startsWith(top)) break;
    dir = parent;
  }
  return { ok: reasons.length === 0, reasons };
}

export function windowsPart2(probes: ProtectionProbes, notes: string[]): ProtectionPart {
  const reasons: string[] = [];
  const who = probes.run("whoami", ["/groups", "/fo", "csv", "/nh"]);
  if (who.status !== 0) return { ok: false, reasons: ["Could not read this user's groups (whoami /groups failed)."] };
  const groups = parseWhoamiGroups(who.stdout);
  if (groups.elevated) reasons.push(`This process is elevated (integrity ${groups.integrity}).`);

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
