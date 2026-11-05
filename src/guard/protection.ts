/**
 * Is the policy protected? (section 5.1). Both parts must pass:
 *
 *  1. the agent's OS user cannot change the policy;
 *  2. the agent's OS user cannot become admin without a factor it lacks.
 *
 * Every OS call goes through `ProtectionProbes`, so the logic is testable with
 * recorded outputs. The real probes run `sudo -n true`, `sudo -n -l`, `doas -n true`,
 * `id`, `whoami` and `reg query`, and read doas.conf; none of them changes anything.
 */
import { spawnSync } from "node:child_process";
import { closeSync, lstatSync, openSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
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

/** Owner, reparse flag and this user's access to one path (Windows). */
export interface WindowsOwnerInfo {
  path: string;
  /** Owner SID, or null when it could not be read. */
  owner: string | null;
  /** A junction, symlink or other reparse point. */
  reparse: boolean;
  /**
   * The access mask that the allow entries applying to the path itself (not inherit-only ones) give
   * the current user or one of its enabled groups; null when it could not be read (fails closed).
   * Deny entries are not subtracted, so a right one of them takes away still counts.
   */
  rights: number | null;
}

export interface ProtectionProbes {
  platform: NodeJS.Platform;
  lstat(path: string): StatInfo | null;
  /** A symlink's target as stored, or null when it cannot be read. */
  readlink(path: string): string | null;
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
  /** The names in a folder, or null when it cannot be listed (/etc/doas.d). Optional for the same reason as readText. */
  listDir?(path: string): string[] | null;
  /**
   * Windows: owner SID, reparse flag and this user's rights for each path, in one call;
   * null when they cannot be read (fails closed). Optional for the same reason as readText.
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

/**
 * Every character PowerShell ends a single-quoted string at (CharExtensions.IsSingleQuote):
 * the ASCII apostrophe and U+2018, U+2019, U+201A, U+201B. Doubling only the ASCII one lets
 * a path holding a curly quote break out of the literal and run code.
 */
export const POWERSHELL_SINGLE_QUOTES: readonly number[] = Object.freeze([0x27, 0x2018, 0x2019, 0x201a, 0x201b]);

/**
 * True when a path holds a character no real path needs and a stdin script cannot carry:
 * C0 and C1 controls (CR or LF would split the script into lines), DEL, U+2028 and U+2029.
 */
export function hasUnsafePathChar(path: string): boolean {
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return true;
  }
  return false;
}

/**
 * A PowerShell single-quoted literal, every quote character doubled the way
 * CodeGeneration.EscapeSingleQuotedStringContent does it. Throws on a path
 * hasUnsafePathChar() rejects; callers check first and fail closed.
 */
export function psSingleQuoted(text: string): string {
  if (hasUnsafePathChar(text)) throw new RangeError("A PowerShell literal cannot hold control characters or line separators.");
  let out = "'";
  for (const ch of text) {
    out += ch;
    if (POWERSHELL_SINGLE_QUOTES.includes(ch.charCodeAt(0))) out += ch;
  }
  return out + "'";
}

/**
 * One PowerShell line (stdin, no -EncodedCommand) that prints, per path as JSON, the owner SID, the
 * reparse flag and `rights`: the OR of the allow entries that apply to the path itself (not
 * inherit-only ones, PropagationFlags 2) and name this process's user or one of its enabled groups
 * (WindowsIdentity.Groups leaves out deny-only and disabled groups).
 */
export function windowsOwnersScript(paths: readonly string[]): string {
  return (
    "$sid = [System.Security.Principal.SecurityIdentifier]; $id = [System.Security.Principal.WindowsIdentity]::GetCurrent(); " +
    "$mine = @($id.User.Value) + @($id.Groups | ForEach-Object { $_.Value }); " +
    `$out = foreach ($p in @(${paths.map(psSingleQuoted).join(", ")})) { try { $i = Get-Item -LiteralPath $p -Force -ErrorAction Stop; ` +
    "$acl = Get-Acl -LiteralPath $p -ErrorAction Stop; $o = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; $r = 0; " +
    "foreach ($e in $acl.GetAccessRules($true, $true, $sid)) { " +
    "if (($e.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and ((([int]$e.PropagationFlags) -band 2) -eq 0) -and ($mine -contains $e.IdentityReference.Value)) " +
    "{ $r = $r -bor ([int]$e.FileSystemRights) } }; " +
    "[pscustomobject]@{ path = $p; owner = $o; reparse = [bool]($i.Attributes -band [System.IO.FileAttributes]::ReparsePoint); rights = $r } } " +
    "catch { [pscustomobject]@{ path = $p; owner = $null; reparse = $false; rights = $null } } }; ConvertTo-Json -InputObject @($out) -Compress"
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
    out.push({
      path: x.path,
      owner: typeof x.owner === "string" && /^S-1-[0-9-]+$/.test(x.owner) ? x.owner : null,
      reparse: x.reparse === true,
      rights: typeof x.rights === "number" && Number.isInteger(x.rights) ? x.rights : null,
    });
  }
  return out;
}

/**
 * The environment the owner probe gives Windows PowerShell: the caller's, except that PSModulePath
 * names only Windows PowerShell's own module folder. A PowerShell 7 parent passes its own module
 * folders down. Windows PowerShell then finds Get-Acl there first and cannot load it, so every
 * owner would read as unknown.
 */
export function windowsPowerShellEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  let systemRoot: string | undefined;
  for (const [key, value] of Object.entries(env)) {
    const name = key.toUpperCase();
    if (name === "PSMODULEPATH") continue;
    if (name === "SYSTEMROOT" && value) systemRoot = value;
    out[key] = value;
  }
  out.PSModulePath = win32.join(systemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "Modules");
  return out;
}

const REMOTE_PATHS_NOTE =
  "This check cannot see remote paths to admin: an SSH or Tailscale SSH key into root or an admin account, or an RMM API key " +
  "that can run scripts (they run as root/SYSTEM). The agent's user must not be able to read any of these (hardening SOP).";

/** Folders the POSIX probes look in for sudo, doas and id, in order. */
export const TRUSTED_POSIX_BIN_DIRS = Object.freeze(["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]);

/** Owner and mode of a path after following symlinks, or null when it does not exist. */
export interface ProgramStat {
  isFile: boolean;
  isDirectory: boolean;
  uid: number;
  mode: number;
}

export type ProbeProgram = { path: string } | { error: "ENOENT" | "EUNTRUSTED" };

/**
 * Where a probe runs `cmd` from, never from the inherited PATH: a PATH the agent can change would let
 * a shim named sudo, doas, id, whoami or reg answer for the real one and make part 2 pass.
 *
 * POSIX: the first trusted bin folder holding the program, where the folder and the file are owned by
 * root and not writable by group or others (so a user-owned /usr/local/bin, as Homebrew leaves it on
 * Intel macOS, does not count). A program found only elsewhere on PATH is EUNTRUSTED, which the checks
 * treat as unknown (fail closed); one found nowhere is ENOENT. Windows: System32 of C:\Windows, or of
 * SystemRoot when C:\Windows does not exist.
 */
export function resolveProbeProgram(
  cmd: string,
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  stat: (path: string) => ProgramStat | null
): ProbeProgram {
  if (platform === "win32") {
    const roots = ["C:\\Windows"];
    const sysRoot = env.SystemRoot ?? env.SYSTEMROOT;
    if (sysRoot && win32.isAbsolute(sysRoot)) roots.push(sysRoot);
    for (const root of roots) {
      const path = win32.join(root, "System32", `${cmd}.exe`);
      if (stat(path)?.isFile) return { path };
    }
    return { error: "ENOENT" };
  }
  const safe = (s: ProgramStat | null) => s !== null && s.uid === 0 && (s.mode & 0o022) === 0;
  for (const dir of TRUSTED_POSIX_BIN_DIRS) {
    const path = posix.join(dir, cmd);
    const f = stat(path);
    if (!f?.isFile) continue;
    const d = stat(dir);
    if (d?.isDirectory && safe(d) && safe(f)) return { path };
  }
  for (const dir of (env.PATH ?? "").split(":")) {
    if (dir && stat(posix.join(dir, cmd))?.isFile) return { error: "EUNTRUSTED" };
  }
  return { error: "ENOENT" };
}

function statProgram(path: string): ProgramStat | null {
  try {
    const s = statSync(path);
    return { isFile: s.isFile(), isDirectory: s.isDirectory(), uid: s.uid, mode: s.mode };
  } catch {
    return null;
  }
}

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
    readlink(path) {
      try {
        return readlinkSync(path);
      } catch {
        return null;
      }
    },
    run(cmd, args) {
      const program = resolveProbeProgram(cmd, process.platform, process.env, statProgram);
      if ("error" in program) return { status: null, stdout: "", stderr: "", error: program.error };
      const env: NodeJS.ProcessEnv = { ...process.env, LC_ALL: "C", LANG: "C" };
      if (process.platform !== "win32") env.PATH = TRUSTED_POSIX_BIN_DIRS.join(":");
      const r = spawnSync(program.path, [...args], {
        encoding: "utf8",
        timeout: 5_000,
        stdio: ["ignore", "pipe", "pipe"],
        env,
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
    listDir(path) {
      try {
        return readdirSync(path);
      } catch {
        return null;
      }
    },
    windowsOwners(paths) {
      // Fail closed without starting PowerShell: such a path cannot be quoted onto one stdin line.
      if (paths.some(hasUnsafePathChar)) return null;
      const ps = resolveProbeProgram("WindowsPowerShell\\v1.0\\powershell", "win32", process.env, statProgram);
      if ("error" in ps) return null;
      const r = spawnSync(ps.path, ["-NoProfile", "-NonInteractive", "-Command", "-"], {
        input: windowsOwnersScript(paths) + "\r\n",
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true,
        env: windowsPowerShellEnv(process.env),
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

/** One entry a path lookup passes through: "/", a folder, a symlink, or what the path names. */
export interface LookupStep {
  path: string;
  stat: StatInfo;
}

/** The most symlinks one lookup follows, as on Linux. */
export const MAX_SYMLINKS = 40;

/**
 * Resolve an absolute POSIX path one name at a time, the way the kernel does, and list every entry
 * the lookup passes through: "/", each folder, each symlink however many links deep, and last what
 * the path names. Whoever can change one of them can point the path somewhere else. `error` (a
 * clause such as "/x cannot be read") says where the lookup stopped; the steps before it are kept.
 */
export function lookupSteps(path: string, probes: Pick<ProtectionProbes, "lstat" | "readlink">): { steps: LookupStep[]; error?: string } {
  const steps: LookupStep[] = [];
  const seen = new Set<string>();
  const step = (p: string): StatInfo | null => {
    const stat = probes.lstat(p);
    if (stat && !seen.has(p)) {
      seen.add(p);
      steps.push({ path: p, stat });
    }
    return stat;
  };
  if (!path.startsWith("/")) return { steps, error: `${path} is not an absolute path` };
  if (!step("/")) return { steps, error: "/ cannot be read" };
  const names = path.split("/").filter((n) => n && n !== ".");
  let dir = "/";
  let links = 0;
  while (names.length) {
    const name = names.shift() as string;
    if (name === "..") {
      dir = posix.dirname(dir);
      continue;
    }
    const next = posix.join(dir, name);
    const stat = step(next);
    if (!stat) return { steps, error: `${next} cannot be read` };
    if (!stat.isSymbolicLink) {
      dir = next;
      continue;
    }
    if (++links > MAX_SYMLINKS) return { steps, error: `${path} cannot be resolved: more than ${MAX_SYMLINKS} symlinks` };
    const target = probes.readlink(next);
    if (target === null) return { steps, error: `the symlink ${next} cannot be read` };
    if (target.startsWith("/")) dir = "/";
    names.unshift(...target.split("/").filter((n) => n && n !== "."));
  }
  return { steps };
}

/** Part 1 on POSIX: the file and every folder its lookup passes through are root-owned and not group/other-writable. */
export function posixPart1(policyPath: string, probes: ProtectionProbes): ProtectionPart {
  const reasons: string[] = [];
  const file = probes.lstat(policyPath);
  if (!file) return { ok: false, reasons: [`No policy file at ${policyPath}.`] };
  if (file.isSymbolicLink) reasons.push(`${policyPath} is a symlink.`);
  else if (!file.isFile) reasons.push(`${policyPath} is not a regular file.`);
  if (file.uid !== 0) reasons.push(`${policyPath} is owned by uid ${file.uid}, not root.`);
  if (file.mode & 0o022) reasons.push(`${policyPath} is writable by its group or others (mode ${(file.mode & 0o777).toString(8)}).`);

  // Every folder the lookup of the policy's folder passes through, however many symlinks deep. A
  // symlink itself cannot be changed, only replaced by whoever can write the folder holding it, and
  // that folder is on the lookup too. A sticky folder others can write fails here anyway.
  const lookup = lookupSteps(posix.dirname(policyPath), probes);
  for (const { path, stat } of [...lookup.steps].reverse()) {
    if (stat.isSymbolicLink) continue;
    if (stat.uid !== 0) reasons.push(`${path} is owned by uid ${stat.uid}, not root.`);
    if (stat.mode & 0o022) reasons.push(`${path} is writable by its group or others (mode ${(stat.mode & 0o777).toString(8)}).`);
  }
  if (lookup.error) reasons.push(`${lookup.error[0].toUpperCase()}${lookup.error.slice(1)}.`);
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
  let doasRefused: RunResult | null = null;
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
    if (tool === "doas") {
      doasRefused = r;
      continue;
    }
    // "sudo -n true" only covers ALL-style rules. With the default listpw=any, "sudo -n -l" lists the
    // rules without a password exactly when one of them is NOPASSWD (tee, vim, systemctl, ... reach root).
    // A refused listing is not read as unknown: it is what every user without a NOPASSWD rule gets,
    // a user who may use sudo with a password included. listpw=always (or all, with rules of both
    // kinds) refuses it too and so hides a narrow NOPASSWD rule; HARDENING.md says not to set that.
    const l = probes.run("sudo", ["-n", "-l"]);
    if (l.status === 0) {
      const nopw = l.stdout.split(/\r?\n/).map((x) => x.trim()).filter((x) => /\bNOPASSWD\s*:/.test(x));
      if (nopw.length) reasons.push(`sudo has NOPASSWD rule(s) for this user: ${listSome(nopw)}.`);
    } else if (l.status === null && l.error !== "ENOENT" && l.error !== "EACCES") {
      reasons.push(`Could not list this user's sudo rules: "sudo -n -l" ${l.error ? `failed (${l.error})` : "was killed"}.`);
    }
  }
  const id = probes.run("id", ["-Gn"]);
  const groups = id.status === 0 ? parseGroupNames(id.stdout) : null;
  if (!groups) {
    reasons.push("Could not list this user's groups (id -Gn failed), so root-equivalent group membership is unknown.");
  } else {
    const bad = groups.filter((g) => ROOT_EQUIVALENT_GROUPS.includes(g));
    if (bad.length) reasons.push(`Member of root-equivalent group(s): ${bad.join(", ")}.`);
  }
  if (doasRefused) reasons.push(...doasRuleReasons(probes, doasRefused, groups));
  return { ok: reasons.length === 0, reasons };
}

function listSome(items: readonly string[]): string {
  return `${items.slice(0, 3).join("; ")}${items.length > 3 ? ` (+${items.length - 3} more)` : ""}`;
}

/** Where doas reads its rules: OpenBSD and OpenDoas, then the BSD ports, MacPorts and Homebrew. */
export const DOAS_CONFIG_FILES = Object.freeze(["/etc/doas.conf", "/usr/local/etc/doas.conf", "/usr/pkg/etc/doas.conf", "/opt/local/etc/doas.conf", "/opt/homebrew/etc/doas.conf"]);
/** Alpine's doas also reads every *.conf file in this folder. */
export const DOAS_CONFIG_DIR = "/etc/doas.d";

export interface DoasRule {
  /** The line the rule starts on. */
  line: number;
  action: "permit" | "deny";
  /** nopass, nolog, persist, keepenv, setenv. */
  options: string[];
  /** A user name or uid, or ":" and a group name or gid. */
  identity: string;
  target?: string;
  cmd?: string;
  args?: string[];
  /** The rule as one line, for messages. */
  text: string;
}

export interface DoasConfig {
  rules: DoasRule[];
  /** The first part doas would refuse, or this parser cannot read. */
  error?: { line: number; message: string };
}

const DOAS_KEYWORDS = new Set(["deny", "permit", "as", "cmd", "args", "nopass", "nolog", "persist", "keepenv", "setenv"]);

type DoasToken = { kind: "word"; text: string; keyword: boolean; line: number } | { kind: "\n" | "{" | "}"; line: number };

/**
 * Split doas.conf into words the way doas does (doas.conf(5)): "#" starts a comment, double quotes
 * keep spaces, a backslash takes the next character as it is, and a backslash at the end of a line
 * joins the next line. A quoted or joined word is never a keyword.
 */
function doasTokens(text: string): { tokens: DoasToken[]; error?: { line: number; message: string } } {
  const tokens: DoasToken[] = [];
  let error: { line: number; message: string } | undefined;
  let line = 1;
  let i = 0;
  const fail = (message: string) => {
    error ??= { line, message };
  };
  while (i < text.length) {
    const c = text[i];
    if (c === " " || c === "\t") {
      i++;
      continue;
    }
    if (c === "\n" || c === "{" || c === "}") {
      tokens.push({ kind: c, line });
      if (c === "\n") line++;
      i++;
      continue;
    }
    if (c === "#") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    const start = line;
    let word = "";
    let quotes = false;
    let quoted = false;
    let escape = false;
    let joined = false;
    for (; i < text.length; i++) {
      const ch = text[i];
      if (ch === "\0") {
        fail("a NUL character");
        escape = false;
        continue;
      }
      if (ch === "\\" && !escape) {
        escape = true;
        continue;
      }
      if (ch === "\n") {
        if (quotes) fail("quotes not closed");
        if (escape) {
          escape = false;
          joined = true;
          line++;
          continue;
        }
        break;
      }
      if (!escape && !quotes && (ch === "{" || ch === "}" || ch === "#" || ch === " " || ch === "\t")) break;
      if (ch === '"' && !escape) {
        quotes = !quotes;
        quoted = true;
        continue;
      }
      word += ch;
      escape = false;
    }
    if (i >= text.length && escape) fail("a backslash at the end of the file");
    if (i >= text.length && quotes) fail("quotes not closed");
    if (word === "" && !quoted) continue; // a joined line with nothing on it
    tokens.push({ kind: "word", text: word, keyword: !quoted && !joined && DOAS_KEYWORDS.has(word), line: start });
  }
  return error ? { tokens, error } : { tokens };
}

/** A value as doas.conf would spell it: quoted when it has spaces or quotes, or is a keyword. */
function doasWord(w: string): string {
  return w === "" || /[\s"#{}\\]/.test(w) || DOAS_KEYWORDS.has(w) ? JSON.stringify(w) : w;
}

/** One rule: permit [options] identity [as target] [cmd command [args ...]], or deny identity [...]. */
function doasRule(t: DoasToken[]): DoasRule | { line: number; message: string } {
  let k = 0;
  const at = (w: string) => {
    const x = t[k];
    return x?.kind === "word" && x.keyword && x.text === w;
  };
  const str = (): string | null => {
    const x = t[k];
    if (x?.kind !== "word" || x.keyword) return null;
    k++;
    return x.text;
  };
  const bad = (message: string) => ({ line: t[Math.min(k, t.length - 1)].line, message });
  const action = at("permit") ? "permit" : at("deny") ? "deny" : null;
  if (!action) return bad("a rule starts with permit or deny");
  k++;
  const options: string[] = [];
  while (action === "permit") {
    const x = t[k];
    if (x?.kind !== "word" || !x.keyword) break;
    if (["nopass", "nolog", "persist", "keepenv"].includes(x.text)) {
      options.push(x.text);
      k++;
    } else if (x.text === "setenv") {
      k++;
      if (t[k]?.kind !== "{") return bad("setenv is followed by { }");
      k++;
      while (str() !== null);
      if (t[k]?.kind !== "}") return bad("setenv { is not closed");
      k++;
      options.push("setenv");
    } else break;
  }
  const identity = str();
  if (identity === null) return bad("no user or group");
  const rule: DoasRule = { line: t[0].line, action, options, identity, text: "" };
  if (at("as")) {
    k++;
    const target = str();
    if (target === null) return bad("as is followed by a user");
    rule.target = target;
  }
  if (at("cmd")) {
    k++;
    const cmd = str();
    if (cmd === null) return bad("cmd is followed by a command");
    rule.cmd = cmd;
    if (at("args")) {
      k++;
      const args: string[] = [];
      for (let a = str(); a !== null; a = str()) args.push(a);
      rule.args = args;
    }
  }
  if (k < t.length) {
    const x = t[k];
    return bad(`${x.kind === "word" ? `"${x.text}"` : x.kind} is not expected here`);
  }
  const parts = [action, ...options, doasWord(identity)];
  if (rule.target !== undefined) parts.push("as", doasWord(rule.target));
  if (rule.cmd !== undefined) parts.push("cmd", doasWord(rule.cmd));
  if (rule.args !== undefined) parts.push("args", ...rule.args.map(doasWord));
  rule.text = parts.join(" ");
  return rule;
}

/**
 * Parse doas.conf. doas refuses every command while its configuration has an error, but a rule
 * this parser cannot read is reported as an error too, so a caller treats any error as unknown.
 */
export function parseDoasConfig(text: string): DoasConfig {
  const { tokens, error } = doasTokens(text);
  const rules: DoasRule[] = [];
  let first = error;
  for (let i = 0; i < tokens.length; ) {
    const lineTokens: DoasToken[] = [];
    while (i < tokens.length && tokens[i].kind !== "\n") lineTokens.push(tokens[i++]);
    i++;
    if (!lineTokens.length) continue;
    const r = doasRule(lineTokens);
    if ("action" in r) rules.push(r);
    else if (!first || r.line < first.line) first = r;
  }
  return first ? { rules, error: first } : { rules };
}

/** A doas uid or gid: a name doas cannot look up is read as a number (strtonum). */
function doasNumber(s: string): number | null {
  return /^\s*[+-]?\d+$/.test(s) ? Number(s) : null;
}

/**
 * "doas -n true" fails when no rule lets this user run true without a password, but a "permit
 * nopass" rule for a single command (tee, an editor, a shell) still reaches root. doas cannot list a
 * user's rules, so read them: from every usual place, unless doas said it has no configuration. A
 * file this user cannot read, or text this parser cannot follow, fails closed. A later deny rule
 * does not clear a permit nopass rule here: remove the rule itself.
 */
function doasRuleReasons(probes: ProtectionProbes, refused: RunResult, groups: string[] | null): string[] {
  // "doas: doas is not enabled, /etc/doas.conf: No such file or directory": there are no rules at all.
  if (/\bdoas is not enabled\b/.test(refused.stderr)) return [];
  const reasons: string[] = [];
  const files = DOAS_CONFIG_FILES.filter((f) => probes.lstat(f) !== null);
  if (probes.lstat(DOAS_CONFIG_DIR) !== null) {
    const names = probes.listDir?.(DOAS_CONFIG_DIR) ?? null;
    if (names === null) reasons.push(`Cannot list ${DOAS_CONFIG_DIR}, so the doas rules in it cannot be checked.`);
    else {
      for (const name of [...names].sort()) {
        const path = posix.join(DOAS_CONFIG_DIR, name);
        if (name.endsWith(".conf") && !probes.lstat(path)?.isDirectory) files.push(path);
      }
    }
  }
  if (!files.length && !reasons.length) {
    return [`doas is set up, but its configuration is in none of ${[...DOAS_CONFIG_FILES, `${DOAS_CONFIG_DIR}/*.conf`].join(", ")}, so this user's doas rules cannot be checked.`];
  }
  const nopass: { file: string; rule: DoasRule }[] = [];
  for (const file of files) {
    const text = probes.readText?.(file) ?? null;
    if (text === null) {
      reasons.push(`Cannot read ${file}, so this user's doas rules cannot be checked: a "permit nopass" rule for one command reaches root. Make it readable (doas needs only that root owns it and nobody else can write it), or let only admins run doas.`);
      continue;
    }
    const conf = parseDoasConfig(text);
    if (conf.error) reasons.push(`Cannot read the doas rules in ${file}: line ${conf.error.line}, ${conf.error.message}.`);
    for (const rule of conf.rules) if (rule.action === "permit" && rule.options.includes("nopass")) nopass.push({ file, rule });
  }
  if (!nopass.length) return reasons;

  const un = probes.run("id", ["-un"]);
  const name = un.status === 0 && un.stdout.trim() ? un.stdout.trim() : null;
  const g = probes.run("id", ["-G"]);
  const gids = g.status === 0 ? parseGroupNames(g.stdout).map(Number).filter(Number.isSafeInteger) : null;
  const uid = probes.getuid();
  // true, false, or null when the id it would be compared with is unknown. A number is an id.
  const applies = (identity: string): boolean | null => {
    if (identity.startsWith(":")) {
      const group = identity.slice(1);
      const gid = doasNumber(group);
      if (groups?.includes(group) || (gid !== null && gids?.includes(gid))) return true;
      if (gid !== null) return gids ? false : null;
      return groups ? false : null;
    }
    const n = doasNumber(identity);
    if (identity === name || (n !== null && n === uid)) return true;
    if (n !== null) return uid === undefined ? null : false;
    return name === null ? null : false;
  };
  const show = ({ file, rule }: { file: string; rule: DoasRule }) => `${file}:${rule.line} "${rule.text}"`;
  const hits = nopass.filter((x) => applies(x.rule.identity) === true).map(show);
  const unsure = nopass.filter((x) => applies(x.rule.identity) === null).map(show);
  if (hits.length) reasons.push(`doas lets this user run commands without a password: ${listSome(hits)}.`);
  if (unsure.length) reasons.push(`Could not tell whether these doas rules without a password apply to this user ("id -un" or "id -G" failed): ${listSome(unsure)}.`);
  return reasons;
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

/** Win32 access rights that let a user write a file or add to a folder, delete either, or change its ACL or owner. */
export const WINDOWS_CHANGE_RIGHTS = Object.freeze({
  FILE_WRITE_DATA: 0x2,
  FILE_APPEND_DATA: 0x4,
  FILE_DELETE_CHILD: 0x40,
  DELETE: 0x10000,
  WRITE_DAC: 0x40000,
  WRITE_OWNER: 0x80000,
  GENERIC_ALL: 0x10000000,
  GENERIC_WRITE: 0x40000000,
});

const W = WINDOWS_CHANGE_RIGHTS;
/** Not on the policy file: writing it, deleting it, or changing its ACL or owner. */
const FILE_RIGHTS = W.FILE_WRITE_DATA | W.FILE_APPEND_DATA | W.DELETE | W.WRITE_DAC | W.WRITE_OWNER | W.GENERIC_ALL | W.GENERIC_WRITE;
/** Not on a folder from the policy's up to the policy root: adding a file, deleting what it holds or the folder, or changing its ACL or owner. */
const FOLDER_RIGHTS = W.FILE_WRITE_DATA | W.FILE_DELETE_CHILD | W.DELETE | W.WRITE_DAC | W.WRITE_OWNER | W.GENERIC_ALL | W.GENERIC_WRITE;
/** Above the policy root users may add files (ProgramData's own entries), but not delete, re-ACL or take over a folder. */
const UPPER_RIGHTS = W.FILE_DELETE_CHILD | W.DELETE | W.WRITE_DAC | W.WRITE_OWNER | W.GENERIC_ALL;

/** The names of the rights set in a mask; on a folder, FILE_WRITE_DATA is FILE_ADD_FILE. */
function rightNames(mask: number, folder: boolean): string[] {
  return Object.entries(WINDOWS_CHANGE_RIGHTS)
    .filter(([, bit]) => (mask & bit) !== 0)
    .map(([name]) => (folder && name === "FILE_WRITE_DATA" ? "FILE_ADD_FILE" : name));
}

export function windowsPart1(policyPath: string, probes: ProtectionProbes): ProtectionPart {
  const reasons: string[] = [];
  if (!probes.lstat(policyPath)) return { ok: false, reasons: [`No policy file at ${policyPath}.`] };
  if (probes.canOpenForWrite(policyPath)) reasons.push(`This user can open ${policyPath} for writing.`);
  // The policy root. Users may create files in NightSquawk above it (mcp-guard init gives it
  // ProgramData's own entries, for other software's folders); only its owner counts.
  const top = win32.join(programDataDir(probes.env), "NightSquawk", "mcp").toLowerCase();
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
  const inner = chain.length; // the file and the folders up to the policy root
  // Above that, up to the drive root, only owners and links are checked. Users may create files in
  // ProgramData and NightSquawk, but whoever owns a folder above the policy can replace everything below it.
  for (let parent = win32.dirname(dir); parent !== dir; parent = win32.dirname(parent)) {
    chain.push(parent);
    dir = parent;
  }
  // "Not writable right now" is not enough: an owner can always change the ACL back (attrib -R,
  // removing a self-added deny entry). Every link must be owned by SYSTEM, Administrators or
  // TrustedInstaller, and none may be a junction or symlink. Nor may an allow entry give this user
  // the right to change a link's ACL or owner or to delete it: with WRITE_DAC alone it can grant
  // itself write, change the policy and put the ACL back, and the owner never changes.
  if (probes.windowsOwners) {
    const owners = probes.windowsOwners(chain);
    if (!owners) reasons.push("Could not read the owners of the policy file and its folders.");
    else {
      for (const [i, p] of chain.entries()) {
        const info = owners.find((o) => o.path.toLowerCase() === p.toLowerCase());
        if (!info || !info.owner) reasons.push(`Could not read the owner of ${p}.`);
        else if (!TRUSTED_OWNER_SIDS.includes(info.owner)) reasons.push(`${p} is owned by ${info.owner}, not SYSTEM, Administrators or TrustedInstaller.`);
        if (info?.reparse) reasons.push(`${p} is a junction or symbolic link.`);
        if (!info?.owner) continue;
        const granted = typeof info.rights === "number" ? info.rights & (i === 0 ? FILE_RIGHTS : i < inner ? FOLDER_RIGHTS : UPPER_RIGHTS) : null;
        if (granted === null) reasons.push(`Could not read what this user may do to ${p}.`);
        else if (granted) reasons.push(`This user has ${rightNames(granted, i > 0).join(", ")} on ${p}, so it can change the policy or put another in its place.`);
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
