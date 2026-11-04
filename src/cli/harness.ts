/**
 * `mcp-guard harness <server> --claude|--codex|--cursor` (section 7.5): client
 * rules from the server's guard manifest. read runs without asking, change asks,
 * critical and spend are denied (--allow-critical and --allow-spend make them ask).
 *
 * These rules are a second fence, not the guard: the server refuses whatever its
 * policy does not allow, whatever the client decides. mcp-guard never writes
 * client config. It prints admin commands for the admin-owned files (exit 3) and
 * fragments for you to merge into your own files.
 *
 * Formats come from the clients' current docs (harness-formats research,
 * 2026-11-04). Where the docs are silent the output says so instead of guessing.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, sha256Hex } from "../guard/canonical.js";
import { hasUnsafePathChar, realProbes } from "../guard/protection.js";
import type { Group } from "../guard/tiers.js";
import { clientPaths, codexHome } from "./clients.js";
import { pathLib, requireServer, serverContext, stateRoot } from "./context.js";
import { policyFileCommands, SID } from "./init.js";
import { CliError, errnoCode, EXIT, rootWarning, type CliIo, type Outcome } from "./io.js";
import { checkManifest, locateManifest, readManifest } from "./manifest.js";
import {
  CLIENT_NAME,
  ruleFor,
  rulesFileName,
  rulesPath,
  RULES_VERSION,
  TAINT_SOURCE,
  TOOL_NAME,
  type HarnessRules,
  type OperationRule,
  type Rule,
  type RulesClient,
  type ToolRule,
} from "./rules.js";
import { taintDir } from "./taint.js";
import { adminCommands, psQuote, renderAdmin, shQuote, type AdminCommands } from "./shell.js";
import { table } from "./status.js";

export type HarnessClient = "claude" | "codex" | "cursor";
export const CLIENT_TITLE: Readonly<Record<HarnessClient, string>> = Object.freeze({ claude: "Claude Code", codex: "Codex", cursor: "Cursor" });

export interface HarnessArgs {
  server?: string;
  claude?: boolean;
  codex?: boolean;
  cursor?: boolean;
  /** The server's names in client config; default the server name. */
  names?: string[];
  allowCritical?: boolean;
  allowSpend?: boolean;
  /** Claude: also a PreToolUse hook that denies tools not in the manifest. */
  hook?: boolean;
  /** Claude --hook: no cross-server taint check (7.9). */
  noTaint?: boolean;
  /** Claude --hook: tools whose every result marks the session (WebFetch, mcp__<server>). */
  taintFrom?: string[];
  /** Claude: the operator sandbox profile (7.12). */
  sandbox?: boolean;
  /** Claude: JSON argv lists for the managed MCP allowlist (allowedMcpServers serverCommand entries). */
  mcpCommand?: string[];
  denyRead?: string[];
  denyWrite?: string[];
  allowDomain?: string[];
  /** Cursor: what the hook answers for servers without harness rules. */
  others?: string;
  /** The mcp-guard entry script hook commands run (default: this one). */
  hookScript?: string;
  manifest?: string;
  package?: string;
}

export interface HarnessFile {
  path: string;
  /** admin: the printed commands install it. user: it is yours to merge. */
  scope: "admin" | "user";
  /** write: the commands create or replace it. merge: add the content to the file you have. none: already up to date. written: mcp-guard wrote it (the NST_MCP_POLICY_DIR test override only). */
  install: "write" | "merge" | "none" | "written";
  format: "json" | "toml";
  purpose: string;
  content: string;
}

export interface ToolDecision {
  tool: string;
  group: Group;
  rule: Rule;
}

const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Admin commands that write one file outside the policy root (root-owned, 0644; Windows: Administrators own it, Users read). */
export function adminFileCommands(platform: NodeJS.Platform, file: string, text: string): string[] {
  if (platform === "win32") {
    return [
      `New-Item -ItemType Directory -Force -Path ${psQuote(win32.dirname(file))} | Out-Null`,
      `$content = @'\n${text}'@`,
      `[System.IO.File]::WriteAllText(${psQuote(file)}, $content)`,
      `icacls ${psQuote(file)} /setowner '${SID.administrators}' /C`,
      `icacls ${psQuote(file)} /inheritance:r /grant:r '${SID.system}:F' '${SID.administrators}:F' '${SID.users}:RX'`,
    ];
  }
  return [
    `sudo install -d -m 0755 -o 0 -g 0 ${shQuote(posix.dirname(file))}`,
    `sudo tee ${shQuote(file)} > /dev/null <<'EOF'\n${text}EOF`,
    `sudo chown 0:0 ${shQuote(file)}`,
    `sudo chmod 0644 ${shQuote(file)}`,
  ];
}

function underHome(io: CliIo, path: string): boolean {
  const lib = pathLib(io.platform);
  const norm = (p: string) => (io.platform === "win32" ? lib.resolve(p).toLowerCase() : lib.resolve(p));
  const home = norm(io.home);
  const p = norm(path);
  return p === home || p.startsWith(home.endsWith(lib.sep) ? home : home + lib.sep);
}

/** One command line for a hook that runs through a shell (Cursor). Plain words stay bare. */
export function commandLine(platform: NodeJS.Platform, words: string[]): string {
  return words
    .map((w) => {
      if (hasUnsafePathChar(w)) throw new CliError(`Refusing to write a hook command for ${JSON.stringify(w)}: it holds a control character or line separator.`);
      if (platform === "win32") {
        if (/["%]/.test(w)) throw new CliError(`Refusing to write a Windows hook command for ${JSON.stringify(w)}: it holds " or %.`);
        return /^[A-Za-z0-9_.:\\/-]+$/.test(w) ? w : `"${w}"`;
      }
      return /^[A-Za-z0-9_./:=@+-]+$/.test(w) ? w : shQuote(w);
    })
    .join(" ");
}

interface HookProgram {
  node: string;
  script: string;
  warnings: string[];
}

/**
 * Why someone other than root may be able to change a file the hook runs (POSIX),
 * or null. The file and every folder above it, as written and with links resolved,
 * must be root's and not writable by group or others. A link's own bits mean
 * nothing, so links are judged by their folder and their target; a root-owned
 * sticky folder (/tmp) is fine, since others cannot replace what is in it.
 */
export function posixWritableBy(io: CliIo, path: string): string | null {
  const probes = io.pathProbes ?? realProbes();
  if (!probes.lstat(path)) return null; // a missing file has its own warning
  let real: string;
  try {
    real = probes.realpath(path);
  } catch (e) {
    return `${path} cannot be resolved (${(e as Error).message})`;
  }
  for (const start of real === path ? [path] : [path, real]) {
    for (let p = start; ; p = posix.dirname(p)) {
      const s = probes.lstat(p);
      if (!s) return `${p} cannot be read`;
      if (!s.isSymbolicLink) {
        if (s.uid !== 0) return `${p} is owned by uid ${s.uid}, not root`;
        if (s.mode & 0o022 && !(s.isDirectory && s.mode & 0o1000)) return `${p} is writable by its group or others (mode ${(s.mode & 0o7777).toString(8)})`;
      }
      if (posix.dirname(p) === p) break;
    }
  }
  return null;
}

function hookProgram(io: CliIo, args: HarnessArgs): HookProgram {
  const lib = pathLib(io.platform);
  const script = args.hookScript ? lib.resolve(io.cwd, args.hookScript) : fileURLToPath(new URL("./index.js", import.meta.url));
  const warnings: string[] = [];
  if (!existsSync(script)) warnings.push(`${script} does not exist, so the hook fails and blocks every call to these servers until it does.`);
  const fix = "Install Node and mcp-guard where only an admin can write, then pass --hook-script <that dist/cli/index.js>.";
  for (const [what, p] of [["Node", io.execPath], ["mcp-guard", script]] as const) {
    if (underHome(io, p)) {
      warnings.push(`The hook runs ${what} from ${p}, under your home folder, so the agent's user can change what the hook does. ${fix}`);
      continue;
    }
    // Windows: only the home-folder check. Folders on other drives and under ProgramData often let every user write; HARDENING.md says what to check.
    const why = io.platform === "win32" ? null : posixWritableBy(io, p);
    if (why) warnings.push(`The hook runs ${what} from ${p}, but ${why}, so the agent's user may be able to change what the hook does. ${fix}`);
  }
  return { node: io.execPath, script, warnings };
}

/** The Cursor hooks.json entry, merged into the file that is there. */
export interface CursorHookEntry {
  command: string;
  timeout: number;
  failClosed: true;
}

export type MergeStatus = "new" | "added" | "replaced" | "present";

/**
 * Add the mcp-guard entry to a Cursor hooks.json. An entry that already runs
 * `hook cursor` (an older install, another script path) is replaced, so a stale
 * path cannot fail closed and block every call. Everything else is kept.
 */
export function mergeCursorHooks(existing: string | null, entry: CursorHookEntry, where = "hooks.json"): { status: MergeStatus; text: string } {
  if (existing === null || !existing.trim()) return { status: "new", text: json({ version: 1, hooks: { beforeMCPExecution: [entry] } }) };
  let doc: unknown;
  try {
    doc = JSON.parse(existing.charCodeAt(0) === 0xfeff ? existing.slice(1) : existing);
  } catch {
    throw new CliError(`${where} is not valid JSON. Fix it first: Cursor blocks permission hooks that answer with bad JSON, but it cannot read a broken file at all.`);
  }
  if (!isRecord(doc)) throw new CliError(`${where} is not a JSON object.`);
  if (doc.hooks !== undefined && !isRecord(doc.hooks)) throw new CliError(`${where}: hooks is not an object.`);
  const hooks = (doc.hooks ?? {}) as Record<string, unknown>;
  if (hooks.beforeMCPExecution !== undefined && !Array.isArray(hooks.beforeMCPExecution)) throw new CliError(`${where}: hooks.beforeMCPExecution is not a list.`);
  const list = [...((hooks.beforeMCPExecution as unknown[] | undefined) ?? [])];
  const ours = (e: unknown) => isRecord(e) && typeof e.command === "string" && (e.command === entry.command || /\shook cursor(\s|$)/.test(e.command));
  const at = list.findIndex(ours);
  let status: MergeStatus;
  if (at === -1) {
    list.push(entry);
    status = "added";
  } else {
    status = canonicalJson(list[at]) === canonicalJson(entry) && list.filter(ours).length === 1 ? "present" : "replaced";
    list[at] = entry;
    for (let i = list.length - 1; i > at; i--) if (ours(list[i])) list.splice(i, 1);
  }
  const out = { ...doc, version: doc.version ?? 1, hooks: { ...hooks, beforeMCPExecution: list } };
  return { status, text: json(out) };
}

// MCP configs can hold keys in their env blocks. A **/ pattern only matches under the folder
// Claude Code starts in, so the home-folder .mcp.json is listed by path as well.
const SANDBOX_DENY_READ = [
  "~/.ssh/**",
  "~/.claude.json",
  "~/.claude/.credentials.json",
  "~/.codex/auth.json",
  "~/.codex/config.toml",
  "~/.cursor/mcp.json",
  "~/.mcp.json",
  "**/.mcp.json",
  "**/.codex/config.toml",
  "**/.cursor/mcp.json",
  // Project files that load hooks, which run outside the sandbox. Claude Code carries **/ Read
  // patterns into the shell sandbox but not **/ Edit patterns, so only a Read rule keeps shell
  // commands from writing these.
  "**/.claude/settings.json",
  "**/.claude/settings.local.json",
  "**/.codex/hooks.json",
  "**/.cursor/hooks.json",
];
const SANDBOX_DENY_EDIT = [
  "~/.claude.json",
  "~/.claude/settings.json",
  "~/.claude/settings.local.json",
  "**/.claude/settings.json",
  "**/.claude/settings.local.json",
  "~/.mcp.json",
  "**/.mcp.json",
  "~/.codex/config.toml",
  "~/.codex/hooks.json",
  "**/.codex/config.toml",
  "**/.codex/hooks.json",
  "~/.cursor/mcp.json",
  "~/.cursor/hooks.json",
  "~/.cursor/permissions.json",
  "**/.cursor/mcp.json",
  "**/.cursor/hooks.json",
];

/** A path pattern in Claude's rule syntax: ~/ (home), // (absolute) or **\/ (any depth under the project). */
function rulePattern(p: string, option: string): string {
  if (hasUnsafePathChar(p) || /[()]/.test(p) || !/^(~\/|\/\/|\*\*\/)./.test(p)) {
    throw new CliError(`${option} ${JSON.stringify(p)}: write it as ~/path, //absolute/path or **/name (Claude's rule syntax; a single leading / means the settings folder, not the root). End a folder with /**.`, EXIT.usage);
  }
  return p;
}

/**
 * The sandbox lists get plain paths: ~/a/** becomes ~/a and //etc/x becomes /etc/x. Other
 * patterns stay in the rules only. Claude Code carries **\/ Read patterns into the shell sandbox
 * itself; **\/ Edit patterns reach its file tools only.
 */
function sandboxPath(p: string): string | null {
  if (p.startsWith("**/")) return null;
  let q = p.endsWith("/**") ? p.slice(0, -3) : p;
  if (q.startsWith("//")) q = q.slice(1);
  return /[*?[\]]/.test(q) ? null : q;
}

const dedupe = (xs: string[]) => [...new Set(xs)];

const MCP_COMMAND_EXAMPLE = `'["node","/opt/example-mcp/dist/index.js"]'`;

/** --mcp-command values: JSON argv lists, as the MCP config starts the server. Duplicates dropped. */
export function parseMcpCommands(raw: string[]): string[][] {
  const out = new Map<string, string[]>();
  for (const r of raw) {
    let v: unknown;
    try {
      v = JSON.parse(r);
    } catch {
      v = undefined;
    }
    const ok =
      Array.isArray(v) &&
      v.length >= 1 &&
      v.length <= 64 &&
      v.every((x) => typeof x === "string" && x.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(x)) &&
      (v[0] as string).trim() !== "";
    if (!ok) throw new CliError(`--mcp-command ${JSON.stringify(r)}: write the command and args as your MCP config gives them, as a JSON list of strings, such as ${MCP_COMMAND_EXAMPLE}.`, EXIT.usage);
    out.set(JSON.stringify(v), v as string[]);
  }
  return [...out.values()];
}

function mcpAllowNotes(commands: string[][]): { notes: string[]; warnings: string[] } {
  const notes = [
    `allowedMcpServers: Claude Code starts a stdio MCP server only when its command and args match ${commands.length === 1 ? "this entry" : `one of these ${commands.length} entries`} exactly, in order. Once any such entry exists, every stdio server needs one: run harness with --mcp-command for each server, or list the others in another managed-settings.d file (the lists combine).`,
    "Remote servers, plugin servers and claude.ai connectors are blocked as well unless a serverUrl entry admits them; built-in servers such as the IDE server are exempt, and so are servers defined in managed-mcp.json.",
    "The env block is not compared: the same command with other environment variables still matches, and some of them (NODE_OPTIONS, for one) load other code into the server. Only managed-mcp.json pins env.",
    "allowManagedMcpServersOnly: allowlists in user, project and local settings are ignored, for every user of this machine.",
  ];
  const warnings = commands
    .filter((c) => c.some((x) => x.includes("${")))
    .map((c) => `--mcp-command ${JSON.stringify(c)}: \${VAR} expands from the environment Claude Code starts with, so the entry can mean another path under another environment. Use literal paths for entries you rely on.`);
  return { notes, warnings };
}

/**
 * The guard's state folder as a rule pattern: the ledger, audit log, kill trips
 * and taint markers that the daily limits and the taint check count on. Null when
 * it cannot be written in rule syntax (Windows outside the home folder, or a path
 * with parentheses).
 */
export function stateRulePattern(io: CliIo): string | null {
  const lib = pathLib(io.platform);
  const root = lib.resolve(stateRoot(io));
  const rel = lib.relative(lib.resolve(io.home), root);
  let pattern: string | null = null;
  if (rel && !rel.startsWith("..") && !lib.isAbsolute(rel)) pattern = `~/${rel.split(lib.sep).join("/")}/**`;
  else if (io.platform !== "win32") pattern = `/${root}/**`;
  return pattern !== null && !hasUnsafePathChar(pattern) && !/[()]/.test(pattern) ? pattern : null;
}

function sandboxProfile(io: CliIo, args: HarnessArgs): { content: string; notes: string[] } {
  const reads = dedupe([...SANDBOX_DENY_READ, ...(args.denyRead ?? []).map((p) => rulePattern(p, "--deny-read"))]);
  const state = stateRulePattern(io);
  const edits = dedupe([...SANDBOX_DENY_EDIT, ...(state ? [state] : []), ...(args.denyWrite ?? []).map((p) => rulePattern(p, "--deny-write"))]);
  const domains = dedupe(args.allowDomain ?? []);
  for (const d of domains) if (!/^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(d)) throw new CliError(`--allow-domain ${JSON.stringify(d)} is not a domain name (a leading *. is allowed).`, EXIT.usage);
  const skipped = dedupe([...reads, ...edits].filter((p) => sandboxPath(p) === null));
  const anyDepthReads = skipped.filter((p) => p.startsWith("**/") && reads.includes(p));
  const anyDepthEdits = skipped.filter((p) => p.startsWith("**/") && !reads.includes(p));
  const wildcards = skipped.filter((p) => !p.startsWith("**/"));
  const profile = {
    permissions: {
      deny: [...reads.map((p) => `Read(${p})`), ...edits.map((p) => `Edit(${p})`)],
      disableBypassPermissionsMode: "disable",
    },
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
      filesystem: {
        denyRead: dedupe(reads.map(sandboxPath).filter((p): p is string => p !== null)),
        denyWrite: dedupe(edits.map(sandboxPath).filter((p): p is string => p !== null)),
      },
      network: { allowedDomains: domains, allowManagedDomainsOnly: true },
    },
  };
  const notes = [
    "Sandbox profile: the sandbox covers shell commands only. MCP servers and hooks run outside it, and the Read and Edit deny rules cover Claude's own file tools (Edit rules cover every tool that edits files).",
    domains.length
      ? `Shell commands can reach only ${domains.join(", ")}. Never add a provider's API host: a shell that can reach the provider can use a leaked key and go around the guard.`
      : "Shell commands get no network (an empty allowedDomains with allowManagedDomainsOnly). Add what your shell work needs with --allow-domain, never a provider's API host.",
    "disableBypassPermissionsMode turns bypassPermissions off for every user of this machine.",
    "mcp-guard does not write managed-mcp.json. It takes exclusive control of MCP for every user of this machine and holds each server's whole entry, env included, so it suits servers whose entry holds no secrets (a launcher that reads its key itself). It is the only way to pin env; --mcp-command pins the command and args.",
    state
      ? `The guard's state folder (${state}) is in the Edit and denyWrite lists: the daily limits count on its ledger and the taint check on its markers, and MCP servers and hooks still write it from outside the sandbox.`
      : `The guard's state folder (${stateRoot(io)}) cannot be written in rule syntax, so shell commands and Claude's file tools can still change its ledger and taint markers. Add it with --deny-write.`,
    "Add your own credential and install paths with --deny-read and --deny-write (folders end with /**).",
    "45-mcp-guard-sandbox.json is one file for the whole machine: a later harness --sandbox run for any server replaces it, so give every run the same --deny-read, --deny-write and --allow-domain options.",
    ...(anyDepthReads.length
      ? [
          `These **/ patterns match only under the folder Claude Code starts in. Claude Code applies them to shell commands too, checking before each command: a matching file can then be neither read nor written, but a file that the same command creates is not covered. The hook and settings files are on the list because a **/ Edit rule alone does not reach shell commands. Name files outside that folder by path (~/ or //) with --deny-read and --deny-write: ${anyDepthReads.join(", ")}.`,
        ]
      : []),
    ...(anyDepthEdits.length
      ? [
          `These **/ Edit patterns cover Claude's file tools only; shell commands can still write the files. Name the files by path (//...) with --deny-write, or pass the pattern to --deny-read as well, which keeps shell commands from reading or writing them: ${anyDepthEdits.join(", ")}.`,
        ]
      : []),
    ...(wildcards.length
      ? [
          `The sandbox lists hold plain paths, and only **/ Read patterns are known to reach shell commands, so these may cover Claude's file tools only. Use a folder ending in /** where you can: ${wildcards.join(", ")}.`,
        ]
      : []),
  ];
  return { content: json(profile), notes };
}

/** A TOML key: bare when it can be, else a basic string. */
const tomlKey = (k: string) => (/^[A-Za-z0-9_-]+$/.test(k) ? k : JSON.stringify(k));
const tomlList = (xs: string[]) => `[${xs.map((x) => JSON.stringify(x)).join(", ")}]`;

function codexToml(server: string, names: string[], decisions: ToolDecision[], info: { version: string; guard_version: string; sha256: string }): string {
  const enabled = decisions.filter((d) => d.rule !== "deny");
  const disabled = decisions.filter((d) => d.rule === "deny");
  const lines = [
    `# mcp-guard harness ${server}: manifest ${info.version}, guard ${info.guard_version}, sha256 ${info.sha256.slice(0, 16)}...`,
    "# Add these keys to your own [mcp_servers.<name>] table; keep its command, args and env.",
    '# approval_mode "approve" runs a tool without asking, even a destructive one, so only read tools get it. "prompt" asks every time.',
  ];
  for (const name of names) {
    lines.push("", `[mcp_servers.${tomlKey(name)}]`, 'default_tools_approval_mode = "prompt"', `enabled_tools = ${tomlList(enabled.map((d) => d.tool))}`);
    if (disabled.length) lines.push(`disabled_tools = ${tomlList(disabled.map((d) => d.tool))}`);
    for (const d of enabled) lines.push("", `[mcp_servers.${tomlKey(name)}.tools.${tomlKey(d.tool)}]`, `approval_mode = "${d.rule === "allow" ? "approve" : "prompt"}"`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Codex 0.166.0, tested: in the full-access sandbox (danger-full-access, which --yolo selects) MCP
 * tools that ask ran without asking, and with --approve-for-me Codex's automatic reviewer approved
 * them. Approval policy "never" refused them, so the floor leaves "never" alone: codex exec uses it.
 */
const CODEX_FLOOR = [
  "# Machine-wide, for every Codex user: rule out the full-access sandbox (and with it --yolo), where MCP",
  "# tools that ask run without asking, and Codex's automatic reviewer, which approves in a person's place.",
  'allowed_sandbox_modes = ["read-only", "workspace-write"]',
  'allowed_approvals_reviewers = ["user"]',
  "",
].join("\n");

interface Built {
  files: HarnessFile[];
  commands: string[];
  notes: string[];
  warnings: string[];
  /** Shown with the summary: how to check the installed hook. */
  test?: string[];
}

/** The cross-server taint check's data (7.9): every callable operation's flags, and the --taint-from tools. */
interface TaintPlan {
  operations: Record<string, OperationRule>;
  from: string[];
  untrusted: number;
  egress: number;
}

function rulesFile(
  io: CliIo,
  client: RulesClient,
  server: string,
  names: string[],
  decisions: ToolDecision[],
  info: HarnessRules["manifest"],
  taint?: TaintPlan
): { file: HarnessFile; commands: string[] } {
  const tools: Record<string, ToolRule> = Object.create(null); // a tool may be named __proto__
  for (const d of decisions) tools[d.tool] = { group: d.group, rule: d.rule };
  const rules = {
    mcp_guard_harness: RULES_VERSION,
    client,
    server,
    names,
    manifest: info,
    generated_at: io.clock().toISOString(),
    tools,
    ...(taint ? { operations: taint.operations, taint: { from: taint.from } } : {}),
  };
  const text = json(rules);
  const ctx = serverContext(server, io);
  const path = rulesPath(io, server, client);
  const file: HarnessFile = { path, scope: "admin", install: "write", format: "json", purpose: `what mcp-guard hook ${client} allows, asks or denies for ${server}`, content: text };
  if (ctx.override) {
    // Tests only, as with init: the override root is never protected, so writing it changes nothing an admin owns.
    mkdirSync(pathLib(io.platform).dirname(path), { recursive: true });
    writeFileSync(path, text, { mode: 0o644 });
    return { file: { ...file, install: "written", purpose: `${file.purpose} (NST_MCP_POLICY_DIR is set: written straight into the test policy folder)` }, commands: [] };
  }
  return { file, commands: policyFileCommands(io.platform, ctx.root, server, text, rulesFileName(client)) };
}

function buildClaude(io: CliIo, args: HarnessArgs, server: string, names: string[], decisions: ToolDecision[], info: HarnessRules["manifest"], taint?: TaintPlan): Built {
  const lib = pathLib(io.platform);
  const dir = lib.join(clientPaths(io).claudeManaged, "managed-settings.d");
  const rule = (r: Rule) => names.flatMap((n) => decisions.filter((d) => d.rule === r).map((d) => `mcp__${n}__${d.tool}`));
  const permissions: Record<string, string[]> = {};
  for (const r of ["allow", "ask", "deny"] as const) if (rule(r).length) permissions[r] = rule(r);
  const settings: Record<string, unknown> = { permissions };
  const built: Built = { files: [], commands: [], notes: [], warnings: [] };
  const mcpCommands = parseMcpCommands(args.mcpCommand ?? []);
  if (mcpCommands.length) {
    // In the server's own drop-in: allowedMcpServers lists from managed-settings.d files combine, so each server's run adds its own.
    settings.allowedMcpServers = mcpCommands.map((c) => ({ serverCommand: c }));
    settings.allowManagedMcpServersOnly = true;
  }
  if (args.hook) {
    const prog = hookProgram(io, args);
    built.warnings.push(...prog.warnings);
    const handler = { type: "command", command: prog.node, args: [prog.script, "hook", "claude", server], timeout: 10, onFailure: "block" };
    const hooks: Record<string, unknown> = { PreToolUse: [{ matcher: `^mcp__(?:${names.join("|")})__.*`, hooks: [handler] }] };
    // PostToolUse marks the session after outside text: this server's flagged results, and every --taint-from tool's.
    const marks = taint ? [...(taint.untrusted ? [`mcp__(?:${names.join("|")})__.*`] : []), ...taint.from.map((f) => (f.startsWith("mcp__") ? `${f}(?:__.*)?` : f))] : [];
    if (marks.length) hooks.PostToolUse = [{ matcher: `^(?:${marks.join("|")})$`, hooks: [handler] }];
    settings.hooks = hooks;
    const r = rulesFile(io, "claude", server, names, decisions, info, taint);
    built.files.push(r.file);
    built.commands.push(...r.commands);
    built.notes.push(
      `The hook denies ${names.map((n) => `mcp__${n}__*`).join(" and ")} tools that are not in this manifest, so a tool a server update adds is refused in every mode until you run harness again. It needs Claude Code v2.1.295 or later: older versions run the call when a hook fails.`
    );
    built.notes.push(...taintNotes(io, server, args, taint));
  } else {
    built.notes.push("A tool the server adds after this run has no rule, and in bypassPermissions mode it runs without asking. --hook denies tools that are not in the manifest.");
  }
  const dropIn = lib.join(dir, `50-mcp-guard-${server}.json`);
  const text = json(settings);
  built.files.unshift({ path: dropIn, scope: "admin", install: "write", format: "json", purpose: `permission rules for ${names.join(", ")}`, content: text });
  built.commands.unshift(...adminFileCommands(io.platform, dropIn, text));
  if (mcpCommands.length) {
    const allow = mcpAllowNotes(mcpCommands);
    built.notes.push(...allow.notes);
    built.warnings.push(...allow.warnings);
  }
  if (args.sandbox) {
    const profile = sandboxProfile(io, args);
    const path = lib.join(dir, "45-mcp-guard-sandbox.json");
    built.files.push({ path, scope: "admin", install: "write", format: "json", purpose: "the operator sandbox profile (every session on this machine)", content: profile.content });
    built.commands.push(...adminFileCommands(io.platform, path, profile.content));
    built.notes.push(...profile.notes);
  }
  built.notes.unshift(
    "deny rules block in every permission mode, and ask rules still prompt in bypassPermissions.",
    "Files in managed-settings.d merge with each other, but Claude Code ignores the file-based managed policy when policy also comes from the server (the admin console) or MDM, unless managedSourcesBehavior is \"merge\" (v2.1.242 or later)."
  );
  return built;
}

function taintNotes(io: CliIo, server: string, args: HarnessArgs, taint: TaintPlan | undefined): string[] {
  if (!taint) return ["--no-taint: no cross-server taint check. The server's own check (taint.egress_after_untrusted in its policy) still covers calls within one server."];
  const from = taint.from.length ? ` and every result of ${taint.from.join(", ")}` : "";
  const notes = [
    taint.untrusted || taint.from.length
      ? `Cross-server taint (7.9): after a result with text from outside parties (${taint.untrusted} ${server} operation${taint.untrusted === 1 ? "" : "s"}${from}), the PostToolUse hook marks the session in ${taintDir(io)}.`
      : `Cross-server taint (7.9): no ${server} operation returns outside text, so ${server} marks no session; other servers' hooks can.`,
    taint.egress
      ? `Once a session is marked, a call to ${server} that can send data out (${taint.egress} operation${taint.egress === 1 ? "" : "s"}) asks first, with the reason, or is denied when the ${server} policy sets taint.egress_after_untrusted to deny. A deny rule still wins.`
      : `No ${server} operation is flagged egress, so a marked session changes nothing for ${server} calls.`,
  ];
  if (!taint.from.length) notes.push("Results from tools that no harness covers (web fetches, mail, other MCP servers) mark nothing. Name them with --taint-from: WebFetch, WebSearch, or mcp__<server> for all of a server's tools.");
  if (!args.sandbox) notes.push("The markers are in your own state folder, so the agent's user can delete them. --sandbox puts the folder out of reach of shell commands and Claude's file tools.");
  return notes;
}

/** Every callable operation's flags from the manifest (blocked operations never run, so they are left out). */
function taintPlan(manifest: { operations?: unknown }, from: string[]): TaintPlan {
  const operations: Record<string, OperationRule> = Object.create(null); // an operation may be named __proto__
  let untrusted = 0;
  let egress = 0;
  const list = Array.isArray(manifest.operations) ? (manifest.operations as Array<{ operation: string; group: Group | null; tool: string | null; flags?: { untrusted_output?: boolean; egress?: boolean } }>) : [];
  for (const o of list) {
    if (o.group === null) continue;
    const rule: OperationRule = { tool: o.tool, group: o.group };
    if (o.flags?.untrusted_output) {
      rule.untrusted_output = true;
      untrusted++;
    }
    if (o.flags?.egress) {
      rule.egress = true;
      egress++;
    }
    operations[o.operation] = rule;
  }
  return { operations, from, untrusted, egress };
}

function buildCodex(io: CliIo, server: string, names: string[], decisions: ToolDecision[], info: HarnessRules["manifest"]): Built {
  const lib = pathLib(io.platform);
  const config = lib.join(codexHome(io), "config.toml");
  const requirements = lib.join(clientPaths(io).codexAdmin, "requirements.toml");
  return {
    files: [
      { path: config, scope: "user", install: "merge", format: "toml", purpose: `tool approval for ${names.join(", ")}`, content: codexToml(server, names, decisions, info) },
      { path: requirements, scope: "admin", install: "merge", format: "toml", purpose: "recommended machine-wide floor (an admin merges it)", content: CODEX_FLOOR },
    ],
    commands: [],
    warnings: [],
    notes: [
      "enabled_tools lists every tool this run allows or asks for, so a tool the server adds later stays hidden until you run harness again. disabled_tools removes the denied groups' tools.",
      "config.toml is yours, so the agent's user can change it too. The admin's part is requirements.toml: it rules out the full-access sandbox, --yolo and the automatic reviewer for everyone.",
      "Tested with Codex 0.166.0 (codex exec): a \"prompt\" tool is refused when no one can answer, and runs without asking in the full-access sandbox or with --approve-for-me. disabled_tools held in every mode: the tools were gone, and calls by name failed.",
      "The floor is UNVERIFIED until an admin installs it: then codex exec -s danger-full-access and --approve-for-me should be refused. allowed_approvals_reviewers is in the 0.166.0 binary's requirements keys, but no Codex doc describes it yet.",
      "A [mcp_servers] table in requirements.toml is an allowlist: once it has one, Codex runs only the servers listed there. mcp-guard does not write it.",
      "Codex hooks cannot ask, and its docs call them \"not a complete enforcement boundary\", so mcp-guard does not generate one.",
    ],
  };
}

function buildCursor(io: CliIo, args: HarnessArgs, server: string, names: string[], decisions: ToolDecision[], info: HarnessRules["manifest"]): Built {
  const lib = pathLib(io.platform);
  const others = args.others ?? "ask";
  const prog = hookProgram(io, args);
  const words = [prog.node, prog.script, "hook", "cursor", ...(others === "allow" ? ["--others", "allow"] : [])];
  const entry: CursorHookEntry = { command: commandLine(io.platform, words), timeout: 10, failClosed: true };
  const target = clientPaths(io).cursorHooks;
  const built: Built = { files: [], commands: [], notes: [], warnings: [...prog.warnings] };

  const r = rulesFile(io, "cursor", server, names, decisions, info);
  built.files.push(r.file);
  built.commands.push(...r.commands);

  let existing: string | null = null;
  let unreadable: string | null = null;
  try {
    existing = readFileSync(target, "utf8");
  } catch (e) {
    if (errnoCode(e) !== "ENOENT") unreadable = (e as Error).message;
  }
  if (unreadable !== null) {
    built.files.push({ path: target, scope: "admin", install: "merge", format: "json", purpose: `add this entry to hooks.beforeMCPExecution (mcp-guard cannot read the file: ${unreadable})`, content: json(entry) });
  } else {
    const merged = mergeCursorHooks(existing, entry, target);
    const purpose =
      merged.status === "new"
        ? "the hook that blocks denied tools"
        : merged.status === "present"
          ? "already has the mcp-guard hook"
          : `the file as it is now, with the mcp-guard hook ${merged.status === "added" ? "added" : "updated"}`;
    built.files.push({ path: target, scope: "admin", install: merged.status === "present" ? "none" : "write", format: "json", purpose, content: merged.text });
    if (merged.status !== "present") built.commands.push(...adminFileCommands(io.platform, target, merged.text));
  }

  const reads = names.flatMap((n) => decisions.filter((d) => d.rule === "allow").map((d) => `${n}:${d.tool}`));
  if (reads.length) {
    built.files.push({
      path: lib.join(io.home, ".cursor", "permissions.json"),
      scope: "user",
      install: "merge",
      format: "json",
      purpose: "lets read tools run without asking (add these to your mcpAllowlist)",
      content: json({ mcpAllowlist: reads }),
    });
  }
  const sample = JSON.stringify({ mcp_server_name: names[0], tool_name: decisions.find((d) => d.rule === "deny")?.tool ?? decisions[0]?.tool ?? "x", tool_input: "{}" });
  built.test = io.platform === "win32" ? [`'${sample}' | & ${entry.command}`] : [`printf '%s' ${shQuote(sample)} | ${entry.command}`];
  built.notes.push(
    "The hook is the only control that blocks a Cursor tool call: permissions.json can only let tools run without asking.",
    `One hook entry covers every server with harness rules. For a server without rules the hook answers ${others}${others === "ask" ? " (--others allow keeps them as they were, if Cursor treats a hook's allow as neutral: its docs do not say, UNVERIFIED)" : ""}.`,
    "failClosed makes a crash, a timeout or no answer block the call. A tool the server adds after this run is denied until you run harness again.",
    "Cursor's docs do not say which shell runs the hook command (UNVERIFIED). Check it once installed with the test command below: it should print a deny.",
    "Cursor CLI rules (cli-config.json) are not generated: their location is not documented.",
    "The cross-server taint check (7.9) is Claude-only for now. The server's own check (taint.egress_after_untrusted) still covers calls within one server."
  );
  return built;
}

export function harnessCommand(args: HarnessArgs, io: CliIo): Outcome {
  const server = requireServer(args.server, "harness");
  const chosen = (["claude", "codex", "cursor"] as const).filter((c) => args[c]);
  if (chosen.length !== 1) throw new CliError("Pick one client: --claude, --codex or --cursor.", EXIT.usage);
  const client = chosen[0]!;
  if (args.hook && client !== "claude") throw new CliError("--hook is for --claude (Cursor always gets a hook; Codex gets none).", EXIT.usage);
  if (args.sandbox && client !== "claude") throw new CliError("--sandbox is for --claude.", EXIT.usage);
  if (args.mcpCommand?.length && client !== "claude") throw new CliError("--mcp-command is for --claude.", EXIT.usage);
  if ((args.denyRead?.length || args.denyWrite?.length || args.allowDomain?.length) && !args.sandbox) throw new CliError("--deny-read, --deny-write and --allow-domain go with --sandbox.", EXIT.usage);
  if (args.others !== undefined && client !== "cursor") throw new CliError("--others is for --cursor.", EXIT.usage);
  if (args.others !== undefined && args.others !== "ask" && args.others !== "allow") throw new CliError("--others is ask or allow.", EXIT.usage);
  if (args.hookScript && !(client === "cursor" || args.hook)) throw new CliError("--hook-script goes with --cursor or --claude --hook.", EXIT.usage);
  const taintFrom = dedupe(args.taintFrom ?? []);
  if ((args.noTaint || taintFrom.length) && !(client === "claude" && args.hook)) {
    throw new CliError("--no-taint and --taint-from go with --claude --hook: the cross-server taint check is Claude-only for now.", EXIT.usage);
  }
  if (args.noTaint && taintFrom.length) throw new CliError("--taint-from turns the taint check on, --no-taint off: pick one.", EXIT.usage);
  for (const f of taintFrom) {
    if (!TAINT_SOURCE.test(f)) {
      throw new CliError(`--taint-from ${JSON.stringify(f)}: write mcp__<server> for all of a server's tools, mcp__<server>__<tool> for one, or a built-in tool name such as WebFetch.`, EXIT.usage);
    }
  }

  const names = dedupe(args.names?.length ? args.names : [server]);
  for (const n of names) {
    if (!CLIENT_NAME.test(n)) throw new CliError(`--name ${JSON.stringify(n)}: letters, digits, _ or -, starting with a letter or digit, at most 64 characters.`, EXIT.usage);
  }

  const loc = locateManifest(io, args);
  const raw = readManifest({ ...loc, explicit: true });
  const report = checkManifest(raw);
  if (!report.ok) {
    throw new CliError(`${loc.path} fails the manifest check, so mcp-guard will not write rules from it (mcp-guard manifest shows why).`, EXIT.fail, { issues: report.issues });
  }
  if (report.server !== server) throw new CliError(`${loc.path} is for ${report.server}, not ${server}.`);
  const manifest = raw as { version: string; guard_version: string; tools: Array<{ name: string; group: Group }>; operations?: unknown };
  for (const t of manifest.tools) if (!TOOL_NAME.test(t.name)) throw new CliError(`Tool ${JSON.stringify(t.name)} cannot go into client rules: tool names are 1-128 of A-Z, a-z, 0-9, _, - and .`);
  const decisions: ToolDecision[] = manifest.tools.map((t) => ({ tool: t.name, group: t.group, rule: ruleFor(t.group, args) }));
  if (!decisions.length) throw new CliError(`${loc.path} lists no tools.`);
  const info = { version: manifest.version, guard_version: manifest.guard_version, sha256: sha256Hex(canonicalJson(raw)) };

  const taint = client === "claude" && args.hook && !args.noTaint ? taintPlan(manifest, taintFrom) : undefined;
  const built =
    client === "claude"
      ? buildClaude(io, args, server, names, decisions, info, taint)
      : client === "codex"
        ? buildCodex(io, server, names, decisions, info)
        : buildCursor(io, args, server, names, decisions, info);
  const warnings = [...rootWarning(io), ...built.warnings, ...report.issues.map((i) => `manifest ${i.where}: ${i.message}`)];
  if (names.length === 1 && names[0] === server && !args.names?.length) {
    built.notes.push(`Rules use the server's name in your MCP config. They assume it is ${server}; pass --name when it is not.`);
  }
  built.notes.push(`Run harness again whenever the server adds, renames or regroups tools (manifest ${info.version}).`);

  // Two files in one folder: create the folder once.
  const dirs = new Set<string>();
  const commands = built.commands.filter((c) => !/^(sudo install -d |New-Item -ItemType Directory )/.test(c) || (!dirs.has(c) && Boolean(dirs.add(c))));
  const admin: AdminCommands | null = commands.length ? adminCommands(io.platform, commands) : null;
  const lib = pathLib(io.platform);
  const rows: string[][] = [["tool", "group", "rule"], ...decisions.map((d) => [d.tool, d.group, d.rule])];
  const text: string[] = [
    `${server}: ${CLIENT_TITLE[client]} rules from ${loc.path} (${server} ${info.version}, guard ${info.guard_version})`,
    ...table(rows).map((l) => `  ${l}`),
    ...(decisions.some((d) => d.group === "critical" && d.rule === "deny") ? ["  (--allow-critical makes critical ask)"] : []),
    ...(decisions.some((d) => d.group === "spend" && d.rule === "deny") ? ["  (--allow-spend makes spend ask)"] : []),
    "",
    "files:",
    ...built.files.map((f) => `  ${f.scope.padEnd(5)}  ${f.install.padEnd(7)}  ${f.path}: ${f.purpose}`),
    ...(warnings.length ? ["", "warnings:", ...warnings.map((w) => `  - ${w}`)] : []),
  ];
  for (const f of built.files.filter((x) => x.install === "merge")) {
    text.push("", `${f.scope === "user" ? "Merge into your" : "An admin merges into"} ${f.path}${f.scope === "user" && lib.basename(f.path) === "permissions.json" ? " (keep what is there)" : ""}:`, "", ...f.content.trimEnd().split("\n"));
  }
  if (admin) text.push("", ...renderAdmin(admin, `mcp-guard does not write these files itself. Read the commands first: they install what is shown above.`));
  if (built.test) text.push("Once installed, this should print a deny:", ...built.test, "");
  if (text[text.length - 1] !== "") text.push("");
  text.push("notes:", ...built.notes.map((n) => `  - ${n}`));

  return {
    code: admin ? EXIT.admin : EXIT.ok,
    data: {
      server,
      client,
      names,
      manifest: { path: loc.path, ...info },
      tools: decisions,
      files: built.files,
      ...(admin ? { admin } : {}),
      ...(built.test ? { test: built.test } : {}),
      warnings,
      notes: built.notes,
    },
    text,
  };
}
