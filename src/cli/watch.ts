/**
 * `mcp-guard verify --watch` (section 7.12): has an agent client's MCP, hook or
 * permission config changed since the accepted baseline? One check per run,
 * meant for a timer: exit 0 when nothing changed, 1 when something did.
 *
 * The baseline holds a hash per key, never a value, and the report names files,
 * keys and counts only, so neither one holds a secret. The files it reads do
 * (MCP env blocks, API keys), so it never prints their content.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { canonicalJson, sha256Hex } from "../guard/canonical.js";
import { replaceFileSync } from "../guard/lock.js";
import { claudeDesktopConfig, clientPaths, codexHome } from "./clients.js";
import { pathLib, stateRoot } from "./context.js";
import { adminFileCommands } from "./harness.js";
import { CliError, confirmTyped, errnoCode, EXIT, needsAdmin, rootWarning, type CliIo, type Outcome } from "./io.js";
import { adminCommands, renderAdmin } from "./shell.js";

export const WATCH_VERSION = 1 as const;

/** How a file is read. settings: Claude settings keys. state: ~/.claude.json. mcp: mcpServers. hooks and all: every key. toml: sections. */
export type Kind = "settings" | "state" | "mcp" | "hooks" | "all" | "toml";
const KINDS: readonly Kind[] = ["settings", "state", "mcp", "hooks", "all", "toml"];

export interface Target {
  path: string;
  kind: Kind;
}

/** Per key, a hash of its value; a list holds one sorted hash per item, so a change can say how many were added or removed. */
export type Keys = Record<string, string | string[]>;

export interface FilePrint {
  kind: Kind;
  keys?: Keys;
  /** Set when the file is there but cannot be read or parsed. */
  error?: string;
  /** Of the raw text, for a file that does not parse. */
  sha256?: string;
}

export interface Baseline {
  mcp_guard_watch: typeof WATCH_VERSION;
  recorded_at: string;
  files: Record<string, FilePrint>;
}

export interface Change {
  file: string;
  change: "added" | "removed" | "changed";
  /** No key: the file itself. */
  key?: string;
  detail?: string;
}

export interface WatchArgs {
  projects?: string[];
  baseline?: string;
  accept?: boolean;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const own = <T>(o: Record<string, T>, k: string): T | undefined => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** Claude Code settings keys that change what an agent can run, reach, or skip asking about. */
export const SETTINGS_KEYS: readonly string[] = Object.freeze([
  "permissions",
  "hooks",
  "env",
  "sandbox",
  "mcpServers",
  "enabledMcpjsonServers",
  "disabledMcpjsonServers",
  "enableAllProjectMcpServers",
  "allowedMcpServers",
  "deniedMcpServers",
  "apiKeyHelper",
  "awsAuthRefresh",
  "awsCredentialExport",
  "otelHeadersHelper",
  "statusLine",
  "fileSuggestion",
  "enabledPlugins",
  "extraKnownMarketplaces",
  "strictKnownMarketplaces",
  "allowManagedHooksOnly",
  "allowManagedPermissionRulesOnly",
  "disableAllHooks",
  "managedSourcesBehavior",
  "forceLoginMethod",
  "forceLoginOrgUUID",
  "allowedHttpHookUrls",
  "httpHookAllowedEnvVars",
]);
/** Blocks reported per entry (one MCP server, one hook event, one variable) rather than as a whole. */
const SPLIT = new Set(["permissions", "hooks", "env", "sandbox", "mcpServers", "enabledPlugins", "extraKnownMarketplaces"]);
/** Per-project keys in ~/.claude.json. */
const PROJECT_KEYS = ["mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "enableAllProjectMcpServers", "allowedTools", "hasTrustDialogAccepted"];
/** Codex config that changes nothing an agent can run. */
const TOML_IGNORED_KEYS = new Set(["model", "model_reasoning_effort", "model_reasoning_summary", "model_verbosity"]);
const TOML_IGNORED_TABLES = ["tui", "notice"];

const hash = (v: unknown): string => sha256Hex(canonicalJson(v));
const entry = (v: unknown): string | string[] => (Array.isArray(v) ? v.map(hash).sort() : hash(v));
/** Unset, false, [] and {} all mean the default, so a new project entry full of defaults is not a change. */
const isDefault = (v: unknown) => v === null || v === false || (Array.isArray(v) && !v.length) || (isRecord(v) && !Object.keys(v).length);
const keyName = (parent: string, k: string) => (/^[A-Za-z0-9_-]+$/.test(k) ? `${parent}.${k}` : `${parent}[${JSON.stringify(k)}]`);

function put(keys: Keys, name: string, value: unknown, split: boolean): void {
  if (isDefault(value)) return;
  if (split && isRecord(value)) {
    for (const [k, v] of Object.entries(value)) if (!isDefault(v)) keys[keyName(name, k)] = entry(v);
  } else {
    keys[name] = entry(value);
  }
}

function jsonKeys(kind: Exclude<Kind, "toml">, doc: Record<string, unknown>): Keys {
  const keys: Keys = Object.create(null);
  if (kind === "settings") {
    for (const k of SETTINGS_KEYS) if (Object.prototype.hasOwnProperty.call(doc, k)) put(keys, k, doc[k], SPLIT.has(k));
  } else if (kind === "mcp") {
    put(keys, "mcpServers", doc.mcpServers, true);
  } else if (kind === "state") {
    put(keys, "mcpServers", doc.mcpServers, true);
    if (isRecord(doc.projects)) {
      for (const [dir, project] of Object.entries(doc.projects)) {
        if (!isRecord(project)) continue;
        for (const k of PROJECT_KEYS) if (Object.prototype.hasOwnProperty.call(project, k)) put(keys, `projects[${JSON.stringify(dir)}].${k}`, project[k], k === "mcpServers");
      }
    }
  } else {
    for (const [k, v] of Object.entries(doc)) put(keys, k, v, kind === "hooks" && k === "hooks");
  }
  return keys;
}

/**
 * Codex TOML, without a TOML parser: a hash per top-level key and per table.
 * Comment lines and blank lines do not count; any other edit to a table changes its hash.
 */
export function tomlKeys(text: string): Keys {
  const keys: Keys = Object.create(null);
  const top = new Map<string, string[]>();
  const tables = new Map<string, string[]>();
  let table: string | null = null;
  let key: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const header = /^\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$/.exec(line);
    if (header) {
      table = header[1]!;
      if (!tables.has(table)) tables.set(table, []);
      continue;
    }
    if (table !== null) {
      tables.get(table)!.push(line);
      continue;
    }
    const kv = /^([A-Za-z0-9_.-]+|"[^"]*"|'[^']*')\s*=/.exec(line);
    if (kv) {
      key = kv[1]!;
      top.set(key, [...(top.get(key) ?? []), line]);
    } else if (key !== null) {
      top.get(key)!.push(line); // a value that runs over several lines
    }
  }
  for (const [k, lines] of top) if (!TOML_IGNORED_KEYS.has(k)) keys[k] = hash(lines);
  for (const [t, lines] of tables) {
    if (TOML_IGNORED_TABLES.some((x) => t === x || t.startsWith(`${x}.`))) continue;
    keys[`[${t}]`] = hash(lines);
  }
  return keys;
}

function listJson(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isFile() && d.name.endsWith(".json") && !d.name.startsWith("."))
      .map((d) => d.name)
      .sort();
  } catch {
    return [];
  }
}

/** A Claude config folder in home: .claude, or a profile such as .claude-work. */
const PROFILE_DIR = /^\.claude(-[A-Za-z0-9_.-]+)?$/;

/** Every file the watch reads, for this user and machine, plus the working folder and each --project. */
export function watchTargets(io: CliIo, projects: readonly string[] = []): Target[] {
  const lib = pathLib(io.platform);
  const out = new Map<string, Kind>();
  const add = (path: string, kind: Kind) => void (out.has(path) || out.set(path, kind));
  const home = io.home;

  add(lib.join(home, ".claude.json"), "state");
  add(lib.join(home, ".mcp.json"), "mcp");
  const profiles = new Set<string>();
  try {
    for (const d of readdirSync(home, { withFileTypes: true })) if (d.isDirectory() && PROFILE_DIR.test(d.name)) profiles.add(lib.join(home, d.name));
  } catch {
    // no readable home: the other files still count
  }
  if (io.env.CLAUDE_CONFIG_DIR) profiles.add(lib.resolve(io.cwd, io.env.CLAUDE_CONFIG_DIR));
  for (const p of [...profiles].sort()) {
    add(lib.join(p, "settings.json"), "settings");
    add(lib.join(p, "settings.local.json"), "settings");
    add(lib.join(p, ".claude.json"), "state");
  }

  const machine = clientPaths(io);
  add(lib.join(machine.claudeManaged, "managed-settings.json"), "settings");
  const dropIns = lib.join(machine.claudeManaged, "managed-settings.d");
  for (const f of listJson(dropIns)) add(lib.join(dropIns, f), "settings");
  add(lib.join(machine.claudeManaged, "managed-mcp.json"), "mcp");

  const cursor = lib.join(home, ".cursor");
  add(lib.join(cursor, "mcp.json"), "mcp");
  add(lib.join(cursor, "hooks.json"), "hooks");
  add(lib.join(cursor, "permissions.json"), "all");
  add(lib.join(cursor, "cli-config.json"), "settings");
  add(machine.cursorHooks, "hooks");

  const codex = codexHome(io);
  add(lib.join(codex, "config.toml"), "toml");
  add(lib.join(codex, "hooks.json"), "hooks");
  add(lib.join(machine.codexAdmin, "requirements.toml"), "toml");
  add(lib.join(machine.codexAdmin, "managed_config.toml"), "toml");

  add(claudeDesktopConfig(io), "mcp");

  for (const dir of [io.cwd, ...projects.map((p) => lib.resolve(io.cwd, p))]) {
    add(lib.join(dir, ".mcp.json"), "mcp");
    add(lib.join(dir, ".claude", "settings.json"), "settings");
    add(lib.join(dir, ".claude", "settings.local.json"), "settings");
    add(lib.join(dir, ".cursor", "mcp.json"), "mcp");
    add(lib.join(dir, ".cursor", "hooks.json"), "hooks");
    add(lib.join(dir, ".cursor", "permissions.json"), "all");
    add(lib.join(dir, ".codex", "config.toml"), "toml");
    add(lib.join(dir, ".codex", "hooks.json"), "hooks");
  }
  return [...out].map(([path, kind]) => ({ path, kind }));
}

/** One file's fingerprint; null when it is not there. */
export function fingerprint(t: Target): FilePrint | null {
  let text: string;
  try {
    text = readFileSync(t.path, "utf8");
  } catch (e) {
    const code = errnoCode(e);
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    return { kind: t.kind, error: `unreadable (${code ?? "error"})` };
  }
  if (t.kind === "toml") return { kind: t.kind, keys: tomlKeys(text) };
  let doc: unknown;
  try {
    doc = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    return { kind: t.kind, error: "not valid JSON", sha256: sha256Hex(text) };
  }
  if (!isRecord(doc)) {
    const keys: Keys = Object.create(null);
    keys["(file)"] = hash(doc);
    return { kind: t.kind, keys };
  }
  return { kind: t.kind, keys: jsonKeys(t.kind, doc) };
}

export function snapshot(targets: readonly Target[]): Record<string, FilePrint> {
  const files: Record<string, FilePrint> = Object.create(null);
  for (const t of targets) {
    const p = fingerprint(t);
    if (p) files[t.path] = p;
  }
  return files;
}

function listDiff(before: readonly string[], after: readonly string[]): { added: number; removed: number } {
  const left = new Map<string, number>();
  for (const h of before) left.set(h, (left.get(h) ?? 0) + 1);
  let added = 0;
  for (const h of after) {
    const n = left.get(h) ?? 0;
    if (n > 0) left.set(h, n - 1);
    else added++;
  }
  let removed = 0;
  for (const n of left.values()) removed += n;
  return { added, removed };
}

const keyCount = (p: FilePrint) => p.error ?? plural(Object.keys(p.keys ?? {}).length, "key");

export function diffPrints(before: Record<string, FilePrint>, after: Record<string, FilePrint>): Change[] {
  const changes: Change[] = [];
  for (const file of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    const b = own(before, file);
    const a = own(after, file);
    if (!b && a) {
      changes.push({ file, change: "added", detail: keyCount(a) });
      continue;
    }
    if (b && !a) {
      changes.push({ file, change: "removed" });
      continue;
    }
    if (!a || !b) continue;
    if (a.error || b.error) {
      if (a.error !== b.error) changes.push({ file, change: "changed", detail: a.error ? `now ${a.error}` : `readable again (was ${b.error}), ${keyCount(a)}` });
      else if (a.sha256 !== b.sha256) changes.push({ file, change: "changed", detail: `still ${a.error}, and its content changed` });
      continue;
    }
    const bk = b.keys ?? {};
    const ak = a.keys ?? {};
    for (const key of [...new Set([...Object.keys(bk), ...Object.keys(ak)])].sort()) {
      const x = own(bk, key);
      const y = own(ak, key);
      if (x === undefined && y !== undefined) changes.push({ file, change: "added", key, ...(Array.isArray(y) ? { detail: plural(y.length, "item") } : {}) });
      else if (y === undefined) changes.push({ file, change: "removed", key });
      else if (Array.isArray(x) && Array.isArray(y)) {
        const d = listDiff(x, y);
        if (d.added || d.removed) changes.push({ file, change: "changed", key, detail: `${d.added} added, ${d.removed} removed` });
      } else if (canonicalJson(x) !== canonicalJson(y)) changes.push({ file, change: "changed", key });
    }
  }
  return changes;
}

export function parseBaseline(text: string): Baseline {
  const raw: unknown = JSON.parse(text);
  if (!isRecord(raw) || raw.mcp_guard_watch !== WATCH_VERSION || typeof raw.recorded_at !== "string" || !isRecord(raw.files)) {
    throw new Error("it is not an mcp-guard watch baseline");
  }
  const files: Record<string, FilePrint> = Object.create(null);
  const isHashes = (v: unknown) => typeof v === "string" || (Array.isArray(v) && v.every((x) => typeof x === "string"));
  for (const [path, p] of Object.entries(raw.files)) {
    const bad = () => new Error(`its entry for ${path} is malformed`);
    if (!isRecord(p) || !(KINDS as readonly unknown[]).includes(p.kind)) throw bad();
    const { kind, keys, error, sha256 } = p;
    if (keys !== undefined && !(isRecord(keys) && Object.values(keys).every(isHashes))) throw bad();
    if ((error !== undefined && typeof error !== "string") || (sha256 !== undefined && typeof sha256 !== "string")) throw bad();
    files[path] = {
      kind: kind as Kind,
      ...(keys ? { keys: Object.assign(Object.create(null), keys) as Keys } : {}),
      ...(typeof error === "string" ? { error } : {}),
      ...(typeof sha256 === "string" ? { sha256 } : {}),
    };
  }
  return { mcp_guard_watch: WATCH_VERSION, recorded_at: raw.recorded_at, files };
}

function renderChanges(changes: readonly Change[]): string[] {
  const out: string[] = [];
  let file: string | null = null;
  for (const c of changes) {
    if (c.file !== file) {
      file = c.file;
      out.push(`  ${file}`);
    }
    out.push(`    ${c.change.padEnd(7)}  ${c.key ?? "(the file)"}${c.detail ? `: ${c.detail}` : ""}`);
  }
  return out;
}

const REVIEW =
  "Look at each change yourself: these files hold secrets, so open them rather than pasting them anywhere. Then run mcp-guard verify --watch --accept to record the new state.";

function writeBaseline(io: CliIo, path: string, text: string): void {
  const lib = pathLib(io.platform);
  mkdirSync(lib.dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${io.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  replaceFileSync(tmp, path);
}

function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export async function watchCommand(args: WatchArgs, io: CliIo): Promise<Outcome> {
  const lib = pathLib(io.platform);
  const explicit = args.baseline !== undefined;
  const path = explicit ? lib.resolve(io.cwd, args.baseline!) : lib.join(stateRoot(io), "_watch", "baseline.json");
  const projects = args.projects ?? [];
  const warnings = projects.filter((p) => !isDir(lib.resolve(io.cwd, p))).map((p) => `--project ${p} is not a folder.`);
  const notes = [
    "The watch reads the config of Claude Code, Codex, Cursor and Claude Desktop for you and this machine, plus the project config in the folder it runs in and in each --project.",
    ...(explicit
      ? []
      : ["The baseline is in your own state folder, so anything running as you can rewrite it. Keep it where only an admin can write with --baseline <file>: the watch then prints the commands that update it."]),
  ];
  const current = snapshot(watchTargets(io, projects));
  const present = Object.keys(current);
  const fresh: Baseline = { mcp_guard_watch: WATCH_VERSION, recorded_at: io.clock().toISOString(), files: current };
  const base = { baseline: path, files: present, warnings, notes };

  const record = (changes: Change[], intro: string): Outcome => {
    const text = `${JSON.stringify(fresh, null, 2)}\n`;
    try {
      writeBaseline(io, path, text);
    } catch (e) {
      if (!explicit || !needsAdmin(e)) throw new CliError(`Cannot write the baseline ${path}: ${(e as Error).message}`);
      const admin = adminCommands(io.platform, adminFileCommands(io.platform, path, text));
      return {
        code: EXIT.admin,
        data: { ...base, changes, recorded: false, admin, warnings: [...rootWarning(io), ...warnings] },
        text: [intro, ...renderChanges(changes), ...rootWarning(io), "", ...renderAdmin(admin, `${path} is not yours to write. The commands below record the new baseline; read them first.`)],
      };
    }
    return {
      code: EXIT.ok,
      data: { ...base, changes, recorded: true, recorded_at: fresh.recorded_at },
      text: [intro, ...renderChanges(changes), `Recorded the baseline of ${plural(present.length, "file")} at ${path}.`, ...warnings.map((w) => `warning: ${w}`)],
    };
  };
  const drift = (changes: Change[], intro: string, extra: Record<string, unknown> = {}): Outcome => ({
    code: EXIT.fail,
    data: { ...base, changes, recorded: false, ...extra },
    text: [intro, ...renderChanges(changes), REVIEW, ...warnings.map((w) => `warning: ${w}`)],
  });

  let stored: string | null = null;
  try {
    stored = readFileSync(path, "utf8");
  } catch (e) {
    if (errnoCode(e) !== "ENOENT") throw new CliError(`Cannot read the baseline ${path}: ${(e as Error).message}`);
  }

  if (stored === null) {
    // The first run records a baseline. A default baseline whose folder is still there was removed by something.
    const removed = !explicit && existsSync(lib.dirname(path));
    if (!removed) return record([], `config watch: no baseline yet at ${path}; recording one.`);
    const intro = `config watch: the baseline ${path} is gone, but its folder is still there, so something removed it.`;
    if (!args.accept) return drift([], intro, { baseline_missing: true });
    await confirmTyped(io, `${intro}\nRecord the current config of ${plural(present.length, "file")} as the new baseline?`, "accept");
    return record([], intro);
  }

  let baseline: Baseline;
  try {
    baseline = parseBaseline(stored);
  } catch (e) {
    const intro = `config watch: the baseline ${path} does not load (${e instanceof SyntaxError ? "not valid JSON" : (e as Error).message}), so something changed it.`;
    if (!args.accept) return drift([], intro, { baseline_corrupt: true });
    await confirmTyped(io, `${intro}\nReplace it with the current config of ${plural(present.length, "file")}?`, "accept");
    return record([], intro);
  }

  const changes = diffPrints(baseline.files, current);
  if (!changes.length) {
    return {
      code: EXIT.ok,
      data: { ...base, changes, recorded: false, recorded_at: baseline.recorded_at },
      text: [
        `config watch: no changes since ${baseline.recorded_at} (${plural(present.length, "file")}, baseline ${path}).${args.accept ? " Nothing to accept." : ""}`,
        ...warnings.map((w) => `warning: ${w}`),
      ],
    };
  }
  const intro = `config watch: ${plural(changes.length, "change")} since ${baseline.recorded_at} (baseline ${path}):`;
  if (!args.accept) return drift(changes, intro, { recorded_at: baseline.recorded_at });
  await confirmTyped(io, `${intro}\n${renderChanges(changes).join("\n")}\nRecord these as the new baseline?`, "accept");
  return record(changes, intro);
}
