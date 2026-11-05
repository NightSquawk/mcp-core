/**
 * The harness rules files, `<policy root>/<server>/harness-<client>.json`: what
 * each of a server's tools gets in that client (allow, ask or deny), written by
 * `mcp-guard harness` and read by `mcp-guard hook` on every call. They live in
 * the admin-owned policy folder, next to policy.json, so the agent's user cannot
 * loosen them. One file per client, so a Cursor run cannot change what the
 * Claude hook does (names and opt-ins may differ between clients).
 *
 * Claude's file can also carry every operation's flags and the taint sources,
 * for the cross-server taint check (section 7.9).
 */
import { readFileSync } from "node:fs";
import { hasUnsafePathChar } from "../guard/protection.js";
import { isGroup, type Group } from "../guard/tiers.js";
import { pathLib, serverContext } from "./context.js";
import { errnoCode, type CliIo } from "./io.js";

export const RULES_VERSION = 1 as const;

/** The clients whose hooks read rules files. Codex gets no hook. */
export type RulesClient = "claude" | "cursor";
export const rulesFileName = (client: RulesClient): string => `harness-${client}.json`;

export type Rule = "allow" | "ask" | "deny";
export const RULES: readonly Rule[] = Object.freeze(["allow", "ask", "deny"]);

export interface ToolRule {
  group: Group;
  rule: Rule;
}

/** One manifest operation, as the taint check needs it. tool is null on servers with hand-written tools. */
export interface OperationRule {
  tool: string | null;
  group: Group;
  untrusted_output?: true;
  egress?: true;
}

export interface TaintRules {
  /** Tools whose every result marks the session: a built-in tool (WebFetch), or mcp__<server>[__<tool>] as in Claude's permission rules. */
  from: string[];
}

export interface HarnessRules {
  mcp_guard_harness: typeof RULES_VERSION;
  client: RulesClient;
  server: string;
  /** The server's names in client config (the key in .mcp.json, mcp.json or config.toml). */
  names: string[];
  manifest: { version: string; guard_version: string; sha256: string };
  tools: Record<string, ToolRule>;
  /** Every callable operation in the manifest, by catalog id. With taint only. */
  operations?: Record<string, OperationRule>;
  /** The cross-server taint check is on (section 7.9). */
  taint?: TaintRules;
}

export interface RuleOptions {
  allowCritical?: boolean;
  allowSpend?: boolean;
}

/** Section 4: read runs without asking, change asks, critical and spend are denied unless opted in to ask. */
export function ruleFor(group: Group, opts: RuleOptions = {}): Rule {
  if (group === "read") return "allow";
  if (group === "change") return "ask";
  if (group === "critical") return opts.allowCritical ? "ask" : "deny";
  return opts.allowSpend ? "ask" : "deny";
}

/** A server's name in client config. Clients build tool names from it (mcp__<name>__<tool>), so keep it plain. */
export const CLIENT_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
/** MCP tool names (spec: 1-128 of A-Z a-z 0-9 _ - .). */
export const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
/** A taint source: mcp__<server>, mcp__<server>__<tool>, or a built-in tool name (they start with a capital). */
export const TAINT_SOURCE = /^(?:mcp__[A-Za-z0-9_-]{1,190}|[A-Z][A-Za-z0-9]{0,63})$/;

/** A taint source covers a tool by its exact name, or (mcp__ sources) every tool under it, as Claude's permission rules do. */
export function taintSourceCovers(source: string, toolName: string): boolean {
  return toolName === source || (source.startsWith("mcp__") && toolName.startsWith(`${source}__`));
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function rulesPath(io: CliIo, server: string, client: RulesClient): string {
  return pathLib(io.platform).join(pathLib(io.platform).dirname(serverContext(server, io).standardPolicyPath), rulesFileName(client));
}

const OPERATION_KEYS = new Set(["tool", "group", "untrusted_output", "egress"]);

function parseOperations(raw: unknown, bad: (what: string) => Error): Record<string, OperationRule> {
  if (!isRecord(raw)) throw bad("operations must be an object");
  const out: Record<string, OperationRule> = Object.create(null); // an operation may be named __proto__
  for (const [id, entry] of Object.entries(raw)) {
    if (!id || id.length > 200 || hasUnsafePathChar(id)) throw bad(`${JSON.stringify(id)} is not an operation id`);
    if (!isRecord(entry) || !isGroup(entry.group) || !(entry.tool === null || (typeof entry.tool === "string" && TOOL_NAME.test(entry.tool)))) {
      throw bad(`operations.${id} needs a group and a tool (a tool name, or null)`);
    }
    const unknown = Object.keys(entry).filter((k) => !OPERATION_KEYS.has(k));
    if (unknown.length) throw bad(`operations.${id}: unknown keys ${unknown.join(", ")}`);
    const rule: OperationRule = { tool: entry.tool, group: entry.group };
    for (const flag of ["untrusted_output", "egress"] as const) {
      if (entry[flag] === undefined) continue;
      if (entry[flag] !== true) throw bad(`operations.${id}.${flag} is true or left out`);
      rule[flag] = true;
    }
    out[id] = rule;
  }
  return out;
}

/** Checks a parsed rules file. Throws an Error that says what is wrong. */
export function parseRules(raw: unknown, server: string, client: RulesClient): HarnessRules {
  const bad = (what: string): Error => new Error(`${rulesFileName(client)} for ${server}: ${what}`);
  if (!isRecord(raw)) throw bad("not a JSON object");
  if (raw.mcp_guard_harness !== RULES_VERSION) throw bad(`mcp_guard_harness must be ${RULES_VERSION}`);
  if (raw.client !== client) throw bad(`it is for client ${JSON.stringify(raw.client)}`);
  if (raw.server !== server) throw bad(`it is for ${JSON.stringify(raw.server)}`);
  const names: unknown = raw.names;
  if (!Array.isArray(names) || !names.length || !names.every((n): n is string => typeof n === "string" && CLIENT_NAME.test(n))) {
    throw bad("names must be a list of client server names");
  }
  const m = raw.manifest;
  if (!isRecord(m) || typeof m.version !== "string" || typeof m.guard_version !== "string" || typeof m.sha256 !== "string") {
    throw bad("manifest must say version, guard_version and sha256");
  }
  if (!isRecord(raw.tools)) throw bad("tools must be an object");
  const tools: Record<string, ToolRule> = Object.create(null);
  for (const [name, entry] of Object.entries(raw.tools)) {
    if (!TOOL_NAME.test(name)) throw bad(`${JSON.stringify(name)} is not a tool name`);
    if (!isRecord(entry) || !isGroup(entry.group) || !(RULES as readonly unknown[]).includes(entry.rule)) throw bad(`tools.${name} needs a group and a rule (allow, ask or deny)`);
    tools[name] = { group: entry.group, rule: entry.rule as Rule };
  }
  const operations = raw.operations === undefined ? undefined : parseOperations(raw.operations, bad);
  let taint: TaintRules | undefined;
  if (raw.taint !== undefined) {
    const t = raw.taint;
    if (!isRecord(t) || Object.keys(t).some((k) => k !== "from") || !Array.isArray(t.from) || !t.from.every((x): x is string => typeof x === "string" && TAINT_SOURCE.test(x))) {
      throw bad("taint must be { from: [tool names] }");
    }
    if (!operations) throw bad("taint needs operations");
    taint = { from: [...new Set(t.from)] };
  }
  const known = new Set(Object.keys(raw));
  for (const k of ["mcp_guard_harness", "client", "server", "names", "manifest", "tools", "operations", "taint", "generated_at"]) known.delete(k);
  if (known.size) throw bad(`unknown keys ${[...known].join(", ")}`);
  return {
    mcp_guard_harness: RULES_VERSION,
    client,
    server,
    names: [...new Set(names as string[])],
    manifest: { version: m.version, guard_version: m.guard_version, sha256: m.sha256 },
    tools,
    ...(operations ? { operations } : {}),
    ...(taint ? { taint } : {}),
  };
}

export type LoadedRules = { ok: true; path: string; rules: HarnessRules } | { ok: false; path: string; missing: boolean; error: string };

export function loadRules(io: CliIo, server: string, client: RulesClient): LoadedRules {
  const path = rulesPath(io, server, client);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    const missing = errnoCode(e) === "ENOENT";
    return { ok: false, path, missing, error: missing ? `no ${rulesFileName(client)} at ${path}` : `cannot read ${path}: ${(e as Error).message}` };
  }
  try {
    const raw: unknown = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    return { ok: true, path, rules: parseRules(raw, server, client) };
  } catch (e) {
    return { ok: false, path, missing: false, error: e instanceof SyntaxError ? `${path} is not valid JSON` : (e as Error).message };
  }
}

/** The tool a rule covers, by its own key only (a tool named __proto__ or constructor is not a prototype member). */
export function toolRule(rules: HarnessRules, tool: string): ToolRule | undefined {
  return Object.prototype.hasOwnProperty.call(rules.tools, tool) ? rules.tools[tool] : undefined;
}

export function operationRule(rules: HarnessRules, id: string): OperationRule | undefined {
  return rules.operations && Object.prototype.hasOwnProperty.call(rules.operations, id) ? rules.operations[id] : undefined;
}
