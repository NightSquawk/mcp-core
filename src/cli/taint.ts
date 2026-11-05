/**
 * The cross-server taint check (section 7.9). One server cannot see what another
 * returned, so the Claude hook keeps a marker per session: after a result that
 * carries text from outside parties, PostToolUse marks the session; before a call
 * that can send data out, PreToolUse sees the mark and asks (or denies, when the
 * server's policy says so).
 *
 * The marker is `<state root>/_taint/<session id>.json`, in the user's own state
 * folder. Outside the sandbox profile the agent's user can delete it, so there it
 * is a speed bump. The guard's own check inside one server does not depend on it.
 */
import { closeSync, mkdirSync, openSync, readdirSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { pathLib, stateRoot } from "./context.js";
import { errnoCode, type CliIo } from "./io.js";
import { operationRule, toolRule, type HarnessRules } from "./rules.js";

export const TAINT_DIR = "_taint";
/** Claude's session ids are UUIDs; anything else cannot name a file safely. */
export const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;
/** Markers older than this are removed when a new one is written. */
export const MARKER_MAX_AGE_MS = 7 * 86_400_000;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** The first result that marked the session. tool is the client's full tool name. */
export interface TaintFirst {
  server: string | null;
  tool: string;
  operation: string | null;
  /** untrusted_output: the manifest flags the operation. label: the result carries the guard's untrusted label. source: a --taint-from tool, or rules that did not load. */
  why: "untrusted_output" | "label" | "source";
  at: string;
}

export type TaintState = { state: "clean" } | { state: "marked"; first: TaintFirst | null } | { state: "unknown"; why: string };

export function taintDir(io: CliIo): string {
  return pathLib(io.platform).join(stateRoot(io), TAINT_DIR);
}

function parseFirst(v: unknown): TaintFirst | null {
  if (!isRecord(v) || typeof v.tool !== "string" || typeof v.at !== "string") return null;
  const why = v.why === "untrusted_output" || v.why === "label" || v.why === "source" ? v.why : "source";
  return { server: typeof v.server === "string" ? v.server : null, tool: v.tool, operation: typeof v.operation === "string" ? v.operation : null, why, at: v.at };
}

/** Whether the session is marked. Anything but a clean "no marker" is unknown or marked, never clean. */
export function readTaint(io: CliIo, sessionId: unknown): TaintState {
  if (typeof sessionId !== "string" || !SESSION_ID.test(sessionId)) return { state: "unknown", why: "the request has no usable session_id" };
  const file = pathLib(io.platform).join(taintDir(io), `${sessionId}.json`);
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    if (errnoCode(e) === "ENOENT") return { state: "clean" };
    return { state: "unknown", why: `cannot read ${file}: ${(e as Error).message}` };
  }
  try {
    return { state: "marked", first: parseFirst((JSON.parse(text) as { first?: unknown } | null)?.first) };
  } catch {
    return { state: "marked", first: null }; // a marker that is there but unreadable still marks
  }
}

function prune(io: CliIo, dir: string, keep: string): void {
  const lib = pathLib(io.platform);
  const cutoff = io.clock().getTime() - MARKER_MAX_AGE_MS;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (name === keep || !name.endsWith(".json")) continue;
    const file = lib.join(dir, name);
    try {
      if (statSync(file).mtimeMs < cutoff) unlinkSync(file);
    } catch {
      // gone already, or not ours to remove: the next marker tries again
    }
  }
}

/** Mark the session. The first mark is kept; a later one changes nothing. */
export function markTaint(io: CliIo, sessionId: unknown, first: TaintFirst): { ok: true; created: boolean } | { ok: false; error: string } {
  if (typeof sessionId !== "string" || !SESSION_ID.test(sessionId)) return { ok: false, error: "the request has no usable session_id" };
  const dir = taintDir(io);
  const name = `${sessionId}.json`;
  const file = pathLib(io.platform).join(dir, name);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (e) {
    return { ok: false, error: `cannot make ${dir}: ${(e as Error).message}` }; // EEXIST here is a file in the way, not a marker
  }
  try {
    const fd = openSync(file, "wx", 0o600);
    try {
      writeSync(fd, `${JSON.stringify({ session_id: sessionId, first }, null, 2)}\n`);
    } finally {
      closeSync(fd);
    }
  } catch (e) {
    if (errnoCode(e) === "EEXIST") return { ok: true, created: false };
    return { ok: false, error: `cannot write ${file}: ${(e as Error).message}` };
  }
  prune(io, dir, name);
  return { ok: true, created: true };
}

export interface CallFlags {
  operation: string | null;
  untrusted: boolean;
  egress: boolean;
  /** false: not a known operation of this tool, so the flags are the worst of what the tool can reach. */
  known: boolean;
}

/**
 * What a call to one of the server's tools can do, from the manifest flags. A
 * catalog group tool names its operation in operation_id. A hand-written tool,
 * an extra tool, or an id the manifest does not list gets the worst of the
 * operations the tool can reach: its own (group tools), else its group's
 * operations that have no group tool.
 */
export function callFlags(rules: HarnessRules, tool: string, input: unknown): CallFlags {
  const ops = rules.operations ? Object.values(rules.operations) : [];
  const group = toolRule(rules, tool)?.group;
  const id = isRecord(input) && typeof input.operation_id === "string" ? input.operation_id : null;
  const op = id === null ? undefined : operationRule(rules, id);
  if (op && (op.tool === tool || (op.tool === null && op.group === group))) return { operation: id, untrusted: op.untrusted_output === true, egress: op.egress === true, known: true };
  const own = ops.filter((o) => o.tool === tool);
  const reach = own.length ? own : ops.filter((o) => o.tool === null && o.group === group);
  return { operation: id, untrusted: reach.some((o) => o.untrusted_output === true), egress: reach.some((o) => o.egress === true), known: false };
}

/** The guard's label for outside text, `{ untrusted: true, source, text }`, as an object or inside JSON text. */
const LABEL = /"untrusted"\s*:\s*true\b/;

/** Whether a tool result carries the label anywhere. A result too big or deep to walk counts as carrying it. */
export function carriesUntrustedLabel(value: unknown): boolean {
  let budget = 10_000;
  const walk = (v: unknown, depth: number): boolean => {
    if (--budget < 0 || depth > 16) return true;
    if (typeof v === "string") return LABEL.test(v);
    if (Array.isArray(v)) return v.some((x) => walk(x, depth + 1));
    if (isRecord(v)) return v.untrusted === true || Object.values(v).some((x) => walk(x, depth + 1));
    return false;
  };
  return walk(value, 0);
}

export function describeFirst(first: TaintFirst | null): string {
  if (!first) return "a tool";
  return `${first.tool}${first.operation ? ` (${first.operation})` : ""}`;
}
