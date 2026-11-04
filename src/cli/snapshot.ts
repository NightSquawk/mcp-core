/**
 * One read-only look at a server, shared by `status` and `verify`: the policy as
 * the guard would load it, protection as the CLI's user sees it, the effective
 * groups per mode, and the user's state (kill trips, ledger, idempotency, audit).
 * Nothing here writes: the ledger and audit classes only write on append/reserve.
 */
import { existsSync } from "node:fs";
import { z } from "zod";
import type { Mode } from "../guard/approvers.js";
import { AuditLog, type ChainCheck } from "../guard/audit.js";
import { computeEffective, readNarrowing, type Effective } from "../guard/effective.js";
import { IdempotencyStateError, IdempotencyStore, type IdemEntry } from "../guard/idempotency.js";
import { KillSwitch, type KillState } from "../guard/kill-switch.js";
import { Ledger } from "../guard/ledger.js";
import { readJsonFile } from "../guard/lock.js";
import { basePolicySchema, loadPolicy, type BasePolicy, type LoadedPolicy } from "../guard/policy.js";
import type { ProtectionReport } from "../guard/protection.js";
import { GROUPS, type Group } from "../guard/tiers.js";
import { pathOptions, type ServerContext } from "./context.js";
import { protectionFor, type CliIo } from "./io.js";

export const MODES: readonly Mode[] = Object.freeze(["live", "sandbox", "none"] as Mode[]);

export function isMode(value: unknown): value is Mode {
  return typeof value === "string" && (MODES as readonly string[]).includes(value);
}

export type IdempotencyView = { ok: true; entries: IdemEntry[] } | { ok: false; file: string; error: string };

export interface LedgerView {
  file: string;
  exists: boolean;
  /** ledger.json exists but is not valid JSON: the guard rebuilds it from the audit log. */
  corrupt: boolean;
  spendToday: Record<string, number>;
  callsToday: Record<Group, number>;
}

export interface ServerSnapshot {
  ctx: ServerContext;
  loaded: LoadedPolicy;
  /** Top-level keys the base schema does not know: server-specific, or typos. */
  serverSpecificKeys: string[];
  protection: ProtectionReport;
  effective: Partial<Record<Mode, Effective>>;
  kill: KillState & { file: string; corrupt: boolean };
  ledger: LedgerView;
  idempotency: IdempotencyView;
  audit: ChainCheck[];
}

const isPlainRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** The schema under .default(), .optional(), .nullable() and refinements. */
function bare(schema: z.ZodTypeAny): z.ZodTypeAny {
  let s = schema;
  for (;;) {
    if (s instanceof z.ZodDefault) s = s.removeDefault();
    else if (s instanceof z.ZodOptional || s instanceof z.ZodNullable) s = s.unwrap();
    else if (s instanceof z.ZodEffects) s = s.innerType();
    else return s;
  }
}

/**
 * `value` without the object keys `schema` does not know, at any depth; their
 * dotted paths go into `extra`. Records (allowlists, operators, rate) take any key.
 */
export function stripUnknownKeys(schema: z.ZodTypeAny, value: unknown, extra: string[], path = ""): unknown {
  const s = bare(schema);
  const at = (k: string) => (path ? `${path}.${k}` : k);
  if (s instanceof z.ZodObject && isPlainRecord(value)) {
    const shape = s.shape as Record<string, z.ZodTypeAny>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value)) {
      if (Object.prototype.hasOwnProperty.call(shape, k)) out[k] = stripUnknownKeys(shape[k]!, value[k], extra, at(k));
      else extra.push(at(k));
    }
    return out;
  }
  if (s instanceof z.ZodArray && Array.isArray(value)) return value.map((v, i) => stripUnknownKeys(s.element as z.ZodTypeAny, v, extra, `${path}[${i}]`));
  if (s instanceof z.ZodUnion && isPlainRecord(value)) {
    const object = (s.options as z.ZodTypeAny[]).find((o) => bare(o) instanceof z.ZodObject);
    return object ? stripUnknownKeys(object, value, extra, path) : value;
  }
  return value;
}

/**
 * Load the policy with the base schema. A server extends the base schema and its
 * sub-schemas with its own keys (Column adds surfaces, client and
 * environment.verified_key_sha256). mcp-guard cannot check those, so it reads
 * the base fields and lists the rest by path.
 */
export function loadPolicyForCli(ctx: ServerContext, io: CliIo): { loaded: LoadedPolicy; serverSpecificKeys: string[] } {
  const extra: string[] = [];
  const schema = z.preprocess((raw) => stripUnknownKeys(basePolicySchema, raw, extra), basePolicySchema) as unknown as z.ZodType<BasePolicy, z.ZodTypeDef, unknown>;
  const loaded = loadPolicy<BasePolicy>({ server: ctx.server, schema, ...pathOptions(io), path: ctx.policyPath });
  const serverSpecificKeys = loaded.source === "file" && !loaded.error ? [...new Set(extra)].sort() : [];
  return { loaded, serverSpecificKeys };
}

function currencies(policy: BasePolicy, ledgerFile: string, audit: AuditLog): string[] {
  const out = new Set<string>();
  const add = (c: unknown) => {
    if (typeof c === "string" && /^[A-Z]{3}$/.test(c)) out.add(c);
  };
  add(policy.limits.spend?.currency);
  try {
    const f = readJsonFile<{ events?: unknown }>(ledgerFile, { events: [] });
    if (Array.isArray(f.events)) for (const e of f.events) add((e as { currency?: unknown } | null)?.currency);
  } catch {
    // corrupt: reported by the caller
  }
  for (const line of audit.read()) if (line.group === "spend") add(line.currency);
  return [...out].sort();
}

export function snapshotServer(ctx: ServerContext, io: CliIo, modes: readonly Mode[] = MODES): ServerSnapshot {
  const { loaded, serverSpecificKeys } = loadPolicyForCli(ctx, io);
  const protection = protectionFor(io, loaded.path, loaded.override);
  // The server's own env can only narrow this further, so the CLI computes it with none.
  const narrowing = readNarrowing({}, ctx.envPrefix);
  const effective: Partial<Record<Mode, Effective>> = {};
  for (const mode of modes) effective[mode] = computeEffective({ loaded, protection, mode, narrowing });

  const clock = io.clock;
  const ks = new KillSwitch({ markers: ctx.markers, stateDir: ctx.stateDir, clock });
  let killCorrupt = false;
  try {
    readJsonFile(ks.file, { trips: [] });
  } catch {
    killCorrupt = true;
  }

  const audit = new AuditLog(ctx.stateDir, ctx.server, { clock });
  const ledger = new Ledger(ctx.stateDir, { clock, audit });
  let ledgerCorrupt = false;
  try {
    readJsonFile(ledger.file, null);
  } catch {
    ledgerCorrupt = true;
  }
  const ls = ledger.snapshot();
  const spendToday: Record<string, number> = {};
  for (const c of currencies(loaded.policy, ledger.file, audit)) spendToday[c] = ls.spendToday(c);
  const callsToday = {} as Record<Group, number>;
  for (const g of GROUPS) callsToday[g] = ls.count(g, "day");

  let idempotency: IdempotencyView;
  try {
    idempotency = { ok: true, entries: new IdempotencyStore(ctx.stateDir, { clock }).entries() };
  } catch (e) {
    if (!(e instanceof IdempotencyStateError)) throw e;
    idempotency = { ok: false, file: e.file, error: e.message };
  }

  return {
    ctx,
    loaded,
    serverSpecificKeys,
    protection,
    effective,
    kill: { ...ks.state(), file: ks.file, corrupt: killCorrupt },
    ledger: { file: ledger.file, exists: existsSync(ledger.file), corrupt: ledgerCorrupt, spendToday, callsToday },
    idempotency,
    audit: audit.verifyAll(),
  };
}

/** Entries that block or may block a retry: unknown, pending, or running. */
export function openEntries(view: IdempotencyView): IdemEntry[] {
  return view.ok ? view.entries.filter((e) => e.status === "unknown" || e.status === "pending" || e.status === "in_flight") : [];
}

/** The last 12 characters of a key: what the guard's outcome_unknown hint prints. */
export function keySuffix(key: string): string {
  return key.slice(-12);
}

/** Integer cents as a plain amount, e.g. 123456 -> "1234.56". */
export function formatCents(cents: number): string {
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(cents);
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, "0")}`;
}
