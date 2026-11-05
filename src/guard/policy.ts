/**
 * The policy file (section 5): base schema plus the revision 2 additions. Servers
 * extend `basePolicySchema` (and the exported sub-schemas) with `.extend()`; every
 * object is strict, so a misspelled key makes the file invalid and the guard fails
 * closed (read-only) instead of silently ignoring it.
 */
import { readFileSync, statSync } from "node:fs";
import { z } from "zod";
import { sha256Hex } from "./canonical.js";
import { policyPath, policyRoot, type PathOptions } from "./paths.js";
import { GROUPS, TIERS, type Group } from "./tiers.js";

export const APPROVER_NAMES = ["none", "deny", "external", "duo", "passkey", "auth0-ciba"] as const;
export type ApproverName = (typeof APPROVER_NAMES)[number];
/** Approvers this version implements (G1). Any other name fails closed. */
export const IMPLEMENTED_APPROVERS: readonly ApproverName[] = Object.freeze(["none", "deny", "external"]);
/** Approvers that put the call in front of a person, which approval.fatigue (6.7) limits. */
export const HUMAN_APPROVERS: readonly ApproverName[] = Object.freeze(["external", "duo", "passkey", "auth0-ciba"]);

const DURATION = /^(\d+)(ms|s|m|h|d)$/;
export const durationSchema = z.string().regex(DURATION, 'a duration such as "30m", "4h" or "1d"');

export function parseDuration(text: string): number {
  const m = DURATION.exec(text);
  if (!m) throw new Error(`Invalid duration ${JSON.stringify(text)}.`);
  const n = Number(m[1]);
  return n * { ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "ms" | "s" | "m" | "h" | "d"];
}

const approverName = z.enum(APPROVER_NAMES);

export const approverTierSchema = z
  .object({
    over_cents: z.number().int().nonnegative(),
    approver: approverName,
    quorum: z.number().int().min(1).optional(),
    independent: z.boolean().optional(),
    delay: durationSchema.optional(),
  })
  .strict();

export const approverObjectSchema = z
  .object({
    approver: approverName,
    unattended: z.boolean().optional(),
    quorum: z.number().int().min(1).optional(),
    independent: z.boolean().optional(),
    delay: durationSchema.optional(),
    tiers: z.array(approverTierSchema).optional(),
  })
  .strict();

/** `"external"` or `{ approver: "duo", ... }` (5.4). */
export const approverConfigSchema = z.union([approverName, approverObjectSchema]);
export type ApproverConfig = z.infer<typeof approverConfigSchema>;

export const groupsSchema = z
  .object({ read: z.boolean().optional(), change: z.boolean().optional(), critical: z.boolean().optional(), spend: z.boolean().optional() })
  .strict();

export const environmentSchema = z.object({ allow_live: z.boolean().default(false) }).strict();

export const RATE_KEY = /^(read|change|critical|spend)_per_(minute|hour|day)$/;

export const limitsSchema = z
  .object({
    spend: z
      .object({
        unit: z.literal("cents"),
        currency: z.string().regex(/^[A-Z]{3}$/, "an ISO 4217 code such as USD"),
        per_call: z.number().int().nonnegative().optional(),
        per_day: z.number().int().nonnegative().optional(),
      })
      .strict()
      .optional(),
    rate: z.record(z.string().regex(RATE_KEY, "<group>_per_<minute|hour|day>"), z.number().int().nonnegative()).optional(),
  })
  .strict();

export const approvalSchema = z
  .object({
    change: approverConfigSchema.optional(),
    critical: approverConfigSchema.optional(),
    spend: approverConfigSchema.optional(),
    delay_new_target: durationSchema.optional(),
    fatigue: z
      .object({
        pending_per_server: z.number().int().min(1).optional(),
        pushes_per_hour: z.number().int().min(1).optional(),
        denied_cooldown_hours: z.number().int().min(0).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

// forward: anything but "none" keeps every non-read group off until G5 forwards lines (effective.ts).
// reads: audit every read. A read that a read_per_* limit counts is audited either way, so that a
// ledger rebuilt from the log keeps counting it.
export const auditSchema = z
  .object({ forward: z.enum(["none", "datadog"]).default("none"), reads: z.boolean().default(false) })
  .strict();

export const taintSchema = z.object({ egress_after_untrusted: z.enum(["approve", "deny", "allow"]).default("approve") }).strict();

export const canariesSchema = z
  .object({ hashes: z.array(z.string().regex(/^sha256:[0-9a-f]{64}$/, '"sha256:" followed by 64 lowercase hex characters (mcp-guard canary add)')).default([]) })
  .strict();

export const clientScopeSchema = z
  .object({ allowed: z.array(z.string().min(1)).min(1), lock_per_session: z.boolean().default(false) })
  .strict();

const allowValue = z.union([z.string().min(1), z.number()]).transform(String);

export const basePolicyShape = {
  version: z.literal(1),
  server: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/, "the server name: lowercase letters, digits, _ or -, at most 64 characters"),
  groups: groupsSchema.default({}),
  tiers_off: z.array(z.enum(TIERS)).default([]),
  environment: environmentSchema.default({}),
  allowlists: z.record(z.string().min(1), z.array(allowValue)).default({}),
  limits: limitsSchema.default({}),
  approval: approvalSchema.default({}),
  audit: auditSchema.default({}),
  duo: z
    .object({
      api_host: z.string().min(1),
      approvers: z.array(z.object({ id: z.string().min(1), duo_username: z.string().min(1), device: z.string().min(1) }).strict()),
    })
    .strict()
    .optional(),
  operators: z.record(z.string().min(1)).optional(),
  // Anything but "none" keeps every non-read group off until G5 reads the flag (effective.ts).
  kill_switch: z.object({ remote_flag: z.string().default("none") }).strict().optional(),
  taint: taintSchema.default({}),
  canaries: canariesSchema.default({}),
  client_scope: clientScopeSchema.optional(),
};

export const basePolicySchema = z.object(basePolicyShape).strict();
export type BasePolicy = z.infer<typeof basePolicySchema>;

/** The policy used when no file exists: read-only, everything else off (fail closed). */
export function defaultPolicy(server: string): BasePolicy {
  return basePolicySchema.parse({ version: 1, server, groups: { read: true, change: false, critical: false, spend: false } });
}

export interface LoadedPolicy<P extends BasePolicy = BasePolicy> {
  /** The parsed policy, or the read-only default when the file is missing or invalid. */
  policy: P;
  source: "file" | "default";
  path: string;
  /** NST_MCP_POLICY_DIR is set: tests only, never protected. */
  override: boolean;
  /** sha256 of the file bytes, or null without a file. */
  hash: string | null;
  mtimeMs: number | null;
  /** Why the file was rejected. The guard is then read-only. */
  error?: string;
}

export interface LoadPolicyOptions<P extends BasePolicy> extends PathOptions {
  server: string;
  schema?: z.ZodType<P, z.ZodTypeDef, unknown>;
  /** Read the file (tests). */
  readFile?: (path: string) => string;
  stat?: (path: string) => { mtimeMs: number };
  /** Use this path instead of the standard location (the CLI's --file). */
  path?: string;
}

export function loadPolicy<P extends BasePolicy = BasePolicy>(opts: LoadPolicyOptions<P>): LoadedPolicy<P> {
  const schema = (opts.schema ?? basePolicySchema) as z.ZodType<P, z.ZodTypeDef, unknown>;
  const path = opts.path ?? policyPath(opts.server, opts);
  const { override } = policyRoot(opts);
  const fallback = (): P => schema.parse({ version: 1, server: opts.server, groups: { read: true, change: false, critical: false, spend: false } });
  const read = opts.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  let text: string;
  try {
    text = read(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { policy: fallback(), source: "default", path, override, hash: null, mtimeMs: null };
    return { policy: fallback(), source: "default", path, override, hash: null, mtimeMs: null, error: `Cannot read ${path}: ${(e as Error).message}` };
  }
  const hash = sha256Hex(text);
  let mtimeMs: number | null = null;
  try {
    mtimeMs = (opts.stat ?? statSync)(path).mtimeMs;
  } catch {
    mtimeMs = null;
  }
  // A UTF-8 byte order mark (Windows PowerShell 5.1 "Set-Content -Encoding UTF8") is not part of the JSON.
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch (e) {
    return { policy: fallback(), source: "default", path, override, hash, mtimeMs, error: `${path} is not valid JSON: ${(e as Error).message}` };
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
    return { policy: fallback(), source: "default", path, override, hash, mtimeMs, error: `${path} does not match the policy schema: ${issues}` };
  }
  if (parsed.data.server !== opts.server) {
    return {
      policy: fallback(),
      source: "default",
      path,
      override,
      hash,
      mtimeMs,
      error: `${path} is for server "${parsed.data.server}", not "${opts.server}".`,
    };
  }
  return { policy: parsed.data, source: "file", path, override, hash, mtimeMs };
}

/** The approver configured for a group, normalized to the object form. */
export function approverFor(policy: BasePolicy, group: Group): z.infer<typeof approverObjectSchema> {
  if (group === "read") return { approver: "none" };
  const cfg = policy.approval[group];
  if (cfg === undefined) return { approver: "none" };
  return typeof cfg === "string" ? { approver: cfg } : cfg;
}

/**
 * The approval.fatigue limits a policy sets (6.7). This version enforces none of them, so a call
 * whose approver asks a person fails closed while any is set (G4a enforces them).
 */
export function fatigueLimits(policy: BasePolicy): string[] {
  return Object.entries(policy.approval.fatigue ?? {})
    .filter(([, v]) => v !== undefined)
    .map(([k]) => k);
}

/** Every approver name a group's config can resolve to (thresholds included). */
export function approverNamesFor(policy: BasePolicy, group: Group): ApproverName[] {
  const cfg = approverFor(policy, group);
  return [cfg.approver, ...(cfg.tiers ?? []).map((t) => t.approver)];
}

export { GROUPS };
