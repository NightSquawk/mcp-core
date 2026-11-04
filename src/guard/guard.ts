/**
 * createGuard(): the enforcement path (section 6, steps 0-9 and dry_run), the
 * read path, availability for list/describe tools, status, and the guard://
 * resources. One guard per server process; it is also the session (7.9).
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  BUILTIN_APPROVERS,
  buildProposal,
  proposalText,
  agentSays,
  selectApprover,
  type Approver,
  type ExternalHold,
  type Extraction,
  type Mode,
  type Target,
} from "./approvers.js";
import { AuditLog, type AuditEntry, type AuditLine } from "./audit.js";
import { Canaries, CANARY_SALT_ENV } from "./canaries.js";
import { canonicalJson, deepFreeze, jsonClone, sha256Hex, utcDay } from "./canonical.js";
import { computeEffective, readNarrowing, type Effective, type GroupState, type ServerCheckResult } from "./effective.js";
import { IdempotencyStateError, IdempotencyStore, MIN_KEY_LENGTH, deriveKey, type IdemEntry } from "./idempotency.js";
import { LockTimeoutError } from "./lock.js";
import { KillSwitch, type KillState } from "./kill-switch.js";
import { Ledger, type LedgerSnapshot } from "./ledger.js";
import { buildManifest, type GuardManifest } from "./manifest.js";
import { killMarkers, stateDir as defaultStateDir, assertServerName } from "./paths.js";
import { approverFor, basePolicySchema, loadPolicy, type ApproverName, type BasePolicy, type LoadedPolicy } from "./policy.js";
import { checkProtection, type ProtectionProbes, type ProtectionReport } from "./protection.js";
import { createRedactor, redactValue, type RedactRule, type Redactor } from "./redact.js";
import { isRefusal, refuse, type Refusal } from "./refusal.js";
import { labelUntrustedFields, sanitizeDeep } from "./sanitize.js";
import { SessionState, trustedLeaves, type TaintState } from "./session.js";
import { GROUPS, GROUP_ANNOTATIONS, groupMeta, groupToolName, TIER_GROUP, type Group, type OperationRef } from "./tiers.js";
import { GUARD_VERSION } from "./version.js";

// ------------------------------------------------------------------ types

export interface GuardRequest {
  pathParams?: Record<string, string | number>;
  query?: Record<string, unknown>;
  body?: unknown;
}

export interface HandlerContext {
  /** Core-derived key; send it as the provider's idempotency header where one exists. Null on reads. */
  idempotencyKey: string | null;
  operation: OperationRef;
  group: Group;
  mode: Mode;
}

export type HandlerResult =
  | { ok: true; status?: number; data: unknown; providerIds?: string[] }
  /** `sent: false` means nothing reached the provider (validation, network refused before sending). */
  | { ok: false; status?: number; error: unknown; sent: boolean };

export type Handler = (request: GuardRequest, ctx: HandlerContext) => Promise<HandlerResult>;

/** Normalize or validate the model's request before any check or hash (pinned fields, path params). Return a new object. */
export type PrepareHook = (op: OperationRef, request: GuardRequest) => Promise<GuardRequest | Refusal> | GuardRequest | Refusal;

export interface ExecuteHooks {
  prepare?: PrepareHook;
  /** Amount, currency, targets and client for this call, or a refusal (e.g. an inline payee). */
  extract?: (op: OperationRef, request: GuardRequest) => Promise<Extraction | Refusal> | Extraction | Refusal;
  /** The object's current state before a write/destructive/sensitive change (step 7). Undefined = nothing to save. */
  fetchCurrent?: (op: OperationRef, request: GuardRequest) => Promise<unknown>;
  /** For the `external` approver: did the provider hold the action for a human? */
  external?: (op: OperationRef, result: { status?: number; data: unknown }) => ExternalHold;
}

export interface ExecuteInput {
  /** The calling tool, e.g. `column_spend`. */
  tool: string;
  /** The calling tool's group (step 2 compares it with the operation's tier). */
  group: Group;
  /** The resolved operation, or null when the id is unknown. */
  operation: OperationRef | null;
  /** The id as the model gave it (for refusals and audit). */
  operationId: string;
  request: GuardRequest;
  dryRun?: boolean;
  /** The model's reason; required for critical and spend. Shown to approvers as unverified. */
  reason?: string;
  hooks?: ExecuteHooks;
  /** Close matches for an unknown id. */
  suggestions?: string[];
}

export interface DryRunPreview {
  operation: string;
  tier: string;
  group: Group;
  mode: Mode;
  request: GuardRequest;
  amount_cents?: number;
  currency?: string;
  targets: Target[];
  client: string | null;
  approval: { approver: ApproverName; effect: string };
  idempotency_key: string;
  duplicate_of?: { status: string; at: string; provider_ids?: string[] };
  approval_text: string;
  note: string;
}

export type ExecuteOutcome =
  | { status: "refused"; refusal: Refusal }
  | { status: "dry_run"; preview: DryRunPreview }
  | {
      status: "deduplicated";
      operation: string;
      idempotency_key: string;
      original: { status: string; at: string; http_status?: number | null; provider_ids?: string[]; data?: unknown; pending?: IdemEntry["result"] extends infer R ? R extends { pending?: infer P } ? P : never : never };
      message: string;
    }
  | {
      status: "pending";
      operation: string;
      idempotency_key: string;
      http_status?: number;
      provider_ids?: string[];
      hold: ExternalHold | { ref: string; url?: string };
      data?: unknown;
      message: string;
    }
  | { status: "done"; operation: string; idempotency_key: string; http_status?: number; provider_ids?: string[]; data: unknown; warnings?: string[] }
  | { status: "failed"; operation: string; idempotency_key: string; http_status?: number; error: unknown; message: string }
  | { status: "unknown_outcome"; operation: string; idempotency_key: string; http_status?: number; error: unknown; message: string };

export interface ReadInput {
  tool: string;
  operation: OperationRef | null;
  operationId: string;
  request: GuardRequest;
  /** Field names (any depth) holding text other people wrote, for `untrusted_output` operations. */
  untrustedFields?: readonly string[];
  prepare?: PrepareHook;
  /** Client and targets of a read (client scope, canary alerts). Optional. */
  extract?: (op: OperationRef, request: GuardRequest) => Promise<Extraction | Refusal> | Extraction | Refusal;
  suggestions?: string[];
}

export type ReadOutcome =
  | { status: "refused"; refusal: Refusal }
  | { status: "done"; operation: string; http_status?: number; data: unknown; untrusted_fields: number }
  | { status: "failed"; operation: string; http_status?: number; error: unknown };

export interface Availability {
  allowed: boolean;
  group: Group | null;
  tool: string | null;
  reason_code?: string;
  reason?: string;
}

export interface GuardStatus {
  server: string;
  version: string;
  guard_version: string;
  session: string;
  mode: Mode;
  policy: { source: "file" | "default"; path: string; override: boolean; hash: string | null; error?: string };
  protection: ProtectionReport;
  groups: Record<Group, GroupState & { approver: string; tool: string }>;
  kill: KillState & { stopped: Record<Group, string | null> };
  taint: TaintState | null;
  client_lock: string | null;
  spend: { currency?: string; per_call?: number; per_day?: number; ledger_today?: number; provider_totals: boolean };
  state_dir: string;
  warnings: string[];
}

export interface GuardOptions<P extends BasePolicy = BasePolicy> {
  /** Server name: policy folder, state folder and audit lines. */
  server: string;
  /** Server version for audit lines and the manifest. */
  version: string;
  /** Tool prefix (default: server). */
  prefix?: string;
  /** Env prefix for `<PREFIX>_PROFILE` and the legacy `<PREFIX>_ALLOW_*` flags (default: server upper-cased). */
  envPrefix?: string;
  env?: NodeJS.ProcessEnv;
  /** The server's policy schema (basePolicySchema.extend(...)). */
  policySchema?: z.ZodType<P, z.ZodTypeDef, unknown>;
  /** Sandbox, live, or none (the server cannot tell). */
  mode?: Mode;
  /** Secret values to mask everywhere (API keys). */
  secrets?: () => readonly string[];
  redactRules?: readonly RedactRule[];
  clock?: () => Date;
  /** A precomputed protection report (tests); otherwise the OS check runs. */
  protection?: ProtectionReport;
  probes?: ProtectionProbes;
  /** Extra or replacement approvers (G4 approvers, tests). */
  approvers?: Partial<Record<ApproverName, Approver>>;
  serverCheck?: (group: Group, policy: P) => ServerCheckResult | null;
  /** Today's spend in `currency` as the provider reports it, in cents (cross-check for per_day). */
  providerTotals?: (currency: string) => Promise<number>;
  /** The client for calls whose extractor does not report one. */
  defaultClient?: (policy: P) => string | null;
  /** Called after every audit line is written (Rule 11 inbox entries, forwarding). Errors are reported, never thrown. */
  onAudit?: (line: AuditLine) => void;
  /** Local dedupe window for providers without an idempotency header (default 10 minutes). */
  idempotencyWindowMs?: number;
  /** Provider limit on the idempotency key (default 255). */
  idempotencyMaxLength?: number;
  /** Override the state folder (tests). */
  stateDir?: string;
  /** Diagnostics (default: stderr). */
  log?: (line: string) => void;
}

const DEDUP_DATA_CHARS = 20_000;
const PREIMAGE_TIERS = new Set(["write", "destructive", "sensitive"]);
const DENIAL_WINDOW_MS = 30 * 60_000;
const REASON_MAX = 500;

// ------------------------------------------------------------------ guard

export class Guard<P extends BasePolicy = BasePolicy> {
  readonly server: string;
  readonly version: string;
  readonly prefix: string;
  readonly mode: Mode;
  readonly loaded: LoadedPolicy<P>;
  readonly protection: ProtectionReport;
  readonly effective: Effective;
  readonly audit: AuditLog;
  readonly ledger: Ledger;
  readonly idempotency: IdempotencyStore;
  readonly kill: KillSwitch;
  readonly session: SessionState;
  readonly canaries: Canaries;
  readonly stateDir: string;
  readonly warnings: string[];
  readonly #opts: GuardOptions<P>;
  readonly #clock: () => Date;
  readonly #redactor: Redactor;
  readonly #approvers: Partial<Record<ApproverName, Approver>>;
  readonly #denials = new Map<Group, number[]>();
  readonly #log: (line: string) => void;

  constructor(opts: GuardOptions<P>) {
    assertServerName(opts.server);
    if (opts.idempotencyMaxLength !== undefined && !(Number.isInteger(opts.idempotencyMaxLength) && opts.idempotencyMaxLength >= MIN_KEY_LENGTH)) {
      throw new Error(`idempotencyMaxLength must be an integer of at least ${MIN_KEY_LENGTH} (got ${opts.idempotencyMaxLength}).`);
    }
    this.#opts = opts;
    this.server = opts.server;
    this.version = opts.version;
    this.prefix = opts.prefix ?? opts.server;
    this.mode = opts.mode ?? "none";
    this.#clock = opts.clock ?? (() => new Date());
    this.#log = opts.log ?? ((l) => console.error(l));
    const env = opts.env ?? process.env;
    this.#redactor = createRedactor(opts.redactRules ?? []);
    this.#approvers = { ...BUILTIN_APPROVERS, ...(opts.approvers ?? {}) };

    this.loaded = loadPolicy<P>({ server: this.server, env, ...(opts.policySchema ? { schema: opts.policySchema } : { schema: basePolicySchema as unknown as z.ZodType<P, z.ZodTypeDef, unknown> }) });
    this.protection = opts.protection ?? checkProtection(this.loaded.path, { override: this.loaded.override, probes: opts.probes });
    this.effective = computeEffective<P>({
      loaded: this.loaded,
      protection: this.protection,
      mode: this.mode,
      narrowing: readNarrowing(env, opts.envPrefix ?? this.server.toUpperCase().replace(/[^A-Z0-9]/g, "_")),
      availableApprovers: Object.keys(this.#approvers),
      serverCheck: opts.serverCheck,
    });
    this.warnings = [...this.effective.warnings];

    this.stateDir = opts.stateDir ?? defaultStateDir(this.server, { env });
    mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
    this.audit = new AuditLog(this.stateDir, this.server, { clock: this.#clock, redactor: this.#redactor, secrets: () => this.#secrets() });
    this.ledger = new Ledger(this.stateDir, { clock: this.#clock, audit: this.audit });
    this.idempotency = new IdempotencyStore(this.stateDir, { clock: this.#clock });
    this.kill = new KillSwitch({ markers: killMarkers(this.server, { env }), stateDir: this.stateDir, clock: this.#clock });
    this.session = new SessionState();
    this.canaries = new Canaries(this.loaded.policy.canaries.hashes, env[CANARY_SALT_ENV]);
    if (this.canaries.misconfigured) this.warnings.push(`Canary hashes are configured but ${CANARY_SALT_ENV} is not set: non-read calls are refused until it is.`);

    // A broken audit chain trips the kill switch (7.8).
    for (const check of this.audit.verifyAll().slice(-2)) {
      if (!check.ok) {
        const reason = `Audit chain broken in ${check.file} at line ${check.brokenAt} (${check.reason}).`;
        this.kill.trip("all", reason);
        this.warnings.push(reason);
      }
    }
    for (const w of this.warnings) this.#log(`${this.server}: guard: ${w}`);
  }

  #secrets(): readonly string[] {
    return this.#opts.secrets?.() ?? [];
  }

  /** Mask secrets and the shared patterns in text. */
  redact(text: string): string {
    return this.#redactor(text, this.#secrets());
  }

  redactValue<T>(value: T): T {
    return redactValue(value, this.#secrets(), this.#redactor);
  }

  get policy(): P {
    return this.loaded.policy;
  }

  toolName(group: Group): string {
    return groupToolName(this.prefix, group);
  }

  groupEnabled(group: Group): boolean {
    return this.effective.groups[group].enabled;
  }

  /** Annotations and `_meta` for a group's tool (section 4, 6.5 unattended). */
  toolConfig(group: Group): { annotations: (typeof GROUP_ANNOTATIONS)[Group]; _meta?: Record<string, unknown> } {
    const cfg = approverFor(this.policy, group);
    const unattended = !!cfg.unattended && (cfg.approver === "duo" || cfg.approver === "passkey");
    const meta = groupMeta(group, { unattended });
    return { annotations: { ...GROUP_ANNOTATIONS[group] }, ...(meta ? { _meta: meta } : {}) };
  }

  /** Whether an operation can run right now (for list/describe tools). */
  availability(op: OperationRef | null): Availability {
    if (!op) return { allowed: false, group: null, tool: null, reason_code: "unknown_operation", reason: "Not in the catalog." };
    const group = TIER_GROUP[op.tier];
    if (!group) return { allowed: false, group: null, tool: null, reason_code: "blocked", reason: "Tier blocked: never exposed to an agent." };
    const tool = this.toolName(group);
    const state = this.effective.groups[group];
    if (!state.enabled) return { allowed: false, group, tool, reason_code: state.reason_code, reason: state.reason };
    if (op.tier === "sandbox" && this.mode !== "sandbox") return { allowed: false, group, tool, reason_code: "sandbox_only", reason: "Sandbox-only operation; this is not a sandbox key." };
    if (this.policy.tiers_off.includes(op.tier)) return { allowed: false, group, tool, reason_code: "tier_off", reason: `Tier ${op.tier} is in the policy's tiers_off.` };
    const stopped = this.kill.stopped(group);
    if (stopped) return { allowed: false, group, tool, reason_code: "kill_switch", reason: stopped };
    return { allowed: true, group, tool };
  }

  // ---------------------------------------------------------------- audit

  #auditBase(input: { tool: string; operation: OperationRef | null; operationId: string; group: Group | null; dryRun?: boolean }): AuditEntry {
    return {
      server: this.server,
      version: this.version,
      guard: GUARD_VERSION,
      session: this.session.id,
      tool: input.tool,
      operation: input.operation?.operationId ?? String(input.operationId).slice(0, 200),
      tier: input.operation?.tier ?? "unknown",
      group: input.group,
      mode: this.mode,
      decision: "refused",
      dry_run: !!input.dryRun,
    };
  }

  #write(entry: AuditEntry): AuditLine | null {
    try {
      const line = this.audit.append(entry);
      try {
        this.#opts.onAudit?.(line);
      } catch (e) {
        this.#log(`${this.server}: guard: onAudit hook failed: ${this.redact(String((e as Error)?.message ?? e))}`);
      }
      return line;
    } catch (e) {
      // An audit log that cannot be written stops every further non-read call.
      const reason = `Audit log write failed: ${this.redact(String((e as Error)?.message ?? e))}`;
      this.#log(`${this.server}: guard: ${reason}`);
      try {
        this.kill.trip("all", reason);
      } catch {
        // the state folder itself is broken; calls will fail at the next lock
      }
      return null;
    }
  }

  /** Record an idempotency outcome; never throws (the call may already have been sent). Returns a note when it failed. */
  #finish(key: string, status: "done" | "pending" | "unknown" | "failed", result?: IdemEntry["result"]): string | null {
    try {
      this.idempotency.finish(key, status, result);
      return null;
    } catch (e) {
      return `The idempotency store could not record this call as ${status}: ${this.redact(String((e as Error)?.message ?? e))}`;
    }
  }

  /** A refusal for an unreadable idempotency store (fail closed), or rethrow anything else. */
  #stateRefusal(e: unknown): Refusal {
    if (e instanceof IdempotencyStateError || e instanceof LockTimeoutError) {
      return refuse("state_unreadable", this.redact(e.message), {
        how_to_enable: `A human inspects ${this.idempotency.file} (mcp-guard status), moves the bad file aside only after checking which calls it records, and retries.`,
      });
    }
    throw e;
  }

  #refused(base: AuditEntry, refusal: Refusal, extra: Partial<AuditEntry> = {}): { status: "refused"; refusal: Refusal } {
    const r = this.redactValue(refusal);
    this.#write({ ...base, ...extra, decision: "refused", reason_code: r.reason_code });
    return { status: "refused", refusal: r };
  }

  // ---------------------------------------------------------------- shared checks

  #client(extraction: Extraction): string | null {
    return extraction.client ?? this.#opts.defaultClient?.(this.policy) ?? null;
  }

  #clientRefusal(client: string | null, nonRead: boolean): Refusal | null {
    const scope = this.policy.client_scope;
    if (scope && (client === null || !scope.allowed.includes(client))) {
      return refuse("client_out_of_scope", `This server instance may only act for ${scope.allowed.join(", ")}; this call is for ${client ?? "an unknown client"}.`, {
        how_to_enable: "Use the server instance (and key) for that client.",
      });
    }
    if (nonRead && scope?.lock_per_session && client !== null && this.session.lockedClient !== null && this.session.lockedClient !== client) {
      return refuse("client_locked", `This session already made changes for ${this.session.lockedClient}; work for ${client} needs a new session.`);
    }
    return null;
  }

  #canaryValues(request: GuardRequest, targets: readonly Target[]): string[] {
    return [...targets.map((t) => t.value), ...Object.values(request.pathParams ?? {}).map(String)];
  }

  #rateRefusal(group: Group, s: LedgerSnapshot): Refusal | null {
    for (const [key, limit] of Object.entries(this.policy.limits.rate ?? {})) {
      const m = /^(read|change|critical|spend)_per_(minute|hour|day)$/.exec(key);
      if (!m || m[1] !== group) continue;
      const window = m[2] as "minute" | "hour" | "day";
      if (s.count(group, window) + 1 > limit) {
        return refuse("rate_limited", `The policy allows ${limit} ${group} calls per ${window}; that many already ran.`, { details: { limit: key, value: limit } });
      }
    }
    return null;
  }

  #spendRefusal(amount: number, currency: string, s: LedgerSnapshot, providerToday: number | null): Refusal | null {
    const limits = this.policy.limits.spend!;
    if (limits.per_call !== undefined && amount > limits.per_call) {
      return refuse("over_per_call", `${amount} cents is over the policy's per-call cap of ${limits.per_call} cents.`, { details: { per_call: limits.per_call, amount_cents: amount } });
    }
    if (limits.per_day !== undefined) {
      const today = Math.max(s.spendToday(currency), providerToday ?? 0);
      if (today + amount > limits.per_day) {
        return refuse("over_per_day", `Today's spend (${today} cents) plus ${amount} cents is over the daily cap of ${limits.per_day} cents.`, {
          details: { per_day: limits.per_day, today_cents: today, amount_cents: amount },
        });
      }
    }
    return null;
  }

  #currentPolicyHash(): string | null {
    try {
      return sha256Hex(readFileSync(this.loaded.path, "utf8"));
    } catch {
      return null;
    }
  }

  // ---------------------------------------------------------------- execute (section 6)

  async execute(input: ExecuteInput, handler: Handler): Promise<ExecuteOutcome> {
    const started = this.#clock().getTime();
    const op = input.operation;
    const group = input.group;
    const base = this.#auditBase({ tool: input.tool, operation: op, operationId: input.operationId, group, dryRun: input.dryRun });
    const says = agentSays(input.reason);
    if (says) base.agent_says = says;

    if (group === "read") {
      return this.#refused(base, refuse("use_read_path", "Reads go through the read tool, not the execute path."));
    }
    // 0. Kill switch.
    const stopped = this.kill.stopped(group);
    if (stopped) return this.#refused(base, refuse("kill_switch", stopped, { how_to_enable: "An admin clears it with mcp-guard unkill / mcp-guard reset after checking why it tripped." }));
    // 1. Resolve.
    if (!op) {
      return this.#refused(
        base,
        refuse("unknown_operation", `Unknown operation ${JSON.stringify(String(input.operationId).slice(0, 200))}.${input.suggestions?.length ? ` Did you mean: ${input.suggestions.join(", ")}?` : ""}`, {
          how_to_enable: `Find operations with ${this.prefix}_list_endpoints.`,
        })
      );
    }
    const opGroup = TIER_GROUP[op.tier];
    if (opGroup === null) return this.#refused(base, refuse("blocked", `${op.operationId} is tier "blocked": it is never exposed to an agent. A human does it in the provider's own interface.`));
    // 2. Group check.
    if (opGroup !== group) {
      return this.#refused(base, refuse("wrong_group", `${op.operationId} is tier "${op.tier}", which runs only through ${this.toolName(opGroup)}, not ${input.tool}.`, { how_to_enable: `Call ${this.toolName(opGroup)}.` }));
    }
    // 3. Policy, protection, live/sandbox.
    const state = this.effective.groups[group];
    if (!state.enabled) return this.#refused(base, refuse(state.reason_code ?? "group_off", state.reason ?? `The ${group} group is off.`, state.how_to_enable ? { how_to_enable: state.how_to_enable } : {}));
    if (op.tier === "sandbox" && this.mode !== "sandbox") return this.#refused(base, refuse("sandbox_only", `${op.operationId} only runs with a sandbox key.`));
    if (this.policy.tiers_off.includes(op.tier)) return this.#refused(base, refuse("tier_off", `Tier ${op.tier} is in the policy's tiers_off.`));
    if ((group === "critical" || group === "spend") && !input.reason?.trim()) {
      return this.#refused(base, refuse("reason_required", `${input.tool} needs a reason: one sentence on why, shown to the approver as unverified.`));
    }
    if (input.reason && input.reason.length > REASON_MAX) return this.#refused(base, refuse("reason_too_long", `reason is limited to ${REASON_MAX} characters.`));

    // 4. Argument checks (the request is frozen from here on: steps 5-8 use exactly this object).
    const prepared = await this.#prepare(op, input.request, input.hooks?.prepare);
    if ("refusal" in prepared) return this.#refused(base, prepared.refusal);
    const request = prepared.request;
    let extraction: Extraction = {};
    try {
      const ex = input.hooks?.extract ? await input.hooks.extract(op, request) : {};
      if (isRefusal(ex)) return this.#refused(base, ex);
      extraction = ex;
    } catch (e) {
      return this.#refused(base, refuse("extract_failed", `Could not check this call's arguments: ${this.redact(String((e as Error)?.message ?? e))}`));
    }
    const targets = extraction.targets ?? [];
    const client = this.#client(extraction);
    base.client = client;
    if (typeof extraction.amount_cents === "number") base.amount_cents = extraction.amount_cents;
    if (extraction.currency) base.currency = extraction.currency;

    if (this.canaries.misconfigured) return this.#refused(base, refuse("canary_salt_missing", `Canaries are configured but ${CANARY_SALT_ENV} is not set, so no call can be checked.`));
    const canary = this.canaries.match(this.#canaryValues(request, targets));
    if (canary) {
      const reason = `Canary hit: ${op.operationId} targeted a decoy record.`;
      this.kill.trip("all", reason);
      this.#write({ ...base, decision: "alert", alert: "canary", note: reason });
      return this.#refused(base, refuse("canary", "This record is not to be touched. The call was refused, reported, and the kill switch is now set."));
    }
    const clientRefusal = this.#clientRefusal(client, true);
    if (clientRefusal) return this.#refused(base, clientRefusal);

    const highRisk = group === "spend" || op.tier === "sensitive";
    for (const t of targets) {
      const list = this.policy.allowlists[t.kind];
      const mustList = t.role === "payee" && highRisk;
      if (mustList && (!list || list.length === 0)) {
        return this.#refused(base, refuse("allowlist_empty", `The policy's allowlists.${t.kind} is missing or empty, so no ${group} call can name a payee.`, { how_to_enable: `Add the approved ${t.kind} values to ${this.loaded.path} (admin rights).` }));
      }
      if ((mustList || list) && !list!.includes(t.value)) {
        return this.#refused(base, refuse("not_allowlisted", `${t.kind} ${t.value} is not in the policy's allowlist.`, { how_to_enable: `A human adds it to allowlists.${t.kind} in ${this.loaded.path}.`, details: { kind: t.kind } }));
      }
    }
    if (group === "spend" && !targets.some((t) => t.role === "payee") && !extraction.notes?.some((n) => n.startsWith("no payee:"))) {
      return this.#refused(base, refuse("payee_unknown", `The server could not tell who ${op.operationId} pays, so it is refused.`));
    }
    if (highRisk) {
      for (const t of targets) {
        const src = this.session.untrustedSource(t.value);
        if (src) {
          return this.#refused(base, refuse("untrusted_target", `${t.kind} ${t.value} first appeared in text other people wrote (${src}) this session. A payee or security change taken from such text is refused.`, {
            how_to_enable: "Have the human confirm the value and run the call in a new session.",
          }));
        }
      }
    }

    let providerToday: number | null = null;
    if (group === "spend") {
      const amount = extraction.amount_cents;
      if (typeof amount !== "number" || !Number.isInteger(amount) || amount < 0) return this.#refused(base, refuse("amount_unknown", `The amount of this ${op.operationId} call could not be read, so it is refused.`));
      if (!extraction.currency) return this.#refused(base, refuse("currency_unknown", "The currency of this call could not be read, so it is refused."));
      const limits = this.policy.limits.spend;
      if (!limits) return this.#refused(base, refuse("spend_limits_missing", "The policy enables spend but sets no limits.spend; refused.", { how_to_enable: "Add limits.spend (unit, currency, per_call, per_day) to the policy." }));
      if (extraction.currency !== limits.currency) return this.#refused(base, refuse("currency_mismatch", `The policy's caps are in ${limits.currency}; this call is in ${extraction.currency}.`));
      if (limits.per_day !== undefined && this.#opts.providerTotals) {
        try {
          providerToday = await this.#opts.providerTotals(limits.currency);
          if (!Number.isFinite(providerToday)) throw new Error("not a number");
        } catch (e) {
          return this.#refused(base, refuse("provider_totals_unavailable", `Could not read today's total from the provider (${this.redact(String((e as Error)?.message ?? e))}), so the daily cap cannot be checked.`));
        }
      }
      const r = this.#spendRefusal(amount, limits.currency, this.ledger.snapshot(), providerToday);
      if (r) return this.#refused(base, r);
    }
    const rate = this.#rateRefusal(group, this.ledger.snapshot());
    if (rate) return this.#refused(base, rate);

    const chosen = selectApprover(approverFor(this.policy, group), extraction.amount_cents);
    const approver = this.#approvers[chosen.approver];
    if (!approver) return this.#refused(base, refuse("approver_unavailable", `This call needs approver "${chosen.approver}"${chosen.threshold !== undefined ? ` (over ${chosen.threshold} cents)` : ""}, which this version cannot run.`));
    if ((chosen.quorum ?? 1) > 1 || chosen.independent || chosen.delay) {
      return this.#refused(base, refuse("approval_feature_unavailable", "This amount needs quorum, independence or a delay (section 6.6), which arrive with G4a."));
    }
    base.approver = approver.name;

    if (op.flags?.egress && this.session.taint) {
      const rule = this.policy.taint.egress_after_untrusted;
      if (rule === "deny") return this.#refused(base, refuse("tainted_session", `This session read untrusted text (${this.session.taint.source}); the policy denies sending data out afterwards.`));
      if (rule === "approve" && !approver.human) {
        return this.#refused(base, refuse("tainted_session_needs_approval", `This session read untrusted text (${this.session.taint.source}), so ${op.operationId} needs a human approver, and this group's approver is "${approver.name}".`));
      }
    }

    // 5. Idempotency (before approval, so a retry never asks twice).
    const canonicalBody = canonicalJson({ path: request.pathParams ?? {}, query: request.query ?? {}, body: request.body ?? null });
    const requestHash = `sha256:${sha256Hex(canonicalBody)}`;
    base.request_hash = requestHash;
    const now = this.#clock();
    const today = utcDay(now);
    const yesterday = utcDay(new Date(now.getTime() - 86_400_000));
    const maxLength = this.#opts.idempotencyMaxLength ?? 255;
    const windowMs = this.#opts.idempotencyWindowMs ?? 10 * 60_000;
    const keyFor = (day: string) => deriveKey({ server: this.server, operation: op.operationId, canonicalBody, proposalDay: day, maxLength });
    const keyToday = keyFor(today);
    let existing: IdemEntry | null;
    try {
      existing = this.idempotency.lookup([keyToday], op.idempotencyKey ? {} : { windowMs }) ?? this.idempotency.lookup([keyFor(yesterday)], { windowMs });
    } catch (e) {
      return this.#refused(base, this.#stateRefusal(e));
    }
    const key = existing && existing.status === "unknown" ? existing.key : keyToday;
    base.idempotency_key = key;

    const dedup = (e: IdemEntry): ExecuteOutcome => {
      const at = e.finished_at ?? e.created_at;
      this.#write({ ...base, idempotency_key: e.key, decision: "deduplicated", http_status: e.result?.http_status ?? null, provider_ids: e.result?.provider_ids });
      return {
        status: "deduplicated",
        operation: op.operationId,
        idempotency_key: e.key,
        original: { status: e.status, at, http_status: e.result?.http_status, provider_ids: e.result?.provider_ids, data: e.result?.data, pending: e.result?.pending },
        message:
          `This exact request already ran at ${at} (${e.status}). Nothing new was sent; the original result is returned. ` +
          "A genuinely new call must differ in a body field (for example the description).",
      };
    };

    if (existing && !input.dryRun) {
      if (existing.status === "done" || existing.status === "pending") return dedup(existing);
      if (existing.status === "in_flight") return this.#refused(base, refuse("in_flight", "The same request is running right now in this or another session."));
      if (existing.status === "unknown" && !op.idempotencyKey) {
        return this.#refused(base, refuse("outcome_unknown", `An identical request at ${existing.created_at} has an unknown outcome and the provider has no idempotency key, so a retry could run it twice.`, {
          how_to_enable: `Check with ${this.toolName("read")} whether it happened. If it did not, a human runs mcp-guard cancel ${key.slice(-12)} to allow a retry.`,
        }));
      }
    }

    // dry_run stops here: no approver contact, nothing recorded.
    if (input.dryRun) {
      const proposal = buildProposal({ server: this.server, operation: op, group, mode: this.mode, extraction, client, requestHash, idempotencyKey: key, policyHash: this.loaded.hash, reason: input.reason, now });
      const effect =
        approver.name === "none"
          ? "Runs immediately; the harness rules for this tool still apply."
          : approver.name === "deny"
            ? "Refused: this group's approver is deny."
            : approver.name === "external"
              ? "Runs, and the provider holds it for a human to approve outside this agent."
              : `Needs approval from ${approver.name}.`;
      const preview: DryRunPreview = {
        operation: op.operationId,
        tier: op.tier,
        group,
        mode: this.mode,
        request: this.redactValue(jsonClone(request)),
        ...(typeof extraction.amount_cents === "number" ? { amount_cents: extraction.amount_cents } : {}),
        ...(extraction.currency ? { currency: extraction.currency } : {}),
        targets: this.redactValue(targets.map((t) => ({ ...t }))),
        client,
        approval: { approver: approver.name, effect },
        idempotency_key: key,
        ...(existing && (existing.status === "done" || existing.status === "pending")
          ? { duplicate_of: { status: existing.status, at: existing.finished_at ?? existing.created_at, provider_ids: existing.result?.provider_ids } }
          : {}),
        approval_text: proposalText(proposal, (t) => this.#redactor(t, this.#secrets())),
        note: "Dry run: every check passed and nothing was sent. Run again without dry_run to execute.",
      };
      this.#write({ ...base, decision: "dry_run" });
      return { status: "dry_run", preview };
    }

    // Claim the key before asking anyone.
    if (existing && existing.status === "unknown") {
      let reclaimed: boolean;
      try {
        reclaimed = this.idempotency.reclaimUnknown(key);
      } catch (e) {
        return this.#refused(base, this.#stateRefusal(e));
      }
      if (!reclaimed) return this.#refused(base, refuse("in_flight", "The same request was just claimed by another call."));
    } else {
      let claim: ReturnType<IdempotencyStore["begin"]>;
      try {
        claim = this.idempotency.begin(key, { operation: op.operationId, request_hash: requestHash, day: today }, op.idempotencyKey ? {} : { windowMs });
      } catch (e) {
        return this.#refused(base, this.#stateRefusal(e));
      }
      if (!claim.claimed) {
        const e = claim.existing;
        if (e.status === "done" || e.status === "pending") return dedup(e);
        if (e.status === "in_flight") return this.#refused(base, refuse("in_flight", "The same request is running right now in this or another session."));
        return this.#refused(base, refuse("outcome_unknown", `An identical request at ${e.created_at} has an unknown outcome.`));
      }
    }
    const release = () => void this.#finish(key, "failed");

    // 6. Approval.
    const proposal = buildProposal({ server: this.server, operation: op, group, mode: this.mode, extraction, client, requestHash, idempotencyKey: key, policyHash: this.loaded.hash, reason: input.reason, now });
    let decision;
    try {
      decision = await approver.request(proposal, proposalText(proposal, (t) => this.#redactor(t, this.#secrets())));
    } catch (e) {
      release();
      return this.#refused(base, refuse("approver_failed", `The approver failed: ${this.redact(String((e as Error)?.message ?? e))}`));
    }
    base.approver_result = decision.result;
    if (decision.result === "denied") {
      release();
      if (decision.human) this.#recordDenial(group);
      return this.#refused(base, refuse("approval_denied", decision.reason));
    }
    if (decision.result === "pending") {
      const stateNote = this.#finish(key, "pending", { pending: { ref: decision.ref, ...(decision.url ? { url: decision.url } : {}) } });
      this.#write({ ...base, decision: "pending", note: [decision.message, stateNote].filter(Boolean).join(" ") || undefined });
      return {
        status: "pending",
        operation: op.operationId,
        idempotency_key: key,
        hold: { ref: decision.ref, ...(decision.url ? { url: decision.url } : {}) },
        message: decision.message ?? "Waiting for a human approver. This agent cannot approve it.",
      };
    }

    // 7. Pre-image.
    if (PREIMAGE_TIERS.has(op.tier) && input.hooks?.fetchCurrent) {
      try {
        const current = await input.hooks.fetchCurrent(op, request);
        if (current !== undefined) this.#savePreimage(op, key, request, current);
      } catch (e) {
        release();
        return this.#refused(base, refuse("preimage_unavailable", `Could not save the current state before the change: ${this.redact(String((e as Error)?.message ?? e))}`));
      }
    }

    // 8. Execute: re-check, reserve, run the stored request.
    const stoppedNow = this.kill.stopped(group);
    if (stoppedNow) {
      release();
      return this.#refused(base, refuse("kill_switch", stoppedNow));
    }
    if (this.#currentPolicyHash() !== this.loaded.hash) {
      release();
      return this.#refused(base, refuse("policy_changed", "The policy file changed after this server started. Restart the server to load it."));
    }
    if (`sha256:${sha256Hex(canonicalJson({ path: request.pathParams ?? {}, query: request.query ?? {}, body: request.body ?? null }))}` !== requestHash) {
      release();
      return this.#refused(base, refuse("request_changed", "The stored request changed after it was checked; refused."));
    }
    const reservation = this.ledger.reserve(
      { group, op: op.operationId, ...(typeof extraction.amount_cents === "number" ? { cents: extraction.amount_cents } : {}), ...(extraction.currency ? { currency: extraction.currency } : {}) },
      (s) => (group === "spend" ? this.#spendRefusal(extraction.amount_cents as number, extraction.currency as string, s, providerToday) : null) ?? this.#rateRefusal(group, s)
    );
    if ("refusal" in reservation) {
      release();
      return this.#refused(base, reservation.refusal);
    }
    if (this.policy.client_scope?.lock_per_session && client !== null && !this.session.lockClient(client)) {
      release();
      this.ledger.settle(reservation.id, "failed");
      return this.#refused(base, refuse("client_locked", `This session is pinned to ${this.session.lockedClient}.`));
    }

    let res: HandlerResult;
    try {
      res = await handler(request, { idempotencyKey: key, operation: op, group, mode: this.mode });
    } catch (e) {
      res = { ok: false, error: { message: this.redact(String((e as Error)?.message ?? e)) }, sent: true };
    }
    const duration_ms = this.#clock().getTime() - started;

    // 9. Audit (and settle).
    if (!res.ok) {
      const rejected = !res.sent || (res.status !== undefined && res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 409);
      const error = this.redactValue(res.error);
      if (rejected) {
        const stateNote = this.#finish(key, "failed", { http_status: res.status ?? null });
        this.ledger.settle(reservation.id, "failed");
        this.#write({ ...base, decision: "failed", http_status: res.status ?? null, duration_ms, ...(stateNote ? { note: stateNote } : {}) });
        return {
          status: "failed",
          operation: op.operationId,
          idempotency_key: key,
          ...(res.status !== undefined ? { http_status: res.status } : {}),
          error,
          message: res.sent ? "The provider rejected the request; nothing was done." : "The request was not sent.",
        };
      }
      const stateNote = this.#finish(key, "unknown", { http_status: res.status ?? null });
      this.ledger.settle(reservation.id, "unknown");
      this.#write({ ...base, decision: "unknown_outcome", http_status: res.status ?? null, duration_ms, ...(stateNote ? { note: stateNote } : {}) });
      return {
        status: "unknown_outcome",
        operation: op.operationId,
        idempotency_key: key,
        ...(res.status !== undefined ? { http_status: res.status } : {}),
        error,
        message:
          `The provider may or may not have done this. Check with ${this.toolName("read")} before anything else. ` +
          (op.idempotencyKey ? "Retrying the same request reuses the same idempotency key, so the provider will not run it twice." : "An identical retry is refused until a human clears it."),
      };
    }

    const data = sanitizeDeep(this.redactValue(res.data));
    const providerIds = res.providerIds?.map((id) => this.redact(id));
    const hold: ExternalHold = input.hooks?.external ? input.hooks.external(op, { status: res.status, data: res.data }) : { held: false };
    const warnings: string[] = [];
    if (approver.name === "external" && !hold.held) {
      const reason = `${op.operationId} ran under the external approver but the provider did not hold it for a human.`;
      if (this.mode === "sandbox") warnings.push(`${reason} (Sandbox: the key may not have approvals configured.)`);
      else {
        this.kill.trip(group, reason);
        warnings.push(`${reason} The ${group} kill switch is now set.`);
        this.#write({ ...base, decision: "alert", alert: "external_not_held", note: reason, provider_ids: providerIds });
      }
    }
    const stored = JSON.stringify(data);
    const result = {
      http_status: res.status ?? null,
      ...(providerIds?.length ? { provider_ids: providerIds } : {}),
      ...(stored !== undefined && stored.length <= DEDUP_DATA_CHARS ? { data } : {}),
      ...(hold.held ? { pending: { ref: hold.ref, status: hold.status, url: hold.url } } : {}),
    };
    const stateNote = this.#finish(key, hold.held ? "pending" : "done", result);
    if (stateNote) warnings.push(stateNote);
    this.ledger.settle(reservation.id, hold.held ? "pending" : "done");
    this.#write({ ...base, decision: hold.held ? "pending" : "executed", http_status: res.status ?? null, provider_ids: providerIds, duration_ms, ...(warnings.length ? { note: warnings.join(" ") } : {}) });

    if (hold.held) {
      return {
        status: "pending",
        operation: op.operationId,
        idempotency_key: key,
        ...(res.status !== undefined ? { http_status: res.status } : {}),
        ...(providerIds?.length ? { provider_ids: providerIds } : {}),
        hold,
        data,
        message: hold.message ?? "The provider is holding this for a human to approve. This agent cannot approve it.",
      };
    }
    return {
      status: "done",
      operation: op.operationId,
      idempotency_key: key,
      ...(res.status !== undefined ? { http_status: res.status } : {}),
      ...(providerIds?.length ? { provider_ids: providerIds } : {}),
      data,
      ...(warnings.length ? { warnings } : {}),
    };
  }

  async #prepare(op: OperationRef, raw: GuardRequest | undefined, prepare?: PrepareHook): Promise<{ request: GuardRequest } | { refusal: Refusal }> {
    const request = deepFreeze(jsonClone(raw ?? {})) as GuardRequest;
    if (!prepare) return { request };
    try {
      const out = await prepare(op, request);
      if (isRefusal(out)) return { refusal: out };
      return { request: deepFreeze(jsonClone(out ?? {})) as GuardRequest };
    } catch (e) {
      return { refusal: refuse("invalid_request", this.redact(String((e as Error)?.message ?? e))) };
    }
  }

  #recordDenial(group: Group): void {
    const now = this.#clock().getTime();
    const recent = (this.#denials.get(group) ?? []).filter((t) => now - t < DENIAL_WINDOW_MS);
    recent.push(now);
    this.#denials.set(group, recent);
    if (recent.length >= 2) this.kill.trip(group, `Denial breaker: ${recent.length} human denials within 30 minutes.`);
  }

  #savePreimage(op: OperationRef, key: string, request: GuardRequest, current: unknown): void {
    const dir = join(this.stateDir, "preimages");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const stamp = this.#clock().toISOString().replace(/[:.]/g, "-");
    const file = join(dir, `${stamp}-${op.operationId.replace(/[^A-Za-z0-9_-]/g, "_")}-${key.slice(-12)}.json`);
    writeFileSync(file, JSON.stringify({ operation: op.operationId, tier: op.tier, request, idempotency_key: key, saved_at: this.#clock().toISOString(), current }, null, 2), { mode: 0o600 });
  }

  // ---------------------------------------------------------------- read path

  async read(input: ReadInput, handler: Handler): Promise<ReadOutcome> {
    const op = input.operation;
    const base = this.#auditBase({ tool: input.tool, operation: op, operationId: input.operationId, group: "read" });
    const auditReads = this.policy.audit.reads;
    const refused = (r: Refusal, always = false): ReadOutcome => {
      const red = this.redactValue(r);
      if (auditReads || always) this.#write({ ...base, decision: "refused", reason_code: red.reason_code });
      return { status: "refused", refusal: red };
    };
    if (!op) {
      return refused(
        refuse("unknown_operation", `Unknown operation ${JSON.stringify(String(input.operationId).slice(0, 200))}.${input.suggestions?.length ? ` Did you mean: ${input.suggestions.join(", ")}?` : ""}`, {
          how_to_enable: `Find operations with ${this.prefix}_list_endpoints.`,
        })
      );
    }
    const opGroup = TIER_GROUP[op.tier];
    if (opGroup === null) return refused(refuse("blocked", `${op.operationId} is tier "blocked": it is never exposed to an agent.`), true);
    if (opGroup !== "read") {
      return refused(refuse("wrong_group", `${op.operationId} is tier "${op.tier}"; ${input.tool} only runs reads.`, { how_to_enable: `It runs only through ${this.toolName(opGroup)}, if the policy enables that group.` }), true);
    }
    const state = this.effective.groups.read;
    if (!state.enabled) return refused(refuse(state.reason_code ?? "group_off", state.reason ?? "Reads are off."));
    if (this.policy.tiers_off.includes("read")) return refused(refuse("tier_off", "Tier read is in the policy's tiers_off."));

    const prepared = await this.#prepare(op, input.request, input.prepare);
    if ("refusal" in prepared) return refused(prepared.refusal);
    const request = prepared.request;
    let extraction: Extraction = {};
    if (input.extract) {
      try {
        const ex = await input.extract(op, request);
        if (isRefusal(ex)) return refused(ex);
        extraction = ex;
      } catch (e) {
        return refused(refuse("extract_failed", `Could not check this call's arguments: ${this.redact(String((e as Error)?.message ?? e))}`));
      }
    }
    const client = this.#client(extraction);
    base.client = client;
    const clientRefusal = this.#clientRefusal(client, false);
    if (clientRefusal) return refused(clientRefusal, true);

    const canary = this.canaries.match(this.#canaryValues(request, extraction.targets ?? []));
    if (canary) this.#write({ ...base, decision: "alert", alert: "canary_read", note: `Read of a decoy record via ${op.operationId}.` });

    let reservation: { id: string } | null = null;
    if (Object.keys(this.policy.limits.rate ?? {}).some((k) => k.startsWith("read_per_"))) {
      const r = this.ledger.reserve({ group: "read", op: op.operationId }, (s) => this.#rateRefusal("read", s));
      if ("refusal" in r) return refused(r.refusal);
      reservation = r;
    }

    let res: HandlerResult;
    try {
      res = await handler(request, { idempotencyKey: null, operation: op, group: "read", mode: this.mode });
    } catch (e) {
      res = { ok: false, error: { message: this.redact(String((e as Error)?.message ?? e)) }, sent: true };
    }
    if (reservation) this.ledger.settle(reservation.id, res.ok ? "done" : "failed");
    if (!res.ok) {
      if (auditReads) this.#write({ ...base, decision: "failed", http_status: res.status ?? null });
      return { status: "failed", operation: op.operationId, ...(res.status !== undefined ? { http_status: res.status } : {}), error: this.redactValue(res.error) };
    }

    // Untrusted content (7.9): label, sanitize, taint, provenance.
    const source = `${this.server}.${op.operationId}`;
    let data: unknown = this.redactValue(res.data);
    let untrustedCount = 0;
    if (op.flags?.untrusted_output) {
      if (input.untrustedFields?.length) {
        const labelled = labelUntrustedFields(data, input.untrustedFields, source);
        data = labelled.value;
        this.session.recordTrusted(trustedLeaves(data));
        this.session.recordUntrusted(labelled.texts, source);
        untrustedCount = labelled.texts.length;
        if (untrustedCount) this.session.markTainted(source, this.#clock());
      } else {
        // No field list: the whole result is untrusted.
        this.session.recordUntrusted(trustedLeaves(data), source);
        this.session.markTainted(source, this.#clock());
        untrustedCount = 1;
      }
    } else {
      this.session.recordTrusted(trustedLeaves(data));
    }
    data = sanitizeDeep(data);
    if (auditReads) this.#write({ ...base, decision: "read", http_status: res.status ?? null });
    return { status: "done", operation: op.operationId, ...(res.status !== undefined ? { http_status: res.status } : {}), data, untrusted_fields: untrustedCount };
  }

  // ---------------------------------------------------------------- status, manifest, resources

  status(): GuardStatus {
    const groups = {} as GuardStatus["groups"];
    const stopped = {} as Record<Group, string | null>;
    for (const g of GROUPS) {
      groups[g] = { ...this.effective.groups[g], approver: this.effective.approvers[g], tool: this.toolName(g) };
      stopped[g] = this.kill.stopped(g);
    }
    const limits = this.policy.limits.spend;
    let ledgerToday: number | undefined;
    try {
      ledgerToday = limits ? this.ledger.snapshot().spendToday(limits.currency) : undefined;
    } catch {
      ledgerToday = undefined;
    }
    return {
      server: this.server,
      version: this.version,
      guard_version: GUARD_VERSION,
      session: this.session.id,
      mode: this.mode,
      policy: { source: this.loaded.source, path: this.loaded.path, override: this.loaded.override, hash: this.loaded.hash, ...(this.loaded.error ? { error: this.loaded.error } : {}) },
      protection: this.protection,
      groups,
      kill: { ...this.kill.state(), stopped },
      taint: this.session.taint,
      client_lock: this.session.lockedClient,
      spend: {
        ...(limits ? { currency: limits.currency, per_call: limits.per_call, per_day: limits.per_day } : {}),
        ...(ledgerToday !== undefined ? { ledger_today: ledgerToday } : {}),
        provider_totals: !!this.#opts.providerTotals,
      },
      state_dir: this.stateDir,
      warnings: [...this.warnings],
    };
  }

  manifest(operations: readonly OperationRef[], extraTools: Array<{ name: string; group: Group }> = [], opts: { groupTools?: boolean } = {}): GuardManifest {
    const unattended: Partial<Record<Group, boolean>> = {};
    for (const g of GROUPS) unattended[g] = !this.toolConfig(g)._meta && (g === "critical" || g === "spend");
    return buildManifest({ server: this.server, version: this.version, prefix: this.prefix, operations, extraTools, unattended, groupTools: opts.groupTools });
  }

  /** guard://manifest and guard://status (sections 4 and 7.5). */
  registerResources(server: McpServer, manifest: () => GuardManifest): void {
    server.registerResource(
      "guard-manifest",
      "guard://manifest",
      { title: "Guard manifest", description: "Every tool's group and every operation's tier.", mimeType: "application/json" },
      async (uri) => ({ contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(manifest()) }] })
    );
    server.registerResource(
      "guard-status",
      "guard://status",
      { title: "Guard status", description: "Effective groups, policy source and protection, mode, approvers, kill switch and taint: why a call is refused.", mimeType: "application/json" },
      async (uri) => ({ contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(this.status()) }] })
    );
  }
}

export function createGuard<P extends BasePolicy = BasePolicy>(opts: GuardOptions<P>): Guard<P> {
  return new Guard<P>(opts);
}
