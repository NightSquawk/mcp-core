/**
 * Proposals and approvers (sections 6.4 and 6.7).
 *
 * A proposal is the canonical summary core writes from the parsed request. It is
 * what a human approver sees. Model-written text appears only in the final
 * "Agent says (unverified)" line, sanitized and cut to 200 characters.
 *
 * G1 implements `none`, `deny` and `external`. `duo` and `passkey` arrive in G4;
 * until then a policy naming them turns the group off (fail closed).
 */
import { canonicalJson, nonce, sha256Hex } from "./canonical.js";
import type { ApproverName } from "./policy.js";
import { redact as sharedRedact, type Redactor } from "./redact.js";
import { sanitizeUntrusted } from "./sanitize.js";
import type { Group, OperationRef, Tier } from "./tiers.js";

export type Mode = "sandbox" | "live" | "none";

/** A value the call acts on. `payee` targets of spend and sensitive calls must be allowlisted. */
export interface Target {
  /** The allowlist key, e.g. `counterparty_id`. */
  kind: string;
  value: string;
  role: "payee" | "source" | "subject";
}

/** What a server's extractor reports about one call (section 6 step 4). */
export interface Extraction {
  /** Integer minor units (cents). Required for spend calls. */
  amount_cents?: number | null;
  /** ISO 4217, upper case. */
  currency?: string | null;
  targets?: Target[];
  /** The Rule 11 client tag (7.11). */
  client?: string | null;
  /** Core-relevant facts to show the approver (written by the server, never by the model). */
  notes?: string[];
}

/** How long an approval stays usable (6.4: within 5 minutes). */
export const PROPOSAL_TTL_MS = 5 * 60_000;
/** The model's `reason` as shown to approvers. */
export const AGENT_SAYS_MAX = 200;

export interface Proposal {
  server: string;
  operation: string;
  tier: Tier;
  group: Group;
  mode: Mode;
  amount_cents?: number;
  currency?: string;
  targets: Target[];
  client?: string | null;
  /** sha256 of the canonical stored request. */
  request_hash: string;
  idempotency_key: string;
  /** sha256 of the policy file, or null for the built-in default. */
  policy_hash: string | null;
  created_at: string;
  expires_at: string;
  nonce: string;
  /** Core-written facts (provenance, thresholds). */
  notes: string[];
  /** The model's reason: sanitized, cut, and shown last with an "unverified" label. */
  agent_says?: string;
  /** Binds everything above (6.7). */
  hash: string;
}

export interface ProposalInput {
  server: string;
  operation: OperationRef;
  group: Group;
  mode: Mode;
  extraction: Extraction;
  requestHash: string;
  idempotencyKey: string;
  policyHash: string | null;
  reason?: string;
  now: Date;
}

/** Sanitize and cut the model's reason for display (6.5, 7.9). */
export function agentSays(reason: string | undefined): string | undefined {
  if (reason === undefined) return undefined;
  const clean = sanitizeUntrusted(reason).replace(/\s+/g, " ").trim();
  if (!clean) return undefined;
  return clean.length > AGENT_SAYS_MAX ? `${clean.slice(0, AGENT_SAYS_MAX - 3)}...` : clean;
}

export function buildProposal(input: ProposalInput): Proposal {
  const ex = input.extraction;
  const body = {
    server: input.server,
    operation: input.operation.operationId,
    tier: input.operation.tier,
    group: input.group,
    mode: input.mode,
    ...(typeof ex.amount_cents === "number" ? { amount_cents: ex.amount_cents } : {}),
    ...(ex.currency ? { currency: ex.currency } : {}),
    targets: (ex.targets ?? []).map((t) => ({ kind: t.kind, value: t.value, role: t.role })),
    client: ex.client ?? null,
    request_hash: input.requestHash,
    idempotency_key: input.idempotencyKey,
    policy_hash: input.policyHash,
    created_at: input.now.toISOString(),
    expires_at: new Date(input.now.getTime() + PROPOSAL_TTL_MS).toISOString(),
    nonce: nonce(),
    notes: (ex.notes ?? []).map((n) => sanitizeUntrusted(n)),
    ...(agentSays(input.reason) !== undefined ? { agent_says: agentSays(input.reason) } : {}),
  };
  return { ...body, hash: `sha256:${sha256Hex(canonicalJson(body))}` };
}

function money(cents: number, currency?: string): string {
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(cents);
  return `${sign}${Math.floor(abs / 100).toLocaleString("en-US")}.${String(abs % 100).padStart(2, "0")}${currency ? ` ${currency}` : ""}`;
}

/**
 * The text an approver sees. Everything except the last line is written by core
 * from parsed values and passed through redact(); the model's reason comes last.
 */
export function proposalText(p: Proposal, redactor: Redactor = sharedRedact): string {
  const lines = [
    `${p.server}: ${p.operation} (${p.tier}, ${p.mode})`,
    ...(p.amount_cents !== undefined ? [`Amount: ${money(p.amount_cents, p.currency)}`] : []),
    ...p.targets.map((t) => `${t.role === "payee" ? "Payee" : t.role === "source" ? "From" : "Target"} ${t.kind}: ${t.value}`),
    ...(p.client ? [`Client: ${p.client}`] : []),
    ...p.notes.map((n) => `Note: ${n}`),
    `Proposal ${p.hash.slice(7, 15)}, expires ${p.expires_at}`,
  ].map((l) => sanitizeUntrusted(redactor(l)));
  if (p.agent_says) lines.push(`Agent says (unverified): ${sanitizeUntrusted(redactor(p.agent_says))}`);
  return lines.join("\n");
}

export type ApprovalDecision =
  | { result: "approved"; approver: ApproverName; human: boolean }
  /** Run it; the provider holds the result for a human (external). */
  | { result: "passthrough"; approver: ApproverName }
  /** Waiting for a human outside this call (G4). */
  | { result: "pending"; approver: ApproverName; ref: string; url?: string; message?: string }
  | { result: "denied"; approver: ApproverName; human: boolean; reason: string };

export interface Approver {
  readonly name: ApproverName;
  /** A person decides. The denial breaker counts only these (6.7). */
  readonly human: boolean;
  request(proposal: Proposal, text: string): Promise<ApprovalDecision>;
}

export const noneApprover: Approver = Object.freeze({
  name: "none" as const,
  human: false,
  request: async (): Promise<ApprovalDecision> => ({ result: "approved", approver: "none", human: false }),
});

export const denyApprover: Approver = Object.freeze({
  name: "deny" as const,
  human: false,
  request: async (): Promise<ApprovalDecision> => ({
    result: "denied",
    approver: "deny",
    human: false,
    reason: "The policy's approver for this group is \"deny\": the tool exists so the operation is visible, but it never runs.",
  }),
});

/** The provider holds the action for a human (Column `pre_review`). Core passes the call through. */
export const externalApprover: Approver = Object.freeze({
  name: "external" as const,
  human: true,
  request: async (): Promise<ApprovalDecision> => ({ result: "passthrough", approver: "external" }),
});

export const BUILTIN_APPROVERS: Readonly<Partial<Record<ApproverName, Approver>>> = Object.freeze({
  none: noneApprover,
  deny: denyApprover,
  external: externalApprover,
});

/** What the server learned from the provider's answer to an `external` call. */
export interface ExternalHold {
  /** The provider is holding the action for a human. */
  held: boolean;
  ref?: string;
  status?: string;
  url?: string;
  /** Shown to the model, e.g. "approve it in the dashboard; this agent cannot". */
  message?: string;
}

/**
 * The approver for a call: the highest `tiers` threshold the amount is over, else
 * the group's approver (5.4, 6.6).
 */
export function selectApprover(
  cfg: { approver: ApproverName; tiers?: Array<{ over_cents: number; approver: ApproverName; quorum?: number; independent?: boolean; delay?: string }> },
  amountCents: number | null | undefined
): { approver: ApproverName; threshold?: number; quorum?: number; independent?: boolean; delay?: string } {
  if (typeof amountCents === "number" && cfg.tiers?.length) {
    const over = cfg.tiers.filter((t) => amountCents > t.over_cents).sort((a, b) => b.over_cents - a.over_cents);
    if (over.length) {
      const t = over[0];
      return { approver: t.approver, threshold: t.over_cents, quorum: t.quorum, independent: t.independent, delay: t.delay };
    }
  }
  return { approver: cfg.approver };
}
