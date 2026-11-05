/**
 * Tiers and tool groups (guard plan, section 4).
 *
 * Every operation has exactly one tier. Tiers roll up into four tool groups, and
 * harness rules target groups, so the group names and tool suffixes are fixed here
 * and identical on every server.
 */
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

export const TIERS = ["read", "reducing", "write", "destructive", "sensitive", "spend", "sandbox", "blocked"] as const;
export type Tier = (typeof TIERS)[number];

export const GROUPS = ["read", "change", "critical", "spend"] as const;
export type Group = (typeof GROUPS)[number];

/** Tier -> group. `blocked` has no group: it is never registered. */
export const TIER_GROUP: Readonly<Record<Tier, Group | null>> = Object.freeze({
  read: "read",
  reducing: "change",
  write: "change",
  sandbox: "change",
  destructive: "critical",
  sensitive: "critical",
  spend: "spend",
  blocked: null,
});

/** The tiers each group runs. */
export const GROUP_TIERS: Readonly<Record<Group, readonly Tier[]>> = Object.freeze({
  read: Object.freeze(["read"] as Tier[]),
  change: Object.freeze(["reducing", "write", "sandbox"] as Tier[]),
  critical: Object.freeze(["destructive", "sensitive"] as Tier[]),
  spend: Object.freeze(["spend"] as Tier[]),
});

/** Groups that are off unless a policy turns them on. */
export const DEFAULT_GROUPS: Readonly<Record<Group, boolean>> = Object.freeze({
  read: true,
  change: false,
  critical: false,
  spend: false,
});

/** Groups an unprotected policy can never enable outside sandbox mode (5.1). */
export const HIGH_RISK_GROUPS: readonly Group[] = Object.freeze(["critical", "spend"]);

export const REQUIRES_USER_INTERACTION = "anthropic/requiresUserInteraction";

/** MCP annotations per group (section 4 table). */
export const GROUP_ANNOTATIONS: Readonly<Record<Group, ToolAnnotations>> = Object.freeze({
  read: Object.freeze({ readOnlyHint: true, openWorldHint: true }),
  change: Object.freeze({ readOnlyHint: false, destructiveHint: false, openWorldHint: true }),
  critical: Object.freeze({ readOnlyHint: false, destructiveHint: true, openWorldHint: true }),
  spend: Object.freeze({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }),
});

/**
 * `_meta` per group. `critical` and `spend` ask the client for user interaction on
 * every call. With `unattended: true` for a human approver (duo/passkey), the guard
 * leaves it off for that group (6.5); that decision is made by the caller.
 */
export function groupMeta(group: Group, opts: { unattended?: boolean } = {}): Record<string, unknown> | undefined {
  if ((group === "critical" || group === "spend") && !opts.unattended) return { [REQUIRES_USER_INTERACTION]: true };
  return undefined;
}

/** `<prefix>_<group>`, e.g. `column_spend`. */
export function groupToolName(prefix: string, group: Group): string {
  return `${prefix}_${group}`;
}

export function isTier(value: unknown): value is Tier {
  return typeof value === "string" && (TIERS as readonly string[]).includes(value);
}

export function isGroup(value: unknown): value is Group {
  return typeof value === "string" && (GROUPS as readonly string[]).includes(value);
}

/** Operation flags carried from a server's tiers.json (7.9). */
export interface OperationFlags {
  /** Returns text other people wrote (CRM notes, emails, payment descriptions). */
  untrusted_output?: boolean;
  /** Sends data out (a message, an email, a webhook, a share link). */
  egress?: boolean;
}

/** The minimum the guard needs to know about an operation. */
export interface OperationRef {
  /** Catalog id (snake_case) or hand-written tool's operation name. */
  operationId: string;
  tier: Tier;
  method?: string;
  path?: string;
  flags?: OperationFlags;
  /** The provider honours an idempotency key for this operation. */
  idempotencyKey?: boolean;
}
