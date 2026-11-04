/**
 * The tiers.json checker for build scripts (phase G2, conformance 7.6 item 1):
 * every operation has exactly one valid tier, flags are known, and an operation
 * that is not a GET only counts as `read` when the file says why.
 */
import { TIERS, type OperationFlags, type Tier } from "./tiers.js";

export const KNOWN_FLAGS: readonly (keyof OperationFlags)[] = Object.freeze(["untrusted_output", "egress"]);

export interface TierEntry {
  tier?: unknown;
  flags?: unknown;
  [key: string]: unknown;
}

export interface TiersCheckInput {
  /** The operations the spec or catalog defines (method upper or lower case). */
  operations: ReadonlyArray<{ operationId: string; method?: string; path?: string }>;
  /** operationId -> entry (the `operations` object of a tiers.json). */
  tiers: Readonly<Record<string, TierEntry>>;
  /** The entry key that explains a non-GET read (default `read_reason`). */
  nonGetReadKey?: string;
  /** Entries for operations the spec no longer has are errors unless this is true. */
  allowExtra?: boolean;
}

export type TiersIssueCode = "missing" | "unknown_tier" | "unknown_flag" | "bad_flag" | "non_get_read" | "extra";

export interface TiersIssue {
  operationId: string;
  code: TiersIssueCode;
  message: string;
}

export interface TiersCheckResult {
  ok: boolean;
  issues: TiersIssue[];
  counts: Record<Tier, number>;
}

export function checkTiers(input: TiersCheckInput): TiersCheckResult {
  const key = input.nonGetReadKey ?? "read_reason";
  const issues: TiersIssue[] = [];
  const counts = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
  const seen = new Set<string>();

  for (const op of input.operations) {
    seen.add(op.operationId);
    const e = Object.prototype.hasOwnProperty.call(input.tiers, op.operationId) ? input.tiers[op.operationId] : undefined;
    const where = `${op.method ? op.method.toUpperCase() + " " : ""}${op.path ?? ""}`.trim();
    if (!e || e.tier === undefined) {
      issues.push({ operationId: op.operationId, code: "missing", message: `${op.operationId}${where ? ` (${where})` : ""} has no tier.` });
      continue;
    }
    if (typeof e.tier !== "string" || !(TIERS as readonly string[]).includes(e.tier)) {
      issues.push({ operationId: op.operationId, code: "unknown_tier", message: `${op.operationId}: tier ${JSON.stringify(e.tier)} is not one of ${TIERS.join(", ")}.` });
      continue;
    }
    counts[e.tier as Tier]++;
    if (e.flags !== undefined) {
      if (!e.flags || typeof e.flags !== "object" || Array.isArray(e.flags)) {
        issues.push({ operationId: op.operationId, code: "bad_flag", message: `${op.operationId}: flags must be an object.` });
      } else {
        for (const [f, v] of Object.entries(e.flags as Record<string, unknown>)) {
          if (!(KNOWN_FLAGS as readonly string[]).includes(f)) {
            issues.push({ operationId: op.operationId, code: "unknown_flag", message: `${op.operationId}: unknown flag ${JSON.stringify(f)} (known: ${KNOWN_FLAGS.join(", ")}).` });
          } else if (typeof v !== "boolean") {
            issues.push({ operationId: op.operationId, code: "bad_flag", message: `${op.operationId}: flag ${f} must be true or false.` });
          }
        }
      }
    }
    const method = (op.method ?? "GET").toUpperCase();
    if (e.tier === "read" && method !== "GET" && method !== "HEAD") {
      const why = e[key];
      if (typeof why !== "string" || why.trim().length < 10) {
        issues.push({
          operationId: op.operationId,
          code: "non_get_read",
          message: `${op.operationId} (${where}) is a ${method} marked read. Say why it has no side effects in "${key}", or give it a write tier.`,
        });
      }
    }
  }

  if (!input.allowExtra) {
    for (const id of Object.keys(input.tiers)) {
      if (!seen.has(id) && !id.startsWith("$")) {
        issues.push({ operationId: id, code: "extra", message: `${id} is in the tiers file but not in the spec.` });
      }
    }
  }
  return { ok: issues.length === 0, issues, counts };
}

/** Throw with every issue listed (for build scripts). */
export function assertTiers(input: TiersCheckInput): TiersCheckResult {
  const r = checkTiers(input);
  if (!r.ok) throw new Error(`tiers check failed (${r.issues.length}):\n${r.issues.map((i) => `  - [${i.code}] ${i.message}`).join("\n")}`);
  return r;
}

/** Copy only the known flags that are true (what the catalog assembler writes into an OperationRef). */
export function flagsOf(entry: TierEntry | undefined): OperationFlags | undefined {
  if (!entry?.flags || typeof entry.flags !== "object") return undefined;
  const out: OperationFlags = {};
  for (const f of KNOWN_FLAGS) if ((entry.flags as Record<string, unknown>)[f] === true) out[f] = true;
  return Object.keys(out).length ? out : undefined;
}
