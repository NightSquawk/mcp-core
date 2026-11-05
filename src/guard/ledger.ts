/**
 * Rolling per-day totals and rate counters (section 7.2). Advisory: rebuilt from
 * the audit log when it is missing, corrupt or not a ledger, and cross-checked
 * with the server's providerTotals() for spend caps. Shared by every session on
 * the machine (file + lock).
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { AuditLog } from "./audit.js";
import { nonce, utcDay } from "./canonical.js";
import { readJsonFile, withFileLock, writeJsonFile } from "./lock.js";
import { GROUPS, type Group } from "./tiers.js";

export type LedgerStatus = "reserved" | "done" | "pending" | "unknown" | "failed";

export interface LedgerEvent {
  id: string;
  t: number;
  group: Group;
  op: string;
  /** The call's idempotency key, so that mcp-guard cancel can release its reservation. */
  key?: string;
  cents?: number;
  currency?: string;
  status: LedgerStatus;
}

interface LedgerFile {
  version: 1;
  rebuilt_from_audit?: string;
  events: LedgerEvent[];
}

const KEEP_MS = 49 * 3_600_000;
/** The audit alert mcp-guard cancel writes; a rebuild releases the call it names. */
export const CANCEL_ALERT = "cli_cancel";
/** Reservations a call that did not finish still holds. */
const OPEN: ReadonlySet<LedgerStatus> = new Set(["reserved", "pending", "unknown"]);
const WINDOW_MS = { minute: 60_000, hour: 3_600_000 } as const;
const STATUSES: ReadonlySet<unknown> = new Set<LedgerStatus>(["reserved", "done", "pending", "unknown", "failed"]);
const GROUP_NAMES: ReadonlySet<unknown> = new Set<Group>(GROUPS);

const optional = (v: unknown, ok: (x: unknown) => boolean) => v === undefined || ok(v);
const isText = (v: unknown) => typeof v === "string";
const isNumber = (v: unknown) => typeof v === "number" && Number.isFinite(v);

function isLedgerEvent(v: unknown): v is LedgerEvent {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    isText(e.id) &&
    isNumber(e.t) &&
    GROUP_NAMES.has(e.group) &&
    isText(e.op) &&
    STATUSES.has(e.status) &&
    optional(e.key, isText) &&
    optional(e.cents, isNumber) &&
    optional(e.currency, isText)
  );
}

/** A ledger file whose every event has the fields the counts read, each of the right type. */
function isLedgerFile(v: unknown): v is LedgerFile {
  if (typeof v !== "object" || v === null) return false;
  const events = (v as { events?: unknown }).events;
  return Array.isArray(events) && events.every(isLedgerEvent);
}

/** An earlier attempt, outcome unknown, of the call a retry under `key` sends again. */
const replaces = (e: LedgerEvent, key: string | undefined) => key !== undefined && e.key === key && e.status === "unknown";

export interface LedgerSnapshot {
  /** Spend counted today (UTC) in `currency`, from this ledger. */
  spendToday(currency: string): number;
  /** Calls in a group within a window: `minute`/`hour` are rolling, `day` is the UTC day. */
  count(group: Group, window: "minute" | "hour" | "day"): number;
}

export class Ledger {
  readonly file: string;
  readonly #lock: string;
  readonly #clock: () => Date;
  readonly #audit?: AuditLog;

  constructor(dir: string, opts: { clock?: () => Date; audit?: AuditLog } = {}) {
    this.file = join(dir, "ledger.json");
    this.#lock = join(dir, "ledger.lock");
    this.#clock = opts.clock ?? (() => new Date());
    this.#audit = opts.audit;
  }

  #load(): LedgerFile {
    if (!existsSync(this.file) && this.#audit) return this.#rebuild();
    let f: unknown = null;
    try {
      f = readJsonFile<unknown>(this.file, { version: 1, events: [] });
    } catch {
      // corrupt JSON: rebuilt below
    }
    if (isLedgerFile(f)) return f;
    // Corrupt, or JSON that is not a ledger ({} after a bad repair, an event with a misspelt group):
    // read as empty, it would count no calls and no spend. The audit log holds them all.
    return this.#audit ? this.#rebuild() : { version: 1, events: [] };
  }

  /**
   * Rebuild from the audit log: every executed, pending or unknown-outcome call, less the ones
   * mcp-guard cancel released, and every read that reached the provider (the guard audits each
   * read a read limit counts, whatever audit.reads says).
   */
  #rebuild(): LedgerFile {
    const events: LedgerEvent[] = [];
    for (const l of this.#audit?.read() ?? []) {
      if (l.alert === CANCEL_ALERT && typeof l.idempotency_key === "string") {
        // Only what the call recorded before the cancel. A retry claims the key once cancel frees
        // it, and may be written before this line: it is a new call and keeps counting.
        const cut = typeof l.cancelled_at === "string" && !Number.isNaN(Date.parse(l.cancelled_at)) ? Date.parse(l.cancelled_at) : Date.parse(l.ts);
        for (const e of events) if (e.key === l.idempotency_key && OPEN.has(e.status) && e.t < cut) e.status = "failed";
        continue;
      }
      // read() already drops lines that are not audit lines; also skip ones with fields of the wrong type.
      if (typeof l.group !== "string" || l.dry_run || Number.isNaN(Date.parse(l.ts)) || typeof l.operation !== "string") continue;
      const status: LedgerStatus | null =
        l.decision === "executed"
          ? "done"
          : l.decision === "pending"
            ? "pending"
            : l.decision === "unknown_outcome"
              ? "unknown"
              : l.group === "read" && (l.decision === "read" || (l.decision === "failed" && l.sent === true))
                ? "done"
                : null;
      if (!status) continue;
      // A retry under the same key (a provider that dedupes on it) is the same call: it replaces an
      // earlier attempt whose outcome was unknown, as reserve() does when it runs.
      if (typeof l.idempotency_key === "string") for (const e of events) if (e.key === l.idempotency_key && e.status === "unknown") e.status = "failed";
      events.push({
        id: `audit-${l.hash.slice(7, 19)}`,
        t: Date.parse(l.ts),
        group: l.group,
        op: l.operation,
        ...(typeof l.idempotency_key === "string" ? { key: l.idempotency_key } : {}),
        ...(typeof l.amount_cents === "number" && Number.isFinite(l.amount_cents) ? { cents: l.amount_cents } : {}),
        ...(typeof l.currency === "string" ? { currency: l.currency } : {}),
        status,
      });
    }
    return { version: 1, rebuilt_from_audit: this.#clock().toISOString(), events };
  }

  #snapshot(f: LedgerFile, replacing?: string): LedgerSnapshot {
    const now = this.#clock();
    const today = utcDay(now);
    const live = f.events.filter((e) => e.status !== "failed" && !replaces(e, replacing));
    return {
      spendToday: (currency) =>
        live
          .filter((e) => e.group === "spend" && e.currency === currency && utcDay(new Date(e.t)) === today)
          .reduce((sum, e) => sum + (e.cents ?? 0), 0),
      count: (group, window) =>
        live.filter((e) => e.group === group && (window === "day" ? utcDay(new Date(e.t)) === today : now.getTime() - e.t < WINDOW_MS[window]))
          .length,
    };
  }

  /**
   * A read-only view (dry runs and step 4 checks). `replacing` is the key of an unknown-outcome call
   * that this call retries under the same key: the totals leave that attempt out, since the retry is
   * the same call and is counted in its place.
   */
  snapshot(opts: { replacing?: string } = {}): LedgerSnapshot {
    return this.#snapshot(this.#load(), opts.replacing);
  }

  /**
   * Check and reserve atomically (step 8 re-check): `check` sees the totals under
   * the lock; when it returns null the event is recorded as `reserved`. With
   * `replacing`, the unknown-outcome attempts under that key are left out of the
   * check and marked failed: the new reservation counts for the call instead.
   */
  reserve<R>(event: Omit<LedgerEvent, "id" | "t" | "status">, check: (s: LedgerSnapshot) => R | null, opts: { replacing?: string } = {}): { refusal: R } | { id: string } {
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const refusal = check(this.#snapshot(f, opts.replacing));
      if (refusal !== null) return { refusal };
      const id = nonce();
      const now = this.#clock().getTime();
      f.events = f.events.filter((e) => now - e.t < KEEP_MS);
      for (const e of f.events) if (replaces(e, opts.replacing)) e.status = "failed";
      f.events.push({ ...event, id, t: now, status: "reserved" });
      writeJsonFile(this.file, f);
      return { id };
    });
  }

  /** The ids of the reservations a call still holds (reserved, pending or unknown), for release(). */
  held(key: string): string[] {
    return this.#load()
      .events.filter((e) => e.key === key && OPEN.has(e.status))
      .map((e) => e.id);
  }

  /**
   * Release reservations a call still holds (mcp-guard cancel), so that they stop counting
   * against the caps and the retry that cancel allows can run. Only `ids` are released, as
   * held() read them before the cancel: a retry that claims the key once it is free reserves
   * its own, and that one must keep counting. Completed calls are kept. Returns how many were
   * released.
   */
  release(key: string, ids: readonly string[]): number {
    const only = new Set(ids);
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      let n = 0;
      for (const e of f.events) {
        if (e.key === key && OPEN.has(e.status) && only.has(e.id)) {
          e.status = "failed";
          n++;
        }
      }
      if (n) writeJsonFile(this.file, f);
      return n;
    });
  }

  settle(id: string, status: Exclude<LedgerStatus, "reserved">): void {
    withFileLock(this.#lock, () => {
      const f = this.#load();
      const e = f.events.find((x) => x.id === id);
      if (e) {
        e.status = status;
        writeJsonFile(this.file, f);
      }
    });
  }
}
