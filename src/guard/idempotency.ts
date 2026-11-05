/**
 * Idempotency (section 7.3). Core derives the key; the model can neither supply
 * nor override it. The local store dedupes retries (and is the only protection for
 * providers without an idempotency header).
 */
import { join } from "node:path";
import { sha256Hex, utcDay } from "./canonical.js";
import { readJsonFile, withFileLock, writeJsonFile } from "./lock.js";

export interface DeriveKeyInput {
  server: string;
  operation: string;
  /** canonicalJson() of the full request (path params, query, body). */
  canonicalBody: string;
  /** The day the proposal was created (YYYY-MM-DD, UTC). */
  proposalDay: string;
  /** Provider limit (Column: 255). */
  maxLength?: number;
}

/** The digest part of a key never shrinks below this (96 bits); the server label is cut first. */
export const MIN_KEY_DIGEST_HEX = 24;
/** The shortest provider limit a guard accepts: "nst-" + 24 digest characters + room for a label. */
export const MIN_KEY_LENGTH = 32;

export function deriveKey(input: DeriveKeyInput): string {
  const digest = sha256Hex(`nst-mcp-guard/v1\n${input.server}\n${input.operation}\n${input.proposalDay}\n${input.canonicalBody}`);
  const max = Math.max(16, input.maxLength ?? 255);
  const key = `nst-${input.server}-${digest}`;
  if (key.length <= max) return key;
  // Keep at least MIN_KEY_DIGEST_HEX digest characters: a long server name must never cut the
  // digest away (every request would then share one key). When the plain cut keeps enough, this
  // is exactly key.slice(0, max).
  const keepDigest = Math.min(digest.length, Math.max(MIN_KEY_DIGEST_HEX, max - `nst-${input.server}-`.length));
  const labelRoom = max - "nst--".length - keepDigest;
  if (labelRoom <= 0) return `nst-${digest}`.slice(0, max);
  return `nst-${input.server.slice(0, labelRoom)}-${digest.slice(0, keepDigest)}`;
}

/**
 * The store's file exists but cannot be read as a store. The guard refuses
 * (state_unreadable) until a human looks at it: starting empty would let a
 * completed call run again.
 */
export class IdempotencyStateError extends Error {
  readonly code = "state_unreadable";
  constructor(
    readonly file: string,
    detail: string
  ) {
    super(`The idempotency store ${file} is unreadable (${detail}). Nothing runs until a human inspects it and moves it aside.`);
    this.name = "IdempotencyStateError";
  }
}

export type IdemStatus = "in_flight" | "done" | "pending" | "unknown" | "failed";

export interface IdemEntry {
  key: string;
  operation: string;
  request_hash: string;
  day: string;
  status: IdemStatus;
  created_at: string;
  finished_at?: string;
  pid: number;
  /** What the first call returned (redacted, size-capped). */
  result?: {
    http_status?: number | null;
    provider_ids?: string[];
    data?: unknown;
    pending?: { ref?: string; status?: string; url?: string };
  };
}

interface IdemFile {
  version: 1;
  entries: Record<string, IdemEntry>;
}

const DAY_MS = 86_400_000;
const KEEP_MS = 3 * DAY_MS;

/**
 * The UTC days whose entries the store may still hold, newest first. An entry is kept for three
 * days after it was created, so a call made on any of these days can still be unknown or held by
 * the provider, and a retry has to look up the key derived from each of them.
 */
export function retainedDays(now: Date): string[] {
  const days: string[] = [];
  for (let back = 0; back * DAY_MS <= KEEP_MS; back++) days.push(utcDay(new Date(now.getTime() - back * DAY_MS)));
  return days;
}
/** An in-flight entry older than this belongs to a process that died mid-call. */
const STALE_IN_FLIGHT_MS = 5 * 60_000;

export class IdempotencyStore {
  readonly file: string;
  readonly #lock: string;
  readonly #clock: () => Date;

  constructor(dir: string, opts: { clock?: () => Date } = {}) {
    this.file = join(dir, "idempotency.json");
    this.#lock = join(dir, "idempotency.lock");
    this.#clock = opts.clock ?? (() => new Date());
  }

  #load(): IdemFile {
    let f: unknown;
    try {
      f = readJsonFile<unknown>(this.file, { version: 1, entries: {} });
    } catch (e) {
      // Never fall back to an empty store, and never overwrite the bad file (fail closed).
      throw new IdempotencyStateError(this.file, e instanceof SyntaxError ? "not valid JSON" : ((e as NodeJS.ErrnoException).code ?? "read failed"));
    }
    const entries = f && typeof f === "object" ? (f as { entries?: unknown }).entries : undefined;
    if (!entries || typeof entries !== "object" || Array.isArray(entries)) throw new IdempotencyStateError(this.file, "no entries object");
    for (const e of Object.values(entries as Record<string, unknown>)) {
      const x = e as Partial<IdemEntry> | null;
      if (!x || typeof x !== "object" || typeof x.key !== "string" || typeof x.status !== "string" || typeof x.created_at !== "string" || Number.isNaN(Date.parse(x.created_at))) {
        throw new IdempotencyStateError(this.file, "an entry is malformed");
      }
    }
    return f as IdemFile;
  }

  /**
   * Whether an existing entry lets the same request run again. Only `failed` (never
   * sent, or refused by the provider) and `done` entries older than the window do.
   * `in_flight`, `unknown` and `pending` may have executed (or hold an approval), so
   * they leave only through reclaimUnknown(), cancel(), or the three-day prune.
   */
  #reopens(e: IdemEntry, windowMs: number | undefined, now: number): boolean {
    if (e.status === "failed") return true;
    return e.status === "done" && windowMs !== undefined && now - Date.parse(e.created_at) > windowMs;
  }

  #normalize(e: IdemEntry): IdemEntry {
    if (e.status === "in_flight" && this.#clock().getTime() - Date.parse(e.created_at) > STALE_IN_FLIGHT_MS) {
      return { ...e, status: "unknown" };
    }
    return e;
  }

  /**
   * The first of `keys` whose entry still stands (no write; used by dry_run and step 5). Entries
   * that let the request run again (failed, or done past the window) are skipped, and so are
   * entries older than three days, which begin() prunes: the search goes on to the older keys,
   * so a newer failed attempt never hides an older call whose outcome is unknown.
   */
  lookup(keys: readonly string[], opts: { windowMs?: number } = {}): IdemEntry | null {
    const f = this.#load();
    const now = this.#clock().getTime();
    for (const k of keys) {
      const e = Object.prototype.hasOwnProperty.call(f.entries, k) ? f.entries[k] : undefined;
      if (!e || now - Date.parse(e.created_at) > KEEP_MS) continue;
      const n = this.#normalize(e);
      if (this.#reopens(n, opts.windowMs, now)) continue;
      return n;
    }
    return null;
  }

  /**
   * Atomically claim `key` for execution. Returns the existing entry instead when
   * another call holds it, finished it inside the window, or may have run it
   * (failed entries and done entries past the window may be claimed).
   */
  begin(key: string, info: { operation: string; request_hash: string; day: string }, opts: { windowMs?: number } = {}): { claimed: true } | { claimed: false; existing: IdemEntry } {
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const now = this.#clock();
      for (const [k, e] of Object.entries(f.entries)) if (now.getTime() - Date.parse(e.created_at) > KEEP_MS) delete f.entries[k];
      const existing = Object.prototype.hasOwnProperty.call(f.entries, key) ? this.#normalize(f.entries[key]) : null;
      // `unknown` is never claimed here: only reclaimUnknown() may retry it, for a provider that dedupes on the key.
      if (existing && !this.#reopens(existing, opts.windowMs, now.getTime())) {
        return { claimed: false, existing };
      }
      f.entries[key] = { key, ...info, status: "in_flight", created_at: now.toISOString(), pid: process.pid };
      writeJsonFile(this.file, f);
      return { claimed: true };
    });
  }

  /** Re-claim an entry whose outcome is unknown, for a provider that dedupes on the same key. */
  reclaimUnknown(key: string): boolean {
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const e = f.entries[key];
      if (!e || this.#normalize(e).status !== "unknown") return false;
      f.entries[key] = { ...e, status: "in_flight", created_at: this.#clock().toISOString(), pid: process.pid };
      writeJsonFile(this.file, f);
      return true;
    });
  }

  finish(key: string, status: Exclude<IdemStatus, "in_flight">, result?: IdemEntry["result"]): void {
    withFileLock(this.#lock, () => {
      const f = this.#load();
      const e = f.entries[key];
      if (!e) return;
      f.entries[key] = { ...e, status, finished_at: this.#clock().toISOString(), ...(result ? { result } : {}) };
      writeJsonFile(this.file, f);
    });
  }

  /**
   * Mark a pending or unknown-outcome entry failed (mcp-guard cancel), so the same
   * request may run again. The prefix (or suffix) must match exactly one entry; a
   * completed or currently running call is never reopened. This does not cancel a
   * hold at the provider.
   */
  cancel(keyPrefix: string): IdemEntry | null {
    const needle = keyPrefix.trim();
    if (!needle) return null;
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const match = Object.values(f.entries).filter((e) => e.key.startsWith(needle) || e.key.endsWith(needle));
      if (match.length !== 1) return null;
      const e = this.#normalize(match[0]);
      if (e.status !== "pending" && e.status !== "unknown") return null;
      f.entries[e.key] = { ...match[0], status: "failed", finished_at: this.#clock().toISOString() };
      writeJsonFile(this.file, f);
      return f.entries[e.key];
    });
  }

  entries(): IdemEntry[] {
    return Object.values(this.#load().entries).map((e) => this.#normalize(e));
  }

  static today(clock: () => Date = () => new Date()): string {
    return utcDay(clock());
  }
}
