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

export function deriveKey(input: DeriveKeyInput): string {
  const digest = sha256Hex(`nst-mcp-guard/v1\n${input.server}\n${input.operation}\n${input.proposalDay}\n${input.canonicalBody}`);
  const key = `nst-${input.server}-${digest}`;
  return key.slice(0, Math.max(16, input.maxLength ?? 255));
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

const KEEP_MS = 3 * 86_400_000;
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
    try {
      const f = readJsonFile<IdemFile>(this.file, { version: 1, entries: {} });
      return f && typeof f.entries === "object" ? f : { version: 1, entries: {} };
    } catch {
      return { version: 1, entries: {} };
    }
  }

  #normalize(e: IdemEntry): IdemEntry {
    if (e.status === "in_flight" && this.#clock().getTime() - Date.parse(e.created_at) > STALE_IN_FLIGHT_MS) {
      return { ...e, status: "unknown" };
    }
    return e;
  }

  /** The first of `keys` with an entry (no write; used by dry_run and step 5). */
  lookup(keys: readonly string[], opts: { windowMs?: number } = {}): IdemEntry | null {
    const f = this.#load();
    const now = this.#clock().getTime();
    for (const k of keys) {
      const e = f.entries[k];
      if (!e) continue;
      if (opts.windowMs !== undefined && now - Date.parse(e.created_at) > opts.windowMs && e.status !== "in_flight") continue;
      return this.#normalize(e);
    }
    return null;
  }

  /**
   * Atomically claim `key` for execution. Returns the existing entry instead when
   * another call holds or finished it (failed entries may be retried).
   */
  begin(key: string, info: { operation: string; request_hash: string; day: string }, opts: { windowMs?: number } = {}): { claimed: true } | { claimed: false; existing: IdemEntry } {
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const now = this.#clock();
      for (const [k, e] of Object.entries(f.entries)) if (now.getTime() - Date.parse(e.created_at) > KEEP_MS) delete f.entries[k];
      const existing = f.entries[key] ? this.#normalize(f.entries[key]) : null;
      const expired = existing && opts.windowMs !== undefined && now.getTime() - Date.parse(existing.created_at) > opts.windowMs && existing.status !== "in_flight";
      if (existing && existing.status !== "failed" && !(existing.status === "unknown" && existing.pid === -1) && !expired) {
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

  /** Mark a pending entry cancelled locally (mcp-guard cancel). */
  cancel(keyPrefix: string): IdemEntry | null {
    return withFileLock(this.#lock, () => {
      const f = this.#load();
      const match = Object.values(f.entries).filter((e) => e.key.startsWith(keyPrefix) || e.key.endsWith(keyPrefix));
      if (match.length !== 1) return null;
      const e = match[0];
      f.entries[e.key] = { ...e, status: "failed", finished_at: this.#clock().toISOString() };
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
