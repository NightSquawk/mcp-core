/**
 * Append-only JSONL audit log with a hash chain (section 7.1).
 *
 * Each line carries the previous line's hash, so edits are detectable (not
 * impossible: the agent's user can rewrite the whole file until G5 forwards lines
 * off-box or the broker writes the log as its own user).
 */
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, sha256Hex, utcMonth } from "./canonical.js";
import { withFileLock } from "./lock.js";
import { redactValue, type Redactor, redact as sharedRedact } from "./redact.js";
import type { Group, Tier } from "./tiers.js";

export type AuditDecision =
  | "executed"
  | "pending"
  | "refused"
  | "dry_run"
  | "deduplicated"
  | "failed"
  | "unknown_outcome"
  | "read"
  | "alert";

export interface AuditEntry {
  server: string;
  version: string;
  guard: string;
  session: string;
  tool: string;
  operation: string;
  tier: Tier | "unknown";
  group: Group | null;
  mode: string;
  decision: AuditDecision;
  dry_run: boolean;
  client?: string | null;
  reason_code?: string;
  request_hash?: string;
  idempotency_key?: string;
  approver?: string;
  approver_result?: string;
  /** The approver is a person (a human denial counts toward the denial breaker, 6.7). */
  approver_human?: boolean;
  http_status?: number | null;
  provider_ids?: string[];
  amount_cents?: number;
  currency?: string;
  duration_ms?: number;
  alert?: string;
  /**
   * When mcp-guard cancel marked the entry failed (on its cli_cancel line). A ledger rebuilt from
   * the log releases only what the call recorded before then, not a retry that claimed the key at
   * once and was written before this line.
   */
  cancelled_at?: string;
  note?: string;
  agent_says?: string;
}

export interface AuditLine extends AuditEntry {
  v: 1;
  ts: string;
  pid: number;
  prev: string;
  hash: string;
}

export interface ChainCheck {
  file: string;
  ok: boolean;
  lines: number;
  brokenAt?: number;
  reason?: string;
}

export function genesis(server: string, month: string): string {
  return `genesis:${server}:${month}`;
}

export function lineHash(prev: string, line: Omit<AuditLine, "hash">): string {
  return `sha256:${sha256Hex(`${prev}\n${canonicalJson(line)}`)}`;
}

export class AuditLog {
  readonly dir: string;
  readonly server: string;
  readonly #clock: () => Date;
  readonly #redact: Redactor;
  readonly #secrets: () => readonly string[];

  constructor(dir: string, server: string, opts: { clock?: () => Date; redactor?: Redactor; secrets?: () => readonly string[] } = {}) {
    this.dir = dir;
    this.server = server;
    this.#clock = opts.clock ?? (() => new Date());
    this.#redact = opts.redactor ?? sharedRedact;
    this.#secrets = opts.secrets ?? (() => []);
  }

  fileFor(month: string): string {
    return join(this.dir, `audit-${month}.jsonl`);
  }

  /** Append one line under the state lock. Everything is redacted before it is written. */
  append(entry: AuditEntry): AuditLine {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const now = this.#clock();
    const month = utcMonth(now);
    const file = this.fileFor(month);
    const clean = redactValue(entry, this.#secrets(), this.#redact);
    if (!clean || typeof clean !== "object" || Array.isArray(clean) || typeof clean.operation !== "string") {
      throw new Error("AuditLog.append: the entry must be an object with an operation.");
    }
    return withFileLock(join(this.dir, "audit.lock"), () => {
      const prev = this.#lastHash(file) ?? genesis(this.server, month);
      // The chain fields are always the log's own: an entry cannot backdate, re-number or re-link a line.
      const { v: _v, ts: _ts, pid: _pid, prev: _prev, hash: _hash, ...fields } = clean as unknown as Record<string, unknown>;
      const body = { v: 1, ts: now.toISOString(), pid: process.pid, ...fields, prev } as Omit<AuditLine, "hash">;
      const line: AuditLine = { ...body, hash: lineHash(prev, body) };
      appendFileSync(file, JSON.stringify(line) + "\n", { mode: 0o600 });
      return line;
    });
  }

  #lastHash(file: string): string | null {
    if (!existsSync(file)) return null;
    const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
    if (!lines.length) return null;
    const last = lines[lines.length - 1];
    try {
      const parsed = JSON.parse(last) as Partial<AuditLine>;
      if (typeof parsed.hash === "string") return parsed.hash;
    } catch {
      // fall through: chain onto the raw bytes so the break stays visible
    }
    return `sha256:${sha256Hex(last)}`;
  }

  /** Audit files, oldest first. */
  files(): string[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((f) => /^audit-\d{4}-\d{2}\.jsonl$/.test(f))
      .sort()
      .map((f) => join(this.dir, f));
  }

  /**
   * Verify one file's chain. Whatever a line holds, a damaged one is reported as the place the
   * chain breaks, never thrown: the guard trips its kill switch on it at start, and mcp-guard
   * verify and reset name it.
   */
  verify(file: string): ChainCheck {
    const month = /audit-(\d{4}-\d{2})\.jsonl$/.exec(file)?.[1] ?? "";
    if (!existsSync(file)) return { file, ok: true, lines: 0 };
    const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
    const broken = (i: number, reason: string): ChainCheck => ({ file, ok: false, lines: lines.length, brokenAt: i + 1, reason });
    let prev = genesis(this.server, month);
    for (let i = 0; i < lines.length; i++) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(lines[i]);
      } catch {
        return broken(i, "not JSON");
      }
      // JSON, but not a line this log writes: null, a number, an array, or no chain fields.
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return broken(i, "not an audit line");
      const { hash, ...rest } = parsed as Record<string, unknown>;
      if (typeof hash !== "string" || typeof rest.prev !== "string") return broken(i, "not an audit line");
      if (rest.prev !== prev) return broken(i, "prev does not match the line before");
      let expected: string;
      try {
        expected = lineHash(prev, rest as unknown as Omit<AuditLine, "hash">);
      } catch {
        // JSON.parse takes any depth, hashing does not: a line nested too deeply to hash.
        return broken(i, "not an audit line");
      }
      if (expected !== hash) return broken(i, "hash does not match the line");
      prev = hash;
    }
    return { file, ok: true, lines: lines.length };
  }

  verifyAll(): ChainCheck[] {
    return this.files().map((f) => this.verify(f));
  }

  /** Parsed lines from the given months (default: this month and last). Corrupt lines are skipped. */
  read(months?: string[]): AuditLine[] {
    const now = this.#clock();
    const prevMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15));
    const wanted = months ?? [utcMonth(prevMonth), utcMonth(now)];
    const out: AuditLine[] = [];
    for (const m of wanted) {
      const file = this.fileFor(m);
      if (!existsSync(file)) continue;
      for (const l of readFileSync(file, "utf8").split("\n")) {
        if (!l.trim()) continue;
        try {
          const x = JSON.parse(l) as AuditLine | null;
          // Lines that are not audit lines (null, arrays, a bad timestamp) are skipped like corrupt ones; verify() reports them.
          if (x && typeof x === "object" && !Array.isArray(x) && typeof x.ts === "string" && !Number.isNaN(Date.parse(x.ts)) && typeof x.hash === "string") out.push(x);
        } catch {
          // skipped; verify() reports it
        }
      }
    }
    return out;
  }
}
