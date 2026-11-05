/**
 * Per-process session state (sections 7.9 and 7.11): taint, provenance of the
 * values the model has seen, and the client lock. One stdio server process is one
 * agent session, so this lives in memory and ends with the process.
 */
import { nonce } from "./canonical.js";

/** Tokens shorter than this are too common to say anything about provenance. */
const MIN_TOKEN = 4;
const MAX_TOKENS = 200_000;

const EDGE_PUNCTUATION = new Set([".", "+", "-"]);

/**
 * Strip leading and trailing . + - in one pass. (The regex form
 * /^[.+-]+|[.+-]+$/ rescans the run from every position: quadratic on a long run
 * of dots inside one token.)
 */
function trimPunctuation(token: string): string {
  let start = 0;
  let end = token.length;
  while (start < end && EDGE_PUNCTUATION.has(token[start]!)) start++;
  while (end > start && EDGE_PUNCTUATION.has(token[end - 1]!)) end--;
  return token.slice(start, end);
}

/**
 * Normalized tokens in a piece of text: identifiers, emails, phone and account
 * numbers. Digit groups joined by spaces, dots or dashes also count as one token
 * ("021 000 021" -> "021000021"), so reformatting a number does not launder it.
 */
export function tokensOf(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/[A-Za-z0-9_@.+-]+/g)) {
    const t = trimPunctuation(m[0]).toLowerCase();
    if (t.length >= MIN_TOKEN) out.add(t);
  }
  for (const m of text.matchAll(/\d(?:[\d \t.-]*\d)?/g)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= MIN_TOKEN) out.add(digits);
  }
  return [...out];
}

/**
 * The tokens of one target value, found exactly as tokensOf finds them in text, so a value matches
 * however the text spelled it: "Evil Corp" is "evil" and "corp", and "1234 5678" is "1234", "5678"
 * and "12345678".
 */
export function normalizeValue(value: string): string[] {
  return tokensOf(value);
}

/** Every string and number leaf of a value, skipping labelled untrusted fields. */
export function trustedLeaves(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 64 || value === null || value === undefined) return out;
  if (typeof value === "string") out.push(value);
  else if (typeof value === "number" || typeof value === "bigint") out.push(String(value));
  else if (Array.isArray(value)) for (const v of value) trustedLeaves(v, out, depth + 1);
  else if (typeof value === "object") {
    const o = value as Record<string, unknown>;
    if (o.untrusted === true && typeof o.text === "string") return out;
    for (const [k, v] of Object.entries(o)) {
      out.push(k);
      trustedLeaves(v, out, depth + 1);
    }
  }
  return out;
}

export interface TaintState {
  at: string;
  source: string;
}

export class SessionState {
  readonly id: string;
  #taint: TaintState | null = null;
  readonly #trusted = new Set<string>();
  readonly #untrusted = new Map<string, string>();
  #client: string | null = null;
  #clientHolds = 0;
  #clientActed = false;

  constructor(id: string = nonce().slice(0, 16)) {
    this.id = id;
  }

  get taint(): TaintState | null {
    return this.#taint;
  }

  get lockedClient(): string | null {
    return this.#client;
  }

  /** The session read text other people wrote (an `untrusted_output` field). */
  markTainted(source: string, at: Date = new Date()): void {
    if (!this.#taint) this.#taint = { at: at.toISOString(), source };
  }

  /** Values seen in structured fields. Recorded before the untrusted text of the same result. */
  recordTrusted(texts: readonly string[]): void {
    for (const text of texts) {
      for (const t of tokensOf(text)) {
        if (this.#trusted.size >= MAX_TOKENS) return;
        this.#trusted.add(t);
      }
    }
  }

  /** Values seen first in untrusted text (provenance, 7.9). */
  recordUntrusted(texts: readonly string[], source: string): void {
    for (const text of texts) {
      for (const t of tokensOf(text)) {
        if (this.#trusted.has(t) || this.#untrusted.has(t)) continue;
        if (this.#untrusted.size >= MAX_TOKENS) return;
        this.#untrusted.set(t, source);
      }
    }
  }

  /**
   * A token of a value that first appeared in untrusted text, and where; null if there is none.
   * One is enough: a payee "Evil Corp" taken from an email is refused even when "corp" also
   * appeared in a structured field, because "evil" did not.
   */
  untrustedToken(value: string): { token: string; source: string } | null {
    for (const token of normalizeValue(value)) {
      if (this.#trusted.has(token)) continue;
      const source = this.#untrusted.get(token);
      if (source) return { token, source };
    }
    return null;
  }

  /** Where a value, or a word or number in it, first appeared, if that was untrusted text; null otherwise. */
  untrustedSource(value: string): string | null {
    return this.untrustedToken(value)?.source ?? null;
  }

  /** Pin non-read calls to one client (7.11) for good. Returns false if another client is already pinned. */
  lockClient(client: string): boolean {
    if (!this.holdClient(client)) return false;
    this.releaseClient(client, true);
    return true;
  }

  /**
   * Hold the pin for a call about to be sent: calls for any other client are refused while it is
   * held. Returns false if another client holds the pin. releaseClient() says whether the call may
   * have acted for the client; the pin stays for good once one did, and is lifted when no call for
   * the client is in flight and none acted (all rejected or never sent).
   */
  holdClient(client: string): boolean {
    if (this.#client !== null && this.#client !== client) return false;
    this.#client = client;
    this.#clientHolds++;
    return true;
  }

  releaseClient(client: string, acted: boolean): void {
    if (this.#client !== client || this.#clientHolds === 0) return;
    this.#clientHolds--;
    if (acted) this.#clientActed = true;
    if (this.#clientHolds === 0 && !this.#clientActed) this.#client = null;
  }
}
