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

/** Scripts written without spaces between words: their runs are also split into overlapping pairs. */
const UNSPACED = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}]/u;
const UNSPACED_RUN = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}\p{M}]+/gu;

/** A token's length for MIN_TOKEN: a character of an unspaced script carries about a word, so counts 2. */
function tokenWeight(token: string): number {
  let n = 0;
  for (const ch of token) n += UNSPACED.test(ch) ? 2 : 1;
  return n;
}

/**
 * Normalized tokens in a piece of text: words and identifiers in any script, emails,
 * phone and account numbers. Text is NFKC-normalized first, so full-width or other
 * compatibility forms match their plain spelling. Digit groups joined by spaces, dots
 * or dashes also count as one token ("021 000 021" -> "021000021"), so reformatting a
 * number does not launder it. Runs of scripts written without spaces (Chinese, Japanese,
 * Thai, ...) also give every pair of adjacent characters, so a name inside a sentence
 * ("请付款给恶意公司") matches the same name as a target ("恶意公司").
 */
export function tokensOf(text: string): string[] {
  const out = new Set<string>();
  const normalized = text.normalize("NFKC");
  for (const m of normalized.matchAll(/[\p{L}\p{M}\p{N}_@.+-]+/gu)) {
    const t = trimPunctuation(m[0]).toLowerCase();
    if (tokenWeight(t) >= MIN_TOKEN) out.add(t);
  }
  for (const m of normalized.matchAll(UNSPACED_RUN)) {
    const chars = [...m[0]].filter((ch) => !/\p{M}/u.test(ch));
    for (let i = 0; i + 1 < chars.length; i++) out.add((chars[i]! + chars[i + 1]!).toLowerCase());
  }
  for (const m of normalized.matchAll(/\d(?:[\d \t.-]*\d)?/g)) {
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

/**
 * Every string and number leaf of a value, and every key, skipping labelled untrusted fields.
 * Walked without a depth limit (iteratively, each object once): a whole untrusted result is
 * recorded through this, and a leaf the model receives must not escape provenance by nesting.
 */
export function trustedLeaves(value: unknown, out: string[] = []): string[] {
  const seen = new WeakSet<object>();
  const stack: unknown[] = [value];
  while (stack.length) {
    const v = stack.pop();
    if (typeof v === "string") out.push(v);
    else if (typeof v === "number" || typeof v === "bigint") out.push(String(v));
    else if (v !== null && typeof v === "object" && !seen.has(v)) {
      seen.add(v);
      if (Array.isArray(v)) {
        for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
        continue;
      }
      const o = v as Record<string, unknown>;
      if (o.untrusted === true && typeof o.text === "string") continue;
      const entries = Object.entries(o);
      for (const [k] of entries) out.push(k);
      for (let i = entries.length - 1; i >= 0; i--) stack.push(entries[i]![1]);
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
