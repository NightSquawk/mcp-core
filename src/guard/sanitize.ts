/**
 * Untrusted content handling (section 7.9).
 *
 * sanitizeUntrusted() runs on every untrusted field before the model sees it, on
 * our own tool descriptions, and on all approval text.
 */

// ANSI CSI / OSC / other ESC sequences, and bare C0/C1 controls except \t \n \r.
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
const ANSI_CSI = /(?:\u001b\[|\u009b)[0-?]*[ -/]*[@-~]/g;
const ANSI_OTHER = /\u001b[@-Z\\-_]/g;
const CONTROLS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;
// Zero-width and invisible format characters.
const ZERO_WIDTH = /[​-‍⁠﻿᠎­]/g;
// Invisible operators U+2061-U+2064.
const INVISIBLE_OPS = /[⁡-⁤]/g;
// Bidi controls: LRM/RLM/ALM, embeddings/overrides, isolates.
const BIDI = /[‎‏؜‪-‮⁦-⁩]/g;
// Variation selectors (BMP and supplementary).
const VS_BMP = /[︀-️]/g;
const VS_SUPP = /\udb40[\udd00-\uddef]/g; // U+E0100-E01EF
// Unicode tag characters U+E0000-E007F (surrogate pairs 󠀀-󠁿).
const TAGS = /\udb40[\udc00-\udc7f]/g;
// Unpaired surrogates.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Remove characters and sequences that can hide instructions from a human reader. */
export function sanitizeUntrusted(input: string): string {
  let out = String(input);
  // Repeat until stable: removing one sequence can join the halves of another.
  for (let i = 0; i < 8; i++) {
    const before = out;
    out = out
      .replace(ANSI_OSC, "")
      .replace(ANSI_CSI, "")
      .replace(ANSI_OTHER, "")
      .replace(TAGS, "")
      .replace(VS_SUPP, "")
      .replace(LONE_SURROGATE, "")
      .replace(ZERO_WIDTH, "")
      .replace(INVISIBLE_OPS, "")
      .replace(BIDI, "")
      .replace(VS_BMP, "")
      .replace(CONTROLS, "");
    if (out === before) break;
  }
  return out;
}

/** True when `text` contains anything sanitizeUntrusted() would remove. */
export function hasHiddenCharacters(text: string): boolean {
  return sanitizeUntrusted(text) !== String(text);
}

/** The label untrusted fields are returned in (spotlighting). */
export interface UntrustedText {
  untrusted: true;
  source: string;
  text: string;
}

export function labelUntrusted(text: string, source: string): UntrustedText {
  return { untrusted: true, source, text: sanitizeUntrusted(text) };
}

/**
 * Walk a JSON value and wrap every string found under one of `fields` (matched by
 * key name at any depth) as an UntrustedText label. Returns the labelled copy and
 * the raw strings, which the session uses for provenance (7.9).
 */
export function labelUntrustedFields(
  value: unknown,
  fields: ReadonlySet<string> | readonly string[],
  source: string
): { value: unknown; texts: string[] } {
  const keys = fields instanceof Set ? fields : new Set(fields as readonly string[]);
  const texts: string[] = [];
  const walk = (v: unknown, key: string | null): unknown => {
    if (typeof v === "string") {
      if (key !== null && keys.has(key) && v.length) {
        texts.push(v);
        return labelUntrusted(v, `${source}.${key}`);
      }
      return v;
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, key));
    if (v && typeof v === "object") {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, k)]));
    }
    return v;
  };
  return { value: walk(value, null), texts };
}

/** Sanitize every string in a JSON value (used when a whole result is untrusted). */
export function sanitizeDeep<T>(value: T): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return sanitizeUntrusted(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [sanitizeUntrusted(k), walk(x)]));
    return v;
  };
  return walk(value) as T;
}
