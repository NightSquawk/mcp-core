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
// Zero-width and invisible format characters: U+200B-U+200D, U+2060, U+FEFF, U+180E, U+00AD.
const ZERO_WIDTH = /[\u200b-\u200d\u2060\ufeff\u180e\u00ad]/g;
// Invisible operators U+2061-U+2064.
const INVISIBLE_OPS = /[\u2061-\u2064]/g;
// Bidi controls: LRM/RLM U+200E-U+200F, ALM U+061C, embeddings/overrides U+202A-U+202E, isolates U+2066-U+2069.
const BIDI = /[\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/g;
// Variation selectors: BMP U+FE00-U+FE0F, supplementary U+E0100-U+E01EF.
const VS_BMP = /[\ufe00-\ufe0f]/g;
const VS_SUPP = /[\u{E0100}-\u{E01EF}]/gu;
// Unicode tag characters U+E0000-U+E007F.
const TAGS = /[\u{E0000}-\u{E007F}]/gu;
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
 * key name at any depth) as an UntrustedText label. A string nested anywhere below a
 * matching key counts too: `{comments: [{body: "..."}]}` with field `comments` labels
 * the body, under the source of the outermost matching key. Returns the labelled copy
 * and the raw strings, which the session uses for provenance (7.9).
 */
export function labelUntrustedFields(
  value: unknown,
  fields: ReadonlySet<string> | readonly string[],
  source: string
): { value: unknown; texts: string[] } {
  const keys = fields instanceof Set ? fields : new Set(fields as readonly string[]);
  const texts: string[] = [];
  // `under` is the untrusted key this value sits below (null when none does).
  const walk = (v: unknown, under: string | null): unknown => {
    if (typeof v === "string") {
      if (under !== null && v.length) {
        texts.push(v);
        return labelUntrusted(v, `${source}.${under}`);
      }
      return v;
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, under));
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, under ?? (keys.has(k) ? k : null))])
      );
    }
    return v;
  };
  return { value: walk(value, null), texts };
}

/**
 * The texts of every UntrustedText label in an already-labelled value: a result as the model
 * receives it, or a stored result returned again. Walked without a depth limit (iteratively, each
 * object once), so a label nested deep in a result is still recorded for provenance.
 */
export function untrustedTexts(value: unknown, out: string[] = []): string[] {
  const seen = new WeakSet<object>();
  const stack: unknown[] = [value];
  while (stack.length) {
    const v = stack.pop();
    if (v === null || typeof v !== "object" || seen.has(v)) continue;
    seen.add(v);
    if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
      continue;
    }
    const o = v as Record<string, unknown>;
    if (o.untrusted === true && typeof o.text === "string") {
      out.push(o.text);
      continue;
    }
    const values = Object.values(o);
    for (let i = values.length - 1; i >= 0; i--) stack.push(values[i]);
  }
  return out;
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
