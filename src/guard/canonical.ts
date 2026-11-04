import { createHash, randomBytes } from "node:crypto";

/**
 * JSON with object keys sorted at every depth and `undefined` members dropped.
 * Values with toJSON (Date) serialize as JSON.stringify would. Objects are built
 * without a prototype, so an own `__proto__` member (JSON.parse creates one) is
 * kept and covered by the hash instead of being applied as a prototype.
 */
export function canonicalJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (v && typeof v === "object" && typeof (v as { toJSON?: unknown }).toJSON === "function") v = (v as { toJSON: () => unknown }).toJSON();
    if (Array.isArray(v)) return v.map((x) => (x === undefined ? null : walk(x)));
    if (v && typeof v === "object") {
      const out = Object.create(null) as Record<string, unknown>;
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        const x = (v as Record<string, unknown>)[k];
        if (x !== undefined && typeof x !== "function" && typeof x !== "symbol") out[k] = walk(x);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value)) ?? "null";
}

export function sha256Hex(text: string | Buffer): string {
  return createHash("sha256").update(text).digest("hex");
}

export function nonce(): string {
  return randomBytes(12).toString("hex");
}

/** Deep-freeze a JSON value so a stored request cannot be mutated after hashing. */
export function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
  }
  return value;
}

/** A structured clone limited to JSON data. */
export function jsonClone<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
}

/** UTC calendar day (YYYY-MM-DD). */
export function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** UTC month (YYYY-MM). */
export function utcMonth(d: Date): string {
  return d.toISOString().slice(0, 7);
}
