/**
 * redact() with shared patterns (section 7.4). Applied to error messages, audit
 * lines and dry_run output. Servers add patterns with createRedactor().
 */

export type RedactRule = readonly [RegExp, string];

/** Shared patterns. Order matters: specific shapes before the digit-run rule. */
export const SHARED_RULES: readonly RedactRule[] = Object.freeze([
  // HTTP Authorization values
  [/\b(Basic|Bearer)\s+[A-Za-z0-9+/=._~-]{6,}/gi, "$1 [redacted]"],
  // Provider key shapes: Column/Stripe test_ and live_, Stripe sk_/rk_/pk_ (with optional mode)
  [/\b(test|live)_[A-Za-z0-9]{8,}/g, "$1_[redacted]"],
  [/\b(sk|rk)_(?:(?:test|live)_)?[A-Za-z0-9]{8,}/g, "$1_[redacted]"],
  // Credentials in query strings and key=value text
  [/\b((?:api[_-]?key|access[_-]?token|key|token|password|passwd|secret|client[_-]?secret)=)[^&\s"']+/gi, "$1[redacted]"],
  // URL user-info
  [/([a-z][a-z0-9+.-]*:\/\/)[^/@\s"']+@/gi, "$1[redacted]@"],
  // Account and routing numbers: runs of 8-17 digits keep only their last 4
  [/\b\d{4,13}(\d{4})\b/g, "****$1"],
] as RedactRule[]);

export type Redactor = (text: string, secrets?: readonly string[]) => string;

/** Build a redactor with server-specific extra rules (applied before the shared ones). */
export function createRedactor(extra: readonly RedactRule[] = []): Redactor {
  const rules = [...extra, ...SHARED_RULES];
  return (text: string, secrets: readonly string[] = []): string => {
    let out = String(text);
    // Exact secret values first, longest first so a secret containing another is masked whole.
    for (const s of [...secrets].filter(Boolean).sort((a, b) => b.length - a.length)) out = out.split(s).join("[redacted]");
    for (const [pattern, replacement] of rules) {
      pattern.lastIndex = 0;
      out = out.replace(pattern, replacement);
    }
    return out;
  };
}

/** Mask secrets in `text` with the shared patterns. */
export const redact: Redactor = createRedactor();

/** Keys whose values are account, routing or card numbers even when the provider sends them as JSON numbers. */
export const SENSITIVE_NUMBER_KEYS = /(^|_)(account|routing|card|aba)_?(number|num|no)$|^(iban|pan|aba)$/i;

function lastFour(value: string | number): string {
  const digits = String(value).replace(/\D/g, "");
  return digits.length > 4 ? `****${digits.slice(-4)}` : String(value);
}

/**
 * redact() for a JSON value. String leaves and object keys go through the
 * redactor; numbers, booleans and the structure are kept, so an amount such as
 * 12345678 cents is never mistaken for an account number. Values under
 * SENSITIVE_NUMBER_KEYS keep only their last 4 digits whatever their type.
 */
export function redactValue<T>(value: T, secrets: readonly string[] = [], redactor: Redactor = redact): T {
  const walk = (v: unknown, key: string | null, depth: number): unknown => {
    if (key !== null && SENSITIVE_NUMBER_KEYS.test(key) && (typeof v === "number" || typeof v === "string")) {
      return redactor(lastFour(v), secrets);
    }
    if (typeof v === "string") return redactor(v, secrets);
    if (v === null || typeof v !== "object") return v;
    if (depth > 64) return "[too deep]";
    if (Array.isArray(v)) return v.map((x) => walk(x, key, depth + 1));
    if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
      const plain: unknown = JSON.parse(JSON.stringify(v) ?? "null");
      return plain !== null && typeof plain === "object" ? walk(plain, key, depth + 1) : walk(plain, key, depth);
    }
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [redactor(k, secrets), walk(x, k, depth + 1)]));
  };
  return walk(value, null, 0) as T;
}
